// Package dockerdriver implements netsim.Driver against a Docker daemon using the Docker Go
// SDK. It is the only place in the tree that imports the SDK, so the engine, the schema, and
// the node runtime stay free of that (heavy) dependency. Image builds shell out to
// `docker build` (which already handles the context tar + .dockerignore); everything else —
// networks, containers, exec, pause, signal, file copy, teardown — goes through the SDK so a
// run is driven programmatically and deterministically.
package dockerdriver

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"

	"github.com/arash16/dualnet/internal/netsim"
	"github.com/arash16/dualnet/internal/singleton"
)

// Driver drives a Docker daemon. Every resource it creates is namespaced with `<prefix>-`, so
// a run's networks/containers are found and removed by that prefix alone — no per-run
// bookkeeping, which means teardown is complete even after a partial or interrupted run.
type Driver struct {
	cli    *client.Client
	prefix string
}

var _ netsim.Driver = (*Driver)(nil)

// New connects to the daemon and namespaces resources with prefix (default "netsim"). It
// honours DOCKER_HOST if set; otherwise it resolves the active Docker CLI context's endpoint
// (so it works with OrbStack / colima / Docker Desktop, whose sockets are not the SDK's
// default /var/run/docker.sock).
func New(prefix string) (*Driver, error) {
	if prefix == "" {
		prefix = "netsim"
	}
	opts := []client.Opt{client.FromEnv, client.WithAPIVersionNegotiation()}
	if os.Getenv("DOCKER_HOST") == "" {
		if host := activeContextHost(); host != "" {
			opts = append(opts, client.WithHost(host))
		}
	}
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}
	return &Driver{cli: cli, prefix: prefix}, nil
}

// activeContextHost returns the current Docker CLI context's daemon endpoint, or "".
func activeContextHost() string {
	out, err := exec.Command("docker", "context", "inspect", "-f", "{{.Endpoints.docker.Host}}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (d *Driver) realNet(name string) string { return d.prefix + "-net-" + name }
func (d *Driver) realCtr(name string) string { return d.prefix + "-" + name }

func (d *Driver) BuildImage(ctx context.Context, tag, dockerfile, contextDir string) error {
	cmd := exec.CommandContext(ctx, "docker", "build", "-f", dockerfile, "-t", tag, contextDir)
	// Stream the build straight through so the caller sees the same layer/cache/progress
	// output `docker build` normally prints, rather than a silent wait.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker build: %w", err)
	}
	return nil
}

func (d *Driver) CreateNetwork(ctx context.Context, name, subnet string) error {
	real := d.realNet(name)
	_ = d.cli.NetworkRemove(ctx, real) // best-effort: clear a crash leftover
	_, err := d.cli.NetworkCreate(ctx, real, network.CreateOptions{
		Driver: "bridge",
		IPAM:   &network.IPAM{Config: []network.IPAMConfig{{Subnet: subnet}}},
	})
	return err
}

func (d *Driver) CreateContainer(ctx context.Context, c netsim.Container) error {
	real := d.realCtr(c.Name)
	_ = d.cli.ContainerRemove(ctx, real, container.RemoveOptions{Force: true}) // clear leftover

	cfg := &container.Config{Image: c.Image, Cmd: c.Cmd, Env: envSlice(c.Env)}
	host := &container.HostConfig{
		CapAdd:     c.CapAdd,
		Sysctls:    c.Sysctls,
		Privileged: c.Privileged,
	}
	for _, dev := range c.Devices {
		host.Devices = append(host.Devices, container.DeviceMapping{
			PathOnHost: dev, PathInContainer: dev, CgroupPermissions: "rwm",
		})
	}

	var netCfg *network.NetworkingConfig
	var extra []netsim.Attachment
	if len(c.Attach) > 0 {
		first := c.Attach[0]
		netCfg = &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{
			d.realNet(first.Fabric): {IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: first.IP}},
		}}
		extra = c.Attach[1:]
	}
	if _, err := d.cli.ContainerCreate(ctx, cfg, host, netCfg, nil, real); err != nil {
		return err
	}
	for _, a := range extra {
		if err := d.cli.NetworkConnect(ctx, d.realNet(a.Fabric), real, &network.EndpointSettings{
			IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: a.IP},
		}); err != nil {
			return fmt.Errorf("connect %s to %s: %w", real, a.Fabric, err)
		}
	}
	if len(c.Files) > 0 {
		if err := d.cli.CopyToContainer(ctx, real, "/", tarFiles(c.Files), container.CopyToContainerOptions{}); err != nil {
			return fmt.Errorf("copy files to %s: %w", real, err)
		}
	}
	return nil
}

func (d *Driver) Start(ctx context.Context, name string) error {
	return d.cli.ContainerStart(ctx, d.realCtr(name), container.StartOptions{})
}

func (d *Driver) Exec(ctx context.Context, name string, cmd []string) (netsim.ExecResult, error) {
	real := d.realCtr(name)
	idResp, err := d.cli.ContainerExecCreate(ctx, real, container.ExecOptions{
		Cmd: cmd, AttachStdout: true, AttachStderr: true,
	})
	if err != nil {
		return netsim.ExecResult{}, err
	}
	att, err := d.cli.ContainerExecAttach(ctx, idResp.ID, container.ExecAttachOptions{})
	if err != nil {
		return netsim.ExecResult{}, err
	}
	defer att.Close()
	var out, errBuf bytes.Buffer
	if _, err := stdcopy.StdCopy(&out, &errBuf, att.Reader); err != nil {
		return netsim.ExecResult{}, err
	}
	insp, err := d.cli.ContainerExecInspect(ctx, idResp.ID)
	if err != nil {
		return netsim.ExecResult{}, err
	}
	return netsim.ExecResult{ExitCode: insp.ExitCode, Stdout: out.String(), Stderr: errBuf.String()}, nil
}

func (d *Driver) Pause(ctx context.Context, name string) error {
	return d.cli.ContainerPause(ctx, d.realCtr(name))
}

func (d *Driver) Unpause(ctx context.Context, name string) error {
	return d.cli.ContainerUnpause(ctx, d.realCtr(name))
}

func (d *Driver) Signal(ctx context.Context, name, signal string) error {
	return d.cli.ContainerKill(ctx, d.realCtr(name), signal)
}

func (d *Driver) Logs(ctx context.Context, name string) (string, error) {
	rc, err := d.cli.ContainerLogs(ctx, d.realCtr(name), container.LogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return "", err
	}
	defer rc.Close()
	var out bytes.Buffer
	if _, err := stdcopy.StdCopy(&out, &out, rc); err != nil {
		return "", err
	}
	return out.String(), nil
}

// Acquire refuses to start a second concurrent run (two runs would collide on the shared
// fabric subnets), then clears any resources a previously-killed run left behind. It detects
// a concurrent run by looking for another process launched from this same binary (via
// internal/singleton, which the node runtime uses for the same "one instance per binary"
// question) rather than a lock file, so a crash never strands a stale lock. Unlike the node,
// which takes over by terminating the old instance, a sim run refuses — two runs racing on
// the same Docker fabrics would corrupt each other rather than hand off cleanly.
func (d *Driver) Acquire(ctx context.Context) error {
	if pids, err := singleton.Others(); err == nil && len(pids) > 0 {
		return fmt.Errorf("another netsim run appears to be active (pid(s) %v); refusing to start a second (they would collide on Docker networks)", pids)
	}
	return d.Cleanup(ctx)
}

// Cleanup force-removes every container and network whose name carries this run's prefix —
// whatever the run created, and any leftovers from an earlier crashed run. It is idempotent
// and safe to call after a partial/interrupted run (the engine defers it, so it also runs on
// SIGINT/SIGTERM via the cancelled context).
func (d *Driver) Cleanup(ctx context.Context) error {
	pfx := d.prefix + "-"
	ctrs, err := d.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err == nil {
		for _, c := range ctrs {
			for _, n := range c.Names {
				if strings.HasPrefix(strings.TrimPrefix(n, "/"), pfx) {
					_ = d.cli.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: true})
					break
				}
			}
		}
	}
	nets, err := d.cli.NetworkList(ctx, network.ListOptions{})
	if err == nil {
		for _, n := range nets {
			if strings.HasPrefix(n.Name, pfx) {
				_ = d.cli.NetworkRemove(ctx, n.ID)
			}
		}
	}
	return nil
}

func envSlice(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(m))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}

// tarFiles builds a tar (rooted at "/") with directory entries for every parent, so
// CopyToContainer can extract absolute-path files into a fresh container.
func tarFiles(files map[string][]byte) io.Reader {
	buf := &bytes.Buffer{}
	tw := tar.NewWriter(buf)
	dirs := map[string]bool{}
	var writeDir func(path string)
	writeDir = func(path string) {
		if path == "" || path == "/" || dirs[path] {
			return
		}
		writeDir(parent(path))
		dirs[path] = true
		_ = tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(path, "/") + "/", Typeflag: tar.TypeDir, Mode: 0o755})
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		writeDir(parent(p))
		content := files[p]
		_ = tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(p, "/"), Mode: 0o644, Size: int64(len(content))})
		_, _ = tw.Write(content)
	}
	_ = tw.Close()
	return buf
}

func parent(path string) string {
	i := strings.LastIndex(path, "/")
	if i <= 0 {
		return "/"
	}
	return path[:i]
}
