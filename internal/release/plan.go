// Package release turns a compiled dualnet network into a self-contained release bundle: a
// deploy.sh that cross-compiles the binary for every build recipe the mesh declares and ships
// each node to its host, plus a thin runtime Dockerfile and one Kubernetes manifest per k8s
// node. It renders text/template files embedded with //go:embed; the deploy work (ssh, rsync,
// docker, kubectl) runs from the generated script at deploy time, so this package links no
// deployment SDKs — nothing in the node runtime imports it (a leaf consumer, like netsim).
package release

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/netschema"
	"gopkg.in/yaml.v3"
)

// Artifact is one generated file: its basename within the out dir, its mode, and its bytes.
type Artifact struct {
	Name string
	Mode os.FileMode
	Data []byte
}

// Plan is the fully-resolved release plan the templates render. It is derived purely from the
// schema and the compiled node configs — defaults are resolved here, never mutated back into
// the schema (mirroring how netschema.Compile builds fresh configs).
type Plan struct {
	RepoRoot  string        // module root where deploy.sh runs `go build .` (overridable via $DUALNET_REPO)
	Network   string        // schema basename, for the banner
	StatsFile string        // stats log cleared on a systemd restart / pulled by --logs ("" = none)
	GoBuilds  []GoBuild     // one per builds: entry (built whether or not deployed), sorted by name
	Docker    []DockerBuild // one per distinct k8s image, sorted by image
	SSHNodes  []SSHPlan     // ssh-mode nodes, sorted by node name
	K8sNodes  []K8sPlan     // k8s-mode nodes, sorted by node name
	SSHFiles  []FileCopy    // condition data files (dst_in) to ship to ssh nodes
}

// FileCopy is one condition data file to ship: its local source (from the schema, relative to
// the repo root unless absolute) and its remote destination (where the node reads it).
type FileCopy struct {
	Node   string
	Local  string
	Remote string
}

// GoBuild is one cross-compile: a build recipe expanded through netschema.ArchBuild.
type GoBuild struct {
	Name   string // build name
	GOARCH string // amd64 | arm64 | arm
	GOARM  string // "7" for arm/v7, else ""
	Upx    bool
	Out    string // artifact filename under dist/ (slash-free), e.g. dualnet-modem
}

// DockerBuild is one runtime image build wrapping a prebuilt binary. It is always built
// locally (buildx --load); delivery (registry push / ctr import) happens at deploy time.
type DockerBuild struct {
	Image    string // -t tag (also the manifest image)
	Platform string // linux/amd64 | linux/arm64 | linux/arm/v7
	Bin      string // the GoBuild.Out it COPYs in
}

// SSHPlan is one ssh-mode node's deploy step.
type SSHPlan struct {
	Node       string
	Host       string // ssh destination (alias, host, or user@host)
	SSHOpts    string // assembled "-p N -i key" ("" for a plain alias)
	Bin        string // the GoBuild.Out this node ships
	BinPath    string // remote binary path
	ConfigPath string // remote config path
	ConfigFile string // local compiled config basename, e.g. vps.yaml
	Daemonize  string // none | systemd
	Unit       string // systemd unit name
	RestartB64 string // base64(restart_cmd), decoded locally before running remotely ("" = none)
}

// K8sPlan is one k8s-mode node's deploy step plus the data its manifest needs.
type K8sPlan struct {
	Node       string
	Context    string // kubectl context ("" = current)
	Namespace  string
	Image      string
	Method     string // registry | ctr
	ImportHost string // method=ctr: ssh host to import into
	Manifest   string // generated manifest basename, e.g. turkish.k8s.yaml
	Deployment string // Deployment/ConfigMap/Secret base name

	// manifest-rendering fields, derived from the compiled config
	Variant    string // hostNetwork | service
	Privileged bool   // any kernel/direct egress or a local tun
	PullPolicy string // ctr -> IfNotPresent, registry -> Always
	Ports      []Port
	ConfigYAML string // the compiled <node>.yaml, embedded inline as the ConfigMap
}

// Port is one listen port exposed by a k8s gateway.
type Port struct {
	Port     int
	Protocol string // TCP | UDP
}

// HasDeploy reports whether any node declares a deploy block, so callers can skip release
// generation entirely and stay backward compatible when no deployment is configured.
func HasDeploy(net *netschema.Network) bool {
	for _, nd := range net.Nodes {
		if nd.Deploy != nil {
			return true
		}
	}
	return false
}

// BuildPlan resolves defaults and derives the build matrix + per-node steps from a network
// schema and its compiled node configs. repoRoot is the module root deploy.sh builds; network
// is the schema basename for the banner. Errors use the release: prefix.
func BuildPlan(net *netschema.Network, nodes map[string]*config.Node, repoRoot, network string) (*Plan, error) {
	p := &Plan{RepoRoot: repoRoot, Network: network, StatsFile: net.StatsFile}

	// Build every declared recipe (an arch may be built without being deployed).
	buildNames := sortedKeys(net.Builds)
	for _, name := range buildNames {
		b := net.Builds[name]
		goarch, goarm, _, ok := netschema.ArchBuild(b.Arch)
		if !ok { // already rejected by validate(); defend anyway
			return nil, fmt.Errorf("release: build %q has unsupported arch %q", name, b.Arch)
		}
		p.GoBuilds = append(p.GoBuilds, GoBuild{
			Name: name, GOARCH: goarch, GOARM: goarm, Upx: b.Upx, Out: "dualnet-" + name,
		})
	}

	// Per distinct k8s image, one runtime image build. Detect a platform/bin conflict.
	dockerByImage := map[string]DockerBuild{}
	for _, name := range sortedKeys(net.Nodes) {
		nd := net.Nodes[name]
		d := nd.Deploy
		if d == nil {
			continue
		}
		cn := nodes[name]
		if cn == nil {
			return nil, fmt.Errorf("release: node %q has a deploy block but no compiled config", name)
		}
		switch d.Mode {
		case "ssh":
			p.SSHNodes = append(p.SSHNodes, sshPlan(name, d, "dualnet-"+d.Build))
			p.SSHFiles = append(p.SSHFiles, conditionFiles(net, name, cn)...)
		case "k8s":
			for _, c := range cn.Conditions {
				if c.DstIn != nil && c.DstIn.File != "" {
					return nil, fmt.Errorf("release: k8s node %q references dst_in file %q — shipping condition files to k8s nodes is not supported yet (mount it via the manifest)", name, c.DstIn.File)
				}
				if c.SrcIn != nil && c.SrcIn.File != "" {
					return nil, fmt.Errorf("release: k8s node %q references src_in file %q — shipping condition files to k8s nodes is not supported yet (mount it via the manifest)", name, c.SrcIn.File)
				}
			}
			k, db, err := k8sPlan(name, d, net.Builds[d.Build].Arch, cn)
			if err != nil {
				return nil, err
			}
			if prev, dup := dockerByImage[db.Image]; dup && (prev.Platform != db.Platform || prev.Bin != db.Bin) {
				return nil, fmt.Errorf("release: image %q is built two incompatible ways (%s/%s vs %s/%s)",
					db.Image, prev.Platform, prev.Bin, db.Platform, db.Bin)
			}
			dockerByImage[db.Image] = db
			p.K8sNodes = append(p.K8sNodes, k)
		default:
			return nil, fmt.Errorf("release: node %q has unknown deploy mode %q", name, d.Mode)
		}
	}
	for _, img := range sortedKeys(dockerByImage) {
		p.Docker = append(p.Docker, dockerByImage[img])
	}
	return p, nil
}

// sshPlan resolves an ssh node's defaults into an SSHPlan.
func sshPlan(node string, d *netschema.DeploySpec, bin string) SSHPlan {
	host := orDefault(d.Host, node)
	// -o form (not -p/-i) so the same opts string works for ssh, rsync -e, and scp alike
	// (scp's -p means "preserve times", not port).
	var opts []string
	if d.Port != 0 {
		opts = append(opts, fmt.Sprintf("-o Port=%d", d.Port))
	}
	if d.Key != "" {
		opts = append(opts, "-o IdentityFile="+d.Key)
	}
	if d.User != "" && !strings.Contains(host, "@") {
		host = d.User + "@" + host
	}
	restart := ""
	if d.RestartCmd != "" {
		restart = base64Std(d.RestartCmd)
	}
	return SSHPlan{
		Node:       node,
		Host:       host,
		SSHOpts:    strings.Join(opts, " "),
		Bin:        bin,
		BinPath:    orDefault(d.BinPath, "/usr/local/bin/dualnet"),
		ConfigPath: orDefault(d.ConfigPath, "/etc/dualnet/node.yaml"),
		ConfigFile: node + ".yaml",
		Daemonize:  orDefault(d.Daemonize, "none"),
		Unit:       orDefault(d.Unit, "dualnet"),
		RestartB64: restart,
	}
}

// k8sPlan resolves a k8s node's defaults and derives its manifest data from the compiled config.
func k8sPlan(node string, d *netschema.DeploySpec, arch string, cn *config.Node) (K8sPlan, DockerBuild, error) {
	_, _, platform, ok := netschema.ArchBuild(arch)
	if !ok {
		return K8sPlan{}, DockerBuild{}, fmt.Errorf("release: node %q build arch %q unsupported", node, arch)
	}
	method := orDefault(d.Method, "registry")
	deployment := orDefault(d.DeploymentName, "dualnet-"+node)

	ports := listenPorts(cn)
	if len(ports) == 0 {
		return K8sPlan{}, DockerBuild{}, fmt.Errorf("release: k8s node %q has no listen connections to expose", node)
	}
	// Strip the PSK: the ConfigMap is applied to the cluster (readable via RBAC), and the pod
	// gets the real PSK from the Secret via DUALNET_PSK, which overrides the config's psk.
	cfgYAML, err := yaml.Marshal(cn.ForArtifact())
	if err != nil {
		return K8sPlan{}, DockerBuild{}, fmt.Errorf("release: marshal %q config: %w", node, err)
	}
	pull := "Always"
	if method == "ctr" {
		pull = "IfNotPresent"
	}
	k := K8sPlan{
		Node:       node,
		Context:    d.Context,
		Namespace:  orDefault(d.Namespace, "default"),
		Image:      d.Image,
		Method:     method,
		ImportHost: orDefault(d.ImportHost, node),
		Manifest:   node + ".k8s.yaml",
		Deployment: deployment,
		Variant:    orDefault(d.Manifest, "hostNetwork"),
		Privileged: needsPrivilege(cn),
		PullPolicy: pull,
		Ports:      ports,
		ConfigYAML: string(cfgYAML),
	}
	db := DockerBuild{Image: d.Image, Platform: platform, Bin: "dualnet-" + d.Build}
	return k, db, nil
}

// conditionFiles pairs each file-based dst_in / src_in condition's schema-declared local source
// with the remote path the compiled config reads it from, so deploy.sh can ship them to the
// node. List-based conditions carry their tokens inline and need no file copy.
func conditionFiles(net *netschema.Network, node string, cn *config.Node) []FileCopy {
	var fs []FileCopy
	for _, c := range cn.Conditions {
		sc, ok := net.Conditions[c.Name]
		if !ok {
			continue
		}
		if c.DstIn != nil && c.DstIn.File != "" && sc.DstIn != nil {
			fs = append(fs, FileCopy{Node: node, Local: sc.DstIn.File, Remote: c.DstIn.File})
		}
		if c.SrcIn != nil && c.SrcIn.File != "" && sc.SrcIn != nil {
			fs = append(fs, FileCopy{Node: node, Local: sc.SrcIn.File, Remote: c.SrcIn.File})
		}
	}
	return fs
}

// listenPorts extracts the exposed ports from a compiled node's listen connections.
func listenPorts(cn *config.Node) []Port {
	var ports []Port
	for _, c := range cn.Connections {
		if c.Type != "listen" || c.Port == 0 {
			continue
		}
		proto := "TCP"
		if c.Transport == "udp" {
			proto = "UDP"
		}
		ports = append(ports, Port{Port: c.Port, Protocol: proto})
	}
	return ports
}

// needsPrivilege reports whether a node needs a privileged container + NET_ADMIN: a kernel
// datapath (ip rule/route + iptables + ip_forward), any kernel/direct egress (iptables/sysctl),
// or a local tun.
func needsPrivilege(cn *config.Node) bool {
	if cn.Datapath == "kernel" {
		return true
	}
	for _, eg := range cn.Egresses {
		if eg.Mode == "kernel" || eg.Mode == "direct" {
			return true
		}
	}
	for _, c := range cn.Connections {
		if c.Type == "tun" {
			return true
		}
	}
	return false
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
