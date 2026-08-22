//go:build e2e

// Package e2e runs the netsim engine against the shipped example network on a real Docker
// daemon: it builds the test image, stands up router + turkish + vps + the simulated
// internet + a LAN client, and asserts every scenario the network derives (tunnel happy
// path, geo/dst_in direct, healthcheck failover + self-heal, vps-origin round-trip, SIGHUP
// prefix reload, no-leak stats) plus the PSK-mismatch negative. It is fully offline.
//
//	go test -tags e2e ./test/e2e            # needs a reachable Docker daemon
//
// It skips (not fails) when Docker is unreachable, so a plain `go test ./...` is unaffected.
package e2e

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/netschema"
	"github.com/arash16/dualnet/internal/netsim"
	"github.com/arash16/dualnet/internal/netsim/dockerdriver"
)

func TestExampleNetworkE2E(t *testing.T) {
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker not available: %v", err)
	}

	repoRoot, _ := filepath.Abs(filepath.Join("..", ".."))
	net, err := netschema.Load(filepath.Join(repoRoot, "docs", "examples", "network-old.yaml"))
	if err != nil {
		t.Fatalf("load network: %v", err)
	}
	// A prefix disjoint from the CLI's "netsim" (not "netsim-…"), so neither run's
	// prefix-scoped cleanup ever touches the other's resources.
	driver, err := dockerdriver.New("netsime2e")
	if err != nil {
		t.Fatalf("docker driver: %v", err)
	}

	// A generous ceiling; scenarios themselves poll with their own shorter deadlines.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	opts := netsim.RunOptions{
		Build:      true,
		Dockerfile: filepath.Join(repoRoot, "test", "sim", "Dockerfile"),
		ContextDir: repoRoot,
		Log:        func(s string) { t.Log(s) },
	}

	rep, err := netsim.Run(ctx, net, driver, opts)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// PSK-mismatch negative: its own broken mesh, image already built.
	opts.Build = false
	pskRep, err := netsim.RunPSKMismatch(ctx, net, driver, opts)
	if err != nil {
		t.Fatalf("psk-mismatch run: %v", err)
	}
	rep.Results = append(rep.Results, pskRep.Results...)

	if len(rep.Results) == 0 {
		t.Fatal("no scenarios ran")
	}
	for _, r := range rep.Results {
		if r.Pass {
			t.Logf("PASS %s — %s", r.Scenario, r.Detail)
		} else {
			t.Errorf("FAIL %s — %s", r.Scenario, r.Detail)
		}
	}
}

// TestKernelWarpE2E stands up a kernel-datapath router whose default branch exits through a
// real kernel WireGuard tunnel to the hub (playing Cloudflare WARP): it asserts the geo/leg
// branches stay on their physical WANs while the default branch's traffic emerges from the
// generated tunnel address — proving the wg device comes up, handshakes, routes, and
// masquerades. It skips when Docker is unreachable or the host kernel lacks the wireguard
// module, so neither a plain `go test ./...` nor a module-less CI is affected.
func TestKernelWarpE2E(t *testing.T) {
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker not available: %v", err)
	}

	repoRoot, _ := filepath.Abs(filepath.Join("..", ".."))
	net, err := netschema.Load(filepath.Join(repoRoot, "docs", "examples", "kernel-warp.yaml"))
	if err != nil {
		t.Fatalf("load network: %v", err)
	}
	// A prefix disjoint from the other e2e runs so prefix-scoped cleanup never crosses over.
	driver, err := dockerdriver.New("netsimwarp")
	if err != nil {
		t.Fatalf("docker driver: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	opts := netsim.RunOptions{
		Build:      true,
		Dockerfile: filepath.Join(repoRoot, "test", "sim", "Dockerfile"),
		ContextDir: repoRoot,
		Log:        func(s string) { t.Log(s) },
	}

	rep, err := netsim.Run(ctx, net, driver, opts)
	if err != nil {
		if errors.Is(err, netsim.ErrNoKernelWireGuard) {
			t.Skip(err)
		}
		t.Fatalf("run: %v", err)
	}

	if len(rep.Results) == 0 {
		t.Fatal("no scenarios ran")
	}
	for _, r := range rep.Results {
		if r.Pass {
			t.Logf("PASS %s — %s", r.Scenario, r.Detail)
		} else {
			t.Errorf("FAIL %s — %s", r.Scenario, r.Detail)
		}
	}
}
