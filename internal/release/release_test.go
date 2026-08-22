package release

import (
	"bytes"
	"strings"
	"testing"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/netschema"
)

// TestNoPSKInArtifacts proves that the real PSK must never be baked into a generated
// artifact. `compile -psk <secret>` sets net.PSK, which the compiler copies into every
// config.Node.PSK; that is delivered out-of-band via DUALNET_PSK (k8s Secret / systemd env),
// which overrides the file at runtime — so the ConfigMap and manifests must not embed it. The
// old TestRenderArtifacts only checked for `kind: Secret`/secretKeyRef and ran with the
// placeholder PSK, so it could not detect the ConfigMap embedding.
func TestNoPSKInArtifacts(t *testing.T) {
	net, err := netschema.Load("../../docs/examples/network-old.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	const sentinel = "SENTINEL-REAL-PSK-98f3ac"
	net.PSK = sentinel // exactly what `compile -psk <secret>` / DUALNET_PSK does
	nodes, err := net.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	plan, err := BuildPlan(net, nodes, "/opt/dualnet", "network-old.yaml")
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	arts, err := plan.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, a := range arts {
		if bytes.Contains(a.Data, []byte(sentinel)) {
			t.Errorf("artifact %q embeds the real PSK — it must be delivered via DUALNET_PSK, not baked in", a.Name)
		}
	}
}

// TestBuildPlanShipped derives a plan from the shipped example mesh and checks the build
// matrix and per-node steps that the templates depend on.
func TestBuildPlanShipped(t *testing.T) {
	net, err := netschema.Load("../../docs/examples/network-old.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !HasDeploy(net) {
		t.Fatal("example mesh should declare deploy blocks")
	}
	nodes, err := net.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	plan, err := BuildPlan(net, nodes, "/repo", "network-old.yaml")
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	// Two build recipes, sorted by name: modem (arm/v7 + upx) then server (amd64).
	if got := len(plan.GoBuilds); got != 2 {
		t.Fatalf("GoBuilds = %d, want 2", got)
	}
	modem := plan.GoBuilds[0]
	if modem.Name != "modem" || modem.GOARCH != "arm" || modem.GOARM != "5" || !modem.Upx || modem.Out != "dualnet-modem" {
		t.Errorf("modem build wrong: %+v", modem)
	}
	server := plan.GoBuilds[1]
	if server.Name != "server" || server.GOARCH != "amd64" || server.GOARM != "" || server.Upx {
		t.Errorf("server build wrong: %+v", server)
	}

	// One image build for turkish: amd64, wrapping the server binary (built locally).
	if len(plan.Docker) != 1 {
		t.Fatalf("Docker = %d, want 1", len(plan.Docker))
	}
	if d := plan.Docker[0]; d.Platform != "linux/amd64" || d.Bin != "dualnet-server" {
		t.Errorf("docker build wrong: %+v", d)
	}

	// router + vps are ssh; turkish is k8s.
	if len(plan.SSHNodes) != 2 || len(plan.K8sNodes) != 1 {
		t.Fatalf("nodes: ssh=%d k8s=%d, want 2/1", len(plan.SSHNodes), len(plan.K8sNodes))
	}
	byNode := map[string]SSHPlan{}
	for _, s := range plan.SSHNodes {
		byNode[s.Node] = s
	}
	if r := byNode["router"]; r.Daemonize != "none" || r.BinPath != "/tmp/dualnet" || r.Bin != "dualnet-modem" {
		t.Errorf("router ssh plan wrong: %+v", r)
	}
	if v := byNode["vps"]; v.Daemonize != "systemd" || v.BinPath != "/usr/local/bin/dualnet" || v.Bin != "dualnet-server" {
		t.Errorf("vps ssh plan wrong: %+v", v)
	}
	k := plan.K8sNodes[0]
	if k.Node != "turkish" || k.PullPolicy != "Always" || !k.Privileged {
		t.Errorf("turkish k8s plan wrong: %+v", k)
	}
	if len(k.Ports) != 3 {
		t.Errorf("turkish ports = %d, want 3 (8443/8444/8445): %+v", len(k.Ports), k.Ports)
	}

	// The router's is-iran dst_in file ships from its local source to the config dir (/tmp).
	if len(plan.SSHFiles) != 1 {
		t.Fatalf("SSHFiles = %d, want 1: %+v", len(plan.SSHFiles), plan.SSHFiles)
	}
	if f := plan.SSHFiles[0]; f.Node != "router" || f.Local != "docs/examples/iran.prefixes" || f.Remote != "/tmp/iran.prefixes" {
		t.Errorf("SSHFiles[0] wrong: %+v", f)
	}
}

// TestRenderArtifacts checks the rendered bundle: deploy.sh is present + syntactically
// plausible, the manifest derives correctly, and no real PSK leaks into any artifact.
func TestRenderArtifacts(t *testing.T) {
	net, err := netschema.Load("../../docs/examples/network-old.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	nodes, err := net.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	plan, err := BuildPlan(net, nodes, "/opt/dualnet", "network-old.yaml")
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	arts, err := plan.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	got := map[string]Artifact{}
	for _, a := range arts {
		got[a.Name] = a
	}

	// build.sh carries the build matrix (recipes + images), not the node tables.
	build, ok := got["build.sh"]
	if !ok {
		t.Fatal("no build.sh artifact")
	}
	if build.Mode != 0o755 {
		t.Errorf("build.sh mode = %o, want 755", build.Mode)
	}
	builds := string(build.Data)
	for _, want := range []string{
		"set -uo pipefail",
		"REPO_ROOT=\"${DUALNET_REPO:-/opt/dualnet}\"",
		`"dualnet-modem|arm|5|1"`,
		`"dualnet-server|amd64||0"`,
		"arash16/dualnet:latest|linux/amd64|dualnet-server",
	} {
		if !strings.Contains(builds, want) {
			t.Errorf("build.sh missing %q", want)
		}
	}
	// build.sh must build images locally only — never push to a registry.
	if strings.Contains(builds, "--push") || strings.Contains(builds, "docker push") {
		t.Error("build.sh must not push images (delivery is deploy.sh's job)")
	}

	// deploy.sh carries the node tables and must NOT build (no build matrix).
	sh, ok := got["deploy.sh"]
	if !ok {
		t.Fatal("no deploy.sh artifact")
	}
	if sh.Mode != 0o755 {
		t.Errorf("deploy.sh mode = %o, want 755", sh.Mode)
	}
	shs := string(sh.Data)
	for _, want := range []string{
		"set -uo pipefail",
		"router|router||dualnet-modem|/tmp/dualnet",
		"vps|vps||dualnet-server|/usr/local/bin/dualnet",
		"turkish||default|arash16/dualnet:latest|registry",
		"docker push", // registry delivery lives in deploy.sh, not build.sh
	} {
		if !strings.Contains(shs, want) {
			t.Errorf("deploy.sh missing %q", want)
		}
	}
	if strings.Contains(shs, "GO_BUILDS=") || strings.Contains(shs, "go build") {
		t.Error("deploy.sh must not contain the build phase")
	}

	if _, ok := got["Dockerfile.release"]; !ok {
		t.Error("no Dockerfile.release (expected, there is a k8s image build)")
	}
	man, ok := got["turkish.k8s.yaml"]
	if !ok {
		t.Fatal("no turkish.k8s.yaml artifact")
	}
	mans := string(man.Data)
	for _, want := range []string{
		"kind: ConfigMap",
		"kind: Deployment",
		"imagePullPolicy: Always",
		"privileged: true",
		"containerPort: 8443, protocol: TCP",
		"containerPort: 8444, protocol: UDP",
		"secretKeyRef: { name: dualnet-turkish, key: psk }",
	} {
		if !strings.Contains(mans, want) {
			t.Errorf("manifest missing %q", want)
		}
	}
	// The Secret is created imperatively by deploy.sh, never embedded in the manifest.
	if strings.Contains(mans, "kind: Secret") {
		t.Error("manifest must not embed a Secret")
	}
}

// TestBuildPlanK8sNoListeners rejects a k8s node whose compiled config exposes nothing.
func TestBuildPlanK8sNoListeners(t *testing.T) {
	net := &netschema.Network{
		Builds: map[string]netschema.BuildSpec{"s": {Arch: "amd64"}},
		Nodes: map[string]netschema.Node{
			"g": {Deploy: &netschema.DeploySpec{Mode: "k8s", Build: "s", Image: "img:latest"}},
		},
	}
	nodes := map[string]*config.Node{"g": {Egresses: map[string]config.Egress{"e": {Mode: "kernel"}}}}
	if _, err := BuildPlan(net, nodes, "/repo", "n.yaml"); err == nil {
		t.Fatal("expected an error for a k8s node with no listen connections")
	}
}

// TestHasDeployFalse keeps compile backward compatible when no node declares deploy.
func TestHasDeployFalse(t *testing.T) {
	net := &netschema.Network{Nodes: map[string]netschema.Node{"a": {}}}
	if HasDeploy(net) {
		t.Fatal("HasDeploy should be false with no deploy blocks")
	}
}
