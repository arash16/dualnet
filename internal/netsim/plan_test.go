package netsim

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/netschema"
	"github.com/arash16/dualnet/internal/netsim/siminit"
	"gopkg.in/yaml.v3"
)

// exampleNet loads the shipped 3-node network (router + turkish + vps).
func exampleNet(t *testing.T) *netschema.Network {
	t.Helper()
	net, err := netschema.Load(filepath.Join("..", "..", "docs", "examples", "network-old.yaml"))
	if err != nil {
		t.Fatalf("load example network: %v", err)
	}
	return net
}

func planExample(t *testing.T) *SimPlan {
	t.Helper()
	sp, err := Plan(exampleNet(t), PlanOptions{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return sp
}

func TestPlanFabricsAndContainers(t *testing.T) {
	sp := planExample(t)

	// The example yields five L2 segments: ftth, starlink, vps↔turkish, turkish's internet
	// uplink, and the router LAN.
	if len(sp.Fabrics) != 5 {
		t.Errorf("fabrics = %d, want 5", len(sp.Fabrics))
	}
	seen := map[string]bool{}
	for _, f := range sp.Fabrics {
		if seen[f.Subnet] {
			t.Errorf("duplicate fabric subnet %s", f.Subnet)
		}
		seen[f.Subnet] = true
	}

	want := map[string]Role{
		"router": RoleNode, "turkish": RoleNode, "vps": RoleNode,
		"internet": RoleHub, "client-router": RoleClient,
	}
	got := map[string]Role{}
	for _, c := range sp.Containers {
		got[c.Name] = c.Role
	}
	for name, role := range want {
		if got[name] != role {
			t.Errorf("container %q role = %q, want %q", name, got[name], role)
		}
	}
	if len(sp.Containers) != len(want) {
		t.Errorf("containers = %d, want %d", len(sp.Containers), len(want))
	}
}

func TestPlanConnectReachability(t *testing.T) {
	net := exampleNet(t)
	sp, err := Plan(net, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	links := map[string]netschema.Link{}
	for _, l := range net.Links {
		links[l.Name] = l
	}

	// Core invariant: every generated `connect` targets an IP the acceptor actually holds on
	// a fabric the dialer is ALSO attached to (i.e. it is reachable on-link), and if the link
	// pins a dialer interface, that interface is the renamed NIC on that same fabric.
	for _, c := range sp.Containers {
		if c.Role != RoleNode {
			continue
		}
		cn := parseConfig(t, c)
		renames := renamesOf(t, c)
		for _, conn := range cn.Connections {
			if conn.Type != "connect" {
				continue
			}
			l := links[conn.Name]
			fab := fabricReaching(sp, c.Name, l.Acceptor, conn.IP)
			if fab == nil {
				t.Errorf("%s connect %q: IP %s is not the acceptor %q on any shared fabric", c.Name, conn.Name, conn.IP, l.Acceptor)
				continue
			}
			if l.DialerSource != "" {
				if conn.Interface == "" {
					t.Errorf("%s connect %q: dialer_iface set but Interface empty", c.Name, conn.Name)
				} else if sub := renames[conn.Interface]; sub != fab.Subnet {
					t.Errorf("%s connect %q: bound iface %q maps to subnet %q, want fabric %q (%s)", c.Name, conn.Name, conn.Interface, sub, fab.Name, fab.Subnet)
				}
			}
		}
	}
}

func TestPlanEgressRewrite(t *testing.T) {
	sp := planExample(t)
	byName := containersByName(sp)

	// router's direct egresses point their gateway at the hub on their own fabric; the
	// observed source IPs (the oracle) are distinct and equal the egress node's fabric IP.
	router := parseConfig(t, byName["router"])
	for name, eg := range router.Egresses {
		if eg.Mode != "direct" {
			t.Errorf("router egress %q mode = %q, want direct", name, eg.Mode)
		}
		fab := fabricByIface(t, sp, "router", eg.ExtIface)
		if eg.Gateway != fab.IPs["internet"] {
			t.Errorf("router egress %q gateway = %q, want hub %q", name, eg.Gateway, fab.IPs["internet"])
		}
		if src := sp.egressIP["router"][name]; src != fab.IPs["router"] {
			t.Errorf("router egress %q oracle src = %q, want %q", name, src, fab.IPs["router"])
		}
	}

	turkish := parseConfig(t, byName["turkish"])
	for name, eg := range turkish.Egresses {
		if eg.Mode != "kernel" {
			t.Errorf("turkish egress %q mode = %q, want kernel", name, eg.Mode)
		}
		// kernel egress needs an explicit route to the echo net via the hub.
		spec := specOf(t, byName["turkish"])
		found := false
		for _, r := range spec.Routes {
			if r.Dst == echoNet && r.Dev == eg.ExtIface {
				found = true
			}
		}
		if !found {
			t.Errorf("turkish egress %q: no echo-net route via hub on %q", name, eg.ExtIface)
		}
	}

	got := map[string]string{
		"ftth":     sp.egressIP["router"]["ftth"],
		"starlink": sp.egressIP["router"]["starlink"],
		"internet": sp.egressIP["turkish"]["internet"],
	}
	if got["ftth"] == got["starlink"] || got["ftth"] == got["internet"] || got["starlink"] == got["internet"] {
		t.Errorf("egress source IPs not distinct: %+v", got)
	}
}

func TestPlanTunAndDebugTun(t *testing.T) {
	sp := planExample(t)
	byName := containersByName(sp)

	hasTun := func(name string) bool {
		for _, d := range byName[name].Devices {
			if d == "/dev/net/tun" {
				return true
			}
		}
		return false
	}
	if !hasTun("router") {
		t.Error("router should expose /dev/net/tun (capture tun)")
	}
	if !hasTun("turkish") {
		t.Error("turkish should expose /dev/net/tun (kernel egress NAT tun)")
	}
	if hasTun("vps") {
		t.Error("vps should NOT expose /dev/net/tun (runs -debug-tun)")
	}
	if !hasArg(byName["vps"].Cmd, "-debug-tun") {
		t.Errorf("vps cmd missing -debug-tun: %v", byName["vps"].Cmd)
	}
	if hasArg(byName["router"].Cmd, "-debug-tun") {
		t.Errorf("router cmd should not have -debug-tun: %v", byName["router"].Cmd)
	}
}

// TestPlanSelfCaptureNode checks the sim generalizes to a capture-tun node with NO `lan:` (a
// client machine that captures its OWN traffic, like the home-bond laptop): it must be marked
// self-capturing (driven from its own container) with NO separate LAN client, while a
// capture-tun node that forwards a LAN (the kernel router) still gets one.
func TestPlanSelfCaptureNode(t *testing.T) {
	net, err := netschema.Load(filepath.Join("..", "..", "docs", "examples", "network.yaml"))
	if err != nil {
		t.Fatalf("load network.yaml: %v", err)
	}
	sp, err := Plan(net, PlanOptions{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	byName := containersByName(sp)

	// The laptop captures its own traffic (tund has no lan:): self-capture, no LAN client.
	if !sp.selfCapture["laptop"] {
		t.Error("laptop (capture tun, no lan) must be marked self-capturing")
	}
	if sp.lanClient["laptop"] != "" {
		t.Errorf("laptop must have no separate LAN client, got %q", sp.lanClient["laptop"])
	}
	if _, ok := byName["client-laptop"]; ok {
		t.Error("no client-laptop container should be created for a self-capturing node")
	}
	// It still runs a real tun (not debug-tun) and exposes /dev/net/tun.
	if sp.debugTun["laptop"] {
		t.Error("a capture tun must not be modelled as debug-tun")
	}
	laptop, ok := byName["laptop"]
	if !ok {
		t.Fatal("no laptop container")
	}
	if !hasArg(laptop.Devices, "/dev/net/tun") {
		t.Errorf("self-capturing laptop must expose /dev/net/tun: %v", laptop.Devices)
	}

	// The kernel router forwards a LAN, so it is NOT self-capturing and DOES get a LAN client.
	if sp.selfCapture["router"] {
		t.Error("the LAN-forwarding kernel router must not be self-capturing")
	}
	if _, ok := byName["client-router"]; !ok {
		t.Error("the LAN-forwarding router should have a LAN client")
	}
}

func TestPlanHubAndClient(t *testing.T) {
	sp := planExample(t)
	byName := containersByName(sp)

	hub := byName["internet"]
	// The hub joins exactly the three egress fabrics (ftth, starlink, turkish uplink).
	if len(hub.Attach) != 3 {
		t.Errorf("hub attachments = %d, want 3", len(hub.Attach))
	}
	hubSpec := specOf(t, hub)
	wantLo := map[string]bool{sp.WorldDst + "/32": false, sp.IranDst + "/32": false}
	for _, a := range hubSpec.LoAddrs {
		if _, ok := wantLo[a]; ok {
			wantLo[a] = true
		}
	}
	for a, ok := range wantLo {
		if !ok {
			t.Errorf("hub missing lo addr %s", a)
		}
	}

	client := byName["client-router"]
	spec := specOf(t, client)
	if len(spec.Routes) != 1 || spec.Routes[0].Dst != "default" {
		t.Fatalf("client should have one default route, got %+v", spec.Routes)
	}
	// The client's default gateway is the router's IP on the LAN fabric.
	lanFab := fabricOfContainer(sp, "client-router")
	if spec.Routes[0].Via != lanFab.IPs["router"] {
		t.Errorf("client default via %q, want router LAN IP %q", spec.Routes[0].Via, lanFab.IPs["router"])
	}
}

func TestPlanFastHealthcheckAndStats(t *testing.T) {
	sp := planExample(t)
	for _, c := range sp.Containers {
		if c.Role != RoleNode {
			continue
		}
		cn := parseConfig(t, c)
		if cn.Healthcheck == nil || *cn.Healthcheck != 1 || cn.HealthcheckTimeout != 3 || cn.HealthcheckUpGrace != 1 {
			t.Errorf("%s healthcheck timing not fast: hc=%v to=%d up=%d", c.Name, cn.Healthcheck, cn.HealthcheckTimeout, cn.HealthcheckUpGrace)
		}
		if cn.StatsFile == "" {
			t.Errorf("%s stats not enabled", c.Name)
		}
	}
}

func TestPlanRejectsWarp(t *testing.T) {
	net := exampleNet(t)
	// Flip an egress to warp; Plan must refuse it (needs the real internet).
	nd := net.Nodes["turkish"]
	eg := nd.Egresses["internet"]
	eg.Mode = "warp"
	nd.Egresses["internet"] = eg
	net.Nodes["turkish"] = nd
	if _, err := Plan(net, PlanOptions{}); err == nil {
		t.Fatal("Plan should reject a warp egress")
	}
}

// --- test helpers ---------------------------------------------------------

func parseConfig(t *testing.T, c Container) *config.Node {
	t.Helper()
	var cn config.Node
	if err := yaml.Unmarshal(c.Files[configDir+"/"+c.Node+".yaml"], &cn); err != nil {
		t.Fatalf("%s: parse config: %v", c.Name, err)
	}
	return &cn
}

func specOf(t *testing.T, c Container) siminit.Spec {
	t.Helper()
	var s siminit.Spec
	if err := json.Unmarshal(c.Files[specPath], &s); err != nil {
		t.Fatalf("%s: parse init spec: %v", c.Name, err)
	}
	return s
}

func renamesOf(t *testing.T, c Container) map[string]string { // dnName -> subnet
	t.Helper()
	out := map[string]string{}
	for _, r := range specOf(t, c).Renames {
		out[r.Name] = r.Subnet
	}
	return out
}

func containersByName(sp *SimPlan) map[string]Container {
	m := map[string]Container{}
	for _, c := range sp.Containers {
		m[c.Name] = c
	}
	return m
}

// fabricReaching returns a fabric on which both `from` and `acceptor` are attached and the
// acceptor's IP equals wantIP, or nil.
func fabricReaching(sp *SimPlan, from, acceptor, wantIP string) *Fabric {
	for i := range sp.Fabrics {
		f := &sp.Fabrics[i]
		if _, ok := f.IPs[from]; ok && f.IPs[acceptor] == wantIP {
			return f
		}
	}
	return nil
}

// fabricByIface returns the fabric a node's renamed NIC belongs to (via the rename subnet).
func fabricByIface(t *testing.T, sp *SimPlan, node, dev string) *Fabric {
	t.Helper()
	sub := renamesOf(t, containersByName(sp)[node])[dev]
	for i := range sp.Fabrics {
		if sp.Fabrics[i].Subnet == sub {
			return &sp.Fabrics[i]
		}
	}
	t.Fatalf("no fabric for %s iface %q (subnet %q)", node, dev, sub)
	return nil
}

func fabricOfContainer(sp *SimPlan, name string) *Fabric {
	for i := range sp.Fabrics {
		if _, ok := sp.Fabrics[i].IPs[name]; ok {
			return &sp.Fabrics[i]
		}
	}
	return nil
}

func hasArg(argv []string, arg string) bool {
	for _, a := range argv {
		if a == arg {
			return true
		}
	}
	return false
}
