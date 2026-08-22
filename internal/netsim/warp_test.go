package netsim

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/netschema"
	"github.com/arash16/dualnet/internal/warp"
)

// writeTempFromBytes writes b to a temp file and returns its path, so a generated profile can
// be handed to the real warp.LoadConfig (which reads from disk).
func writeTempFromBytes(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "profile.conf")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// kernelWarpNet is a kernel router whose default branch tunnels out through WARP; iran-geo
// stays on the physical FTTH WAN. The warp egress's exit (starlink) is the underlay the
// tunnel rides.
func kernelWarpNet() *netschema.Network {
	return &netschema.Network{
		Subnet: "10.9.0.0/24",
		Conditions: map[string]netschema.ConditionSpec{
			"is-iran": {DstIn: &config.IPSet{File: "iran.prefixes"}},
		},
		Nodes: map[string]netschema.Node{
			"router": {
				Datapath:    "kernel",
				Connections: map[string]netschema.Conn{"lan": {Iface: "br0"}, "ftth": {Iface: "ppp1"}, "starlink": {Iface: "nas10"}},
				Egresses: map[string]config.Egress{
					"ftth": {Mode: "kernel", ExtIface: "ftth"},
					"warp": {Mode: "warp", ExtIface: "starlink"},
				},
			},
		},
		Paths: []netschema.Path{{Name: "wan", Node: "router", Routes: []netschema.Branch{
			{When: []string{"is-iran"}, Egress: "ftth"},
			{Egress: "warp"},
		}}},
	}
}

// TestPlanKernelWarp checks the sim models a kernel-warp egress as a real WireGuard tunnel to
// the hub: the hub gets a WireGuard device with the router as a peer, the router gets a
// wgcf-style profile its config points at, and the warp oracle is the generated tunnel address
// (distinct from any underlay IP) — while the node still opens no tun.
func TestPlanKernelWarp(t *testing.T) {
	sp, err := Plan(kernelWarpNet(), PlanOptions{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !sp.NeedsWireGuard {
		t.Error("a kernel-warp plan must set NeedsWireGuard")
	}
	byName := containersByName(sp)

	router := byName["router"]
	for _, d := range router.Devices {
		if d == "/dev/net/tun" {
			t.Error("a kernel-warp node still opens no tun")
		}
	}
	cn := parseConfig(t, router)
	eg := cn.Egresses["warp"]
	if eg.Mode != "warp" {
		t.Fatalf("warp egress mode = %q", eg.Mode)
	}
	confPath := configDir + "/warp-warp.conf"
	if eg.WARPConfig != confPath {
		t.Errorf("warp_config = %q, want %q", eg.WARPConfig, confPath)
	}
	if eg.WARPCache != "" {
		t.Errorf("warp_cache = %q, want empty (the sim never reaches Cloudflare)", eg.WARPCache)
	}

	// The oracle is the tunnel address, not the underlay fabric IP.
	tunIP := sp.egressIP["router"]["warp"]
	if tunIP != "100.64.0.2" {
		t.Errorf("warp oracle = %q, want 100.64.0.2", tunIP)
	}
	underlay := fabricByIface(t, sp, "router", eg.ExtIface).IPs["router"]
	if tunIP == underlay {
		t.Errorf("warp oracle %q must differ from the underlay IP %q", tunIP, underlay)
	}

	// The emitted profile round-trips through the real loader the runtime uses, and names the
	// hub as its peer/endpoint.
	prof := writeTempFromBytes(t, router.Files[confPath])
	acct, err := warp.LoadConfig(prof)
	if err != nil {
		t.Fatalf("generated profile does not parse: %v", err)
	}
	if acct.V4 != tunIP {
		t.Errorf("profile address = %q, want the tunnel IP %q", acct.V4, tunIP)
	}
	hubUnderlay := fabricByIface(t, sp, "router", eg.ExtIface).IPs["internet"]
	wantEndpoint := hubUnderlay + ":51820"
	if acct.EndpointHost != wantEndpoint {
		t.Errorf("profile endpoint = %q, want the hub %q", acct.EndpointHost, wantEndpoint)
	}

	// The hub terminates the tunnel: one WireGuard device with the router as a peer whose
	// allowed-ips is the router's tunnel /32, keyed to match warpKeys.
	hub := byName["internet"]
	hs := specOf(t, hub)
	if len(hs.WGDevices) != 1 {
		t.Fatalf("hub WGDevices = %+v, want exactly one", hs.WGDevices)
	}
	d := hs.WGDevices[0]
	if d.Name != warpHubDev || d.ListenPort != warpPort || len(d.Addrs) != 1 || d.Addrs[0] != warpHubIP+"/24" {
		t.Errorf("hub wg device = %+v, want %s :%d %s/24", d, warpHubDev, warpPort, warpHubIP)
	}
	_, wantPub := warpKeys("router/warp")
	if len(d.Peers) != 1 || d.Peers[0].PublicKey != wantPub.String() || len(d.Peers[0].AllowedIPs) != 1 || d.Peers[0].AllowedIPs[0] != tunIP+"/32" {
		t.Errorf("hub peer = %+v, want pubkey %s allowed %s/32", d.Peers, wantPub, tunIP)
	}
}

// TestPlanKernelWarpDeterministic pins that Plan stays reproducible with a warp egress: two
// runs emit byte-identical profiles and hub device specs (keys are hashed, not random).
func TestPlanKernelWarpDeterministic(t *testing.T) {
	a, err := Plan(kernelWarpNet(), PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Plan(kernelWarpNet(), PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pa := containersByName(a)["router"].Files[configDir+"/warp-warp.conf"]
	pb := containersByName(b)["router"].Files[configDir+"/warp-warp.conf"]
	if string(pa) != string(pb) {
		t.Errorf("warp profile is not deterministic:\n%s\n---\n%s", pa, pb)
	}
	if string(specOf(t, containersByName(a)["internet"]).WGDevices[0].PrivateKey) !=
		string(specOf(t, containersByName(b)["internet"]).WGDevices[0].PrivateKey) {
		t.Error("hub key is not deterministic")
	}
}

// TestScenariosKernelWarp checks the derived matrix routes the default branch through the warp
// tunnel (oracle = tunnel IP) while the geo branch stays on the physical WAN.
func TestScenariosKernelWarp(t *testing.T) {
	net := kernelWarpNet()
	sp, err := Plan(net, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Scenario{}
	for _, s := range Scenarios(net, sp) {
		byName[s.Name] = s
	}
	warpIP := sp.egressIP["router"]["warp"]
	ftth := sp.egressIP["router"]["ftth"]

	if p := firstProbe(byName["route/wan/default"]); p == nil || p.Dst != sp.WorldDst || p.ExpectSrc != warpIP {
		t.Errorf("default probe = %+v (want WorldDst src %s = the warp tunnel)", p, warpIP)
	}
	if p := firstProbe(byName["route/wan/dst-is-iran"]); p == nil || p.Dst != sp.IranDst || p.ExpectSrc != ftth {
		t.Errorf("dst_in probe = %+v (want IranDst src %s = FTTH underlay)", p, ftth)
	}
}

// TestPlanRejectsUserspaceWarpEgress pins that only the kernel datapath's warp is simulable:
// a userspace warp egress is still rejected (it needs the real Cloudflare WARP).
func TestPlanRejectsUserspaceWarpEgress(t *testing.T) {
	net := &netschema.Network{
		Subnet:    "10.9.0.0/24",
		Protocols: map[string]netschema.ProtocolSpec{"udp": {Transport: "udp"}},
		Nodes: map[string]netschema.Node{
			"gw": {IP: "1.1.1.1", Egresses: map[string]config.Egress{"w": {Mode: "warp"}}},
			"pi": {Connections: map[string]netschema.Conn{"T": {Type: "tun", IP: "10.9.0.2", CaptureDefault: true}}},
		},
		Links: []netschema.Link{{Name: "pi-up", Dialer: "pi", Acceptor: "gw", Dataflow: "to-acceptor", Protocol: "udp", Port: 1}},
		Paths: []netschema.Path{{Name: "lan", Node: "pi", Routes: []netschema.Branch{{Gateway: "gw", Egress: "w"}}}},
	}
	if _, err := Plan(net, PlanOptions{}); err == nil {
		t.Fatal("expected a userspace warp egress to be rejected")
	}
}

// TestPlanWithoutWarpNeedsNoWireGuard pins that a plain kernel plan never triggers the
// WireGuard host-module probe.
func TestPlanWithoutWarpNeedsNoWireGuard(t *testing.T) {
	sp, err := Plan(kernelNet(), PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sp.NeedsWireGuard {
		t.Error("a non-warp plan must not set NeedsWireGuard")
	}
}
