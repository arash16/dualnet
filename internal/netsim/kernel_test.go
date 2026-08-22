package netsim

import (
	"testing"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/netschema"
)

// kernelNet is a home router modelled as a kernel-datapath node: a source-IP up-leg and
// iran-geo steer to FTTH, everything else to Starlink.
func kernelNet() *netschema.Network {
	return &netschema.Network{
		Subnet: "10.9.0.0/24",
		Conditions: map[string]netschema.ConditionSpec{
			"up-leg":  {SrcIn: &config.IPSet{List: []string{"10.99.0.1/32"}}},
			"is-iran": {DstIn: &config.IPSet{File: "iran.prefixes"}},
		},
		Nodes: map[string]netschema.Node{
			"router": {
				Datapath:    "kernel",
				Connections: map[string]netschema.Conn{"lan": {Iface: "br0"}, "ftth": {Iface: "ppp1"}, "starlink": {Iface: "nas10"}},
				Egresses: map[string]config.Egress{
					"ftth":     {Mode: "kernel", ExtIface: "ftth"},
					"starlink": {Mode: "kernel", ExtIface: "starlink"},
				},
			},
		},
		Paths: []netschema.Path{{Name: "wan", Node: "router", Routes: []netschema.Branch{
			{When: []string{"up-leg"}, Egress: "ftth"},
			{When: []string{"is-iran"}, Egress: "ftth"},
			{Egress: "starlink"},
		}}},
	}
}

// TestPlanKernelNode checks the sim models a kernel node: no tun, a LAN client that owns the
// leg source IP, distinct per-WAN egress oracles, and WANs pinned to the hub gateway.
func TestPlanKernelNode(t *testing.T) {
	sp, err := Plan(kernelNet(), PlanOptions{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	byName := containersByName(sp)

	router, ok := byName["router"]
	if !ok {
		t.Fatal("no router container")
	}
	for _, d := range router.Devices {
		if d == "/dev/net/tun" {
			t.Error("kernel node must NOT expose /dev/net/tun")
		}
	}
	if !hasArg(router.CapAdd, "NET_ADMIN") {
		t.Errorf("kernel node needs NET_ADMIN: %v", router.CapAdd)
	}
	if router.Sysctls["net.ipv4.ip_forward"] != "1" {
		t.Errorf("kernel node needs ip_forward=1: %v", router.Sysctls)
	}

	// The kernel router's WANs are pinned to the hub gateway so the sim needs no live default.
	cn := parseConfig(t, router)
	for name, eg := range cn.Egresses {
		fab := fabricByIface(t, sp, "router", eg.ExtIface)
		if eg.Gateway != fab.IPs["internet"] {
			t.Errorf("kernel egress %q gateway = %q, want hub %q", name, eg.Gateway, fab.IPs["internet"])
		}
	}
	// Distinct per-WAN oracles (which egress fired).
	if sp.egressIP["router"]["ftth"] == sp.egressIP["router"]["starlink"] {
		t.Error("ftth and starlink egress oracles must differ")
	}

	client, ok := byName["client-router"]
	if !ok {
		t.Fatal("kernel node should have a LAN client")
	}
	spec := specOf(t, client)
	hasLeg := false
	for _, a := range spec.LoAddrs {
		if a == "10.99.0.1/32" {
			hasLeg = true
		}
	}
	if !hasLeg {
		t.Errorf("LAN client must own the leg source IP to probe from it: %v", spec.LoAddrs)
	}
}

// TestScenariosKernelNode checks the derived kernel-routing matrix: a src_in branch is probed
// from the bound leg IP, a dst_in branch to the geo dst, the default to the world dst, plus a
// SIGHUP reload — each asserting the expected egress source (the oracle).
func TestScenariosKernelNode(t *testing.T) {
	net := kernelNet()
	sp, err := Plan(net, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	scs := Scenarios(net, sp)
	byName := map[string]Scenario{}
	for _, s := range scs {
		byName[s.Name] = s
	}
	ftth := sp.egressIP["router"]["ftth"]
	star := sp.egressIP["router"]["starlink"]

	// src_in: probe from the leg IP to the world dst, expect FTTH.
	if p := firstProbe(byName["route/wan/src-up-leg"]); p == nil {
		t.Fatalf("missing src_in scenario; got %v", names(scs))
	} else if p.SrcIP != "10.99.0.1" || p.Dst != sp.WorldDst || p.ExpectSrc != ftth {
		t.Errorf("src_in probe = %+v (want src-ip 10.99.0.1 → WorldDst src %s)", p, ftth)
	}
	// dst_in: probe to the geo dst, expect FTTH.
	if p := firstProbe(byName["route/wan/dst-is-iran"]); p == nil || p.Dst != sp.IranDst || p.ExpectSrc != ftth {
		t.Errorf("dst_in probe = %+v (want IranDst src %s)", p, ftth)
	}
	// default: probe to the world dst (no source binding), expect Starlink.
	if p := firstProbe(byName["route/wan/default"]); p == nil || p.SrcIP != "" || p.Dst != sp.WorldDst || p.ExpectSrc != star {
		t.Errorf("default probe = %+v (want WorldDst src %s)", p, star)
	}
	// SIGHUP: append WorldDst to the geo file + reload flips it from Starlink to FTTH.
	sh, ok := byName["sighup/wan"]
	if !ok {
		t.Fatalf("missing sighup scenario; got %v", names(scs))
	}
	if !hasStep(sh, OpSignal, sp.nodeContainer["router"]) {
		t.Errorf("sighup must SIGHUP the router: %+v", sh.Steps)
	}
	shp := allProbes(sh)
	if len(shp) != 2 || shp[0].ExpectSrc != star || shp[1].ExpectSrc != ftth {
		t.Errorf("sighup probes = %+v (want before=starlink %s, after=ftth %s)", shp, star, ftth)
	}
}
