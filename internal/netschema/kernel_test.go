package netschema

import (
	"testing"

	"github.com/arash16/dualnet/internal/config"
)

// validKernelNet returns a minimal network with one kernel-datapath router that steers a
// source-IP leg to FTTH, iran-geo to FTTH, and everything else to Starlink. Negative cases
// below mutate a fresh copy.
func validKernelNet() *Network {
	return &Network{
		Subnet: "10.9.0.0/24",
		Conditions: map[string]ConditionSpec{
			"up-leg":  {SrcIn: &config.IPSet{List: []string{"10.99.0.1/32"}}},
			"is-iran": {DstIn: &config.IPSet{List: []string{"1.2.3.0/24"}}},
		},
		Nodes: map[string]Node{
			"router": {
				Datapath:    "kernel",
				Connections: map[string]Conn{"lan": {Iface: "br0"}, "ftth": {Iface: "ppp1"}, "starlink": {Iface: "nas10"}},
				Egresses: map[string]config.Egress{
					"ftth":     {Mode: "kernel", ExtIface: "ftth"},
					"starlink": {Mode: "kernel", ExtIface: "starlink"},
				},
			},
		},
		Paths: []Path{{Name: "wan", Node: "router", Routes: []Branch{
			{When: []string{"up-leg"}, Egress: "ftth"},
			{When: []string{"is-iran"}, Egress: "ftth"},
			{Egress: "starlink"},
		}}},
	}
}

// TestCompileKernelNode checks a kernel node compiles into a Forward policy, derived LAN
// ifaces, and src_in/dst_in conditions — and that the generated config validates.
func TestCompileKernelNode(t *testing.T) {
	if err := validKernelNet().validate(); err != nil {
		t.Fatalf("baseline kernel net should validate: %v", err)
	}
	nodes, err := validKernelNet().Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	r := nodes["router"]
	if r.Datapath != "kernel" {
		t.Fatalf("router datapath = %q, want kernel", r.Datapath)
	}
	if len(r.Connections) != 0 {
		t.Errorf("kernel node should have no connections, got %d", len(r.Connections))
	}
	if len(r.LANIfaces) != 1 || r.LANIfaces[0] != "br0" {
		t.Errorf("router lan_ifaces = %v, want [br0]", r.LANIfaces)
	}
	// WAN aliases resolve to devices in the egresses.
	if eg := r.Egresses["ftth"]; eg.ExtIface != "ppp1" {
		t.Errorf("egress ftth ext_iface = %q, want ppp1", eg.ExtIface)
	}
	// Forward preserves the branch order: src leg, geo, default.
	if len(r.Forward) != 3 {
		t.Fatalf("router forward = %+v, want 3 branches", r.Forward)
	}
	want := []struct {
		when   string
		egress string
	}{{"up-leg", "ftth"}, {"is-iran", "ftth"}, {"", "starlink"}}
	for i, w := range want {
		f := r.Forward[i]
		got := ""
		if len(f.When) > 0 {
			got = f.When[0]
		}
		if got != w.when || f.Egress != w.egress {
			t.Errorf("forward[%d] = {%v %s}, want {%s %s}", i, f.When, f.Egress, w.when, w.egress)
		}
	}
	// Conditions carry through as src_in / dst_in.
	if c := findCondition(r, "up-leg"); c == nil || c.SrcIn == nil || len(c.SrcIn.List) != 1 {
		t.Errorf("router up-leg src_in missing: %+v", c)
	}
	if c := findCondition(r, "is-iran"); c == nil || c.DstIn == nil {
		t.Errorf("router is-iran dst_in missing: %+v", c)
	}
}

// TestCompileKernelWarpEgress checks a kernel node's warp egress compiles with its exit
// resolved to the underlay device, the WireGuard device name defaulted, and the underlay
// still excluded from the derived LAN set — and that the generated config validates.
func TestCompileKernelWarpEgress(t *testing.T) {
	n := validKernelNet()
	r := n.Nodes["router"]
	r.Egresses["cf"] = config.Egress{Mode: "warp", ExtIface: "starlink", WARPCache: "/var/lib/dualnet/warp.json"}
	n.Nodes["router"] = r
	n.Paths[0].Routes[2].Egress = "cf" // the default branch tunnels out through WARP
	if err := n.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	nodes, err := n.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	eg := nodes["router"].Egresses["cf"]
	if eg.ExtIface != "nas10" {
		t.Errorf("warp exit = %q, want nas10 (the underlay device)", eg.ExtIface)
	}
	if eg.TunName != "warp-cf" {
		t.Errorf("warp device = %q, want warp-cf", eg.TunName)
	}
	if lans := nodes["router"].LANIfaces; len(lans) != 1 || lans[0] != "br0" {
		t.Errorf("lan_ifaces = %v, want [br0] (the warp underlay is a WAN, not a LAN)", lans)
	}
}

func TestValidateKernelRejects(t *testing.T) {
	cases := map[string]func(*Network){
		"src after dst branch": func(n *Network) {
			p := &n.Paths[0]
			p.Routes[0], p.Routes[1] = p.Routes[1], p.Routes[0] // is-iran (dst) before up-leg (src)
		},
		"no default branch": func(n *Network) {
			n.Paths[0].Routes = n.Paths[0].Routes[:2] // drop the {starlink} default
		},
		"two default branches": func(n *Network) {
			n.Paths[0].Routes = append(n.Paths[0].Routes, Branch{Egress: "ftth"})
		},
		"kernel node with tun": func(n *Network) {
			n.Nodes["router"].Connections["T"] = Conn{Type: "tun", IP: "10.9.0.2"}
		},
		"kernel node no egress": func(n *Network) {
			r := n.Nodes["router"]
			r.Egresses = nil
			n.Nodes["router"] = r
		},
		"warp egress without exit": func(n *Network) {
			r := n.Nodes["router"]
			r.Egresses["cf"] = config.Egress{Mode: "warp"}
			n.Nodes["router"] = r
		},
		"direct egress on kernel node": func(n *Network) {
			r := n.Nodes["router"]
			r.Egresses["d"] = config.Egress{Mode: "direct", ExtIface: "starlink"}
			n.Nodes["router"] = r
		},
		"branch egress not on node": func(n *Network) {
			n.Paths[0].Routes[2].Egress = "nope"
		},
		"multi-condition branch": func(n *Network) {
			n.Paths[0].Routes[0].When = []string{"up-leg", "is-iran"}
		},
		"condition sets both dst_in and src_in": func(n *Network) {
			n.Conditions["up-leg"] = ConditionSpec{
				SrcIn: &config.IPSet{List: []string{"10.99.0.1/32"}},
				DstIn: &config.IPSet{List: []string{"1.2.3.0/24"}},
			}
		},
		"ipset file and list": func(n *Network) {
			n.Conditions["is-iran"] = ConditionSpec{DstIn: &config.IPSet{File: "x", List: []string{"1.2.3.0/24"}}}
		},
		"bad source ip": func(n *Network) {
			r := n.Nodes["router"]
			r.Connections = map[string]Conn{"lan": {Iface: "br0"}, "ftth": {Iface: "ppp1"}, "starlink": {Iface: "nas10", IP: "not-an-ip"}}
			n.Nodes["router"] = r
		},
	}
	for name, mutate := range cases {
		n := validKernelNet()
		mutate(n)
		if err := n.validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

// TestValidateSrcInOnUserspaceRejected checks src_in is refused on a userspace (packet-router)
// path — it is a kernel-only mechanism (`ip rule from`).
func TestValidateSrcInOnUserspaceRejected(t *testing.T) {
	n := &Network{
		Subnet:     "10.9.0.0/24",
		Protocols:  map[string]ProtocolSpec{"udp": {Transport: "udp"}},
		Conditions: map[string]ConditionSpec{"up-leg": {SrcIn: &config.IPSet{List: []string{"10.99.0.1/32"}}}},
		Nodes: map[string]Node{
			"gw": {IP: "1.1.1.1", Egresses: map[string]config.Egress{"net": {Mode: "kernel", ExtIface: "eth0"}}},
			"pi": {Connections: map[string]Conn{"T": {Type: "tun", IP: "10.9.0.2"}}},
		},
		Links: []Link{{Name: "pi-up", Dialer: "pi", Acceptor: "gw", Dataflow: "to-acceptor", Protocol: "udp", Port: 1}},
		Paths: []Path{{Name: "lan", Node: "pi", Routes: []Branch{
			{When: []string{"up-leg"}, Egress: "net"},
		}}},
	}
	if err := n.validate(); err == nil {
		t.Fatal("expected src_in on a userspace path to be rejected")
	}
}
