package netschema

import (
	"testing"

	"github.com/arash16/dualnet/internal/config"
)

// TestCompileShippedNetwork loads the shipped root schema and checks the derived per-node
// configs. Compile() validates every generated config, so reaching this point proves they
// are internally consistent; here we assert the key derivations.
func TestCompileShippedNetwork(t *testing.T) {
	net, err := Load("../../docs/examples/network-old.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	nodes, err := net.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, name := range []string{"turkish", "router", "vps"} {
		if nodes[name] == nil {
			t.Fatalf("missing generated node %q", name)
		}
	}

	// A link becomes a connect on the dialer and a listen on the acceptor.
	if k := kindOfConn(nodes["router"], "router-up"); k != "connect/outgoing" {
		t.Errorf("router/router-up = %s, want connect/outgoing", k)
	}
	if k := kindOfConn(nodes["turkish"], "router-up"); k != "listen/incoming" {
		t.Errorf("turkish/router-up = %s, want listen/incoming", k)
	}
	// Interface aliases resolve to the real devices.
	if c := findConn(nodes["router"], "router-up"); c == nil || c.Interface != "ppp1" {
		t.Errorf("router/router-up iface = %v, want ppp1 (ftth)", c)
	}
	if c := findConn(nodes["router"], "turkish-router"); c == nil || c.Interface != "nas10" {
		t.Errorf("router/turkish-router iface = %v, want nas10 (starlink)", c)
	}
	// Named egresses carry through (with ext_iface aliases resolved).
	if eg, ok := nodes["router"].Egresses["ftth"]; !ok || eg.Mode != "direct" || eg.ExtIface != "ppp1" {
		t.Errorf("router egress ftth = %+v, want direct/ppp1", eg)
	}
	if eg, ok := nodes["turkish"].Egresses["internet"]; !ok || eg.Mode != "kernel" || eg.ExtIface != "eth0" {
		t.Errorf("turkish egress internet = %+v, want kernel/eth0", eg)
	}

	// The router's LAN path derives the ordered branch rules from Tun: is-iran→ftth,
	// turkey→router-up, fallback→starlink.
	var origin []string
	for _, r := range nodes["router"].Routes {
		if r.Match.Source == "Tun" && !isTrue(r.Match.Processed) {
			origin = append(origin, branchLabel(r))
		}
	}
	want := []string{"[is-iran]egress:ftth", "[turkey]->router-up", "[]egress:starlink"}
	if len(origin) != len(want) {
		t.Fatalf("router origin branches = %v, want %v", origin, want)
	}
	for i := range want {
		if origin[i] != want[i] {
			t.Fatalf("router origin branch %d = %q, want %q (full: %v)", i, origin[i], want[i], origin)
		}
	}

	// The shared Starlink downlink demuxes: deliver to the router's own Tun before relaying
	// to the vps.
	var down []string
	for _, r := range nodes["router"].Routes {
		if r.Match.Source == "turkish-router" && isTrue(r.Match.Processed) {
			down = append(down, r.Action.Target)
		}
	}
	if len(down) != 2 || down[0] != "Tun" || down[1] != "router-vps" {
		t.Fatalf("router turkish-router targets = %v, want [Tun router-vps]", down)
	}

	// The router carries both conditions (is-iran with its inlined file, turkey derived
	// from the lan path); the vps runs its (unreferenced) healthcheck condition anyway.
	if c := findCondition(nodes["router"], "is-iran"); c == nil || c.DstIn == nil || c.DstIn.File == "" {
		t.Errorf("router is-iran condition missing its dst_in file: %+v", c)
	}
	if c := findCondition(nodes["router"], "turkey"); c == nil || c.Healthcheck == nil || len(c.Healthcheck.Up) == 0 || c.Healthcheck.Up[0] != "router-up" {
		t.Errorf("router turkey healthcheck up-path = %+v, want [router-up]", c)
	}
	if !hasCondition(nodes["vps"], "vps-turkey") {
		t.Errorf("vps should carry its healthcheck condition even though unreferenced")
	}

	// Gateway derives one finalize rule per uplink it terminates (router, vps).
	if n := countFinalize(nodes["turkish"]); n != 2 {
		t.Errorf("turkish finalize rules = %d, want 2", n)
	}
}

// TestCompileTunFirstOrdering checks that when a node both owns a tun and relays on the
// same processed source, the tun-target rule is ordered first.
func TestCompileTunFirstOrdering(t *testing.T) {
	net := &Network{
		PSK: "s", MTU: 1360, Subnet: "10.0.0.0/24",
		Protocols: map[string]ProtocolSpec{"udp": {Transport: "udp"}},
		Nodes: map[string]Node{
			"gw":   {IP: "1.1.1.1", Egresses: map[string]config.Egress{"net": {Mode: "kernel", ExtIface: "eth0"}}},
			"mid":  {IP: "2.2.2.2", Connections: map[string]Conn{"T": {Type: "tun", IP: "10.0.0.2"}}},
			"leaf": {Connections: map[string]Conn{"T": {Type: "tun", IP: "10.0.0.3"}}},
		},
		Links: []Link{
			{Name: "mid-up", Dialer: "mid", Acceptor: "gw", Dataflow: "to-acceptor", Protocol: "udp", Port: 1},
			{Name: "leaf-up", Dialer: "leaf", Acceptor: "gw", Dataflow: "to-acceptor", Protocol: "udp", Port: 2},
			{Name: "gw-mid", Dialer: "mid", Acceptor: "gw", Dataflow: "to-dialer", Protocol: "udp", Port: 3},
			{Name: "mid-leaf", Dialer: "leaf", Acceptor: "mid", Dataflow: "to-dialer", Protocol: "udp", Port: 4, Multiple: true, IDSetter: "T"},
		},
		// Gateway is derived (the terminus of the last up-link), not set here.
		Paths: []Path{
			{Node: "mid", Routes: []Branch{{Egress: "net", Up: []string{"mid-up"}, Down: []string{"gw-mid"}}}},
			{Node: "leaf", Routes: []Branch{{Egress: "net", Up: []string{"leaf-up"}, Down: []string{"gw-mid", "mid-leaf"}}}},
		},
	}
	nodes, err := net.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var targets []string
	for _, r := range nodes["mid"].Routes {
		if r.Match.Source == "gw-mid" {
			targets = append(targets, r.Action.Target)
		}
	}
	if len(targets) != 2 || targets[0] != "T" || targets[1] != "mid-leaf" {
		t.Fatalf("mid gw-mid targets = %v, want [T mid-leaf]", targets)
	}
}

func findConn(n *config.Node, name string) *config.Connection {
	for i := range n.Connections {
		if n.Connections[i].Name == name {
			return &n.Connections[i]
		}
	}
	return nil
}

func kindOfConn(n *config.Node, name string) string {
	c := findConn(n, name)
	if c == nil {
		return "missing"
	}
	return c.Type + "/" + c.Direction
}

func countFinalize(n *config.Node) int {
	c := 0
	for _, r := range n.Routes {
		if r.Action.Egress != "" {
			c++
		}
	}
	return c
}

func findCondition(n *config.Node, name string) *config.Condition {
	for i := range n.Conditions {
		if n.Conditions[i].Name == name {
			return &n.Conditions[i]
		}
	}
	return nil
}

func hasCondition(n *config.Node, name string) bool { return findCondition(n, name) != nil }

func isTrue(b *bool) bool { return b != nil && *b }

func branchLabel(r config.Route) string {
	lbl := "["
	for i, c := range r.Match.Conditions {
		if i > 0 {
			lbl += ","
		}
		lbl += c
	}
	lbl += "]"
	if r.Action.Egress != "" {
		return lbl + "egress:" + r.Action.Egress
	}
	return lbl + "->" + r.Action.Target
}
