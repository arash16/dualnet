package netschema

import (
	"strings"
	"testing"

	"github.com/arash16/dualnet/internal/config"
)

// Two branches of one path that travel the same link and only part ways further along —
// a per-destination exception routed to the same gateway as everything else, say — derive
// rules with an identical {processed,source} match at the point they diverge, because only
// the origin rule carries the branch condition. The router takes the first accepting target,
// so without help the later branch is dead. Compile restates the branch's dst_in condition
// on the diverging rule; these tests pin that down (and the cases where it must not, or
// cannot, be done).

// splitNet builds a leaf→gw mesh whose path sends both branches up the SAME link and
// finalizes them through different egresses at the gateway.
func splitNet(when []string, conds map[string]ConditionSpec) *Network {
	return &Network{
		PSK: "s", MTU: 1360, Subnet: "10.0.0.0/24",
		Protocols:  map[string]ProtocolSpec{"udp": {Transport: "udp"}},
		Conditions: conds,
		Nodes: map[string]Node{
			"gw": {IP: "1.1.1.1", Egresses: map[string]config.Egress{
				"a": {Mode: "kernel", ExtIface: "eth0"},
				"b": {Mode: "kernel", ExtIface: "eth1"},
			}},
			"leaf": {Connections: map[string]Conn{"T": {Type: "tun", IP: "10.0.0.2", CaptureDefault: true}}},
		},
		Links: []Link{
			{Name: "leaf-up", Dialer: "leaf", Acceptor: "gw", Dataflow: "to-acceptor", Protocol: "udp", Port: 1},
			{Name: "gw-leaf", Dialer: "leaf", Acceptor: "gw", Dataflow: "to-dialer", Protocol: "udp", Port: 2, Multiple: true, IDSetter: "T"},
		},
		Paths: []Path{
			{Name: "leaf", Node: "leaf", Routes: []Branch{
				{When: when, Egress: "a", Up: []string{"leaf-up"}, Down: []string{"gw-leaf"}},
				{Egress: "b", Up: []string{"leaf-up"}, Down: []string{"gw-leaf"}},
			}},
		},
	}
}

// unprocessedFrom returns a node's unprocessed rules arriving on source, in table order.
func unprocessedFrom(n *config.Node, source string) []config.Route {
	var rs []config.Route
	for _, r := range n.Routes {
		if r.Match.Source == source && !isTrue(r.Match.Processed) {
			rs = append(rs, r)
		}
	}
	return rs
}

// TestCompileSplitsGatewayByDstCondition covers the exception-route case: everything goes up
// one link to the gateway, but the branch matching a destination set finalizes through a
// different egress there. The gateway must get both finalize rules, the conditional one FIRST
// (the router takes the first accepting target) and guarded by the branch's dst_in set, which
// must also be emitted onto the gateway so its guard resolves.
func TestCompileSplitsGatewayByDstCondition(t *testing.T) {
	net := splitNet([]string{"is-svc"}, map[string]ConditionSpec{
		"is-svc": {DstIn: &config.IPSet{List: []string{"203.0.113.0/24"}}},
	})
	nodes, err := net.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rs := unprocessedFrom(nodes["gw"], "leaf-up")
	if len(rs) != 2 {
		t.Fatalf("gw rules from leaf-up = %d, want 2 (one per branch): %+v", len(rs), rs)
	}
	if got := branchLabel(rs[0]); got != "[is-svc]egress:a" {
		t.Errorf("gw first rule = %s, want [is-svc]egress:a (the exception must be tried first)", got)
	}
	if got := branchLabel(rs[1]); got != "[]egress:b" {
		t.Errorf("gw second rule = %s, want []egress:b (the default catch-all)", got)
	}
	if c := findCondition(nodes["gw"], "is-svc"); c == nil || c.DstIn == nil {
		t.Errorf("gw must carry the is-svc dst_in set its restated rule guards on: %+v", c)
	}
	// The origin is untouched: both branches still leave over the shared up-link.
	for _, r := range unprocessedFrom(nodes["leaf"], "T") {
		if r.Action.Target != "leaf-up" {
			t.Errorf("leaf rule %s should still target leaf-up", branchLabel(r))
		}
	}
}

// TestCompileRestatesOnlyWhereBranchesDiverge covers that the restatement is placed only where
// it is needed: a gateway reached by ONE branch keeps an unconditional rule, and is not made to
// carry (nor be shipped) a condition set it never has to evaluate.
func TestCompileRestatesOnlyWhereBranchesDiverge(t *testing.T) {
	net := splitNet([]string{"is-svc"}, map[string]ConditionSpec{
		"is-svc": {DstIn: &config.IPSet{List: []string{"203.0.113.0/24"}}},
	})
	// Default branch exits locally instead of sharing the up-link, so nothing diverges at gw.
	net.Nodes["leaf"] = Node{
		Connections: map[string]Conn{"T": {Type: "tun", IP: "10.0.0.2", CaptureDefault: true}},
		Egresses:    map[string]config.Egress{"local": {Mode: "direct", ExtIface: "eth0"}},
	}
	net.Paths[0].Routes[1] = Branch{Egress: "local"}
	nodes, err := net.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rs := unprocessedFrom(nodes["gw"], "leaf-up")
	if len(rs) != 1 || len(rs[0].Match.Conditions) != 0 {
		t.Fatalf("gw rules from leaf-up = %+v, want a single unconditional finalize rule", rs)
	}
	if hasCondition(nodes["gw"], "is-svc") {
		t.Error("gw must not carry a condition it never evaluates (its data file would be shipped for nothing)")
	}
}

// TestCompileSplitsRelayByDstCondition covers a divergence BEFORE the gateway: two branches
// share their first hop and then head to different gateways. The relay in the middle sees one
// arrival connection and two targets, so it needs the same restatement the gateway case does —
// otherwise its first rule swallows every packet and the second branch never happens.
func TestCompileSplitsRelayByDstCondition(t *testing.T) {
	net := &Network{
		PSK: "s", MTU: 1360, Subnet: "10.0.0.0/24",
		Protocols:  map[string]ProtocolSpec{"udp": {Transport: "udp"}},
		Conditions: map[string]ConditionSpec{"is-svc": {DstIn: &config.IPSet{List: []string{"203.0.113.0/24"}}}},
		Nodes: map[string]Node{
			"gwa":  {IP: "1.1.1.1", Egresses: map[string]config.Egress{"net": {Mode: "kernel", ExtIface: "eth0"}}},
			"gwb":  {IP: "2.2.2.2", Egresses: map[string]config.Egress{"net": {Mode: "kernel", ExtIface: "eth0"}}},
			"mid":  {IP: "3.3.3.3"},
			"leaf": {Connections: map[string]Conn{"T": {Type: "tun", IP: "10.0.0.2", CaptureDefault: true}}},
		},
		Links: []Link{
			{Name: "leaf-up", Dialer: "leaf", Acceptor: "mid", Dataflow: "to-acceptor", Protocol: "udp", Port: 1},
			{Name: "mid-a", Dialer: "mid", Acceptor: "gwa", Dataflow: "to-acceptor", Protocol: "udp", Port: 2},
			{Name: "mid-b", Dialer: "mid", Acceptor: "gwb", Dataflow: "to-acceptor", Protocol: "udp", Port: 3},
			{Name: "a-mid", Dialer: "mid", Acceptor: "gwa", Dataflow: "to-dialer", Protocol: "udp", Port: 4},
			{Name: "b-mid", Dialer: "mid", Acceptor: "gwb", Dataflow: "to-dialer", Protocol: "udp", Port: 5},
			{Name: "mid-leaf", Dialer: "leaf", Acceptor: "mid", Dataflow: "to-dialer", Protocol: "udp", Port: 6, Multiple: true, IDSetter: "T"},
		},
		Paths: []Path{
			{Node: "leaf", Routes: []Branch{
				{When: []string{"is-svc"}, Egress: "net", Up: []string{"leaf-up", "mid-a"}, Down: []string{"a-mid", "mid-leaf"}},
				{Egress: "net", Up: []string{"leaf-up", "mid-b"}, Down: []string{"b-mid", "mid-leaf"}},
			}},
		},
	}
	nodes, err := net.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rs := unprocessedFrom(nodes["mid"], "leaf-up")
	if len(rs) != 2 {
		t.Fatalf("mid rules from leaf-up = %d, want 2 (one per branch): %+v", len(rs), rs)
	}
	if got := branchLabel(rs[0]); got != "[is-svc]->mid-a" {
		t.Errorf("mid first rule = %s, want [is-svc]->mid-a", got)
	}
	if got := branchLabel(rs[1]); got != "[]->mid-b" {
		t.Errorf("mid second rule = %s, want []->mid-b", got)
	}
	if !hasCondition(nodes["mid"], "is-svc") {
		t.Error("mid must carry the is-svc set its restated rule guards on")
	}
}

// TestCompileRejectsDefaultBeforeConditionalSplit covers the ordering the restatement depends
// on: an unconditional branch placed above a conditional one matches every packet arriving at
// the divergence point, leaving the conditional branch dead. The schema forbids a branch after
// the default, so this only reaches Compile through a hand-built network — which must still
// refuse it rather than emit a table with an unreachable rule.
func TestCompileRejectsDefaultBeforeConditionalSplit(t *testing.T) {
	net := splitNet([]string{"is-svc"}, map[string]ConditionSpec{
		"is-svc": {DstIn: &config.IPSet{List: []string{"203.0.113.0/24"}}},
	})
	net.Paths[0].Routes[0], net.Paths[0].Routes[1] = net.Paths[0].Routes[1], net.Paths[0].Routes[0]
	_, err := net.Compile()
	if err == nil {
		t.Fatal("a default branch above a conditional one should be rejected: it shadows the conditional branch at the gateway")
	}
	if !strings.Contains(err.Error(), "dead") {
		t.Fatalf("error should name the dead branch, got: %v", err)
	}
}

// TestCompileRejectsUnrestatableSplit covers the divergence that CANNOT be resolved: a branch
// guarded only by a healthcheck is a statement about link liveness at the origin, which means
// nothing at the gateway, so both branches still collapse to one match there. Compile must
// reject it (and say why) rather than emit a table whose second branch is dead.
func TestCompileRejectsUnrestatableSplit(t *testing.T) {
	net := splitNet([]string{"primary-up"}, map[string]ConditionSpec{
		"primary-up": {Healthcheck: &HealthcheckSpec{Path: "leaf"}},
	})
	_, err := net.Compile()
	if err == nil {
		t.Fatal("a healthcheck-guarded branch that shares its up-link with the default must be rejected: the gateway cannot tell the two apart")
	}
	if !strings.Contains(err.Error(), "dst_in") {
		t.Fatalf("error should explain that only a dst_in condition can be re-evaluated downstream, got: %v", err)
	}
}
