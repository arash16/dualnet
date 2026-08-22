package netschema

import (
	"strings"
	"testing"

	"github.com/arash16/dualnet/internal/config"
)

// TestHealthcheckReconnectLinksAreScoped covers that a healthcheck's reconnect set must be
// scoped to the connections ITS path dials, so one path's outage never tears down another
// path's healthy connections. On the shipped mesh the router's `turkey` healthcheck (path lan)
// must reconnect only its own links (router-up, turkish-router) and NOT the unrelated
// router→vps relay connection (router-vps), which belongs to the vps path.
func TestHealthcheckReconnectLinksAreScoped(t *testing.T) {
	net, err := Load("../../docs/examples/network-old.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	nodes, err := net.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	c := findCondition(nodes["router"], "turkey")
	if c == nil || c.Healthcheck == nil {
		t.Fatalf("router turkey healthcheck missing: %+v", c)
	}
	got := map[string]bool{}
	for _, l := range c.Healthcheck.Links {
		got[l] = true
	}
	if !got["router-up"] || !got["turkish-router"] {
		t.Errorf("turkey reconnect links = %v, want to include router-up and turkish-router", c.Healthcheck.Links)
	}
	if got["router-vps"] {
		t.Errorf("turkey reconnect links = %v, must NOT include the unrelated relay router-vps", c.Healthcheck.Links)
	}
}

// TestCompileRejectsIDSetterWithoutMultiple proves that an id-setter downlink whose acceptor is
// NOT `multiple` compiles cleanly today but hangs the origin tun forever at runtime — a single
// (non-multiple) listen-out never mints/returns an owner id, so the pending tun's read loop
// blocks on SetID that never arrives. Compile must reject it.
func TestCompileRejectsIDSetterWithoutMultiple(t *testing.T) {
	net := &Network{
		PSK: "s", MTU: 1360, Subnet: "10.0.0.0/24",
		Protocols: map[string]ProtocolSpec{"udp": {Transport: "udp"}},
		Nodes: map[string]Node{
			"gw":   {IP: "1.1.1.1", Egresses: map[string]config.Egress{"net": {Mode: "kernel", ExtIface: "eth0"}}},
			"leaf": {Connections: map[string]Conn{"T": {Type: "tun", IP: "10.0.0.2"}}},
		},
		Links: []Link{
			{Name: "leaf-up", Dialer: "leaf", Acceptor: "gw", Dataflow: "to-acceptor", Protocol: "udp", Port: 1},
			// id-setter downlink but Multiple:false — the bug.
			{Name: "gw-leaf", Dialer: "leaf", Acceptor: "gw", Dataflow: "to-dialer", Protocol: "udp", Port: 2, IDSetter: "T"},
		},
		Paths: []Path{
			{Node: "leaf", Routes: []Branch{{Egress: "net", Up: []string{"leaf-up"}, Down: []string{"gw-leaf"}}}},
		},
	}
	_, err := net.Compile()
	if err == nil {
		t.Fatal("id-setter link without `multiple` should be rejected (non-multiple acceptor never mints an id → tun hangs)")
	}
	if !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("error should explain the multiple requirement, got: %v", err)
	}
}

// TestCompileRejectsMisChainedDownPath proves that a relay link oriented so its shared node is
// the link's target (receiver) rather than its sender yields a route whose target is a receiver
// connection, which the router silently drops. Here r-o delivers TO r again instead of onward
// to o. Compile must reject the mis-chain.
func TestCompileRejectsMisChainedDownPath(t *testing.T) {
	net := &Network{
		PSK: "s", MTU: 1360, Subnet: "10.0.0.0/24",
		Protocols: map[string]ProtocolSpec{"udp": {Transport: "udp"}},
		Nodes: map[string]Node{
			"gw": {IP: "1.1.1.1", Egresses: map[string]config.Egress{"net": {Mode: "kernel", ExtIface: "eth0"}}},
			"r":  {IP: "2.2.2.2"},
			"o":  {IP: "3.3.3.3", Connections: map[string]Conn{"T": {Type: "tun", IP: "10.0.0.2"}}},
		},
		Links: []Link{
			{Name: "o-up", Dialer: "o", Acceptor: "gw", Dataflow: "to-acceptor", Protocol: "udp", Port: 1},
			{Name: "gw-r", Dialer: "r", Acceptor: "gw", Dataflow: "to-dialer", Protocol: "udp", Port: 2}, // gw -> r (ok)
			// r-o oriented so o SENDS to r (target=r) — should be r sends to o. Mis-chained.
			{Name: "r-o", Dialer: "r", Acceptor: "o", Dataflow: "to-dialer", Protocol: "udp", Port: 3},
		},
		Paths: []Path{
			{Node: "o", Routes: []Branch{{Egress: "net", Up: []string{"o-up"}, Down: []string{"gw-r", "r-o"}}}},
		},
	}
	if _, err := net.Compile(); err == nil {
		t.Fatal("mis-chained down-path (relay link not oriented onward) should be rejected")
	}
}
