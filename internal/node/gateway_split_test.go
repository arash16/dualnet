package node

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/egress"
	"github.com/arash16/dualnet/internal/netschema"
)

// TestGatewaySplitsExceptionByDestination runs the "exception route" topology end to end: all
// of the leaf's traffic travels one link up to the gateway, but destinations in a named set
// must leave through a different egress there (a service that rejects the default exit, say).
// Both branches share the up-link, so the split can only happen at the gateway — it re-evaluates
// the branch's dst_in set on the inner packet. This proves the compiled guard survives the hop:
// the exception traffic exits `svc` and everything else exits `bulk`, with neither leaking into
// the other and replies returning to the origin tun both ways.
func TestGatewaySplitsExceptionByDestination(t *testing.T) {
	svcFile := filepath.Join(t.TempDir(), "svc.prefixes")
	if err := os.WriteFile(svcFile, []byte("203.0.113.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	leafUp := freeTCP(t)
	gwLeaf := freeUDP(t)

	net := &netschema.Network{
		PSK: testPSK, Subnet: "10.9.0.0/24", MTU: 1360,
		Protocols: map[string]netschema.ProtocolSpec{
			"http": {Transport: "http"},
			"udp":  {Transport: "udp"},
		},
		Conditions: map[string]netschema.ConditionSpec{
			"is-svc": {DstIn: &config.IPSet{File: svcFile}},
		},
		Nodes: map[string]netschema.Node{
			"leaf": {
				Connections: map[string]netschema.Conn{"Tun": {Type: "tun", Iface: "leaf-tun", IP: "10.9.0.2", CaptureDefault: true}},
			},
			"gw": {IP: "127.0.0.1", Egresses: map[string]config.Egress{
				"svc":  {Mode: "kernel", ExtIface: "eth0"},
				"bulk": {Mode: "kernel", ExtIface: "eth1"},
			}},
		},
		Links: []netschema.Link{
			{Name: "leaf-up", Dialer: "leaf", Acceptor: "gw", Dataflow: "to-acceptor", Protocol: "http", Port: leafUp},
			{Name: "gw-leaf", Dialer: "leaf", Acceptor: "gw", Dataflow: "to-dialer", Protocol: "udp", Port: gwLeaf, Multiple: true, IDSetter: "Tun"},
		},
		Paths: []netschema.Path{
			{Name: "leaf", Node: "leaf", Routes: []netschema.Branch{
				{When: []string{"is-svc"}, Egress: "svc", Up: []string{"leaf-up"}, Down: []string{"gw-leaf"}},
				{Egress: "bulk", Up: []string{"leaf-up"}, Down: []string{"gw-leaf"}},
			}},
		},
	}
	cfgs, err := net.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svcEg, bulkEg := newCountEgress(), newCountEgress()
	leafTun := newFakeTun()
	startSplitNode(t, ctx, cfgs["gw"], nil, map[string]egress.Egress{"svc": svcEg, "bulk": bulkEg})
	startSplitNode(t, ctx, cfgs["leaf"], map[string]*fakeTun{"leaf-tun": leafTun}, nil)

	if !driveUntilReply(t, leafTun, "10.9.0.2", "203.0.113.5", 20*time.Second) {
		t.Fatal("exception destination: no reply at the leaf tun")
	}
	if svcEg.count() == 0 {
		t.Fatal("exception destination did not exit through the svc egress")
	}
	if bulkEg.count() != 0 {
		t.Fatalf("exception destination leaked to the bulk egress (%d packets)", bulkEg.count())
	}

	if !driveUntilReply(t, leafTun, "10.9.0.2", "8.8.8.8", 20*time.Second) {
		t.Fatal("ordinary destination: no reply at the leaf tun")
	}
	if bulkEg.count() == 0 {
		t.Fatal("ordinary destination did not exit through the bulk egress")
	}
}
