package node

import (
	"context"
	"testing"

	"github.com/arash16/dualnet/internal/config"
)

// TestMeshRoundTripTCP drives a full request/reply round-trip through the node runtime over
// the pure-tcp transport (chacha4): a client tun originates up a tcp connect-out, a gateway
// finalizes it through a reflecting egress, and the reply returns down a multiple tcp
// listen-out to the client's connect-in — which first had to register and adopt its minted
// owner (id_setter). This exercises the transport end-to-end with the real router, finalizer,
// peer registry and id-assignment, not just the conn layer in isolation.
func TestMeshRoundTripTCP(t *testing.T) {
	up := freeTCP(t)
	down := freeTCP(t)
	const ip = "127.0.0.1"

	gateway := &config.Node{
		PSK: testPSK, Subnet: "10.9.0.0/24",
		Egresses: map[string]config.Egress{"internet": {Mode: "kernel", ExtIface: "eth0"}}, // egress injected in test
		Connections: []config.Connection{
			{Name: "Up", Type: "listen", Direction: "incoming", Transport: "tcp", Cipher: "chacha4", Port: up},
			{Name: "Down", Type: "listen", Direction: "outgoing", Transport: "tcp", Cipher: "chacha4", Port: down, Multiple: true},
		},
		Routes: []config.Route{
			{Match: config.Match{Source: "Up", Processed: pfalse()}, Action: config.Action{Egress: "internet", Target: "Down"}},
		},
	}

	client := &config.Node{
		PSK: testPSK, Subnet: "10.9.0.0/24",
		Connections: []config.Connection{
			{Name: "Up", Type: "connect", Direction: "outgoing", Transport: "tcp", Cipher: "chacha4", IP: ip, Port: up},
			{Name: "Down", Type: "connect", Direction: "incoming", Transport: "tcp", Cipher: "chacha4", IP: ip, Port: down, IDSetter: "Tun"},
			{Name: "Tun", Type: "tun", Interface: "tcp-tun", Address: "10.9.0.2"},
		},
		Routes: []config.Route{
			{Match: config.Match{Source: "Tun", Processed: pfalse()}, Action: config.Action{Target: "Up"}},
			{Match: config.Match{Source: "Down", Processed: ptrue()}, Action: config.Action{Target: "Tun"}},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eg := newReflectEgress()
	defer eg.Close()
	clientTun := newFakeTun()

	startNode(t, ctx, gateway, nil, eg)
	startNode(t, ctx, client, map[string]*fakeTun{"tcp-tun": clientTun}, nil)

	runMeshRoundTrip(t, "tcp", clientTun, "10.9.0.2")
}
