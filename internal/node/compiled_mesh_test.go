package node

import (
	"context"
	"testing"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/netschema"
)

// TestCompiledMeshRoundTrips proves the network compiler end-to-end: it builds the
// mesh from the root schema (netschema.Network), compiles it to per-node configs, and
// runs the same phone/laptop/vps round-trips as TestMeshRoundTrips — but over the
// *generated* configs, so the derived connections and routes are validated against the
// real runtime.
func TestCompiledMeshRoundTrips(t *testing.T) {
	clientIn := freeTCP(t)
	hpiIn := freeTCP(t)
	vpsIn := freeTCP(t)
	hpiOut := freeUDP(t)
	laptopOut := freeUDP(t)
	vpsHpiIn := freeUDP(t)
	phoneOut := freeUDP(t)
	hpiLaptopIn := freeUDP(t)

	net := &netschema.Network{
		PSK: testPSK, Subnet: "10.9.0.0/24", MTU: 1360,
		// The http protocol carries a custom upload path + header, so this round-trip also
		// proves both ends of every http link agree on the customized carrier (a POST to a
		// non-default path would 404 on the server if they disagreed). split_mesh_test
		// covers the default-path fallback (omitted fields → proto defaults).
		Protocols: map[string]netschema.ProtocolSpec{
			"http": {Transport: "http", UploadPath: "/api/v2/objects", Headers: map[string]string{"X-Client-Version": "2.4.1"}},
			"udp":  {Transport: "udp"},
		},
		Nodes: map[string]netschema.Node{
			"turkish": {IP: "127.0.0.1", Egresses: map[string]config.Egress{"internet": {Mode: "kernel", ExtIface: "eth0"}}},
			"hpi":     {IP: "127.0.0.1"},
			"vps":     {IP: "127.0.0.1", Connections: map[string]netschema.Conn{"V2Ray": {Type: "tun", Iface: "vps-v2ray", IP: "10.9.0.5"}}},
			"phone":   {Connections: map[string]netschema.Conn{"Tun": {Type: "tun", Iface: "phone-tun", IP: "10.9.0.2", CaptureDefault: true}}},
			"laptop":  {Connections: map[string]netschema.Conn{"Tun": {Type: "tun", Iface: "laptop-tun", IP: "10.9.0.3", CaptureDefault: true}}},
		},
		Links: []netschema.Link{
			{Name: "phone-up", Dialer: "phone", Acceptor: "turkish", Dataflow: "to-acceptor", Protocol: "http", Port: clientIn},
			{Name: "vps-up", Dialer: "vps", Acceptor: "turkish", Dataflow: "to-acceptor", Protocol: "http", Port: vpsIn},
			{Name: "hpi-up", Dialer: "hpi", Acceptor: "turkish", Dataflow: "to-acceptor", Protocol: "http", Port: hpiIn},
			{Name: "turkish-hpi", Dialer: "hpi", Acceptor: "turkish", Dataflow: "to-dialer", Protocol: "udp", Port: hpiOut},
			{Name: "turkish-laptop", Dialer: "laptop", Acceptor: "turkish", Dataflow: "to-dialer", Protocol: "udp", Port: laptopOut, Multiple: true, IDSetter: "Tun"},
			{Name: "hpi-vps", Dialer: "hpi", Acceptor: "vps", Dataflow: "to-acceptor", Protocol: "udp", Port: vpsHpiIn},
			{Name: "vps-phone", Dialer: "phone", Acceptor: "vps", Dataflow: "to-dialer", Protocol: "udp", Port: phoneOut, Multiple: true, IDSetter: "Tun"},
			{Name: "laptop-hpi", Dialer: "laptop", Acceptor: "hpi", Dataflow: "to-acceptor", Protocol: "udp", Port: hpiLaptopIn},
		},
		Paths: []netschema.Path{
			{Name: "phone", Node: "phone", Routes: []netschema.Branch{{Gateway: "turkish", Egress: "internet", Up: []string{"phone-up"}, Down: []string{"turkish-hpi", "hpi-vps", "vps-phone"}}}},
			{Name: "laptop", Node: "laptop", Routes: []netschema.Branch{{Gateway: "turkish", Egress: "internet", Up: []string{"laptop-hpi", "hpi-up"}, Down: []string{"turkish-laptop"}}}},
			{Name: "vps", Node: "vps", Routes: []netschema.Branch{{Gateway: "turkish", Egress: "internet", Up: []string{"vps-up"}, Down: []string{"turkish-hpi", "hpi-vps"}}}},
		},
	}

	cfgs, err := net.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eg := newReflectEgress()
	defer eg.Close()
	phoneTun := newFakeTun()
	vpsTun := newFakeTun()
	laptopTun := newFakeTun()

	startNode(t, ctx, cfgs["turkish"], nil, eg)
	startNode(t, ctx, cfgs["hpi"], nil, nil)
	startNode(t, ctx, cfgs["vps"], map[string]*fakeTun{"vps-v2ray": vpsTun}, nil)
	startNode(t, ctx, cfgs["phone"], map[string]*fakeTun{"phone-tun": phoneTun}, nil)
	startNode(t, ctx, cfgs["laptop"], map[string]*fakeTun{"laptop-tun": laptopTun}, nil)

	runMeshRoundTrip(t, "phone", phoneTun, "10.9.0.2")
	runMeshRoundTrip(t, "laptop", laptopTun, "10.9.0.3")
	runMeshRoundTrip(t, "vps", vpsTun, "10.9.0.5")
}
