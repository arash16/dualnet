package node

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/conn"
	"github.com/arash16/dualnet/internal/egress"
	"github.com/arash16/dualnet/internal/netschema"
)

// countEgress is a reflecting fake internet that also counts data packets it egresses
// (healthcheck pings are reflected at the finalizer and never reach here).
type countEgress struct {
	*reflectEgress
	n atomic.Int64
}

func newCountEgress() *countEgress { return &countEgress{reflectEgress: newReflectEgress()} }

func (c *countEgress) Write(pkts [][]byte) error {
	for _, p := range pkts {
		if len(p) >= 20 && p[0]>>4 == 4 {
			c.n.Add(1)
		}
	}
	return c.reflectEgress.Write(pkts)
}

func (c *countEgress) count() int64 { return c.n.Load() }

// TestSplitMeshRoundTrips exercises the new home-router topology end-to-end over real
// loopback carriers with faked tuns and per-egress reflecting fakes:
//   - an Iran-destined packet from the router is finalized locally out the ftth egress
//     (never touching Turkey or Starlink) and its reply returns to the router tun;
//   - a non-Iran packet self-heals out the local starlink egress while Turkey is unhealthy;
//   - a vps packet round-trips up to Turkey and back down the shared Starlink downlink,
//     which the router demuxes by owner and relays to the vps.
func TestSplitMeshRoundTrips(t *testing.T) {
	iranFile := filepath.Join(t.TempDir(), "iran.prefixes")
	if err := os.WriteFile(iranFile, []byte("100.64.0.0/10\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	routerUp := freeTCP(t)
	vpsUp := freeTCP(t)
	turkishRouter := freeUDP(t)
	routerVps := freeUDP(t)

	fast := 1
	net := &netschema.Network{
		PSK: testPSK, Subnet: "10.9.0.0/24", MTU: 1360,
		Healthcheck: &fast, HealthcheckTimeout: 3, HealthcheckUpGrace: 1,
		Protocols: map[string]netschema.ProtocolSpec{
			"http": {Transport: "http"},
			"udp":  {Transport: "udp"},
		},
		Conditions: map[string]netschema.ConditionSpec{
			"is-iran":    {DstIn: &config.IPSet{File: iranFile}},
			"turkey":     {Healthcheck: &netschema.HealthcheckSpec{Path: "lan"}},
			"vps-turkey": {Healthcheck: &netschema.HealthcheckSpec{Path: "vps"}},
		},
		Nodes: map[string]netschema.Node{
			"router": {
				Connections: map[string]netschema.Conn{"Tun": {Type: "tun", Iface: "router-tun", IP: "10.9.0.2", CaptureDefault: true}},
				Egresses: map[string]config.Egress{
					"ftth":     {Mode: "direct", ExtIface: "lo"},
					"starlink": {Mode: "direct", ExtIface: "lo"},
				},
			},
			"turkish": {IP: "127.0.0.1", Egresses: map[string]config.Egress{"internet": {Mode: "kernel", ExtIface: "eth0"}}},
			"vps":     {IP: "127.0.0.1", Connections: map[string]netschema.Conn{"V2Ray": {Type: "tun", Iface: "vps-tun", IP: "10.9.0.5"}}},
		},
		Links: []netschema.Link{
			{Name: "router-up", Dialer: "router", Acceptor: "turkish", Dataflow: "to-acceptor", Protocol: "http", Port: routerUp},
			{Name: "turkish-router", Dialer: "router", Acceptor: "turkish", Dataflow: "to-dialer", Protocol: "udp", Port: turkishRouter},
			{Name: "vps-up", Dialer: "vps", Acceptor: "turkish", Dataflow: "to-acceptor", Protocol: "http", Port: vpsUp},
			{Name: "router-vps", Dialer: "router", Acceptor: "vps", Dataflow: "to-acceptor", Protocol: "udp", Port: routerVps},
		},
		Paths: []netschema.Path{
			{Name: "lan", Node: "router", Routes: []netschema.Branch{
				{When: []string{"is-iran"}, Egress: "ftth"},
				{When: []string{"turkey"}, Gateway: "turkish", Egress: "internet", Up: []string{"router-up"}, Down: []string{"turkish-router"}},
				{Egress: "starlink"},
			}},
			{Name: "vps", Node: "vps", Routes: []netschema.Branch{
				{Gateway: "turkish", Egress: "internet", Up: []string{"vps-up"}, Down: []string{"turkish-router", "router-vps"}},
			}},
		},
	}
	cfgs, err := net.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ftthEg, starlinkEg, internetEg := newCountEgress(), newCountEgress(), newCountEgress()
	routerTun, vpsTun := newFakeTun(), newFakeTun()

	startSplitNode(t, ctx, cfgs["turkish"], nil, map[string]egress.Egress{"internet": internetEg})
	startSplitNode(t, ctx, cfgs["router"], map[string]*fakeTun{"router-tun": routerTun},
		map[string]egress.Egress{"ftth": ftthEg, "starlink": starlinkEg})
	startSplitNode(t, ctx, cfgs["vps"], map[string]*fakeTun{"vps-tun": vpsTun}, nil)

	// (1) Iran destination → finalized locally out ftth, reply back to the router tun.
	if !driveUntilReply(t, routerTun, "10.9.0.2", "100.64.0.5", 10*time.Second) {
		t.Fatal("iran packet: no reply at router tun")
	}
	if ftthEg.count() == 0 {
		t.Fatal("iran packet did not egress via ftth")
	}
	if starlinkEg.count() != 0 || internetEg.count() != 0 {
		t.Fatalf("iran packet leaked to other egresses: starlink=%d internet=%d", starlinkEg.count(), internetEg.count())
	}

	// (2) Non-Iran while Turkey is (initially) unhealthy → self-heals out the local
	// starlink egress; reply back to the router tun.
	if !driveUntilReply(t, routerTun, "10.9.0.2", "8.8.8.8", 10*time.Second) {
		t.Fatal("non-iran packet: no reply at router tun")
	}
	if starlinkEg.count() == 0 {
		t.Fatal("non-iran packet did not fall back to the starlink egress")
	}

	// (3) VPS packet → up to Turkey, reply down the shared Starlink downlink, demuxed by
	// the router and relayed to the vps. Proves turkish + turkish-router + router relay.
	if !driveUntilReply(t, vpsTun, "10.9.0.5", "8.8.8.8", 20*time.Second) {
		t.Fatal("vps packet: no reply at vps tun")
	}
	if internetEg.count() == 0 {
		t.Fatal("vps packet did not egress via the turkish internet egress")
	}
}

func startSplitNode(t *testing.T, ctx context.Context, cfg *config.Node, tuns map[string]*fakeTun, egs map[string]egress.Egress) {
	t.Helper()
	opt := Options{
		OpenTun:  func(name string, _ int) (conn.TunDevice, error) { return tuns[name], nil },
		Egresses: egs,
	}
	go func() {
		if err := RunWith(ctx, cfg, opt); err != nil {
			t.Errorf("node: %v", err)
		}
	}()
}

// driveUntilReply repeatedly injects an app packet (src->dst) at tun and waits for the
// reflected reply (dst->src) to arrive, retrying to cover startup (dial/registration).
func driveUntilReply(t *testing.T, tun *fakeTun, srcAddr, dstAddr string, timeout time.Duration) bool {
	t.Helper()
	pkt := ipv4Packet(srcAddr, dstAddr, "hi")
	deadline := time.After(timeout)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	tun.out <- append([]byte(nil), pkt...)
	for {
		select {
		case got := <-tun.in:
			if len(got) < 20 {
				continue
			}
			gotSrc := netip.AddrFrom4([4]byte{got[12], got[13], got[14], got[15]})
			gotDst := netip.AddrFrom4([4]byte{got[16], got[17], got[18], got[19]})
			if gotSrc.String() == dstAddr && gotDst.String() == srcAddr {
				return true
			}
		case <-tick.C:
			tun.out <- append([]byte(nil), pkt...)
		case <-deadline:
			return false
		}
	}
}
