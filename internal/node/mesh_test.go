package node

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/conn"
	"github.com/arash16/dualnet/internal/pktbuf"
)

// This exercises the full generalized routing model in-process, over real loopback
// HTTP/UDP carriers, with faked tuns and a reflecting fake egress — the hand-traced
// round-trips from the design turned into executable tests:
//   phone-origin:  Phone.Tun -> Turkey(process) -> HPi -> VPS -> Phone.Tun
//   laptop-origin: Laptop.Tun -> HPi -> Turkey(process) -> Turkey -> Laptop.Tun
//   vps-origin:    VPS.V2Ray -> Turkey(process) -> HPi -> VPS.V2Ray
// plus id-assignment (Multiple listeners mint; id_setter stamps the tun).

const testPSK = "mesh-test-psk"

// fakeTun is an in-memory TunDevice: the test enqueues "app" packets on out and reads
// delivered packets from in.
type fakeTun struct {
	out    chan []byte
	in     chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFakeTun() *fakeTun {
	return &fakeTun{out: make(chan []byte, 64), in: make(chan []byte, 64), closed: make(chan struct{})}
}

func (f *fakeTun) NewReadBatch() *pktbuf.Batch { return pktbuf.NewBatch(1, 65535, 1) }

func (f *fakeTun) Fill(b *pktbuf.Batch) error {
	select {
	case p := <-f.out:
		dst := b.Slots()[0]
		n := copy(dst, p)
		b.Add(dst[:n])
		return nil
	case <-f.closed:
		return io.EOF
	}
}

func (f *fakeTun) writeOne(p []byte) {
	cp := append([]byte(nil), p...)
	select {
	case f.in <- cp:
	case <-f.closed:
	}
}

func (f *fakeTun) Write(pkts [][]byte) error {
	for _, p := range pkts {
		f.writeOne(p)
	}
	return nil
}

func (f *fakeTun) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

// reflectEgress is a fake internet: it swaps the IPv4 src/dst of each submitted packet
// and returns it as the reply (as a real destination would).
type reflectEgress struct {
	replies chan []byte
	closed  chan struct{}
	once    sync.Once
}

func newReflectEgress() *reflectEgress {
	return &reflectEgress{replies: make(chan []byte, 64), closed: make(chan struct{})}
}

func (e *reflectEgress) reflect(p []byte) {
	if len(p) >= 20 && p[0]>>4 == 4 {
		r := append([]byte(nil), p...)
		copy(r[12:16], p[16:20])
		copy(r[16:20], p[12:16])
		select {
		case e.replies <- r:
		case <-e.closed:
		}
	}
}

func (e *reflectEgress) Write(pkts [][]byte) error {
	for _, p := range pkts {
		e.reflect(p)
	}
	return nil
}

func (e *reflectEgress) NewReadBatch() *pktbuf.Batch { return pktbuf.NewBatch(1, 65535, 1) }

func (e *reflectEgress) Fill(b *pktbuf.Batch) error {
	select {
	case r := <-e.replies:
		dst := b.Slots()[0]
		n := copy(dst, r)
		b.Add(dst[:n])
		return nil
	case <-e.closed:
		return io.EOF
	}
}

func (e *reflectEgress) Close() error {
	e.once.Do(func() { close(e.closed) })
	return nil
}

func ipv4Packet(src, dst string, payload string) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 6 // TCP (not a ping)
	copy(p[12:16], netip.MustParseAddr(src).AsSlice())
	copy(p[16:20], netip.MustParseAddr(dst).AsSlice())
	copy(p[20:], payload)
	return p
}

func freeTCP(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func freeUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func pfalse() *bool { b := false; return &b }
func ptrue() *bool  { b := true; return &b }

// startNode runs one mesh node in the background with faked tun devices and an
// optional injected egress; returns a stop func.
func startNode(t *testing.T, ctx context.Context, cfg *config.Node, tuns map[string]*fakeTun, eg *reflectEgress) {
	t.Helper()
	opt := Options{
		OpenTun: func(name string, _ int) (conn.TunDevice, error) {
			return tuns[name], nil
		},
	}
	if eg != nil {
		opt.Egress = eg
	}
	go func() {
		if err := RunWith(ctx, cfg, opt); err != nil {
			t.Errorf("node %q: %v", cfg.Connections[0].Name, err)
		}
	}()
}

func TestMeshRoundTrips(t *testing.T) {
	// Ports.
	clientIn := freeTCP(t)
	hpiIn := freeTCP(t)
	vpsIn := freeTCP(t)
	hpiOut := freeUDP(t)
	laptopOut := freeUDP(t)
	vpsHpiIn := freeUDP(t)
	phoneOut := freeUDP(t)
	hpiLaptopIn := freeUDP(t)

	const ip = "127.0.0.1"

	turkish := &config.Node{
		PSK: testPSK, Subnet: "10.9.0.0/24",
		Egresses: map[string]config.Egress{"internet": {Mode: "kernel", ExtIface: "eth0"}}, // egress injected in test
		Connections: []config.Connection{
			{Name: "ClientIn", Type: "listen", Direction: "incoming", Transport: "http", Port: clientIn},
			{Name: "LaptopOut", Type: "listen", Direction: "outgoing", Transport: "udp", Port: laptopOut, Multiple: true},
			{Name: "HPiOut", Type: "listen", Direction: "outgoing", Transport: "udp", Port: hpiOut},
			{Name: "HPiIn", Type: "listen", Direction: "incoming", Transport: "http", Port: hpiIn},
			{Name: "VPSIn", Type: "listen", Direction: "incoming", Transport: "http", Port: vpsIn},
		},
		Routes: []config.Route{
			{Match: config.Match{Source: "HPiIn", Processed: pfalse()}, Action: config.Action{Egress: "internet", Target: "LaptopOut"}},
			{Match: config.Match{Source: "", Processed: pfalse()}, Action: config.Action{Egress: "internet", Target: "HPiOut"}},
		},
	}

	hpi := &config.Node{
		PSK: testPSK, Subnet: "10.9.0.0/24",
		Connections: []config.Connection{
			{Name: "TurkishIn", Type: "connect", Direction: "incoming", Transport: "udp", IP: ip, Port: hpiOut},
			{Name: "TurkishOut", Type: "connect", Direction: "outgoing", Transport: "http", IP: ip, Port: hpiIn},
			{Name: "VPSOut", Type: "connect", Direction: "outgoing", Transport: "udp", IP: ip, Port: vpsHpiIn},
			{Name: "LaptopIn", Type: "listen", Direction: "incoming", Transport: "udp", Port: hpiLaptopIn},
		},
		Routes: []config.Route{
			{Match: config.Match{Source: "LaptopIn", Processed: pfalse()}, Action: config.Action{Target: "TurkishOut"}},
			{Match: config.Match{Source: "TurkishIn", Processed: ptrue()}, Action: config.Action{Target: "VPSOut"}},
		},
	}

	vps := &config.Node{
		PSK: testPSK, Subnet: "10.9.0.0/24",
		Connections: []config.Connection{
			{Name: "HPiIn", Type: "listen", Direction: "incoming", Transport: "udp", Port: vpsHpiIn},
			{Name: "TurkishOut", Type: "connect", Direction: "outgoing", Transport: "http", IP: ip, Port: vpsIn},
			{Name: "PhoneOut", Type: "listen", Direction: "outgoing", Transport: "udp", Port: phoneOut, Multiple: true},
			{Name: "V2Ray", Type: "tun", Interface: "vps-v2ray", Address: "10.9.0.5"},
		},
		Routes: []config.Route{
			{Match: config.Match{Source: "HPiIn", Processed: ptrue()}, Action: config.Action{Target: "V2Ray"}},
			{Match: config.Match{Source: "HPiIn", Processed: ptrue()}, Action: config.Action{Target: "PhoneOut"}},
			{Match: config.Match{Source: "V2Ray", Processed: pfalse()}, Action: config.Action{Target: "TurkishOut"}},
		},
	}

	phone := &config.Node{
		PSK: testPSK, Subnet: "10.9.0.0/24",
		Connections: []config.Connection{
			{Name: "VPSIn", Type: "connect", Direction: "incoming", Transport: "udp", IP: ip, Port: phoneOut, IDSetter: "Tun"},
			{Name: "TurkishOut", Type: "connect", Direction: "outgoing", Transport: "http", IP: ip, Port: clientIn},
			{Name: "Tun", Type: "tun", Interface: "phone-tun", Address: "10.9.0.2"},
		},
		Routes: []config.Route{
			{Match: config.Match{Source: "Tun", Processed: pfalse()}, Action: config.Action{Target: "TurkishOut"}},
			{Match: config.Match{Source: "VPSIn", Processed: ptrue()}, Action: config.Action{Target: "Tun"}},
		},
	}

	laptop := &config.Node{
		PSK: testPSK, Subnet: "10.9.0.0/24",
		Connections: []config.Connection{
			{Name: "TurkishRecv", Type: "connect", Direction: "incoming", Transport: "udp", IP: ip, Port: laptopOut, IDSetter: "Tun"},
			{Name: "HPiSend", Type: "connect", Direction: "outgoing", Transport: "udp", IP: ip, Port: hpiLaptopIn},
			{Name: "Tun", Type: "tun", Interface: "laptop-tun", Address: "10.9.0.3"},
		},
		Routes: []config.Route{
			{Match: config.Match{Source: "Tun", Processed: pfalse()}, Action: config.Action{Target: "HPiSend"}},
			{Match: config.Match{Source: "TurkishRecv", Processed: ptrue()}, Action: config.Action{Target: "Tun"}},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eg := newReflectEgress()
	defer eg.Close()
	phoneTun := newFakeTun()
	vpsTun := newFakeTun()
	laptopTun := newFakeTun()

	startNode(t, ctx, turkish, nil, eg)
	startNode(t, ctx, hpi, nil, nil)
	startNode(t, ctx, vps, map[string]*fakeTun{"vps-v2ray": vpsTun}, nil)
	startNode(t, ctx, phone, map[string]*fakeTun{"phone-tun": phoneTun}, nil)
	startNode(t, ctx, laptop, map[string]*fakeTun{"laptop-tun": laptopTun}, nil)

	runMeshRoundTrip(t, "phone", phoneTun, "10.9.0.2")
	runMeshRoundTrip(t, "laptop", laptopTun, "10.9.0.3")
	runMeshRoundTrip(t, "vps", vpsTun, "10.9.0.5")
}

// runMeshRoundTrip injects an app packet at a tun and asserts the (reflected) reply
// comes back to that tun. It retransmits until the reply arrives (covering startup:
// id assignment, registration, connect dial retries) — mirroring inner-TCP retransmit.
func runMeshRoundTrip(t *testing.T, name string, tun *fakeTun, srcAddr string) {
	t.Helper()
	pkt := ipv4Packet(srcAddr, "1.2.3.4", "hello-"+name)
	deadline := time.After(20 * time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	tun.out <- append([]byte(nil), pkt...)
	for {
		select {
		case got := <-tun.in:
			if len(got) < 20 {
				t.Fatalf("%s: short reply", name)
			}
			gotSrc := netip.AddrFrom4([4]byte{got[12], got[13], got[14], got[15]})
			gotDst := netip.AddrFrom4([4]byte{got[16], got[17], got[18], got[19]})
			if gotSrc.String() != "1.2.3.4" || gotDst.String() != srcAddr {
				t.Fatalf("%s: reply addrs = %s->%s, want 1.2.3.4->%s", name, gotSrc, gotDst, srcAddr)
			}
			if string(got[20:]) != "hello-"+name {
				t.Fatalf("%s: reply payload = %q", name, string(got[20:]))
			}
			return
		case <-tick.C:
			tun.out <- append([]byte(nil), pkt...)
		case <-deadline:
			t.Fatalf("%s: no reply within timeout", name)
		}
	}
}
