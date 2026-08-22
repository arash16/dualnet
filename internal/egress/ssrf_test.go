package egress

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// TestBlockedDst pins the SSRF destination filter: link-local (incl. 169.254.169.254 cloud
// metadata), loopback, unspecified, and multicast are blocked; ordinary public and RFC1918 LAN
// destinations are allowed (a home-router gateway serves its LAN).
func TestBlockedDst(t *testing.T) {
	blocked := []string{"127.0.0.1", "169.254.169.254", "169.254.1.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "ff02::1", "::"}
	allowed := []string{"8.8.8.8", "1.1.1.1", "192.0.2.10", "10.0.0.5", "192.168.1.1", "172.16.0.1", "2606:4700::1111"}
	for _, s := range blocked {
		if !blockedDst(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked (SSRF vector)", s)
		}
	}
	for _, s := range allowed {
		if blockedDst(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

// recordingDialer records every destination it is asked to dial and always fails the dial, so a
// test can assert which destinations reached the dialer (i.e. were NOT filtered out first).
type recordingDialer struct {
	mu   sync.Mutex
	seen []netip.Addr
}

func (d *recordingDialer) record(a netip.AddrPort) {
	d.mu.Lock()
	d.seen = append(d.seen, a.Addr())
	d.mu.Unlock()
}
func (d *recordingDialer) asked(a netip.Addr) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range d.seen {
		if s == a {
			return true
		}
	}
	return false
}
func (d *recordingDialer) DialTCP(_ context.Context, a netip.AddrPort) (net.Conn, error) {
	d.record(a)
	return nil, net.ErrClosed
}
func (d *recordingDialer) DialUDP(a netip.AddrPort) (net.Conn, error) {
	d.record(a)
	return nil, net.ErrClosed
}

// TestNetstackBlocksMetadataDial verifies end to end that a client TCP SYN to 169.254.169.254 is
// refused by the egress (RST) BEFORE the dialer is consulted, while a SYN to a public address
// does reach the dialer — so the metadata endpoint is unreachable through the tunnel.
func TestNetstackBlocksMetadataDial(t *testing.T) {
	dialer := &recordingDialer{}
	eg, err := NewNetstack(dialer, 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer eg.Close()

	cs := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	cep := channel.New(1024, 1500, "")
	if err := cs.CreateNIC(1, cep); err != nil {
		t.Fatalf("client nic: %v", err)
	}
	if err := cs.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 9, 0, 2}).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("client addr: %v", err)
	}
	cs.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			pb := cep.ReadContext(ctx)
			if pb == nil {
				return
			}
			b := pb.ToView().AsSlice()
			cp := make([]byte, len(b))
			copy(cp, b)
			pb.DecRef()
			injectOnePacket(eg, cp)
		}
	}()
	go func() {
		read := egressReader(eg)
		for {
			pkt, rerr := read()
			if rerr != nil {
				return
			}
			proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
			if len(pkt) > 0 && pkt[0]>>4 == 6 {
				proto = ipv6.ProtocolNumber
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
			cep.InjectInbound(proto, pb)
			pb.DecRef()
		}
	}()

	dialTo := func(ip [4]byte) error {
		dctx, dcancel := context.WithTimeout(ctx, 3*time.Second)
		defer dcancel()
		conn, err := gonet.DialContextTCP(dctx, cs, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ip), Port: 80}, ipv4.ProtocolNumber)
		if err == nil {
			conn.Close()
		}
		return err
	}

	// Metadata endpoint: must be refused (RST) and must never reach the dialer.
	if err := dialTo([4]byte{169, 254, 169, 254}); err == nil {
		t.Fatal("dial to 169.254.169.254 succeeded — SSRF filter did not block it")
	}
	if dialer.asked(netip.MustParseAddr("169.254.169.254")) {
		t.Fatal("the egress dialed 169.254.169.254 — it must be filtered before the dial")
	}

	// A public destination reaches the dialer (proving the filter is not over-broad); the dial
	// then fails because recordingDialer always fails, which is fine — we only assert it was asked.
	_ = dialTo([4]byte{8, 8, 8, 8})
	deadline := time.After(2 * time.Second)
	for !dialer.asked(netip.MustParseAddr("8.8.8.8")) {
		select {
		case <-deadline:
			t.Fatal("the egress never dialed the allowed public destination 8.8.8.8")
		case <-time.After(20 * time.Millisecond):
		}
	}
}
