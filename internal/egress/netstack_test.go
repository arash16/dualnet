package egress

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
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

// redirectDialer ignores the requested address and always dials target. It lets
// the client dial a non-loopback "internet" IP (so gVisor doesn't drop it as a
// martian) while the actual connection goes to a local test server.
type redirectDialer struct{ target string }

func (d redirectDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.target)
}
func (d redirectDialer) DialUDP(_ netip.AddrPort) (net.Conn, error) {
	return net.Dial("udp", d.target)
}

// TestNetstackEgressTCP drives the egress with a second gVisor stack acting as
// the client and verifies a TCP flow is terminated, dialed out, and spliced back.
func TestNetstackEgressTCP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "hello-through-egress")
	}))
	defer srv.Close()
	eg, err := NewNetstack(redirectDialer{target: srv.Listener.Addr().String()}, 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer eg.Close()

	// Client-side gVisor stack, bridged to the egress via its channel endpoint.
	cs := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	cep := channel.New(1024, 1500, "")
	if err := cs.CreateNIC(1, cep); err != nil {
		t.Fatalf("client nic: %v", err)
	}
	clientIP := tcpip.AddrFrom4([4]byte{10, 9, 0, 2})
	if err := cs.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: clientIP.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("client addr: %v", err)
	}
	cs.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// client stack -> egress (client's outgoing packets).
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
	// egress -> client stack (return packets).
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

	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()
	// A non-loopback "internet" destination (TEST-NET-1); the dialer redirects it.
	full := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 10}), Port: 80}
	conn, err := gonet.DialContextTCP(dialCtx, cs, full, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial through egress: %v", err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, _ := io.ReadAll(conn)
	if !strings.Contains(string(resp), "hello-through-egress") {
		t.Fatalf("did not get the expected body through the egress; got %q", string(resp))
	}
}
