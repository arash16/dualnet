package egress

import (
	"context"
	"net"
	"runtime"
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

// TestNetstackReapsVanishedClientTCP is the regression guard for the measured hard-hang: a LAN
// client whose return path silently dies (sleep / Wi-Fi roam / NAT rebind — no FIN or RST) must
// not leak its forwarded flow forever. With TCP keepalive on the client-facing endpoint the
// egress detects the dead client and tears the flow down; the control below shows that without
// timely keepalive the same flow is NOT reaped (the leak that eventually OOMs a no-swap router).
func TestNetstackReapsVanishedClientTCP(t *testing.T) {
	// Fast keepalive: first probe after 300ms, then 3 probes 200ms apart ⇒ reaped within ~1s.
	if reaped := runVanishScenario(t, 300*time.Millisecond, 200*time.Millisecond, 3, 6*time.Second); !reaped {
		t.Fatal("flow was NOT reaped after the client vanished — this is the goroutine/fd/memory leak that hard-hangs the router")
	}
}

// TestNetstackLeaksVanishedClientWithoutTimelyKeepalive isolates the fix: with the keepalive
// idle pushed far past the observation window (≈ the old no-keepalive behavior) the vanished
// client's flow stays up — confirming keepalive is what does the reaping, not some other cleanup.
func TestNetstackLeaksVanishedClientWithoutTimelyKeepalive(t *testing.T) {
	if reaped := runVanishScenario(t, time.Hour, time.Hour, 3, 2*time.Second); reaped {
		t.Fatal("flow was reaped without timely keepalive — the scenario does not actually isolate the keepalive fix")
	}
}

// runVanishScenario stands up a real end-to-end flow through the egress (a second gVisor stack
// as the LAN client, a loopback server as the internet peer), establishes it, then kills the
// client→egress path without a FIN and reports whether the flow was torn down within waitFor.
// The signal is the server side of the dialed-out socket seeing its connection close, which only
// happens once the egress abandons the flow.
func runVanishScenario(t *testing.T, kaIdle, kaInterval time.Duration, kaCount int, waitFor time.Duration) bool {
	t.Helper()

	// Loopback "internet" peer: accept one connection and hold it open (a live-but-idle server,
	// so the ONLY thing that can end the flow is the egress reaping the vanished client).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	serverClosed := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		close(accepted)
		buf := make([]byte, 256)
		for {
			if _, err := c.Read(buf); err != nil { // unblocks when the egress closes its out socket
				close(serverClosed)
				return
			}
		}
	}()

	eg, err := NewNetstack(redirectDialer{target: ln.Addr().String()}, 1500)
	if err != nil {
		t.Fatal(err)
	}
	eg.kaIdle, eg.kaInterval, eg.kaCount = kaIdle, kaInterval, kaCount
	defer eg.Close()

	// Client-side gVisor stack bridged to the egress via its channel endpoint.
	cs := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	defer cs.Close()
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

	// client→egress pump is cancellable: cancelling it simulates the client's return path dying
	// (the egress's keepalive probes then go unanswered). The egress→client pump runs until the
	// egress closes, so probes still reach the (alive) client — only its ACKs never get back.
	upCtx, vanish := context.WithCancel(context.Background())
	defer vanish()
	go func() {
		for {
			pb := cep.ReadContext(upCtx)
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

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	full := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 10}), Port: 80}
	conn, err := gonet.DialContextTCP(dialCtx, cs, full, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial through egress: %v", err)
	}

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("flow never established end-to-end")
	}

	// The client vanishes: its return path dies and it never sends a FIN.
	vanish()

	var reaped bool
	select {
	case <-serverClosed:
		reaped = true
	case <-time.After(waitFor):
		reaped = false
	}
	// Keep the client connection referenced so a GC + finalizer can't close it and end the flow
	// cleanly — the reaping under test must come from keepalive, not from conn being collected.
	runtime.KeepAlive(conn)
	return reaped
}
