package egress

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/arash16/dualnet/internal/pktbuf"
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
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID       = 1
	udpIdle     = 60 * time.Second
	dialTimeout = 15 * time.Second

	// pipeBuf bounds the userspace splice buffer per direction (2 per TCP flow). Small on
	// purpose: the tunnel MTU is tiny and the throughput bottleneck is CPU/gVisor, not this
	// copy, so the old 64 KiB (50× the 1280 MTU) was avoidable RAM on a small router.
	pipeBuf = 16 * 1024

	// maxFlows caps concurrent forwarded flows per egress. Past it, new flows are refused
	// (TCP RST / UDP drop) instead of letting an unbounded fan-out of goroutines + gVisor
	// buffers + fds exhaust a no-swap router's RAM. Sized (with tcpBufMax below) so the
	// worst-case aggregate — maxFlows*(2*tcpBufMax + 2*pipeBuf) ≈ 80 MiB — fits the ~128 MiB
	// no-swap box these caps protect; still ample for a home LAN.
	maxFlows = 512

	// TCP keepalive on the client-facing endpoint reaps a flow whose LAN client vanished
	// silently — slept / roamed / NAT-rebind, no FIN or RST. Without it those flows (3
	// goroutines + ~140 KiB + an fd each) leak forever; on a no-swap router that is the
	// measured whole-system hang. Keepalive distinguishes "vanished" from "idle but alive"
	// (an alive client ACKs the probes), so unlike a data-idle timeout it never severs a
	// healthy but quiet connection (ssh, long-poll, …). ~idle + interval×count ≈ 2 min.
	defaultKAIdle     = 60 * time.Second
	defaultKAInterval = 15 * time.Second
	defaultKACount    = 4

	// Per-flow gVisor TCP buffer auto-tuning bounds. Caps per-flow memory so a few active
	// high-bandwidth flows can't each claim gVisor's multi-MB default on a 128 MB box. tcpBufMax
	// is bounded so maxFlows*(2*tcpBufMax + 2*pipeBuf) stays under the RAM budget (see maxFlows);
	// the tiny tunnel MTU means the low-BDP realistic case sits near tcpBufDefault anyway.
	tcpBufMin     = 4 * 1024
	tcpBufDefault = 32 * 1024
	tcpBufMax     = 64 * 1024

	// netstackReadCap is the per-slot capacity of a Fill batch. The stack emits inner IP packets
	// bounded by the tunnel MTU, well under this; 65535 is the u16 length ceiling, a safe upper
	// bound that never rejects a legitimate emitted packet.
	netstackReadCap = 65535
)

// Netstack is a userspace exit: client inner packets are injected into a gVisor
// stack that terminates each TCP/UDP flow and bridges it to a connection opened
// through the Dialer. Return traffic emerges as inner IP packets.
type Netstack struct {
	stack     *stack.Stack
	ep        *channel.Endpoint
	dialer    Dialer
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once

	// client-facing TCP keepalive timing (fields, not consts, so tests can shorten them).
	kaIdle     time.Duration
	kaInterval time.Duration
	kaCount    int

	// flows is a counting semaphore (one token per live forwarded flow) bounding concurrency.
	flows chan struct{}
}

// NewNetstack builds the userspace exit stack. mtu should match the tunnel MTU.
func NewNetstack(dialer Dialer, mtu int) (*Netstack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	// Cap per-flow TCP send/recv buffers (auto-tuning range) so a few active flows can't each
	// grab gVisor's multi-MB default and exhaust a small router's RAM.
	sndBuf := tcpip.TCPSendBufferSizeRangeOption{Min: tcpBufMin, Default: tcpBufDefault, Max: tcpBufMax}
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndBuf)
	rcvBuf := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcpBufMin, Default: tcpBufDefault, Max: tcpBufMax}
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvBuf)

	ep := channel.New(1024, uint32(mtu), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("egress: create nic: %v", err)
	}
	// Accept packets for any destination (clients reach arbitrary internet IPs).
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("egress: promiscuous: %v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("egress: spoofing: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	ctx, cancel := context.WithCancel(context.Background())
	n := &Netstack{
		stack: s, ep: ep, dialer: dialer, ctx: ctx, cancel: cancel,
		kaIdle: defaultKAIdle, kaInterval: defaultKAInterval, kaCount: defaultKACount,
		flows: make(chan struct{}, maxFlows),
	}

	tcpFwd := tcp.NewForwarder(s, 0, 2048, n.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, n.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	return n, nil
}

// injectOne injects one client inner IP packet into the stack.
func (n *Netstack) injectOne(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	switch pkt[0] >> 4 {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	n.ep.InjectInbound(proto, pb)
	pb.DecRef()
}

// BatchSize is 1: the userspace stack emits one packet per read (no OS batch).
func (n *Netstack) BatchSize() int { return 1 }

// NewReadBatch makes a single-packet pktbuf.Batch for a Reader draining this egress. netstack has
// no vectored read, so a batch is one packet; the Reader still prefetches the next while the
// finalizer routes the current.
func (n *Netstack) NewReadBatch() *pktbuf.Batch { return pktbuf.NewBatch(1, netstackReadCap, 1) }

// Fill reads the next inner IP packet the stack emits toward a client into b (one packet). The
// view aliases b's storage; the Reader's double-buffering keeps it stable until b is refilled.
func (n *Netstack) Fill(b *pktbuf.Batch) error {
	pb := n.ep.ReadContext(n.ctx)
	if pb == nil {
		return io.EOF
	}
	view := pb.ToView().AsSlice()
	dst := b.Slots()[0]
	if len(view) > len(dst) {
		pb.DecRef()
		return fmt.Errorf("egress: read packet too large (%d > %d)", len(view), len(dst))
	}
	m := copy(dst, view)
	pb.DecRef()
	b.Add(dst[:m])
	return nil
}

// Write injects a batch of client packets, one at a time (no OS batch).
func (n *Netstack) Write(pkts [][]byte) error {
	for _, p := range pkts {
		n.injectOne(p)
	}
	return nil
}

// Close tears down the stack and unblocks a blocked Fill. Safe to call more than once.
func (n *Netstack) Close() error {
	n.closeOnce.Do(func() {
		n.cancel()
		n.ep.Close()
		n.stack.Close()
	})
	return nil
}

// handleTCP and handleUDP MUST dial off the forwarder goroutine. gVisor delivers these
// callbacks synchronously inside packet injection (Write → injectOne → InjectInbound), which for a
// capture tun is driven by a single read loop (see conn.TunConn.Start). A dial that blocks —
// e.g. a SYN to a host that is slow or unreachable via the egress — would otherwise stall the
// callback for up to dialTimeout and freeze ALL forwarding through the node. Returning
// immediately keeps the pump flowing; the flow is simply completed once the dial resolves.
func (n *Netstack) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst, ok := addrPort(id.LocalAddress, id.LocalPort)
	if !ok || blockedDst(dst.Addr()) {
		r.Complete(true) // RST: unresolvable or a forbidden (SSRF) destination
		return
	}
	if !n.acquire() {
		r.Complete(true) // at the flow cap: RST rather than exhaust memory
		return
	}
	go func() {
		defer n.release()
		ctx, cancel := context.WithTimeout(n.ctx, dialTimeout)
		out, err := n.dialer.DialTCP(ctx, dst)
		cancel()
		if err != nil {
			r.Complete(true) // RST
			return
		}
		var wq waiter.Queue
		tep, tErr := r.CreateEndpoint(&wq)
		if tErr != nil {
			_ = out.Close()
			r.Complete(true)
			return
		}
		n.enableKeepalive(tep) // reap a silently-vanished client (else the flow leaks forever)
		r.Complete(false)
		bridge(gonet.NewTCPConn(&wq, tep), out, 0)
	}()
}

func (n *Netstack) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dst, ok := addrPort(id.LocalAddress, id.LocalPort)
	if !ok || blockedDst(dst.Addr()) {
		return // drop: unresolvable or a forbidden (SSRF) destination
	}
	if !n.acquire() {
		return // at the flow cap: drop
	}
	go func() {
		defer n.release()
		out, err := n.dialer.DialUDP(dst)
		if err != nil {
			return
		}
		var wq waiter.Queue
		tep, tErr := r.CreateEndpoint(&wq)
		if tErr != nil {
			_ = out.Close()
			return
		}
		bridge(gonet.NewUDPConn(&wq, tep), out, udpIdle)
	}()
}

// acquire takes a flow token without blocking; false means the egress is at maxFlows.
func (n *Netstack) acquire() bool {
	select {
	case n.flows <- struct{}{}:
		return true
	default:
		return false
	}
}

// release returns a flow token when a forwarded flow ends.
func (n *Netstack) release() { <-n.flows }

// enableKeepalive turns on TCP keepalive on the client-facing endpoint so gVisor probes a
// quiet client and tears the endpoint down when the probes go unanswered — the reads in
// bridge then unblock and the flow's goroutines/buffers/fd are reclaimed.
func (n *Netstack) enableKeepalive(ep tcpip.Endpoint) {
	ep.SocketOptions().SetKeepAlive(true)
	idle := tcpip.KeepaliveIdleOption(n.kaIdle)
	_ = ep.SetSockOpt(&idle)
	interval := tcpip.KeepaliveIntervalOption(n.kaInterval)
	_ = ep.SetSockOpt(&interval)
	_ = ep.SetSockOptInt(tcpip.KeepaliveCountOption, n.kaCount)
}

// blockedDst reports whether a client-chosen destination must not be dialed out the egress.
// The destination comes verbatim from the (unauthenticated) inner IP header, so a client could
// otherwise reach services that are on-link to the egress interface but never meant to be tunnel-
// reachable: cloud instance metadata (169.254.169.254 — link-local), the gateway's own services
// bound to link-local/loopback, or multicast/unspecified addresses. Blocking these closes an SSRF
// vector without touching the obscurity posture. RFC1918/ULA are intentionally NOT blocked — a
// home-router gateway legitimately serves its LAN.
func blockedDst(a netip.Addr) bool {
	a = a.Unmap()
	return !a.IsValid() || a.IsLoopback() || a.IsUnspecified() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsInterfaceLocalMulticast()
}

// addrPort converts a netstack address+port to a netip.AddrPort.
func addrPort(a tcpip.Address, port uint16) (netip.AddrPort, bool) {
	ip, ok := netip.AddrFromSlice(a.AsSlice())
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), port), true
}

// bridge copies bytes in both directions and closes both ends when either
// finishes. A nonzero idle sets a read/write idle timeout (for UDP flows).
func bridge(a, b net.Conn, idle time.Duration) {
	done := make(chan struct{}, 2)
	go func() { pipe(a, b, idle); done <- struct{}{} }()
	go func() { pipe(b, a, idle); done <- struct{}{} }()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}

func pipe(dst, src net.Conn, idle time.Duration) {
	buf := make([]byte, pipeBuf)
	for {
		if idle > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idle))
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			if idle > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(idle))
			}
			if _, ew := dst.Write(buf[:nr]); ew != nil {
				return
			}
		}
		if er != nil {
			return
		}
	}
}
