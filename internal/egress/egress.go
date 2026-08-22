// Package egress abstracts how the relay sends client traffic to the internet.
//
// Two backends satisfy Egress:
//   - the kernel TUN + NAT path (internal/tundev.Device already implements these
//     methods), used by default;
//   - Netstack (this package), a userspace gVisor TCP/IP stack that terminates
//     each client flow and dials the destination through a Dialer (e.g. WARP),
//     with no kernel TUN, no iptables, and no routing-table changes.
package egress

import (
	"context"
	"net"
	"net/netip"

	"github.com/arash16/dualnet/internal/pktbuf"
)

// Egress moves inner IP packets between the relay core and the internet, batched to cut syscalls.
// Fill reads a batch of packets destined back to clients (driving the finalizer's reply Reader);
// NewReadBatch sizes that Reader's batches. Write injects a batch of client packets toward the
// internet (the finalizer's inject Writer flush).
type Egress interface {
	Fill(b *pktbuf.Batch) error
	NewReadBatch() *pktbuf.Batch
	Write(pkts [][]byte) error
	Close() error
}

// Dialer opens connections to the internet on the relay's behalf. The WARP
// dialer implements it; a plain net-based dialer can be used for testing.
type Dialer interface {
	DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	DialUDP(addr netip.AddrPort) (net.Conn, error)
}
