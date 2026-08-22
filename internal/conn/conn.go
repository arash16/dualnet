// Package conn is the runtime model of a node's connections. It replaces the four
// dataflow-role interfaces of the old channel package with a single Conn plus a
// Sender capability, so the router can treat every routing target uniformly.
//
// A connection is one of five kinds = (Type × Direction), per protocol:
//
//	KindTun        local tun device; originates/consumes packets by its owner id
//	KindConnectOut we dial, we push packets                (old TXClient)
//	KindConnectIn  we dial, we receive packets             (old RXClient)
//	KindListenIn   we accept, we receive packets           (old RXServer)
//	KindListenOut  we accept, we send packets by owner     (old TXServer)
//
// Every inter-node packet is carried as an obfuscated blob whose plaintext is
// wire.PutEnvelope(owner, flags, innerIP): serialized at an Outgoing send, parsed at
// an Incoming receive. Inside the node packets travel as (wire.Envelope, payload).
package conn

import (
	"context"
	"net"

	"github.com/arash16/dualnet/internal/wire"
)

// Kind identifies a connection's (type, direction).
type Kind int

const (
	KindTun Kind = iota
	KindConnectOut
	KindConnectIn
	KindListenIn
	KindListenOut
)

func (k Kind) String() string {
	switch k {
	case KindTun:
		return "tun"
	case KindConnectOut:
		return "connect-out"
	case KindConnectIn:
		return "connect-in"
	case KindListenIn:
		return "listen-in"
	case KindListenOut:
		return "listen-out"
	default:
		return "unknown"
	}
}

// Ingress is the node's intake. A receiving connection calls it for every packet
// after de-obfuscation, envelope parse, and the PlausibleIP tripwire. src is the
// receiving connection's name; payload aliases a reused buffer and must be copied if
// retained.
type Ingress func(src string, e wire.Envelope, payload []byte)

// Conn is one runtime connection. Start runs its dial/accept/tun loops until ctx is
// cancelled, delivering received packets to in.
type Conn interface {
	Name() string
	Kind() Kind
	Start(ctx context.Context, in Ingress) error
	Close() error
}

// Sender is implemented by connections that can be a routing target: Tun (write to
// the device), ConnectOut (push to the remote), ListenOut (send to a peer by owner).
// ConnectIn and ListenIn are receivers and are not Senders.
type Sender interface {
	// Accepts reports whether a packet with this owner can be delivered right now
	// (Tun→owner==id; ConnectOut→always; ListenOut→peer registered). Checked at route
	// time, including to pick a process rule's reply target.
	Accepts(owner wire.Owner) bool
	// Send delivers one packet. delivered=false means the owner is no longer routable
	// here (raced out) → the router tries the next target. err is a transport error on
	// a live target (packet dropped; inner TCP retransmits).
	Send(e wire.Envelope, payload []byte) (delivered bool, err error)
}

// Reconnecter is implemented by Connect connections; the healthcheck driver calls it
// to re-establish the path when the tunnel goes silent.
type Reconnecter interface {
	Reconnect(ctx context.Context) error
}

// SocketDialer abstracts how a Connect connection dials its transport socket: a
// per-interface-pinned *net.Dialer (netbind) for the plain path, or a WARP userspace
// dialer when the connection is warpped.
type SocketDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}
