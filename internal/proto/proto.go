// Package proto holds the wire-level constants shared by the client and server
// transports: the HTTP upstream path/headers and the UDP downstream datagram
// format.
package proto

import "time"

// HTTP upstream (FTTH, censored). The client streams framed+obfuscated inner IP
// packets as the body of a long-lived POST that looks like a large upload.
const (
	// UpstreamPath is intentionally mundane to blend in.
	UpstreamPath = "/upload"

	// DownstreamPath is used when HTTP carries the downlink: the client issues a
	// long-lived GET whose response body streams inner packets.
	DownstreamPath = "/download"

	// HeaderID carries the connection/tun 4-byte routing id (hex) so a listening
	// HTTP carrier knows which peer an incoming stream belongs to (demux by owner +
	// supersede). A ConnectIn without an assigned id sends the zero id; a Multiple
	// ListenOut answers with the minted id in this header before streaming.
	HeaderID = "X-Upload-Tag"
)

// UDP control/data. Datagrams are 1 type byte + payload.
//
//	ConnectIn -> ListenOut : MsgRegister, MsgKeepalive  (control; carry id+flags+tag)
//	ListenOut -> ConnectIn : MsgAssignID                 (minted id for the peer)
//	ListenOut -> ConnectIn : MsgData                      (one enveloped inner packet)
//	ListenOut -> ConnectIn : MsgPong                      (single-peer liveness reply)
const (
	MsgRegister  byte = 0x01
	MsgKeepalive byte = 0x02
	MsgData      byte = 0x03
	MsgPong      byte = 0x04 // reply to register/keepalive (liveness; single listeners)
	MsgAssignID  byte = 0x05 // Multiple ListenOut -> ConnectIn: the minted 4-byte id
)

// Defaults.
const (
	// DefaultKeepalive is how often a UDP receive channel refreshes its CGNAT
	// mapping so the relay's return datagrams keep arriving. Kept short because a
	// jammed uplink may drop these. (End-to-end path liveness is a separate,
	// configurable concern handled by package keepalive.)
	DefaultKeepalive = 15 * time.Second

	// UpstreamMaxAge bounds how long a single HTTP upstream connection is reused
	// before it is recycled (closed, reconnected lazily on the next packet). This
	// keeps connections looking like ordinary finite uploads and sheds stale ones.
	UpstreamMaxAge = 5 * time.Minute

	// DefaultMTU for the tunnel interface. Bounded by a Starlink UDP datagram
	// (payload = 1 type byte + IP packet) fitting inside the path MTU.
	DefaultMTU = 1360
)
