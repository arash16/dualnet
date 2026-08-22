package wire

// Per-packet routing envelope.
//
// In the generalized multi-node model a packet is no longer identified by its inner
// IP addresses; instead every inter-node packet carries a small tunnel header,
// [owner:4][flags:1], prefixed to the inner IP packet *before* the cipher. Because it
// rides inside the obfuscated blob (under the XOR keystream / per-datagram nonce)
// there is no constant on-wire marker to fingerprint.
//
//	plaintext blob = [owner:4][flags:1][ inner IP packet ]
//	wire (stream)  = len16 || cipher(blob)
//	wire (udp)     = nonce || cipher(blob)
//
// The envelope is serialized only at an Outgoing connection's send and parsed at an
// Incoming connection's receive; inside a node packets travel as (Envelope, payload)
// and a Tun never sees bytes 0..4.

// OwnerLen is the length of a routing identity: a random 4-byte id, stamped by the
// Tun that originates a packet and preserved across every hop and the finalizer
// round-trip. It replaces the tunnel virtual IP as the routing key.
const OwnerLen = 4

// EnvelopeLen is the size of the [owner:4][flags:1] header.
const EnvelopeLen = OwnerLen + 1

// flagProcessed marks a packet that has been through a finalizer (sent to / received
// from the internet), as opposed to a raw packet still travelling toward a gateway.
const flagProcessed = 0x01

// Owner is a 4-byte routing identity.
type Owner [OwnerLen]byte

// IsZero reports whether the owner is the all-zero (unassigned) id.
func (o Owner) IsZero() bool { return o == Owner{} }

// Envelope is the per-packet routing metadata carried between nodes.
type Envelope struct {
	Owner     Owner
	Processed bool
}

func (e Envelope) flags() byte {
	if e.Processed {
		return flagProcessed
	}
	return 0
}

// PutEnvelope writes owner||flags||inner into dst and returns the result. Pass
// dst[:0] with spare capacity to reuse a buffer without allocating.
func PutEnvelope(dst []byte, e Envelope, inner []byte) []byte {
	dst = append(dst[:0], e.Owner[0], e.Owner[1], e.Owner[2], e.Owner[3], e.flags())
	return append(dst, inner...)
}

// ParseEnvelope splits a de-obfuscated blob into its envelope and inner payload. ok
// is false if the blob is too short. The returned payload aliases blob.
func ParseEnvelope(blob []byte) (e Envelope, inner []byte, ok bool) {
	if len(blob) < EnvelopeLen {
		return Envelope{}, nil, false
	}
	copy(e.Owner[:], blob[:OwnerLen])
	e.Processed = blob[OwnerLen]&flagProcessed != 0
	return e, blob[EnvelopeLen:], true
}
