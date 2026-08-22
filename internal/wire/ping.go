package wire

import "encoding/binary"

// End-to-end healthcheck ping.
//
// The healthcheck is a round-trip probe oblivious to which carrier each hop uses: a
// Tun injects a ping into the routing table (owner = the tun's id, Processed=false),
// it travels the same path as data up to a gateway, the gateway's finalizer reflects
// it back (Processed=true) to the process rule's Target instead of egressing it, and
// it returns to the origin Tun which consumes it as liveness. Identity is the
// envelope owner, so the ping's inner IP addresses are never inspected — it only has
// to be a well-formed, otherwise-unused IPv4 packet so it passes the PlausibleIP
// tripwire while riding the tunnel obfuscated like any other packet.

// pingProto is the IP protocol number stamped on pings. 253/254 are IANA
// "experimentation and testing" values, so a ping is a well-formed but unused packet.
const pingProto = 253

// pingLen is the size of a ping: a 20-byte IPv4 header + 8-byte nonce.
const pingLen = 20 + 8

// EncodePing builds a healthcheck ping carrying nonce. The inner addresses are left
// zero: routing and reflection are driven entirely by the envelope owner, not the IP
// header.
func EncodePing(nonce uint64) []byte {
	p := make([]byte, pingLen)
	p[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(p[2:4], uint16(pingLen))
	p[8] = 64        // TTL
	p[9] = pingProto // protocol
	binary.BigEndian.PutUint64(p[20:28], nonce)
	return p
}

// IsPing reports whether pkt is a healthcheck ping produced by EncodePing.
func IsPing(pkt []byte) bool {
	return len(pkt) >= pingLen && pkt[0]>>4 == 4 && pkt[9] == pingProto
}
