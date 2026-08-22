package wire

import "net/netip"

// PlausibleIP reports whether p could be an IPv4 or IPv6 packet. It is used as a
// wrong-key tripwire on unauthenticated carriers: a wrong-PSK peer's
// de-obfuscated stream decodes to garbage that this rejects.
func PlausibleIP(p []byte) bool {
	if len(p) < 20 {
		return false
	}
	switch p[0] >> 4 {
	case 4:
		return len(p) >= 20
	case 6:
		return len(p) >= 40
	default:
		return false
	}
}

// DstIP extracts the destination address from an IPv4/IPv6 packet, if parseable.
// The relay uses it to route a return packet to the right client session.
func DstIP(p []byte) (netip.Addr, bool) {
	switch {
	case len(p) >= 20 && p[0]>>4 == 4:
		return netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]}), true
	case len(p) >= 40 && p[0]>>4 == 6:
		var a [16]byte
		copy(a[:], p[24:40])
		return netip.AddrFrom16(a), true
	}
	return netip.Addr{}, false
}

// SrcIP extracts the source address from an IPv4/IPv6 packet, if parseable. The
// relay uses it to identify which client a ping/packet came from.
func SrcIP(p []byte) (netip.Addr, bool) {
	switch {
	case len(p) >= 20 && p[0]>>4 == 4:
		return netip.AddrFrom4([4]byte{p[12], p[13], p[14], p[15]}), true
	case len(p) >= 40 && p[0]>>4 == 6:
		var a [16]byte
		copy(a[:], p[8:24])
		return netip.AddrFrom16(a), true
	}
	return netip.Addr{}, false
}
