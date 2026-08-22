//go:build !linux

package conn

import "net"

// groReadBufOOB is unused off Linux (no UDP_GRO), but the receive loops allocate it
// unconditionally; keep it tiny.
const groReadBufOOB = 1

// enableGRO is a no-op where UDP_GRO is unavailable (macOS client, others).
func enableGRO(net.Conn) {}

// readGRO reads one datagram. Without UDP_GRO the segment size is always 0 (the buffer holds a
// single datagram). It preserves the value-type AddrPort read that avoids a per-datagram
// *net.UDPAddr allocation for a *net.UDPConn.
func readGRO(c net.Conn, buf, _ []byte) (n, segSize int, err error) {
	if uc, ok := c.(*net.UDPConn); ok {
		n, _, err = uc.ReadFromUDPAddrPort(buf)
		return n, 0, err
	}
	n, err = c.Read(buf)
	return n, 0, err
}
