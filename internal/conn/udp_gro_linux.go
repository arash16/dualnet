//go:build linux

package conn

import (
	"encoding/binary"
	"net"

	"golang.org/x/sys/unix"
)

// groReadBufOOB sizes the out-of-band scratch for one ReadMsg: it only ever carries the single
// UDP_GRO control message (an int), so a small fixed buffer is ample.
const groReadBufOOB = 64

// enableGRO turns on UDP generic receive offload: the kernel coalesces a run of consecutive
// equal-sized datagrams from the same flow into one larger buffer delivered by a single recvmsg,
// with the per-segment size reported in an out-of-band control message. Best-effort — an older
// kernel or a non-UDP conn (WARP userspace) simply keeps one-datagram-per-read.
func enableGRO(c net.Conn) {
	uc, ok := c.(*net.UDPConn)
	if !ok {
		return
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	})
}

// readGRO reads one (possibly GRO-coalesced) datagram into buf and returns its byte count and
// the GRO segment size — 0 when the read was not coalesced (a single datagram) or the conn is
// not a *net.UDPConn. A non-zero segSize means buf[:n] holds back-to-back datagrams of segSize
// bytes each, the last possibly shorter. ReadMsgUDPAddrPort returns a value-type AddrPort, so
// like ReadFromUDPAddrPort it avoids a per-datagram *net.UDPAddr allocation.
func readGRO(c net.Conn, buf, oob []byte) (n, segSize int, err error) {
	uc, ok := c.(*net.UDPConn)
	if !ok {
		n, err = c.Read(buf)
		return n, 0, err
	}
	n, oobn, _, _, err := uc.ReadMsgUDPAddrPort(buf, oob)
	if err != nil {
		return 0, 0, err
	}
	return n, groSegSize(oob[:oobn]), nil
}

// groSegSize extracts the UDP_GRO segment size from a control-message buffer, or 0 if absent.
func groSegSize(oob []byte) int {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, m := range msgs {
		if m.Header.Level == unix.IPPROTO_UDP && m.Header.Type == unix.UDP_GRO && len(m.Data) >= 4 {
			// The kernel writes the GRO segment size as a C int in native byte order.
			return int(int32(binary.NativeEndian.Uint32(m.Data)))
		}
	}
	return 0
}
