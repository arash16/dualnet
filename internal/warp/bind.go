package warp

import "golang.zx2c4.com/wireguard/conn"

// reservedBind wraps a conn.Bind and stamps the 3 WireGuard "reserved" header
// bytes (bytes 1..3) of every outgoing packet with the WARP client id. Cloudflare
// uses these to identify the account; vanilla wireguard-go leaves them zero.
type reservedBind struct {
	inner    conn.Bind
	reserved [3]byte
}

func newReservedBind(reserved [3]byte) *reservedBind {
	return &reservedBind{inner: conn.NewDefaultBind(), reserved: reserved}
}

// Open wraps the receive functions so incoming packets have their reserved
// bytes zeroed. WARP sets those bytes on its replies; wireguard-go reads the
// message type as a uint32 over bytes 0..3, so non-zero reserved bytes make it
// reject the handshake response as an "unknown message type". Zeroing them
// restores the standard type check.
func (b *reservedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i := range fns {
		fn := fns[i]
		wrapped[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, rerr := fn(packets, sizes, eps)
			for j := 0; j < n; j++ {
				if sizes[j] >= 4 {
					packets[j][1], packets[j][2], packets[j][3] = 0, 0, 0
				}
			}
			return n, rerr
		}
	}
	return wrapped, actualPort, err
}

func (b *reservedBind) Close() error              { return b.inner.Close() }
func (b *reservedBind) SetMark(mark uint32) error { return b.inner.SetMark(mark) }
func (b *reservedBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.inner.ParseEndpoint(s)
}
func (b *reservedBind) BatchSize() int { return b.inner.BatchSize() }

func (b *reservedBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.reserved != ([3]byte{}) {
		for _, buf := range bufs {
			if len(buf) >= 4 {
				buf[1], buf[2], buf[3] = b.reserved[0], b.reserved[1], b.reserved[2]
			}
		}
	}
	return b.inner.Send(bufs, ep)
}
