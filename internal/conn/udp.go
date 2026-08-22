package conn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arash16/dualnet/internal/cipher"
	"github.com/arash16/dualnet/internal/netbind"
	"github.com/arash16/dualnet/internal/peers"
	"github.com/arash16/dualnet/internal/pktbuf"
	"github.com/arash16/dualnet/internal/proto"
	"github.com/arash16/dualnet/internal/wire"
)

const udpReadBuf = 65535

// udpBatchViews caps datagrams a receive Reader publishes per GRO read. The kernel coalesces at
// most ~64 same-size datagrams into one recvmsg; 128 leaves headroom so the views slice never
// reallocates (which would allocate on the hot path).
const udpBatchViews = 128

// newUDPBatch makes a receive Reader's batch: one 65535-byte buffer that a GRO read fills, split
// into up to udpBatchViews datagram views aliasing it.
func newUDPBatch() *pktbuf.Batch { return pktbuf.NewBatch(1, udpReadBuf, udpBatchViews) }

// udpSocketBuffer is the SO_RCVBUF/SO_SNDBUF we request on every UDP carrier socket. The OS
// silently clamps it to net.core.rmem_max/wmem_max (Linux) or kern.ipc.maxsockbuf (macOS), so
// a box that wants the full size must raise those sysctls; the request is harmless where it is
// clamped. A few MiB absorbs the burst that arrives while the single reader goroutine is busy
// in the cipher, which default (~208 KiB on Linux) buffers overflow — a silent drop storm at
// high pps. TCP is left to autotune (setting SO_*BUF there pins the window and hurts).
const udpSocketBuffer = 4 << 20

// bufferedConn is the socket-buffer surface of *net.UDPConn; a WARP userspace conn does not
// implement it, so setUDPBuffers is a no-op there (the WARP bind does its own sizing).
type bufferedConn interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

// setUDPBuffers enlarges a UDP socket's send/receive buffers. Errors are ignored: an
// unsupported conn (WARP) or a kernel that rejects the size just keeps its defaults.
func setUDPBuffers(c net.Conn) {
	if bc, ok := c.(bufferedConn); ok {
		_ = bc.SetReadBuffer(udpSocketBuffer)
		_ = bc.SetWriteBuffer(udpSocketBuffer)
	}
}

// udpSendBuf pools scratch buffers for the ListenOut reply path (the envelope blob and
// the sealed MsgData datagram), so a downlink send allocates nothing per packet. Safe
// for concurrent Send: each call gets its own buffer(s) and returns them when done.
var udpSendBuf = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

func getSendBuf() *[]byte  { return udpSendBuf.Get().(*[]byte) }
func putSendBuf(b *[]byte) { udpSendBuf.Put(b) }

// bindUDP opens a UDP listen socket, pinned to iface if non-empty.
func bindUDP(ctx context.Context, iface, listen string) (*net.UDPConn, error) {
	pc, err := netbind.ListenPacket(ctx, iface, "udp", listen)
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, errors.New("conn: listen socket is not UDP")
	}
	setUDPBuffers(uc)
	return uc, nil
}

func dialUDP(ctx context.Context, d SocketDialer, addr string) (net.Conn, error) {
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("conn: dial udp %s: %w", addr, err)
	}
	setUDPBuffers(c)
	return c, nil
}

// --- Connect + Outgoing (data sender) ----------------------------------------

type udpConnectOut struct {
	name   string
	addr   string
	dialer SocketDialer
	cipher cipher.PacketCipher

	mu   sync.Mutex
	conn net.Conn
	buf  []byte // reused datagram scratch: [nonce][envelope+inner], sealed in place
}

func (c *udpConnectOut) Name() string { return c.name }
func (c *udpConnectOut) Kind() Kind   { return KindConnectOut }

func (c *udpConnectOut) Start(ctx context.Context, _ Ingress) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if conn, err := dialUDP(ctx, c.dialer, c.addr); err == nil {
		c.conn = conn
	}
	return nil // dial lazily on first Send if it failed
}

func (c *udpConnectOut) Accepts(wire.Owner) bool { return true } // single outbound pipe

func (c *udpConnectOut) Send(e wire.Envelope, payload []byte) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		conn, err := dialUDP(context.Background(), c.dialer, c.addr)
		if err != nil {
			return true, err
		}
		c.conn = conn
	}
	// Build [nonce][envelope+inner] in one reused buffer and seal the body in place, rather
	// than serializing into a blob buffer and copying into a separate sealed buffer.
	hdr := c.cipher.Overhead()
	need := hdr + wire.EnvelopeLen + len(payload)
	if cap(c.buf) < need {
		c.buf = make([]byte, need)
	} else {
		c.buf = c.buf[:need]
	}
	wire.PutEnvelope(c.buf[hdr:hdr], e, payload)
	if err := c.cipher.SealInPlace(c.buf); err != nil {
		return true, err
	}
	if _, err := c.conn.Write(c.buf); err != nil {
		_ = c.conn.Close()
		c.conn = nil
		return true, err
	}
	return true, nil
}

func (c *udpConnectOut) Reconnect(ctx context.Context) error {
	nc, err := dialUDP(ctx, c.dialer, c.addr)
	if err != nil {
		return err
	}
	c.mu.Lock()
	old := c.conn
	c.conn = nc
	c.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (c *udpConnectOut) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// --- Connect + Incoming (data receiver; registers, applies assigned id) -------

type udpConnectIn struct {
	name     string
	addr     string
	dialer   SocketDialer
	cipher   cipher.PacketCipher
	key      [32]byte
	idSetter func(wire.Owner)
	onDrop   func()
	refresh  time.Duration

	mu     sync.Mutex
	conn   net.Conn
	curID  wire.Owner    // claimed id sent in registers (0 until assigned)
	lastTS atomic.Uint64 // last freshness stamp sent (strictly increasing)
}

func (c *udpConnectIn) Name() string { return c.name }
func (c *udpConnectIn) Kind() Kind   { return KindConnectIn }

// nextTS returns a strictly-increasing freshness stamp seeded by the wall clock, so control
// datagrams carry a monotonic timestamp the ListenOut uses to reject replays. Seeding from
// unix-nanos means a restarted peer's stamps still exceed the ones the ListenOut last recorded.
func (c *udpConnectIn) nextTS() uint64 {
	now := uint64(time.Now().UnixNano())
	for {
		prev := c.lastTS.Load()
		ts := now
		if ts <= prev {
			ts = prev + 1
		}
		if c.lastTS.CompareAndSwap(prev, ts) {
			return ts
		}
	}
}

func (c *udpConnectIn) Start(ctx context.Context, in Ingress) error {
	conn, err := dialUDP(ctx, c.dialer, c.addr)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	if err := c.sendControl(proto.MsgRegister); err != nil {
		return err
	}
	go c.maintain(ctx)
	go c.readLoop(ctx, in)
	return nil
}

func (c *udpConnectIn) getConn() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

func (c *udpConnectIn) sendControl(typ byte) error {
	c.mu.Lock()
	id, conn := c.curID, c.conn
	c.mu.Unlock()
	if conn == nil {
		return errors.New("conn: udp connect-in not dialed")
	}
	_, err := conn.Write(encodeControl(typ, id, 0, c.nextTS(), c.key))
	return err
}

func (c *udpConnectIn) maintain(ctx context.Context) {
	// Warm up with a few quick re-registers so a lost initial register (remote not yet
	// listening) recovers in well under the steady NAT-refresh cadence.
	for _, d := range []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second} {
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
		_ = c.sendControl(proto.MsgRegister)
	}
	t := time.NewTicker(c.refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = c.sendControl(proto.MsgKeepalive)
		}
	}
}

func (c *udpConnectIn) readLoop(ctx context.Context, in Ingress) {
	oob := make([]byte, groReadBufOOB)
	var groConn net.Conn
	// fill re-fetches the (reconnectable) conn, (re)enables GRO on a fresh one, reads one
	// (possibly coalesced) datagram burst, and publishes each segment. A transient read error
	// retries after a short backoff so a reconnect does not end the Reader; only ctx cancel does.
	fill := func(b *pktbuf.Batch) error {
		buf := b.Slots()[0]
		for {
			conn := c.getConn()
			if conn == nil {
				return io.EOF
			}
			if conn != groConn {
				enableGRO(conn)
				groConn = conn
			}
			n, segSize, err := readGRO(conn, buf, oob)
			if err != nil {
				if ctx.Err() != nil {
					return err
				}
				select {
				case <-ctx.Done():
					return err
				case <-time.After(200 * time.Millisecond):
				}
				continue
			}
			added := splitGRO(b, buf, n, segSize)
			if added == 0 {
				continue // empty datagram: read again rather than yield an empty batch
			}
			return nil
		}
	}
	r := pktbuf.NewReader(fill, nil, newUDPBatch)
	r.Start(ctx)
	for {
		pkt, ok := r.Next()
		if !ok {
			return
		}
		c.handleDatagram(pkt, in)
	}
}

// splitGRO publishes each datagram in a (possibly GRO-coalesced) read of buf[:n] as a view into b.
// segSize>0 means back-to-back datagrams of that size (the last possibly shorter); 0 is a single
// datagram. Returns the count published.
func splitGRO(b *pktbuf.Batch, buf []byte, n, segSize int) int {
	added := 0
	for off := 0; off < n; {
		dlen := n - off
		if segSize > 0 && dlen > segSize {
			dlen = segSize
		}
		b.Add(buf[off : off+dlen])
		off += dlen
		added++
	}
	return added
}

func (c *udpConnectIn) handleDatagram(dg []byte, in Ingress) {
	if len(dg) < 1 {
		return
	}
	switch dg[0] {
	case proto.MsgData:
		blob, oerr := c.cipher.Open(dg[1:])
		if oerr != nil {
			if c.onDrop != nil {
				c.onDrop()
			}
			return
		}
		e, payload, ok := wire.ParseEnvelope(blob)
		if !ok || !wire.PlausibleIP(payload) {
			if c.onDrop != nil {
				c.onDrop()
			}
			return
		}
		in(c.name, e, payload)
	case proto.MsgAssignID:
		typ, id, _, _, derr := decodeControl(dg, c.key)
		if derr != nil || typ != proto.MsgAssignID {
			return
		}
		c.mu.Lock()
		c.curID = id
		c.mu.Unlock()
		if c.idSetter != nil {
			c.idSetter(id)
		}
	case proto.MsgPong:
		// single-listener liveness; nothing to do
	}
}

func (c *udpConnectIn) Reconnect(ctx context.Context) error {
	nc, err := dialUDP(ctx, c.dialer, c.addr)
	if err != nil {
		return err
	}
	c.mu.Lock()
	old := c.conn
	c.conn = nc
	c.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return c.sendControl(proto.MsgRegister)
}

func (c *udpConnectIn) Close() error {
	if conn := c.getConn(); conn != nil {
		return conn.Close()
	}
	return nil
}

// --- Listen + Incoming (data receiver) ---------------------------------------

type udpListenIn struct {
	name   string
	conn   *net.UDPConn
	cipher cipher.PacketCipher
	onDrop func()
}

func (c *udpListenIn) Name() string { return c.name }
func (c *udpListenIn) Kind() Kind   { return KindListenIn }

func (c *udpListenIn) Start(ctx context.Context, in Ingress) error {
	enableGRO(c.conn) // best-effort; coalesces a run of same-size datagrams into one recvmsg
	oob := make([]byte, groReadBufOOB)
	fill := func(b *pktbuf.Batch) error {
		for {
			n, segSize, err := readGRO(c.conn, b.Slots()[0], oob)
			if err != nil {
				return err
			}
			if splitGRO(b, b.Slots()[0], n, segSize) > 0 {
				return nil
			}
			// empty datagram: read again rather than yield an empty batch
		}
	}
	r := pktbuf.NewReader(fill, c.conn.Close, newUDPBatch)
	r.Start(ctx)
	go func() {
		for {
			pkt, ok := r.Next()
			if !ok {
				return
			}
			c.deliver(pkt, in)
		}
	}()
	return nil
}

// deliver de-obfuscates one datagram, runs the tripwire, and hands it to routing (or drops it).
func (c *udpListenIn) deliver(datagram []byte, in Ingress) {
	blob, err := c.cipher.Open(datagram)
	if err != nil {
		if c.onDrop != nil {
			c.onDrop()
		}
		return
	}
	e, payload, ok := wire.ParseEnvelope(blob)
	if !ok || !wire.PlausibleIP(payload) {
		if c.onDrop != nil {
			c.onDrop()
		}
		return
	}
	in(c.name, e, payload)
}

func (c *udpListenIn) Close() error { return c.conn.Close() }

// --- Listen + Outgoing (data sender; tracks peers, mints ids) -----------------

type udpListenOut struct {
	name     string
	conn     *net.UDPConn
	cipher   cipher.PacketCipher
	key      [32]byte
	multiple bool
	reg      *peers.Registry
}

func (c *udpListenOut) Name() string { return c.name }
func (c *udpListenOut) Kind() Kind   { return KindListenOut }

func (c *udpListenOut) Start(ctx context.Context, _ Ingress) error {
	go func() {
		buf := make([]byte, udpReadBuf)
		for {
			n, addr, err := c.conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			typ, id, _, ts, derr := decodeControl(buf[:n], c.key)
			if derr != nil {
				continue
			}
			switch typ {
			case proto.MsgRegister, proto.MsgKeepalive:
				peerAddr := cloneUDPAddr(addr)
				assigned, ok := c.reg.Register(id, addr.String(), ts, c.sinkFor(peerAddr))
				if !ok {
					continue // stale/replayed control or peer cap reached — do not (re)bind or reply
				}
				if c.multiple {
					if id.IsZero() {
						_, _ = c.conn.WriteToUDP(encodeControl(proto.MsgAssignID, assigned, 0, ts, c.key), addr)
					}
				} else {
					_, _ = c.conn.WriteToUDP([]byte{proto.MsgPong}, addr)
				}
			}
		}
	}()
	return nil
}

// sinkFor returns a Sink that writes an already-sealed datagram to addr. Serialization and
// sealing happen once in Send (below), so the sink is just the per-peer write.
func (c *udpListenOut) sinkFor(addr *net.UDPAddr) peers.Sink {
	return func(datagram []byte) error {
		_, err := c.conn.WriteToUDP(datagram, addr)
		return err
	}
}

func (c *udpListenOut) Accepts(owner wire.Owner) bool { return c.reg.Accepts(owner) }

func (c *udpListenOut) Send(e wire.Envelope, payload []byte) (bool, error) {
	// Look up the peer first so we only serialize+seal when there is somewhere to send. Then
	// build [MsgData][nonce][envelope+inner] in one pooled buffer and seal the body in place —
	// one buffer, one pool round-trip, no separate blob/sealed copies.
	sink, ok := c.reg.SinkFor(e.Owner)
	if !ok {
		return false, nil
	}
	hdr := 1 + c.cipher.Overhead()
	need := hdr + wire.EnvelopeLen + len(payload)
	op := getSendBuf()
	out := *op
	if cap(out) < need {
		out = make([]byte, need)
	} else {
		out = out[:need]
	}
	out[0] = proto.MsgData
	wire.PutEnvelope(out[hdr:hdr], e, payload)
	err := c.cipher.SealInPlace(out[1:])
	if err == nil {
		err = sink(out)
	}
	*op = out
	putSendBuf(op)
	return true, err
}

// GC drops idle peers; called periodically by the node.
func (c *udpListenOut) GC() int { return c.reg.GC() }

func (c *udpListenOut) Close() error { return c.conn.Close() }

func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	ip := make(net.IP, len(a.IP))
	copy(ip, a.IP)
	return &net.UDPAddr{IP: ip, Port: a.Port, Zone: a.Zone}
}

var (
	_ Conn        = (*udpConnectOut)(nil)
	_ Sender      = (*udpConnectOut)(nil)
	_ Reconnecter = (*udpConnectOut)(nil)
	_ Conn        = (*udpConnectIn)(nil)
	_ Reconnecter = (*udpConnectIn)(nil)
	_ Conn        = (*udpListenIn)(nil)
	_ Conn        = (*udpListenOut)(nil)
	_ Sender      = (*udpListenOut)(nil)
)
