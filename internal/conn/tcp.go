package conn

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arash16/dualnet/internal/cipher"
	"github.com/arash16/dualnet/internal/peers"
	"github.com/arash16/dualnet/internal/pktbuf"
	"github.com/arash16/dualnet/internal/proto"
	"github.com/arash16/dualnet/internal/wire"
)

// The "tcp" transport is a raw, framed byte-stream carrier: length-prefixed, cipher-
// obfuscated frames straight over a TCP connection, with none of HTTP's request/response
// dressing. It exists for links that need a plain TCP flow (some middleboxes only pass
// TCP, and it drops HTTP's per-packet chunk framing and header overhead). It reuses the
// same stream framing (wire.WriteFrame/ReadFrame), stream cipher, control codec
// (control.go) and peer registry (package peers) as the other carriers, so it is
// structurally the UDP transport carried over a reliable stream.
//
// Data frames are pure enveloped blobs (identical to the HTTP body): frame =
// cipher(len16 || owner||flags||inner). The down-path (ConnectIn -> ListenOut) adds a
// tiny authenticated handshake on top:
//
//	ConnectIn -> ListenOut : one MsgRegister control frame, then periodic MsgKeepalive
//	                         frames (refresh the peer's idle timer; no data ever)
//	ListenOut -> ConnectIn : one MsgAssignID control frame (the minted id in Multiple
//	                         mode, the zero id as a bare ack otherwise), then data frames
//
// The two socket directions are independent keystreams; the first frame each way is the
// handshake, everything after is that direction's steady traffic. The control frames are
// PSK-authenticated and freshness-stamped exactly as the UDP carrier's datagrams, so an
// off-path party can neither register a peer nor make one adopt an attacker-chosen owner.
// The up-path (ConnectOut -> ListenIn) carries only data frames — no registration, like
// the obfuscation-only HTTP upload body.

const (
	tcpDialTimeout      = 15 * time.Second
	tcpHandshakeTimeout = 10 * time.Second
	tcpKeepAlivePeriod  = 30 * time.Second
	// tcpReadBufSize buffers the raw stream under the frame reader so a burst of frames is
	// pulled from the kernel in one read syscall instead of two per frame (the 2-byte length
	// then the body). Bounded per connection; the listener's connection cap bounds the total.
	tcpReadBufSize = 32 * 1024
	// tcpWriteBufSize buffers frames on the send side so a batch of packets (a download burst
	// off the egress tun, or a router receive-batch) coalesces into a few large socket writes —
	// and larger TCP segments — instead of one write per packet. Flush emits it at the batch
	// boundary; the buffer auto-drains when full. Sized to hold a full read-batch of MTU frames.
	tcpWriteBufSize = 128 * 1024
	// tcpBadFrames bounds undecodable frames before a receiver tears the stream down: a
	// wrong-key / MITM peer (the stream is not authenticated) could otherwise stream junk
	// at line rate. Mirrors the HTTP carrier.
	tcpBadFrames = 8
)

var errTCPDownDead = errors.New("conn: tcp downlink connection dead")

// setTCPOpts tunes an established TCP socket for tunnel traffic: Nagle off (latency) and
// OS-level keepalive on (reap a silently-dead peer). Shared by every tcp/http dialer and
// acceptor.
func setTCPOpts(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(tcpKeepAlivePeriod)
	}
}

// --- Connect + Outgoing (data sender; up-path) --------------------------------

// streamWriteBatch caps buffered packets in a stream carrier's write batch (connect-out uplink,
// listen-out per-peer downlink) before a full batch flushes inline; the arena (tcpWriteBufSize)
// caps the buffered bytes.
const streamWriteBatch = 64

type tcpConnectOut struct {
	name   string
	addr   string
	dialer SocketDialer
	cipher cipher.StreamCipher

	// Send buffers envelope blobs into w; flush (below) frames+ciphers a whole batch down the
	// stream. The flush group flushes a partial batch on its tick, so no separate flush trigger is
	// needed and the tun-driven uplink coalesces just like the download path.
	fg *pktbuf.FlushGroup
	w  *pktbuf.Writer

	mu        sync.Mutex
	conn      net.Conn
	bw        *bufio.Writer // buffers the raw socket so a batch coalesces into few writes
	obf       io.Writer     // frame writer (cipher over bw)
	connected bool
	dialing   bool // a background dial is in flight (at most one at a time)
	closed    bool // Close was called; a dial that completes later must not install a conn
	nextRetry time.Time
}

func (c *tcpConnectOut) Name() string                         { return c.name }
func (c *tcpConnectOut) Kind() Kind                           { return KindConnectOut }
func (c *tcpConnectOut) Accepts(wire.Owner) bool              { return true } // single outbound pipe
func (c *tcpConnectOut) Start(context.Context, Ingress) error { return nil }  // dials lazily on first flush

// Send buffers the packet's envelope blob; flush emits the batch to the wire.
func (c *tcpConnectOut) Send(e wire.Envelope, payload []byte) (bool, error) {
	dst := c.w.Reserve(wire.EnvelopeLen + len(payload))
	b := wire.PutEnvelope(dst[:0], e, payload)
	c.w.Commit(len(b))
	return true, nil
}

// flush frames every buffered blob down the stream and emits them in as few socket writes as the
// buffer allows. It NEVER dials: it runs on the node-wide flush-group goroutine (and inline in a
// producer's Commit), where a blocking dial would stall every writer on the node for the whole
// dial timeout. Disconnected, it kicks a background dial and drops the batch (the inner TCP
// retransmits); a write error likewise drops the batch and schedules a reconnect.
func (c *tcpConnectOut) flush(views [][]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.connected {
		c.kickDialLocked()
		return ErrBackoff
	}
	for _, v := range views {
		if err := wire.WriteFrame(c.obf, v); err != nil {
			c.resetLocked()
			c.nextRetry = time.Now().Add(reconnectBackoff)
			return err
		}
	}
	if err := c.bw.Flush(); err != nil {
		c.resetLocked()
		c.nextRetry = time.Now().Add(reconnectBackoff)
		return err
	}
	return nil
}

// kickDialLocked starts one background dial unless one is already in flight, the connection is
// closed, or a recent failure is still backing off.
func (c *tcpConnectOut) kickDialLocked() {
	if c.dialing || c.closed || time.Now().Before(c.nextRetry) {
		return
	}
	c.dialing = true
	go c.dial()
}

// dial establishes the transport socket off the flush path and installs it under the lock. A
// failure arms the retry backoff; a success that lost a race with Close is discarded.
func (c *tcpConnectOut) dial() {
	ctx, cancel := context.WithTimeout(context.Background(), tcpDialTimeout)
	defer cancel()
	conn, err := c.dialer.DialContext(ctx, "tcp", c.addr)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dialing = false
	if err != nil {
		c.nextRetry = time.Now().Add(reconnectBackoff)
		return
	}
	if c.closed {
		_ = conn.Close()
		return
	}
	setTCPOpts(conn)
	bw := bufio.NewWriterSize(conn, tcpWriteBufSize)
	obf, err := c.cipher.WrapWriter(bw) // emits the leading nonce (into the buffer, sent on first flush)
	if err != nil {
		_ = conn.Close()
		c.nextRetry = time.Now().Add(reconnectBackoff)
		return
	}
	c.conn, c.bw, c.obf, c.connected = conn, bw, obf, true
}

func (c *tcpConnectOut) resetLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn, c.bw, c.obf, c.connected = nil, nil, nil, false
}

func (c *tcpConnectOut) Reconnect(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetLocked()
	c.nextRetry = time.Time{}
	return nil
}

func (c *tcpConnectOut) Close() error {
	c.fg.Remove(c.w)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.resetLocked()
	return nil
}

// --- Listen + Incoming (data receiver; up-path) -------------------------------

type tcpListenIn struct {
	name   string
	ln     net.Listener
	cipher cipher.StreamCipher
	onDrop func()
}

func (c *tcpListenIn) Name() string { return c.name }
func (c *tcpListenIn) Kind() Kind   { return KindListenIn }

func (c *tcpListenIn) Start(ctx context.Context, in Ingress) error {
	go acceptLoop(ctx, c.ln, func(conn net.Conn) { c.handle(ctx, conn, in) })
	return nil
}

func (c *tcpListenIn) handle(ctx context.Context, conn net.Conn, in Ingress) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	setTCPOpts(conn)
	br := bufio.NewReaderSize(conn, tcpReadBufSize)
	obf, err := c.cipher.WrapReader(br)
	if err != nil {
		return
	}
	runStreamReader(ctx, conn, br, obf, c.name, in, c.onDrop)
}

// newStreamBatch sizes a stream Reader's batch: one frame at a time (net/http and bufio expose no
// portable "read many frames" primitive, so the frame is the unit), each up to MaxPacket. The
// prefetch goroutine reads+decrypts the next frame while the consumer routes the current one.
func newStreamBatch() *pktbuf.Batch { return pktbuf.NewBatch(1, wire.MaxPacket, 1) }

// runStreamReader reads frames off an obfuscated stream through a prefetch Reader and routes each.
// Frames buffered in br from one socket read are pulled without extra syscalls; the stall-reaping
// read deadline is refreshed only when about to block (br empty), so buffered frames cost no extra
// SetReadDeadline syscall. A run of undecodable frames tears the stream down (a wrong-key/MITM peer
// streaming junk). Routing targets self-flush via the node's flush group, so there is nothing to
// flush here. Returns when the stream ends, errors, or ctx is cancelled.
func runStreamReader(ctx context.Context, conn net.Conn, br *bufio.Reader, obf io.Reader, name string, in Ingress, onDrop func()) {
	fill := func(b *pktbuf.Batch) error {
		if br.Buffered() == 0 {
			_ = conn.SetReadDeadline(time.Now().Add(httpFrameReadTimeout))
		}
		n, err := wire.ReadFrame(obf, b.Slots()[0])
		if err != nil {
			return err
		}
		b.Add(b.Slots()[0][:n])
		return nil
	}
	r := pktbuf.NewReader(fill, conn.Close, newStreamBatch)
	r.Start(ctx)
	bad := 0
	for {
		pkt, ok := r.Next()
		if !ok {
			return
		}
		if e, payload, ok := wire.ParseEnvelope(pkt); ok && wire.PlausibleIP(payload) {
			bad = 0
			in(name, e, payload)
			continue
		}
		if onDrop != nil {
			onDrop()
		}
		if bad++; bad > tcpBadFrames {
			_ = r.Close()
			return
		}
	}
}

func (c *tcpListenIn) Close() error { return c.ln.Close() }

// --- Connect + Incoming (data receiver; registers, adopts assigned id) --------

type tcpConnectIn struct {
	name     string
	addr     string
	dialer   SocketDialer
	cipher   cipher.StreamCipher
	key      [32]byte
	idSetter func(wire.Owner)
	onDrop   func()
	refresh  time.Duration

	sendTS atomic.Uint64 // monotonic freshness stamp for our control frames

	mu         sync.Mutex
	cancel     context.CancelFunc
	curID      wire.Owner // claimed id sent in registers (0 until assigned)
	lastAssign uint64     // freshness of the last accepted id-assignment
}

func (c *tcpConnectIn) Name() string { return c.name }
func (c *tcpConnectIn) Kind() Kind   { return KindConnectIn }

// nextTS returns a strictly-increasing freshness stamp seeded by the wall clock, so a
// restarted peer's stamps still exceed the ones the ListenOut last recorded. See the UDP
// analogue in udpConnectIn.nextTS.
func (c *tcpConnectIn) nextTS() uint64 {
	now := uint64(time.Now().UnixNano())
	for {
		prev := c.sendTS.Load()
		ts := now
		if ts <= prev {
			ts = prev + 1
		}
		if c.sendTS.CompareAndSwap(prev, ts) {
			return ts
		}
	}
}

func (c *tcpConnectIn) Start(ctx context.Context, in Ingress) error {
	go func() {
		for ctx.Err() == nil {
			c.stream(ctx, in)
			select {
			case <-ctx.Done():
				return
			case <-time.After(reconnectBackoff):
			}
		}
	}()
	return nil
}

func (c *tcpConnectIn) stream(ctx context.Context, in Ingress) {
	reqCtx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.cancel = cancel
	id := c.curID
	c.mu.Unlock()
	defer cancel()

	conn, err := c.dialer.DialContext(reqCtx, "tcp", c.addr)
	if err != nil {
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(reqCtx, func() { _ = conn.Close() })
	defer stop()
	setTCPOpts(conn)

	// Handshake: register under our current id, then read the (authenticated) assignment.
	_ = conn.SetReadDeadline(time.Now().Add(tcpHandshakeTimeout))
	obfW, err := c.cipher.WrapWriter(conn) // emits our nonce
	if err != nil {
		return
	}
	if err := wire.WriteFrame(obfW, encodeControl(proto.MsgRegister, id, 0, c.nextTS(), c.key)); err != nil {
		return
	}
	br := bufio.NewReaderSize(conn, tcpReadBufSize)
	obfR, err := c.cipher.WrapReader(br) // consumes the peer's nonce
	if err != nil {
		return
	}
	buf := make([]byte, wire.MaxPacket)
	n, err := wire.ReadFrame(obfR, buf)
	if err != nil {
		return
	}
	if typ, aid, _, ts, derr := decodeControl(buf[:n], c.key); derr == nil && typ == proto.MsgAssignID && !aid.IsZero() {
		// Adopt only a PSK-authenticated id fresher than the last accepted, so neither a MITM
		// (the stream is not authenticated) nor a replayed assignment can flap our tun's owner.
		c.mu.Lock()
		fresh := ts > c.lastAssign
		if fresh {
			c.lastAssign = ts
			c.curID = aid
			id = aid
		}
		c.mu.Unlock()
		if fresh && c.idSetter != nil {
			c.idSetter(aid)
		}
	}
	_ = conn.SetReadDeadline(time.Time{}) // steady downlink may idle between packets; liveness is the healthcheck's job

	// Keepalives are now the sole writer of obfW; refreshing our idle timer so a Multiple
	// ListenOut's GC does not evict us while the connection is alive (TCP needs no NAT punch,
	// unlike UDP, but the registry's timer still has to be bumped).
	go c.keepalive(reqCtx, obfW, id)

	runStreamReader(reqCtx, conn, br, obfR, c.name, in, c.onDrop)
}

func (c *tcpConnectIn) keepalive(ctx context.Context, obfW io.Writer, id wire.Owner) {
	t := time.NewTicker(c.refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := wire.WriteFrame(obfW, encodeControl(proto.MsgKeepalive, id, 0, c.nextTS(), c.key)); err != nil {
				return // the read loop will see the same failure and reconnect
			}
		}
	}
}

func (c *tcpConnectIn) Reconnect(context.Context) error {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

func (c *tcpConnectIn) Close() error { return c.Reconnect(context.Background()) }

// --- Listen + Outgoing (data sender; tracks peers, mints ids; down-path) ------

// tcpDownConn is one accepted downstream connection: the write half of the stream. The router's
// Send buffers into w (via sink); flushViews frames a whole batch down the stream in a few large
// socket writes. pc.mu serializes flushes with the handshake's assignment write, so no data frame
// can reach the wire before the assignment.
type tcpDownConn struct {
	conn net.Conn
	w    *pktbuf.Writer
	dead atomic.Bool // stream torn down (handler exited, or a write desynced the keystream)

	mu  sync.Mutex
	bw  *bufio.Writer // buffers the raw socket so a flushed batch coalesces into few writes
	obf io.Writer     // frame writer (cipher over bw)
}

// sink is the peers.Sink installed for this connection: it buffers an already-enveloped blob into
// the peer's write batch. The dead check is advisory (a racing teardown just wastes the copy); the
// wire is only ever touched in flushViews.
func (pc *tcpDownConn) sink(blob []byte) error {
	if pc.dead.Load() {
		return errTCPDownDead
	}
	dst := pc.w.Reserve(len(blob))
	n := copy(dst, blob)
	pc.w.Commit(n)
	return nil
}

// flushViews is the peer Writer's flush: it frames the batch down the stream and drains the
// socket buffer once. A write failure desyncs the stateful keystream, so it closes the connection
// (the client reconnects fresh) and refuses further writes.
func (pc *tcpDownConn) flushViews(views [][]byte) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.dead.Load() {
		return errTCPDownDead
	}
	for _, v := range views {
		if err := wire.WriteFrame(pc.obf, v); err != nil {
			pc.teardownLocked()
			return err
		}
	}
	if err := pc.bw.Flush(); err != nil {
		pc.teardownLocked()
		return err
	}
	return nil
}

func (pc *tcpDownConn) teardownLocked() {
	pc.dead.Store(true)
	_ = pc.conn.Close()
}

type tcpListenOut struct {
	name     string
	ln       net.Listener
	cipher   cipher.StreamCipher
	key      [32]byte
	multiple bool
	reg      *peers.Registry
	fg       *pktbuf.FlushGroup // flushes each peer's write batch on the node-wide interval
}

func (c *tcpListenOut) Name() string { return c.name }
func (c *tcpListenOut) Kind() Kind   { return KindListenOut }

func (c *tcpListenOut) Start(ctx context.Context, _ Ingress) error {
	go acceptLoop(ctx, c.ln, func(conn net.Conn) { c.handle(ctx, conn) })
	return nil
}

func (c *tcpListenOut) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	setTCPOpts(conn)

	// Read the registration, verify + freshness-check it, then install this stream as the
	// peer's return path and answer with its assigned id — all before any data can flow.
	_ = conn.SetReadDeadline(time.Now().Add(tcpHandshakeTimeout))
	obfR, err := c.cipher.WrapReader(conn) // consumes the client's nonce
	if err != nil {
		return
	}
	buf := make([]byte, wire.MaxPacket)
	n, err := wire.ReadFrame(obfR, buf)
	if err != nil {
		return
	}
	typ, id, _, ts, derr := decodeControl(buf[:n], c.key)
	if derr != nil || (typ != proto.MsgRegister && typ != proto.MsgKeepalive) {
		return // not an authenticated registration — a scanner or wrong-key/mismatched client
	}
	bw := bufio.NewWriterSize(conn, tcpWriteBufSize)
	obfW, err := c.cipher.WrapWriter(bw) // emits our nonce (into the buffer, sent with the assignment)
	if err != nil {
		return
	}
	peerKey := conn.RemoteAddr().String()
	pc := &tcpDownConn{conn: conn, bw: bw, obf: obfW}
	pc.w = pktbuf.NewWriter(pc.flushViews, tcpWriteBufSize, streamWriteBatch)

	// Hold pc.mu across Register + the assignment write so a concurrent router Send (whose
	// buffered batch reaches the wire only through flushViews, under pc.mu) cannot slip a data
	// frame ahead of the assignment: the client relies on the first frame being the assignment.
	pc.mu.Lock()
	assigned, ok := c.reg.Register(id, peerKey, ts, pc.sink)
	if !ok {
		pc.mu.Unlock()
		return // stale/replayed registration or the peer cap is reached
	}
	err = wire.WriteFrame(obfW, encodeControl(proto.MsgAssignID, assigned, 0, ts, c.key))
	if err == nil {
		err = bw.Flush() // the client waits on the assignment under a deadline; push it out now
	}
	pc.mu.Unlock()
	if err != nil {
		return
	}
	c.fg.Add(pc.w)
	defer c.fg.Remove(pc.w)
	defer pc.dead.Store(true) // stop buffering into a stream whose read half is gone
	_ = conn.SetReadDeadline(time.Time{})

	// Steady read: the client sends only keepalives, which refresh its idle timer; the read
	// also detects the connection closing (the client reconnecting, or dying) so the slot and
	// goroutine are freed. A per-read deadline reaps a peer that goes silent (its keepalives
	// stop) well before the registry GC would.
	bad := 0
	for {
		_ = conn.SetReadDeadline(time.Now().Add(httpFrameReadTimeout))
		n, err := wire.ReadFrame(obfR, buf)
		if err != nil {
			return
		}
		ktyp, kid, _, kts, kerr := decodeControl(buf[:n], c.key)
		if kerr != nil || (ktyp != proto.MsgRegister && ktyp != proto.MsgKeepalive) {
			if bad++; bad > tcpBadFrames {
				return
			}
			continue
		}
		bad = 0
		c.reg.Register(kid, peerKey, kts, pc.sink) // freshness-gated refresh (lastSeen/sink)
	}
}

func (c *tcpListenOut) Accepts(owner wire.Owner) bool { return c.reg.Accepts(owner) }

func (c *tcpListenOut) Send(e wire.Envelope, payload []byte) (bool, error) {
	// reg.Send calls the sink synchronously, so the pooled blob buffer is done being read
	// (the sink copies it into the peer's write batch) by the time Send returns.
	bp := getSendBuf()
	*bp = wire.PutEnvelope((*bp)[:0], e, payload)
	delivered, err := c.reg.Send(e.Owner, *bp)
	putSendBuf(bp)
	return delivered, err
}

func (c *tcpListenOut) GC() int { return c.reg.GC() }

func (c *tcpListenOut) Close() error { return c.ln.Close() }

// acceptLoop accepts connections until ctx is cancelled (which closes ln, unblocking
// Accept) and runs handle for each in its own goroutine.
func acceptLoop(ctx context.Context, ln net.Listener, handle func(net.Conn)) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(conn)
	}
}

var (
	_ Conn        = (*tcpConnectOut)(nil)
	_ Sender      = (*tcpConnectOut)(nil)
	_ Reconnecter = (*tcpConnectOut)(nil)
	_ Conn        = (*tcpListenIn)(nil)
	_ Conn        = (*tcpConnectIn)(nil)
	_ Reconnecter = (*tcpConnectIn)(nil)
	_ Conn        = (*tcpListenOut)(nil)
	_ Sender      = (*tcpListenOut)(nil)
	_ Maintainer  = (*tcpListenOut)(nil)
)
