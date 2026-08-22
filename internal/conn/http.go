package conn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arash16/dualnet/internal/cipher"
	"github.com/arash16/dualnet/internal/pktbuf"
	"github.com/arash16/dualnet/internal/proto"
	"github.com/arash16/dualnet/internal/wire"
)

const httpDialTimeout = 15 * time.Second
const reconnectBackoff = time.Second
const defaultUserAgent = "Mozilla/5.0"

// HTTPParams customizes the HTTP carrier of a connection. Empty fields fall back to the
// proto defaults via withDefaults. Headers are extra request headers sent by the client.
type HTTPParams struct {
	UploadPath   string
	DownloadPath string
	Host         string // Host header override ("" = the dial host)
	UserAgent    string
	IDHeader     string // routing-tag header name
	Headers      map[string]string
}

// withDefaults returns a copy with empty fields filled from the proto defaults. dialHost
// seeds the Host-header default (pass "" on the listen side, which sends no request).
func (h HTTPParams) withDefaults(dialHost string) HTTPParams {
	if h.UploadPath == "" {
		h.UploadPath = proto.UpstreamPath
	}
	if h.DownloadPath == "" {
		h.DownloadPath = proto.DownstreamPath
	}
	if h.UserAgent == "" {
		h.UserAgent = defaultUserAgent
	}
	if h.IDHeader == "" {
		h.IDHeader = proto.HeaderID
	}
	if h.Host == "" {
		h.Host = dialHost
	}
	return h
}

// ErrBackoff is returned by a ConnectOut Send while a reconnect is throttled; the
// packet is dropped (inner TCP retransmits).
var ErrBackoff = errors.New("conn: upstream reconnect backoff")

// --- Connect + Outgoing over HTTP (chunked POST body) -------------------------

type httpConnectOut struct {
	name       string
	host       string // dial target host:port
	path       string // upload path
	hostHeader string // Host header value
	userAgent  string
	idHeader   string // routing-tag header name
	headers    map[string]string
	chanID     string // stable per-connection id, for ListenIn supersede
	cipher     cipher.StreamCipher
	dialer     SocketDialer
	maxAge     time.Duration

	mu          sync.Mutex
	conn        net.Conn
	obf         io.Writer
	cw          *chunkedWriter
	connected   bool
	connectedAt time.Time
	nextRetry   time.Time
	blobBuf     []byte
}

func (c *httpConnectOut) Name() string                         { return c.name }
func (c *httpConnectOut) Kind() Kind                           { return KindConnectOut }
func (c *httpConnectOut) Accepts(wire.Owner) bool              { return true }
func (c *httpConnectOut) Start(context.Context, Ingress) error { return nil } // connects lazily on first Send

func (c *httpConnectOut) Send(e wire.Envelope, payload []byte) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connected && c.maxAge > 0 && time.Since(c.connectedAt) > c.maxAge {
		c.resetLocked()
	}
	if !c.connected {
		if time.Now().Before(c.nextRetry) {
			return true, ErrBackoff
		}
		if err := c.connectLocked(); err != nil {
			c.nextRetry = time.Now().Add(reconnectBackoff)
			return true, err
		}
	}
	c.blobBuf = wire.PutEnvelope(c.blobBuf, e, payload)
	if err := wire.WriteFrame(c.obf, c.blobBuf); err != nil {
		c.resetLocked()
		c.nextRetry = time.Now().Add(reconnectBackoff)
		return true, err
	}
	return true, nil
}

func (c *httpConnectOut) connectLocked() error {
	ctx, cancel := context.WithTimeout(context.Background(), httpDialTimeout)
	defer cancel()
	conn, err := c.dialer.DialContext(ctx, "tcp", c.host)
	if err != nil {
		return err
	}
	setTCPOpts(conn)
	var hb bytes.Buffer
	fmt.Fprintf(&hb, "POST %s HTTP/1.1\r\n", c.path)
	fmt.Fprintf(&hb, "Host: %s\r\n", c.hostHeader)
	fmt.Fprintf(&hb, "User-Agent: %s\r\n", c.userAgent)
	fmt.Fprintf(&hb, "%s: %s\r\n", c.idHeader, c.chanID)
	fmt.Fprintf(&hb, "Content-Type: application/octet-stream\r\n")
	for k, v := range c.headers {
		fmt.Fprintf(&hb, "%s: %s\r\n", k, v)
	}
	fmt.Fprintf(&hb, "Transfer-Encoding: chunked\r\n\r\n")
	if _, err := conn.Write(hb.Bytes()); err != nil {
		_ = conn.Close()
		return err
	}
	cw := &chunkedWriter{w: conn}
	obf, err := c.cipher.WrapWriter(cw)
	if err != nil {
		_ = conn.Close()
		return err
	}
	c.conn, c.cw, c.obf = conn, cw, obf
	c.connected = true
	c.connectedAt = time.Now()
	go func(cc net.Conn) { _, _ = io.Copy(io.Discard, cc); _ = cc.Close() }(conn)
	return nil
}

func (c *httpConnectOut) resetLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn, c.obf, c.cw, c.connected = nil, nil, nil, false
}

func (c *httpConnectOut) Reconnect(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetLocked()
	c.nextRetry = time.Time{}
	return nil
}

func (c *httpConnectOut) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetLocked()
	return nil
}

// chunkedWriter emits each Write as one HTTP/1.1 chunk directly to the connection.
type chunkedWriter struct {
	w   io.Writer
	buf []byte
}

func (c *chunkedWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.buf = c.buf[:0]
	c.buf = strconv.AppendInt(c.buf, int64(len(p)), 16)
	c.buf = append(c.buf, '\r', '\n')
	c.buf = append(c.buf, p...)
	c.buf = append(c.buf, '\r', '\n')
	if _, err := c.w.Write(c.buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

// --- Connect + Incoming over HTTP (long-lived GET response body) --------------

type httpConnectIn struct {
	name       string
	url        string
	hostHeader string // Host header value
	userAgent  string
	idHeader   string   // routing-tag header name
	key        [32]byte // PSK-derived key: authenticates registration + verifies id-assignment
	headers    map[string]string
	cipher     cipher.StreamCipher
	client     *http.Client
	idSetter   func(wire.Owner)
	onDrop     func()

	sendTS atomic.Uint64 // monotonic freshness stamp for our registration tokens

	mu         sync.Mutex
	cancel     context.CancelFunc
	curID      wire.Owner
	lastAssign uint64 // freshness of the last accepted id-assignment (rejects a replayed old one)
}

// nextTS returns a strictly-increasing freshness stamp seeded by the wall clock (see the UDP
// analogue): a registration token carries it so the server can reject a replayed GET.
func (c *httpConnectIn) nextTS() uint64 {
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

func (c *httpConnectIn) Name() string { return c.name }
func (c *httpConnectIn) Kind() Kind   { return KindConnectIn }

func (c *httpConnectIn) Start(ctx context.Context, in Ingress) error {
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

func (c *httpConnectIn) stream(ctx context.Context, in Ingress) {
	reqCtx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.cancel = cancel
	id := c.curID
	c.mu.Unlock()
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, c.url, nil)
	if err != nil {
		return
	}
	if c.hostHeader != "" {
		req.Host = c.hostHeader
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set(c.idHeader, ownerHex(id))
	// Prove PSK knowledge over the id we register under, so the server won't register an
	// off-path client (or let a scanner hijack the downlink). Freshness (ts) lets it reject a
	// replayed GET.
	req.Header.Set(sigHeaderName(c.idHeader), authToken(c.key, authDomainReg, id, c.nextTS()))
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if h := resp.Header.Get(c.idHeader); h != "" {
		if assigned := parseOwnerHex(h); !assigned.IsZero() {
			// Only adopt an id the server authenticated with the PSK — else a MITM on the
			// plaintext response could stamp our tun with an attacker-chosen owner. Require the
			// assignment to be fresher than the last accepted, so an old assignment can't be
			// replayed to flap our id.
			ts, ok := verifyAuthToken(c.key, authDomainAssign, assigned, resp.Header.Get(sigHeaderName(c.idHeader)))
			c.mu.Lock()
			fresh := ok && ts > c.lastAssign
			if fresh {
				c.lastAssign = ts
				c.curID = assigned
			}
			c.mu.Unlock()
			if fresh && c.idSetter != nil {
				c.idSetter(assigned)
			}
		}
	}

	obf, err := c.cipher.WrapReader(resp.Body)
	if err != nil {
		return
	}
	// net/http buffers the body but exposes no "frames available" hook, so the Reader prefetches
	// one frame at a time: it still overlaps decrypt of the next frame with routing of the current.
	// reqCtx cancel (Reconnect / shutdown) aborts the body, unblocking a read in fill.
	fill := func(b *pktbuf.Batch) error {
		n, err := wire.ReadFrame(obf, b.Slots()[0])
		if err != nil {
			return err
		}
		b.Add(b.Slots()[0][:n])
		return nil
	}
	rd := pktbuf.NewReader(fill, nil, newStreamBatch)
	rd.Start(reqCtx)
	bad := 0
	for {
		pkt, ok := rd.Next()
		if !ok {
			return
		}
		e, payload, ok := wire.ParseEnvelope(pkt)
		if ok && wire.PlausibleIP(payload) {
			bad = 0
			in(c.name, e, payload)
			continue
		}
		if c.onDrop != nil {
			c.onDrop()
		}
		// Bail after a run of undecodable frames — a MITM / wrong-key downstream (the download
		// body is plaintext, no TLS) could otherwise stream endless junk and spin at line rate.
		// Returning lets the deferred cancel abort the body and Start's backoff reconnect.
		if bad++; bad > 8 {
			return
		}
	}
}

func (c *httpConnectIn) Reconnect(context.Context) error {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

func (c *httpConnectIn) Close() error {
	_ = c.Reconnect(context.Background())
	c.client.CloseIdleConnections()
	return nil
}

// --- Listen + Incoming over HTTP (accepts POST bodies) ------------------------

type httpListenIn struct {
	name     string
	path     string // upload path to match
	idHeader string // routing-tag header name
	srv      *http.Server
	ln       net.Listener
	cipher   cipher.StreamCipher
	onDrop   func()

	mu     sync.Mutex
	sink   Ingress
	active map[string]*httpInHandle
}

type httpInHandle struct{ cancel func() }

func (c *httpListenIn) Name() string { return c.name }
func (c *httpListenIn) Kind() Kind   { return KindListenIn }

func (c *httpListenIn) Start(ctx context.Context, in Ingress) error {
	c.mu.Lock()
	c.sink = in
	c.mu.Unlock()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = c.srv.Shutdown(sctx)
	}()
	go func() {
		if err := c.srv.Serve(c.ln); err != nil && err != http.ErrServerClosed {
			return
		}
	}()
	return nil
}

func (c *httpListenIn) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != c.path {
		http.NotFound(w, r)
		return
	}
	chanID := r.Header.Get(c.idHeader)
	rc := http.NewResponseController(w)
	h := &httpInHandle{cancel: func() { _ = rc.SetReadDeadline(time.Now()) }}
	c.replace(chanID, h)
	defer c.remove(chanID, h)

	obf, err := c.cipher.WrapReader(r.Body)
	if err != nil {
		return
	}
	c.mu.Lock()
	sink := c.sink
	c.mu.Unlock()
	// Reap a body that stalls with no frame (a slowloris past the header timeout): fill refreshes
	// the per-frame deadline before each read, so an active stream is never severed but a stalled
	// one errors out and frees its slot. A supersede (replace → SetReadDeadline(now)) unblocks it
	// the same way. net/http exposes no drain hook, so the Reader prefetches one frame at a time.
	fill := func(b *pktbuf.Batch) error {
		_ = rc.SetReadDeadline(time.Now().Add(httpFrameReadTimeout))
		n, err := wire.ReadFrame(obf, b.Slots()[0])
		if err != nil {
			return err
		}
		b.Add(b.Slots()[0][:n])
		return nil
	}
	rd := pktbuf.NewReader(fill, nil, newStreamBatch)
	rd.Start(r.Context())
	bad := 0
	for {
		pkt, ok := rd.Next()
		if !ok {
			return
		}
		e, payload, ok := wire.ParseEnvelope(pkt)
		if ok && wire.PlausibleIP(payload) {
			bad = 0
			if sink != nil {
				sink(c.name, e, payload)
			}
			continue
		}
		if c.onDrop != nil {
			c.onDrop()
		}
		if bad++; bad > 8 {
			return
		}
	}
}

func (c *httpListenIn) replace(id string, h *httpInHandle) {
	c.mu.Lock()
	old := c.active[id]
	c.active[id] = h
	c.mu.Unlock()
	if old != nil {
		old.cancel()
	}
}

func (c *httpListenIn) remove(id string, h *httpInHandle) {
	c.mu.Lock()
	if c.active[id] == h {
		delete(c.active, id)
	}
	c.mu.Unlock()
}

func (c *httpListenIn) Close() error { return c.srv.Close() }

// --- Listen + Outgoing over HTTP (streams into held-open GET responses) -------

var errHTTPDownDead = errors.New("conn: http downlink stream dead")

// httpDownConn is one held-open download response. Send buffers into w; flushViews frames a whole
// batch into the response and flushes it to the client once, so a burst costs one response flush
// instead of one per packet.
type httpDownConn struct {
	w    *pktbuf.Writer
	live atomic.Bool // stream installed (WrapWriter done) and not torn down
	done chan struct{}

	mu  sync.Mutex
	obf io.Writer
	rc  *http.ResponseController
}

// teardown marks the stream dead, waiting out any in-flight flush: the handler must never return
// while a batch is still being written, because net/http forbids touching the ResponseWriter once
// the handler has returned. After this, a straggling flush (e.g. from a tick snapshot taken just
// before the group Remove) sees the dead stream under the lock and never touches the response.
func (dc *httpDownConn) teardown() {
	dc.mu.Lock()
	dc.live.Store(false)
	dc.mu.Unlock()
}

// flushViews is the peer Writer's flush. A write error means the client is gone (or the stream
// broke); stop buffering and let the request context end the handler.
func (dc *httpDownConn) flushViews(views [][]byte) error {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if !dc.live.Load() {
		return errHTTPDownDead
	}
	for _, v := range views {
		if err := wire.WriteFrame(dc.obf, v); err != nil {
			dc.live.Store(false)
			return err
		}
	}
	if err := dc.rc.Flush(); err != nil {
		dc.live.Store(false)
		return err
	}
	return nil
}

type httpListenOut struct {
	name     string
	path     string   // download path to match
	idHeader string   // routing-tag header name
	key      [32]byte // PSK-derived key: authenticates the download GET + signs id-assignments
	maxPeers int      // cap on tracked downstream peers (0 = unbounded)
	srv      *http.Server
	ln       net.Listener
	cipher   cipher.StreamCipher
	multiple bool
	fg       *pktbuf.FlushGroup // flushes each peer's write batch on the node-wide interval

	assignTS atomic.Uint64 // monotonic stamp for id-assignment tokens

	mu     sync.Mutex
	byID   map[wire.Owner]*httpDownConn
	lastTS map[wire.Owner]uint64 // freshness per registered id (rejects replayed GETs)
}

func (c *httpListenOut) nextAssignTS() uint64 {
	now := uint64(time.Now().UnixNano())
	for {
		prev := c.assignTS.Load()
		ts := now
		if ts <= prev {
			ts = prev + 1
		}
		if c.assignTS.CompareAndSwap(prev, ts) {
			return ts
		}
	}
}

func (c *httpListenOut) Name() string { return c.name }
func (c *httpListenOut) Kind() Kind   { return KindListenOut }

func (c *httpListenOut) Start(ctx context.Context, _ Ingress) error {
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = c.srv.Shutdown(sctx)
	}()
	go func() {
		if err := c.srv.Serve(c.ln); err != nil && err != http.ErrServerClosed {
			return
		}
	}()
	return nil
}

func (c *httpListenOut) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != c.path {
		http.NotFound(w, r)
		return
	}
	claimed := parseOwnerHex(r.Header.Get(c.idHeader))
	// The download GET must prove PSK knowledge over the id it registers under, or an off-path
	// client could register/hijack this downlink (the plaintext response body then streams a
	// peer's packets to the attacker). Freshness rejects a replayed GET.
	ts, ok := verifyAuthToken(c.key, authDomainReg, claimed, r.Header.Get(sigHeaderName(c.idHeader)))
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Reserve the id (minting under the cap for a multiple-mode first contact) and install this
	// stream, superseding any prior one — all atomically, and only if the GET is fresh + within
	// the peer cap. The stream is not yet live (obf unset) until we WrapWriter below.
	dc := &httpDownConn{done: make(chan struct{})}
	dc.w = pktbuf.NewWriter(dc.flushViews, tcpWriteBufSize, streamWriteBatch)
	id, ok := c.reserve(claimed, ts, dc)
	if !ok {
		http.NotFound(w, r)
		return
	}
	defer c.remove(id, dc)

	w.Header().Set("Content-Type", "application/octet-stream")
	if c.multiple {
		w.Header().Set(c.idHeader, ownerHex(id))
		// Sign the assigned id so a MITM on the plaintext response cannot make the peer adopt an
		// attacker-chosen owner.
		w.Header().Set(sigHeaderName(c.idHeader), authToken(c.key, authDomainAssign, id, c.nextAssignTS()))
	}
	rc := http.NewResponseController(w)
	obf, err := c.cipher.WrapWriter(w)
	if err != nil {
		return
	}
	_ = rc.Flush()
	dc.mu.Lock()
	dc.obf, dc.rc = obf, rc
	dc.mu.Unlock()
	dc.live.Store(true) // Send skipped this stream until now
	defer dc.teardown()
	c.fg.Add(dc.w)
	defer c.fg.Remove(dc.w)

	select {
	case <-r.Context().Done():
	case <-dc.done:
	}
}

// reserve verifies freshness + the peer cap and installs dc under id, superseding any prior
// stream. It returns the id to use (minted for a multiple-mode first contact) and false if the
// GET is a replay or the peer cap is reached.
func (c *httpListenOut) reserve(claimed wire.Owner, ts uint64, dc *httpDownConn) (wire.Owner, bool) {
	id := claimed
	if !c.multiple {
		id = wire.Owner{} // single mode has one peer, keyed by the zero id (matches lookup)
	}
	c.mu.Lock()
	mintPath := c.multiple && claimed.IsZero()
	if mintPath {
		if c.maxPeers > 0 && len(c.byID) >= c.maxPeers {
			c.mu.Unlock()
			return wire.Owner{}, false // peer cap reached — refuse the mint
		}
		for {
			id = randomOwner()
			if _, exists := c.byID[id]; !exists {
				break
			}
		}
	} else {
		// Existing-peer path (single mode's one peer, or a multiple-mode reconnect under its
		// assigned id): reject a stale/replayed GET, and cap a brand-new id.
		if ts <= c.lastTS[id] {
			c.mu.Unlock()
			return wire.Owner{}, false
		}
		if _, exists := c.byID[id]; !exists && c.maxPeers > 0 && len(c.byID) >= c.maxPeers {
			c.mu.Unlock()
			return wire.Owner{}, false
		}
	}
	old := c.byID[id]
	c.byID[id] = dc
	c.lastTS[id] = ts
	c.mu.Unlock()
	if old != nil {
		close(old.done) // supersede the prior stream for this id
	}
	return id, true
}

func (c *httpListenOut) remove(id wire.Owner, dc *httpDownConn) {
	c.mu.Lock()
	if c.byID[id] == dc {
		delete(c.byID, id)
	}
	c.mu.Unlock()
}

func (c *httpListenOut) lookup(owner wire.Owner) *httpDownConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.multiple {
		return c.byID[owner]
	}
	// single: one peer, keyed by the zero id
	return c.byID[wire.Owner{}]
}

func (c *httpListenOut) Accepts(owner wire.Owner) bool { return c.lookup(owner) != nil }

// Send buffers the packet's envelope blob into the peer's write batch; flushViews emits the batch
// to the response when it fills or on the flush group's tick.
func (c *httpListenOut) Send(e wire.Envelope, payload []byte) (bool, error) {
	dc := c.lookup(e.Owner)
	if dc == nil {
		return false, nil
	}
	if !dc.live.Load() {
		return false, nil // reserved but not yet live (WrapWriter pending), or torn down — try again later
	}
	dst := dc.w.Reserve(wire.EnvelopeLen + len(payload))
	b := wire.PutEnvelope(dst[:0], e, payload)
	dc.w.Commit(len(b))
	return true, nil
}

func (c *httpListenOut) Close() error { return c.srv.Close() }

// urlFor builds a carrier URL from host:port and a path.
func urlFor(host string, port int, path string) string {
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: path}
	return u.String()
}

var (
	_ Conn        = (*httpConnectOut)(nil)
	_ Sender      = (*httpConnectOut)(nil)
	_ Reconnecter = (*httpConnectOut)(nil)
	_ Conn        = (*httpConnectIn)(nil)
	_ Reconnecter = (*httpConnectIn)(nil)
	_ Conn        = (*httpListenIn)(nil)
	_ Conn        = (*httpListenOut)(nil)
	_ Sender      = (*httpListenOut)(nil)
)
