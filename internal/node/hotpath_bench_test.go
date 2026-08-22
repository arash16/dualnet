package node

// Packet-routing hot-path benchmarks, driven by the real example mesh
// (docs/examples/network-old.yaml). Each node's per-packet work is exercised in
// isolation with the *real* router, ciphers, envelope, framing and senders, but with
// the kernel/socket edges replaced by discard transports so the profile shows only the
// CPU and allocations dualnet itself spends per packet.
//
// Two layers:
//   - BenchmarkNode_* : one bench per (node, direction) of the example design. This is
//     the "run based on each node" view — it builds that node's compiled routing table
//     and drives a representative 1280-byte data packet through Route (+ decode on the
//     receive side, + finalizer on the gateway).
//   - BenchmarkHot_*  : component micro-benchmarks that isolate each shared primitive
//     (packet/stream cipher, envelope, framing, route lookup, finalizer, gateway
//     downlink serialization) so a regression can be pinned to one place.
//
// Profile with pprof, e.g.:
//   go test ./internal/node -run x -bench 'BenchmarkNode' -benchmem \
//       -cpuprofile cpu.out -memprofile mem.out
//   go tool pprof -top cpu.out
//   go tool pprof -top -alloc_objects mem.out

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/cipher"
	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/conn"
	"github.com/arash16/dualnet/internal/egress"
	"github.com/arash16/dualnet/internal/finalizer"
	"github.com/arash16/dualnet/internal/netschema"
	"github.com/arash16/dualnet/internal/peers"
	"github.com/arash16/dualnet/internal/pktbuf"
	"github.com/arash16/dualnet/internal/proto"
	"github.com/arash16/dualnet/internal/router"
	"github.com/arash16/dualnet/internal/wire"
)

const (
	benchMTU     = 1280 // example network.yaml mtu
	benchPayload = benchMTU - 20
)

// benchOwner is the tun owner id used throughout; tun targets Accept only this id.
var benchOwner = wire.Owner{0xDE, 0xAD, 0xBE, 0xEF}

var benchKey = wire.KeyFromPSK("hotpath-bench")

// --- discard transports (no syscalls; measure only dualnet's own work) --------

type dummyAddr struct{}

func (dummyAddr) Network() string { return "discard" }
func (dummyAddr) String() string  { return "discard:0" }

// discardConn is a net.Conn whose writes succeed and vanish; reads block until Close.
type discardConn struct {
	closed chan struct{}
	once   sync.Once
}

func newDiscardConn() *discardConn { return &discardConn{closed: make(chan struct{})} }

func (d *discardConn) Read([]byte) (int, error)         { <-d.closed; return 0, io.EOF }
func (d *discardConn) Write(p []byte) (int, error)      { return len(p), nil }
func (d *discardConn) Close() error                     { d.once.Do(func() { close(d.closed) }); return nil }
func (d *discardConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (d *discardConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (d *discardConn) SetDeadline(time.Time) error      { return nil }
func (d *discardConn) SetReadDeadline(time.Time) error  { return nil }
func (d *discardConn) SetWriteDeadline(time.Time) error { return nil }

// discardDialer hands every Connect connection a discardConn.
type discardDialer struct{}

func (discardDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return newDiscardConn(), nil
}

// nullTun is a TunDevice that drops writes and blocks reads until Close.
type nullTun struct {
	closed chan struct{}
	once   sync.Once
}

func newNullTun() *nullTun                     { return &nullTun{closed: make(chan struct{})} }
func (n *nullTun) NewReadBatch() *pktbuf.Batch { return pktbuf.NewBatch(1, 65535, 1) }
func (n *nullTun) Fill(*pktbuf.Batch) error    { <-n.closed; return io.EOF }
func (n *nullTun) Write([][]byte) error        { return nil }
func (n *nullTun) Close() error                { n.once.Do(func() { close(n.closed) }); return nil }

// discardEgress is an internet that swallows every packet and never replies.
type discardEgress struct {
	closed chan struct{}
	once   sync.Once
}

func newDiscardEgress() *discardEgress               { return &discardEgress{closed: make(chan struct{})} }
func (e *discardEgress) NewReadBatch() *pktbuf.Batch { return pktbuf.NewBatch(1, 65535, 1) }
func (e *discardEgress) Fill(*pktbuf.Batch) error    { <-e.closed; return io.EOF }
func (e *discardEgress) Write([][]byte) error        { return nil }
func (e *discardEgress) Close() error                { e.once.Do(func() { close(e.closed) }); return nil }

var _ egress.Egress = (*discardEgress)(nil)

// stubConn is a placeholder for a receive-only source connection (connect-in /
// listen-in): the router needs it present to resolve the source, but it never sends.
type stubConn struct {
	name string
	kind conn.Kind
}

func (s stubConn) Name() string                              { return s.name }
func (s stubConn) Kind() conn.Kind                           { return s.kind }
func (s stubConn) Start(context.Context, conn.Ingress) error { return nil }
func (s stubConn) Close() error                              { return nil }

// fakeSenderConn stands in for a listen-out target. On the up/process path the router
// only needs it to Accept the owner (the real send happens on the downlink, measured by
// BenchmarkHot_GatewayDownlinkSerialize), so Send is a no-op here.
type fakeSenderConn struct {
	name string
	kind conn.Kind
}

func (f fakeSenderConn) Name() string                              { return f.name }
func (f fakeSenderConn) Kind() conn.Kind                           { return f.kind }
func (f fakeSenderConn) Start(context.Context, conn.Ingress) error { return nil }
func (f fakeSenderConn) Close() error                              { return nil }
func (f fakeSenderConn) Accepts(wire.Owner) bool                   { return true }
func (f fakeSenderConn) Send(wire.Envelope, []byte) (bool, error)  { return true, nil }

// --- helpers ------------------------------------------------------------------

func benchDataPacket() []byte {
	return ipv4Packet("10.9.0.3", "1.2.3.4", strings.Repeat("x", benchPayload-20))
}

func newPacketCipher(tb testing.TB) cipher.PacketCipher {
	pc, err := cipher.NewPacket("chacha4", benchKey)
	if err != nil {
		tb.Fatal(err)
	}
	return pc
}

// sealUDP builds the on-wire datagram body a UDP receiver would read: cipher(nonce||env||inner).
func sealUDP(tb testing.TB, pc cipher.PacketCipher, e wire.Envelope, inner []byte) []byte {
	blob := wire.PutEnvelope(nil, e, inner)
	sealed, err := pc.Seal(nil, blob)
	if err != nil {
		tb.Fatal(err)
	}
	return append([]byte(nil), sealed...)
}

// decodeUDP mirrors the receive path in udpListenIn/udpConnectIn readLoop: copy the
// fresh socket bytes into buf, Open in place, parse the envelope, run the IP tripwire.
func decodeUDP(pc cipher.PacketCipher, buf, sealed []byte) (wire.Envelope, []byte, bool) {
	n := copy(buf, sealed)
	blob, err := pc.Open(buf[:n])
	if err != nil {
		return wire.Envelope{}, nil, false
	}
	e, payload, ok := wire.ParseEnvelope(blob)
	if !ok || !wire.PlausibleIP(payload) {
		return wire.Envelope{}, nil, false
	}
	return e, payload, true
}

// exampleNodes compiles the real docs/examples/network-old.yaml into per-node configs.
func exampleNodes(tb testing.TB) map[string]*config.Node {
	net, err := netschema.Load("../../docs/examples/network-old.yaml")
	if err != nil {
		tb.Fatalf("load network.yaml: %v", err)
	}
	cfgs, err := net.Compile()
	if err != nil {
		tb.Fatalf("compile: %v", err)
	}
	return cfgs
}

// buildNodeRouter builds the real compiled router for one node's config, wiring real
// discard-backed senders for connect-out and tun targets, fake senders for listen-out
// targets, and stubs for receive-only sources. Returns a cleanup func.
func buildNodeRouter(tb testing.TB, cfg *config.Node) (*router.Router, func()) {
	cfg.Defaults()
	conns := map[string]conn.Conn{}
	var closers []func() error
	// A group is required by writer-backed conns; the bench measures routing, not flushing, so it
	// is never Run (writers flush on full; the discard sinks make a flush a no-op anyway).
	bfg := pktbuf.NewFlushGroup(flushInterval)

	for _, c := range cfg.Connections {
		switch kindOf(c) {
		case conn.KindTun:
			tc := conn.NewTun(c.Name, newNullTun(), benchOwner, false, bfg)
			conns[c.Name] = tc
			closers = append(closers, tc.Close)
		case conn.KindConnectOut:
			cc, err := conn.New(context.Background(), conn.Spec{
				Name: c.Name, Kind: conn.KindConnectOut, Transport: c.Transport,
				Cipher: "chacha4", Key: benchKey, Dialer: discardDialer{},
				RemoteIP: "203.0.113.9", Port: 9, MaxAge: proto.UpstreamMaxAge, Flush: bfg,
			})
			if err != nil {
				tb.Fatalf("build %s: %v", c.Name, err)
			}
			conns[c.Name] = cc
			closers = append(closers, cc.Close)
		case conn.KindListenOut:
			conns[c.Name] = fakeSenderConn{name: c.Name, kind: conn.KindListenOut}
		default: // KindConnectIn / KindListenIn: receive-only sources
			conns[c.Name] = stubConn{name: c.Name, kind: kindOf(c)}
		}
	}

	finalizers := map[string]router.FinalizeFunc{}
	for name := range egressesUsed(cfg) {
		eg := newDiscardEgress()
		fin := finalizer.New(eg, sessionTTL, finalizerMaxFlows, bfg)
		finalizers[name] = fin.Submit
		closers = append(closers, eg.Close)
	}

	conditions := map[string]router.Guard{}
	for _, c := range cfg.Conditions {
		conditions[c.Name] = benchGuard{}
	}

	sources := make([]string, 0, len(conns))
	for name := range conns {
		sources = append(sources, name)
	}
	rt, err := router.Compile(compileRules(cfg), conns, sources, conditions, finalizers)
	if err != nil {
		tb.Fatalf("compile router: %v", err)
	}
	return rt, func() {
		for _, c := range closers {
			_ = c()
		}
	}
}

// --- per-node benchmarks ------------------------------------------------------

type nodeDir struct {
	node      string
	dir       string
	src       string // receiving/originating connection name
	processed bool   // envelope Processed flag entering this node
	decode    bool   // whether a UDP receive decode precedes routing
}

// The example mesh, one entry per (node, direction). See docs/examples/network-old.yaml.
// Turkish's receive on the uplink is HTTP (stream), decoded separately by
// BenchmarkHot_StreamDecode; its downlink send is BenchmarkHot_GatewayDownlinkSerialize.
var nodeDirs = []nodeDir{
	{"router", "uplink", "Tun", false, false},            // tun -> branch (finalize ftth / forward router-up)
	{"router", "downlink", "turkish-router", true, true}, // udp connect-in -> Tun (own reply)
	{"turkish", "uplink", "router-up", false, false},     // http listen-in -> process (finalizer+egress)
	{"vps", "uplink", "V2Ray", false, false},             // tun -> vps-up (http connect-out)
	{"vps", "downlink", "router-vps", true, true},        // udp listen-in -> V2Ray tun
}

// benchGuard is an always-pass condition guard for building the compiled router in
// benchmarks without loading real prefix-set files or running healthchecks.
type benchGuard struct{}

func (benchGuard) Pass(wire.Owner, netip.Addr, bool) bool { return true }

func BenchmarkNode(b *testing.B) {
	cfgs := exampleNodes(b)
	pkt := benchDataPacket()
	for _, nd := range nodeDirs {
		nd := nd
		b.Run(nd.node+"/"+nd.dir, func(b *testing.B) {
			cfg := cfgs[nd.node]
			if cfg == nil {
				b.Fatalf("no config for node %q", nd.node)
			}
			rt, cleanup := buildNodeRouter(b, cfg)
			defer cleanup()

			pc := newPacketCipher(b)
			env := wire.Envelope{Owner: benchOwner, Processed: nd.processed}
			var sealed []byte
			if nd.decode {
				sealed = sealUDP(b, pc, env, pkt)
			}
			buf := make([]byte, udpReadBufBench)

			b.ReportAllocs()
			b.SetBytes(int64(len(pkt)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if nd.decode {
					e, payload, ok := decodeUDP(pc, buf, sealed)
					if !ok {
						b.Fatal("decode failed")
					}
					rt.Route(nd.src, e, payload)
				} else {
					rt.Route(nd.src, env, pkt)
				}
			}
		})
	}
}

const udpReadBufBench = 65535

// --- component micro-benchmarks -----------------------------------------------

// BenchmarkHot_PacketSeal isolates the per-datagram UDP send transform: envelope +
// chacha4 keystream seal. A fresh cipher is constructed per datagram (see chacha4.go).
func BenchmarkHot_PacketSeal(b *testing.B) {
	pc := newPacketCipher(b)
	pkt := benchDataPacket()
	blob := wire.PutEnvelope(nil, wire.Envelope{Owner: benchOwner}, pkt)
	dst := make([]byte, 0, pc.Overhead()+len(blob))
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	for i := 0; i < b.N; i++ {
		if _, err := pc.Seal(dst[:0], blob); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHot_PacketOpen isolates the per-datagram UDP receive transform.
func BenchmarkHot_PacketOpen(b *testing.B) {
	pc := newPacketCipher(b)
	pkt := benchDataPacket()
	sealed := sealUDP(b, pc, wire.Envelope{Owner: benchOwner}, pkt)
	buf := make([]byte, udpReadBufBench)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	for i := 0; i < b.N; i++ {
		n := copy(buf, sealed)
		if _, err := pc.Open(buf[:n]); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHot_TCPConnectOutSend isolates the tcp-carrier up-path send: PutEnvelope into a
// reused blob buffer + one framed chacha4 write down a discard socket. It reports 0 allocs,
// proving the pure-TCP transport's steady send path is allocation-free like the others.
func BenchmarkHot_TCPConnectOutSend(b *testing.B) {
	cc, err := conn.New(context.Background(), conn.Spec{
		Name: "tcp-out", Kind: conn.KindConnectOut, Transport: "tcp",
		Cipher: "chacha4", Key: benchKey, Dialer: discardDialer{}, RemoteIP: "203.0.113.9", Port: 9,
		Flush: pktbuf.NewFlushGroup(flushInterval),
	})
	if err != nil {
		b.Fatal(err)
	}
	s := cc.(conn.Sender)
	pkt := benchDataPacket()
	e := wire.Envelope{Owner: benchOwner}
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Send(e, pkt); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHot_StreamWrite isolates the HTTP-carrier send transform (chacha4 keystream
// XOR over the frame). The cipher is created once per stream, so this is steady state.
func BenchmarkHot_StreamWrite(b *testing.B) {
	sc, err := cipher.NewStream("chacha4", benchKey)
	if err != nil {
		b.Fatal(err)
	}
	w, err := sc.WrapWriter(io.Discard)
	if err != nil {
		b.Fatal(err)
	}
	pkt := benchDataPacket()
	blob := wire.PutEnvelope(nil, wire.Envelope{Owner: benchOwner}, pkt)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	for i := 0; i < b.N; i++ {
		if err := wire.WriteFrame(w, blob); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHot_StreamWritePartial is BenchmarkHot_StreamWrite with chacha4:256, the CPU-saving
// path for a cipher-bound TCP node: only the frame's length + first 256 payload bytes are XORed.
// Compare its ns/op against BenchmarkHot_StreamWrite (whole frame) to see the saving at MTU size.
func BenchmarkHot_StreamWritePartial(b *testing.B) {
	sc, err := cipher.NewStream("chacha4:256", benchKey)
	if err != nil {
		b.Fatal(err)
	}
	w, err := sc.WrapWriter(io.Discard)
	if err != nil {
		b.Fatal(err)
	}
	pkt := benchDataPacket()
	blob := wire.PutEnvelope(nil, wire.Envelope{Owner: benchOwner}, pkt)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	for i := 0; i < b.N; i++ {
		if err := wire.WriteFrame(w, blob); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHot_StreamDecode isolates the HTTP-carrier receive transform: ReadFrame off
// an obfuscated reader that replays one framed packet, then parse.
func BenchmarkHot_StreamDecode(b *testing.B) {
	sc, err := cipher.NewStream("chacha4", benchKey)
	if err != nil {
		b.Fatal(err)
	}
	pkt := benchDataPacket()
	blob := wire.PutEnvelope(nil, wire.Envelope{Owner: benchOwner}, pkt)
	r, err := sc.WrapReader(newFrameReplayReader(b, sc, blob))
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, wire.MaxPacket)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	for i := 0; i < b.N; i++ {
		n, err := wire.ReadFrame(r, buf)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, ok := wire.ParseEnvelope(buf[:n]); !ok {
			b.Fatal("parse failed")
		}
	}
}

// frameReplayReader produces an endless obfuscated stream of the same framed packet.
// It holds the writer-side cipher and generates more framed+sealed bytes on demand, so
// the keystream stays continuous and a reader-side cipher wrapping it never desyncs.
type frameReplayReader struct {
	w    io.Writer // obf writer feeding buf
	buf  *seqBuf
	blob []byte
}

func newFrameReplayReader(tb testing.TB, sc cipher.StreamCipher, blob []byte) *frameReplayReader {
	buf := &seqBuf{}
	w, err := sc.WrapWriter(buf) // emits the leading nonce into buf; reader consumes it first
	if err != nil {
		tb.Fatal(err)
	}
	return &frameReplayReader{w: w, buf: buf, blob: blob}
}

func (r *frameReplayReader) Read(p []byte) (int, error) {
	for r.buf.len() == 0 {
		if err := wire.WriteFrame(r.w, r.blob); err != nil {
			return 0, err
		}
	}
	return r.buf.read(p)
}

// seqBuf is a tiny FIFO byte buffer: WriteFrame appends, Read drains from the front.
type seqBuf struct {
	b   []byte
	off int
}

func (s *seqBuf) Write(p []byte) (int, error) { s.b = append(s.b, p...); return len(p), nil }
func (s *seqBuf) len() int                    { return len(s.b) - s.off }
func (s *seqBuf) read(p []byte) (int, error) {
	n := copy(p, s.b[s.off:])
	s.off += n
	if s.off == len(s.b) { // fully drained: reset without growing the backing array
		s.b = s.b[:0]
		s.off = 0
	}
	return n, nil
}

// BenchmarkHot_PutEnvelopeReuse is the send-buffer path every real sender takes: a reused
// (connect-out) or pooled (listen-out) buffer, so it reports 0 allocs. BenchmarkHot_PutEnvelopeAlloc
// is a reference for the cost of NOT reusing — PutEnvelope(nil, ...) — which no production sender
// does anymore; it stays as a regression signpost so a future caller that drops buffer reuse is
// visible against the reuse bench above.
func BenchmarkHot_PutEnvelopeReuse(b *testing.B) {
	pkt := benchDataPacket()
	var buf []byte
	e := wire.Envelope{Owner: benchOwner}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf = wire.PutEnvelope(buf, e, pkt)
	}
}

func BenchmarkHot_PutEnvelopeAlloc(b *testing.B) {
	pkt := benchDataPacket()
	e := wire.Envelope{Owner: benchOwner}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = wire.PutEnvelope(nil, e, pkt)
	}
}

// BenchmarkHot_ParseAndTripwire isolates envelope parse + PlausibleIP (every receiver).
func BenchmarkHot_ParseAndTripwire(b *testing.B) {
	pkt := benchDataPacket()
	blob := wire.PutEnvelope(nil, wire.Envelope{Owner: benchOwner, Processed: true}, pkt)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e, payload, ok := wire.ParseEnvelope(blob)
		if !ok || !wire.PlausibleIP(payload) || e.Owner != benchOwner {
			b.Fatal("bad parse")
		}
	}
}

// BenchmarkHot_RouteLookup isolates the router dispatch cost (compiled map lookup +
// Accepts + Send) with a no-op sender, so it excludes cipher/framing.
func BenchmarkHot_RouteLookup(b *testing.B) {
	conns := map[string]conn.Conn{
		"src": stubConn{name: "src", kind: conn.KindListenIn},
		"dst": fakeSenderConn{name: "dst", kind: conn.KindListenOut},
	}
	rules := []router.Rule{{MatchProcessed: pfalse(), Source: "src", Target: "dst"}}
	rt, err := router.Compile(rules, conns, []string{"src", "dst"}, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	pkt := benchDataPacket()
	e := wire.Envelope{Owner: benchOwner}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rt.Route("src", e, pkt)
	}
}

// BenchmarkHot_RouteLookupBound is the same dispatch via the per-source intake every real
// receive loop uses (SourceRouter), which captures the two target lists once and so avoids the
// per-packet source-name map hash BenchmarkHot_RouteLookup still pays.
func BenchmarkHot_RouteLookupBound(b *testing.B) {
	conns := map[string]conn.Conn{
		"src": stubConn{name: "src", kind: conn.KindListenIn},
		"dst": fakeSenderConn{name: "dst", kind: conn.KindListenOut},
	}
	rules := []router.Rule{{MatchProcessed: pfalse(), Source: "src", Target: "dst"}}
	rt, err := router.Compile(rules, conns, []string{"src", "dst"}, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	route := rt.SourceRouter("src")
	if route == nil {
		b.Fatal("no bound router for src")
	}
	pkt := benchDataPacket()
	e := wire.Envelope{Owner: benchOwner}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		route(e, pkt)
	}
}

// BenchmarkHot_PacketSealPartial seals a 1280-byte datagram obfuscating only the first 256
// bytes (chacha4:256). Compare against BenchmarkHot_PacketSeal (whole payload) to see the
// partial-obfuscation CPU saving on a high-entropy tail.
func BenchmarkHot_PacketSealPartial(b *testing.B) {
	pc, err := cipher.NewPacket("chacha4:256", benchKey)
	if err != nil {
		b.Fatal(err)
	}
	pkt := benchDataPacket()
	blob := wire.PutEnvelope(nil, wire.Envelope{Owner: benchOwner}, pkt)
	dst := make([]byte, 0, pc.Overhead()+len(blob))
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	for i := 0; i < b.N; i++ {
		if _, err := pc.Seal(dst[:0], blob); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHot_FinalizerSubmit isolates the gateway process step: SrcIP + track-map
// insert under the finalizer mutex + egress write.
func BenchmarkHot_FinalizerSubmit(b *testing.B) {
	fin := finalizer.New(newDiscardEgress(), sessionTTL, finalizerMaxFlows, pktbuf.NewFlushGroup(flushInterval))
	pkt := benchDataPacket()
	target := fakeSenderConn{name: "down", kind: conn.KindListenOut}
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	for i := 0; i < b.N; i++ {
		fin.Submit(benchOwner, target, pkt)
	}
}

// BenchmarkHot_GatewayDownlinkSerialize mirrors udpListenOut.Send + sinkFor
// (internal/conn/udp.go), the gateway's high-throughput download direction: look up the peer,
// build [MsgData][nonce][envelope+inner] in one pooled buffer, seal the body in place, write.
// It should report 0 allocs and one pool round-trip per packet.
func BenchmarkHot_GatewayDownlinkSerialize(b *testing.B) {
	pc := newPacketCipher(b)
	pool := sync.Pool{New: func() any { s := make([]byte, 0, 2048); return &s }}
	reg := peers.New(false, time.Minute, 0) // single-peer (turkish-hpi shape)
	reg.Register(wire.Owner{}, "peer", 1, func(datagram []byte) error { return nil })
	pkt := benchDataPacket()
	e := wire.Envelope{Owner: benchOwner, Processed: true}
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	for i := 0; i < b.N; i++ {
		sink, ok := reg.SinkFor(e.Owner)
		if !ok {
			b.Fatal("no peer")
		}
		op := pool.Get().(*[]byte)
		hdr := 1 + pc.Overhead()
		need := hdr + wire.EnvelopeLen + len(pkt)
		out := *op
		if cap(out) < need {
			out = make([]byte, need)
		} else {
			out = out[:need]
		}
		out[0] = proto.MsgData
		wire.PutEnvelope(out[hdr:hdr], e, pkt)
		if err := pc.SealInPlace(out[1:]); err != nil {
			b.Fatal(err)
		}
		if err := sink(out); err != nil {
			b.Fatal(err)
		}
		*op = out
		pool.Put(op)
	}
}
