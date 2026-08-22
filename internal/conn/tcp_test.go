package conn

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/cipher"
	"github.com/arash16/dualnet/internal/peers"
	"github.com/arash16/dualnet/internal/pktbuf"
	"github.com/arash16/dualnet/internal/proto"
	"github.com/arash16/dualnet/internal/wire"
)

// plainDialer dials real loopback sockets (the tcp transport's SocketDialer seam).
type plainDialer struct{}

func (plainDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func testIPv4(payload string) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	p[9] = 6 // TCP, so it is not mistaken for a ping
	copy(p[12:16], []byte{10, 0, 0, 1})
	copy(p[16:20], []byte{10, 0, 0, 2})
	copy(p[20:], payload)
	return p
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if cond() {
			return
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatalf("timeout waiting for %s", what)
		}
	}
}

// TestTCPUpPathRoundTrip drives a real tcpConnectOut -> tcpListenIn over loopback with the
// production chacha4 stream and asserts a data packet arrives intact with its envelope.
func TestTCPUpPathRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key := wire.KeyFromPSK("tcp-up")
	port := freeUDPPort(t)

	li, err := New(ctx, Spec{Name: "in", Kind: KindListenIn, Transport: "tcp", Cipher: "chacha4", Key: key, Listen: ":" + itoa(port)})
	if err != nil {
		t.Fatal(err)
	}
	type got struct {
		src string
		e   wire.Envelope
		p   []byte
	}
	recv := make(chan got, 4)
	if err := li.Start(ctx, func(src string, e wire.Envelope, p []byte) {
		recv <- got{src, e, append([]byte(nil), p...)}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = li.Close() })

	fg := pktbuf.NewFlushGroup(time.Millisecond)
	go fg.Run(ctx)
	co, err := New(ctx, Spec{Name: "out", Kind: KindConnectOut, Transport: "tcp", Cipher: "chacha4", Key: key, RemoteIP: "127.0.0.1", Port: port, Dialer: plainDialer{}, Flush: fg})
	if err != nil {
		t.Fatal(err)
	}
	_ = co.Start(ctx, nil)
	t.Cleanup(func() { _ = co.Close() })

	owner := wire.Owner{1, 2, 3, 4}
	pkt := testIPv4("up-hello")
	// The listener may not have accepted yet on the very first Send; the connect-out drops and
	// backs off, so retry (as inner TCP would retransmit).
	waitFor(t, "up-path delivery", func() bool {
		_, _ = co.(Sender).Send(wire.Envelope{Owner: owner}, pkt)
		select {
		case g := <-recv:
			if g.e.Owner != owner || g.e.Processed || string(g.p) != string(pkt) {
				t.Fatalf("bad receive: owner=%v processed=%v payload=%q", g.e.Owner, g.e.Processed, g.p)
			}
			return true
		case <-time.After(50 * time.Millisecond):
			return false
		}
	})
}

// hangDialer blocks every dial until its context expires (a blackholed upstream: SYNs vanish and
// the dial returns only at its timeout). tried is signalled once a dial has been attempted.
type hangDialer struct{ tried chan struct{} }

func (d hangDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	select {
	case d.tried <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestTCPConnectOutFlushNeverBlocksOnDial: flush runs on the node-wide flush-group goroutine (and
// inline in a producer's Commit), so it must never sit in a dial. With a blackholed upstream a
// dial lasts its full timeout; a flush waiting on it would freeze every writer on the node — tun
// downlink partials, healthcheck pings buffered in other carriers — for that long. The dial must
// run on its own goroutine, with flush dropping the batch and returning promptly (the posture for
// an unreachable upstream: inner TCP retransmits).
func TestTCPConnectOutFlushNeverBlocksOnDial(t *testing.T) {
	fg := pktbuf.NewFlushGroup(time.Hour) // never ticks; the test drives the flush itself
	d := hangDialer{tried: make(chan struct{}, 1)}
	co, err := New(context.Background(), Spec{
		Name: "out", Kind: KindConnectOut, Transport: "tcp", Cipher: "none",
		Key: wire.KeyFromPSK("k"), RemoteIP: "203.0.113.1", Port: 9, Dialer: d, Flush: fg,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = co.Close() })
	c := co.(*tcpConnectOut)

	if _, err := c.Send(wire.Envelope{Owner: wire.Owner{1, 2, 3, 4}}, testIPv4("x")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = c.w.Flush()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("flush blocked %v in the upstream dial; it must return without dialing inline", elapsed)
	}
	select {
	case <-d.tried:
	case <-time.After(2 * time.Second):
		t.Fatal("flush never triggered a dial attempt")
	}
}

// gateDialer refuses dials instantly until gate is closed, then dials for real: an upstream that
// is down and later comes back.
type gateDialer struct{ gate chan struct{} }

func (d gateDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	select {
	case <-d.gate:
		var nd net.Dialer
		return nd.DialContext(ctx, network, addr)
	default:
		return nil, errors.New("upstream down")
	}
}

// TestTCPConnectOutRecoversViaAsyncDial: packets sent while the upstream is down are dropped, and
// once it is back the background dial installs the connection so subsequent sends flow.
func TestTCPConnectOutRecoversViaAsyncDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key := wire.KeyFromPSK("tcp-async")
	port := freeUDPPort(t)

	li, err := New(ctx, Spec{Name: "in", Kind: KindListenIn, Transport: "tcp", Cipher: "chacha4", Key: key, Listen: ":" + itoa(port)})
	if err != nil {
		t.Fatal(err)
	}
	recv := make(chan []byte, 16)
	if err := li.Start(ctx, func(_ string, _ wire.Envelope, p []byte) {
		recv <- append([]byte(nil), p...)
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = li.Close() })

	fg := pktbuf.NewFlushGroup(time.Millisecond)
	go fg.Run(ctx)
	gate := make(chan struct{})
	co, err := New(ctx, Spec{Name: "out", Kind: KindConnectOut, Transport: "tcp", Cipher: "chacha4", Key: key, RemoteIP: "127.0.0.1", Port: port, Dialer: gateDialer{gate: gate}, Flush: fg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = co.Close() })

	pkt := testIPv4("recovered")
	// Down: sends drop (dial refused, backoff). None of these may block or deliver.
	for i := 0; i < 3; i++ {
		_, _ = co.(Sender).Send(wire.Envelope{Owner: wire.Owner{5, 6, 7, 8}}, pkt)
		time.Sleep(2 * time.Millisecond)
	}
	select {
	case p := <-recv:
		t.Fatalf("delivery while the upstream was down: %q", p)
	default:
	}

	close(gate) // upstream back; backoff expiry + async dial must restore the path
	waitFor(t, "delivery after upstream recovery", func() bool {
		_, _ = co.(Sender).Send(wire.Envelope{Owner: wire.Owner{5, 6, 7, 8}}, pkt)
		select {
		case p := <-recv:
			if string(p) != string(pkt) {
				t.Fatalf("bad payload %q", p)
			}
			return true
		case <-time.After(50 * time.Millisecond):
			return false
		}
	})
}

// TestTCPDownPathRoundTrip drives a real tcpConnectIn <- tcpListenOut (Multiple) over loopback:
// the connect-in registers, adopts a minted id, and a reply sent by that owner arrives at it.
func TestTCPDownPathRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key := wire.KeyFromPSK("tcp-down")
	port := freeUDPPort(t)

	fg := pktbuf.NewFlushGroup(time.Millisecond)
	go fg.Run(ctx)
	lo, err := New(ctx, Spec{
		Name: "down", Kind: KindListenOut, Transport: "tcp", Cipher: "chacha4", Key: key,
		Listen: ":" + itoa(port), Multiple: true, SessionTTL: time.Minute, Flush: fg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := lo.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lo.Close() })

	var assigned wire.Owner
	assignedCh := make(chan wire.Owner, 1)
	recv := make(chan []byte, 4)
	ci, err := New(ctx, Spec{
		Name: "ci", Kind: KindConnectIn, Transport: "tcp", Cipher: "chacha4", Key: key,
		RemoteIP: "127.0.0.1", Port: port, Dialer: plainDialer{},
		IDSetter: func(o wire.Owner) {
			select {
			case assignedCh <- o:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ci.Start(ctx, func(_ string, _ wire.Envelope, p []byte) {
		recv <- append([]byte(nil), p...)
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ci.Close() })

	select {
	case assigned = <-assignedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("connect-in was never assigned an id")
	}
	if assigned.IsZero() {
		t.Fatal("assigned id is zero")
	}

	pkt := testIPv4("down-hello")
	waitFor(t, "down-path delivery", func() bool {
		delivered, err := lo.(Sender).Send(wire.Envelope{Owner: assigned, Processed: true}, pkt)
		if err != nil {
			t.Fatalf("listen-out send: %v", err)
		}
		if !delivered {
			return false // peer not yet registered on the server side
		}
		select {
		case p := <-recv:
			if string(p) != string(pkt) {
				t.Fatalf("bad down payload %q", p)
			}
			return true
		case <-time.After(50 * time.Millisecond):
			return false
		}
	})
}

// --- control-plane auth boundary (cipher=none, so hand-crafted frames reach the codec) ---

// tcpRegister dials the listen-out, sends one register frame under sendKey, and returns the open
// connection, a frame reader over it, and the assigned id from the server's reply (ok=false if the
// server refused, i.e. closed without a valid assignment). Uses the none cipher so the frames on
// the wire are exactly the codec bytes. The caller owns the connection.
func tcpRegister(t *testing.T, addr string, sendKey, verifyKey [32]byte, id wire.Owner, ts uint64) (net.Conn, io.Reader, wire.Owner, bool) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	sc, _ := cipher.NewStream("none", sendKey)
	w, _ := sc.WrapWriter(conn)
	if err := wire.WriteFrame(w, encodeControl(proto.MsgRegister, id, 0, ts, sendKey)); err != nil {
		t.Fatalf("write register: %v", err)
	}
	rc, _ := cipher.NewStream("none", verifyKey)
	r, _ := rc.WrapReader(conn)
	buf := make([]byte, wire.MaxPacket)
	n, err := wire.ReadFrame(r, buf)
	if err != nil {
		return conn, r, wire.Owner{}, false // server refused the registration and closed
	}
	typ, aid, _, _, derr := decodeControl(buf[:n], verifyKey)
	if derr != nil || typ != proto.MsgAssignID {
		return conn, r, wire.Owner{}, false
	}
	return conn, r, aid, true
}

// tcpHandshake is tcpRegister for tests that only care about the registration outcome.
func tcpHandshake(t *testing.T, addr string, sendKey, verifyKey [32]byte, id wire.Owner, ts uint64) (wire.Owner, bool) {
	t.Helper()
	conn, _, aid, ok := tcpRegister(t, addr, sendKey, verifyKey, id, ts)
	_ = conn.Close()
	return aid, ok
}

func startTestListenOut(t *testing.T, key [32]byte, multiple bool, fg *pktbuf.FlushGroup) (*tcpListenOut, string) {
	t.Helper()
	port := freeUDPPort(t)
	ln, err := listenTCP(context.Background(), "", ":"+itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	sc, _ := cipher.NewStream("none", key)
	lo := &tcpListenOut{name: "down", ln: ln, cipher: sc, key: key, multiple: multiple, reg: peers.New(multiple, time.Minute, 0), fg: fg}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := lo.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lo.Close() })
	return lo, "127.0.0.1:" + itoa(port)
}

// TestTCPListenOutBatchesDownlinkWrites proves the per-peer write batch on the down-path: packets
// sent while the flush group is idle stay buffered (no per-packet socket write); one group flush
// then emits the whole batch, in send order.
func TestTCPListenOutBatchesDownlinkWrites(t *testing.T) {
	key := wire.KeyFromPSK("batch-psk")
	fg := pktbuf.NewFlushGroup(time.Millisecond) // built now, run later: sends stay buffered until then
	lo, addr := startTestListenOut(t, key, true, fg)

	conn, r, id, ok := tcpRegister(t, addr, key, key, wire.Owner{}, 1)
	if !ok {
		t.Fatal("register refused")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})

	pkts := [][]byte{testIPv4("d0"), testIPv4("d1"), testIPv4("d2")}
	for i, p := range pkts {
		delivered, err := lo.Send(wire.Envelope{Owner: id, Processed: true}, p)
		if !delivered || err != nil {
			t.Fatalf("send %d: delivered=%v err=%v", i, delivered, err)
		}
	}

	// Nothing may reach the socket before a flush: the sends above buffer into the peer's write
	// batch instead of costing one write syscall each.
	buf := make([]byte, wire.MaxPacket)
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if n, err := wire.ReadFrame(r, buf); err == nil {
		t.Fatalf("a %d-byte frame reached the wire before any flush (per-packet write?)", n)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fg.Run(ctx)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i, want := range pkts {
		n, err := wire.ReadFrame(r, buf)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		e, payload, pok := wire.ParseEnvelope(buf[:n])
		if !pok || e.Owner != id || !e.Processed || string(payload) != string(want) {
			t.Fatalf("frame %d: owner=%v processed=%v payload=%q, want %q", i, e.Owner, e.Processed, payload, want)
		}
	}
}

// TestTCPListenOutRequiresAuth proves the registration boundary: only a register frame tagged
// under the real PSK is accepted (mints/returns an id); an unauthenticated one is refused.
func TestTCPListenOutRequiresAuth(t *testing.T) {
	key := wire.KeyFromPSK("real-psk")
	_, addr := startTestListenOut(t, key, true, pktbuf.NewFlushGroup(time.Hour))

	// Wrong-key register: the server's decodeControl (real key) rejects the tag → no assignment.
	if _, ok := tcpHandshake(t, addr, wire.KeyFromPSK("attacker"), key, wire.Owner{}, 1); ok {
		t.Fatal("a wrong-key register was accepted (off-path peer could hijack the return path)")
	}
	// Correct-key register: accepted, a fresh id is minted and returned.
	id, ok := tcpHandshake(t, addr, key, key, wire.Owner{}, 2)
	if !ok || id.IsZero() {
		t.Fatalf("a correctly-authenticated register was refused: ok=%v id=%v", ok, id)
	}
}

// TestTCPListenOutRejectsReplay proves freshness on a single-mode listener: a verbatim replay of
// an accepted register (same ts) is refused, so a captured registration cannot re-bind the peer.
func TestTCPListenOutRejectsReplay(t *testing.T) {
	key := wire.KeyFromPSK("real-psk")
	_, addr := startTestListenOut(t, key, false, pktbuf.NewFlushGroup(time.Hour)) // single mode: freshness keyed globally

	if _, ok := tcpHandshake(t, addr, key, key, wire.Owner{}, 100); !ok {
		t.Fatal("first register refused")
	}
	if _, ok := tcpHandshake(t, addr, key, key, wire.Owner{}, 100); ok {
		t.Fatal("a replayed (equal-ts) register was accepted — anti-replay not enforced")
	}
	if _, ok := tcpHandshake(t, addr, key, key, wire.Owner{}, 200); !ok {
		t.Fatal("a fresher (newer-ts) register was refused")
	}
}

// TestTCPConnectInRejectsForgedAssignment proves that a tcpConnectIn adopts an id only from an
// assignment authenticated with the PSK: a MITM on the (unauthenticated) stream must not be able
// to stamp the tun with an attacker-chosen owner.
func TestTCPConnectInRejectsForgedAssignment(t *testing.T) {
	key := wire.KeyFromPSK("real-psk")
	serverOwner := wire.Owner{9, 8, 7, 6}

	// signKey selects whether the fake server signs the assignment with the real PSK or a forged one.
	run := func(signKey [32]byte) (adopted wire.Owner, called bool) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		srvDone := make(chan struct{})
		go func() {
			defer close(srvDone)
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			sc, _ := cipher.NewStream("none", key)
			r, _ := sc.WrapReader(conn) // consume the client's register frame
			buf := make([]byte, wire.MaxPacket)
			if _, err := wire.ReadFrame(r, buf); err != nil {
				return
			}
			wsc, _ := cipher.NewStream("none", key)
			w, _ := wsc.WrapWriter(conn)
			_ = wire.WriteFrame(w, encodeControl(proto.MsgAssignID, serverOwner, 0, 1, signKey))
			// Close (defer) after the assignment: the client processes adoption before its data
			// loop, which then sees EOF and returns — no need to hold the connection open.
		}()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ci := &tcpConnectIn{
			name: "ci", addr: ln.Addr().String(), dialer: plainDialer{},
			key: key, refresh: time.Hour, idSetter: func(o wire.Owner) { adopted, called = o, true },
		}
		ci.cipher, _ = cipher.NewStream("none", key)
		streamed := make(chan struct{})
		go func() { ci.stream(ctx, func(string, wire.Envelope, []byte) {}); close(streamed) }()
		select {
		case <-streamed: // adoption (if any) happened-before this; safe to read the vars below
		case <-time.After(3 * time.Second):
			t.Fatal("connect-in stream did not return")
		}
		cancel()
		<-srvDone
		return
	}

	if _, called := run(wire.KeyFromPSK("mitm")); called {
		t.Fatal("adopted an id from a forged (wrong-key) assignment — MITM could hijack the tun owner")
	}
	if got, called := run(key); !called || got != serverOwner {
		t.Fatalf("a PSK-signed assignment was not adopted: called=%v got=%v", called, got)
	}
}
