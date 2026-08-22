package conn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/cipher"
	"github.com/arash16/dualnet/internal/pktbuf"
	"github.com/arash16/dualnet/internal/wire"
)

// startDownloadServer builds and starts a multiple httpListenOut on a free port with the given
// PSK key, returning it and its base URL.
func startDownloadServer(t *testing.T, key [32]byte, multiple bool, fg *pktbuf.FlushGroup) (*httpListenOut, string) {
	t.Helper()
	port := freeUDPPort(t) // any free localhost port
	sc, _ := cipher.NewStream("none", key)
	ln, err := listenTCP(context.Background(), "", ":"+itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	lo := &httpListenOut{
		name: "down", cipher: sc, multiple: multiple, byID: map[wire.Owner]*httpDownConn{},
		lastTS: map[wire.Owner]uint64{}, key: key, ln: ln, path: "/download", idHeader: "X-Id",
		fg: fg,
	}
	lo.srv = &http.Server{Handler: http.HandlerFunc(lo.serveHTTP)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := lo.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lo.Close() })
	return lo, "http://127.0.0.1:" + itoa(port) + "/download"
}

// get issues a GET with the given id + optional auth header and returns the status code (closing
// the body immediately so a held-open 200 stream is released).
func get(t *testing.T, url string, headers map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	cl := &http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestHTTPDownloadRequiresAuth proves that the download GET must prove PSK knowledge, or an
// off-path client could register/hijack the downlink. A GET with no auth header, or one tagged
// under the wrong key, is refused (404); only a correctly-tagged GET is accepted (200).
func TestHTTPDownloadRequiresAuth(t *testing.T) {
	key := wire.KeyFromPSK("real-psk")
	_, url := startDownloadServer(t, key, true, pktbuf.NewFlushGroup(time.Hour))
	zero := wire.Owner{}

	// (a) no auth header at all → refused.
	if code := get(t, url, map[string]string{"X-Id": ownerHex(zero)}); code == http.StatusOK {
		t.Fatal("unauthenticated download GET was accepted (off-path hijack possible)")
	}
	// (b) auth tagged under the WRONG key → refused.
	bad := authToken(wire.KeyFromPSK("attacker-guess"), authDomainReg, zero, 1)
	if code := get(t, url, map[string]string{"X-Id": ownerHex(zero), "X-Id-Sig": bad}); code == http.StatusOK {
		t.Fatal("download GET with a wrong-key auth tag was accepted")
	}
	// (c) correctly-tagged GET → accepted.
	good := authToken(key, authDomainReg, zero, 1)
	if code := get(t, url, map[string]string{"X-Id": ownerHex(zero), "X-Id-Sig": good}); code != http.StatusOK {
		t.Fatalf("correctly-authenticated download GET was refused: %d", code)
	}
}

// TestHTTPDownloadRejectsReplay proves the freshness property on a single-mode listener (its one
// peer is keyed by the zero id): a verbatim replay of an accepted GET (same token → same ts) is
// refused, so a captured GET cannot re-bind the downlink to a replayer.
func TestHTTPDownloadRejectsReplay(t *testing.T) {
	key := wire.KeyFromPSK("real-psk")
	_, url := startDownloadServer(t, key, false, pktbuf.NewFlushGroup(time.Hour)) // single mode
	zero := wire.Owner{}
	tok := authToken(key, authDomainReg, zero, 100)
	hdr := map[string]string{"X-Id": ownerHex(zero), "X-Id-Sig": tok}

	if code := get(t, url, hdr); code != http.StatusOK {
		t.Fatalf("first register refused: %d", code)
	}
	if code := get(t, url, hdr); code == http.StatusOK {
		t.Fatal("a replayed (stale-ts) download GET was accepted — anti-replay not enforced")
	}
	// A fresher token (newer ts) from the legit client is still accepted.
	fresh := map[string]string{"X-Id": ownerHex(zero), "X-Id-Sig": authToken(key, authDomainReg, zero, 200)}
	if code := get(t, url, fresh); code != http.StatusOK {
		t.Fatalf("a fresher register was refused: %d", code)
	}
}

// TestHTTPListenOutBatchesDownlinkWrites proves the per-peer write batch on the http down stream:
// packets sent while the flush group is idle stay buffered (no per-packet response write+flush);
// one group flush then emits the whole batch into the held-open response, in send order.
func TestHTTPListenOutBatchesDownlinkWrites(t *testing.T) {
	key := wire.KeyFromPSK("http-batch")
	fg := pktbuf.NewFlushGroup(time.Millisecond) // built now, run later: sends stay buffered until then
	lo, url := startDownloadServer(t, key, true, fg)

	zero := wire.Owner{}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Id", ownerHex(zero))
	req.Header.Set("X-Id-Sig", authToken(key, authDomainReg, zero, 1))
	resp, err := (&http.Client{}).Do(req) // no client timeout: the body is a held-open stream
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download GET refused: %d", resp.StatusCode)
	}
	id := parseOwnerHex(resp.Header.Get("X-Id"))
	if id.IsZero() {
		t.Fatal("no id assigned")
	}

	pkts := [][]byte{testIPv4("h0"), testIPv4("h1"), testIPv4("h2")}
	// The stream goes live (WrapWriter done) slightly after the client sees headers; until then
	// Send reports not-delivered, so retry the first packet.
	waitFor(t, "stream live", func() bool {
		delivered, err := lo.Send(wire.Envelope{Owner: id, Processed: true}, pkts[0])
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		return delivered
	})
	for _, p := range pkts[1:] {
		if delivered, err := lo.Send(wire.Envelope{Owner: id, Processed: true}, p); !delivered || err != nil {
			t.Fatalf("send: delivered=%v err=%v", delivered, err)
		}
	}

	// Frames are read off the body on a side goroutine (the none cipher leaves the codec bytes
	// bare on the wire); none may appear before the group flushes.
	type frame struct {
		payload []byte
		err     error
	}
	frames := make(chan frame, len(pkts)+1)
	go func() {
		buf := make([]byte, wire.MaxPacket)
		for {
			n, err := wire.ReadFrame(resp.Body, buf)
			if err != nil {
				frames <- frame{err: err}
				return
			}
			e, payload, ok := wire.ParseEnvelope(buf[:n])
			if !ok || e.Owner != id || !e.Processed {
				frames <- frame{err: errBadHTTPFrame}
				return
			}
			frames <- frame{payload: append([]byte(nil), payload...)}
		}
	}()
	select {
	case f := <-frames:
		t.Fatalf("a frame reached the client before any flush (per-packet write?): %q err=%v", f.payload, f.err)
	case <-time.After(150 * time.Millisecond):
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fg.Run(ctx)
	for i, want := range pkts {
		select {
		case f := <-frames:
			if f.err != nil {
				t.Fatalf("frame %d: %v", i, f.err)
			}
			if string(f.payload) != string(want) {
				t.Fatalf("frame %d payload %q, want %q", i, f.payload, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("frame %d never arrived", i)
		}
	}
}

var errBadHTTPFrame = errors.New("bad frame envelope")

// TestHTTPConnectInRejectsForgedAssignment proves that httpConnectIn must not adopt an id from a
// download response unless it is authenticated with the PSK, or a MITM on the plaintext response
// could stamp the tun with an attacker-chosen owner. It adopts only a properly-signed assignment.
func TestHTTPConnectInRejectsForgedAssignment(t *testing.T) {
	key := wire.KeyFromPSK("real-psk")
	serverOwner := wire.Owner{1, 2, 3, 4}
	var signed bool // controls whether the server signs the assignment

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Id", ownerHex(serverOwner))
		if signed {
			w.Header().Set("X-Id-Sig", authToken(key, authDomainAssign, serverOwner, 1))
		} else {
			w.Header().Set("X-Id-Sig", authToken(wire.KeyFromPSK("mitm"), authDomainAssign, serverOwner, 1)) // forged
		}
		w.WriteHeader(http.StatusOK) // empty body → stream() returns after the header check
	}))
	defer srv.Close()

	run := func() (adopted wire.Owner, called bool) {
		sc, _ := cipher.NewStream("none", key)
		c := &httpConnectIn{
			name: "in", url: srv.URL, userAgent: "t", idHeader: "X-Id", key: key,
			cipher: sc, client: srv.Client(),
			idSetter: func(o wire.Owner) { adopted, called = o, true },
		}
		c.stream(context.Background(), func(string, wire.Envelope, []byte) {})
		return
	}

	// Forged (wrong-key) assignment: must NOT be adopted.
	signed = false
	if _, called := run(); called {
		t.Fatal("adopted an id from a forged (unauthenticated) assignment — MITM could hijack the tun owner")
	}
	// Properly-signed assignment: adopted.
	signed = true
	if got, called := run(); !called || got != serverOwner {
		t.Fatalf("a PSK-signed assignment was not adopted: called=%v got=%v", called, got)
	}
}
