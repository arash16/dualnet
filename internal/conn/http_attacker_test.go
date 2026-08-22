package conn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/cipher"
	"github.com/arash16/dualnet/internal/wire"
)

// TestHTTPConnectInBailsOnBadFrameFlood proves that a compromised/MITM download endpoint (the
// body is plaintext, no TLS) can stream endless undecodable frames. httpConnectIn.stream must
// bail after a bounded run of bad frames (like httpListenIn) instead of processing every one and
// spinning the goroutine. The server streams many zero-length frames; a bounded number of drops
// proves the cap fired.
func TestHTTPConnectInBailsOnBadFrameFlood(t *testing.T) {
	const flood = 100000
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		zero := []byte{0, 0} // a complete 2-byte length-prefixed frame of length 0
		for i := 0; i < flood; i++ {
			if _, err := w.Write(zero); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	sc, _ := cipher.NewStream("none", [32]byte{})
	var drops atomic.Int64
	c := &httpConnectIn{
		name: "in", url: srv.URL, userAgent: "test", idHeader: "X-Id",
		cipher: sc, client: srv.Client(), onDrop: func() { drops.Add(1) },
	}

	done := make(chan struct{})
	go func() { c.stream(context.Background(), func(string, wire.Envelope, []byte) {}); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream() did not return — it spun on the bad-frame flood instead of bailing")
	}
	if n := drops.Load(); n > 50 {
		t.Fatalf("stream processed %d bad frames before bailing; want a small bounded number (cap ~8)", n)
	}
}
