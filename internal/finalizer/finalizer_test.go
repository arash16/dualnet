package finalizer

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/pktbuf"
	"github.com/arash16/dualnet/internal/wire"
)

type fakeEgress struct {
	written [][]byte
	replies chan []byte
}

func (e *fakeEgress) NewReadBatch() *pktbuf.Batch { return pktbuf.NewBatch(1, 65535, 1) }
func (e *fakeEgress) Fill(b *pktbuf.Batch) error {
	r, ok := <-e.replies
	if !ok {
		return io.EOF
	}
	dst := b.Slots()[0]
	n := copy(dst, r)
	b.Add(dst[:n])
	return nil
}
func (e *fakeEgress) Write(pkts [][]byte) error {
	for _, p := range pkts {
		e.written = append(e.written, append([]byte(nil), p...))
	}
	return nil
}
func (e *fakeEgress) Close() error { return nil }

// newTestFin builds a Finalizer with a flush group that is never Run, so the inject Writer flushes
// only on an explicit f.w.Flush() (or when full) — letting a test observe egress deterministically.
func newTestFin(eg *fakeEgress, ttl time.Duration, maxTrack int) *Finalizer {
	return New(eg, ttl, maxTrack, pktbuf.NewFlushGroup(time.Hour))
}

type capture struct {
	e   wire.Envelope
	pkt []byte
}
type fakeSender struct{ got chan capture }

func (s *fakeSender) Accepts(wire.Owner) bool { return true }
func (s *fakeSender) Send(e wire.Envelope, p []byte) (bool, error) {
	s.got <- capture{e, append([]byte(nil), p...)}
	return true, nil
}

func ipv4(src, dst string, proto byte) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], 28)
	p[9] = proto
	copy(p[12:16], netip.MustParseAddr(src).AsSlice())
	copy(p[16:20], netip.MustParseAddr(dst).AsSlice())
	return p
}

func TestSubmitReplyRoundTrip(t *testing.T) {
	eg := &fakeEgress{replies: make(chan []byte, 1)}
	f := newTestFin(eg, time.Minute, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)

	snd := &fakeSender{got: make(chan capture, 1)}
	owner := wire.Owner{1, 2, 3, 4}
	f.Submit(owner, snd, ipv4("10.9.0.2", "1.2.3.4", 6))
	_ = f.w.Flush() // Submit buffers into the inject batch; force it out so the fake records it
	if len(eg.written) != 1 {
		t.Fatalf("submit should egress the packet; wrote %d", len(eg.written))
	}
	// Reply from the internet (dst = the originating inner IP).
	eg.replies <- ipv4("1.2.3.4", "10.9.0.2", 6)
	select {
	case c := <-snd.got:
		if c.e.Owner != owner || !c.e.Processed {
			t.Fatalf("reply envelope = %+v, want owner=%v processed", c.e, owner)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reply not delivered to target")
	}
}

func TestPingReflectedWithoutEgress(t *testing.T) {
	eg := &fakeEgress{replies: make(chan []byte)}
	f := newTestFin(eg, time.Minute, 0)
	snd := &fakeSender{got: make(chan capture, 1)}
	owner := wire.Owner{9, 9, 9, 9}
	f.Submit(owner, snd, wire.EncodePing(42))
	if len(eg.written) != 0 {
		t.Fatal("a ping must not be egressed")
	}
	select {
	case c := <-snd.got:
		if c.e.Owner != owner || !c.e.Processed || !wire.IsPing(c.pkt) {
			t.Fatalf("ping reflect = %+v isPing=%v", c.e, wire.IsPing(c.pkt))
		}
	case <-time.After(time.Second):
		t.Fatal("ping not reflected to target")
	}
}

func TestSentHookCountsReplies(t *testing.T) {
	eg := &fakeEgress{replies: make(chan []byte, 1)}
	f := newTestFin(eg, time.Minute, 0)
	var hookBytes, hookCalls int
	done := make(chan struct{}, 1)
	f.SetSentHook(func(_ string, n int) { hookBytes += n; hookCalls++; done <- struct{}{} })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)

	snd := &fakeSender{got: make(chan capture, 1)}
	owner := wire.Owner{1, 2, 3, 4}
	f.Submit(owner, snd, ipv4("10.9.0.2", "1.2.3.4", 6)) // egress; not a reply, no hook
	eg.replies <- ipv4("1.2.3.4", "10.9.0.2", 6)         // reply -> counted
	<-snd.got
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sent hook not called for reply")
	}
	if hookCalls != 1 || hookBytes != 28 {
		t.Fatalf("hook calls=%d bytes=%d, want 1/28", hookCalls, hookBytes)
	}
}
