package cipher

import (
	"bytes"
	"io"
	"testing"

	"github.com/arash16/dualnet/internal/wire"
)

// TestStreamFrameRoundTrip proves the chacha4 stream writer's FrameWriter fast path is wire-
// compatible with a reader using wire.ReadFrame: frames written through the length-prefixing
// shortcut decode byte-for-byte, including a zero-length frame (header only).
func TestStreamFrameRoundTrip(t *testing.T) {
	key := wire.KeyFromPSK("frame-roundtrip")
	sc, _ := NewStream("chacha4", key)
	var wireBuf bytes.Buffer
	w, err := sc.WrapWriter(&wireBuf)
	if err != nil {
		t.Fatal(err)
	}
	frames := [][]byte{
		[]byte("a"),
		bytes.Repeat([]byte{0x07}, 1400),
		{},
		[]byte("tail"),
	}
	for i, f := range frames {
		if err := wire.WriteFrame(w, f); err != nil {
			t.Fatalf("write frame %d: %v", i, err)
		}
	}

	rc, _ := NewStream("chacha4", key)
	r, err := rc.WrapReader(&wireBuf)
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, wire.MaxPacket)
	for i, want := range frames {
		n, err := wire.ReadFrame(r, dst)
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		if !bytes.Equal(dst[:n], want) {
			t.Fatalf("frame %d: got %d bytes, want %d", i, n, len(want))
		}
	}
}

// TestStreamWriteFrameZeroAlloc locks in the production send-path guarantee: framing a packet
// through the chacha4 stream writer allocates nothing per frame in steady state.
func TestStreamWriteFrameZeroAlloc(t *testing.T) {
	key := wire.KeyFromPSK("frame-alloc")
	sc, _ := NewStream("chacha4", key)
	w, err := sc.WrapWriter(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	p := bytes.Repeat([]byte{0xEE}, 1400)
	allocs := testing.AllocsPerRun(500, func() {
		if err := wire.WriteFrame(w, p); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("chacha4 stream WriteFrame allocated %v objects/op, want 0", allocs)
	}
}
