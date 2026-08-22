package wire

import (
	"bytes"
	"testing"
)

// recordingFrameWriter is an io.Writer that also implements FrameWriter, so WriteFrame
// should take the FrameWriter path and never call Write.
type recordingFrameWriter struct {
	last        []byte
	writeCalled bool
}

func (f *recordingFrameWriter) WriteFrame(p []byte) error {
	f.last = append(f.last[:0], p...)
	return nil
}

func (f *recordingFrameWriter) Write(p []byte) (int, error) {
	f.writeCalled = true
	return len(p), nil
}

// TestWriteFrameDelegatesToFrameWriter proves WriteFrame prefers a writer's own FrameWriter
// (the allocation-free path) over the generic two-Write fallback.
func TestWriteFrameDelegatesToFrameWriter(t *testing.T) {
	fw := &recordingFrameWriter{}
	if err := WriteFrame(fw, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if fw.writeCalled {
		t.Fatal("WriteFrame used the generic Write path instead of delegating to FrameWriter")
	}
	if string(fw.last) != "hello" {
		t.Fatalf("FrameWriter got %q, want hello", fw.last)
	}
}

// TestReadFrameZeroAlloc locks in the receive-path allocation-free guarantee: a hot loop
// reusing one buffer must allocate nothing per frame (the 2-byte length header is read into
// the buffer, not a heap-escaping local array).
func TestReadFrameZeroAlloc(t *testing.T) {
	var w bytes.Buffer
	if err := WriteFrame(&w, bytes.Repeat([]byte{0xAB}, 1400)); err != nil {
		t.Fatal(err)
	}
	frame := append([]byte(nil), w.Bytes()...)
	r := bytes.NewReader(frame)
	dst := make([]byte, MaxPacket)
	allocs := testing.AllocsPerRun(200, func() {
		r.Reset(frame)
		if _, err := ReadFrame(r, dst); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("ReadFrame allocated %v objects/op, want 0", allocs)
	}
}

// TestWriteFrameZeroAllocViaFrameWriter locks in the send-path guarantee for a FrameWriter.
func TestWriteFrameZeroAllocViaFrameWriter(t *testing.T) {
	fw := &recordingFrameWriter{}
	p := bytes.Repeat([]byte{0xCD}, 1400)
	allocs := testing.AllocsPerRun(200, func() {
		if err := WriteFrame(fw, p); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("WriteFrame via FrameWriter allocated %v objects/op, want 0", allocs)
	}
}
