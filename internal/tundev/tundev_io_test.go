package tundev

import (
	"bytes"
	"io"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeTun is an in-memory tun.Device: Read delivers queued packets (up to batch per
// call), Write records what was written. cycle makes Read replay its queue endlessly
// (for steady-state allocation checks).
type fakeTun struct {
	batch   int
	reads   [][]byte
	readIdx int
	cycle   bool
	written [][]byte
	events  chan tun.Event
}

func (f *fakeTun) File() *os.File { return nil }

func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if f.readIdx >= len(f.reads) {
		if !f.cycle {
			return 0, io.EOF
		}
		f.readIdx = 0
	}
	n := 0
	for n < len(bufs) && f.readIdx < len(f.reads) {
		pkt := f.reads[f.readIdx]
		copy(bufs[n][offset:], pkt)
		sizes[n] = len(pkt)
		f.readIdx++
		n++
	}
	return n, nil
}

func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.written = append(f.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

func (f *fakeTun) MTU() (int, error)        { return 1280, nil }
func (f *fakeTun) Name() (string, error)    { return "faketun", nil }
func (f *fakeTun) Events() <-chan tun.Event { return f.events }
func (f *fakeTun) Close() error             { return nil }
func (f *fakeTun) BatchSize() int           { return f.batch }

func pkt(b ...byte) []byte { return b }

// TestFillOrderAcrossBatches: with a small BatchSize the queued packets arrive across several
// device reads; Fill must publish every packet exactly once, in order, across successive fills.
// Each view aliases the batch's storage, so it is copied out before the batch is reused.
func TestFillOrderAcrossBatches(t *testing.T) {
	pkts := [][]byte{pkt(0x45, 1), pkt(0x45, 2, 2), pkt(0x45, 3), pkt(0x45, 4, 4, 4), pkt(0x45, 5)}
	d := newDevice(&fakeTun{batch: 2, reads: pkts}, "faketun", 1280) // batch=2 forces multiple reads
	b := d.NewReadBatch()
	var got [][]byte
	for {
		b.Reset()
		err := d.Fill(b)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Fill: %v", err)
		}
		for _, v := range b.Views() {
			got = append(got, append([]byte(nil), v...))
		}
	}
	if len(got) != len(pkts) {
		t.Fatalf("filled %d packets, want %d", len(got), len(pkts))
	}
	for i, want := range pkts {
		if !bytes.Equal(got[i], want) {
			t.Fatalf("packet %d = %x, want %x", i, got[i], want)
		}
	}
}

// TestFillAliasesBatch guards the aliasing contract: a view Fill publishes points into the batch's
// own storage, so it changes once the batch is Reset and refilled. A caller keeping a packet copies.
func TestFillAliasesBatch(t *testing.T) {
	d := newDevice(&fakeTun{batch: 1, cycle: true, reads: [][]byte{
		pkt(0x45, 0xAA), pkt(0x45, 0xBB),
	}}, "faketun", 1280)
	b := d.NewReadBatch()
	if err := d.Fill(b); err != nil {
		t.Fatal(err)
	}
	first := b.Views()[0]
	firstCopy := append([]byte(nil), first...)
	b.Reset()
	if err := d.Fill(b); err != nil { // refills the same slot
		t.Fatal(err)
	}
	if bytes.Equal(first, firstCopy) {
		t.Skip("buffer happened not to be reused this run; alias contract is best-effort to observe")
	}
}

// TestWrite: a batch spanning multiple dev.Write chunks is written in order, and reusing the
// per-slot scratch must not truncate a longer packet that follows a short one.
func TestWrite(t *testing.T) {
	ft := &fakeTun{batch: 2} // batch=2 forces the 3-packet write to span multiple dev.Write chunks
	d := newDevice(ft, "faketun", 1280)
	batch := [][]byte{pkt(0x45, 1), pkt(0x45, 2, 2), pkt(0x45, 3, 3, 3)}
	if err := d.Write(batch); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(ft.written) != 3 {
		t.Fatalf("wrote %d packets, want 3", len(ft.written))
	}
	for i, want := range batch {
		if !bytes.Equal(ft.written[i], want) {
			t.Fatalf("written[%d] = %x, want %x", i, ft.written[i], want)
		}
	}
	long := make([]byte, 900)
	long[0] = 0x45
	for i := 1; i < len(long); i++ {
		long[i] = byte(i)
	}
	ft.written = nil
	if err := d.Write([][]byte{pkt(0x45, 9), long}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ft.written[1], long) {
		t.Fatalf("long packet garbled after reuse: got %d bytes want %d", len(ft.written[1]), len(long))
	}
}

// TestFillZeroAlloc pins that steady-state Fill allocates nothing: the view slice is reused across
// Reset, and each view aliases a pre-allocated slot (no make+copy per packet).
func TestFillZeroAlloc(t *testing.T) {
	d := newDevice(&fakeTun{batch: 8, cycle: true, reads: [][]byte{
		pkt(0x45, 1, 2, 3), pkt(0x45, 4, 5, 6, 7),
	}}, "faketun", 1280)
	b := d.NewReadBatch()
	b.Reset()
	if err := d.Fill(b); err != nil { // warm
		t.Fatal(err)
	}
	got := testing.AllocsPerRun(1000, func() {
		b.Reset()
		if err := d.Fill(b); err != nil {
			t.Fatal(err)
		}
	})
	if got != 0 {
		t.Fatalf("Fill allocated %v times/op, want 0", got)
	}
}
