package pktbuf

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordSink copies each flushed view (views alias a reused arena, so a sink that
// retains them must copy) and records them in flush order.
type recordSink struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (s *recordSink) flush(views [][]byte) error {
	s.mu.Lock()
	for _, v := range views {
		s.pkts = append(s.pkts, append([]byte(nil), v...))
	}
	s.mu.Unlock()
	return nil
}

func (s *recordSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pkts)
}

func TestWriterFlushOnFullPreservesOrder(t *testing.T) {
	s := &recordSink{}
	w := NewWriter(s.flush, 1024, 4) // flush every 4 packets
	for i := 0; i < 10; i++ {
		dst := w.Reserve(1)
		dst[0] = byte(i)
		w.Commit(1)
	}
	w.Flush()
	if len(s.pkts) != 10 {
		t.Fatalf("got %d packets, want 10", len(s.pkts))
	}
	for i := range s.pkts {
		if s.pkts[i][0] != byte(i) {
			t.Fatalf("packet %d = %d", i, s.pkts[i][0])
		}
	}
}

// A packet that would overflow the arena flushes the batch first, then goes into
// the freed buffer — order preserved, no allocation, no truncation.
func TestWriterFlushOnArenaFull(t *testing.T) {
	s := &recordSink{}
	w := NewWriter(s.flush, 10, 100) // 10-byte arena, high packet cap
	for i := 0; i < 5; i++ {
		dst := w.Reserve(4)
		for j := range dst {
			dst[j] = byte(i)
		}
		w.Commit(4)
	}
	w.Flush()
	if len(s.pkts) != 5 {
		t.Fatalf("got %d packets, want 5", len(s.pkts))
	}
	for i := range s.pkts {
		if len(s.pkts[i]) != 4 || s.pkts[i][0] != byte(i) {
			t.Fatalf("packet %d = %v", i, s.pkts[i])
		}
	}
}

// Single producer: flush order must equal commit order (the stream cipher relies
// on it). Every flush runs under the one lock over the one buffer, so it holds.
func TestWriterFlushInCommitOrder(t *testing.T) {
	var order []byte
	flush := func(views [][]byte) error {
		for _, v := range views {
			order = append(order, v[0])
		}
		return nil
	}
	w := NewWriter(flush, 64, 3)
	for i := 0; i < 9; i++ {
		dst := w.Reserve(1)
		dst[0] = byte(i)
		w.Commit(1)
	}
	w.Flush()
	if len(order) != 9 {
		t.Fatalf("got %d, want 9", len(order))
	}
	for i := range order {
		if order[i] != byte(i) {
			t.Fatalf("order[%d] = %d", i, order[i])
		}
	}
}

// Several producers feeding one Writer (the tun case): no lost or corrupted
// packets. Each packet is a run of one producer's id; the sink verifies no build
// interleaved with another. Run under -race.
func TestWriterMultiProducerRace(t *testing.T) {
	var count atomic.Int64
	flush := func(views [][]byte) error {
		for _, v := range views {
			for _, x := range v {
				if x != v[0] {
					t.Errorf("corrupt packet: %v", v)
					return nil
				}
			}
			count.Add(1)
		}
		return nil
	}
	w := NewWriter(flush, 4096, 32)
	var wg sync.WaitGroup
	for p := 0; p < 8; p++ {
		wg.Add(1)
		go func(id byte) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				dst := w.Reserve(16)
				for j := range dst {
					dst[j] = id
				}
				w.Commit(16)
			}
		}(byte(p))
	}
	wg.Wait()
	w.Flush()
	if count.Load() != 8000 {
		t.Fatalf("delivered %d packets, want 8000", count.Load())
	}
}

func TestWriterReserveCommitZeroAlloc(t *testing.T) {
	var n int64
	flush := func(views [][]byte) error { n += int64(len(views)); return nil }
	w := NewWriter(flush, 4096, 32)
	for i := 0; i < 2000; i++ {
		dst := w.Reserve(16)
		dst[0] = 1
		w.Commit(16)
	}
	got := testing.AllocsPerRun(20000, func() {
		dst := w.Reserve(16)
		dst[0] = 1
		w.Commit(16)
	})
	if got != 0 {
		t.Fatalf("Reserve/Commit allocated %v/op, want 0", got)
	}
	_ = n
}

func TestFlushGroupFlushesIdlePartial(t *testing.T) {
	s := &recordSink{}
	w := NewWriter(s.flush, 1024, 100)
	dst := w.Reserve(1)
	dst[0] = 42
	w.Commit(1) // one partial packet, batch not full

	g := NewFlushGroup(5 * time.Millisecond)
	g.Add(w)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)

	deadline := time.After(2 * time.Second)
	for s.count() == 0 {
		select {
		case <-deadline:
			t.Fatal("idle partial batch was not flushed by the group ticker")
		case <-time.After(2 * time.Millisecond):
		}
	}
	if s.pkts[0][0] != 42 {
		t.Fatalf("flushed packet = %d, want 42", s.pkts[0][0])
	}
}
