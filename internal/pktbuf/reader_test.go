package pktbuf

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// seqSource yields count single-byte packets (payload == index mod 256), at most
// batch per fill; once exhausted, fill returns finalErr.
type seqSource struct {
	next     int
	count    int
	batch    int
	finalErr error
}

func (s *seqSource) fill(b *Batch) error {
	if s.next >= s.count {
		return s.finalErr
	}
	slots := b.Slots()
	added := 0
	for added < s.batch && added < len(slots) && s.next < s.count {
		slots[added][0] = byte(s.next & 0xff)
		b.Add(slots[added][:1])
		s.next++
		added++
	}
	return nil
}

func TestReaderOrderAcrossBatches(t *testing.T) {
	s := &seqSource{count: 10, batch: 3, finalErr: io.EOF}
	r := NewReader(s.fill, nil, func() *Batch { return NewBatch(3, 8, 3) })
	r.Start(context.Background())
	for i := 0; i < 10; i++ {
		v, ok := r.Next()
		if !ok {
			t.Fatalf("Next(%d) not ok", i)
		}
		if v[0] != byte(i) {
			t.Fatalf("packet %d = %d, want %d", i, v[0], i)
		}
	}
	if v, ok := r.Next(); ok {
		t.Fatalf("expected end, got %v", v)
	}
	if !errors.Is(r.Err(), io.EOF) {
		t.Fatalf("Err = %v, want io.EOF", r.Err())
	}
}

// The next batch is fetched while the current one is being drained: the consumer
// must drain batch 1 in full even while the fill of batch 2 is blocked.
func TestReaderPrefetchesAhead(t *testing.T) {
	block := make(chan struct{})
	calls := 0
	fill := func(b *Batch) error {
		calls++
		switch calls {
		case 1:
			for i := 0; i < 3; i++ {
				b.Slots()[i][0] = byte(i)
				b.Add(b.Slots()[i][:1])
			}
			return nil
		case 2:
			<-block
			for i := 0; i < 2; i++ {
				b.Slots()[i][0] = byte(10 + i)
				b.Add(b.Slots()[i][:1])
			}
			return nil
		default:
			return io.EOF
		}
	}
	r := NewReader(fill, nil, func() *Batch { return NewBatch(4, 8, 4) })
	r.Start(context.Background())
	defer r.Close()

	for i := 0; i < 3; i++ {
		v, ok := r.Next()
		if !ok || v[0] != byte(i) {
			t.Fatalf("batch1[%d] = %v ok=%v", i, v, ok)
		}
	}
	got := make(chan bool, 1)
	go func() { _, ok := r.Next(); got <- ok }()
	select {
	case <-got:
		t.Fatal("Next returned before batch 2 was filled")
	case <-time.After(50 * time.Millisecond):
	}
	close(block)
	if ok := <-got; !ok {
		t.Fatal("Next should have returned batch 2")
	}
}

// A fill error must surface only after every already-delivered view is consumed.
func TestReaderErrAfterDrain(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	fill := func(b *Batch) error {
		calls++
		if calls == 1 {
			b.Slots()[0][0], b.Slots()[1][0] = 7, 8
			b.Add(b.Slots()[0][:1])
			b.Add(b.Slots()[1][:1])
			return nil
		}
		return boom
	}
	r := NewReader(fill, nil, func() *Batch { return NewBatch(2, 8, 2) })
	r.Start(context.Background())
	for _, want := range []byte{7, 8} {
		v, ok := r.Next()
		if !ok || v[0] != want {
			t.Fatalf("got %v ok=%v, want %d", v, ok, want)
		}
	}
	if _, ok := r.Next(); ok {
		t.Fatal("expected end after error")
	}
	if !errors.Is(r.Err(), boom) {
		t.Fatalf("Err = %v, want boom", r.Err())
	}
}

func TestReaderCloseUnblocksNext(t *testing.T) {
	closed := make(chan struct{})
	fill := func(b *Batch) error { <-closed; return io.EOF }
	onClose := func() error { close(closed); return nil }
	r := NewReader(fill, onClose, func() *Batch { return NewBatch(1, 8, 1) })
	r.Start(context.Background())

	done := make(chan bool, 1)
	go func() { _, ok := r.Next(); done <- ok }()
	select {
	case <-done:
		t.Fatal("Next returned before Close")
	case <-time.After(50 * time.Millisecond):
	}
	r.Close()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("Next should return !ok after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Next did not return after Close")
	}
}

func TestReaderCtxCancelStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	closed := make(chan struct{})
	fill := func(b *Batch) error { <-closed; return io.EOF }
	onClose := func() error { close(closed); return nil }
	r := NewReader(fill, onClose, func() *Batch { return NewBatch(1, 8, 1) })
	r.Start(ctx)

	done := make(chan bool, 1)
	go func() { _, ok := r.Next(); done <- ok }()
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("Next should return !ok after ctx cancel")
		}
	case <-time.After(time.Second):
		t.Fatal("Next did not return after ctx cancel")
	}
}

// Draining in steady state must not allocate, on the consumer or the prefetch
// goroutine (both share the process malloc counter AllocsPerRun reads).
func TestReaderNextZeroAlloc(t *testing.T) {
	fill := func(b *Batch) error {
		for i := 0; i < 16; i++ {
			b.Slots()[i][0] = byte(i)
			b.Add(b.Slots()[i][:1])
		}
		return nil
	}
	r := NewReader(fill, nil, func() *Batch { return NewBatch(16, 8, 16) })
	r.Start(context.Background())
	defer r.Close()
	for i := 0; i < 2000; i++ {
		r.Next()
	}
	if got := testing.AllocsPerRun(20000, func() { r.Next() }); got != 0 {
		t.Fatalf("Next allocated %v/op, want 0", got)
	}
}

// Run under -race: the prefetch goroutine and the consumer hand batches across
// channels, so there must be no data race on batch storage.
func TestReaderRace(t *testing.T) {
	fill := func(b *Batch) error {
		for i := 0; i < 8; i++ {
			b.Slots()[i][0] = byte(i)
			b.Add(b.Slots()[i][:1])
		}
		return nil
	}
	r := NewReader(fill, nil, func() *Batch { return NewBatch(8, 8, 8) })
	r.Start(context.Background())
	defer r.Close()
	for i := 0; i < 100000; i++ {
		if _, ok := r.Next(); !ok {
			t.Fatal("unexpected end")
		}
	}
}
