package pktbuf

import (
	"context"
	"sync"
)

// FillFunc reads one or more packets from a source into b, publishing each with
// b.Add (using b.Slots()/b.Sizes() as storage). It blocks until at least one
// packet is available, then returns; it returns an error only when the source is
// dead (fd closed, EOF). A fill must Add at least one view or return an error — a
// nil return with zero views would make the Reader spin.
type FillFunc func(b *Batch) error

// Reader turns a batched source into a single-packet stream, prefetching the next
// batch in a background goroutine while the caller drains the current one. The
// caller blocks in Next only when the current batch is exhausted and the next is
// not yet filled — the sole blocking point, exactly as required.
//
// Lifecycle follows the repo convention: Start registers context.AfterFunc(ctx,
// Close); Close closes the source (via onClose) so a fill blocked in a read
// syscall returns, and stops the prefetch goroutine. Close is idempotent.
type Reader struct {
	fill    FillFunc
	onClose func() error

	ready chan *Batch // filled batches, prefetch -> consumer (cap 1: stay one ahead)
	spent chan *Batch // drained batches, consumer -> prefetch (cap 2 = #batches, never blocks)
	quit  chan struct{}

	initial *Batch // the batch the prefetch goroutine starts with (set in New, cleared in Start)

	cur *Batch
	idx int

	errMu sync.Mutex
	err   error

	closeOnce sync.Once
	readyOnce sync.Once
}

// NewReader builds a Reader over fill. onClose closes the underlying source so a
// blocked fill unblocks (typically the connection/device Close); it may be nil.
// newBatch makes one correctly-sized Batch for this source (see NewBatch); it is
// called twice, once per double-buffered batch. Call Start to launch prefetching.
func NewReader(fill FillFunc, onClose func() error, newBatch func() *Batch) *Reader {
	r := &Reader{
		fill:    fill,
		onClose: onClose,
		ready:   make(chan *Batch, 1),
		spent:   make(chan *Batch, 2),
		quit:    make(chan struct{}),
		initial: newBatch(),
	}
	r.spent <- newBatch()
	return r
}

// Start launches the prefetch goroutine and arms ctx-cancel teardown.
func (r *Reader) Start(ctx context.Context) {
	if r.onClose != nil {
		context.AfterFunc(ctx, func() { _ = r.Close() })
	}
	b := r.initial
	r.initial = nil
	go r.prefetch(b)
}

func (r *Reader) prefetch(b *Batch) {
	// Any exit path closes ready exactly once, so a consumer blocked in Next sees it.
	defer r.readyOnce.Do(func() { close(r.ready) })
	for {
		b.Reset()
		if err := r.fill(b); err != nil {
			r.setErr(err)
			return
		}
		select {
		case r.ready <- b:
		case <-r.quit:
			return
		}
		select {
		case b = <-r.spent:
		case <-r.quit:
			return
		}
	}
}

// Next returns the next packet view, or (nil, false) once the source is drained
// and closed/errored. The returned slice aliases the current batch's storage and
// is valid only until the next Next call; a caller that retains it must copy.
func (r *Reader) Next() ([]byte, bool) {
	for {
		if r.cur != nil && r.idx < len(r.cur.views) {
			v := r.cur.views[r.idx]
			r.idx++
			return v, true
		}
		if r.cur != nil {
			r.spent <- r.cur // cap 2 with 2 batches total: never blocks
			r.cur = nil
		}
		b, ok := <-r.ready
		if !ok {
			return nil, false
		}
		r.cur, r.idx = b, 0
	}
}

// Err returns the error that ended prefetching, or nil on a clean close.
func (r *Reader) Err() error {
	r.errMu.Lock()
	defer r.errMu.Unlock()
	return r.err
}

func (r *Reader) setErr(err error) {
	r.errMu.Lock()
	r.err = err
	r.errMu.Unlock()
}

// Close stops the prefetch goroutine and closes the source. Idempotent.
func (r *Reader) Close() error {
	var err error
	r.closeOnce.Do(func() {
		close(r.quit)
		if r.onClose != nil {
			err = r.onClose()
		}
	})
	return err
}
