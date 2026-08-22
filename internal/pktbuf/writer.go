package pktbuf

import "sync"

// FlushFunc writes a batch of packet views to a sink in as few syscalls as
// possible (e.g. a vectored tun write, or one coalesced stream write). It runs
// under the Writer's lock, so it is never called concurrently with itself and the
// sink it wraps need not be concurrency-safe. For a stream carrier the frame
// cipher runs here; because the Writer holds a single buffer and every flush runs
// under the lock, flushes happen strictly in commit order, keeping the stateful
// keystream in sync.
type FlushFunc func(views [][]byte) error

// Writer buffers packets and flushes them together. Producers build a packet
// directly into the buffer with Reserve/Commit; when the buffer fills, Commit
// flushes it inline. A FlushGroup ticker flushes an idle partial batch so a
// trickle is never stuck. Safe for multiple producer goroutines (e.g. several
// carriers feeding one tun): one mutex guards the buffer and serializes flushes.
type Writer struct {
	flush FlushFunc

	mu    sync.Mutex
	arena []byte
	views [][]byte
	err   error // last flush error (best-effort; surfaced by Flush/Close)
}

// NewWriter builds a Writer whose flush serializes a batch to the wire. arenaCap
// bounds the buffered bytes and must be at least the largest single packet the
// caller will Reserve; maxPackets bounds the buffered packet count. Register the
// Writer with a FlushGroup so idle partials get flushed on the interval.
func NewWriter(flush FlushFunc, arenaCap, maxPackets int) *Writer {
	return &Writer{
		flush: flush,
		arena: make([]byte, 0, arenaCap),
		views: make([][]byte, 0, maxPackets),
	}
}

// Reserve locks the Writer and returns a slice of length max at the tail of the
// buffer to build one packet into. If the packet would not fit or the batch is
// full it flushes the current batch first. The caller MUST call Commit with the
// actual byte count to release the lock; Reserve and Commit bracket one packet
// build and must not be interleaved or nested.
func (w *Writer) Reserve(max int) []byte {
	w.mu.Lock()
	if len(w.views) == cap(w.views) || len(w.arena)+max > cap(w.arena) {
		w.flushLocked()
	}
	start := len(w.arena)
	return w.arena[start : start+max]
}

// Commit records the n bytes just written into the slice Reserve returned as one
// packet and releases the lock, flushing eagerly if the batch is now full.
func (w *Writer) Commit(n int) {
	start := len(w.arena)
	w.arena = w.arena[:start+n]
	w.views = append(w.views, w.arena[start:start+n])
	if len(w.views) == cap(w.views) || len(w.arena) == cap(w.arena) {
		w.flushLocked()
	}
	w.mu.Unlock()
}

// Flush writes any buffered packets now. Called by the FlushGroup ticker and on
// teardown. Returns the last flush error, if any.
func (w *Writer) Flush() error {
	w.mu.Lock()
	w.flushLocked()
	err := w.err
	w.mu.Unlock()
	return err
}

// tryFlush flushes an idle partial without blocking a producer: a held lock means
// a producer is mid-build (so the buffer is not idle) and the tick is skipped.
func (w *Writer) tryFlush() {
	if w.mu.TryLock() {
		w.flushLocked()
		w.mu.Unlock()
	}
}

// Close flushes any buffered packets a final time.
func (w *Writer) Close() error { return w.Flush() }

func (w *Writer) flushLocked() {
	if len(w.views) == 0 {
		return
	}
	if err := w.flush(w.views); err != nil {
		w.err = err // data plane: record and drop; inner TCP retransmits
	}
	w.arena = w.arena[:0]
	w.views = w.views[:0]
}
