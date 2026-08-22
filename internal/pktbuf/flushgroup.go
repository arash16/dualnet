package pktbuf

import (
	"context"
	"sync"
	"time"
)

// FlushGroup flushes registered Writers on an interval so a partially-filled
// batch is never stuck waiting for the next write. One goroutine (Run) serves
// every Writer on a node, so per-Writer flushing needs no goroutine of its own.
type FlushGroup struct {
	interval time.Duration

	mu      sync.Mutex
	writers map[*Writer]struct{}
	scratch []*Writer // reused snapshot, so flushing runs off the lock without per-tick alloc
}

// NewFlushGroup creates a group whose Run flushes members every interval.
func NewFlushGroup(interval time.Duration) *FlushGroup {
	return &FlushGroup{interval: interval, writers: make(map[*Writer]struct{})}
}

// Add registers w for interval flushing.
func (g *FlushGroup) Add(w *Writer) {
	g.mu.Lock()
	g.writers[w] = struct{}{}
	g.mu.Unlock()
}

// Remove stops flushing w (call before the Writer's final Close on teardown).
func (g *FlushGroup) Remove(w *Writer) {
	g.mu.Lock()
	delete(g.writers, w)
	g.mu.Unlock()
}

// Run flushes every registered Writer once per interval until ctx is cancelled.
func (g *FlushGroup) Run(ctx context.Context) {
	t := time.NewTicker(g.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.flushAll()
		}
	}
}

func (g *FlushGroup) flushAll() {
	g.mu.Lock()
	g.scratch = g.scratch[:0]
	for w := range g.writers {
		g.scratch = append(g.scratch, w)
	}
	ws := g.scratch
	g.mu.Unlock()
	// Off the group lock: a slow flush must not stall Add/Remove. tryFlush skips a
	// Writer whose producer holds its lock (not idle, so no partial to rescue).
	for _, w := range ws {
		w.tryFlush()
	}
}
