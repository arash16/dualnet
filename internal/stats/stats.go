// Package stats gathers lightweight runtime counters for a node and periodically
// writes a snapshot to a file (one JSON object per line, JSONL). It tracks, per
// connection, how many data packets were received and sent; per routing rule, how many
// packets it matched; and, globally, how many packets were dropped (either because no
// route accepted them or because they failed to decrypt/parse). It also samples memory
// use and the goroutine count once a second and reports the peak of each over every
// write interval, so a slow leak shows up as a rising max.
//
// Counters are plain atomics behind maps that are populated once at construction and
// only read afterward, so the hot path is lock-free (a map read plus an atomic add).
package stats

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// connStat holds one connection's counters.
type connStat struct {
	recv      atomic.Uint64 // data packets received
	sent      atomic.Uint64 // data packets sent
	recvBytes atomic.Uint64 // inner payload bytes received
	sentBytes atomic.Uint64 // inner payload bytes sent
}

// Registry holds every counter for a node. Build it with New, register route labels
// with SetRoutes, then hand its methods to the router / connections / ingress.
type Registry struct {
	conns  map[string]*connStat
	routes map[string]*atomic.Uint64

	noRouteDrops atomic.Uint64 // packets no target accepted
	decodeDrops  atomic.Uint64 // packets that failed to decrypt/parse at a receiver

	start time.Time
	now   func() time.Time

	// memory window (peak since the last snapshot); guarded by memMu.
	memMu    sync.Mutex
	maxHeap  uint64
	maxSys   uint64
	maxGoros int
}

// New builds a registry with a counter slot per connection name. Route labels are
// registered later via SetRoutes (they are only known after the router compiles).
func New(connNames []string) *Registry {
	r := &Registry{
		conns:  make(map[string]*connStat, len(connNames)),
		routes: make(map[string]*atomic.Uint64),
		start:  time.Now(),
		now:    time.Now,
	}
	for _, n := range connNames {
		r.conns[n] = &connStat{}
	}
	return r
}

// SetRoutes registers the routing-rule labels that Route may report. Call once, before
// any traffic flows (before connections start), so the map is never written concurrently.
func (r *Registry) SetRoutes(labels []string) {
	for _, l := range labels {
		if _, ok := r.routes[l]; !ok {
			r.routes[l] = new(atomic.Uint64)
		}
	}
}

// Recv records a data packet of n payload bytes received on connection name.
func (r *Registry) Recv(name string, n int) {
	if c := r.conns[name]; c != nil {
		c.recv.Add(1)
		c.recvBytes.Add(uint64(n))
	}
}

// Sent records a data packet of n payload bytes delivered out of connection name.
func (r *Registry) Sent(name string, n int) {
	if c := r.conns[name]; c != nil {
		c.sent.Add(1)
		c.sentBytes.Add(uint64(n))
	}
}

// Route records that the routing rule with this label matched a packet.
func (r *Registry) Route(label string) {
	if c := r.routes[label]; c != nil {
		c.Add(1)
	}
}

// NoRouteDrop records a packet dropped because no target accepted it.
func (r *Registry) NoRouteDrop() { r.noRouteDrops.Add(1) }

// DecodeDrop records a packet dropped at a receiver because it failed to decrypt/parse
// (e.g. a PSK mismatch or corruption).
func (r *Registry) DecodeDrop() { r.decodeDrops.Add(1) }

// Counts is one connection's cumulative packet + byte counts.
type Counts struct {
	Recv      uint64 `json:"recv"`
	Sent      uint64 `json:"sent"`
	RecvBytes uint64 `json:"recv_bytes"`
	SentBytes uint64 `json:"sent_bytes"`
}

// Drops breaks the dropped-packet total down by cause.
type Drops struct {
	NoRoute uint64 `json:"no_route"`
	Decode  uint64 `json:"decode"`
}

// Snapshot is one line written to the stats file: cumulative counters plus the memory
// peaks observed over the interval that just ended.
type Snapshot struct {
	Time      string            `json:"time"`
	UptimeSec int64             `json:"uptime_s"`
	MaxHeapMB float64           `json:"max_heap_mb"`    // peak HeapAlloc over the interval
	MaxSysMB  float64           `json:"max_sys_mb"`     // peak Sys (total from OS) over the interval
	MaxGoros  int               `json:"max_goroutines"` // peak goroutine count over the interval
	Conns     map[string]Counts `json:"conns"`
	Routes    map[string]uint64 `json:"routes"`
	Drops     Drops             `json:"drops"`
}

// sample folds the current memory/goroutine reading into the interval window.
func (r *Registry) sample() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	g := runtime.NumGoroutine()
	r.memMu.Lock()
	if m.HeapAlloc > r.maxHeap {
		r.maxHeap = m.HeapAlloc
	}
	if m.Sys > r.maxSys {
		r.maxSys = m.Sys
	}
	if g > r.maxGoros {
		r.maxGoros = g
	}
	r.memMu.Unlock()
}

// takeWindow returns the interval peaks and resets them for the next window.
func (r *Registry) takeWindow() (heap, sys uint64, goros int) {
	r.memMu.Lock()
	defer r.memMu.Unlock()
	heap, sys, goros = r.maxHeap, r.maxSys, r.maxGoros
	r.maxHeap, r.maxSys, r.maxGoros = 0, 0, 0
	return
}

const mib = 1024 * 1024

// snapshot builds a Snapshot from the current counters, consuming the memory window.
func (r *Registry) snapshot() Snapshot {
	heap, sys, goros := r.takeWindow()
	conns := make(map[string]Counts, len(r.conns))
	for name, c := range r.conns {
		conns[name] = Counts{
			Recv: c.recv.Load(), Sent: c.sent.Load(),
			RecvBytes: c.recvBytes.Load(), SentBytes: c.sentBytes.Load(),
		}
	}
	routes := make(map[string]uint64, len(r.routes))
	for label, c := range r.routes {
		routes[label] = c.Load()
	}
	return Snapshot{
		Time:      r.now().UTC().Format(time.RFC3339),
		UptimeSec: int64(r.now().Sub(r.start).Seconds()),
		MaxHeapMB: float64(heap) / mib,
		MaxSysMB:  float64(sys) / mib,
		MaxGoros:  goros,
		Conns:     conns,
		Routes:    routes,
		Drops:     Drops{NoRoute: r.noRouteDrops.Load(), Decode: r.decodeDrops.Load()},
	}
}

// Run samples memory every second and appends a snapshot to path every interval, until
// ctx is cancelled (then it writes one final snapshot). The file is rotated once it would
// exceed maxBytes (renamed to <base>-old<ext>, overwriting any previous rotation, then
// restarted), so it is bounded to roughly 2*maxBytes; maxBytes <= 0 disables rotation. It
// returns any error opening the file; write errors are otherwise silent (stats must never
// take the node down).
func (r *Registry) Run(ctx context.Context, path string, interval time.Duration, maxBytes int64) error {
	f, err := newRotatingWriter(path, maxBytes)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)

	r.sample() // seed the first window immediately
	sampleT := time.NewTicker(time.Second)
	defer sampleT.Stop()
	writeT := time.NewTicker(interval)
	defer writeT.Stop()

	for {
		select {
		case <-ctx.Done():
			r.sample() // fold in a final reading so the last window is never empty
			_ = enc.Encode(r.snapshot())
			return nil
		case <-sampleT.C:
			r.sample()
		case <-writeT.C:
			r.sample() // ensure the window has a fresh reading even if interval==sample rate
			_ = enc.Encode(r.snapshot())
		}
	}
}

// rotatedName inserts "-old" before the extension: /var/log/x.jsonl -> /var/log/x-old.jsonl.
func rotatedName(path string) string {
	ext := filepath.Ext(path)
	return strings.TrimSuffix(path, ext) + "-old" + ext
}

// rotatingWriter appends to a file, rotating it to <base>-old<ext> once a write would
// push it past max bytes (max <= 0 disables rotation). Only the current file and one
// previous rotation are kept, so total on-disk size stays bounded.
type rotatingWriter struct {
	path    string
	rotated string
	max     int64
	f       *os.File
	size    int64
}

func newRotatingWriter(path string, max int64) (*rotatingWriter, error) {
	w := &rotatingWriter{path: path, rotated: rotatedName(path), max: max}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	w.f = f
	if st, err := f.Stat(); err == nil {
		w.size = st.Size() // continue an existing file toward its cap
	}
	return w, nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	if w.max > 0 && w.size+int64(len(p)) > w.max {
		w.rotate()
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate closes the current file, renames it over the previous rotation, and reopens a
// fresh empty file. On any failure it falls back to truncating in place so the file can
// never grow without bound.
func (w *rotatingWriter) rotate() {
	_ = w.f.Close()
	_ = os.Rename(w.path, w.rotated) // overwrites the previous -old
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		// Reopen failed after the rename; try once more without assumptions.
		f, err = os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return // keep the (closed) old handle; next Write errors, which we ignore
		}
	}
	w.f = f
	w.size = 0
}

func (w *rotatingWriter) Close() error { return w.f.Close() }
