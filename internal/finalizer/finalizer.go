// Package finalizer is a node's gateway to the internet. It wraps an egress backend
// (kernel TUN+NAT or userspace WARP netstack) and adds the return-routing state the
// generalized model needs: an internet reply carries no owner, so on submit the
// finalizer remembers, per originating inner IP, the {owner, reply target} chosen by
// the process rule; when the reply comes back it restores the owner, marks it
// processed, and sends it straight to that target (one hop). A healthcheck ping is
// reflected at the process point without ever touching the egress.
package finalizer

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arash16/dualnet/internal/conn"
	"github.com/arash16/dualnet/internal/egress"
	"github.com/arash16/dualnet/internal/pktbuf"
	"github.com/arash16/dualnet/internal/wire"
)

// clockTick is how often Run refreshes the coarse clock. lastSeen is stamped from that
// cached value, so the per-packet paths never call time.Now; a 250ms granularity on a
// minutes-long flow TTL is far finer than the expiry needs.
const clockTick = 250 * time.Millisecond

// The uplink inject buffer: client packets Submit forwards to the internet are batched into one
// egress write (GSO-coalesced on the kernel path) when full or on the flush group's tick.
// injectArena must exceed the largest inner packet (wire.MaxPacket).
const (
	injectArena = 128 * 1024
	injectBatch = 64
)

type entry struct {
	owner    wire.Owner
	target   conn.Sender
	lastSeen int64 // unix nanos, from the coarse clock
}

// Finalizer submits packets to the internet and routes replies back to their owner.
type Finalizer struct {
	eg       egress.Egress
	ttl      time.Duration
	maxTrack int // cap on tracked flows (<=0 = unbounded); bounds a spoofed-source flood
	now      func() time.Time
	clock    atomic.Int64 // coarse now-nanos, refreshed off the per-packet path (see clockTick)

	sentHook func(target string, n int) // optional stats hook for reply sends

	// inject batches the client packets Submit forwards to the internet; the flush group flushes
	// a partial batch on its tick (registered in New).
	fg *pktbuf.FlushGroup
	w  *pktbuf.Writer

	// The hot paths (Submit for an established flow, Run for most replies) take only the read
	// lock: a flow is rewritten only when it is new, rebound, or its coarse lastSeen advanced.
	mu    sync.RWMutex
	track map[netip.Addr]entry // keyed by the originating inner IP (unique per owner)
}

// New wraps an egress backend. ttl bounds how long an idle flow's return mapping is retained.
// maxTrack caps the number of concurrently-tracked return flows (<=0 = unbounded): the map is
// keyed by the inner source IP, which — with cipher=none — an attacker can vary per packet, so
// without a cap a spoofed-source flood would grow it without bound. At the cap a brand-new flow
// is egressed but its return mapping is not recorded (its reply is simply un-routable — the same
// "a dropped return path is silent" posture), so memory stays bounded and existing flows keep
// working; GC reclaims idle entries.
func New(eg egress.Egress, ttl time.Duration, maxTrack int, fg *pktbuf.FlushGroup) *Finalizer {
	f := &Finalizer{eg: eg, ttl: ttl, maxTrack: maxTrack, now: time.Now, track: make(map[netip.Addr]entry), fg: fg}
	f.w = pktbuf.NewWriter(eg.Write, injectArena, injectBatch)
	fg.Add(f.w)
	f.refreshClock()
	return f
}

// refreshClock caches the current time for the per-packet paths to stamp lastSeen with. Run
// calls it on a ticker; tests that drive f.now manually call it to publish the new time.
func (f *Finalizer) refreshClock() { f.clock.Store(f.now().UnixNano()) }

// SetSentHook registers a callback invoked for every packet the finalizer sends back to
// its reply target (the return path, which bypasses the router). Used for stats; the
// target's name is resolved if it also implements Name(). Set before traffic flows.
func (f *Finalizer) SetSentHook(fn func(target string, n int)) { f.sentHook = fn }

func (f *Finalizer) recordSent(target conn.Sender, n int) {
	if f.sentHook == nil {
		return
	}
	name := ""
	if named, ok := target.(interface{ Name() string }); ok {
		name = named.Name()
	}
	f.sentHook(name, n)
}

// Submit sends payload toward the internet, remembering target as the reply path for
// this owner. A ping is reflected immediately (never egressed).
func (f *Finalizer) Submit(owner wire.Owner, target conn.Sender, payload []byte) {
	if wire.IsPing(payload) {
		// The reply carrier buffers the reflected ping; the flush group's tick emits it well within
		// the healthcheck's (seconds-scale) timeout, so no explicit flush is needed here.
		_, _ = target.Send(wire.Envelope{Owner: owner, Processed: true}, payload)
		f.recordSent(target, len(payload))
		return
	}
	if src, ok := wire.SrcIP(payload); ok {
		now := f.clock.Load()
		// Fast path: an established flow whose mapping and coarse lastSeen are unchanged needs
		// no write, so a steady upload takes only the read lock.
		f.mu.RLock()
		e, known := f.track[src]
		fresh := known && e.owner == owner && e.target == target && e.lastSeen == now
		f.mu.RUnlock()
		if !fresh {
			f.mu.Lock()
			if e, known := f.track[src]; known {
				// Rebind/refresh an existing flow — always allowed (no growth).
				e.owner, e.target, e.lastSeen = owner, target, now
				f.track[src] = e
			} else if f.maxTrack <= 0 || len(f.track) < f.maxTrack {
				// A brand-new flow is recorded only while under the cap, bounding memory
				// against a per-packet-spoofed inner source flood.
				f.track[src] = entry{owner: owner, target: target, lastSeen: now}
			}
			f.mu.Unlock()
		}
	}
	dst := f.w.Reserve(len(payload))
	n := copy(dst, payload)
	f.w.Commit(n)
}

// Run reads replies from the egress and sends each back to its owner's remembered
// target, marked processed. It blocks until ctx is cancelled or the egress errors.
func (f *Finalizer) Run(ctx context.Context) error {
	t := time.NewTicker(clockTick)
	defer t.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				f.refreshClock()
			}
		}
	}()
	// Replies are read in batches through a prefetch Reader; each is routed straight to its owner's
	// reply target. The target buffers into its own write batch and self-flushes (full batch or the
	// flush group's tick), so a download burst still coalesces into a few large carrier writes with
	// no flush bookkeeping here. onClose closes the egress so a Fill blocked on the device returns.
	r := pktbuf.NewReader(f.eg.Fill, f.eg.Close, f.eg.NewReadBatch)
	r.Start(ctx)
	defer f.fg.Remove(f.w)
	for {
		pkt, ok := r.Next()
		if !ok {
			if ctx.Err() != nil {
				return nil
			}
			return r.Err()
		}
		if dst, ok := wire.DstIP(pkt); ok {
			now := f.clock.Load()
			f.mu.RLock()
			e, known := f.track[dst]
			f.mu.RUnlock()
			if known {
				if e.lastSeen != now {
					// The coarse clock advanced: refresh this flow's lifetime. Re-check under the
					// write lock in case GC/Submit changed it meanwhile; only the timestamp is bumped.
					f.mu.Lock()
					if cur, ok := f.track[dst]; ok {
						cur.lastSeen = now
						f.track[dst] = cur
					}
					f.mu.Unlock()
				}
				_, _ = e.target.Send(wire.Envelope{Owner: e.owner, Processed: true}, pkt)
				f.recordSent(e.target, len(pkt))
			}
		}
	}
}

// GC drops return mappings idle beyond the ttl and returns how many were removed.
func (f *Finalizer) GC() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	cutoff := f.now().Add(-f.ttl).UnixNano()
	n := 0
	for ip, e := range f.track {
		if e.lastSeen < cutoff {
			delete(f.track, ip)
			n++
		}
	}
	return n
}
