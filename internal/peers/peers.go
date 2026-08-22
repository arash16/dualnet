// Package peers tracks the downstream peers of a Listen+Outgoing connection so the
// router can deliver a packet to the right one by its routing owner id. It replaces
// the old single global session table (keyed by client vIP) with a per-connection
// registry keyed by the 4-byte owner.
//
// A "multiple" registry tracks many peers, minting a random id for each new peer and
// demultiplexing return traffic by owner. A "single" registry tracks exactly one peer
// (a new registration supersedes the old) and ignores the owner when sending — it
// just forwards to its one peer, leaving the envelope owner intact for a downstream
// node to route on.
package peers

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/arash16/dualnet/internal/wire"
)

// Sink writes already-serialized bytes to one peer's transport (e.g. a UDP WriteTo to
// the peer's current address, or a framed write down its open HTTP response).
type Sink func(blob []byte) error

type peer struct {
	id       wire.Owner
	key      string // transport identity (e.g. UDP source addr) for idempotent minting
	sink     Sink
	lastSeen time.Time
	lastTS   uint64 // freshness: the highest control timestamp accepted for this peer
}

// Registry is a concurrency-safe set of downstream peers for one ListenOut connection.
// The hot read paths (Send, Accepts) take only a read lock; Register/GC (rare, control-driven)
// take the write lock, so many concurrent downlink sends to distinct peers don't serialize.
type Registry struct {
	mu       sync.RWMutex
	multiple bool
	ttl      time.Duration
	maxPeers int // 0 = unbounded; caps concurrently-tracked peers against a register flood
	now      func() time.Time
	newID    func() wire.Owner

	byID     map[wire.Owner]*peer // multiple mode
	byKey    map[string]*peer     // multiple mode: idempotent mint per transport identity
	single   *peer                // single mode
	singleTS uint64               // single mode: highest control timestamp accepted
}

// New returns a registry. ttl bounds how long a multiple-mode peer may be idle before GC
// removes it (ignored in single mode). maxPeers caps concurrently-tracked peers (<=0 =
// unbounded): a PSK holder could otherwise flood registrations (spoofed source addresses or
// distinct claimed ids) and grow the maps without bound.
func New(multiple bool, ttl time.Duration, maxPeers int) *Registry {
	return &Registry{
		multiple: multiple,
		ttl:      ttl,
		maxPeers: maxPeers,
		now:      time.Now,
		newID:    randomOwner,
		byID:     make(map[wire.Owner]*peer),
		byKey:    make(map[string]*peer),
	}
}

// Register records or refreshes a peer and returns the id to use for it. peerKey is a
// stable transport identity (e.g. the UDP source address) used to make minting
// idempotent, so a register retransmitted before the peer learns its id returns the
// same id rather than minting a duplicate. In multiple mode: a non-zero claimed id is
// adopted/refreshed (a reconnecting peer keeps its id and updates its sink/address); a
// zero claimed id reuses the peerKey's existing id or mints a fresh one. In single
// mode: claimed is ignored, this becomes the one current peer (superseding any
// previous), and the zero id is returned.
func (r *Registry) Register(claimed wire.Owner, peerKey string, ts uint64, sink Sink) (wire.Owner, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.multiple {
		if ts != 0 && ts <= r.singleTS { // replay of an already-seen control datagram
			return wire.Owner{}, false
		}
		r.singleTS = ts
		r.single = &peer{sink: sink, lastSeen: r.now(), lastTS: ts}
		return wire.Owner{}, true
	}
	id := claimed
	if id.IsZero() {
		if p := r.byKey[peerKey]; p != nil {
			id = p.id // idempotent: same peerKey → same id
		} else {
			id = r.mintLocked()
		}
	}
	p := r.byID[id]
	if p == nil {
		// A brand-new peer: enforce the cap here (the only place the maps grow), so a flood of
		// distinct claimed ids / spoofed sources cannot exhaust memory.
		if r.maxPeers > 0 && len(r.byID) >= r.maxPeers {
			return wire.Owner{}, false
		}
		p = &peer{id: id}
		r.byID[id] = p
	} else if ts != 0 && ts <= p.lastTS {
		// Stale/replayed control for an existing peer: reject, preserving its current sink/address
		// binding. This defeats a captured-and-replayed register/keepalive that would otherwise
		// silently hijack the peer's return path to the replayer's address.
		return wire.Owner{}, false
	}
	if p.key != peerKey {
		delete(r.byKey, p.key)
		p.key = peerKey
		r.byKey[peerKey] = p
	}
	p.sink = sink
	p.lastSeen = r.now()
	p.lastTS = ts
	return id, true
}

// Accepts reports whether a packet with this owner can be delivered right now.
func (r *Registry) Accepts(owner wire.Owner) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.multiple {
		return r.single != nil
	}
	return r.byID[owner] != nil
}

// Send delivers blob to the peer selected by owner (multiple) or to the single peer
// (single, owner ignored). delivered=false means no such peer is currently known, so
// the router should try the next target.
func (r *Registry) Send(owner wire.Owner, blob []byte) (delivered bool, err error) {
	r.mu.RLock()
	var sink Sink
	if r.multiple {
		if p := r.byID[owner]; p != nil {
			sink = p.sink
		}
	} else if r.single != nil {
		sink = r.single.sink
	}
	r.mu.RUnlock()
	if sink == nil {
		return false, nil
	}
	return true, sink(blob)
}

// SinkFor returns the sink selected by owner (multiple) or the single peer's sink (single,
// owner ignored), and whether such a peer is currently known. The sink may be invoked after
// this returns; a caller that serializes/seals into a buffer can thus look up once, do the
// work only when a peer exists, and write — without going through Send's blob argument.
func (r *Registry) SinkFor(owner wire.Owner) (Sink, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.multiple {
		if p := r.byID[owner]; p != nil {
			return p.sink, true
		}
		return nil, false
	}
	if r.single != nil {
		return r.single.sink, true
	}
	return nil, false
}

// GC removes multiple-mode peers idle beyond the ttl and returns how many were
// dropped. It is a no-op in single mode.
func (r *Registry) GC() int {
	if !r.multiple {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := r.now().Add(-r.ttl)
	n := 0
	for id, p := range r.byID {
		if p.lastSeen.Before(cutoff) {
			delete(r.byID, id)
			// Only drop the byKey entry if it still points at THIS peer: a newer peer may have
			// reassigned this transport key (a stable client claiming a different id), leaving
			// this one an orphan whose stale key now maps to the live peer. Deleting it blindly
			// would break idempotent minting for that transport identity.
			if r.byKey[p.key] == p {
				delete(r.byKey, p.key)
			}
			n++
		}
	}
	return n
}

// mintLocked returns a fresh non-zero id not already in use. Caller holds r.mu.
func (r *Registry) mintLocked() wire.Owner {
	for {
		id := r.newID()
		if id.IsZero() {
			continue
		}
		if _, exists := r.byID[id]; !exists {
			return id
		}
	}
}

func randomOwner() wire.Owner {
	var o wire.Owner
	_, _ = rand.Read(o[:])
	return o
}
