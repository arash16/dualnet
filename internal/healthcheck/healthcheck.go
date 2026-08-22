// Package healthcheck implements dualnet's end-to-end liveness probe: a round-trip that
// tests the whole path a tun's traffic takes, regardless of which carrier each hop uses.
//
// A Driver periodically injects a ping into the path (owner = the tun's id,
// Processed=false). It travels the same path as data up to a gateway, whose finalizer
// reflects it back (Processed=true) to the process rule's Target instead of egressing it,
// and it returns to the origin tun, which records liveness via Seen. If nothing is heard
// for the timeout, the Driver reconnects the node's Connect connections.
//
// The Driver also exposes a healthy⇄unhealthy edge (onHealth): it starts unhealthy, goes
// down immediately on silence (safe), and goes up only after sustained liveness for
// upGrace (anti-flap). Consumers gate a routing branch on that state to fail over
// in-process.
//
// Cadence (interval): negative disables active probing; 0 is "lazy" (probe only when
// there is outbound traffic, so an idle tun stays quiet); positive probes on that fixed
// schedule.
package healthcheck

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/arash16/dualnet/internal/wire"
)

// Reconnecter is a Connect connection the driver re-establishes on probe failure.
type Reconnecter interface {
	Reconnect(ctx context.Context) error
}

// Driver runs one round-trip's end-to-end healthcheck loop.
type Driver struct {
	interval time.Duration // <0 disabled, 0 lazy, >0 fixed cadence
	timeout  time.Duration
	upGrace  time.Duration     // sustained liveness required before declaring healthy
	probe    func(ping []byte) // injects a ping (owner stamped by the caller)
	links    []Reconnecter     // Connect connections to reconnect on silence
	onHealth func(bool)        // edge-fired healthy⇄unhealthy transition (may be nil)

	seq      atomic.Uint64
	lastSeen atomic.Int64
	lastSent atomic.Int64
	sentTick atomic.Bool
	now      func() time.Time

	// run-loop state; only touched by Run's goroutine (or tests, single-threaded).
	healthy        bool
	lastObserved   int64
	candidateSince time.Time
	wasActive      bool      // previous tick's `active`, to detect lazy-mode resume from idle
	activeSince    time.Time // when the current active (probing) window began
}

// New builds a driver. probe injects an owner-stamped ping; links are the Connect
// connections to reconnect when the path goes silent; onHealth (may be nil) is fired on
// each healthy⇄unhealthy edge; upGrace is the sustained-liveness window before healthy.
func New(interval, timeout, upGrace time.Duration, probe func(ping []byte), links []Reconnecter, onHealth func(bool)) *Driver {
	return &Driver{
		interval: interval, timeout: timeout, upGrace: upGrace,
		probe: probe, links: links, onHealth: onHealth, now: time.Now,
	}
}

// Seen records that a packet arrived back at the tun (data or a reflected ping).
func (d *Driver) Seen() { d.lastSeen.Store(d.now().UnixNano()) }

// SentData records that the tun sent a data packet; gates lazy-mode probing.
func (d *Driver) SentData() {
	d.lastSent.Store(d.now().UnixNano())
	d.sentTick.Store(true)
}

// Healthy reports the current liveness state.
func (d *Driver) Healthy() bool { return d.healthy }

// Run drives the loop until ctx is cancelled.
func (d *Driver) Run(ctx context.Context) {
	if d.interval < 0 {
		return
	}
	tick := d.interval
	if tick == 0 {
		tick = d.timeout / 3
		if tick < time.Second {
			tick = time.Second
		}
	}
	d.init(d.now())
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if d.step(ctx, d.now()) {
				d.probe(wire.EncodePing(d.seq.Add(1)))
			}
		}
	}
}

// init resets the run-loop baseline at the given start time.
func (d *Driver) init(now time.Time) {
	d.lastSeen.Store(now.UnixNano())
	d.lastObserved = now.UnixNano()
	d.candidateSince = time.Time{}
	d.wasActive = false
	d.activeSince = time.Time{}
	d.setHealthy(false)
}

// step advances the loop one tick at time now, performing reconnects and firing health
// transitions, and reports whether the caller should emit a probe. It is the whole tick
// body, extracted so tests can drive it deterministically.
func (d *Driver) step(ctx context.Context, now time.Time) (doProbe bool) {
	seen := d.lastSeen.Load()
	active := d.interval > 0 || now.Sub(time.Unix(0, d.lastSent.Load())) < d.timeout
	if active && !d.wasActive {
		d.activeSince = now // a probing window (re)started this tick
	}
	d.wasActive = active
	// The down edge means "we were probing and heard nothing for `timeout`". Lazy mode (interval
	// ==0) only probes while traffic flows, so during an idle gap lastSeen freezes; silence must
	// be measured from when probing (re)started, not from a lastSeen predating the idle —
	// otherwise the first packet after a long idle would fail the path over before its probe
	// could even round-trip. Fixed cadence never idles, so this floor is a no-op there.
	effectiveSeen := seen
	if d.interval == 0 && d.activeSince.UnixNano() > effectiveSeen {
		effectiveSeen = d.activeSince.UnixNano()
	}
	silent := now.Sub(time.Unix(0, effectiveSeen))
	if active && silent > d.timeout {
		// Down edge: fast + safe. Reconnect, then reset lastSeen so we don't re-fire for
		// another full window; keep lastObserved in sync so the reset is not later
		// misread as a fresh return (false recovery).
		d.setHealthy(false)
		d.candidateSince = time.Time{}
		for _, l := range d.links {
			_ = l.Reconnect(ctx)
		}
		d.lastSeen.Store(now.UnixNano())
		d.lastObserved = d.lastSeen.Load()
		return false
	}
	fresh := seen != d.lastObserved // a genuinely new returning packet since last tick
	d.lastObserved = seen
	if !d.healthy {
		// Up edge: slow + careful. Require continuous liveness across upGrace; any stalled
		// tick restarts the window so a lone stray packet never captures.
		if fresh {
			if d.candidateSince.IsZero() {
				d.candidateSince = now
			}
			if now.Sub(d.candidateSince) >= d.upGrace {
				d.setHealthy(true)
			}
		} else {
			d.candidateSince = time.Time{}
		}
	}
	return d.interval > 0 || d.sentTick.Swap(false)
}

func (d *Driver) setHealthy(h bool) {
	if h != d.healthy {
		d.healthy = h
		if d.onHealth != nil {
			d.onHealth(h)
		}
	}
}
