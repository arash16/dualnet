package finalizer

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/wire"
)

// spoofSrc returns a distinct inner source IP for each i (an attacker varying the source).
func spoofSrc(i int) string { return fmt.Sprintf("100.64.%d.%d", i/256, i%256) }

// TestGCExpiresIdleFlow pins that a return mapping idle beyond the ttl is removed by GC, and a
// still-young one is kept. GC drives production flow-expiry (node.gcLoop) yet had no coverage.
func TestGCExpiresIdleFlow(t *testing.T) {
	f := newTestFin(&fakeEgress{}, time.Minute, 0)
	var nowNs atomic.Int64
	nowNs.Store(time.Unix(1000, 0).UnixNano())
	f.now = func() time.Time { return time.Unix(0, nowNs.Load()) }
	f.refreshClock() // publish the test clock (production does this on a ticker in Run)

	f.Submit(wire.Owner{1}, &fakeSender{got: make(chan capture, 1)}, ipv4("10.9.0.2", "1.2.3.4", 6))

	nowNs.Store(time.Unix(1030, 0).UnixNano()) // 30s < ttl
	if n := f.GC(); n != 0 {
		t.Fatalf("premature GC of a young flow: removed %d", n)
	}
	nowNs.Store(time.Unix(1061, 0).UnixNano()) // 61s > ttl
	if n := f.GC(); n != 1 {
		t.Fatalf("idle flow past ttl should be GC'd: removed %d, want 1", n)
	}
}

// TestReplyRefreshesFlowLifetime pins the complementary property: each internet reply refreshes the
// mapping's lastSeen (Run lines 95-97), so an actively-replying long-lived flow is never GC'd
// mid-conversation. A regression that dropped the refresh would silently expire live flows.
func TestReplyRefreshesFlowLifetime(t *testing.T) {
	eg := &fakeEgress{replies: make(chan []byte)}
	f := newTestFin(eg, time.Minute, 0)
	var nowNs atomic.Int64
	nowNs.Store(time.Unix(1000, 0).UnixNano())
	f.now = func() time.Time { return time.Unix(0, nowNs.Load()) }
	f.refreshClock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)

	snd := &fakeSender{got: make(chan capture, 1)}
	owner := wire.Owner{1, 2, 3, 4}
	f.Submit(owner, snd, ipv4("10.9.0.2", "1.2.3.4", 6))

	// 50s in, a reply arrives — it must refresh lastSeen to t=1050.
	nowNs.Store(time.Unix(1050, 0).UnixNano())
	f.refreshClock() // publish before the reply so Run stamps lastSeen=1050 deterministically
	eg.replies <- ipv4("1.2.3.4", "10.9.0.2", 6)
	<-snd.got // synchronizes: the refresh has happened by the time the reply is delivered

	// 40s after the refresh (t=1090, < ttl from 1050) → still alive.
	nowNs.Store(time.Unix(1090, 0).UnixNano())
	if n := f.GC(); n != 0 {
		t.Fatalf("reply should have extended the flow's lifetime; GC removed %d", n)
	}
	// 61s after the refresh (t=1111) → now expired.
	nowNs.Store(time.Unix(1111, 0).UnixNano())
	if n := f.GC(); n != 1 {
		t.Fatalf("flow idle past ttl after its last reply should be GC'd: removed %d, want 1", n)
	}
}

// TestReplyForUnknownOwnerIsDropped pins that a reply whose inner-dst IP has no live mapping
// (expired / never submitted) is silently dropped — Run continues, target.Send is not called.
func TestReplyForUnknownOwnerIsDropped(t *testing.T) {
	eg := &fakeEgress{replies: make(chan []byte, 1)}
	f := newTestFin(eg, time.Minute, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)

	// No Submit, so track is empty; a reply for 10.9.0.2 has no owner mapping.
	eg.replies <- ipv4("1.2.3.4", "10.9.0.2", 6)
	// Give Run a moment; then a subsequent, mapped reply proves Run kept running past the drop.
	snd := &fakeSender{got: make(chan capture, 1)}
	f.Submit(wire.Owner{7}, snd, ipv4("10.9.0.9", "8.8.8.8", 6))
	eg.replies <- ipv4("8.8.8.8", "10.9.0.9", 6)
	select {
	case c := <-snd.got:
		if c.e.Owner != (wire.Owner{7}) {
			t.Fatalf("mapped reply owner = %v, want {7}", c.e.Owner)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run stopped after dropping an unmapped reply (should continue)")
	}
}

// TestTrackMapIsBounded proves that with cipher=none an attacker varies the inner source IP per
// packet, so the finalizer's return-tracking map must be capped. Beyond the cap a new flow is
// still egressed but its return mapping is not recorded (bounded memory), while an already-tracked
// flow keeps refreshing.
func TestTrackMapIsBounded(t *testing.T) {
	eg := &fakeEgress{}
	const cap = 4
	f := newTestFin(eg, time.Minute, cap)
	snd := &fakeSender{got: make(chan capture, 1)}

	// A "legit" flow tracked first.
	f.Submit(wire.Owner{1}, snd, ipv4("10.9.0.2", "1.1.1.1", 6))

	// Flood distinct spoofed inner sources far past the cap.
	for i := 0; i < 1000; i++ {
		f.Submit(wire.Owner{2}, snd, ipv4(spoofSrc(i), "2.2.2.2", 6))
	}
	f.mu.Lock()
	n := len(f.track)
	f.mu.Unlock()
	if n > cap {
		t.Fatalf("track map grew to %d, must stay within the cap %d", n, cap)
	}
	// Every packet was still egressed (the attack does not drop the forward path).
	_ = f.w.Flush() // drain the inject batch's tail so the fake records every packet
	if len(eg.written) != 1001 {
		t.Fatalf("egressed %d packets, want all 1001", len(eg.written))
	}
	// The originally-tracked flow's reply still routes (refresh of an existing key is never
	// refused), even though the map is full of attacker entries.
	f.Submit(wire.Owner{1}, snd, ipv4("10.9.0.2", "1.1.1.1", 6)) // refresh
	f.mu.Lock()
	_, ok := f.track[netip.MustParseAddr("10.9.0.2")]
	f.mu.Unlock()
	if !ok {
		t.Fatal("an established flow was evicted by the spoofed-source flood")
	}
}

// TestSubmitCollisionOnSharedInnerIP pins that the return table is keyed only by inner source
// IP, so if two owners submit flows from the SAME inner IP (a duplicated tun address — the
// mesh-wide uniqueness invariant the docs require, enforced nowhere here), the second submit
// overwrites the first and the first owner's reply is silently misrouted to the second. This
// test documents that reliance explicitly so a regression (or a future dedup fix) is visible.
func TestSubmitCollisionOnSharedInnerIP(t *testing.T) {
	eg := &fakeEgress{replies: make(chan []byte, 1)}
	f := newTestFin(eg, time.Minute, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)

	sndA := &fakeSender{got: make(chan capture, 1)}
	sndB := &fakeSender{got: make(chan capture, 1)}
	ownerA, ownerB := wire.Owner{0xA}, wire.Owner{0xB}
	f.Submit(ownerA, sndA, ipv4("10.9.0.2", "1.1.1.1", 6))
	f.Submit(ownerB, sndB, ipv4("10.9.0.2", "2.2.2.2", 6)) // same inner src IP overwrites A

	eg.replies <- ipv4("9.9.9.9", "10.9.0.2", 6) // a reply destined to the shared inner IP
	select {
	case <-sndA.got:
		t.Fatal("reply reached owner A's target; expected the shared-IP collision to route it to the last submitter B")
	case c := <-sndB.got:
		if c.e.Owner != ownerB {
			t.Fatalf("collision reply owner = %v, want B (last submitter) %v", c.e.Owner, ownerB)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no reply delivered")
	}
}
