package healthcheck

import (
	"context"
	"testing"
	"time"
)

type fakeLink struct{ n int }

func (f *fakeLink) Reconnect(context.Context) error { f.n++; return nil }

// driver builds a fixed-cadence driver with a recording onHealth for step-driven tests.
func driver(interval, timeout, upGrace time.Duration) (*Driver, *fakeLink, *[]bool) {
	link := &fakeLink{}
	var edges []bool
	d := New(interval, timeout, upGrace, func([]byte) {}, []Reconnecter{link}, func(h bool) {
		edges = append(edges, h)
	})
	return d, link, &edges
}

func TestStartsUnhealthyAndUpAfterGrace(t *testing.T) {
	d, _, edges := driver(5*time.Second, 20*time.Second, 15*time.Second)
	t0 := time.Unix(1_000_000, 0)
	d.init(t0)
	if d.Healthy() {
		t.Fatal("must start unhealthy")
	}
	// Simulate a fresh reflection before each 5s tick. The grace window opens at the first
	// fresh tick (t0+5) and closes 15s later (t0+20), so only then does health flip up.
	for tickT := 5; tickT <= 15; tickT += 5 {
		d.lastSeen.Store(t0.Add(time.Duration(tickT-4) * time.Second).UnixNano())
		d.step(context.Background(), t0.Add(time.Duration(tickT)*time.Second))
		if d.Healthy() {
			t.Fatalf("premature up at t0+%ds; edges=%v", tickT, *edges)
		}
	}
	d.lastSeen.Store(t0.Add(17 * time.Second).UnixNano())
	d.step(context.Background(), t0.Add(20*time.Second)) // 15s after candidate → up
	if !d.Healthy() {
		t.Fatalf("should be healthy after upGrace; edges=%v", *edges)
	}
	if len(*edges) != 1 || (*edges)[0] != true {
		t.Fatalf("expected a single up edge, got %v", *edges)
	}
}

func TestDownOnSilence(t *testing.T) {
	d, link, edges := driver(5*time.Second, 20*time.Second, 1*time.Second)
	t0 := time.Unix(2_000_000, 0)
	d.init(t0)
	// Become healthy first: two fresh ticks past the 1s grace.
	d.lastSeen.Store(t0.Add(1 * time.Second).UnixNano())
	d.step(context.Background(), t0.Add(5*time.Second))
	d.lastSeen.Store(t0.Add(6 * time.Second).UnixNano())
	d.step(context.Background(), t0.Add(10*time.Second))
	if !d.Healthy() {
		t.Fatalf("precondition: expected healthy; edges=%v", *edges)
	}
	// Now go silent past the timeout (lastSeen stuck at t0+6s).
	d.step(context.Background(), t0.Add(40*time.Second))
	if d.Healthy() {
		t.Fatal("should be unhealthy after silence")
	}
	if link.n != 1 {
		t.Fatalf("expected one reconnect, got %d", link.n)
	}
	// The post-down lastSeen reset must not be misread as recovery on the next tick.
	d.step(context.Background(), t0.Add(45*time.Second))
	if d.Healthy() {
		t.Fatal("reconnect reset should not read as instant recovery")
	}
}

func TestGraceRestartsOnStall(t *testing.T) {
	d, _, _ := driver(5*time.Second, 60*time.Second, 15*time.Second)
	t0 := time.Unix(3_000_000, 0)
	d.init(t0)
	// One fresh tick starts the grace window.
	d.lastSeen.Store(t0.Add(1 * time.Second).UnixNano())
	d.step(context.Background(), t0.Add(5*time.Second))
	// Then a stalled tick (no new return) must reset the window.
	d.step(context.Background(), t0.Add(10*time.Second))
	// A single later fresh tick 15s after the FIRST candidate would wrongly be "up" if the
	// window had not reset; it must not be, because the window restarted.
	d.lastSeen.Store(t0.Add(12 * time.Second).UnixNano())
	d.step(context.Background(), t0.Add(20*time.Second))
	if d.Healthy() {
		t.Fatal("a stalled tick should restart the grace window (no premature up)")
	}
}

// TestLazyModeNoSpuriousFlapOnResume proves that in lazy mode (interval==0) a probe is only
// emitted while traffic flows, so during an idle gap lastSeen freezes. When traffic resumes
// after an idle gap longer than the timeout, the first tick must NOT read the stale lastSeen as
// instant death — the resumed probe has not had a chance to round-trip yet. Before the fix it
// spuriously flipped unhealthy and reconnected every link on the first packet after waking.
func TestLazyModeNoSpuriousFlapOnResume(t *testing.T) {
	d, link, edges := driver(0, 20*time.Second, 5*time.Second) // interval 0 = lazy
	t0 := time.Unix(5_000_000, 0)
	d.init(t0)
	at := func(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

	// Become healthy under traffic: mark data sent, deliver fresh reflected pings across grace.
	d.lastSent.Store(at(0).UnixNano())
	d.lastSeen.Store(at(1).UnixNano())
	d.step(context.Background(), at(2)) // candidate window opens
	d.lastSent.Store(at(2).UnixNano())
	d.lastSeen.Store(at(6).UnixNano())
	d.step(context.Background(), at(7)) // >= 5s of continuous liveness → healthy
	if !d.Healthy() {
		t.Fatalf("precondition: expected healthy; edges=%v", *edges)
	}

	// Idle far past the timeout with no SentData: lazy mode probes nothing, so lastSeen stays
	// frozen at t=6 and the path must remain healthy (we never actually probed-and-failed).
	d.step(context.Background(), at(60))
	if !d.Healthy() {
		t.Fatal("lazy idle should not flip unhealthy — nothing was probed")
	}
	reconnectsBefore := link.n

	// Traffic resumes at t=80 (74s of stale lastSeen). The first tick must start a fresh probe
	// window, not fail the path over on a lastSeen from before the idle gap.
	d.lastSent.Store(at(80).UnixNano())
	d.sentTick.Store(true)
	d.step(context.Background(), at(80))
	if !d.Healthy() {
		t.Fatalf("resume after idle spuriously flipped unhealthy; edges=%v", *edges)
	}
	if link.n != reconnectsBefore {
		t.Fatalf("resume after idle spuriously reconnected links: %d -> %d", reconnectsBefore, link.n)
	}
}

func TestDisabledInterval(t *testing.T) {
	d := New(-1, 20*time.Second, 5*time.Second, func([]byte) {}, nil, func(bool) {})
	// Run must return immediately for a disabled interval.
	done := make(chan struct{})
	go func() { d.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run should return immediately when interval < 0")
	}
}
