package peers

import (
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/wire"
)

func nilSink([]byte) error { return nil }

// reg builds an unbounded multiple/single registry (0 = no peer cap).
func reg(multiple bool) *Registry { return New(multiple, time.Minute, 0) }

func TestMintIdempotentPerPeerKey(t *testing.T) {
	r := reg(true)
	id1, ok := r.Register(wire.Owner{}, "addrA", 1, nilSink)
	if !ok || id1.IsZero() {
		t.Fatalf("mint returned ok=%v id=%v", ok, id1)
	}
	if got, ok := r.Register(wire.Owner{}, "addrA", 2, nilSink); !ok || got != id1 {
		t.Fatalf("re-register from same peerKey minted a new id: %v vs %v (ok=%v)", got, id1, ok)
	}
	id2, ok := r.Register(wire.Owner{}, "addrB", 1, nilSink)
	if !ok || id2 == id1 {
		t.Fatalf("different peerKey should mint a distinct id: %v vs %v", id2, id1)
	}
}

func TestAdoptClaimedID(t *testing.T) {
	r := reg(true)
	claimed := wire.Owner{7, 7, 7, 7}
	if got, ok := r.Register(claimed, "addrA", 1, nilSink); !ok || got != claimed {
		t.Fatalf("claimed id not adopted: %v ok=%v", got, ok)
	}
	if !r.Accepts(claimed) {
		t.Fatal("adopted id should be accepted")
	}
}

func TestSendSelectsByOwner(t *testing.T) {
	r := reg(true)
	var toA, toB int
	idA, _ := r.Register(wire.Owner{}, "A", 1, func([]byte) error { toA++; return nil })
	idB, _ := r.Register(wire.Owner{}, "B", 1, func([]byte) error { toB++; return nil })
	if ok, _ := r.Send(idA, []byte("x")); !ok || toA != 1 || toB != 0 {
		t.Fatalf("send to A: ok=%v toA=%d toB=%d", ok, toA, toB)
	}
	if ok, _ := r.Send(idB, []byte("x")); !ok || toB != 1 {
		t.Fatalf("send to B: ok=%v toB=%d", ok, toB)
	}
	if ok, _ := r.Send(wire.Owner{9, 9, 9, 9}, []byte("x")); ok {
		t.Fatal("send to unknown owner should not be delivered")
	}
}

func TestSingleAcceptsAnyOwner(t *testing.T) {
	r := reg(false)
	var sent int
	if id, ok := r.Register(wire.Owner{5}, "A", 1, func([]byte) error { sent++; return nil }); !ok || !id.IsZero() {
		t.Fatalf("single register should return zero id, got %v ok=%v", id, ok)
	}
	if !r.Accepts(wire.Owner{1, 2, 3, 4}) {
		t.Fatal("single peer should accept any owner")
	}
	if ok, _ := r.Send(wire.Owner{1, 2, 3, 4}, []byte("x")); !ok || sent != 1 {
		t.Fatalf("single send: ok=%v sent=%d", ok, sent)
	}
}

// TestRejectsStaleReplay proves, at the registry level, that a register/keepalive whose freshness
// stamp is not newer than the last accepted for that peer is rejected, so a replayed (captured)
// datagram cannot re-bind the peer's return path to the replayer's sink.
func TestRejectsStaleReplay(t *testing.T) {
	// multiple mode: adopt id P at ts=10 with sink A, then replay ts<=10 with sink B (attacker).
	r := reg(true)
	P := wire.Owner{1, 1, 1, 1}
	var toA, toB int
	if _, ok := r.Register(P, "victim", 10, func([]byte) error { toA++; return nil }); !ok {
		t.Fatal("initial register should be accepted")
	}
	if _, ok := r.Register(P, "attacker", 10, func([]byte) error { toB++; return nil }); ok {
		t.Fatal("replay with an equal ts must be rejected (would hijack the return path)")
	}
	if _, ok := r.Register(P, "attacker", 9, func([]byte) error { toB++; return nil }); ok {
		t.Fatal("replay with an older ts must be rejected")
	}
	r.Send(P, []byte("reply"))
	if toA != 1 || toB != 0 {
		t.Fatalf("reply went to the wrong sink after replay: toA=%d toB=%d (want 1/0)", toA, toB)
	}
	// A genuinely newer refresh (legit reconnect) is still honored.
	if _, ok := r.Register(P, "victim2", 11, func([]byte) error { toA++; return nil }); !ok {
		t.Fatal("a fresher (newer ts) refresh must be accepted")
	}

	// single mode: same freshness gate.
	rs := reg(false)
	if _, ok := rs.Register(wire.Owner{}, "x", 5, nilSink); !ok {
		t.Fatal("single: first register accepted")
	}
	if _, ok := rs.Register(wire.Owner{}, "x", 5, nilSink); ok {
		t.Fatal("single: replay with equal ts must be rejected")
	}
}

// TestPeerCap proves that a Multiple registry caps concurrently-tracked peers, so a flood of
// distinct claimed ids / spoofed source keys cannot grow the maps without bound. Refreshing an
// existing peer is always allowed.
func TestPeerCap(t *testing.T) {
	const cap = 3
	r := New(true, time.Minute, cap)
	ts := uint64(1)
	accepted := 0
	for i := 1; i <= 100; i++ {
		id := wire.Owner{byte(i), byte(i >> 8), 0, 0}
		if _, ok := r.Register(id, "k", ts, nilSink); ok {
			accepted++
		}
		ts++
	}
	if accepted != cap {
		t.Fatalf("accepted %d new peers, want exactly the cap %d", accepted, cap)
	}
	// A peer already tracked can still refresh (no new map entry).
	first := wire.Owner{1, 0, 0, 0}
	if _, ok := r.Register(first, "k", ts, nilSink); !ok {
		t.Fatal("refreshing an already-tracked peer must be allowed even at the cap")
	}
}

func TestGCDoesNotEvictReassignedPeerKey(t *testing.T) {
	r := reg(true)
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }

	x, _ := r.Register(wire.Owner{}, "A", 1, nilSink) // mint X for transport key "A"
	z := wire.Owner{9, 9, 9, 9}
	if z == x {
		t.Skip("astronomically unlikely mint collision with the fixed test id")
	}
	now = now.Add(time.Second)
	r.Register(z, "A", 2, nilSink) // same key "A" now claims a different id Z; byKey["A"] -> Z, X orphaned

	now = time.Unix(1000, 0).Add(time.Minute + time.Second)
	r.GC()

	if got, ok := r.Register(wire.Owner{}, "A", 3, nilSink); !ok || got != z {
		t.Fatalf("after GC of the orphan, zero-claim on key A minted %v ok=%v, want the live id %v", got, ok, z)
	}
}

func TestGCRemovesIdle(t *testing.T) {
	r := reg(true)
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	id, _ := r.Register(wire.Owner{}, "A", 1, nilSink)
	now = now.Add(2 * time.Minute)
	if n := r.GC(); n != 1 {
		t.Fatalf("GC removed %d, want 1", n)
	}
	if r.Accepts(id) {
		t.Fatal("GC'd peer should no longer be accepted")
	}
}
