package ipmatch

import (
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"
)

// TestCacheKeyMatchesAs4 guards the unsafe layout assumption in cache.contains:
// the low 32 bits of netip.Addr's internal uint128 must equal the big-endian
// As4 form. If netip ever changes its layout, this fails instead of silently
// corrupting the lookup cache.
func TestCacheKeyMatchesAs4(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "1.2.3.4", "203.0.113.7", "255.255.255.255"} {
		a := mustAddr(t, s).Unmap()
		b := a.As4()
		want := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		got := uint32((*netipAddr)(unsafe.Pointer(&a)).lo)
		if got != want {
			t.Fatalf("%s: key = %#08x, want %#08x (netip.Addr layout changed?)", s, got, want)
		}
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func TestLoadReaderContains(t *testing.T) {
	const data = `
# Iran-ish sample
10.0.0.0/8
192.168.1.0/24
2001:db8::/32
203.0.113.7        # a bare-ish host with trailing comment
`
	s, err := LoadReader(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if s.Size() != 4 {
		t.Fatalf("size = %d, want 4", s.Size())
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"11.0.0.1", false},
		{"192.168.1.55", true},
		{"192.168.2.1", false},
		{"203.0.113.7", true},
		{"203.0.113.8", false},
		{"2001:db8::1", true},
		{"2001:dead::1", false},
	}
	for _, c := range cases {
		if got := s.Contains(mustAddr(t, c.ip)); got != c.want {
			t.Errorf("Contains(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := LoadReader(strings.NewReader("not-an-ip")); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err := LoadReader(strings.NewReader("10.0.0.0/999")); err == nil {
		t.Fatal("expected bad-prefix error")
	}
}

func TestEmptySet(t *testing.T) {
	s, err := LoadReader(strings.NewReader("# only comments\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Size() != 0 {
		t.Fatalf("size = %d, want 0", s.Size())
	}
	if s.Contains(mustAddr(t, "10.0.0.1")) {
		t.Fatal("empty set should contain nothing")
	}
}

// TestCacheSkipsMiss verifies a repeated v4 lookup is served from the cache without a
// second call to the backing miss function.
func TestCacheSkipsMiss(t *testing.T) {
	var calls atomic.Int64
	member := netip.MustParsePrefix("10.0.0.0/8")
	c := newCache(func(ip netip.Addr) bool {
		calls.Add(1)
		return member.Contains(ip)
	})
	ip := mustAddr(t, "10.9.0.2")
	if !c.contains(ip) || !c.contains(ip) || !c.contains(ip) {
		t.Fatal("expected membership")
	}
	if calls.Load() != 1 {
		t.Fatalf("miss called %d times, want 1 (cache should serve repeats)", calls.Load())
	}
	// A different address (a different slot) still resolves correctly.
	out := mustAddr(t, "11.9.0.2")
	if c.contains(out) {
		t.Fatal("11.9.0.2 should not be a member")
	}
}

// slot32 mirrors cache.contains's key derivation (the big-endian As4 as a uint32).
func slot32(ip netip.Addr) uint32 {
	q := ip.As4()
	return uint32(q[0])<<24 | uint32(q[1])<<16 | uint32(q[2])<<8 | uint32(q[3])
}

// TestCacheSameSlotCollision covers that the direct-mapped cache's correctness against a slot
// COLLISION (two addresses hashing to the same slot) hinges on the tag check
// `uint32(w>>32) == key` at ipmatch.go:59. The existing TestCacheSkipsMiss never exercises
// this — its two addresses (10.9.0.2, 11.9.0.2) land in different slots — so a broken/dropped
// tag check would pass the whole suite while returning a stale neighbour's membership. Here A
// (a member) and B (a non-member) differ by exactly cacheSize in the 32-bit key, so they share
// a slot: after A populates it, B must still be a miss (the tag rejects the stale entry).
func TestCacheSameSlotCollision(t *testing.T) {
	var calls atomic.Int64
	member := netip.MustParsePrefix("10.9.0.0/24")
	c := newCache(func(ip netip.Addr) bool { calls.Add(1); return member.Contains(ip) })

	a := mustAddr(t, "10.9.0.2")   // member of 10.9.0.0/24
	b := mustAddr(t, "10.9.1.255") // NOT a member; key = a's key + cacheSize → same slot
	if slot32(a)%cacheSize != slot32(b)%cacheSize {
		t.Fatalf("setup: %s and %s not in the same cache slot (%d vs %d)", a, b, slot32(a)%cacheSize, slot32(b)%cacheSize)
	}

	if !c.contains(a) {
		t.Fatal("10.9.0.2 should be a member")
	}
	calls.Store(0) // ignore the populate call; count only the collision lookup
	if c.contains(b) {
		t.Fatal("10.9.1.255 must NOT be a member — the tag check failed and returned the neighbour's cached true")
	}
	if calls.Load() != 1 {
		t.Fatalf("a colliding non-member must consult the backing fn (tag mismatch), calls=%d want 1", calls.Load())
	}
}

// TestCacheV6Bypass confirms IPv6 always consults the backing function (no packing).
func TestCacheV6Bypass(t *testing.T) {
	var calls atomic.Int64
	c := newCache(func(netip.Addr) bool { calls.Add(1); return true })
	ip := mustAddr(t, "2001:db8::1")
	c.contains(ip)
	c.contains(ip)
	if calls.Load() != 2 {
		t.Fatalf("v6 miss called %d times, want 2 (no cache)", calls.Load())
	}
}
