// Package ipmatch answers "is this IP in the set?" for a set of prefixes loaded from a
// static file. It wraps a longest-prefix-match table (github.com/gaissmai/bart) behind a
// small abstraction and puts a lock-free direct-mapped cache in front, so bursts of
// packets to a single destination (the common case on the routing hot path) skip the
// tree walk entirely.
//
// A Reloadable table can be swapped atomically (e.g. on SIGHUP) without disturbing
// concurrent readers.
package ipmatch

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/gaissmai/bart"
)

// Matcher reports whether an address is contained in the set. Implementations are safe
// for concurrent use.
type Matcher interface {
	Contains(netip.Addr) bool
}

// cacheSize is the number of direct-mapped cache slots: a prime < 1000 so that
// ip%cacheSize spreads consecutive addresses. Small enough to stay cache-resident.
const cacheSize = 509

// cache is a direct-mapped IPv4 lookup cache in front of a miss function. Each slot is a
// single atomic word packing the address and its result, so a concurrent read never sees
// a torn (addr, result) pair: [63:32]=addr32, bit1=valid, bit0=result. IPv6 bypasses the
// cache (it cannot be packed exactly and is rare on this path).
type cache struct {
	miss  func(netip.Addr) bool
	slots [cacheSize]atomic.Uint64
}

func newCache(miss func(netip.Addr) bool) *cache { return &cache{miss: miss} }

// netipAddr mirrors the leading fields of netip.Addr, whose first field is a
// uint128 stored as big-endian {hi, lo} halves (see the netip source). For an
// IPv4 (or v4-in-v6) address the dotted-quad lives in the low 32 bits of lo, so
// we read the cache key straight from the value and skip the As4 round-trip
// (uint128 -> [4]byte -> uint32). TestCacheKeyMatchesAs4 guards this layout.
type netipAddr struct{ hi, lo uint64 }

func (c *cache) contains(ip netip.Addr) bool {
	ip = ip.Unmap() // bart requires native v4, not v4-in-v6
	if !ip.Is4() {
		return c.miss(ip)
	}
	key := uint32((*netipAddr)(unsafe.Pointer(&ip)).lo)
	idx := int(key % cacheSize)
	if w := c.slots[idx].Load(); w&2 != 0 && uint32(w>>32) == key {
		return w&1 != 0
	}
	res := c.miss(ip)
	w := uint64(key)<<32 | 2 // valid
	if res {
		w |= 1
	}
	c.slots[idx].Store(w)
	return res
}

// set is an immutable bart table plus its lookup cache.
type set struct {
	c    *cache
	size int
}

func newSet(tbl *bart.Lite, size int) *set {
	return &set{c: newCache(tbl.Contains), size: size}
}

func (s *set) Contains(ip netip.Addr) bool { return s.c.contains(ip) }

// Size reports how many prefixes were loaded (for empty-set warnings).
func (s *set) Size() int { return s.size }

// LoadReader builds a Matcher from prefixes, one per line: "ip/mask" or a bare address
// (treated as a host route, /32 or /128). Blank lines, lines beginning with '#', and any
// trailing "# comment" are ignored.
func LoadReader(r io.Reader) (*set, error) {
	tbl := &bart.Lite{}
	sc := bufio.NewScanner(r)
	n, line := 0, 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		if s == "" {
			continue
		}
		pfx, err := parsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("ipmatch: line %d: %w", line, err)
		}
		tbl.Insert(pfx)
		n++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return newSet(tbl, n), nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.ContainsRune(s, '/') {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil // clear host bits so bart never sees a set host bit
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// LoadList builds a Matcher from inline prefix tokens (each the same grammar as one file
// line: "ip/mask" or a bare address). Used for a dst_in/src_in condition given as a list
// rather than a file; it has no reload (the tokens are fixed in the config).
func LoadList(entries []string) (*set, error) {
	return LoadReader(strings.NewReader(strings.Join(entries, "\n")))
}

// Load reads a Matcher from a file. A missing or malformed file is an error.
func Load(path string) (*set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := LoadReader(f)
	if err != nil {
		return nil, fmt.Errorf("ipmatch: %s: %w", path, err)
	}
	return s, nil
}

// Reloadable is a Matcher whose underlying table can be atomically replaced. The hot path
// (Contains) is lock-free.
type Reloadable struct {
	path string
	cur  atomic.Pointer[set]
}

// Open loads path into a new Reloadable (strict: a missing/invalid file fails).
func Open(path string) (*Reloadable, error) {
	r := &Reloadable{path: path}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Contains reports set membership against the current table.
func (r *Reloadable) Contains(ip netip.Addr) bool {
	s := r.cur.Load()
	return s != nil && s.Contains(ip)
}

// Reload re-reads the file and atomically swaps in a fresh table (with a fresh cache). On
// error the previous table is kept, so a bad edit never disables a running matcher.
func (r *Reloadable) Reload() error {
	s, err := Load(r.path)
	if err != nil {
		return err
	}
	r.cur.Store(s)
	return nil
}

// Size reports the prefix count in the current table.
func (r *Reloadable) Size() int {
	if s := r.cur.Load(); s != nil {
		return s.Size()
	}
	return 0
}

// Path returns the file this matcher loads from.
func (r *Reloadable) Path() string { return r.path }
