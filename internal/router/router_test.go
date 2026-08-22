package router

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/arash16/dualnet/internal/conn"
	"github.com/arash16/dualnet/internal/wire"
)

// recvConn is a Conn that is not a Sender (a receiver / dead routing target).
type recvConn struct{ name string }

func (r recvConn) Name() string                              { return r.name }
func (r recvConn) Kind() conn.Kind                           { return conn.KindListenIn }
func (r recvConn) Start(context.Context, conn.Ingress) error { return nil }
func (r recvConn) Close() error                              { return nil }

// sendConn is a Conn+Sender whose acceptance is controllable.
type sendConn struct {
	name   string
	accept bool
	got    []wire.Envelope
}

func (s *sendConn) Name() string                              { return s.name }
func (s *sendConn) Kind() conn.Kind                           { return conn.KindConnectOut }
func (s *sendConn) Start(context.Context, conn.Ingress) error { return nil }
func (s *sendConn) Close() error                              { return nil }
func (s *sendConn) Accepts(wire.Owner) bool                   { return s.accept }
func (s *sendConn) Send(e wire.Envelope, _ []byte) (bool, error) {
	if !s.accept {
		return false, nil
	}
	s.got = append(s.got, e)
	return true, nil
}

func bp(b bool) *bool { return &b }

// dstGuard passes when the packet's destination is inside member.
type dstGuard struct{ member netip.Prefix }

func (g dstGuard) Pass(_ wire.Owner, dst netip.Addr, ok bool) bool {
	return ok && g.member.Contains(dst)
}

// healthGuard passes while up is set.
type healthGuard struct{ up *atomic.Bool }

func (g healthGuard) Pass(wire.Owner, netip.Addr, bool) bool { return g.up.Load() }

// ipv4 builds a minimal IPv4 packet with the given destination address.
func ipv4(dst string) []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	d := netip.MustParseAddr(dst).As4()
	copy(p[16:20], d[:])
	return p
}

func finMap(fns map[string]func(wire.Owner, conn.Sender, []byte)) map[string]FinalizeFunc {
	m := make(map[string]FinalizeFunc, len(fns))
	for k, v := range fns {
		m[k] = v
	}
	return m
}

func TestCompileRejectsFinalizeOnProcessed(t *testing.T) {
	conns := map[string]conn.Conn{"eg": &sendConn{name: "eg", accept: true}}
	fins := finMap(map[string]func(wire.Owner, conn.Sender, []byte){"eg": func(wire.Owner, conn.Sender, []byte) {}})
	for _, mp := range []*bool{nil, bp(true)} {
		_, err := Compile([]Rule{{MatchProcessed: mp, Egress: "eg", Target: "eg"}}, conns, []string{"eg"}, nil, fins)
		if err == nil {
			t.Fatalf("expected error for finalize rule matching processed=%v", mp)
		}
	}
	if _, err := Compile([]Rule{{MatchProcessed: bp(false), Egress: "eg", Target: "eg"}}, conns, []string{"eg"}, nil, fins); err != nil {
		t.Fatalf("finalize rule with processed:false should compile: %v", err)
	}
}

func TestCompileUnknownRefs(t *testing.T) {
	conns := map[string]conn.Conn{"a": &sendConn{name: "a", accept: true}}
	if _, err := Compile([]Rule{{Target: "missing"}}, conns, []string{"a"}, nil, nil); err == nil {
		t.Fatal("expected unknown-target error")
	}
	if _, err := Compile([]Rule{{Source: "ghost", Target: "a"}}, conns, []string{"a"}, nil, nil); err == nil {
		t.Fatal("expected unknown-source error")
	}
	if _, err := Compile([]Rule{{MatchProcessed: bp(false), Egress: "nope", Target: "a"}}, conns, []string{"a"}, nil, nil); err == nil {
		t.Fatal("expected unknown-egress error")
	}
	if _, err := Compile([]Rule{{Source: "", Conditions: []string{"nope"}, Target: "a"}}, conns, []string{"a"}, nil, nil); err == nil {
		t.Fatal("expected unknown-condition error")
	}
}

func TestRouteFirstAccepting(t *testing.T) {
	a := &sendConn{name: "a", accept: false}
	b := &sendConn{name: "b", accept: true}
	conns := map[string]conn.Conn{"a": a, "b": b, "src": recvConn{"src"}}
	rt, err := Compile([]Rule{
		{MatchProcessed: bp(false), Source: "src", Target: "a"},
		{MatchProcessed: bp(false), Source: "src", Target: "b"},
	}, conns, []string{"src", "a", "b"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.Route("src", wire.Envelope{Owner: wire.Owner{1}}, []byte("x"))
	if len(a.got) != 0 {
		t.Fatal("non-accepting target a should be skipped")
	}
	if len(b.got) != 1 {
		t.Fatalf("accepting target b should receive; got %d", len(b.got))
	}
}

// TestGuardFallThrough exercises the geo-split + in-process-failover shape: a dst-set
// branch, a health-gated branch, and an unconditional local fallback.
func TestGuardFallThrough(t *testing.T) {
	iran := &sendConn{name: "iran", accept: true}
	up := &sendConn{name: "up", accept: true}
	fb := &sendConn{name: "fb", accept: true}
	conns := map[string]conn.Conn{"iran": iran, "up": up, "fb": fb, "src": recvConn{"src"}}
	turkeyUp := &atomic.Bool{}
	conditions := map[string]Guard{
		"is-iran": dstGuard{netip.MustParsePrefix("10.0.0.0/8")},
		"turkey":  healthGuard{turkeyUp},
	}
	rt, err := Compile([]Rule{
		{MatchProcessed: bp(false), Source: "src", Conditions: []string{"is-iran"}, Target: "iran"},
		{MatchProcessed: bp(false), Source: "src", Conditions: []string{"turkey"}, Target: "up"},
		{MatchProcessed: bp(false), Source: "src", Target: "fb"},
	}, conns, []string{"src", "iran", "up", "fb"}, conditions, nil)
	if err != nil {
		t.Fatal(err)
	}
	env := wire.Envelope{Owner: wire.Owner{1}}

	// iran dst → first branch, regardless of turkey health.
	rt.Route("src", env, ipv4("10.9.0.2"))
	if len(iran.got) != 1 || len(up.got) != 0 || len(fb.got) != 0 {
		t.Fatalf("iran packet mis-routed: iran=%d up=%d fb=%d", len(iran.got), len(up.got), len(fb.got))
	}
	// non-iran, turkey down → fallback.
	rt.Route("src", env, ipv4("8.8.8.8"))
	if len(fb.got) != 1 || len(up.got) != 0 {
		t.Fatalf("down: non-iran should fall to fb: up=%d fb=%d", len(up.got), len(fb.got))
	}
	// non-iran, turkey up → gateway branch.
	turkeyUp.Store(true)
	rt.Route("src", env, ipv4("8.8.8.8"))
	if len(up.got) != 1 {
		t.Fatalf("up: non-iran should take turkey branch: up=%d", len(up.got))
	}
	// iran still uses ftth even with turkey up.
	rt.Route("src", env, ipv4("10.1.1.1"))
	if len(iran.got) != 2 {
		t.Fatalf("iran should still use its branch: iran=%d", len(iran.got))
	}
}

func TestRouteToReceiverIsDeadAndDrops(t *testing.T) {
	conns := map[string]conn.Conn{"r": recvConn{"r"}, "src": recvConn{"src"}}
	rt, err := Compile([]Rule{{MatchProcessed: bp(false), Source: "src", Target: "r"}}, conns, []string{"src", "r"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.Warnings) == 0 {
		t.Fatal("expected a dead-rule warning for a receiver target")
	}
	rt.Route("src", wire.Envelope{}, []byte("x")) // must not panic; just drops
}

func TestRouteFinalizeDispatchesByEgress(t *testing.T) {
	eg := &sendConn{name: "eg", accept: true}
	conns := map[string]conn.Conn{"eg": eg, "src": recvConn{"src"}}
	var ftth, other []wire.Owner
	fins := finMap(map[string]func(wire.Owner, conn.Sender, []byte){
		"ftth":  func(o wire.Owner, _ conn.Sender, _ []byte) { ftth = append(ftth, o) },
		"other": func(o wire.Owner, _ conn.Sender, _ []byte) { other = append(other, o) },
	})
	rt, err := Compile([]Rule{{MatchProcessed: bp(false), Source: "src", Egress: "ftth", Target: "eg"}}, conns, []string{"src", "eg"}, nil, fins)
	if err != nil {
		t.Fatal(err)
	}
	rt.Route("src", wire.Envelope{Owner: wire.Owner{9}}, []byte("x"))
	if len(ftth) != 1 || ftth[0] != (wire.Owner{9}) || len(other) != 0 {
		t.Fatalf("finalize dispatched wrong: ftth=%v other=%v", ftth, other)
	}
	// If the reply target cannot accept the owner, the finalize rule must not fire.
	eg.accept = false
	ftth = nil
	rt.Route("src", wire.Envelope{Owner: wire.Owner{9}}, []byte("x"))
	if len(ftth) != 0 {
		t.Fatal("finalize fired even though reply target rejected the owner")
	}
}

// captureRec records router events for assertions.
type captureRec struct {
	routed  []string
	sent    []string
	dropped []string
}

func (c *captureRec) Routed(l string)      { c.routed = append(c.routed, l) }
func (c *captureRec) Sent(t string, _ int) { c.sent = append(c.sent, t) }
func (c *captureRec) Dropped(s string)     { c.dropped = append(c.dropped, s) }

func TestRouteRecorder(t *testing.T) {
	a := &sendConn{name: "a", accept: false}
	b := &sendConn{name: "b", accept: true}
	conns := map[string]conn.Conn{"a": a, "b": b, "src": recvConn{"src"}}
	rt, err := Compile([]Rule{
		{MatchProcessed: bp(false), Source: "src", Target: "a"},
		{MatchProcessed: bp(false), Source: "src", Target: "b"},
	}, conns, []string{"src", "a", "b"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := &captureRec{}
	rt.SetRecorder(rec)

	// a rejects, b accepts → delivered to b, one Routed(label) + one Sent(b).
	rt.Route("src", wire.Envelope{}, []byte("x"))
	if len(rec.sent) != 1 || rec.sent[0] != "b" {
		t.Fatalf("sent = %v", rec.sent)
	}
	if len(rec.routed) != 1 || rec.routed[0] != "unproc/src→b" {
		t.Fatalf("routed = %v", rec.routed)
	}
	if len(rec.dropped) != 0 {
		t.Fatalf("unexpected drops = %v", rec.dropped)
	}

	// No accepting target → Dropped(src).
	b.accept = false
	rt.Route("src", wire.Envelope{}, []byte("x"))
	if len(rec.dropped) != 1 || rec.dropped[0] != "src" {
		t.Fatalf("dropped = %v", rec.dropped)
	}

	labels := map[string]bool{}
	for _, l := range rt.Labels() {
		labels[l] = true
	}
	if !labels["unproc/src→a"] || !labels["unproc/src→b"] {
		t.Fatalf("labels = %v", rt.Labels())
	}
}
