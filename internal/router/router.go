// Package router forwards packets between a node's connections according to its
// routing table. Because a row matches only on {processed, source}, once that pair is
// fixed there is nothing left to statically match on, so the table compiles into an
// ordered list of targets per (processed, source); routing a packet is walking that list
// and taking the first target that accepts the owner and passes every guard.
//
// A guard is a per-target predicate resolved from the rule's named conditions (e.g. a
// destination-IP set, or a healthcheck liveness bool). Guards let a branch fall through
// to the next target exactly as a rejected owner does, which is how conditional and
// health-gated routing (geo split, in-process failover) is expressed.
package router

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/arash16/dualnet/internal/conn"
	"github.com/arash16/dualnet/internal/wire"
)

// Guard is a per-target predicate. A target is eligible only if every guard passes. dst
// is the inner packet's destination (dstOK=false if it could not be parsed); a guard that
// does not care about the destination (e.g. a healthcheck) ignores them.
type Guard interface {
	Pass(owner wire.Owner, dst netip.Addr, dstOK bool) bool
}

// Rule is one routing-table row. MatchProcessed nil matches either processed state;
// Source "" matches any source connection. Conditions names guards that must all pass.
// Egress, if set, finalizes the packet through that named egress (its reply exits via
// Target); otherwise the packet is forwarded to Target.
type Rule struct {
	MatchProcessed *bool
	Source         string
	Conditions     []string
	Egress         string
	Target         string
}

// FinalizeFunc hands a packet to a named egress's finalizer, remembering the reply target
// (already confirmed to accept the owner). It is invoked for a matched finalize rule.
type FinalizeFunc func(owner wire.Owner, target conn.Sender, payload []byte)

// Recorder receives routing events for stats. A nil Recorder disables recording; all
// methods must be safe for concurrent use.
type Recorder interface {
	Routed(label string)       // a rule matched and the packet was delivered/finalized
	Sent(target string, n int) // n payload bytes were delivered to a sender connection
	Dropped(src string)        // no target accepted the packet
}

type target struct {
	egress   string       // "" = forward via sender; else finalize through this named egress
	finalize FinalizeFunc // resolved finalizer for egress (nil unless egress != ""), bound at compile
	conn     conn.Conn
	sender   conn.Sender // nil if the target connection cannot send (a receiver)
	guards   []Guard     // all must pass for this target to be chosen
	label    string      // stable label identifying the originating rule (for stats)
}

type key struct {
	processed bool
	src       string
}

// Router evaluates a compiled routing table. Route is safe for concurrent use.
type Router struct {
	finalizers map[string]FinalizeFunc
	compiled   map[key][]target
	labels     []string // deduped rule labels (for stats registration)
	rec        Recorder // optional stats sink
	Warnings   []string
}

// SetRecorder attaches a stats sink. Call before starting traffic.
func (r *Router) SetRecorder(rec Recorder) { r.rec = rec }

// Labels returns the deduped set of routing-rule labels this router may report.
func (r *Router) Labels() []string { return r.labels }

// labelFor builds a stable, human-readable label uniquely identifying a rule.
func labelFor(ru Rule) string {
	src := ru.Source
	if src == "" {
		src = "*"
	}
	m := "any"
	if ru.MatchProcessed != nil {
		if *ru.MatchProcessed {
			m = "proc"
		} else {
			m = "unproc"
		}
	}
	label := m + "/" + src
	if len(ru.Conditions) > 0 {
		label += "[" + strings.Join(ru.Conditions, ",") + "]"
	}
	if ru.Egress != "" {
		return label + "→egress:" + ru.Egress + "→" + ru.Target
	}
	return label + "→" + ru.Target
}

// Compile builds a Router from rules, resolving targets against conns, condition names
// against conditions, and finalize egress names against finalizers. sources are the names
// of connections that may originate/receive packets (used to precompute a per-source
// target list with wildcard rows merged in table order).
func Compile(rules []Rule, conns map[string]conn.Conn, sources []string, conditions map[string]Guard, finalizers map[string]FinalizeFunc) (*Router, error) {
	r := &Router{finalizers: finalizers, compiled: make(map[key][]target)}

	// Validate + resolve every rule up front.
	resolved := make([]target, len(rules))
	for i, ru := range rules {
		if ru.Egress != "" {
			if ru.MatchProcessed == nil || *ru.MatchProcessed {
				return nil, fmt.Errorf("router: rule %d cannot process an already-processed packet (finalize rules must match processed:false)", i)
			}
			if finalizers[ru.Egress] == nil {
				return nil, fmt.Errorf("router: rule %d references unknown egress %q", i, ru.Egress)
			}
		}
		c := conns[ru.Target]
		if c == nil {
			return nil, fmt.Errorf("router: rule %d targets unknown connection %q", i, ru.Target)
		}
		if ru.Source != "" && conns[ru.Source] == nil {
			return nil, fmt.Errorf("router: rule %d has unknown source connection %q", i, ru.Source)
		}
		s, _ := c.(conn.Sender)
		if s == nil {
			r.Warnings = append(r.Warnings, fmt.Sprintf("rule %d target %q is a receiver and can never accept a packet (dead rule)", i, ru.Target))
		}
		var guards []Guard
		for _, name := range ru.Conditions {
			g := conditions[name]
			if g == nil {
				return nil, fmt.Errorf("router: rule %d references unknown condition %q", i, name)
			}
			guards = append(guards, g)
		}
		resolved[i] = target{egress: ru.Egress, finalize: finalizers[ru.Egress], conn: c, sender: s, guards: guards, label: labelFor(ru)}
	}

	// Deduped labels for stats registration.
	seenLabel := map[string]bool{}
	for i := range resolved {
		if l := resolved[i].label; !seenLabel[l] {
			seenLabel[l] = true
			r.labels = append(r.labels, l)
		}
	}

	matches := func(ru Rule, processed bool) bool {
		return ru.MatchProcessed == nil || *ru.MatchProcessed == processed
	}

	// Per (processed, known source): walk rules in table order, including a matching row for
	// this source and every wildcard (source: "") row merged in place. Route is only ever
	// called with a source that is one of these connection names, so there is no separate
	// unknown-source fallback — an absent key yields a nil list, which drops.
	for _, processed := range []bool{false, true} {
		for _, src := range sources {
			var list []target
			for i, ru := range rules {
				if matches(ru, processed) && (ru.Source == "" || ru.Source == src) {
					list = append(list, resolved[i])
				}
			}
			r.compiled[key{processed, src}] = list
		}
	}
	return r, nil
}

// Route forwards one packet received on connection src. It looks up the compiled target
// list for (e.Processed, src) and dispatches it. A receive loop that always reports the
// same source should bind once via SourceRouter to skip this per-packet map lookup.
func (r *Router) Route(src string, e wire.Envelope, payload []byte) {
	r.dispatch(src, r.compiled[key{e.Processed, src}], e, payload)
}

// SourceRouter returns an intake bound to a fixed source connection, so a receive loop
// routes without hashing the source name on every packet: the two compiled target lists
// (unprocessed / processed) are captured once here and selected per packet by the flag.
// Returns nil if src is not a known source (its packets would only ever drop).
func (r *Router) SourceRouter(src string) func(e wire.Envelope, payload []byte) {
	unproc := r.compiled[key{false, src}]
	proc := r.compiled[key{true, src}]
	if unproc == nil && proc == nil {
		return nil
	}
	return func(e wire.Envelope, payload []byte) {
		list := unproc
		if e.Processed {
			list = proc
		}
		r.dispatch(src, list, e, payload)
	}
}

// dispatch walks a resolved target list and delivers to the first target that accepts
// e.Owner and passes every guard; a finalize target hands the packet to its egress. The
// inner destination is parsed lazily, only when a guarded target is reached — nodes with
// no guarded rules never inspect the payload. Unmatched packets are dropped.
func (r *Router) dispatch(src string, list []target, e wire.Envelope, payload []byte) {
	var (
		dst       netip.Addr
		dstOK     bool
		dstParsed bool
	)
	for _, t := range list {
		if t.sender == nil || !t.sender.Accepts(e.Owner) {
			continue
		}
		if len(t.guards) > 0 {
			if !dstParsed {
				dst, dstOK = wire.DstIP(payload)
				dstParsed = true
			}
			if !allPass(t.guards, e.Owner, dst, dstOK) {
				continue
			}
		}
		if t.finalize != nil {
			t.finalize(e.Owner, t.sender, payload)
			if r.rec != nil {
				r.rec.Routed(t.label)
			}
			return
		}
		if delivered, _ := t.sender.Send(e, payload); delivered {
			if r.rec != nil {
				r.rec.Routed(t.label)
				r.rec.Sent(t.conn.Name(), len(payload))
			}
			return
		}
	}
	// no target accepted → drop (inner TCP retransmits)
	if r.rec != nil {
		r.rec.Dropped(src)
	}
}

func allPass(guards []Guard, owner wire.Owner, dst netip.Addr, dstOK bool) bool {
	for _, g := range guards {
		if !g.Pass(owner, dst, dstOK) {
			return false
		}
	}
	return true
}
