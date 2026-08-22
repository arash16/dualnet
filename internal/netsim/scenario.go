package netsim

import (
	"fmt"
	"strings"
	"time"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/netschema"
)

// A Scenario is an ordered list of steps the engine executes against a running mesh; the
// first failing assertion fails the scenario. Scenarios are DERIVED from the schema, so any
// network gets a test matrix that matches its own paths and conditions — no hand-authoring.
type Scenario struct {
	Name        string
	Description string
	Steps       []Step
}

// StepOp is the kind of a step.
type StepOp string

const (
	OpProbe      StepOp = "probe"       // drive traffic and assert the result
	OpPause      StepOp = "pause"       // freeze a container (simulate a node going down)
	OpUnpause    StepOp = "unpause"     // thaw it
	OpSignal     StepOp = "signal"      // send a signal (e.g. SIGHUP to reload prefixes)
	OpAppendFile StepOp = "append_file" // append to a file inside a container
	OpSleep      StepOp = "sleep"       // let a state change (healthcheck) settle
)

// Step is one action. Only the fields relevant to Op are set.
type Step struct {
	Op      StepOp
	Target  string        // container name (pause/unpause/signal/append_file)
	Signal  string        // signal name (SIGHUP, …)
	File    string        // path (append_file)
	Content string        // content to append (append_file)
	Wait    time.Duration // duration (sleep)
	Probe   *ProbeStep    // OpProbe
}

// ProbeStep drives one flow and asserts its outcome. The engine resolves how to run it from
// the origin node: a capture-tun node is driven through its LAN client over real TCP; a
// locally-fed (debug-tun) node is driven by injecting an inner UDP packet.
type ProbeStep struct {
	Node         string        // origin node
	Inject       bool          // true: inject at the node's debug-tun; false: HTTP from its LAN client
	Src          string        // inject: inner source IP (the node's tun address)
	SrcIP        string        // http: bind the LAN client's socket to this source IP (kernel src_in test)
	Dst          string        // echo destination IP
	ExpectSrc    string        // expected echoed source IP ("" = don't assert which egress)
	ExpectFail   bool          // true: the round-trip must NOT complete (negative test)
	CheckNoDrops bool          // after success, assert every node reports 0 no_route/decode drops
	Hold         time.Duration // after converging, drive continuous traffic this long; egress must not drift
}

// settle windows for a state change to propagate through the mesh (sized for the fast
// healthcheck defaults: timeout 3s, up-grace 1s). Probes also poll-until-deadline, so these
// only make the assertion snappy and unambiguous, they are not load-bearing.
const (
	downSettle = 5 * time.Second
	upSettle   = 4 * time.Second
	// holdWindow is how long the failover down-probe drives sustained fallback traffic while
	// asserting the egress does not drift. It must exceed the healthcheck up-grace (fast sim
	// default 1s) so a false-heal off the fallback's return traffic has time to flip and be caught.
	holdWindow = 3 * time.Second
)

// Scenarios derives the full reversible test matrix for a network. Each path branch becomes
// one scenario:
//   - a branch reachable with all gateways healthy → a routing assertion (which egress fired);
//   - a branch only reachable once an upstream healthcheck fails → a failover+self-heal
//     assertion (pause the gateway, assert the fallback, unpause, assert recovery);
//   - a locally-fed (debug-tun) origin is driven by injection instead of a LAN client.
//
// Plus, for every dst_in condition, a SIGHUP reload assertion. (The PSK-mismatch negative is
// a separate broken-mesh run — see Engine.) A kernel-warp egress is simulated as a real kernel
// WireGuard tunnel to the hub, so its oracle is the generated tunnel address; userspace warp
// egresses are rejected earlier in Plan.
func Scenarios(net *netschema.Network, sp *SimPlan) []Scenario {
	condKind := map[string]string{} // condition name -> "dst_in" | "src_in" | "healthcheck"
	for name, c := range net.Conditions {
		switch {
		case c.DstIn != nil:
			condKind[name] = "dst_in"
		case c.SrcIn != nil:
			condKind[name] = "src_in"
		default:
			condKind[name] = "healthcheck"
		}
	}

	var out []Scenario
	for _, p := range net.Paths {
		origin := p.OriginNode()
		// A kernel node forwards in the kernel: one probe per branch (src_in from a bound source
		// IP, dst_in to the geo dst, default to the world dst), plus a SIGHUP reload per geo set.
		if net.Nodes[origin].Datapath == "kernel" {
			out = append(out, kernelScenarios(net, sp, p, condKind)...)
			continue
		}
		for i, br := range p.Routes {
			// Gateways of earlier healthcheck-guarded branches must be down to reach branch i.
			var pauseGWs []string
			for j := 0; j < i; j++ {
				prev := p.Routes[j]
				if prev.Gateway != "" && hasHealthcheck(prev.When, condKind) {
					pauseGWs = append(pauseGWs, prev.Gateway)
				}
			}
			dst := sp.WorldDst
			if usesDstInWhen(br.When, condKind) {
				dst = sp.IranDst
			}
			expect := branchEgressIP(sp, origin, br)

			if len(pauseGWs) == 0 {
				out = append(out, routingScenario(net, sp, p, br, origin, dst, expect))
				continue
			}
			// Failover + self-heal: what we recover to is the branch WorldDst takes healthy.
			restore := p.Routes[firstHealthyBranch(p, condKind, dst)]
			out = append(out, failoverScenario(net, sp, p, br, origin, dst, expect, pauseGWs, branchEgressIP(sp, origin, restore)))
		}
	}

	// SIGHUP prefix reload: appending the world dst to the prefix file must flip it from the
	// non-dst_in branch to the dst_in (geo-direct) branch. One reload scenario per path. Kernel
	// paths handle their own reload inside kernelScenarios.
	for _, p := range net.Paths {
		if net.Nodes[p.OriginNode()].Datapath == "kernel" {
			continue
		}
		for _, br := range p.Routes {
			if !usesDstInWhen(br.When, condKind) {
				continue
			}
			if sc, ok := sighupScenario(net, sp, p, br, condKind); ok {
				out = append(out, sc)
			}
			break
		}
	}
	return out
}

// kernelScenarios derives the routing matrix for a kernel-datapath path: one probe per branch
// asserting the observed egress source IP (the oracle) — a src_in branch is driven from a LAN
// client bound to the leg source IP, a dst_in branch is driven to the geo dst, the default to
// the world dst — plus a SIGHUP reload for the first file-based dst_in geo set.
func kernelScenarios(net *netschema.Network, sp *SimPlan, p netschema.Path, condKind map[string]string) []Scenario {
	origin := p.OriginNode()
	var out []Scenario
	var geo *netschema.Branch
	for i := range p.Routes {
		br := p.Routes[i]
		expect := sp.egressIP[origin][br.Egress]
		probe := &ProbeStep{Node: origin, ExpectSrc: expect, CheckNoDrops: true}
		var label string
		switch {
		case len(br.When) == 0:
			probe.Dst = sp.WorldDst
			label = "default"
		case condKind[br.When[0]] == "src_in":
			leg := firstListIP(net.Conditions[br.When[0]].SrcIn)
			if leg == "" {
				continue // file-based src_in: cannot derive the source IP without I/O
			}
			probe.Dst, probe.SrcIP = sp.WorldDst, leg
			label = "src-" + br.When[0]
		case condKind[br.When[0]] == "dst_in":
			probe.Dst = sp.IranDst
			label = "dst-" + br.When[0]
			if geo == nil {
				geo = &p.Routes[i]
			}
		default:
			continue
		}
		via := ""
		if net.Nodes[origin].Egresses[br.Egress].Mode == "warp" {
			via = " via warp tunnel"
		}
		out = append(out, Scenario{
			Name:        fmt.Sprintf("route/%s/%s", p.Label(), label),
			Description: fmt.Sprintf("kernel path %q: %s → egress %q%s (src %s)", p.Label(), describeWhen(br), br.Egress, via, expect),
			Steps:       []Step{{Op: OpProbe, Probe: probe}},
		})
	}
	if geo != nil {
		if sc, ok := kernelSighupScenario(net, sp, p, *geo, condKind); ok {
			out = append(out, sc)
		}
	}
	return out
}

// kernelSighupScenario appends WorldDst to a kernel node's geo prefix file and SIGHUPs it,
// asserting WorldDst flips from the default egress to the geo branch's egress.
func kernelSighupScenario(net *netschema.Network, sp *SimPlan, p netschema.Path, geo netschema.Branch, condKind map[string]string) (Scenario, bool) {
	origin := p.OriginNode()
	prefixFile := sp.conditionFile[origin][geo.When[0]]
	defBr, ok := defaultBranch(p)
	if !ok || prefixFile == "" {
		return Scenario{}, false
	}
	before := sp.egressIP[origin][defBr.Egress]
	after := sp.egressIP[origin][geo.Egress]
	if before == "" || after == "" || before == after {
		return Scenario{}, false
	}
	ctr := sp.nodeContainer[origin]
	return Scenario{
		Name:        fmt.Sprintf("sighup/%s", p.Label()),
		Description: fmt.Sprintf("append %s to %s + SIGHUP flips WorldDst from src %s to geo egress %q (src %s)", sp.WorldDst, prefixFile, before, geo.Egress, after),
		Steps: []Step{
			{Op: OpProbe, Probe: &ProbeStep{Node: origin, Dst: sp.WorldDst, ExpectSrc: before}},
			{Op: OpAppendFile, Target: ctr, File: prefixFile, Content: sp.WorldDst + "/32"},
			{Op: OpSignal, Target: ctr, Signal: "SIGHUP"},
			{Op: OpSleep, Wait: 2 * time.Second},
			{Op: OpProbe, Probe: &ProbeStep{Node: origin, Dst: sp.WorldDst, ExpectSrc: after}},
		},
	}, true
}

// defaultBranch returns a path's default (no-`when`) branch.
func defaultBranch(p netschema.Path) (netschema.Branch, bool) {
	for _, br := range p.Routes {
		if len(br.When) == 0 {
			return br, true
		}
	}
	return netschema.Branch{}, false
}

// firstListIP returns the address of an IPSet's first inline list entry ("" for a file-based
// set or an empty/invalid list).
func firstListIP(s *config.IPSet) string {
	if s == nil || len(s.List) == 0 {
		return ""
	}
	tok := s.List[0]
	if i := strings.IndexByte(tok, '/'); i >= 0 {
		tok = tok[:i]
	}
	return tok
}

func hasHealthcheck(when []string, kind map[string]string) bool {
	for _, c := range when {
		if kind[c] == "healthcheck" {
			return true
		}
	}
	return false
}

// firstHealthyBranch returns the index of the branch that wins for dst when all gateways are
// healthy: the first branch whose dst_in requirement matches dst (healthcheck guards hold).
func firstHealthyBranch(p netschema.Path, kind map[string]string, dst string) int {
	for i, br := range p.Routes {
		if usesDstInWhen(br.When, kind) == (dst == iranDst) {
			return i
		}
	}
	return len(p.Routes) - 1
}

// branchEgressIP is the source IP the hub observes for a branch: its egress on the tun node
// (local branch) or on its gateway.
func branchEgressIP(sp *SimPlan, origin string, br netschema.Branch) string {
	node := origin
	if br.Gateway != "" {
		node = br.Gateway
	}
	return sp.egressIP[node][br.Egress]
}

func routingScenario(net *netschema.Network, sp *SimPlan, p netschema.Path, br netschema.Branch, origin, dst, expect string) Scenario {
	return Scenario{
		Name:        fmt.Sprintf("route/%s/%s", p.Label(), branchLabel(br)),
		Description: fmt.Sprintf("path %q: %s → egress %q (src %s)", p.Label(), describeWhen(br), br.Egress, expect),
		Steps:       []Step{{Op: OpProbe, Probe: probeFor(net, sp, origin, dst, expect, false, true)}},
	}
}

func failoverScenario(net *netschema.Network, sp *SimPlan, p netschema.Path, br netschema.Branch, origin, dst, expect string, pauseGWs []string, restoreExpect string) Scenario {
	sc := Scenario{
		Name:        fmt.Sprintf("failover/%s/%s", p.Label(), branchLabel(br)),
		Description: fmt.Sprintf("path %q: pause %v → fallback egress %q (src %s), then self-heal (src %s)", p.Label(), pauseGWs, br.Egress, expect, restoreExpect),
	}
	for _, gw := range pauseGWs {
		sc.Steps = append(sc.Steps, Step{Op: OpPause, Target: gw})
	}
	// The down-probe HOLDS: after converging to the fallback egress it drives continuous
	// traffic for holdWindow (> the healthcheck up-grace) and asserts the egress never drifts.
	// A healthcheck that (wrongly) counts ANY return as liveness would false-heal off this
	// fallback traffic and route back into the paused gateway — the hold catches that drift.
	downProbe := probeFor(net, sp, origin, dst, expect, false, false)
	downProbe.Hold = holdWindow
	sc.Steps = append(sc.Steps,
		Step{Op: OpSleep, Wait: downSettle},
		Step{Op: OpProbe, Probe: downProbe},
	)
	for _, gw := range pauseGWs {
		sc.Steps = append(sc.Steps, Step{Op: OpUnpause, Target: gw})
	}
	sc.Steps = append(sc.Steps,
		Step{Op: OpSleep, Wait: upSettle},
		Step{Op: OpProbe, Probe: probeFor(net, sp, origin, dst, restoreExpect, false, false)},
	)
	return sc
}

func sighupScenario(net *netschema.Network, sp *SimPlan, p netschema.Path, geo netschema.Branch, kind map[string]string) (Scenario, bool) {
	origin := p.OriginNode()
	var prefixFile string
	for _, c := range geo.When {
		if kind[c] == "dst_in" {
			// The RUNTIME path inside the origin's container (compile rewrites a schema dst_in
			// file to its deploy files_dir), which is what dualnet actually reads — not
			// net.Conditions[c].DstIn.File, the raw schema path the container doesn't have.
			prefixFile = sp.conditionFile[origin][c]
		}
	}
	// The branch WorldDst takes today (its expected egress before the reload flips it to geo).
	before := branchEgressIP(sp, origin, p.Routes[firstHealthyBranch(p, kind, sp.WorldDst)])
	if prefixFile == "" || before == "" {
		return Scenario{}, false
	}
	after := branchEgressIP(sp, origin, geo)
	ctr := sp.nodeContainer[origin]
	return Scenario{
		Name:        fmt.Sprintf("sighup/%s", p.Label()),
		Description: fmt.Sprintf("append %s to %s + SIGHUP flips WorldDst from src %s to geo egress %q (src %s)", sp.WorldDst, prefixFile, before, geo.Egress, after),
		Steps: []Step{
			{Op: OpProbe, Probe: probeFor(net, sp, origin, sp.WorldDst, before, false, false)},
			{Op: OpAppendFile, Target: ctr, File: prefixFile, Content: sp.WorldDst + "/32"},
			{Op: OpSignal, Target: ctr, Signal: "SIGHUP"},
			{Op: OpSleep, Wait: 2 * time.Second},
			{Op: OpProbe, Probe: probeFor(net, sp, origin, sp.WorldDst, after, false, false)},
		},
	}, true
}

func usesDstInWhen(when []string, kind map[string]string) bool {
	for _, c := range when {
		if kind[c] == "dst_in" {
			return true
		}
	}
	return false
}

// probeFor builds a ProbeStep, choosing injection (debug-tun origin) vs a LAN-client HTTP
// probe automatically from the plan.
func probeFor(net *netschema.Network, sp *SimPlan, origin, dst, expect string, expectFail, checkDrops bool) *ProbeStep {
	ps := &ProbeStep{Node: origin, Dst: dst, ExpectSrc: expect, ExpectFail: expectFail, CheckNoDrops: checkDrops}
	if sp.debugTun[origin] {
		ps.Inject = true
		if _, c, ok := anyTun(net.Nodes[origin]); ok {
			ps.Src = c.IP
		}
	}
	return ps
}

func branchLabel(br netschema.Branch) string {
	if br.Gateway != "" {
		return "gw-" + br.Gateway + "-" + br.Egress
	}
	return "egress-" + br.Egress
}

func describeWhen(br netschema.Branch) string {
	if len(br.When) == 0 {
		return "default"
	}
	s := "when"
	for _, c := range br.When {
		s += " " + c
	}
	return s
}
