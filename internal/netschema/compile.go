package netschema

import (
	"fmt"
	"sort"
	"strings"

	"github.com/arash16/dualnet/internal/config"
)

// Compile expands the network schema into one config.Node per node. It builds each node's
// connections from the links it participates in, its named egresses, the routing table
// derived from the paths' branches, and the conditions/sets those branches reference, then
// validates the result.
func (n *Network) Compile() (map[string]*config.Node, error) {
	out := make(map[string]*config.Node, len(n.Nodes))
	for name, nd := range n.Nodes {
		psk := nd.PSK
		if psk == "" {
			psk = n.PSK
		}
		egresses := map[string]config.Egress{}
		for en, eg := range nd.Egresses {
			eg.ExtIface = nd.resolveIface(eg.ExtIface)
			egresses[en] = eg
		}
		cn := &config.Node{
			PSK: psk, MTU: n.MTU, Subnet: n.Subnet,
			Healthcheck: n.Healthcheck, HealthcheckTimeout: n.HealthcheckTimeout, HealthcheckUpGrace: n.HealthcheckUpGrace,
			StatsFile: n.StatsFile, StatsInterval: n.StatsInterval, StatsMaxMB: n.StatsMaxMB,
		}
		if len(egresses) > 0 {
			cn.Egresses = egresses
		}
		if nd.Datapath == "kernel" {
			cn.Datapath = "kernel"
			cn.LANIfaces = nd.kernelLANIfaces()
		} else {
			// Each tun connection becomes a real config connection the node opens; its map key is
			// the routing name. Emit in sorted order for a deterministic config.
			for _, tn := range sortedKeys(nd.Connections) {
				c := nd.Connections[tn]
				if !c.isTun() {
					continue
				}
				cn.Connections = append(cn.Connections, config.Connection{
					Name: tn, Type: "tun", Interface: c.Iface, Address: c.IP,
					CaptureDefault: c.CaptureDefault, LANIface: nd.resolveIface(c.LAN),
				})
			}
		}
		out[name] = cn
	}

	links := n.linkMap()
	for _, l := range n.Links {
		if err := n.addLinkConnections(out, l); err != nil {
			return nil, err
		}
	}
	// Fill each branch's derived gateway (Compile may be called without Load/validate, e.g. in
	// tests), then build the routing tables.
	if err := n.inferGateways(links); err != nil {
		return nil, err
	}
	if err := n.deriveRoutes(out, links); err != nil {
		return nil, err
	}

	// Validate every generated node config.
	for name, cn := range out {
		cn.Defaults()
		if err := cn.Validate(); err != nil {
			return nil, fmt.Errorf("netschema: generated config for %q invalid: %w", name, err)
		}
	}
	return out, nil
}

// sortedKeys returns a map's keys in sorted order, for deterministic emission.
func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// addLinkConnections adds the connect (dialer) and listen (acceptor) connections a link
// expands into.
func (n *Network) addLinkConnections(out map[string]*config.Node, l Link) error {
	dialer, acceptor := n.Nodes[l.Dialer], n.Nodes[l.Acceptor]
	proto := n.Protocols[l.Protocol] // validated to exist

	dialerDir, acceptorDir := "incoming", "outgoing"
	if l.Dataflow == toAcceptor {
		dialerDir, acceptorDir = "outgoing", "incoming"
	}

	dialerIface, dialerIP := dialer.resolveSource(l.DialerSource)
	dc := config.Connection{
		Name: l.Name, Type: "connect", Direction: dialerDir, Transport: proto.Transport,
		Port: l.Port, IP: acceptor.IP, Interface: dialerIface, SourceIP: dialerIP,
		Warpped: proto.Warpped, Cipher: proto.Cipher, HTTP: proto.httpConfig(), PSK: l.PSK,
	}
	if l.IDSetter != "" {
		if l.Dataflow != toDialer {
			return fmt.Errorf("netschema: link %q assigns an id-setter tun but is not a downlink (use the `<...-` arrow)", l.Name)
		}
		if !l.Multiple {
			// A single (non-multiple) acceptor never mints/returns an owner id — it answers a
			// register with a bare pong — so a pending id-setter tun would block its read loop
			// forever waiting for SetID. Only a multiple listen-out mints ids (use `<<...-`).
			return fmt.Errorf("netschema: link %q assigns id-setter tun %q but is not `multiple` — a non-multiple acceptor never mints an owner id, so the tun would hang forever (use the `<<...-` arrow)", l.Name, l.IDSetter)
		}
		if c, ok := dialer.Connections[l.IDSetter]; !ok || !c.isTun() {
			return fmt.Errorf("netschema: link %q id-setter %q is not a tun connection on dialer %q", l.Name, l.IDSetter, l.Dialer)
		}
		dc.IDSetter = l.IDSetter
	}
	out[l.Dialer].Connections = append(out[l.Dialer].Connections, dc)

	acceptorIface, acceptorIP := acceptor.resolveSource(l.AcceptorSource)
	ac := config.Connection{
		Name: l.Name, Type: "listen", Direction: acceptorDir, Transport: proto.Transport,
		Port: l.Port, Interface: acceptorIface, SourceIP: acceptorIP, Cipher: proto.Cipher,
		HTTP: proto.httpConfig(), PSK: l.PSK,
	}
	if l.Dataflow == toDialer {
		ac.Multiple = l.Multiple
	}
	out[l.Acceptor].Connections = append(out[l.Acceptor].Connections, ac)
	return nil
}

// dataSource reports whether node participates in link l as the data sender.
func dataSource(l Link, node string) bool {
	return senderOf(l) == node
}

// relayNode returns the node that forwards a packet from prev onto next: it must RECEIVE on
// prev (be prev's target) and SEND on next (be next's sender). It errors if the two links are
// mis-chained — the shared node is not oriented prev-in → next-out — which would otherwise emit
// a route whose target is a receiver connection (not a Sender), silently dropping the packet.
func relayNode(prev, next Link) (string, error) {
	mid := targetOf(prev)
	if senderOf(next) != mid {
		return "", fmt.Errorf("links %q and %q are mis-chained: a packet received at %q on %q cannot be forwarded on %q (which is sent from %q, not %q)",
			prev.Name, next.Name, mid, prev.Name, next.Name, senderOf(next), mid)
	}
	return mid, nil
}

func boolPtr(b bool) *bool { return &b }

// pendingRule is one derived route before it is placed on its node. Rules are collected
// first and emitted afterwards because a rule downstream of the origin only knows whether
// it must restate its branch's condition once every branch is known — see qualifyRules.
type pendingRule struct {
	node  string
	route config.Route
	relay bool     // rule on the unprocessed leg downstream of the origin (a restatement candidate)
	when  []string // the conditions of the branch that produced it (empty for the default branch)
	path  string   // path label, for the error when a branch cannot be restated
}

// deriveRoutes builds each node's routing table from the paths' branches, and emits onto
// each node the conditions (and their sets) its rules reference. Healthcheck conditions
// are additionally emitted onto their via-owner node even if unreferenced, so their probe
// always runs.
func (n *Network) deriveRoutes(out map[string]*config.Node, links map[string]Link) error {
	var pend []pendingRule
	addRule := func(node string, r config.Route) {
		pend = append(pend, pendingRule{node: node, route: r})
	}
	// A relay/gateway rule carries the branch it came from, so a divergence at that node can be
	// resolved by restating the branch condition there.
	addBranchRule := func(node string, r config.Route, p Path, br Branch) {
		pend = append(pend, pendingRule{node: node, route: r, relay: true, when: br.When, path: p.Label()})
	}

	// Track which condition each node references, then emit.
	refs := map[string]map[string]bool{}
	ref := func(node, cond string) {
		if refs[node] == nil {
			refs[node] = map[string]bool{}
		}
		refs[node][cond] = true
	}

	for _, p := range n.Paths {
		origin := p.OriginNode()
		// Kernel node: lower branches to a Forward policy (no packet-router rules).
		if n.Nodes[origin].Datapath == "kernel" {
			for _, br := range p.Routes {
				for _, cn := range br.When {
					ref(origin, cn)
				}
				out[origin].Forward = append(out[origin].Forward, config.Forward{When: br.When, Egress: br.Egress})
			}
			continue
		}
		tun, _ := n.Nodes[origin].originTun() // validated present for a userspace path
		for _, br := range p.Routes {
			for _, cn := range br.When {
				ref(origin, cn)
			}
			if br.Gateway == "" {
				// Local-egress branch: finalize on the origin node, reply to the tun.
				addRule(origin, config.Route{
					Match:  config.Match{Processed: boolPtr(false), Source: tun, Conditions: br.When},
					Action: config.Action{Egress: br.Egress, Target: tun},
				})
				continue
			}
			// Gateway branch.
			up := make([]Link, len(br.Up))
			for i, ln := range br.Up {
				up[i] = links[ln]
			}
			down := make([]Link, len(br.Down))
			for i, ln := range br.Down {
				down[i] = links[ln]
			}
			if !dataSource(up[0], origin) {
				return fmt.Errorf("netschema: path %q origin %q is not the sender on its first up link %q", p.Name, origin, up[0].Name)
			}
			addRule(origin, config.Route{
				Match:  config.Match{Processed: boolPtr(false), Source: tun, Conditions: br.When},
				Action: config.Action{Target: up[0].Name},
			})
			for i := 0; i+1 < len(up); i++ {
				mid, err := relayNode(up[i], up[i+1])
				if err != nil {
					return fmt.Errorf("netschema: path %q up-path: %w", p.Label(), err)
				}
				addBranchRule(mid, config.Route{
					Match:  config.Match{Processed: boolPtr(false), Source: up[i].Name},
					Action: config.Action{Target: up[i+1].Name},
				}, p, br)
			}
			lastUp := up[len(up)-1]
			gwTarget := tun
			if len(down) > 0 {
				gwTarget = down[0].Name
			}
			addBranchRule(br.Gateway, config.Route{
				Match:  config.Match{Processed: boolPtr(false), Source: lastUp.Name},
				Action: config.Action{Egress: br.Egress, Target: gwTarget},
			}, p, br)
			if len(down) == 0 {
				continue
			}
			for j := 0; j+1 < len(down); j++ {
				mid, err := relayNode(down[j], down[j+1])
				if err != nil {
					return fmt.Errorf("netschema: path %q down-path: %w", p.Label(), err)
				}
				addRule(mid, config.Route{
					Match:  config.Match{Processed: boolPtr(true), Source: down[j].Name},
					Action: config.Action{Target: down[j+1].Name},
				})
			}
			lastDown := down[len(down)-1]
			// The origin must RECEIVE the reply on the last down-link (be its target), or the
			// `proc from lastDown → tun` rule below matches a source the node never receives on.
			if t := targetOf(lastDown); t != origin {
				return fmt.Errorf("netschema: path %q down-path: last link %q delivers to %q, not the origin %q — the reply never reaches the tun", p.Label(), lastDown.Name, t, origin)
			}
			addRule(origin, config.Route{
				Match:  config.Match{Processed: boolPtr(true), Source: lastDown.Name},
				Action: config.Action{Target: tun},
			})
		}
	}

	if err := n.qualifyRules(pend, ref); err != nil {
		return err
	}
	if err := emitRules(out, pend); err != nil {
		return err
	}

	if err := n.emitConditions(out, refs); err != nil {
		return err
	}

	// Within each node, deliver-to-own-tun reply rules first, so a node that both delivers
	// to its tun and relays for others on the same processed source tries its tun first.
	// Scoped to processed rules only, so unprocessed origin-branch order is preserved.
	for name, cn := range out {
		tunName, ok := n.Nodes[name].originTun()
		if !ok {
			continue
		}
		sort.SliceStable(cn.Routes, func(i, j int) bool {
			return isProcessedTun(cn.Routes[i], tunName) && !isProcessedTun(cn.Routes[j], tunName)
		})
	}
	return nil
}

// qualifyRules restates a branch's packet conditions on the rules it derives downstream of
// its origin, wherever two branches of one path diverge there. Such branches arrive at the
// node on the same connection but forward (or finalize) differently, and the derived rules
// carry no condition of their own — only the origin rule does — so they collapse to one
// match and the router, which takes the first accepting target, makes the later branch dead.
// Restating the condition splits the match back apart, and re-evaluating it is sound because
// it is a predicate on the inner packet, which travels unchanged to the divergence point.
//
// Only dst_in conditions are restatable. A healthcheck is liveness of a link at the origin
// and means nothing downstream, so a divergence guarded solely by one is rejected. The
// restatement is placed only where a divergence actually needs it, so no node evaluates a
// set it does not need (nor is shipped its prefix file).
func (n *Network) qualifyRules(pend []pendingRule, ref func(node, cond string)) error {
	actions := map[string]map[string]bool{}
	arrival := func(pr pendingRule) string { return pr.node + "\x00" + pr.route.Match.Source }
	for _, pr := range pend {
		if !pr.relay {
			continue
		}
		k := arrival(pr)
		if actions[k] == nil {
			actions[k] = map[string]bool{}
		}
		actions[k][pr.route.Action.Egress+"→"+pr.route.Action.Target] = true
	}
	catchAll := map[string]bool{} // arrival points already claimed by an unguarded rule
	for i := range pend {
		pr := &pend[i]
		if !pr.relay || len(actions[arrival(*pr)]) < 2 {
			continue
		}
		var restate []string
		for _, cond := range pr.when {
			if n.Conditions[cond].DstIn == nil {
				continue
			}
			restate = append(restate, cond)
			ref(pr.node, cond)
		}
		if len(restate) == 0 {
			// The default branch (no condition) needs no restatement, as long as it stays below
			// the conditional branches — the router would otherwise match it for every packet.
			if len(pr.when) > 0 {
				return fmt.Errorf("netschema: node %q receives two branches of path %q on %q but routes them differently, and branch condition %v cannot be re-evaluated there (only a dst_in condition can — a healthcheck is liveness local to the origin): give the branches distinct links to this node, or the same egress/target",
					pr.node, pr.path, pr.route.Match.Source, pr.when)
			}
			catchAll[arrival(*pr)] = true
			continue
		}
		if catchAll[arrival(*pr)] {
			return fmt.Errorf("netschema: path %q branch %v is dead at node %q: an unconditional branch of the same path already matches everything arriving on %q — order the default branch last",
				pr.path, pr.when, pr.node, pr.route.Match.Source)
		}
		pr.route.Match.Conditions = restate
	}
	return nil
}

// emitRules places the derived rules on their nodes in derivation order, dropping exact
// duplicates (two branches that agree at a node emit one rule). It rejects two finalize
// rules that share a match but differ in egress→target: the router takes the first accepting
// target, so the second would be silently dead. qualifyRules resolves that collision when the
// branches are distinguishable; reaching here means they are not.
func emitRules(out map[string]*config.Node, pend []pendingRule) error {
	seen := map[string]map[string]bool{}
	finAt := map[string]map[string]config.Action{}
	for _, pr := range pend {
		r := pr.route
		match := fmt.Sprintf("%v|%s|%s", *r.Match.Processed, r.Match.Source, strings.Join(r.Match.Conditions, ","))
		if r.Action.Egress != "" {
			if finAt[pr.node] == nil {
				finAt[pr.node] = map[string]config.Action{}
			}
			if prev, ok := finAt[pr.node][match]; ok && prev != r.Action {
				return fmt.Errorf("netschema: node %q has two finalize rules for the same match {processed:%v source:%q conditions:%v} but different egress→target (%q→%q vs %q→%q): two path branches reach this gateway indistinguishably but finalize differently, which collapses to one rule — give them distinct up-links, distinct dst_in conditions, or the same egress",
					pr.node, *r.Match.Processed, r.Match.Source, r.Match.Conditions, prev.Egress, prev.Target, r.Action.Egress, r.Action.Target)
			}
			finAt[pr.node][match] = r.Action
		}
		key := match + "|" + r.Action.Egress + "|" + r.Action.Target
		if seen[pr.node] == nil {
			seen[pr.node] = map[string]bool{}
		}
		if seen[pr.node][key] {
			continue
		}
		seen[pr.node][key] = true
		out[pr.node].Routes = append(out[pr.node].Routes, r)
	}
	return nil
}

func isProcessedTun(r config.Route, tunName string) bool {
	return r.Match.Processed != nil && *r.Match.Processed && r.Action.Target == tunName
}

// relocateSet copies an IPSet, rewriting a file path (a LOCAL source path in the schema) to
// where the node reads it at runtime (deploy copies it there); an inline list is unchanged.
// The copy avoids mutating the shared schema value.
func (n *Network) relocateSet(node string, s *config.IPSet) *config.IPSet {
	cp := *s
	if cp.File != "" {
		cp.File = n.remoteConditionFile(node, cp.File)
	}
	return &cp
}

// emitConditions places each referenced condition onto the referencing node, and each
// healthcheck condition onto its path's tun node even if unreferenced (so its probe runs).
// A healthcheck's up-path is derived from the gateway branch of the path it names.
func (n *Network) emitConditions(out map[string]*config.Node, refs map[string]map[string]bool) error {
	condDone := map[string]map[string]bool{}
	emit := func(node, cond string) error {
		if condDone[node] == nil {
			condDone[node] = map[string]bool{}
		}
		if condDone[node][cond] {
			return nil
		}
		condDone[node][cond] = true
		spec := n.Conditions[cond]
		if spec.DstIn != nil {
			out[node].Conditions = append(out[node].Conditions, config.Condition{Name: cond, DstIn: n.relocateSet(node, spec.DstIn)})
			return nil
		}
		if spec.SrcIn != nil {
			out[node].Conditions = append(out[node].Conditions, config.Condition{Name: cond, SrcIn: n.relocateSet(node, spec.SrcIn)})
			return nil
		}
		hc := spec.Healthcheck
		br, tunNode, err := n.gatewayBranch(hc.Path, hc.Gateway)
		if err != nil {
			return fmt.Errorf("netschema: healthcheck condition %q: %w", cond, err)
		}
		if node != tunNode {
			return fmt.Errorf("netschema: healthcheck condition %q probes path %q (tun node %q) but is emitted on %q", cond, hc.Path, tunNode, node)
		}
		tun := hc.Tun
		if tun == "" {
			tun, _ = n.Nodes[tunNode].originTun()
		}
		out[node].Conditions = append(out[node].Conditions, config.Condition{
			Name: cond,
			Healthcheck: &config.HealthcheckSpec{
				Up: br.Up, Tun: tun, Interval: hc.Interval, Timeout: hc.Timeout, UpGrace: hc.UpGrace,
				Links: n.pathReconnectLinks(br, tunNode),
			},
		})
		return nil
	}

	for _, node := range sortedKeys(refs) {
		for _, cond := range sortedKeys(refs[node]) {
			spec := n.Conditions[cond]
			if spec.Healthcheck != nil {
				_, tunNode, err := n.gatewayBranch(spec.Healthcheck.Path, spec.Healthcheck.Gateway)
				if err != nil {
					return fmt.Errorf("netschema: healthcheck condition %q: %w", cond, err)
				}
				if tunNode != node {
					return fmt.Errorf("netschema: healthcheck condition %q is used on %q but probes path %q (tun node %q)", cond, node, spec.Healthcheck.Path, tunNode)
				}
			}
			if err := emit(node, cond); err != nil {
				return err
			}
		}
	}
	// Healthcheck conditions run even when unreferenced: emit onto their path's tun node.
	for cond, spec := range n.Conditions {
		if spec.Healthcheck == nil {
			continue
		}
		_, tunNode, err := n.gatewayBranch(spec.Healthcheck.Path, spec.Healthcheck.Gateway)
		if err != nil {
			return fmt.Errorf("netschema: healthcheck condition %q: %w", cond, err)
		}
		if err := emit(tunNode, cond); err != nil {
			return err
		}
	}
	return nil
}

// pathReconnectLinks returns, in path order, the names of the branch's up/down links that the
// origin DIALS (its connect connections). Those are the reconnectable connections this path
// depends on; a link the origin accepts (a listener) is not dialed and cannot be reconnected.
// Scoping a healthcheck's reconnects to just these keeps one path's outage from tearing down
// another path's connections.
func (n *Network) pathReconnectLinks(br Branch, origin string) []string {
	lm := n.linkMap()
	var out []string
	for _, ln := range append(append([]string{}, br.Up...), br.Down...) {
		if l, ok := lm[ln]; ok && l.Dialer == origin {
			out = append(out, ln)
		}
	}
	return out
}

// gatewayBranch returns the (single) gateway branch of a path — optionally filtered to a
// given gateway — and the path's tun node. It is how a healthcheck condition finds the
// full round-trip it probes.
func (n *Network) gatewayBranch(pathName, gateway string) (Branch, string, error) {
	var p *Path
	for i := range n.Paths {
		if n.Paths[i].Name == pathName {
			p = &n.Paths[i]
			break
		}
	}
	if p == nil {
		return Branch{}, "", fmt.Errorf("unknown path %q", pathName)
	}
	var found []Branch
	for _, br := range p.Routes {
		if br.Gateway == "" || (gateway != "" && br.Gateway != gateway) {
			continue
		}
		found = append(found, br)
	}
	if len(found) == 0 {
		return Branch{}, "", fmt.Errorf("path %q has no gateway branch to probe", pathName)
	}
	if len(found) > 1 {
		return Branch{}, "", fmt.Errorf("path %q has multiple gateway branches; set gateway: to pick one", pathName)
	}
	return found[0], p.OriginNode(), nil
}
