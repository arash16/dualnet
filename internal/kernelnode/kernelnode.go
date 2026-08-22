// Package kernelnode is dualnet's kernel-datapath runtime: instead of a userspace packet
// router it programs the Linux forwarding plane (ip rule / ip route + iptables MASQUERADE) so
// the box forwards near line rate (hardware-offload-friendly), and keeps that programming
// applied — reloading dst_in geo sets on SIGHUP — until its context is cancelled.
//
// It exists because a userspace gVisor egress terminates and re-dials every flow, which caps a
// slow softfloat home router at ~20 Mbps. A kernel node does no per-packet userspace work: it
// lowers a config.Node's Forward policy + Egresses + Conditions into policy routing.
//
// Lowering model (fixed precedence src_in > dst_in > default, mirroring how the kernel consults
// ip rule before the routing table, and specific routes before a default):
//
//   - each egress e gets a routing table with `default via <gw|dev>` (its WAN) + a MASQUERADE
//     out its ext_iface + FORWARD accept;
//   - a src_in branch → `ip rule from <legIP> lookup <e-table>` (per source IP), so leg-sourced
//     traffic always exits e regardless of destination — plus an on-link /32 return route for
//     each leg IP on the LAN device so replies find their way back;
//   - a dst_in branch → its prefixes as routes in a per-branch geo table (FIB longest-prefix,
//     reloadable) consulted by one `ip rule lookup <geo-table>`, so those destinations exit e;
//   - the default branch → `ip rule lookup <default-e-table>` at the lowest priority.
package kernelnode

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/arash16/dualnet/internal/config"
)

// Routing-table numbers and ip-rule priorities. The table base avoids the userspace node's
// PinIfaceDefault range (220+). Priorities encode the precedence: src rules (11xxx) are
// consulted before dst rules (12xxx) before the default rule (13000).
const (
	tableEgressBase = 300   // per-egress default table: `default via <WAN>`
	tableGeoBase    = 350   // per dst_in branch geo table: prefix routes
	prioMain        = 10000 // `ip rule lookup main suppress_prefixlength 0` (connected routes win)
	prioSrcBase     = 11000 // `ip rule from <legIP> lookup <e-table>`
	prioDstBase     = 12000 // `ip rule lookup <geo-table>` (per dst branch, in order)
	prioDefault     = 13000 // `ip rule lookup <default-e-table>`
)

// Runtime runs one kernel-datapath node.
type Runtime struct {
	cfg *config.Node
	// reloadMu serializes geo-set reloads: a SIGHUP-triggered reload and a per-set interval
	// reload can otherwise call loadGeo on the same table concurrently, interleaving their
	// flush/batch-add so one `ip -batch` fails ("File exists") or re-empties a freshly loaded
	// table. Held for the whole flush+repopulate of every reload.
	reloadMu sync.Mutex
}

// New builds a kernel-node runtime from its compiled config.
func New(cfg *config.Node) *Runtime { return &Runtime{cfg: cfg} }

// withVerb returns a copy of an `ip …` argv with its verb (the 3rd token, e.g. "add") replaced,
// so an add becomes its matching del. Pure and cross-platform so the idempotency contract
// (delete-before-add on re-apply) is unit-testable without shelling out to `ip`.
func withVerb(argv []string, verb string) []string {
	out := append([]string(nil), argv...)
	if len(out) >= 3 {
		out[2] = verb
	}
	return out
}

// flipAppendToDelete returns a copy of an iptables rule tail with -A/-I turned into -D, so an
// appended/inserted rule can be removed (on teardown, or as a pre-delete before re-adding it so
// a crash-leaked copy is not duplicated). Pure and cross-platform for the same reason.
func flipAppendToDelete(rule []string) []string {
	out := append([]string(nil), rule...)
	for i, a := range out {
		if a == "-A" || a == "-I" {
			out[i] = "-D"
		}
	}
	return out
}

// wan is an egress's realized next-hop: its device and gateway ("" = point-to-point, no via).
type wan struct {
	dev string
	gw  string
	// ep, when set (a warp egress), is the tunnel's resolved WireGuard endpoint and the
	// underlay it must exit: lower() pins <ip>/32 in the MAIN table via that underlay so the
	// tunnel's own encrypted UDP never falls through to the policy rules and back into the
	// tunnel (a routing loop that kills the handshake). The prio-10000 main-suppress rule only
	// rejects main's default route, so a /32 there wins before every policy rule — no fwmark
	// needed, which matters on the old kernels this targets.
	ep *underlayRoute
}

// underlayRoute pins a warp egress's endpoint address to the underlay WAN it must exit.
type underlayRoute struct {
	ip  string // endpoint address (no port)
	dev string // underlay WAN device (the egress's exit)
	gw  string // underlay next-hop ("" = dev-only, e.g. PPPoE)
}

// geoBinding is one dst_in branch's reloadable geo set: the prefixes route to wan in table.
type geoBinding struct {
	cond  string
	set   config.IPSet
	table int
	wan   wan
}

// plan is the fully-lowered kernel forwarding config, expressed as command argv so it is
// unit-testable without touching the OS. Every Rules/MainRoutes/TableRoutes entry is a
// complete `ip …` invocation; IPTables entries are rule tails (argv after `iptables [-w]`).
type plan struct {
	tables      []int      // routing tables populated (flushed before apply and on teardown)
	tableRoutes [][]string // `ip route …` into our tables (default tables); removed by table flush
	mainRoutes  [][]string // `ip route …` in the main table (on-link /32s); deleted individually
	rules       [][]string // `ip rule add …`; deleted individually
	iptables    [][]string // iptables rule tails; teardown flips -A/-I to -D
	geo         []geoBinding
}

// lower turns a kernel-node config plus resolved per-egress next-hops into a plan. It is pure:
// no OS calls, so tests assert on the emitted argv.
func lower(cfg *config.Node, wans map[string]wan) (*plan, error) {
	p := &plan{}
	// A default table per egress (sorted for determinism), used by src_in and default rules.
	egresses := sortedKeys(cfg.Egresses)
	egTable := map[string]int{}
	epPinned := map[string]underlayRoute{} // endpoint ip -> its pinned underlay
	for i, name := range egresses {
		t := tableEgressBase + i
		egTable[name] = t
		p.tables = append(p.tables, t)
		p.tableRoutes = append(p.tableRoutes, defaultRoute(wans[name], t))
		p.iptables = append(p.iptables, masqRules(wans[name].dev, cfg.LANIfaces)...)
		if ep := wans[name].ep; ep != nil {
			// Two warp egresses often resolve the same anycast endpoint: one /32 suffices,
			// but it cannot exit two different underlays.
			if prev, dup := epPinned[ep.ip]; dup {
				if prev != *ep {
					return nil, fmt.Errorf("kernelnode: warp endpoint %s pinned to two different underlays (%s via %q, %s via %q)", ep.ip, prev.dev, prev.gw, ep.dev, ep.gw)
				}
			} else {
				epPinned[ep.ip] = *ep
				p.mainRoutes = append(p.mainRoutes, hostRoute(*ep))
			}
		}
	}

	// Consult the main table first, but IGNORE its default route: connected/LAN/management/
	// specific routes (prefixlen > 0) win, so the router still reaches its own LAN and replies
	// to the box itself go out the right interface. Only genuinely default-bound (internet)
	// traffic falls through to the per-egress rules below. WITHOUT this, a per-egress table's
	// catch-all `default` (consulted before main) hijacks every reply — including the deploy's
	// own SSH — onto one WAN, and the router goes dark. This rule must precede all others.
	p.rules = append(p.rules, ruleMainSuppress(prioMain))

	condByName := map[string]config.Condition{}
	for _, c := range cfg.Conditions {
		condByName[c.Name] = c
	}
	lan := ""
	if len(cfg.LANIfaces) > 0 {
		lan = cfg.LANIfaces[0]
	}

	srcPrio := prioSrcBase
	dstIdx := 0
	seenLeg := map[string]bool{}
	for _, f := range cfg.Forward {
		if len(f.When) == 0 { // default branch
			p.rules = append(p.rules, ruleLookup(prioDefault, "", egTable[f.Egress]))
			continue
		}
		cond := condByName[f.When[0]]
		switch {
		case cond.SrcIn != nil:
			ips, err := readPrefixes(*cond.SrcIn)
			if err != nil {
				return nil, fmt.Errorf("kernelnode: condition %q: %w", f.When[0], err)
			}
			for _, ip := range ips {
				p.rules = append(p.rules, ruleFrom(srcPrio, ip, egTable[f.Egress]))
				srcPrio++
				if lan != "" && !seenLeg[ip] {
					seenLeg[ip] = true
					p.mainRoutes = append(p.mainRoutes, onLinkRoute(ip, lan))
				}
			}
		case cond.DstIn != nil:
			t := tableGeoBase + dstIdx
			p.tables = append(p.tables, t)
			p.rules = append(p.rules, ruleLookup(prioDstBase+dstIdx, "", t))
			p.geo = append(p.geo, geoBinding{cond: f.When[0], set: *cond.DstIn, table: t, wan: wans[f.Egress]})
			dstIdx++
		default:
			return nil, fmt.Errorf("kernelnode: forward branch condition %q is neither src_in nor dst_in", f.When[0])
		}
	}
	return p, nil
}

// defaultRoute is the `ip route` argv for an egress's default table: `default [via gw] dev dev`.
func defaultRoute(w wan, table int) []string {
	r := []string{"ip", "route", "add", "default"}
	if w.gw != "" {
		r = append(r, "via", w.gw)
	}
	return append(r, "dev", w.dev, "table", strconv.Itoa(table))
}

// geoRoute is the `ip route` argv routing one prefix out an egress's WAN in a geo table.
func geoRoute(prefix string, w wan, table int) []string {
	r := []string{"ip", "route", "add", prefix}
	if w.gw != "" {
		r = append(r, "via", w.gw)
	}
	return append(r, "dev", w.dev, "table", strconv.Itoa(table))
}

// onLinkRoute is the `ip route` argv for a leg IP's on-link return route on the LAN device.
func onLinkRoute(cidr, lan string) []string {
	return []string{"ip", "route", "add", cidr, "dev", lan}
}

// hostRoute is the `ip route` argv pinning a warp endpoint /32 in the main table via its
// underlay WAN.
func hostRoute(u underlayRoute) []string {
	r := []string{"ip", "route", "add", u.ip + "/32"}
	if u.gw != "" {
		r = append(r, "via", u.gw)
	}
	return append(r, "dev", u.dev)
}

// ruleMainSuppress is `ip rule add priority P from all lookup main suppress_prefixlength 0`:
// use the main table but reject its default route, so specific/connected routes still win and
// only default-bound traffic falls through to the policy rules.
func ruleMainSuppress(prio int) []string {
	return []string{"ip", "rule", "add", "priority", strconv.Itoa(prio), "from", "all", "lookup", "main", "suppress_prefixlength", "0"}
}

// ruleFrom is `ip rule add priority P from <cidr> lookup <table>`.
func ruleFrom(prio int, cidr string, table int) []string {
	return []string{"ip", "rule", "add", "priority", strconv.Itoa(prio), "from", cidr, "lookup", strconv.Itoa(table)}
}

// ruleLookup is `ip rule add priority P [from cidr] lookup <table>`; an empty from matches all.
func ruleLookup(prio int, from string, table int) []string {
	r := []string{"ip", "rule", "add", "priority", strconv.Itoa(prio)}
	if from != "" {
		r = append(r, "from", from)
	}
	return append(r, "lookup", strconv.Itoa(table))
}

// masqRules is the iptables rule tails for one WAN: MASQUERADE out it, FORWARD accept between
// each LAN and it (with stateful return), and an MSS clamp for TCP crossing it (helps PPPoE).
func masqRules(wanDev string, lans []string) [][]string {
	out := [][]string{
		{"-t", "nat", "-A", "POSTROUTING", "-o", wanDev, "-j", "MASQUERADE"},
	}
	for _, lan := range lans {
		out = append(out,
			[]string{"-A", "FORWARD", "-i", lan, "-o", wanDev, "-j", "ACCEPT"},
			[]string{"-A", "FORWARD", "-i", wanDev, "-o", lan, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		)
	}
	out = append(out, []string{"-t", "mangle", "-A", "FORWARD", "-o", wanDev, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"})
	return out
}

// readPrefixes returns the normalized (masked) CIDR strings of an IPSet — its inline list, or
// the lines of its file (same grammar as ipmatch: `ip/mask` or a bare address, `#` comments,
// blank lines ignored). A bare address becomes a host /32 (/128 for v6).
func readPrefixes(s config.IPSet) ([]string, error) {
	var raw []string
	if len(s.List) > 0 {
		raw = s.List
	} else {
		b, err := os.ReadFile(s.File)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			if line = strings.TrimSpace(line); line != "" {
				raw = append(raw, line)
			}
		}
	}
	out := make([]string, 0, len(raw))
	for _, tok := range raw {
		norm, err := normalizePrefix(tok)
		if err != nil {
			return nil, err
		}
		out = append(out, norm)
	}
	return out, nil
}

// normalizePrefix masks host bits (so `ip route` accepts it) and turns a bare address into a
// host route.
func normalizePrefix(tok string) (string, error) {
	if strings.ContainsRune(tok, '/') {
		p, err := netip.ParsePrefix(tok)
		if err != nil {
			return "", err
		}
		return p.Masked().String(), nil
	}
	a, err := netip.ParseAddr(tok)
	if err != nil {
		return "", err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()).String(), nil
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
