package kernelnode

import (
	"strings"
	"testing"

	"github.com/arash16/dualnet/internal/config"
)

// homeRouter is the compiled kernel config for the home-bond router: iran-geo and a source-IP
// up-leg to FTTH (PPPoE, dev-only), everything else to Starlink (broadcast, via a gateway).
func homeRouter() *config.Node {
	return &config.Node{
		Datapath:  "kernel",
		LANIfaces: []string{"br0"},
		Egresses: map[string]config.Egress{
			"ftth":     {Mode: "kernel", ExtIface: "ppp1"},
			"starlink": {Mode: "kernel", ExtIface: "nas10"},
		},
		Conditions: []config.Condition{
			{Name: "up-leg", SrcIn: &config.IPSet{List: []string{"10.99.0.1/32"}}},
			{Name: "is-iran", DstIn: &config.IPSet{List: []string{"1.2.3.0/24"}}},
		},
		Forward: []config.Forward{
			{When: []string{"up-leg"}, Egress: "ftth"},
			{When: []string{"is-iran"}, Egress: "ftth"},
			{Egress: "starlink"},
		},
	}
}

func homeWANs() map[string]wan {
	return map[string]wan{
		"ftth":     {dev: "ppp1", gw: ""},           // PPPoE: point-to-point, dev-only
		"starlink": {dev: "nas10", gw: "192.0.2.1"}, // broadcast WAN: via a gateway
	}
}

// contains reports whether argv (joined) appears among the argv list (joined).
func hasArgv(t *testing.T, list [][]string, want string) {
	t.Helper()
	for _, a := range list {
		if strings.Join(a, " ") == want {
			return
		}
	}
	var got []string
	for _, a := range list {
		got = append(got, strings.Join(a, " "))
	}
	t.Errorf("missing argv %q\n  have:\n    %s", want, strings.Join(got, "\n    "))
}

func TestLowerHomeRouter(t *testing.T) {
	p, err := lower(homeRouter(), homeWANs())
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	// Per-egress default tables: ftth=300 (dev-only), starlink=301 (via gw).
	hasArgv(t, p.tableRoutes, "ip route add default dev ppp1 table 300")
	hasArgv(t, p.tableRoutes, "ip route add default via 192.0.2.1 dev nas10 table 301")

	// The main-table suppressor MUST come first (priority < the policy rules): it keeps
	// connected/LAN/management routing intact, so the router does not black-hole its own replies
	// (the deploy-hangs-the-router bug). Only default-bound traffic reaches the policy rules.
	hasArgv(t, p.rules, "ip rule add priority 10000 from all lookup main suppress_prefixlength 0")

	// Rules encode the precedence: main-suppress (10000) < src (11xxx) < dst (12xxx) < default (13000).
	hasArgv(t, p.rules, "ip rule add priority 11000 from 10.99.0.1/32 lookup 300")
	hasArgv(t, p.rules, "ip rule add priority 12000 lookup 350")
	hasArgv(t, p.rules, "ip rule add priority 13000 lookup 301")

	// The leg source IP gets an on-link return route on the LAN device.
	hasArgv(t, p.mainRoutes, "ip route add 10.99.0.1/32 dev br0")

	// Each WAN masquerades and forwards to/from the LAN.
	hasArgv(t, p.iptables, "-t nat -A POSTROUTING -o ppp1 -j MASQUERADE")
	hasArgv(t, p.iptables, "-t nat -A POSTROUTING -o nas10 -j MASQUERADE")
	hasArgv(t, p.iptables, "-A FORWARD -i br0 -o ppp1 -j ACCEPT")
	hasArgv(t, p.iptables, "-A FORWARD -i nas10 -o br0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")

	// The dst_in geo set binds to its table + WAN for (re)loading.
	if len(p.geo) != 1 || p.geo[0].cond != "is-iran" || p.geo[0].table != 350 || p.geo[0].wan.dev != "ppp1" {
		t.Fatalf("geo binding = %+v, want is-iran -> table 350 via ppp1", p.geo)
	}
	// All three tables are tracked for flush/teardown.
	if got := len(p.tables); got != 3 {
		t.Errorf("tables = %v, want 3 (300,301,350)", p.tables)
	}
}

// warpRouter is a kernel router whose default branch exits through a WARP WireGuard device:
// iran destinations stay on the physical FTTH WAN, vpn-flagged destinations and everything
// else tunnel out the wg device (which rides the starlink underlay).
func warpRouter() *config.Node {
	return &config.Node{
		Datapath:  "kernel",
		LANIfaces: []string{"br0"},
		Egresses: map[string]config.Egress{
			"ftth": {Mode: "kernel", ExtIface: "ppp1"},
			"warp": {Mode: "warp", ExtIface: "nas10", TunName: "warp-warp"},
		},
		Conditions: []config.Condition{
			{Name: "is-iran", DstIn: &config.IPSet{List: []string{"1.2.3.0/24"}}},
			{Name: "is-vpn", DstIn: &config.IPSet{List: []string{"4.5.6.0/24"}}},
		},
		Forward: []config.Forward{
			{When: []string{"is-iran"}, Egress: "ftth"},
			{When: []string{"is-vpn"}, Egress: "warp"},
			{Egress: "warp"},
		},
	}
}

func warpWANs() map[string]wan {
	return map[string]wan{
		"ftth": {dev: "ppp1"},
		"warp": {dev: "warp-warp", ep: &underlayRoute{ip: "162.159.192.1", dev: "nas10", gw: "192.0.2.1"}},
	}
}

// TestLowerWarpEgress pins how a warp egress lowers: the wg device is routed like any other
// (dev-only) WAN — default table, MASQUERADE, MSS clamp, geo routes — plus the one warp-only
// artifact, the endpoint /32 pinned in the main table via the underlay so the tunnel's own
// encrypted UDP cannot be policy-routed back into the tunnel.
func TestLowerWarpEgress(t *testing.T) {
	p, err := lower(warpRouter(), warpWANs())
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	// Egress tables are sorted: ftth=300, warp=301. The wg device routes dev-only.
	hasArgv(t, p.tableRoutes, "ip route add default dev warp-warp table 301")
	hasArgv(t, p.rules, "ip rule add priority 13000 lookup 301")

	// The endpoint pin: a main-table /32 via the underlay WAN. Its prefixlen beats the
	// prio-10000 suppress_prefixlength 0, so it wins before every policy rule.
	hasArgv(t, p.mainRoutes, "ip route add 162.159.192.1/32 via 192.0.2.1 dev nas10")

	// The wg device masquerades and forwards like a physical WAN; the clamp handles MTU 1280.
	hasArgv(t, p.iptables, "-t nat -A POSTROUTING -o warp-warp -j MASQUERADE")
	hasArgv(t, p.iptables, "-A FORWARD -i br0 -o warp-warp -j ACCEPT")
	hasArgv(t, p.iptables, "-t mangle -A FORWARD -o warp-warp -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")

	// A dst_in branch pointing at the warp egress routes its prefixes into the wg device.
	if len(p.geo) != 2 || p.geo[1].cond != "is-vpn" || p.geo[1].wan.dev != "warp-warp" {
		t.Fatalf("geo bindings = %+v, want is-vpn -> warp-warp", p.geo)
	}

	// A point-to-point underlay (PPPoE) pins the endpoint dev-only.
	wans := warpWANs()
	wans["warp"] = wan{dev: "warp-warp", ep: &underlayRoute{ip: "162.159.192.1", dev: "ppp1"}}
	if p, err = lower(warpRouter(), wans); err != nil {
		t.Fatalf("lower dev-only underlay: %v", err)
	}
	hasArgv(t, p.mainRoutes, "ip route add 162.159.192.1/32 dev ppp1")
}

// TestLowerWarpSharedEndpoint covers two warp egresses resolving the same (anycast) endpoint:
// one shared underlay yields a single /32 pin, while two different underlays are an error — a
// single host route cannot exit two devices, and silently picking one would black-hole the
// other tunnel.
func TestLowerWarpSharedEndpoint(t *testing.T) {
	cfg := &config.Node{
		Datapath:  "kernel",
		LANIfaces: []string{"br0"},
		Egresses: map[string]config.Egress{
			"a": {Mode: "warp", ExtIface: "eth0", TunName: "wg-a"},
			"b": {Mode: "warp", ExtIface: "eth0", TunName: "wg-b"},
		},
		Forward: []config.Forward{{Egress: "a"}},
	}
	shared := underlayRoute{ip: "162.159.192.1", dev: "eth0", gw: "192.0.2.1"}
	sameUnderlay := map[string]wan{
		"a": {dev: "wg-a", ep: &shared},
		"b": {dev: "wg-b", ep: &shared},
	}
	p, err := lower(cfg, sameUnderlay)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	pins := 0
	for _, rt := range p.mainRoutes {
		if strings.Contains(strings.Join(rt, " "), "162.159.192.1/32") {
			pins++
		}
	}
	if pins != 1 {
		t.Errorf("endpoint /32 pinned %d times, want exactly once", pins)
	}

	other := shared
	other.dev = "eth1"
	conflicting := map[string]wan{
		"a": {dev: "wg-a", ep: &shared},
		"b": {dev: "wg-b", ep: &other},
	}
	if _, err := lower(cfg, conflicting); err == nil {
		t.Error("expected error for one endpoint pinned to two different underlays")
	}
}

// TestIdempotencyDeleteForms covers that apply() must be able to delete a crash-leaked copy of
// every rule before (re)adding it, so a re-apply after an ungraceful exit does not stack
// duplicates. This pins the pure delete-form generators the fix relies on: withVerb turns an
// `ip … add` into its matching `del`, and flipAppendToDelete turns an iptables -A/-I tail into
// -D while preserving the table selector — exercised against the real emitted plan shapes.
func TestIdempotencyDeleteForms(t *testing.T) {
	for _, fixture := range []struct {
		name string
		cfg  *config.Node
		wans map[string]wan
	}{
		{"home", homeRouter(), homeWANs()},
		{"warp", warpRouter(), warpWANs()}, // its endpoint pin must be crash-leak deletable too
	} {
		t.Run(fixture.name, func(t *testing.T) {
			testIdempotencyDeleteForms(t, fixture.cfg, fixture.wans)
		})
	}
}

func testIdempotencyDeleteForms(t *testing.T, cfg *config.Node, wans map[string]wan) {
	p, err := lower(cfg, wans)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	// ip rules/routes: `add` → `del`, same otherwise.
	for _, ru := range append(append([][]string{}, p.rules...), p.mainRoutes...) {
		del := withVerb(ru, "del")
		if len(del) < 3 || del[2] != "del" || del[0] != "ip" || del[1] != ru[1] {
			t.Errorf("withVerb(%v) = %v, want the same argv with verb=del", ru, del)
		}
	}

	// iptables tails: -A/-I → -D, table selector (-t nat / -t mangle) preserved.
	for _, ipt := range p.iptables {
		del := flipAppendToDelete(ipt)
		if len(del) != len(ipt) {
			t.Fatalf("flipAppendToDelete changed length: %v -> %v", ipt, del)
		}
		sawDelete := false
		for i := range ipt {
			switch ipt[i] {
			case "-A", "-I":
				if del[i] != "-D" {
					t.Errorf("flipAppendToDelete(%v): position %d not flipped to -D: %v", ipt, i, del)
				}
				sawDelete = true
			default:
				if del[i] != ipt[i] {
					t.Errorf("flipAppendToDelete(%v) altered non-verb token %q -> %q", ipt, ipt[i], del[i])
				}
			}
		}
		if !sawDelete {
			t.Errorf("iptables rule %v has no -A/-I to flip (cannot be pre-deleted / torn down)", ipt)
		}
	}
}

// TestGeoRoute checks a geo prefix routes out its WAN in the geo table (via a gateway when the
// WAN has one, dev-only otherwise).
func TestGeoRoute(t *testing.T) {
	if got := strings.Join(geoRoute("1.2.3.0/24", wan{dev: "nas10", gw: "192.0.2.1"}, 350), " "); got != "ip route add 1.2.3.0/24 via 192.0.2.1 dev nas10 table 350" {
		t.Errorf("geoRoute via = %q", got)
	}
	if got := strings.Join(geoRoute("1.2.3.0/24", wan{dev: "ppp1"}, 350), " "); got != "ip route add 1.2.3.0/24 dev ppp1 table 350" {
		t.Errorf("geoRoute dev-only = %q", got)
	}
}

// TestReadPrefixesNormalizes checks host bits are masked and a bare address becomes a host /32
// (so `ip route add` accepts every token).
func TestReadPrefixesNormalizes(t *testing.T) {
	got, err := readPrefixes(config.IPSet{List: []string{"10.0.0.5/24", "8.8.8.8"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "10.0.0.0/24" || got[1] != "8.8.8.8/32" {
		t.Errorf("readPrefixes = %v, want [10.0.0.0/24 8.8.8.8/32]", got)
	}
}
