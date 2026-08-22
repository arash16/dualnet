package node

import (
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/conn"
	"github.com/arash16/dualnet/internal/healthcheck"
	"github.com/arash16/dualnet/internal/ipmatch"
	"github.com/arash16/dualnet/internal/netcfg"
	"github.com/arash16/dualnet/internal/router"
	"github.com/arash16/dualnet/internal/wire"
)

// pathLinks selects the reconnectable connections a healthcheck should re-establish on silence:
// the connections named in hc.Links (this path's dialed links), or — for a hand-written spec
// that omits Links — a fallback of just Up[0]. Scoping to the path's own links keeps one path's
// outage from reconnecting unrelated healthy connections (e.g. a shared relay leg).
func pathLinks(hc *config.HealthcheckSpec, byName map[string]healthcheck.Reconnecter) []healthcheck.Reconnecter {
	names := hc.Links
	if len(names) == 0 && len(hc.Up) > 0 {
		names = hc.Up[:1] // fallback: the up-link the probe rides
	}
	var out []healthcheck.Reconnecter
	for _, n := range names {
		if rc := byName[n]; rc != nil {
			out = append(out, rc)
		}
	}
	return out
}

// teardown collects undo steps and runs them in reverse on exit.
type teardown struct{ steps []func() error }

func (t *teardown) add(f func() error) {
	if f != nil {
		t.steps = append(t.steps, f)
	}
}

func (t *teardown) run() {
	for i := len(t.steps) - 1; i >= 0; i-- {
		_ = t.steps[i]()
	}
}

func kindOf(c config.Connection) conn.Kind {
	switch c.Type {
	case "tun":
		return conn.KindTun
	case "connect":
		if c.Direction == "outgoing" {
			return conn.KindConnectOut
		}
		return conn.KindConnectIn
	default: // listen
		if c.Direction == "outgoing" {
			return conn.KindListenOut
		}
		return conn.KindListenIn
	}
}

// httpParams maps a connection's optional HTTP carrier customization into the conn spec's
// form (empty when unset; the factory fills proto defaults).
func httpParams(h *config.HTTPConfig) conn.HTTPParams {
	if h == nil {
		return conn.HTTPParams{}
	}
	return conn.HTTPParams{
		UploadPath: h.UploadPath, DownloadPath: h.DownloadPath, Host: h.Host,
		UserAgent: h.UserAgent, IDHeader: h.IDHeader, Headers: h.Headers,
	}
}

// egressesUsed returns the set of named egresses referenced by a finalize rule.
func egressesUsed(cfg *config.Node) map[string]bool {
	used := map[string]bool{}
	for _, r := range cfg.Routes {
		if r.Action.Egress != "" {
			used[r.Action.Egress] = true
		}
	}
	return used
}

// dstGuard passes when the packet's destination is in the set.
type dstGuard struct{ m ipmatch.Matcher }

func (g dstGuard) Pass(_ wire.Owner, dst netip.Addr, ok bool) bool { return ok && g.m.Contains(dst) }

// healthGuard passes while the referenced healthcheck condition is up.
type healthGuard struct{ up *atomic.Bool }

func (g healthGuard) Pass(wire.Owner, netip.Addr, bool) bool { return g.up.Load() }

// pendingTuns returns the set of tun names whose id is assigned by a remote (some
// connect+incoming connection sets it via id_setter), so their read loops must hold
// until the id arrives.
func pendingTuns(cfg *config.Node) map[string]bool {
	p := map[string]bool{}
	for _, c := range cfg.Connections {
		if c.IDSetter != "" {
			p[c.IDSetter] = true
		}
	}
	return p
}

func capturesDefault(cfg *config.Node) bool {
	for _, c := range cfg.Connections {
		if c.Type == "tun" && c.CaptureDefault {
			return true
		}
	}
	return false
}

// pinRoutes collects scoped host routes to every connect connection's remote via its
// interface (macOS; needed once a tun captures the default route).
func pinRoutes(cfg *config.Node) []netcfg.PinRoute {
	var pins []netcfg.PinRoute
	for _, c := range cfg.Connections {
		if c.Type == "connect" && c.IP != "" && c.Interface != "" {
			pins = append(pins, netcfg.PinRoute{Dst: c.IP, Iface: c.Interface})
		}
	}
	return pins
}

func compileRules(cfg *config.Node) []router.Rule {
	rules := make([]router.Rule, len(cfg.Routes))
	for i, r := range cfg.Routes {
		rules[i] = router.Rule{
			MatchProcessed: r.Match.Processed,
			Source:         r.Match.Source,
			Conditions:     r.Match.Conditions,
			Egress:         r.Action.Egress,
			Target:         r.Action.Target,
		}
	}
	return rules
}

// condTiming resolves a healthcheck condition's interval/timeout/up-grace, applying the
// spec's values over the node defaults (Healthcheck/HealthcheckTimeout/HealthcheckUpGrace).
func condTiming(cfg *config.Node, hc *config.HealthcheckSpec) (interval, timeout, upGrace time.Duration) {
	iv := 15
	if cfg.Healthcheck != nil {
		iv = *cfg.Healthcheck
	}
	if hc.Interval != 0 {
		iv = hc.Interval
	}
	to := 90
	if cfg.HealthcheckTimeout > 0 {
		to = cfg.HealthcheckTimeout
	}
	if hc.Timeout > 0 {
		to = hc.Timeout
	}
	ug := cfg.HealthcheckUpGrace
	if hc.UpGrace > 0 {
		ug = hc.UpGrace
	}
	if ug <= 0 {
		if ug = iv * 2; ug < 1 {
			ug = 1
		}
	}
	return time.Duration(iv) * time.Second, time.Duration(to) * time.Second, time.Duration(ug) * time.Second
}

func listenAddr(port int) string { return ":" + strconv.Itoa(port) }

// derivePeer returns a point-to-point peer / default-route gateway address in prefix,
// distinct from local (macOS utun needs a peer address on the tunnel subnet).
func derivePeer(prefix netip.Prefix, local netip.Addr) netip.Addr {
	peer := prefix.Masked().Addr().Next() // network + 1
	if peer == local {
		peer = peer.Next()
	}
	return peer
}
