//go:build linux

package kernelnode

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/arash16/dualnet/internal/netcfg"
	"github.com/arash16/dualnet/internal/warp"
)

// Run resolves each egress's WAN next-hop, lowers the config into policy routing + iptables,
// applies it, then keeps it applied — reloading dst_in geo sets on SIGHUP (and on any per-set
// interval) — until ctx is cancelled, at which point everything is torn down in reverse.
func (r *Runtime) Run(ctx context.Context) error {
	// WARP devices come up first: account registration / endpoint DNS need the box's native
	// routing (apply() rewires it), and the plan's routes reference the devices. The LIFO
	// defers tear down in reverse — routes first, links last.
	eps, devTd, err := r.setupWarpDevices()
	if err != nil {
		return err
	}
	defer func() { _ = devTd() }()
	wans, err := r.resolveWANs(eps)
	if err != nil {
		return err
	}
	p, err := lower(r.cfg, wans)
	if err != nil {
		return err
	}
	td, err := r.apply(p)
	if err != nil {
		return err
	}
	defer func() { _ = td() }()

	log.Printf("kernelnode: up — %d egress(es), %d rule(s), %d geo set(s), lan %v",
		len(r.cfg.Egresses), len(p.rules), len(p.geo), r.cfg.LANIfaces)

	// Dynamic from day one: dst_in geo sets reload on SIGHUP and on any per-set interval, so the
	// forwarding plane tracks a changing prefix list without a restart. (A future response-speed
	// auto-planner would re-lower and swap the rule chain here the same way.)
	r.watchReload(ctx, p)
	<-ctx.Done()
	return nil
}

// resolveWANs finds each egress's next-hop from the current routing table. A WAN with no
// detectable default gateway (a point-to-point PPPoE link, or one that is not the system
// default) is routed dev-only, which PPP handles and an on-link WAN tolerates. A warp
// egress's next-hop is its WireGuard device (point-to-point); its exit iface + gateway
// realize only the endpoint pin's underlay.
func (r *Runtime) resolveWANs(warpEndpoints map[string]netip.Addr) (map[string]wan, error) {
	out := make(map[string]wan, len(r.cfg.Egresses))
	for name, eg := range r.cfg.Egresses {
		gw := eg.Gateway // explicit next-hop wins (a multi-homed WAN that is not the default)
		if gw == "" {
			var err error
			if gw, err = netcfg.DefaultGatewayVia(eg.ExtIface); err != nil {
				gw = ""
				log.Printf("kernelnode: egress %q (%s): no default gateway found, routing dev-only", name, eg.ExtIface)
			}
		}
		if eg.Mode == "warp" {
			out[name] = wan{dev: eg.TunName, ep: &underlayRoute{ip: warpEndpoints[name].String(), dev: eg.ExtIface, gw: gw}}
			continue
		}
		out[name] = wan{dev: eg.ExtIface, gw: gw}
	}
	return out, nil
}

// setupWarpDevices brings up a kernel WireGuard device per mode:warp egress (sorted for
// determinism) and returns each egress's resolved endpoint plus a teardown that deletes the
// links.
func (r *Runtime) setupWarpDevices() (map[string]netip.Addr, netcfg.TeardownFunc, error) {
	eps := map[string]netip.Addr{}
	var ch chain
	for _, name := range sortedKeys(r.cfg.Egresses) {
		eg := r.cfg.Egresses[name]
		if eg.Mode != "warp" {
			continue
		}
		acct, err := warp.Credentials(eg.WARPConfig, eg.WARPCache, eg.WARPInsecure)
		if err != nil {
			_ = ch.teardown()
			return nil, nil, fmt.Errorf("kernelnode: egress %q: %w", name, err)
		}
		ep, td, err := warp.SetupKernelDevice(eg.TunName, acct, r.cfg.MTU)
		if err != nil {
			_ = ch.teardown()
			return nil, nil, fmt.Errorf("kernelnode: egress %q: %w", name, err)
		}
		ch.add(td)
		eps[name] = ep
		log.Printf("kernelnode: egress %q: WARP device %s up (assigned %s, endpoint %s via %s)",
			name, eg.TunName, acct.V4, ep, eg.ExtIface)
	}
	return eps, ch.teardown, nil
}

// apply installs the plan and returns a teardown that reverses it. It is idempotent: routing
// tables are flushed and rules/routes deleted before being (re)added, so a crash-leaked prior
// programming is reasserted cleanly.
func (r *Runtime) apply(p *plan) (netcfg.TeardownFunc, error) {
	var ch chain

	// Enable forwarding, restoring the previous value on teardown only if we changed it.
	prev, _ := os.ReadFile(ipForwardPath)
	if strings.TrimSpace(string(prev)) != "1" {
		if err := setIPForward("1"); err != nil {
			return nil, err
		}
		if pv := strings.TrimSpace(string(prev)); pv != "" {
			ch.add(func() error { return setIPForward(pv) })
		}
	}

	// Flush our tables first (leak cleanup) and again on teardown.
	for _, t := range p.tables {
		ts := strconv.Itoa(t)
		_ = run("ip", "route", "flush", "table", ts)
		ch.add(func() error { return run("ip", "route", "flush", "table", ts) })
	}
	// Default-table routes live in the flushed tables, so no per-route teardown is needed.
	for _, rt := range p.tableRoutes {
		if err := run(rt...); err != nil {
			_ = ch.teardown()
			return nil, err
		}
	}
	// On-link return routes live in the main table: delete a leak, add, and undo individually.
	for _, rt := range p.mainRoutes {
		_ = run(withVerb(rt, "del")...)
		if err := run(rt...); err != nil {
			_ = ch.teardown()
			return nil, err
		}
		del := withVerb(rt, "del")
		ch.add(func() error { return run(del...) })
	}
	// ip rules: delete a leak at each priority, add, and undo individually.
	for _, ru := range p.rules {
		_ = run(withVerb(ru, "del")...)
		if err := run(ru...); err != nil {
			_ = ch.teardown()
			return nil, err
		}
		del := withVerb(ru, "del")
		ch.add(func() error { return run(del...) })
	}
	// iptables MASQUERADE/FORWARD: delete a crash-leaked copy first, then add — mirroring the
	// ip route/rule loops above — so a re-apply after an ungraceful exit does not stack a second
	// identical rule that teardown's single -D would leave behind.
	for _, ipt := range p.iptables {
		del := iptablesCmd(flipAppendToDelete(ipt))
		_ = run(del...)
		if err := run(iptablesCmd(ipt)...); err != nil {
			_ = ch.teardown()
			return nil, err
		}
		ch.add(func() error { return run(del...) })
	}
	// Geo sets (bulk-loaded via ip -batch); their tables are already registered for flush.
	for _, g := range p.geo {
		if err := r.loadGeo(g); err != nil {
			_ = ch.teardown()
			return nil, err
		}
	}
	return ch.teardown, nil
}

// loadGeo (re)loads one dst_in geo set: flush its table, then bulk-add its prefix routes in a
// single `ip -batch` process (2k routes as 2k execs would crawl on a slow router).
func (r *Runtime) loadGeo(g geoBinding) error {
	// Serialize reloads so a SIGHUP-triggered reload and a per-set interval reload never
	// interleave their flush/batch-add on the same table.
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()
	ts := strconv.Itoa(g.table)
	// Ignore the flush error: on the first load the geo table does not exist yet (a FIB table
	// exists only once it holds a route), and `ip route flush table N` then exits non-zero with
	// "FIB table does not exist" — benign, there is nothing to clear. apply() ignores the same
	// error for the same reason; not ignoring it here crashes a kernel node that has a dst_in set.
	_ = run("ip", "route", "flush", "table", ts)
	prefixes, err := readPrefixes(g.set)
	if err != nil {
		return err
	}
	if len(prefixes) == 0 {
		log.Printf("kernelnode: geo set %q is empty — its branch matches nothing", g.cond)
		return nil
	}
	var b strings.Builder
	for _, pfx := range prefixes {
		// Each batch line is an ip command without the leading "ip".
		b.WriteString(strings.Join(geoRoute(pfx, g.wan, g.table)[1:], " "))
		b.WriteByte('\n')
	}
	return runBatch(b.String())
}

// watchReload wires SIGHUP-triggered and per-set interval reloads of the dst_in geo sets.
func (r *Runtime) watchReload(ctx context.Context, p *plan) {
	if len(p.geo) == 0 {
		return
	}
	reloadAll := func() {
		for _, g := range p.geo {
			if err := r.loadGeo(g); err != nil {
				log.Printf("kernelnode: reload %q: %v (keeping previous)", g.cond, err)
			} else {
				log.Printf("kernelnode: reloaded %q", g.cond)
			}
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	go func() {
		defer signal.Stop(sig)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				reloadAll()
			}
		}
	}()
	for _, g := range p.geo {
		if g.set.Reload <= 0 {
			continue
		}
		g := g
		go func() {
			t := time.NewTicker(time.Duration(g.set.Reload) * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := r.loadGeo(g); err != nil {
						log.Printf("kernelnode: reload %q: %v (keeping previous)", g.cond, err)
					}
				}
			}
		}()
	}
}

// --- OS primitives (small, package-local; DefaultGatewayVia is reused from netcfg) ----------

const ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// run executes a command, folding its combined output into any error for diagnosability.
func run(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

// runBatch feeds newline-separated ip commands to a single `ip -batch -` process.
func runBatch(input string) error {
	cmd := exec.Command("ip", "-batch", "-")
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip -batch: %v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// setIPForward writes the ip_forward proc file directly (the minimal runtime image has no
// sysctl binary).
func setIPForward(v string) error {
	if err := os.WriteFile(ipForwardPath, []byte(v), 0o644); err != nil {
		return fmt.Errorf("kernelnode: set %s=%s: %w", ipForwardPath, v, err)
	}
	return nil
}

var (
	iptablesWaitOnce sync.Once
	iptablesWait     bool
)

// iptablesSupportsWait probes whether this host's iptables understands -w (absent on a busybox
// 1.4.17); dualnet's calls are sequential, so losing the lock-wait is harmless.
func iptablesSupportsWait() bool {
	iptablesWaitOnce.Do(func() { iptablesWait = run("iptables", "-w", "-t", "filter", "-S") == nil })
	return iptablesWait
}

// iptablesCmd prepends the iptables binary (and -w when supported) to a rule tail.
func iptablesCmd(rule []string) []string {
	if iptablesSupportsWait() {
		return append([]string{"iptables", "-w"}, rule...)
	}
	return append([]string{"iptables"}, rule...)
}

// chain collects undo steps and runs them in reverse on teardown, past individual failures.
type chain struct{ steps []func() error }

func (c *chain) add(f func() error) { c.steps = append(c.steps, f) }

func (c *chain) teardown() error {
	var firstErr error
	for i := len(c.steps) - 1; i >= 0; i-- {
		if err := c.steps[i](); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
