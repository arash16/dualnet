// Package node is dualnet's unified runtime: it turns a config.Node (a list of
// connections + a routing table) into a running set of connections, a routing engine,
// zero or more finalizers (named internet egresses), and condition-driven healthchecks.
// It replaces the old separate client and server run loops — client/router/gateway are
// now just different connection+route+condition configurations of the same node.
package node

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/conn"
	"github.com/arash16/dualnet/internal/egress"
	"github.com/arash16/dualnet/internal/finalizer"
	"github.com/arash16/dualnet/internal/healthcheck"
	"github.com/arash16/dualnet/internal/ipmatch"
	"github.com/arash16/dualnet/internal/netcfg"
	"github.com/arash16/dualnet/internal/pktbuf"
	"github.com/arash16/dualnet/internal/proto"
	"github.com/arash16/dualnet/internal/router"
	"github.com/arash16/dualnet/internal/stats"
	"github.com/arash16/dualnet/internal/tundev"
	"github.com/arash16/dualnet/internal/wire"
)

const (
	sessionTTL = 2 * time.Minute
	gcInterval = 30 * time.Second

	// flushInterval bounds how long a partially-filled write batch waits before the flush group
	// forces it out. Sub-millisecond so a trickled packet adds negligible latency per hop; a full
	// batch flushes immediately regardless.
	flushInterval = 500 * time.Microsecond

	ifacePinBaseTable = 220 // policy-routing table base for PinIfaceDefault

	// finalizerMaxFlows caps a finalizer's concurrently-tracked return flows. With cipher=none an
	// attacker can vary the inner source IP per packet, so this bounds the return-tracking map's
	// memory (~a few MiB at this size) against such a flood; idle entries are GC'd well before it.
	finalizerMaxFlows = 1 << 16
	// maxPeers caps a Multiple listener's tracked downstream peers, bounding the registry against
	// a register flood (spoofed source addresses or distinct claimed ids) from a PSK holder.
	maxPeers = 1 << 16
)

// Options carries test/embedding seams. In production all fields are nil/false and
// the node opens real tun devices, builds real egresses, and applies OS network
// config; tests inject fakes and skip the OS config.
type Options struct {
	// OpenTun, if set, builds a tun device instead of tundev.Open. When set, OS
	// network configuration (tun addr/routes, NAT, iface pins, capture) is skipped.
	OpenTun func(name string, mtu int) (conn.TunDevice, error)
	// Egress, if set, is wrapped by a finalizer for every named egress not covered by
	// Egresses, instead of building a real egress.
	Egress egress.Egress
	// Egresses injects a specific egress backend per name (overrides Egress for that name).
	Egresses map[string]egress.Egress
}

// Runtime adapts a userspace (packet-router) node config to the common Run(ctx) shape shared
// with kernelnode.Runtime, so main can dispatch on datapath through one interface.
type Runtime struct {
	cfg *config.Node
	opt Options
}

// New builds a userspace node runtime from its config and embedding seams.
func New(cfg *config.Node, opt Options) *Runtime { return &Runtime{cfg: cfg, opt: opt} }

// Run builds and runs the node until ctx is cancelled or a fatal error occurs.
func (r *Runtime) Run(ctx context.Context) error { return RunWith(ctx, r.cfg, r.opt) }

// RunWith builds and runs a node with injectable seams (see Options), until ctx is cancelled
// or a fatal error occurs.
func RunWith(ctx context.Context, cfg *config.Node, opt Options) error {
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		return err
	}
	prefix, err := cfg.Prefix()
	if err != nil {
		return err
	}

	// Stats: enabled only when an output file is configured. When disabled, reg stays nil
	// and no instrumentation is wired below, so the packet hot path carries zero overhead.
	var reg *stats.Registry
	if cfg.StatsFile != "" {
		connNames := make([]string, 0, len(cfg.Connections))
		for _, c := range cfg.Connections {
			connNames = append(connNames, c.Name)
		}
		reg = stats.New(connNames)
	}

	skipOS := opt.OpenTun != nil
	openTun := opt.OpenTun
	if openTun == nil {
		openTun = func(name string, mtu int) (conn.TunDevice, error) { return tundev.Open(name, mtu) }
	}
	var td teardown
	defer td.run()

	// One node-wide group flushes every buffered write batch (tun downlink, connect-out carriers,
	// listen-out peers, egress inject) on a short interval so a partial batch is never stuck. It is
	// started now; connections register their writers with it as they are built.
	flushGroup := pktbuf.NewFlushGroup(flushInterval)
	go flushGroup.Run(ctx)

	// Finalizers: one per named egress referenced by a finalize rule. Tests may inject an
	// egress backend per name (Egresses) or a shared one (Egress); otherwise build real.
	used := egressesUsed(cfg)
	injected := opt.Egress != nil || len(opt.Egresses) > 0
	finalizers := map[string]*finalizer.Finalizer{}
	var runFins []*finalizer.Finalizer
	for name := range used {
		var (
			eg   egress.Egress
			egTd func() error
		)
		if injected {
			if e, ok := opt.Egresses[name]; ok {
				eg = e
			} else {
				eg = opt.Egress
			}
			if eg == nil {
				return fmt.Errorf("node: no injected egress for %q", name)
			}
		} else {
			var err error
			eg, egTd, err = buildEgress(ctx, cfg, prefix, name, cfg.Egresses[name])
			if err != nil {
				return err
			}
			td.add(egTd)
		}
		f := finalizer.New(eg, sessionTTL, finalizerMaxFlows, flushGroup)
		finalizers[name] = f
		runFins = append(runFins, f)
	}
	if reg != nil {
		for _, f := range runFins {
			// Reply-path sends bypass the router; count them against their target connection.
			f.SetSentHook(func(target string, n int) { reg.Sent(target, n) })
		}
	}

	// Direct egresses (and their co-bound carriers) live on non-default interfaces; give
	// each a policy-routing table so their SO_BINDTODEVICE sockets can reach the internet.
	if !skipOS {
		if err := pinDirectEgressIfaces(cfg, used, &td); err != nil {
			return err
		}
		// Source addresses a link binds (dialer_source with an ip): create them on their
		// device before any connection dials, so LocalAddr binding and on-link ARP work.
		for _, sa := range sourceAddrs(cfg) {
			satd, err := netcfg.ConfigureSourceAddr(sa)
			if err != nil {
				return fmt.Errorf("node: source address %s on %s: %w", sa.Addr, sa.Iface, err)
			}
			td.add(satd)
		}
	}

	// Scoped route pinning to off-link remotes before a tun captures the default (macOS).
	if !skipOS && capturesDefault(cfg) {
		pinTd, err := netcfg.PinRoutes(pinRoutes(cfg))
		if err != nil {
			return err
		}
		td.add(pinTd)
	}

	// Tun connections first: other connections' id_setters reference them.
	pending := pendingTuns(cfg)
	tuns := map[string]*conn.TunConn{}
	conns := map[string]conn.Conn{}
	var order []conn.Conn
	reconnecters := map[string]healthcheck.Reconnecter{}
	var maintainers []conn.Maintainer
	var capturer *netcfg.Capturer

	for _, c := range cfg.Connections {
		if c.Type != "tun" {
			continue
		}
		dev, err := openTun(c.Interface, cfg.MTU)
		if err != nil {
			return err
		}
		tc := conn.NewTun(c.Name, dev, randomOwner(), pending[c.Name], flushGroup)
		tuns[c.Name] = tc
		conns[c.Name] = tc
		order = append(order, tc)
		if !skipOS {
			devName := dev.(interface{ Name() string }).Name()
			setup := netcfg.TunSetup{Name: devName, Bits: prefix.Bits(), MTU: cfg.MTU}
			if c.Address != "" {
				local, err := netip.ParseAddr(c.Address)
				if err != nil {
					_ = dev.Close()
					return err
				}
				setup.Local = local
				setup.Peer = derivePeer(prefix, local)
			}
			tunTd, err := netcfg.ConfigureTun(setup)
			if err != nil {
				_ = dev.Close()
				return err
			}
			td.add(tunTd)
			if c.CaptureDefault {
				capturer = netcfg.NewCapturer(devName, setup.Peer)
				td.add(capturer.Release)
				if c.LANIface != "" {
					lfTd, err := netcfg.ConfigureLANForward(netcfg.LANForward{LANIface: c.LANIface, TunName: devName})
					if err != nil {
						return err
					}
					td.add(lfTd)
				}
			}
		}
		log.Printf("node: tun %s up", c.Name)
	}

	// Non-tun connections.
	var onDrop func()
	if reg != nil {
		onDrop = reg.DecodeDrop
	}
	warp := newWarpDialers()
	td.add(warp.close)
	for _, c := range cfg.Connections {
		if c.Type == "tun" {
			continue
		}
		kind := kindOf(c)
		spec := conn.Spec{
			Name: c.Name, Kind: kind, Transport: c.Transport, Cipher: c.Cipher,
			HTTP: httpParams(c.HTTP),
			Key:  c.Key(cfg.PSK), RemoteIP: c.IP, Port: c.Port, Iface: c.Interface,
			Multiple: c.Multiple, SessionTTL: sessionTTL, MaxPeers: maxPeers, MaxAge: proto.UpstreamMaxAge,
			Listen: listenAddr(c.Port), OnDrop: onDrop, Flush: flushGroup,
		}
		if kind == conn.KindConnectOut || kind == conn.KindConnectIn {
			d, err := warp.dialerFor(c)
			if err != nil {
				return err
			}
			spec.Dialer = d
		}
		if kind == conn.KindConnectIn && c.IDSetter != "" {
			if tc := tuns[c.IDSetter]; tc != nil {
				spec.IDSetter = tc.SetID
			}
		}
		cc, err := conn.New(ctx, spec)
		if err != nil {
			return err
		}
		conns[c.Name] = cc
		order = append(order, cc)
		if rc, ok := cc.(healthcheck.Reconnecter); ok {
			reconnecters[c.Name] = rc
		}
		if m, ok := cc.(conn.Maintainer); ok {
			maintainers = append(maintainers, m)
		}
	}

	// Condition guards: dst_in prefix files and healthcheck liveness. Healthcheck
	// conditions also build (but do not yet start) a Driver that probes their up-path.
	conditions := map[string]router.Guard{}
	var reloaders []setReloader
	var drivers []*healthcheck.Driver
	for _, c := range cfg.Conditions {
		if c.DstIn != nil {
			// A list-based set is static (no file to watch); a file-based set is reloadable.
			if len(c.DstIn.List) > 0 {
				m, err := ipmatch.LoadList(c.DstIn.List)
				if err != nil {
					return fmt.Errorf("node: dst_in condition %q: %w", c.Name, err)
				}
				conditions[c.Name] = dstGuard{m}
				continue
			}
			m, err := ipmatch.Open(c.DstIn.File)
			if err != nil {
				return err
			}
			if m.Size() == 0 {
				log.Printf("node: dst_in condition %q (%s) is empty — rules using it always fall through", c.Name, c.DstIn.File)
			}
			conditions[c.Name] = dstGuard{m}
			reloaders = append(reloaders, setReloader{c.Name, m, time.Duration(c.DstIn.Reload) * time.Second})
			continue
		}
		hc := c.Healthcheck
		state := &atomic.Bool{}
		conditions[c.Name] = healthGuard{state}
		tc := tuns[hc.Tun]
		if hc.Tun == "" {
			for _, t := range tuns {
				tc = t
			}
		}
		via, _ := conns[hc.Up[0]].(conn.Sender)
		if via == nil || tc == nil {
			return fmt.Errorf("node: healthcheck condition %q: up[0] %q must be a sending connection and tun %q must exist", c.Name, hc.Up[0], hc.Tun)
		}
		interval, timeout, upGrace := condTiming(cfg, hc)
		state.Store(false)
		condName := c.Name
		probe := func(ping []byte) {
			if id, ok := tc.ID(); ok {
				// A buffering carrier holds the ping until the flush group's tick (sub-ms) emits it,
				// far inside the healthcheck's seconds-scale timeout; a direct carrier sends it now.
				_, _ = via.Send(wire.Envelope{Owner: id}, ping)
			}
		}
		onHealth := func(h bool) { state.Store(h); log.Printf("node: healthcheck %q → %v", condName, h) }
		// Reconnect only THIS path's connections on silence — not every dialed connection on the
		// node — so one path's outage doesn't tear down another path's healthy carriers.
		drv := healthcheck.New(interval, timeout, upGrace, probe, pathLinks(hc, reconnecters), onHealth)
		tc.SetHooks(drv.Seen, drv.SentData)
		drivers = append(drivers, drv)
	}

	// Router over the compiled routing table.
	sources := make([]string, 0, len(conns))
	for name := range conns {
		sources = append(sources, name)
	}
	finalizeFuncs := make(map[string]router.FinalizeFunc, len(finalizers))
	for name, f := range finalizers {
		finalizeFuncs[name] = f.Submit
	}
	rt, err := router.Compile(compileRules(cfg), conns, sources, conditions, finalizeFuncs)
	if err != nil {
		return err
	}
	for _, w := range rt.Warnings {
		log.Printf("node: routing warning: %s", w)
	}
	// Start receiving/serving. Each connection gets an intake bound to its own source, so the
	// per-packet path indexes its compiled target list directly instead of hashing the source
	// name on every packet. When stats are on, the wrapper also counts each received data
	// packet (and its bytes) against that source connection.
	if reg != nil {
		reg.SetRoutes(rt.Labels())
		rt.SetRecorder(statsRecorder{reg})
	}
	for _, cc := range order {
		if err := cc.Start(ctx, boundIngress(rt, cc.Name(), reg)); err != nil {
			return err
		}
		td.add(cc.Close)
	}
	for _, f := range runFins {
		f := f
		go func() {
			if err := f.Run(ctx); err != nil {
				log.Printf("node: finalizer: %v", err)
			}
		}()
	}

	// Stats reporter (optional).
	if reg != nil {
		statsEvery := time.Duration(cfg.StatsInterval) * time.Second
		maxBytes := int64(cfg.StatsMaxMB) * 1024 * 1024
		log.Printf("node: writing stats to %s every %s (rotate at %dMiB)", cfg.StatsFile, statsEvery, cfg.StatsMaxMB)
		go func() {
			if err := reg.Run(ctx, cfg.StatsFile, statsEvery, maxBytes); err != nil {
				log.Printf("node: stats: %v", err)
			}
		}()
	}

	// Healthcheck drivers (one per healthcheck condition; run regardless of whether a rule
	// references the condition).
	for _, drv := range drivers {
		go drv.Run(ctx)
	}

	// Hot-reload dst_in prefix files on SIGHUP and, for those with reload>0, periodically.
	startSetReload(ctx, reloaders)

	log.Printf("node: up — %d connection(s), %d route(s), %d egress(es)", len(cfg.Connections), len(cfg.Routes), len(finalizers))

	// GC idle peers / finalizer flows.
	go gcLoop(ctx, runFins, maintainers)

	// Now that everything is running, let the capture tun take the default route. Doing it
	// last means the original (Starlink) default stays intact until dualnet can actually
	// route; a crash later drops the tun and the kernel restores that default.
	if capturer != nil {
		if err := capturer.Capture(); err != nil {
			log.Printf("node: capture default route: %v (leaving original default in place)", err)
		} else {
			log.Printf("node: captured default route")
		}
	}

	<-ctx.Done()
	return nil
}

// pinDirectEgressIfaces installs a policy-routing table per distinct direct-egress
// interface so bound sockets on non-default links reach the internet.
func pinDirectEgressIfaces(cfg *config.Node, used map[string]bool, td *teardown) error {
	seen := map[string]bool{}
	table := ifacePinBaseTable
	for name := range used {
		eg := cfg.Egresses[name]
		if eg.Mode != "direct" || eg.ExtIface == "" || seen[eg.ExtIface] {
			continue
		}
		seen[eg.ExtIface] = true
		pinTd, err := netcfg.PinIfaceDefault(netcfg.IfaceRoute{
			Iface: eg.ExtIface, Gateway: eg.Gateway, Table: table, Prio: table,
		})
		if err != nil {
			return err
		}
		td.add(pinTd)
		table++
	}
	return nil
}

// sourceAddrs returns the distinct source addresses a node's connections bind (a link with a
// dialer_source that carries an ip), each paired with the device to create it on. dualnet
// assigns these so the socket can source from the address and it is ARP-reachable on-link.
func sourceAddrs(cfg *config.Node) []netcfg.SourceAddr {
	seen := map[string]bool{}
	var out []netcfg.SourceAddr
	for _, c := range cfg.Connections {
		if c.SourceIP == "" || c.Interface == "" {
			continue
		}
		key := c.SourceIP + "\x00" + c.Interface
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, netcfg.SourceAddr{Addr: c.SourceIP, Iface: c.Interface})
	}
	return out
}

// setReloader ties a dst_in condition's reloadable matcher to its periodic-reload cadence.
type setReloader struct {
	name  string
	m     *ipmatch.Reloadable
	every time.Duration // 0 = SIGHUP-only
}

// startSetReload wires SIGHUP-triggered and (per condition) periodic reloads of dst_in files.
func startSetReload(ctx context.Context, reloaders []setReloader) {
	if len(reloaders) == 0 {
		return
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
				for _, r := range reloaders {
					if err := r.m.Reload(); err != nil {
						log.Printf("node: reload %q: %v (keeping previous)", r.name, err)
					} else {
						log.Printf("node: reloaded %q (%d prefixes)", r.name, r.m.Size())
					}
				}
			}
		}
	}()
	for _, r := range reloaders {
		if r.every <= 0 {
			continue
		}
		r := r
		go func() {
			t := time.NewTicker(r.every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := r.m.Reload(); err != nil {
						log.Printf("node: reload %q: %v (keeping previous)", r.name, err)
					}
				}
			}
		}()
	}
}

func gcLoop(ctx context.Context, fins []*finalizer.Finalizer, ms []conn.Maintainer) {
	t := time.NewTicker(gcInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, f := range fins {
				f.GC()
			}
			for _, m := range ms {
				m.GC()
			}
		}
	}
}

// boundIngress builds a connection's intake, bound once to its own source so routing skips
// the per-packet source-name lookup. reg (may be nil) counts each received packet's bytes
// against the source. A source with no routing rules (SourceRouter returns nil) falls back to
// the generic Route, which simply drops — packets still get counted for stats.
func boundIngress(rt *router.Router, name string, reg *stats.Registry) conn.Ingress {
	bound := rt.SourceRouter(name)
	switch {
	case bound != nil && reg != nil:
		return func(_ string, e wire.Envelope, p []byte) { reg.Recv(name, len(p)); bound(e, p) }
	case bound != nil:
		return func(_ string, e wire.Envelope, p []byte) { bound(e, p) }
	case reg != nil:
		return func(src string, e wire.Envelope, p []byte) { reg.Recv(src, len(p)); rt.Route(src, e, p) }
	default:
		return rt.Route
	}
}

// statsRecorder adapts the stats registry to the router's Recorder interface.
type statsRecorder struct{ reg *stats.Registry }

func (s statsRecorder) Routed(label string)       { s.reg.Route(label) }
func (s statsRecorder) Sent(target string, n int) { s.reg.Sent(target, n) }
func (s statsRecorder) Dropped(string)            { s.reg.NoRouteDrop() }

func randomOwner() wire.Owner {
	for {
		var o wire.Owner
		_, _ = rand.Read(o[:])
		if !o.IsZero() {
			return o
		}
	}
}
