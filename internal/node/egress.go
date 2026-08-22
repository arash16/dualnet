package node

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/conn"
	"github.com/arash16/dualnet/internal/egress"
	"github.com/arash16/dualnet/internal/netbind"
	"github.com/arash16/dualnet/internal/netcfg"
	"github.com/arash16/dualnet/internal/tundev"
	"github.com/arash16/dualnet/internal/warp"

	"net/netip"
)

// egressDialKeepAlive enables SO_KEEPALIVE on a direct egress's out sockets so a flow whose
// far end goes silent is detected and torn down rather than leaked.
const egressDialKeepAlive = 30 * time.Second

// boundDialer adapts a physical-interface-bound *net.Dialer to egress.Dialer, so the
// userspace netstack egress dials the internet through a SO_BINDTODEVICE socket.
type boundDialer struct{ d *net.Dialer }

func (b boundDialer) DialTCP(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
	return b.d.DialContext(ctx, "tcp", a.String())
}

func (b boundDialer) DialUDP(a netip.AddrPort) (net.Conn, error) {
	return b.d.Dial("udp", a.String())
}

// buildEgress constructs one named finalizer exit: a userspace WARP netstack, a
// userspace netstack dialed out a bound interface (mode: direct), or the kernel TUN + NAT
// path.
func buildEgress(ctx context.Context, cfg *config.Node, prefix netip.Prefix, name string, eg config.Egress) (egress.Egress, func() error, error) {
	switch eg.Mode {
	case "warp":
		acct, err := warp.Credentials(eg.WARPConfig, eg.WARPCache, eg.WARPInsecure)
		if err != nil {
			return nil, nil, err
		}
		dialer, err := warp.NewDialer(acct, false)
		if err != nil {
			return nil, nil, err
		}
		ns, err := egress.NewNetstack(dialer, cfg.MTU)
		if err != nil {
			_ = dialer.Close()
			return nil, nil, err
		}
		log.Printf("node: egress %q: WARP (assigned %s)", name, acct.V4)
		return ns, func() error { _ = ns.Close(); return dialer.Close() }, nil

	case "direct":
		// Userspace netstack that terminates each flow and re-dials out a socket bound to
		// ext_iface. No kernel tun, no MASQUERADE, no re-injection — so it works even when
		// ext_iface is not the system default (see netcfg.PinIfaceDefault) and does not
		// collide with the capture tun's conntrack.
		//
		// KeepAlive on the out socket detects a vanished *server* (the mirror of the netstack's
		// client-side keepalive), so a flow idle in both directions can't leak — the reason a
		// speedtest could eventually hard-hang the router.
		d := netbind.Dialer(eg.ExtIface)
		d.KeepAlive = egressDialKeepAlive
		ns, err := egress.NewNetstack(boundDialer{d}, cfg.MTU)
		if err != nil {
			return nil, nil, err
		}
		log.Printf("node: egress %q: direct via %s (netstack)", name, eg.ExtIface)
		return ns, func() error { return ns.Close() }, nil

	default: // kernel
		tunName := eg.TunName
		if tunName == "" {
			tunName = "dualnet0"
		}
		dev, err := tundev.Open(tunName, cfg.MTU)
		if err != nil {
			return nil, nil, err
		}
		gw := prefix.Masked().Addr().Next()
		tunTd, err := netcfg.ConfigureTun(netcfg.TunSetup{
			Name: dev.Name(), Local: gw, Peer: derivePeer(prefix, gw), Bits: prefix.Bits(), MTU: cfg.MTU,
		})
		if err != nil {
			_ = dev.Close()
			return nil, nil, err
		}
		natTd, err := netcfg.ConfigureNAT(netcfg.NATSetup{TunName: dev.Name(), Subnet: prefix.Masked(), ExtIface: eg.ExtIface})
		if err != nil {
			_ = tunTd()
			_ = dev.Close()
			return nil, nil, err
		}
		log.Printf("node: egress %q: kernel on %s via %s", name, dev.Name(), eg.ExtIface)
		teardown := func() error {
			_ = natTd()
			_ = tunTd()
			return dev.Close()
		}
		return dev, teardown, nil
	}
}

// warpDialers lazily builds a shared WARP transport dialer for warpped connections;
// non-warpped connections get a per-interface-pinned net dialer.
type warpDialers struct {
	mu     sync.Mutex
	shared conn.SocketDialer
	dialer *warp.Dialer
}

func newWarpDialers() *warpDialers { return &warpDialers{} }

func (w *warpDialers) dialerFor(c config.Connection) (conn.SocketDialer, error) {
	if !c.Warpped {
		return netbind.SourceDialer(c.Interface, c.SourceIP)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.shared == nil {
		acct, err := warp.LoadOrRegister("", false)
		if err != nil {
			return nil, err
		}
		d, err := warp.NewDialer(acct, false)
		if err != nil {
			return nil, err
		}
		w.dialer, w.shared = d, d
	}
	return w.shared, nil
}

func (w *warpDialers) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dialer != nil {
		return w.dialer.Close()
	}
	return nil
}
