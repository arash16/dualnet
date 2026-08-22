//go:build darwin

package netcfg

import (
	"fmt"
	"math/bits"
	"net/netip"
	"strconv"
	"strings"
)

// ConfigureTun brings up a macOS utun. If Local is set it is a point-to-point link
// (local -> peer). A tun with no address is brought up "raw" (no inet, no routes) for an
// external tool. Default-route capture is owned by a Capturer, not here.
func ConfigureTun(t TunSetup) (TeardownFunc, error) {
	if t.Local.IsValid() {
		local := t.Local.String()
		peer := t.Peer.String()
		if err := run("ifconfig", t.Name, "inet", local, peer, "mtu", strconv.Itoa(t.MTU), "up"); err != nil {
			return nil, err
		}
	} else if err := run("ifconfig", t.Name, "mtu", strconv.Itoa(t.MTU), "up"); err != nil {
		return nil, err
	}
	return func() error { return nil }, nil
}

// captureDefault routes all traffic through the tun with two /1 routes (the OpenVPN def1
// trick), leaving the existing default route intact. peer is the tun's point-to-point
// gateway (capture requires an address).
func captureDefault(_ string, peer netip.Addr) (*chain, error) {
	var ch chain
	gw := peer.String()
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run("route", "-n", "add", "-net", cidr, gw); err != nil {
			_ = ch.teardown()
			return nil, err
		}
		c := cidr
		ch.add(func() error { _ = run("route", "-n", "delete", "-net", c, gw); return nil })
	}
	return &ch, nil
}

// PinIfaceDefault, ConfigureLANForward, and DefaultGatewayVia are Linux-router features
// (policy routing + iptables); they are unsupported on macOS.
func PinIfaceDefault(IfaceRoute) (TeardownFunc, error) {
	return nil, fmt.Errorf("netcfg: PinIfaceDefault is only supported on Linux")
}

func ConfigureLANForward(LANForward) (TeardownFunc, error) {
	return nil, fmt.Errorf("netcfg: ConfigureLANForward is only supported on Linux")
}

func DefaultGatewayVia(string) (string, error) {
	return "", fmt.Errorf("netcfg: DefaultGatewayVia is only supported on Linux")
}

// ConfigureSourceAddr adds a host IP alias to an interface (macOS), so an outbound link can
// bind it as its socket source and it answers ARP on-link. A bare ip or an ip/mask both alias
// as a host (netmask 255.255.255.255) — a leg source is a single address, and a host alias
// avoids re-adding a subnet route. The teardown removes the alias.
func ConfigureSourceAddr(s SourceAddr) (TeardownFunc, error) {
	ip := s.Addr
	if i := strings.IndexByte(ip, '/'); i >= 0 {
		ip = ip[:i]
	}
	if err := run("ifconfig", s.Iface, "alias", ip, "255.255.255.255"); err != nil {
		return nil, err
	}
	return func() error { return run("ifconfig", s.Iface, "-alias", ip) }, nil
}

// PinRoutes pins each remote to its physical link via that link's gateway, scoped to
// the interface. Essential once a capture_default tun's 0.0.0.0/1 route overrides each
// link's /0 default: without a still-more-specific scoped /32, the IP_BOUND_IF sockets
// lose their route to their remotes.
func PinRoutes(pins []PinRoute) (TeardownFunc, error) {
	var ch chain
	seen := map[string]bool{}
	for _, p := range pins {
		key := p.Dst + "\x00" + p.Iface
		if p.Iface == "" || seen[key] {
			continue
		}
		seen[key] = true
		// On-link destinations don't need pinning: the interface's own subnet route is
		// more specific than the 0.0.0.0/1 capture, so they stay reachable directly.
		// Pinning them via the gateway would needlessly detour LAN traffic.
		if onLink(p.Iface, p.Dst) {
			continue
		}
		gw, err := interfaceGateway(p.Iface)
		if err != nil {
			_ = ch.teardown()
			return nil, fmt.Errorf("pin route to %s via %s: %w", p.Dst, p.Iface, err)
		}
		if err := run("route", "-n", "add", "-host", p.Dst, gw, "-ifscope", p.Iface); err != nil {
			_ = ch.teardown()
			return nil, err
		}
		dst, ifn := p.Dst, p.Iface
		ch.add(func() error { _ = run("route", "-n", "delete", "-host", dst, "-ifscope", ifn); return nil })
	}
	return ch.teardown, nil
}

// ConfigureNAT is unsupported on macOS (NAT needs Linux iptables); deploy a gateway
// node on Linux.
func ConfigureNAT(NATSetup) (TeardownFunc, error) {
	return nil, fmt.Errorf("netcfg: kernel NAT egress is only supported on Linux; run the gateway node on Linux")
}

// onLink reports whether dst is in iface's own IPv4 subnet (directly reachable), so it
// needs no scoped /32 pin. Parses `ifconfig <iface>` lines like
// "inet 192.168.1.2 netmask 0xffffff00 broadcast 192.168.1.255".
func onLink(iface, dst string) bool {
	d, err := netip.ParseAddr(dst)
	if err != nil {
		return false
	}
	out, err := output("ifconfig", iface)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i := 0; i+3 < len(f); i++ {
			if f[i] != "inet" || f[i+2] != "netmask" {
				continue
			}
			ip, e1 := netip.ParseAddr(f[i+1])
			bits := maskBits(f[i+3])
			if e1 != nil || bits < 0 {
				continue
			}
			if pfx := netip.PrefixFrom(ip, bits).Masked(); pfx.Contains(d) {
				return true
			}
		}
	}
	return false
}

// maskBits converts a hex netmask like "0xffffff00" to a prefix length (24), or -1.
func maskBits(mask string) int {
	if !strings.HasPrefix(mask, "0x") {
		return -1
	}
	v, err := strconv.ParseUint(mask[2:], 16, 32)
	if err != nil {
		return -1
	}
	return bits.OnesCount32(uint32(v))
}

// interfaceGateway returns the IPv4 gateway of a physical interface.
func interfaceGateway(iface string) (string, error) {
	if gw, err := output("ipconfig", "getoption", iface, "router"); err == nil && gw != "" {
		return gw, nil
	}
	out, err := output("route", "-n", "get", "-ifscope", iface, "default")
	if err != nil {
		return "", fmt.Errorf("no gateway for %s", iface)
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			if gw := strings.TrimSpace(strings.TrimPrefix(line, "gateway:")); gw != "" {
				return gw, nil
			}
		}
	}
	return "", fmt.Errorf("no gateway found for %s", iface)
}
