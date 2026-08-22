//go:build linux

package netcfg

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
)

// iptablesWait caches whether this host's iptables understands -w (wait for the xtables
// lock). It was added in iptables 1.4.20; an old build (e.g. a busybox router's 1.4.17)
// rejects it with `unknown option "-w"`. We probe once with a benign list and omit -w when
// unsupported — dualnet's iptables calls are sequential, so losing the lock-wait is harmless.
var (
	iptablesWaitOnce sync.Once
	iptablesWait     bool
)

func iptablesSupportsWait() bool {
	iptablesWaitOnce.Do(func() { iptablesWait = run("iptables", "-w", "-t", "filter", "-S") == nil })
	return iptablesWait
}

// iptablesCmd builds an iptables invocation for rule, prepending -w only when supported.
func iptablesCmd(rule []string) []string {
	if iptablesSupportsWait() {
		return append([]string{"iptables", "-w"}, rule...)
	}
	return append([]string{"iptables"}, rule...)
}

// setIPForward toggles IPv4 forwarding by writing the proc file directly rather than shelling
// out to `sysctl`, which a minimal runtime image (the deploy/k8s Dockerfile ships only
// iproute2 + iptables) does not include — a missing sysctl otherwise crashes kernel egress.
func setIPForward(v string) error {
	const p = "/proc/sys/net/ipv4/ip_forward"
	if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
		return fmt.Errorf("netcfg: set %s=%s: %w", p, v, err)
	}
	return nil
}

// ConfigureTun sets the tun's MTU and brings it up; if Local is set it also assigns the
// address. A tun with no address is left "raw" (device up, no addressing/routing) for an
// external tool to manage. Default-route capture is owned by a Capturer, not here.
// Per-link egress for the node's own sockets is handled by SO_BINDTODEVICE (netbind).
func ConfigureTun(t TunSetup) (TeardownFunc, error) {
	if t.Local.IsValid() {
		addr := t.Local.String() + "/" + strconv.Itoa(t.Bits)
		if err := run("ip", "addr", "add", addr, "dev", t.Name); err != nil {
			return nil, err
		}
	}
	if err := run("ip", "link", "set", t.Name, "mtu", strconv.Itoa(t.MTU), "up"); err != nil {
		return nil, err
	}
	return func() error { return nil }, nil
}

// EnsureWireGuardLink (re)creates a kernel WireGuard link: best-effort modprobe (a container
// cannot load modules, which is fine when the host already did), delete a crash-leaked link of
// the same name, then `ip link add`. The add's error is authoritative — "Operation not
// supported" means the host kernel lacks the wireguard module. The teardown deletes the link,
// which removes its address and any routes through it.
func EnsureWireGuardLink(name string) (TeardownFunc, error) {
	_ = run("modprobe", "wireguard")
	_ = run("ip", "link", "del", "dev", name)
	if err := run("ip", "link", "add", "dev", name, "type", "wireguard"); err != nil {
		return nil, fmt.Errorf("netcfg: create wireguard link %s (does the host kernel provide the wireguard module?): %w", name, err)
	}
	return func() error { return run("ip", "link", "del", "dev", name) }, nil
}

// captureDefault installs the def1 0.0.0.0/1 + 128.0.0.0/1 routes into dev (they shadow,
// never delete, the original default). `replace` tolerates a pre-existing route so a
// crash-leaked capture is reasserted cleanly. peer is unused on Linux.
func captureDefault(dev string, _ netip.Addr) (*chain, error) {
	var ch chain
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run("ip", "route", "replace", cidr, "dev", dev); err != nil {
			_ = ch.teardown()
			return nil, err
		}
		c := cidr
		ch.add(func() error { _ = run("ip", "route", "del", c, "dev", dev); return nil })
	}
	return &ch, nil
}

// PinRoutes is a no-op on Linux (SO_BINDTODEVICE handles per-link egress).
func PinRoutes([]PinRoute) (TeardownFunc, error) {
	return func() error { return nil }, nil
}

// PinIfaceDefault gives sockets bound to r.Iface a route to the internet via a dedicated
// policy-routing table, so a direct egress (and pinned carriers) on a non-default
// interface can reach out. Idempotent: it flushes the table and deletes a stale rule at
// the given priority first, so a crash-leaked pin is reasserted cleanly.
func PinIfaceDefault(r IfaceRoute) (TeardownFunc, error) {
	tbl := strconv.Itoa(r.Table)
	prio := strconv.Itoa(r.Prio)
	var ch chain

	_ = run("ip", "route", "flush", "table", tbl) // clear any crash leftover
	// Resolve the next-hop when the egress didn't specify one. A broadcast WAN (e.g. Starlink
	// on a regular NIC) MUST route via a gateway — a plain `default dev X` can only reach the
	// on-link subnet, so off-link/internet traffic (incl. DNS) black-holes. A point-to-point
	// link (PPPoE) has no gateway: DefaultGatewayVia errors there and we route dev-only, which
	// PPP handles. Detected from the main table's default before the capture tun shadows it.
	gw := r.Gateway
	if gw == "" {
		if g, err := DefaultGatewayVia(r.Iface); err == nil && g != "" {
			gw = g
		}
	}
	route := []string{"ip", "route", "replace", "default"}
	if gw != "" {
		route = append(route, "via", gw)
	}
	route = append(route, "dev", r.Iface, "table", tbl)
	if err := run(route...); err != nil {
		return nil, err
	}
	ch.add(func() error { return run("ip", "route", "flush", "table", tbl) })

	_ = run("ip", "rule", "del", "priority", prio) // clear any crash leftover at this prio
	if err := run("ip", "rule", "add", "priority", prio, "oif", r.Iface, "lookup", tbl); err != nil {
		_ = ch.teardown()
		return nil, err
	}
	ch.add(func() error { return run("ip", "rule", "del", "priority", prio, "oif", r.Iface, "lookup", tbl) })
	return ch.teardown, nil
}

// lanForwardRules is the iptables rule set for forwarding a LAN interface into a capture
// tun: accept the forward both ways, SNAT LAN hosts to the tun's own address, and MSS-clamp
// TCP crossing the tun to the path MTU.
//
// The MASQUERADE is essential and was the source of a "gateway works from the router itself
// but not from LAN clients" bug. Every flow entering the capture tun must present a source
// inside the mesh subnet: a gateway finalizes tunneled traffic through a kernel egress whose
// MASQUERADE is scoped to that subnet AND whose return route into the gateway tun only
// matches that subnet (the finalizer keys replies by inner dst IP). A LAN host's real source
// (e.g. 192.168.1.x) satisfies neither, so its reply black-holes at the gateway — while the
// router's own traffic (already sourced from the tun address) works. `-o <tun>` masquerades
// to the tun's address; the router's own already-in-subnet traffic is a no-op. A direct
// egress (netstack) re-originates the flow and is unaffected; return traffic the finalizer
// writes back into the tun is un-SNATed by conntrack before it forwards out to the LAN.
func lanForwardRules(l LANForward) [][]string {
	return [][]string{
		{"-A", "FORWARD", "-i", l.LANIface, "-o", l.TunName, "-j", "ACCEPT"},
		{"-A", "FORWARD", "-i", l.TunName, "-o", l.LANIface, "-j", "ACCEPT"},
		{"-t", "nat", "-A", "POSTROUTING", "-o", l.TunName, "-j", "MASQUERADE"},
		{"-t", "mangle", "-A", "FORWARD", "-o", l.TunName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		{"-t", "mangle", "-A", "FORWARD", "-i", l.TunName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
	}
}

// ConfigureLANForward enables forwarding of a LAN interface's traffic into a capture tun,
// SNATs it to the tun's inner address (see lanForwardRules), and MSS-clamps TCP crossing
// the tun to the path MTU.
func ConfigureLANForward(l LANForward) (TeardownFunc, error) {
	var ch chain
	// Enable forwarding, only writing (and later restoring) it if not already on.
	prev, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if prevVal := strings.TrimSpace(string(prev)); prevVal != "1" {
		if err := setIPForward("1"); err != nil {
			return nil, err
		}
		if prevVal != "" {
			ch.add(func() error { return setIPForward(prevVal) })
		}
	}
	for _, r := range lanForwardRules(l) {
		if err := run(iptablesCmd(r)...); err != nil {
			_ = ch.teardown()
			return nil, err
		}
		del := iptablesCmd(r)
		for i, a := range del {
			if a == "-A" {
				del[i] = "-D"
			}
		}
		ch.add(func() error { return run(del...) })
	}
	return ch.teardown, nil
}

// ConfigureSourceAddr assigns a source address to a device so an outbound link can bind it as
// its socket source and it answers ARP on-link. Idempotent (`ip addr replace` tolerates a
// crash-leaked address); the teardown removes it. A bare ip is treated as a host /32.
func ConfigureSourceAddr(s SourceAddr) (TeardownFunc, error) {
	cidr := s.Addr
	if !strings.ContainsRune(cidr, '/') {
		cidr += "/32"
	}
	if err := run("ip", "addr", "replace", cidr, "dev", s.Iface); err != nil {
		return nil, err
	}
	return func() error { return run("ip", "addr", "del", cidr, "dev", s.Iface) }, nil
}

// DefaultGatewayVia returns the next-hop for the default route via iface, "" for a
// point-to-point link (no via, e.g. PPPoE), or an error if there is no default via iface.
func DefaultGatewayVia(iface string) (string, error) {
	out, err := output("ip", "-o", "-4", "route", "show", "default", "dev", iface)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(out) == "" {
		return "", fmt.Errorf("netcfg: no default route via %s", iface)
	}
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", nil // point-to-point default: no via
}

// ConfigureNAT enables IPv4 forwarding and installs masquerade + FORWARD rules so a
// finalizer's tunneled traffic reaches the internet. All rules are reversed on teardown.
func ConfigureNAT(n NATSetup) (TeardownFunc, error) {
	var ch chain
	// Only write ip_forward if not already enabled (containers may pre-enable it and
	// mount /proc read-only).
	prev, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if prevVal := strings.TrimSpace(string(prev)); prevVal != "1" {
		if err := setIPForward("1"); err != nil {
			return nil, err
		}
		if prevVal != "" {
			ch.add(func() error { return setIPForward(prevVal) })
		}
	}
	sub := n.Subnet.String()
	rules := [][]string{
		{"-t", "nat", "-A", "POSTROUTING", "-s", sub, "-o", n.ExtIface, "-j", "MASQUERADE"},
		{"-A", "FORWARD", "-i", n.TunName, "-o", n.ExtIface, "-j", "ACCEPT"},
		{"-A", "FORWARD", "-i", n.ExtIface, "-o", n.TunName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		// MSS-clamp TCP crossing the tunnel to the tun's (small) MTU, so inner TCP
		// segments never exceed what the tunnel can carry and get fragmented/dropped
		// (the "connects but pages hang" symptom). Both directions of the SYN handshake.
		{"-t", "mangle", "-A", "FORWARD", "-o", n.TunName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		{"-t", "mangle", "-A", "FORWARD", "-i", n.TunName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
	}
	for _, r := range rules {
		if err := run(iptablesCmd(r)...); err != nil {
			_ = ch.teardown()
			return nil, err
		}
		del := iptablesCmd(r)
		for i, a := range del {
			if a == "-A" {
				del[i] = "-D"
			}
		}
		ch.add(func() error { return run(del...) })
	}
	return ch.teardown, nil
}
