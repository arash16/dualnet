// Package netbind binds sockets to a specific physical interface so that egress
// is forced over a chosen link regardless of the routing table. This is what
// makes dualnet's directional split work: the HTTP upstream socket is pinned to
// the FTTH link and the UDP downstream socket to the Starlink link.
//
// macOS has no SO_BINDTODEVICE, so on darwin we use IP_BOUND_IF / IPV6_BOUND_IF.
// On Linux we use SO_BINDTODEVICE.
package netbind

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// Control returns a callback suitable for net.Dialer.Control and
// net.ListenConfig.Control that binds the socket to the named interface. An
// empty iface is a no-op (lets the OS route normally).
func Control(iface string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		if iface == "" {
			return nil
		}
		var ctrlErr error
		if err := c.Control(func(fd uintptr) {
			ctrlErr = bindToInterface(int(fd), iface, network)
		}); err != nil {
			return err
		}
		return ctrlErr
	}
}

// Dialer returns a *net.Dialer that binds outbound connections to iface.
func Dialer(iface string) *net.Dialer {
	return &net.Dialer{Control: Control(iface)}
}

// Bound is a SocketDialer that binds outbound sockets to an interface (SO_BINDTODEVICE) and,
// when ip is valid, uses it as the socket's local address so the peer sees that source. The
// local-address type is chosen per dial network (TCP vs UDP), so one Bound serves either
// transport. dualnet must have created ip on iface first (see netcfg.ConfigureSourceAddr).
type Bound struct {
	iface string
	ip    netip.Addr
}

// SourceDialer builds a Bound. iface may be empty (OS routes normally). source, when set, is
// an "ip" or "ip/mask" whose address becomes the socket's local address.
func SourceDialer(iface, source string) (Bound, error) {
	b := Bound{iface: iface}
	if source != "" {
		ip, err := parseSourceAddr(source)
		if err != nil {
			return Bound{}, fmt.Errorf("netbind: bad source %q: %w", source, err)
		}
		b.ip = ip
	}
	return b, nil
}

// DialContext dials address over network, pinned to the interface and (if set) the source IP.
func (b Bound) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{Control: Control(b.iface)}
	if b.ip.IsValid() {
		d.LocalAddr = localAddr(network, b.ip)
	}
	return d.DialContext(ctx, network, address)
}

// localAddr builds a zero-port local address of the type the network requires, or nil for an
// unrecognized network (letting the OS choose).
func localAddr(network string, ip netip.Addr) net.Addr {
	std := net.IP(ip.AsSlice())
	switch {
	case strings.HasPrefix(network, "udp"):
		return &net.UDPAddr{IP: std}
	case strings.HasPrefix(network, "tcp"):
		return &net.TCPAddr{IP: std}
	default:
		return nil
	}
}

// parseSourceAddr extracts the address from an "ip" or "ip/mask" source string.
func parseSourceAddr(s string) (netip.Addr, error) {
	if strings.ContainsRune(s, '/') {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, err
		}
		return p.Addr(), nil
	}
	return netip.ParseAddr(s)
}

// ListenPacket opens a UDP socket bound to iface.
func ListenPacket(ctx context.Context, iface, network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: Control(iface)}
	return lc.ListenPacket(ctx, network, address)
}
