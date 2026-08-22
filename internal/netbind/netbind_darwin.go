//go:build darwin

package netbind

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

// bindToInterface pins the socket to iface using IP_BOUND_IF (IPv4) or
// IPV6_BOUND_IF (IPv6). For an address-family-agnostic network ("tcp"/"udp") we
// try both and succeed if either sticks.
func bindToInterface(fd int, iface, network string) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("netbind: interface %q: %w", iface, err)
	}
	idx := ifi.Index

	setV4 := func() error { return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, idx) }
	setV6 := func() error { return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, idx) }

	switch {
	case strings.HasSuffix(network, "6"):
		return setV6()
	case strings.HasSuffix(network, "4"):
		return setV4()
	default:
		errV4, errV6 := setV4(), setV6()
		if errV4 != nil && errV6 != nil {
			return fmt.Errorf("netbind: bind %q failed (v4: %v, v6: %v)", iface, errV4, errV6)
		}
		return nil
	}
}
