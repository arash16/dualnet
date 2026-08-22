//go:build linux

package netbind

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// bindToInterface pins the socket to iface using SO_BINDTODEVICE. Note this may
// require CAP_NET_RAW / root on Linux.
func bindToInterface(fd int, iface, _ string) error {
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface); err != nil {
		return fmt.Errorf("netbind: SO_BINDTODEVICE %q: %w", iface, err)
	}
	return nil
}
