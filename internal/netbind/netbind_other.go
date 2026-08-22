//go:build !darwin && !linux

package netbind

import "fmt"

func bindToInterface(_ int, iface, _ string) error {
	return fmt.Errorf("netbind: binding to interface %q not supported on this OS", iface)
}
