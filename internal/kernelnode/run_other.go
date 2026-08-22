//go:build !linux

package kernelnode

import (
	"context"
	"fmt"
)

// Run reports that the kernel datapath is Linux-only (it programs Linux policy routing and
// iptables). A kernel node must be deployed to a Linux host.
func (r *Runtime) Run(context.Context) error {
	return fmt.Errorf("kernelnode: the kernel datapath is only supported on Linux")
}
