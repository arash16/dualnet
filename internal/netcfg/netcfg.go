// Package netcfg applies the operating-system network configuration dualnet
// needs — assigning the tunnel address, pointing the default route at the tunnel
// (client), and enabling forwarding + NAT (server) — and returns a teardown
// function that reverses everything on exit.
//
// The per-OS implementations live in netcfg_darwin.go / netcfg_linux.go. The
// client is designed for macOS; the server for Linux.
package netcfg

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
)

// TeardownFunc reverses the configuration applied by a Configure* call.
type TeardownFunc func() error

// TunSetup describes one tun interface to bring up. Local is its inner address; Peer
// is the point-to-point peer / default-route gateway (macOS); Bits is the subnet
// prefix length. Default-route capture is owned separately by a Capturer.
type TunSetup struct {
	Name  string
	Local netip.Addr
	Peer  netip.Addr
	Bits  int
	MTU   int
}

// IfaceRoute pins internet reachability for sockets bound to Iface: an ip rule sends
// oif==Iface traffic to a dedicated Table whose default routes via Gateway, or straight
// out Iface if Gateway is empty (a point-to-point link such as PPPoE). Needed when Iface
// is not the system default so SO_BINDTODEVICE sockets (a direct egress and its pinned
// carriers) can still reach the internet. Linux only.
type IfaceRoute struct {
	Iface   string
	Gateway string // "" = point-to-point (default dev Iface, no via)
	Table   int
	Prio    int
}

// LANForward forwards a LAN interface's traffic into a capture tun (Linux router):
// FORWARD both directions plus an MSS clamp to the tun's path MTU.
type LANForward struct {
	LANIface string
	TunName  string
}

// Capturer owns a tun's default-route capture — the def1 0.0.0.0/1 + 128.0.0.0/1 trick
// that shadows (never deletes) the original default route. Capture and Release are
// idempotent, so a caller may toggle them freely; splitting this out of ConfigureTun
// lets the node defer capture until it is fully operational and release it on shutdown.
type Capturer struct {
	dev  string
	peer netip.Addr // macOS needs a gateway for the /1 routes
	mu   sync.Mutex
	ch   *chain
}

// NewCapturer builds a Capturer for tun device dev; peer is used only on macOS.
func NewCapturer(dev string, peer netip.Addr) *Capturer { return &Capturer{dev: dev, peer: peer} }

// Capture installs the two /1 routes into the tun (idempotent).
func (c *Capturer) Capture() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ch != nil {
		return nil
	}
	ch, err := captureDefault(c.dev, c.peer)
	if err != nil {
		return err
	}
	c.ch = ch
	return nil
}

// Release removes the two /1 routes, restoring the original default (idempotent).
func (c *Capturer) Release() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ch == nil {
		return nil
	}
	err := c.ch.teardown()
	c.ch = nil
	return err
}

// PinRoute pins a scoped host route to a remote peer via a physical interface (macOS
// only; on Linux SO_BINDTODEVICE makes this unnecessary). Needed so a node's pinned
// sockets keep reaching their remotes after a capture_default tun overrides the
// default route.
type PinRoute struct {
	Dst   string // remote real IP
	Iface string
}

// NATSetup describes the finalizer's kernel NAT (Linux): masquerade the tun subnet
// out ExtIface and forward between them.
type NATSetup struct {
	TunName  string
	Subnet   netip.Prefix
	ExtIface string
}

// SourceAddr is a source address dualnet assigns to a device so an outbound link can bind it
// as its socket source (LocalAddr) and it is ARP-reachable on-link for return traffic. Addr is
// an "ip" or "ip/mask" (a bare ip is treated as a host /32). Linux only.
type SourceAddr struct {
	Addr  string
	Iface string
}

// run executes a command and includes its combined output in any error, which
// makes misconfiguration far easier to diagnose than a bare exit code.
func run(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

// output runs a command and returns its trimmed stdout.
func output(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).Output()
	return strings.TrimSpace(string(out)), err
}

// chain builds a teardown that runs the collected undo steps in reverse order,
// continuing past individual failures and returning the first error seen.
type chain struct {
	steps []func() error
}

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
