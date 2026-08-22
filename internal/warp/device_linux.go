//go:build linux

package warp

import (
	"fmt"
	"net/netip"

	"github.com/arash16/dualnet/internal/netcfg"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// SetupKernelDevice (re)creates kernel WireGuard device name from acct — link add
// (replacing a crash-leaked one), wgctrl programming, WARP v4/32 address + MTU + up — and
// returns the resolved peer endpoint address: the caller must route it via its underlay, or
// the tunnel's own encrypted UDP is policy-routed back into the tunnel and the handshake
// never completes. mtu is the requested device MTU (the node's mtu config), clamped to WARP's
// 1280 ceiling by deviceMTU. The teardown deletes the link, which takes the address and any
// routes through it along.
func SetupKernelDevice(name string, acct *Account, mtu int) (netip.Addr, netcfg.TeardownFunc, error) {
	cfg, err := DeviceConfig(acct)
	if err != nil {
		return netip.Addr{}, nil, err
	}
	v4, err := netip.ParseAddr(acct.V4)
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("warp: bad v4 addr %q: %w", acct.V4, err)
	}
	linkTd, err := netcfg.EnsureWireGuardLink(name)
	if err != nil {
		return netip.Addr{}, nil, err
	}
	fail := func(err error) (netip.Addr, netcfg.TeardownFunc, error) {
		_ = linkTd()
		return netip.Addr{}, nil, err
	}
	c, err := wgctrl.New()
	if err != nil {
		return fail(fmt.Errorf("warp: wgctrl: %w", err))
	}
	err = c.ConfigureDevice(name, cfg)
	_ = c.Close()
	if err != nil {
		return fail(fmt.Errorf("warp: configure %s: %w", name, err))
	}
	if _, err := netcfg.ConfigureTun(netcfg.TunSetup{Name: name, Local: v4, Bits: 32, MTU: deviceMTU(mtu)}); err != nil {
		return fail(err)
	}
	ep, ok := netip.AddrFromSlice(cfg.Peers[0].Endpoint.IP)
	if !ok {
		return fail(fmt.Errorf("warp: bad endpoint address %v", cfg.Peers[0].Endpoint.IP))
	}
	return ep.Unmap(), linkTd, nil
}
