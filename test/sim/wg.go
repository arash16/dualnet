package main

import (
	"fmt"
	"net"

	"github.com/arash16/dualnet/internal/netsim/siminit"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// applyWGDevices creates and programs the spec's kernel WireGuard devices — the hub's
// simulated "Cloudflare" side of kernel-warp egresses. Link creation goes through `ip` (its
// failure is the authoritative "host kernel lacks the wireguard module" signal); keys and
// peers go through wgctrl because the sim image ships no `wg` binary.
func applyWGDevices(devs []siminit.WGDevice) error {
	if len(devs) == 0 {
		return nil
	}
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl: %w", err)
	}
	defer c.Close()
	for _, d := range devs {
		if err := ipCmd("link", "add", "dev", d.Name, "type", "wireguard"); err != nil {
			return fmt.Errorf("create %s (host kernel must provide the wireguard module): %w", d.Name, err)
		}
		priv, err := wgtypes.ParseKey(d.PrivateKey)
		if err != nil {
			return fmt.Errorf("%s: private key: %w", d.Name, err)
		}
		cfg := wgtypes.Config{PrivateKey: &priv, ReplacePeers: true}
		if d.ListenPort != 0 {
			port := d.ListenPort
			cfg.ListenPort = &port
		}
		for _, p := range d.Peers {
			pub, err := wgtypes.ParseKey(p.PublicKey)
			if err != nil {
				return fmt.Errorf("%s: peer key: %w", d.Name, err)
			}
			pc := wgtypes.PeerConfig{PublicKey: pub, ReplaceAllowedIPs: true}
			for _, cidr := range p.AllowedIPs {
				_, ipn, err := net.ParseCIDR(cidr)
				if err != nil {
					return fmt.Errorf("%s: allowed ip %q: %w", d.Name, cidr, err)
				}
				pc.AllowedIPs = append(pc.AllowedIPs, *ipn)
			}
			cfg.Peers = append(cfg.Peers, pc)
		}
		if err := c.ConfigureDevice(d.Name, cfg); err != nil {
			return fmt.Errorf("configure %s: %w", d.Name, err)
		}
		for _, a := range d.Addrs {
			if err := ipCmd("addr", "add", a, "dev", d.Name); err != nil {
				return err
			}
		}
		if err := ipCmd("link", "set", d.Name, "up"); err != nil {
			return err
		}
	}
	return nil
}
