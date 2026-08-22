package warp

import (
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// MTU is Cloudflare's recommended WARP tunnel MTU, shared by the userspace netstack
// dialer and the kernel WireGuard device so the two paths cannot drift.
const MTU = 1280

// deviceMTU is the MTU to give a kernel WireGuard device for a requested (node-config) value:
// WARP's 1280 by default and as a hard ceiling — a larger inner MTU fragments over the tunnel —
// but a smaller configured value is honored, so an operator on a path that still fragments at
// 1280 can lower it. requested <= 0 (unset) also falls back to 1280.
func deviceMTU(requested int) int {
	if requested <= 0 || requested > MTU {
		return MTU
	}
	return requested
}

// keepalive keeps the tunnel's NAT/conntrack state alive from our side; Cloudflare
// never initiates, so without it an idle tunnel behind NAT goes deaf.
const keepalive = 25 * time.Second

// Credentials returns the WARP account an egress uses: an explicit wgcf profile wins
// over the (auto-registering) cached account — one precedence for both datapaths. insecure
// skips TLS verification on the registration call (a wgcf profile hits no network, so it is
// irrelevant there).
func Credentials(configPath, cachePath string, insecure bool) (*Account, error) {
	if configPath != "" {
		return LoadConfig(configPath)
	}
	return LoadOrRegister(cachePath, insecure)
}

// DeviceConfig maps a WARP account onto a kernel WireGuard device configuration: our
// private key, the Cloudflare peer as the v4 catch-all (the kernel datapath is
// v4-only, so no ::/0 and the account's v6 address is never assigned), the endpoint
// resolved to an address now (kernel WireGuard takes an address, not a name), and the
// same keepalive as the userspace dialer. ReplacePeers/ReplaceAllowedIPs make
// re-programming an existing device idempotent. Kernel WireGuard sends the header's
// reserved bytes zeroed (the userspace dialer stamps the WARP client id there); WARP
// accepts that, the same way wgcf profiles work with standard WireGuard clients.
func DeviceConfig(acct *Account) (wgtypes.Config, error) {
	priv, err := wgtypes.ParseKey(acct.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("warp: private key: %w", err)
	}
	peer, err := wgtypes.ParseKey(acct.PeerPublicKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("warp: peer key: %w", err)
	}
	ep, err := resolveEndpoint(acct.endpoint())
	if err != nil {
		return wgtypes.Config{}, err
	}
	if ep.IP.To4() == nil && acct.EndpointV4 != "" {
		// The preferred endpoint resolved to IPv6, which the v4-only kernel datapath
		// cannot route; the account carries a v4 endpoint exactly for this.
		if ep, err = resolveEndpoint(acct.EndpointV4); err != nil {
			return wgtypes.Config{}, err
		}
	}
	ka := keepalive
	return wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   peer,
			Endpoint:                    ep,
			PersistentKeepaliveInterval: &ka,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  []net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}},
		}},
	}, nil
}
