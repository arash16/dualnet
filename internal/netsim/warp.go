package netsim

import (
	"crypto/sha256"
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The sim's WARP stand-in: each kernel-warp egress gets a real kernel WireGuard tunnel to the
// hub, which plays Cloudflare. Tunnel addresses live in CGNAT space so they can never collide
// with fabrics (172.30.x), the echo net (10.200.0.x), inner subnets, or leg IPs.
const (
	warpNet    = "100.64.0.0/24"
	warpHubIP  = "100.64.0.1"
	warpPort   = 51820
	warpHubDev = "wg-sim"
)

// warpKeys derives a deterministic WireGuard keypair for a sim identity: Plan is pure and
// reproducible, so keys come from a hash, not crypto/rand — they protect nothing (the "WARP"
// peer is the sim's own hub).
func warpKeys(identity string) (priv, pub wgtypes.Key) {
	seed := sha256.Sum256([]byte("netsim-warp/" + identity))
	seed[0] &= 248
	seed[31] &= 127
	seed[31] |= 64
	priv = wgtypes.Key(seed)
	return priv, priv.PublicKey()
}

// warpINI renders the wgcf-style profile warp.LoadConfig consumes for one kernel-warp egress:
// the node's key, the hub as the "Cloudflare" peer, and the generated tunnel address. No
// Reserved line — kernel WireGuard sends zeroed reserved bytes, which is also how real wgcf
// accounts run on standard WireGuard clients.
func warpINI(priv, hubPub wgtypes.Key, endpoint, tunIP string) []byte {
	return []byte(fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s
`, priv, tunIP, hubPub, endpoint))
}
