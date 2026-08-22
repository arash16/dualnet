//go:build linux

package netcfg

import (
	"strings"
	"testing"
)

// TestLANForwardMasqueradesLANHosts guards the invariant that a capture tun's LAN forwarding
// SNATs forwarded traffic to the tun's own address. Without it, a LAN host's real source
// (outside the mesh subnet) traverses a gateway tunnel unchanged; the gateway's
// subnet-scoped MASQUERADE never rewrites it and the reply can't route back into the gateway
// tun — so the gateway works for the router itself but every LAN client black-holes.
func TestLANForwardMasqueradesLANHosts(t *testing.T) {
	rules := lanForwardRules(LANForward{LANIface: "br0", TunName: "dnlan0"})

	var masq []string
	for _, r := range rules {
		joined := strings.Join(r, " ")
		if strings.Contains(joined, "POSTROUTING") && contains(r, "MASQUERADE") {
			masq = r
		}
	}
	if masq == nil {
		t.Fatalf("no POSTROUTING MASQUERADE rule — LAN clients cannot egress through a gateway tunnel; rules=%v", rules)
	}
	// It must SNAT out the capture tun, so the source becomes the tun's (in-mesh-subnet) address.
	if !hasPair(masq, "-o", "dnlan0") {
		t.Errorf("MASQUERADE must be scoped to the capture tun (-o dnlan0); got %v", masq)
	}
	// It must NOT be scoped to a source subnet: a LAN host's real source (e.g. 192.168.1.x) is
	// exactly what needs rewriting, and the router cannot enumerate arbitrary home LAN subnets.
	if contains(masq, "-s") {
		t.Errorf("MASQUERADE must not be source-scoped (a foreign LAN source would be excluded); got %v", masq)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func hasPair(ss []string, flag, val string) bool {
	for i := 0; i+1 < len(ss); i++ {
		if ss[i] == flag && ss[i+1] == val {
			return true
		}
	}
	return false
}
