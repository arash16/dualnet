// Package netwait blocks until the physical network interfaces a node depends on are
// present and usable. dualnet is often started at boot (a systemd unit) before the slow
// links it binds to have come up — most notably a PPPoE uplink (ppp1) that does not even
// exist until its session is established. Binding a socket to an absent or addressless
// interface fails, so the node waits here first.
package netwait

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	pollInterval = 500 * time.Millisecond
	// heartbeat re-logs the still-missing set periodically so a stuck boot is visibly
	// waiting (rather than silently hung) in the logs.
	heartbeat = 15 * time.Second
)

// Wait blocks until every named interface is ready (see Ready) or ctx is cancelled,
// returning ctx.Err() in the latter case. It has no timeout of its own: a link that
// never comes up is a deployment problem the operator (or systemd) resolves, and blocking
// is safer than starting half-configured. names may contain duplicates or empties; both
// are ignored. logf may be nil.
func Wait(ctx context.Context, names []string, logf func(string, ...any)) error {
	want := dedup(names)
	if len(want) == 0 {
		return nil
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	t := time.NewTicker(pollInterval)
	defer t.Stop()

	var lastMissing string
	var lastLog time.Time
	for {
		missing := notReady(want)
		if len(missing) == 0 {
			if lastMissing != "" {
				logf("netwait: all required interfaces are up: %s", strings.Join(want, ", "))
			}
			return nil
		}
		if cur, now := strings.Join(missing, ", "), time.Now(); cur != lastMissing || now.Sub(lastLog) >= heartbeat {
			logf("netwait: waiting for interface(s) to come up: %s", cur)
			lastMissing, lastLog = cur, now
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

func notReady(names []string) []string {
	var out []string
	for _, n := range names {
		if !Ready(n) {
			out = append(out, n)
		}
	}
	return out
}

// Ready reports whether iface exists, is administratively up, and carries a usable
// (non-loopback, non-link-local) IPv4 address — the minimum for dualnet to bind a socket
// to it and reach the network. A link-local-only address means the link is still coming
// up (e.g. DHCP has not completed), so it is treated as not yet ready.
func Ready(name string) bool {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	if ifi.Flags&net.FlagUp == 0 {
		return false
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		if ip = ip.Unmap(); ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

func dedup(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
