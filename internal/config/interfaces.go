package config

import "sort"

// RequiredInterfaces returns the physical interfaces this node binds sockets to or
// egresses through and that must therefore already be up before the node can start,
// deduplicated and sorted:
//
//   - every non-tun connection's pinned Interface (SO_BINDTODEVICE / IP_BOUND_IF),
//   - every capture tun's LANIface (traffic forwarded into the tun),
//   - every egress's ExtIface (kernel NAT out-iface / direct-egress bound iface).
//
// A tun connection's own Interface is deliberately excluded: that device is created by
// the node itself, not something to wait for. Egresses with no ExtIface (e.g. warp) and
// empty names contribute nothing.
//
// This is what lets a node started at boot (systemd) wait for a slow uplink — notably a
// PPPoE link (ppp1) that only appears once its session is established — before it tries
// to bind to it.
func (n *Node) RequiredInterfaces() []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, c := range n.Connections {
		if c.Type == "tun" {
			add(c.LANIface)
			continue
		}
		add(c.Interface)
	}
	for _, eg := range n.Egresses {
		add(eg.ExtIface)
	}
	// Kernel-datapath node: LAN-facing devices it forwards from (no connections above).
	for _, iface := range n.LANIfaces {
		add(iface)
	}
	sort.Strings(out)
	return out
}
