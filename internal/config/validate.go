package config

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/arash16/dualnet/internal/cipher"
)

// Validate checks the whole node config for internal consistency.
func (n *Node) Validate() error {
	if n.MTU < 576 || n.MTU > 9000 {
		return fmt.Errorf("config: mtu %d out of range", n.MTU)
	}
	if _, err := n.Prefix(); err != nil {
		return fmt.Errorf("config: bad subnet %q: %w", n.Subnet, err)
	}
	switch n.Datapath {
	case "", "userspace":
		return n.validateUserspace()
	case "kernel":
		return n.validateKernel()
	default:
		return fmt.Errorf("config: unknown datapath %q (want userspace or kernel)", n.Datapath)
	}
}

// validateUserspace checks a packet-router node: connections, egresses, conditions, routes.
func (n *Node) validateUserspace() error {
	if len(n.Forward) != 0 || len(n.LANIfaces) != 0 {
		return fmt.Errorf("config: forward/lan_ifaces are kernel-datapath only")
	}
	if len(n.Connections) == 0 {
		return fmt.Errorf("config: no connections")
	}

	names := make(map[string]Connection, len(n.Connections))
	tunAddrs := make(map[string]bool)
	captureDefaults := 0
	for _, c := range n.Connections {
		if c.Name == "" {
			return fmt.Errorf("config: a connection has no name")
		}
		if _, dup := names[c.Name]; dup {
			return fmt.Errorf("config: duplicate connection name %q", c.Name)
		}
		names[c.Name] = c
		if c.EffectivePSK(n.PSK) == "" {
			return fmt.Errorf("config: connection %q has no psk (set a global psk or a per-connection psk)", c.Name)
		}
		if _, _, err := cipher.ParseName(c.Cipher); err != nil {
			return fmt.Errorf("config: connection %q: %w", c.Name, err)
		}
		if err := n.validateConn(c, &tunAddrs, &captureDefaults); err != nil {
			return err
		}
	}
	if captureDefaults > 1 {
		return fmt.Errorf("config: at most one tun may set capture_default (only one default route)")
	}

	// id_setter references must name a local tun.
	for _, c := range n.Connections {
		if c.IDSetter == "" {
			continue
		}
		t, ok := names[c.IDSetter]
		if !ok || t.Type != "tun" {
			return fmt.Errorf("config: connection %q id_setter %q must name a local tun", c.Name, c.IDSetter)
		}
	}

	if err := n.validateEgresses(); err != nil {
		return err
	}
	conds, err := n.validateConditions(names)
	if err != nil {
		return err
	}
	return n.validateRoutes(names, conds)
}

func (n *Node) validateConn(c Connection, tunAddrs *map[string]bool, captureDefaults *int) error {
	// source_ip is a socket-source binding, valid only on connect/listen; validate its form
	// here (like ip) so a malformed value fails at load, not at `ip addr replace` on bring-up.
	if c.SourceIP != "" {
		if c.Type == "tun" {
			return fmt.Errorf("config: tun %q must not set source_ip (connect/listen only)", c.Name)
		}
		if err := validateIPToken(c.SourceIP); err != nil {
			return fmt.Errorf("config: connection %q bad source_ip %q: %w", c.Name, c.SourceIP, err)
		}
	}
	switch c.Type {
	case "connect":
		if c.IP == "" || c.Port <= 0 {
			return fmt.Errorf("config: connect %q needs ip and port", c.Name)
		}
		if _, err := netip.ParseAddr(c.IP); err != nil {
			return fmt.Errorf("config: connect %q bad ip %q", c.Name, c.IP)
		}
		if err := validateTransport(c); err != nil {
			return err
		}
		if c.Direction != "outgoing" && c.Direction != "incoming" {
			return fmt.Errorf("config: connect %q direction %q must be outgoing or incoming", c.Name, c.Direction)
		}
		if c.Multiple {
			return fmt.Errorf("config: connect %q cannot be multiple (listen-only)", c.Name)
		}
		if c.Warpped && c.Transport != "http" {
			return fmt.Errorf("config: connect %q: warpped requires transport http (WARP MTU < tunnel MTU fragments UDP)", c.Name)
		}
		if c.IDSetter != "" && c.Direction != "incoming" {
			return fmt.Errorf("config: connect %q: id_setter is only valid on an incoming connection", c.Name)
		}
		if c.LANIface != "" {
			return fmt.Errorf("config: connect %q cannot set lan_iface (tun-only)", c.Name)
		}
	case "listen":
		if c.Port <= 0 {
			return fmt.Errorf("config: listen %q needs port", c.Name)
		}
		if err := validateTransport(c); err != nil {
			return err
		}
		if c.Direction != "outgoing" && c.Direction != "incoming" {
			return fmt.Errorf("config: listen %q direction %q must be outgoing or incoming", c.Name, c.Direction)
		}
		if c.IP != "" || c.Warpped || c.IDSetter != "" || c.LANIface != "" {
			return fmt.Errorf("config: listen %q cannot set ip/warpped/id_setter/lan_iface", c.Name)
		}
		if c.Multiple && c.Direction != "outgoing" {
			return fmt.Errorf("config: listen %q: multiple is only meaningful with direction outgoing", c.Name)
		}
	case "tun":
		if c.Transport != "" || c.Port != 0 || c.IP != "" || c.Direction != "" {
			return fmt.Errorf("config: tun %q must not set transport/port/ip/direction", c.Name)
		}
		if c.HTTP != nil {
			return fmt.Errorf("config: tun %q must not set http options", c.Name)
		}
		if c.Address != "" {
			addr, err := netip.ParseAddr(c.Address)
			if err != nil {
				return fmt.Errorf("config: tun %q bad address %q", c.Name, c.Address)
			}
			if (*tunAddrs)[addr.String()] {
				return fmt.Errorf("config: tun address %q used by more than one tun", c.Address)
			}
			(*tunAddrs)[addr.String()] = true
		}
		if c.CaptureDefault {
			if c.Address == "" {
				return fmt.Errorf("config: tun %q sets capture_default but has no address (a default route needs a peer address)", c.Name)
			}
			*captureDefaults++
		}
		if c.LANIface != "" && !c.CaptureDefault {
			return fmt.Errorf("config: tun %q sets lan_iface but not capture_default (LAN forwarding needs the capture)", c.Name)
		}
	default:
		return fmt.Errorf("config: connection %q has unknown type %q", c.Name, c.Type)
	}
	return nil
}

// validateTransport checks a connect/listen connection's transport and its transport-scoped
// options (http carrier customization is only valid when transport is http).
func validateTransport(c Connection) error {
	if c.Transport != "http" && c.Transport != "udp" && c.Transport != "tcp" {
		return fmt.Errorf("config: connection %q transport %q must be http, udp or tcp", c.Name, c.Transport)
	}
	if c.HTTP == nil {
		return nil
	}
	if c.Transport != "http" {
		return fmt.Errorf("config: connection %q sets http options but transport is %q", c.Name, c.Transport)
	}
	for _, p := range []string{c.HTTP.UploadPath, c.HTTP.DownloadPath} {
		if p != "" && p[0] != '/' {
			return fmt.Errorf("config: connection %q http path %q must begin with /", c.Name, p)
		}
	}
	return nil
}

func (n *Node) validateEgresses() error {
	for name, eg := range n.Egresses {
		if name == "" {
			return fmt.Errorf("config: an egress has no name")
		}
		switch eg.Mode {
		case "kernel", "direct":
			if eg.ExtIface == "" {
				return fmt.Errorf("config: egress %q mode %s needs exit (the internet-facing connection)", name, eg.Mode)
			}
			if eg.Mode == "kernel" && eg.Gateway != "" {
				return fmt.Errorf("config: egress %q mode kernel must not set gateway", name)
			}
		case "warp":
			if eg.ExtIface != "" || eg.Gateway != "" || eg.TunName != "" {
				return fmt.Errorf("config: egress %q mode warp must not set exit/gateway/tun_name", name)
			}
		default:
			return fmt.Errorf("config: egress %q mode %q must be kernel, direct, or warp", name, eg.Mode)
		}
		if eg.Gateway != "" {
			if _, err := netip.ParseAddr(eg.Gateway); err != nil {
				return fmt.Errorf("config: egress %q bad gateway %q", name, eg.Gateway)
			}
		}
	}
	return nil
}

// validateIfaceName enforces Linux IFNAMSIZ (15 chars + NUL) and rejects the characters
// `ip link add` cannot accept, so a bad device name fails at config load rather than at
// link creation.
func validateIfaceName(s string) error {
	if s == "" || len(s) > 15 {
		return fmt.Errorf("device name %q must be 1-15 characters", s)
	}
	if strings.ContainsAny(s, "/ \t\n") {
		return fmt.Errorf("device name %q must not contain '/' or whitespace", s)
	}
	return nil
}

// validateConditions returns the set of condition names by kind ("dst" or "health").
func (n *Node) validateConditions(names map[string]Connection) (map[string]string, error) {
	conds := make(map[string]string, len(n.Conditions))
	healthTuns := map[string]int{}
	for _, c := range n.Conditions {
		if c.Name == "" {
			return nil, fmt.Errorf("config: a condition has no name")
		}
		if _, dup := conds[c.Name]; dup {
			return nil, fmt.Errorf("config: duplicate condition name %q", c.Name)
		}
		if c.SrcIn != nil {
			return nil, fmt.Errorf("config: condition %q src_in is only valid on a kernel-datapath node", c.Name)
		}
		hasDst := c.DstIn != nil
		hasHC := c.Healthcheck != nil
		if hasDst == hasHC {
			return nil, fmt.Errorf("config: condition %q must set exactly one of dst_in / healthcheck", c.Name)
		}
		if hasDst {
			if err := c.DstIn.Validate(c.Name); err != nil {
				return nil, err
			}
			conds[c.Name] = "dst"
			continue
		}
		hc := c.Healthcheck
		if len(hc.Up) == 0 {
			return nil, fmt.Errorf("config: condition %q healthcheck has no up-link path", c.Name)
		}
		via, ok := names[hc.Up[0]]
		if !ok {
			return nil, fmt.Errorf("config: condition %q healthcheck up[0] %q is not a connection", c.Name, hc.Up[0])
		}
		if via.Type == "tun" {
			return nil, fmt.Errorf("config: condition %q healthcheck up[0] %q must be a connect/listen, not a tun", c.Name, hc.Up[0])
		}
		// The probe is injected directly on up[0], so it must be a sender (an outgoing
		// connection). A receiver (incoming) is not routable as a target and only fails at
		// node build time otherwise.
		if via.Direction != "outgoing" {
			return nil, fmt.Errorf("config: condition %q healthcheck up[0] %q must be an outgoing (sending) connection, not %q", c.Name, hc.Up[0], via.Direction)
		}
		tun := hc.Tun
		if tun == "" {
			only := ""
			for _, cc := range n.Connections {
				if cc.Type == "tun" {
					if only != "" {
						return nil, fmt.Errorf("config: condition %q healthcheck needs an explicit tun (node has several)", c.Name)
					}
					only = cc.Name
				}
			}
			if only == "" {
				return nil, fmt.Errorf("config: condition %q healthcheck needs a tun but the node has none", c.Name)
			}
			tun = only
		} else if t, ok := names[tun]; !ok || t.Type != "tun" {
			return nil, fmt.Errorf("config: condition %q healthcheck tun %q must name a local tun", c.Name, tun)
		}
		healthTuns[tun]++
		if healthTuns[tun] > 1 {
			return nil, fmt.Errorf("config: tun %q has more than one healthcheck condition (only one per tun is supported)", tun)
		}
		conds[c.Name] = "health"
	}
	return conds, nil
}

// validate checks that an IPSet sets exactly one of File / List, and that inline List entries
// parse as prefixes or bare addresses. name is the owning condition, for error messages.
func (s *IPSet) Validate(name string) error {
	hasFile := s.File != ""
	hasList := len(s.List) > 0
	if hasFile == hasList {
		return fmt.Errorf("config: condition %q must set exactly one of file / list", name)
	}
	for _, e := range s.List {
		if err := validateIPToken(e); err != nil {
			return fmt.Errorf("config: condition %q list entry %q: %w", name, e, err)
		}
	}
	return nil
}

// validateIPToken accepts an "ip/mask" prefix or a bare address (a host route).
func validateIPToken(s string) error {
	if len(s) > 0 && containsSlash(s) {
		_, err := netip.ParsePrefix(s)
		return err
	}
	_, err := netip.ParseAddr(s)
	return err
}

func containsSlash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}

// validateKernel checks a kernel-datapath node: no connections/routes, WAN egresses, dst_in /
// src_in conditions (no healthcheck), and an ordered Forward policy (src_in*, dst_in*, one
// default). See internal/kernelnode for how these lower to ip rule/route + iptables.
func (n *Node) validateKernel() error {
	if len(n.Connections) != 0 {
		return fmt.Errorf("config: kernel-datapath node must have no connections")
	}
	if len(n.Routes) != 0 {
		return fmt.Errorf("config: kernel-datapath node must have no routes (use forward)")
	}
	if len(n.Egresses) == 0 {
		return fmt.Errorf("config: kernel-datapath node needs at least one egress")
	}
	wgDevs := map[string]string{} // WireGuard device name -> egress that claimed it
	for name, eg := range n.Egresses {
		switch eg.Mode {
		case "kernel":
			if eg.ExtIface == "" {
				return fmt.Errorf("config: kernel node egress %q needs exit (the internet-facing connection)", name)
			}
			if eg.TunName != "" || eg.WARPConfig != "" || eg.WARPCache != "" || eg.WARPInsecure {
				return fmt.Errorf("config: kernel node egress %q mode kernel must not set tun_name/warp_config/warp_cache/warp_insecure", name)
			}
		case "warp":
			if eg.ExtIface == "" {
				return fmt.Errorf("config: kernel node egress %q mode warp needs exit (the underlay WAN its endpoint UDP leaves through)", name)
			}
			// TunName is always set post-Defaults; it becomes the `ip link add` argument.
			if err := validateIfaceName(eg.TunName); err != nil {
				return fmt.Errorf("config: kernel node egress %q tun_name: %w (set tun_name explicitly)", name, err)
			}
			if prev, dup := wgDevs[eg.TunName]; dup {
				return fmt.Errorf("config: kernel node egresses %q and %q share WireGuard device %q", prev, name, eg.TunName)
			}
			wgDevs[eg.TunName] = name
		default:
			return fmt.Errorf("config: kernel node egress %q mode %q must be kernel or warp", name, eg.Mode)
		}
		if eg.Gateway != "" {
			if _, err := netip.ParseAddr(eg.Gateway); err != nil {
				return fmt.Errorf("config: kernel node egress %q bad gateway %q", name, eg.Gateway)
			}
		}
	}
	conds := map[string]string{} // name -> "dst" | "src"
	for _, c := range n.Conditions {
		if c.Name == "" {
			return fmt.Errorf("config: a condition has no name")
		}
		if _, dup := conds[c.Name]; dup {
			return fmt.Errorf("config: duplicate condition name %q", c.Name)
		}
		if c.Healthcheck != nil {
			return fmt.Errorf("config: kernel node condition %q cannot use healthcheck", c.Name)
		}
		hasDst := c.DstIn != nil
		hasSrc := c.SrcIn != nil
		if hasDst == hasSrc {
			return fmt.Errorf("config: kernel node condition %q must set exactly one of dst_in / src_in", c.Name)
		}
		if hasDst {
			if err := c.DstIn.Validate(c.Name); err != nil {
				return err
			}
			conds[c.Name] = "dst"
		} else {
			if err := c.SrcIn.Validate(c.Name); err != nil {
				return err
			}
			conds[c.Name] = "src"
		}
	}
	return n.validateForward(conds)
}

// validateForward checks the kernel Forward policy: every branch names a known egress; a
// conditional branch names exactly one src_in/dst_in condition; branches are ordered src_in*
// then dst_in* then exactly one default (empty When) last. This mirrors the fixed kernel
// precedence (ip rule > FIB route > main-table default).
func (n *Node) validateForward(conds map[string]string) error {
	if len(n.Forward) == 0 {
		return fmt.Errorf("config: kernel node needs a forward policy")
	}
	phase := 0 // 0=src_in, 1=dst_in, 2=default seen
	defaults := 0
	for i, f := range n.Forward {
		if f.Egress == "" {
			return fmt.Errorf("config: forward branch %d has no egress", i)
		}
		if _, ok := n.Egresses[f.Egress]; !ok {
			return fmt.Errorf("config: forward branch %d references unknown egress %q", i, f.Egress)
		}
		if len(f.When) == 0 {
			defaults++
			phase = 2
			continue
		}
		if phase == 2 {
			return fmt.Errorf("config: forward branch %d comes after the default branch", i)
		}
		if len(f.When) != 1 {
			return fmt.Errorf("config: forward branch %d must name exactly one condition", i)
		}
		kind, ok := conds[f.When[0]]
		if !ok {
			return fmt.Errorf("config: forward branch %d references unknown condition %q", i, f.When[0])
		}
		switch kind {
		case "src":
			if phase > 0 {
				return fmt.Errorf("config: forward branch %d (src_in) must come before dst_in branches", i)
			}
		case "dst":
			phase = 1
		}
	}
	if defaults != 1 {
		return fmt.Errorf("config: kernel forward policy needs exactly one default branch (got %d)", defaults)
	}
	return nil
}

func (n *Node) validateRoutes(names map[string]Connection, conds map[string]string) error {
	for i, r := range n.Routes {
		if r.Action.Target == "" || names[r.Action.Target].Name == "" {
			return fmt.Errorf("config: route %d targets unknown connection %q", i, r.Action.Target)
		}
		if r.Match.Source != "" && names[r.Match.Source].Name == "" {
			return fmt.Errorf("config: route %d has unknown source %q", i, r.Match.Source)
		}
		if r.Action.Egress != "" {
			if _, ok := n.Egresses[r.Action.Egress]; !ok {
				return fmt.Errorf("config: route %d references unknown egress %q", i, r.Action.Egress)
			}
			if r.Match.Processed == nil || *r.Match.Processed {
				return fmt.Errorf("config: route %d cannot finalize an already-processed packet (set match.processed: false)", i)
			}
		}
		for _, cn := range r.Match.Conditions {
			kind, ok := conds[cn]
			if !ok {
				return fmt.Errorf("config: route %d references unknown condition %q", i, cn)
			}
			if kind == "dst" && r.Match.Processed != nil && *r.Match.Processed {
				return fmt.Errorf("config: route %d uses packet condition %q on a processed rule (only valid on unprocessed)", i, cn)
			}
		}
	}
	return nil
}
