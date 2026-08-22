// Package config defines dualnet's node configuration: a list of connections plus a
// routing table, loaded from YAML. It replaces the old flat client/server key-value
// config. A node has no identity of its own; connections and tuns carry the routing
// identities (a random 4-byte owner id, minted/assigned at runtime).
package config

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/arash16/dualnet/internal/proto"
	"github.com/arash16/dualnet/internal/wire"
	"gopkg.in/yaml.v3"
)

// Node is a whole node's configuration.
type Node struct {
	PSK         string            `yaml:"psk"`    // global default PSK (overridable per connection)
	MTU         int               `yaml:"mtu"`    // tunnel MTU; default proto.DefaultMTU
	Subnet      string            `yaml:"subnet"` // inner address space for the finalizer NAT
	Connections []Connection      `yaml:"connections"`
	Egresses    map[string]Egress `yaml:"egresses,omitempty"`   // named finalizers; a finalize rule references one
	Conditions  []Condition       `yaml:"conditions,omitempty"` // named routing predicates (dst_in / src_in / healthcheck)
	Routes      []Route           `yaml:"routes,omitempty"`

	// Datapath selects the node runtime: "" / "userspace" runs the packet router
	// (connections + routes + finalizers); "kernel" runs a kernel forwarder (ip rule/route
	// + iptables MASQUERADE) driven by Forward + Egresses + Conditions, with no
	// connections / tun / cipher. See internal/kernelnode.
	Datapath string `yaml:"datapath,omitempty"`
	// Forward is a kernel node's ordered forwarding policy: the first branch whose condition
	// holds (a src_in or dst_in condition) — else the default branch (empty When) — selects
	// the egress its matched traffic exits. Kernel datapath only.
	Forward []Forward `yaml:"forward,omitempty"`
	// LANIfaces are a kernel node's LAN-facing devices: traffic is forwarded from them out an
	// egress, and on-link /32 return routes for steered leg source IPs are installed on the
	// first of them. Kernel datapath only.
	LANIfaces []string `yaml:"lan_ifaces,omitempty"`

	// Healthcheck is the default probe cadence in seconds for healthcheck conditions that
	// do not set their own: nil/absent = 15, <0 never, 0 lazy, N every N seconds.
	Healthcheck *int `yaml:"healthcheck,omitempty"`
	// HealthcheckTimeout is the default silence-before-down window in seconds (default 90).
	HealthcheckTimeout int `yaml:"healthcheck_timeout,omitempty"`
	// HealthcheckUpGrace is the default sustained-liveness window in seconds required before
	// a healthcheck condition is (re)declared up (default = 2*interval, min 1s).
	HealthcheckUpGrace int `yaml:"healthcheck_up_grace,omitempty"`

	// StatsFile, if set, is a path to which the node appends runtime stats (one JSON
	// object per line) every StatsInterval seconds. Empty disables stats output.
	// Overridable at runtime by -stats / DUALNET_STATS.
	StatsFile string `yaml:"stats_file,omitempty"`
	// StatsInterval is the stats write cadence in seconds (default 10).
	StatsInterval int `yaml:"stats_interval,omitempty"`
	// StatsMaxMB caps the stats file size in MiB; when a write would exceed it the file
	// is rotated to <base>-old<ext> (overwriting the previous rotation) and restarted, so
	// on-disk size stays ~2*StatsMaxMB. Default 10; <0 disables rotation.
	StatsMaxMB int `yaml:"stats_max_mb,omitempty"`
}

// Connection describes one connection or tun.
type Connection struct {
	Name      string      `yaml:"name"`
	Type      string      `yaml:"type"`                // connect | listen | tun
	Interface string      `yaml:"interface,omitempty"` // physical iface to pin, or tun device name
	SourceIP  string      `yaml:"source_ip,omitempty"` // connect/listen: bind this source address (ip/mask) as the socket LocalAddr; dualnet creates it on Interface
	Direction string      `yaml:"direction,omitempty"` // connect/listen: outgoing | incoming
	Transport string      `yaml:"transport,omitempty"` // connect/listen: http | udp | tcp
	Port      int         `yaml:"port,omitempty"`      // connect/listen
	IP        string      `yaml:"ip,omitempty"`        // connect: remote real IP
	Warpped   bool        `yaml:"warpped,omitempty"`   // connect: dial the transport through WARP
	Multiple  bool        `yaml:"multiple,omitempty"`  // listen+outgoing: track many peers vs one
	IDSetter  string      `yaml:"id_setter,omitempty"` // connect+incoming: local tun whose id the remote sets
	PSK       string      `yaml:"psk,omitempty"`       // optional per-connection PSK override
	Cipher    string      `yaml:"cipher,omitempty"`    // chacha4 | none; default none (raw, unencrypted)
	HTTP      *HTTPConfig `yaml:"http,omitempty"`      // transport http: carrier customization

	// Tun-only.
	Address        string `yaml:"address,omitempty"`         // inner IP (unique per owner), e.g. 10.9.0.2
	CaptureDefault bool   `yaml:"capture_default,omitempty"` // route all traffic into this tun
	LANIface       string `yaml:"lan_iface,omitempty"`       // capture tun: LAN iface whose traffic is forwarded in
}

// HTTPConfig customizes the HTTP carrier of a connection whose transport is http. Every
// field is optional; an empty field falls back to the proto default (/upload, /download,
// X-Upload-Tag, Mozilla/5.0, the dial host). Both ends of a link carry the same HTTPConfig,
// so client requests and server matching agree.
type HTTPConfig struct {
	UploadPath   string            `yaml:"upload_path,omitempty"`   // POST path for the uplink body
	DownloadPath string            `yaml:"download_path,omitempty"` // GET path for the downlink body
	Host         string            `yaml:"host,omitempty"`          // Host header override
	UserAgent    string            `yaml:"user_agent,omitempty"`    // User-Agent header
	IDHeader     string            `yaml:"id_header,omitempty"`     // routing-tag header name
	Headers      map[string]string `yaml:"headers,omitempty"`       // extra request headers (client-side)
}

// Egress configures one named finalizer (internet exit). On a kernel-datapath node a warp
// egress is a kernel WireGuard device: exit names the underlay WAN its encrypted endpoint UDP
// leaves through, and tun_name names the WireGuard device itself.
type Egress struct {
	Mode       string `yaml:"mode"`                  // kernel | warp | direct; default kernel
	ExtIface   string `yaml:"exit,omitempty"`        // kernel/direct: internet-facing iface (a connection name or device); kernel-datapath warp: underlay WAN
	Gateway    string `yaml:"gateway,omitempty"`     // direct / kernel datapath: next-hop for the exit iface (auto-detected if empty)
	TunName    string `yaml:"tun_name,omitempty"`    // kernel: finalizer tun device name (default dualnet0); kernel-datapath warp: WireGuard device name (default warp-<egress>)
	WARPConfig string `yaml:"warp_config,omitempty"` // warp: wgcf profile path (wins over warp_cache)
	WARPCache  string `yaml:"warp_cache,omitempty"`  // warp: cache for an auto-registered account
	// WARPInsecure skips TLS certificate verification on the Cloudflare registration API call —
	// for a minimal router image that ships no CA bundle. It affects only that one HTTPS call
	// (skipped entirely when warp_config points at a wgcf profile); the WireGuard tunnel it
	// brings up authenticates with Noise, not TLS, so the data path is unaffected.
	WARPInsecure bool `yaml:"warp_insecure,omitempty"`
}

// Condition is a named boolean predicate referenced by a route's match.conditions (userspace)
// or a Forward branch's when (kernel). Exactly one kind is set: a per-packet DstIn
// (destination in a set), a SrcIn (source in a set; kernel only), or a Healthcheck
// (round-trip liveness; userspace only).
type Condition struct {
	Name        string           `yaml:"name"`
	DstIn       *IPSet           `yaml:"dst_in,omitempty"`      // packet predicate: dst ∈ this set
	SrcIn       *IPSet           `yaml:"src_in,omitempty"`      // kernel: source ∈ this set (lowered to `ip rule from`)
	Healthcheck *HealthcheckSpec `yaml:"healthcheck,omitempty"` // liveness of a round-trip
}

// IPSet is a set of IP prefixes used by a dst_in / src_in condition, given either as a File
// (one ip/mask or bare address per line, matched in-process with a cached longest-prefix
// table and SIGHUP/interval-reloadable) or an inline List of the same tokens. Exactly one of
// File / List is set.
type IPSet struct {
	File   string   `yaml:"file,omitempty"`
	List   []string `yaml:"list,omitempty"`
	Reload int      `yaml:"reload,omitempty"` // file: periodic reload seconds; 0 = SIGHUP-only
}

// Forward is one kernel-datapath forwarding branch: match traffic by a single condition
// (a src_in or dst_in condition named in When) — or unconditionally when When is empty (the
// default branch) — and send it out the named Egress.
type Forward struct {
	When   []string `yaml:"when,omitempty"` // condition names (exactly one, or empty for the default)
	Egress string   `yaml:"egress"`
}

// HealthcheckSpec probes a full round-trip and tracks its liveness: a ping stamped with
// Tun's owner is injected on the first up-link (Up[0]) and travels the up-path to a
// gateway, which reflects it back along the flow's reply path to Tun. Liveness is the
// whole round-trip, not a single link.
type HealthcheckSpec struct {
	Up       []string `yaml:"up"`                 // up-link path; the probe is injected on Up[0]
	Tun      string   `yaml:"tun,omitempty"`      // origin tun (default: the node's sole tun)
	Interval int      `yaml:"interval,omitempty"` // probe cadence seconds (default: node Healthcheck)
	Timeout  int      `yaml:"timeout,omitempty"`  // silence-before-down seconds (default: node timeout)
	UpGrace  int      `yaml:"up_grace,omitempty"` // sustained-liveness-before-up seconds
	// Links names the local connect connections this path uses, which the driver re-establishes
	// when the path goes silent. It scopes reconnects to THIS path's links so one path's outage
	// never tears down another path's healthy connections. Empty falls back to Up[0] alone.
	Links []string `yaml:"links,omitempty"`
}

// Route is one routing-table row.
type Route struct {
	Match  Match  `yaml:"match"`
	Action Action `yaml:"action"`
}

// Match selects packets by processed state, source connection, and named conditions.
type Match struct {
	Processed  *bool    `yaml:"processed,omitempty"`  // nil = match any; require present in practice
	Source     string   `yaml:"source,omitempty"`     // conn name, or "" = any
	Conditions []string `yaml:"conditions,omitempty"` // condition names that must all hold
}

// Action forwards a matched packet, or finalizes it through a named egress.
type Action struct {
	Egress string `yaml:"egress,omitempty"` // finalize via this named egress (reply exits via Target)
	Target string `yaml:"target"`           // connection to send to (or reply target when Egress is set)
}

// Parse reads and defaults a node config from path WITHOUT validating, so callers can
// apply overrides (e.g. a PSK from -psk / DUALNET_PSK) before Validate.
func Parse(path string) (*Node, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true) // reject typos rather than silently defaulting them
	var n Node
	if err := dec.Decode(&n); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	n.Defaults()
	return &n, nil
}

// Load reads, defaults, and validates a node config from path.
func Load(path string) (*Node, error) {
	n, err := Parse(path)
	if err != nil {
		return nil, err
	}
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return n, nil
}

// Defaults fills in unset fields (MTU, subnet, per-connection cipher, egress mode).
// It is idempotent, so it is safe to call again on an already-loaded config.
func (n *Node) Defaults() {
	if n.MTU == 0 {
		n.MTU = proto.DefaultMTU
	}
	if n.Subnet == "" {
		n.Subnet = "10.9.0.0/24"
	}
	for i := range n.Connections {
		if n.Connections[i].Cipher == "" {
			n.Connections[i].Cipher = "none"
		}
	}
	for name, eg := range n.Egresses {
		if eg.Mode == "" {
			eg.Mode = "kernel"
		}
		// Materialize a kernel-warp egress's WireGuard device name here so every consumer
		// (validation, WAN resolution, device setup, compiled-schema output) sees one value.
		if n.Datapath == "kernel" && eg.Mode == "warp" && eg.TunName == "" {
			eg.TunName = "warp-" + name
		}
		n.Egresses[name] = eg
	}
	if n.StatsInterval == 0 {
		n.StatsInterval = 10
	}
	if n.StatsMaxMB == 0 {
		n.StatsMaxMB = 10
	}
}

// ForArtifact returns a shallow copy of the config safe to serialize into a deployment
// artifact (a k8s ConfigMap, an rsync-shipped node.yaml): the global PSK is stripped, because
// every deploy path provides it out-of-band via DUALNET_PSK — a k8s Secret or a systemd env
// drop-in — and DUALNET_PSK overrides the file at runtime. Baking the secret into the config
// would defeat that separation ("the PSK is never in the configs"). Per-connection PSK
// overrides are left intact: they have no env-delivery mechanism, so stripping them would
// break the node. A node loaded from such an artifact must be given DUALNET_PSK (or -psk) at
// runtime, or it fails validation with a clear "no psk" error.
func (n Node) ForArtifact() Node {
	n.PSK = "" // value receiver: mutate the copy, not the caller's config
	return n
}

// EffectivePSK returns the connection's PSK, falling back to the node default.
func (c Connection) EffectivePSK(nodePSK string) string {
	if c.PSK != "" {
		return c.PSK
	}
	return nodePSK
}

// Key derives a connection's obfuscation/tag key.
func (c Connection) Key(nodePSK string) [32]byte { return wire.KeyFromPSK(c.EffectivePSK(nodePSK)) }

// Prefix parses the node subnet.
func (n *Node) Prefix() (netip.Prefix, error) { return netip.ParsePrefix(n.Subnet) }
