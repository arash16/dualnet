// Package netschema declares a whole dualnet network in one file and compiles it into
// the per-node configs (config.Node) that each node runs. The schema avoids repetition:
// a node's reachable IP and interfaces are named once; a link between two nodes is
// declared once (a connect on one end, a listen on the other); named egresses and named
// conditions are declared once and referenced by name; and per-node routing tables are
// DERIVED from end-to-end paths whose branches choose an egress or a gateway based on
// conditions.
package netschema

import (
	"fmt"
	"net/netip"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/arash16/dualnet/internal/config"
	"gopkg.in/yaml.v3"
)

// Network is the root schema: the whole mesh in one document.
type Network struct {
	PSK                string                   `yaml:"psk"`
	MTU                int                      `yaml:"mtu"`
	Subnet             string                   `yaml:"subnet"`
	Healthcheck        *int                     `yaml:"healthcheck"`
	HealthcheckTimeout int                      `yaml:"healthcheck_timeout"`
	HealthcheckUpGrace int                      `yaml:"healthcheck_up_grace"`
	StatsFile          string                   `yaml:"stats_file"`
	StatsInterval      int                      `yaml:"stats_interval"`
	StatsMaxMB         int                      `yaml:"stats_max_mb"`
	Protocols          map[string]ProtocolSpec  `yaml:"protocols"`  // protocol name -> configured transport
	Conditions         map[string]ConditionSpec `yaml:"conditions"` // condition name -> predicate
	Nodes              map[string]Node          `yaml:"nodes"`
	Links              Links                    `yaml:"links"`
	Paths              []Path                   `yaml:"paths"`
	Builds             map[string]BuildSpec     `yaml:"builds"` // named cross-compile recipes referenced by deploy.build
}

// ProtocolSpec is a named, configured transport that links reference by name. The
// transport is the built-in low-level carrier (http, udp or tcp); the remaining fields
// customize it. Both ends of a link resolve from the same protocol, so their transport
// parameters (paths, headers, cipher) agree by construction. The http-only fields must be
// empty unless transport is http.
type ProtocolSpec struct {
	Transport string `yaml:"transport"` // http | udp | tcp
	Cipher    string `yaml:"cipher"`    // chacha4 | none; default none (raw, unencrypted)
	Warpped   bool   `yaml:"warpped"`   // dial the transport through WARP (http only)

	// http-only carrier customization. Empty fields fall back to the proto defaults
	// (/upload, /download, X-Upload-Tag, Mozilla/5.0, the dial host).
	UploadPath   string            `yaml:"upload_path"`   // POST path for the uplink body
	DownloadPath string            `yaml:"download_path"` // GET path for the downlink body
	Host         string            `yaml:"host"`          // Host header override
	UserAgent    string            `yaml:"user_agent"`    // User-Agent header
	IDHeader     string            `yaml:"id_header"`     // routing-tag header name
	Headers      map[string]string `yaml:"headers"`       // extra request headers (client-side)
}

// hasHTTPOpts reports whether any http-only carrier field is set (independent of transport,
// so validation can reject them on a udp protocol).
func (p ProtocolSpec) hasHTTPOpts() bool {
	return p.UploadPath != "" || p.DownloadPath != "" || p.Host != "" ||
		p.UserAgent != "" || p.IDHeader != "" || len(p.Headers) > 0
}

// httpConfig materializes the http-only carrier customization into a config.HTTPConfig, or
// returns nil when the transport is not http or nothing is customized.
func (p ProtocolSpec) httpConfig() *config.HTTPConfig {
	if p.Transport != "http" || !p.hasHTTPOpts() {
		return nil
	}
	return &config.HTTPConfig{
		UploadPath: p.UploadPath, DownloadPath: p.DownloadPath, Host: p.Host,
		UserAgent: p.UserAgent, IDHeader: p.IDHeader, Headers: p.Headers,
	}
}

// Node is per-node data declared once (not repeated per connection).
type Node struct {
	IP          string                   `yaml:"ip"`          // reachable address (when this node is a link acceptor)
	Datapath    string                   `yaml:"datapath"`    // "" / userspace (packet router) | kernel (fast forwarder)
	Connections map[string]Conn          `yaml:"connections"` // name -> attachment: an interface binding, or a tun (type: tun)
	Egresses    map[string]config.Egress `yaml:"egresses"`    // named finalizers referenced by path branches
	PSK         string                   `yaml:"psk"`         // optional node-level PSK override
	Deploy      *DeploySpec              `yaml:"deploy"`      // optional: how this node's binary + config reach its host
}

// Conn is one of a node's named network attachments; the map key is its name (what a link's
// `.conn`, an egress `exit`, an id-setter arrow, and routes reference). By default it is an
// interface binding: Iface is the OS device a link's socket binds to (SO_BINDTODEVICE), and IP
// an optional source address dualnet creates there (bindable as LocalAddr + ARP-reachable on
// return). With Type "tun" it is instead a local tun device: Iface is its OS device (auto if
// empty), IP its inner address, CaptureDefault routes all traffic into it, and LAN names the
// connection whose LAN traffic is forwarded in. A node may declare several tuns (distinct keys).
type Conn struct {
	Type           string `yaml:"type,omitempty"`            // "" (interface binding) | "tun"
	Iface          string `yaml:"iface,omitempty"`           // OS device (tun: auto if empty)
	IP             string `yaml:"ip,omitempty"`              // interface: source addr; tun: inner address
	CaptureDefault bool   `yaml:"capture_default,omitempty"` // tun: route all traffic into it
	LAN            string `yaml:"lan,omitempty"`             // tun: connection whose LAN traffic is forwarded in
}

// isTun reports whether this connection is a tun device.
func (c Conn) isTun() bool { return c.Type == "tun" }

// BuildSpec is a named recipe for cross-compiling the dualnet binary, referenced by a node's
// deploy.build. It is deliberately separate from deployment: a build (an arch plus build-time
// options like upx) is reused across deploy modes — a ssh-shipped binary and a k8s image are
// produced from the same recipe — and an arch may be declared here for manual distribution
// without any node deploying it.
type BuildSpec struct {
	Arch string `yaml:"arch"`          // amd64 | arm64 | arm/v5 | arm/v6 | arm/v7 (v5 = softfloat, for a CPU without VFP)
	Upx  bool   `yaml:"upx,omitempty"` // compress with `upx --best --lzma` (transfer/image size only)
	// room to grow: ldflags, trimpath, tags, cgo — all build-time knobs, never deploy-time.
}

// DeploySpec declares how a node's compiled config and a built binary reach the host that
// runs it. Optional: a node with no deploy block is compiled but deploy.sh skips it. Like
// config.Egress, this is ONE flat, mode-discriminated struct — Mode selects which field group
// applies; the others must stay empty (enforced by validate).
type DeploySpec struct {
	Mode  string `yaml:"mode"`  // ssh | k8s
	Build string `yaml:"build"` // name of a builds: entry — the arch/binary this node ships

	// ssh mode: rsync the binary + config to a host, then (re)start it.
	Host       string `yaml:"host,omitempty"`        // ssh destination (alias or user@host); default = node name
	User       string `yaml:"user,omitempty"`        // ssh user override (for hosts absent from ~/.ssh/config)
	Port       int    `yaml:"port,omitempty"`        // ssh port override (default 22 / ssh config)
	Key        string `yaml:"key,omitempty"`         // IdentityFile override (default from ssh config)
	BinPath    string `yaml:"bin_path,omitempty"`    // remote binary path; default /usr/local/bin/dualnet
	ConfigPath string `yaml:"config_path,omitempty"` // remote config path; default /etc/dualnet/node.yaml
	FilesDir   string `yaml:"files_dir,omitempty"`   // remote dir for condition data files (dst_in); default: dir of config_path
	Daemonize  string `yaml:"daemonize,omitempty"`   // none | systemd ; default none (orthogonal to running it)
	Unit       string `yaml:"unit,omitempty"`        // daemonize=systemd: unit name; default dualnet
	RestartCmd string `yaml:"restart_cmd,omitempty"` // optional override of the built-in (re)start step

	// k8s mode: build+deliver an image, apply a generated manifest.
	Context        string `yaml:"context,omitempty"`     // kubectl context; default = current context
	Namespace      string `yaml:"namespace,omitempty"`   // default = default
	Image          string `yaml:"image,omitempty"`       // image ref; used for BOTH `docker -t` and the manifest image (required)
	Method         string `yaml:"method,omitempty"`      // registry | ctr ; default registry
	ImportHost     string `yaml:"import_host,omitempty"` // method=ctr: ssh host to `ctr import` into; default = node name
	Manifest       string `yaml:"manifest,omitempty"`    // hostNetwork | service ; default hostNetwork
	DeploymentName string `yaml:"deployment,omitempty"`  // Deployment/ConfigMap/Secret base name; default dualnet-<node>
}

// ConditionSpec is a named boolean predicate: a per-packet dst_in membership, a src_in
// membership (source IP; kernel nodes only), or a healthcheck liveness probe. Exactly one is
// set. dst_in / src_in each take an IPSet (a file or an inline list).
type ConditionSpec struct {
	DstIn       *config.IPSet    `yaml:"dst_in"`
	SrcIn       *config.IPSet    `yaml:"src_in"`
	Healthcheck *HealthcheckSpec `yaml:"healthcheck"`
}

// HealthcheckSpec probes the full round-trip of a path's gateway branch: a ping stamped with
// the origin tun's owner travels the branch's up-path to the gateway, which reflects it back
// along the flow's reply path to the tun. It names the Path (and, if that path has more than
// one gateway branch, the Gateway) rather than a single link — liveness is the whole
// round-trip, not one hop. Single-link keepalives are a separate future mechanism.
type HealthcheckSpec struct {
	Path     string `yaml:"path"`
	Gateway  string `yaml:"gateway"`
	Tun      string `yaml:"tun"`
	Interval int    `yaml:"interval"`
	Timeout  int    `yaml:"timeout"`
	UpGrace  int    `yaml:"up_grace"`
}

// Link is one directional data flow between two nodes over a transport (a connect on the
// dialer, a listen on the acceptor). In the schema it is written as one line — see Links.
type Link struct {
	Name           string
	Dialer         string
	Acceptor       string
	Dataflow       string // to-acceptor (dialer sends) | to-dialer (acceptor sends)
	Protocol       string
	Port           int
	DialerSource   string // connection on the dialer to bind: SO_BINDTODEVICE + optional LocalAddr
	AcceptorSource string
	Multiple       bool
	IDSetter       string // dialer tun connection whose owner id the acceptor assigns (from the arrow)
	PSK            string
}

// Path is one node's traffic handling: an ordered set of condition→route branches. The first
// branch whose condition holds routes the packet; a final `default` branch always matches. See
// Branches for the one-line route syntax. Name is optional — set it only so a healthcheck
// condition can reference the path.
type Path struct {
	Name   string   `yaml:"name,omitempty"`
	Node   string   `yaml:"node"`
	Routes Branches `yaml:"routes"`
}

// OriginNode returns the node a path handles.
func (p Path) OriginNode() string { return p.Node }

// Label identifies a path in error messages: its name if set, else its origin node.
func (p Path) Label() string {
	if p.Name != "" {
		return p.Name
	}
	return p.Node
}

// Branch is one alternative within a path. When is the single condition guarding it (empty for
// the default). A branch either finalizes locally through Egress on the origin node (no
// Up/Down), or forwards up to a gateway that finalizes via Egress and returns replies down.
// Gateway is DERIVED (the terminus of the last up-link); it is not written in the schema.
type Branch struct {
	When    []string
	Egress  string
	Up      []string
	Down    []string
	Gateway string // derived by inferGateways / gatewayOf
}

const (
	toAcceptor = "to-acceptor"
	toDialer   = "to-dialer"
)

// targetOf returns the node a link delivers data TO (its receiver).
func targetOf(l Link) string {
	if l.Dataflow == toAcceptor {
		return l.Acceptor
	}
	return l.Dialer
}

// gatewayOf infers a branch's gateway: the terminus of its last up-link. It returns "" for a
// local branch (no up/down), and errors if the down-path does not begin at that gateway.
func gatewayOf(br Branch, links map[string]Link) (string, error) {
	if len(br.Up) == 0 {
		if len(br.Down) != 0 {
			return "", fmt.Errorf("branch has down-links but no up-links")
		}
		return "", nil
	}
	last, ok := links[br.Up[len(br.Up)-1]]
	if !ok {
		return "", fmt.Errorf("unknown up-link %q", br.Up[len(br.Up)-1])
	}
	gw := targetOf(last)
	if len(br.Down) > 0 {
		first, ok := links[br.Down[0]]
		if !ok {
			return "", fmt.Errorf("unknown down-link %q", br.Down[0])
		}
		if src := senderOf(first); src != gw {
			return "", fmt.Errorf("up-path ends at %q but down-path starts at %q (they must be the same gateway)", gw, src)
		}
	}
	return gw, nil
}

// inferGateways fills each branch's derived Gateway from its up/down links. Idempotent, so it
// is safe to run from both validate (via Load) and Compile (called directly by tests).
func (n *Network) inferGateways(links map[string]Link) error {
	for pi := range n.Paths {
		for bi := range n.Paths[pi].Routes {
			gw, err := gatewayOf(n.Paths[pi].Routes[bi], links)
			if err != nil {
				return fmt.Errorf("netschema: path for node %q: %w", n.Paths[pi].OriginNode(), err)
			}
			n.Paths[pi].Routes[bi].Gateway = gw
		}
	}
	return nil
}

// linkMap indexes the parsed links by name.
func (n *Network) linkMap() map[string]Link {
	m := make(map[string]Link, len(n.Links))
	for _, l := range n.Links {
		m[l.Name] = l
	}
	return m
}

// Load reads and validates a network schema from path.
func Load(path string) (*Network, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var n Network
	if err := dec.Decode(&n); err != nil {
		return nil, fmt.Errorf("netschema: parse %s: %w", path, err)
	}
	if err := n.validate(); err != nil {
		return nil, err
	}
	return &n, nil
}

func (n *Network) validate() error {
	if len(n.Nodes) == 0 {
		return fmt.Errorf("netschema: no nodes")
	}
	for name, nd := range n.Nodes {
		switch nd.Datapath {
		case "", "userspace":
		case "kernel":
			for cn, c := range nd.Connections {
				if c.isTun() {
					return fmt.Errorf("netschema: kernel node %q must not declare a tun (connection %q)", name, cn)
				}
			}
			if len(nd.Egresses) == 0 {
				return fmt.Errorf("netschema: kernel node %q needs at least one egress", name)
			}
			// Early mode/exit checks so a schema error names the schema, not a compiled
			// artifact; the deep per-mode rules run in config.Validate on every compiled node.
			for en, eg := range nd.Egresses {
				switch eg.Mode {
				case "", "kernel", "warp":
				default:
					return fmt.Errorf("netschema: kernel node %q egress %q mode %q must be kernel or warp", name, en, eg.Mode)
				}
				if eg.ExtIface == "" {
					return fmt.Errorf("netschema: kernel node %q egress %q needs exit (warp: the underlay WAN)", name, en)
				}
			}
		default:
			return fmt.Errorf("netschema: node %q datapath %q must be userspace or kernel", name, nd.Datapath)
		}
		captures := 0
		for cn, c := range nd.Connections {
			if c.IP != "" && !validSourceIP(c.IP) {
				return fmt.Errorf("netschema: node %q connection %q bad ip %q", name, cn, c.IP)
			}
			switch c.Type {
			case "":
				if c.Iface == "" {
					return fmt.Errorf("netschema: node %q connection %q has no iface", name, cn)
				}
				if c.CaptureDefault || c.LAN != "" {
					return fmt.Errorf("netschema: node %q connection %q sets capture_default/lan but is not a tun (type: tun)", name, cn)
				}
			case "tun":
				if c.CaptureDefault {
					captures++
					if c.IP == "" {
						return fmt.Errorf("netschema: node %q tun %q sets capture_default but has no ip (address)", name, cn)
					}
				}
				if c.LAN != "" {
					if !c.CaptureDefault {
						return fmt.Errorf("netschema: node %q tun %q sets lan but not capture_default", name, cn)
					}
					if lc, ok := nd.Connections[c.LAN]; !ok || lc.isTun() {
						return fmt.Errorf("netschema: node %q tun %q lan %q is not an interface connection", name, cn, c.LAN)
					}
				}
			default:
				return fmt.Errorf("netschema: node %q connection %q type %q must be empty or tun", name, cn, c.Type)
			}
		}
		if captures > 1 {
			return fmt.Errorf("netschema: node %q has more than one capture_default tun", name)
		}
	}
	for name, p := range n.Protocols {
		if p.Transport != "http" && p.Transport != "udp" && p.Transport != "tcp" {
			return fmt.Errorf("netschema: protocol %q transport %q must be http, udp or tcp", name, p.Transport)
		}
		if p.Transport != "http" {
			if p.hasHTTPOpts() {
				return fmt.Errorf("netschema: protocol %q sets http-only fields but transport is %q", name, p.Transport)
			}
			if p.Warpped {
				return fmt.Errorf("netschema: protocol %q sets warpped but transport is %q (WARP is wired for the http carrier only)", name, p.Transport)
			}
		}
	}
	links := make(map[string]Link, len(n.Links))
	for _, l := range n.Links {
		if l.Name == "" {
			return fmt.Errorf("netschema: a link has no name")
		}
		if _, dup := links[l.Name]; dup {
			return fmt.Errorf("netschema: duplicate link name %q", l.Name)
		}
		links[l.Name] = l
		if _, ok := n.Nodes[l.Dialer]; !ok {
			return fmt.Errorf("netschema: link %q dialer %q is not a node", l.Name, l.Dialer)
		}
		if _, ok := n.Nodes[l.Acceptor]; !ok {
			return fmt.Errorf("netschema: link %q acceptor %q is not a node", l.Name, l.Acceptor)
		}
		if l.Dataflow != toAcceptor && l.Dataflow != toDialer {
			return fmt.Errorf("netschema: link %q dataflow %q must be %q or %q", l.Name, l.Dataflow, toAcceptor, toDialer)
		}
		if l.Protocol == "" {
			return fmt.Errorf("netschema: link %q has no protocol", l.Name)
		}
		if _, ok := n.Protocols[l.Protocol]; !ok {
			return fmt.Errorf("netschema: link %q references unknown protocol %q", l.Name, l.Protocol)
		}
		if n.Nodes[l.Acceptor].IP == "" {
			return fmt.Errorf("netschema: link %q acceptor %q needs an ip (the dialer must reach it)", l.Name, l.Acceptor)
		}
		if n.Nodes[l.Dialer].Datapath == "kernel" || n.Nodes[l.Acceptor].Datapath == "kernel" {
			return fmt.Errorf("netschema: link %q has a kernel-datapath endpoint (kernel nodes carry no links)", l.Name)
		}
		if l.DialerSource != "" {
			if _, ip := n.Nodes[l.Dialer].resolveSource(l.DialerSource); ip != "" && n.Protocols[l.Protocol].Warpped {
				return fmt.Errorf("netschema: link %q binds source %q (ip) but protocol %q is warpped — WARP cannot bind a source", l.Name, l.DialerSource, l.Protocol)
			}
		}
	}
	if err := n.inferGateways(links); err != nil {
		return err
	}
	// One path per node; only NAMED paths are referenceable by a healthcheck condition.
	paths := map[string]bool{}
	pathNodes := map[string]bool{}
	for _, p := range n.Paths {
		if p.Node == "" {
			return fmt.Errorf("netschema: a path has no node")
		}
		if pathNodes[p.Node] {
			return fmt.Errorf("netschema: node %q has more than one path", p.Node)
		}
		pathNodes[p.Node] = true
		if p.Name != "" {
			if paths[p.Name] {
				return fmt.Errorf("netschema: duplicate path name %q", p.Name)
			}
			paths[p.Name] = true
		}
	}
	condKind := map[string]string{} // condition name -> "dst" | "src" | "health"
	for name, c := range n.Conditions {
		set := 0
		if c.DstIn != nil {
			set++
		}
		if c.SrcIn != nil {
			set++
		}
		if c.Healthcheck != nil {
			set++
		}
		if set != 1 {
			return fmt.Errorf("netschema: condition %q must set exactly one of dst_in / src_in / healthcheck", name)
		}
		switch {
		case c.DstIn != nil:
			if err := c.DstIn.Validate(name); err != nil {
				return err
			}
			condKind[name] = "dst"
		case c.SrcIn != nil:
			if err := c.SrcIn.Validate(name); err != nil {
				return err
			}
			condKind[name] = "src"
		default:
			if !paths[c.Healthcheck.Path] {
				return fmt.Errorf("netschema: condition %q healthcheck path %q is not a path", name, c.Healthcheck.Path)
			}
			condKind[name] = "health"
		}
	}
	for _, p := range n.Paths {
		origin := p.OriginNode()
		nd, ok := n.Nodes[origin]
		if !ok {
			return fmt.Errorf("netschema: path %q node %q is not a node", p.Label(), origin)
		}
		kernel := nd.Datapath == "kernel"
		if !kernel {
			if _, ok := nd.originTun(); !ok {
				return fmt.Errorf("netschema: path %q origin %q has no tun connection (or has several without one capturing the default)", p.Label(), origin)
			}
		}
		if len(p.Routes) == 0 {
			return fmt.Errorf("netschema: path %q has no routes", p.Label())
		}
		if kernel {
			if err := n.validateKernelPath(p, condKind); err != nil {
				return err
			}
			continue
		}
		sawDefault := false
		for _, br := range p.Routes {
			if len(br.When) == 0 {
				sawDefault = true
			} else if sawDefault {
				return fmt.Errorf("netschema: path %q has a branch after the default", p.Label())
			}
			for _, cn := range br.When {
				if condKind[cn] == "" {
					return fmt.Errorf("netschema: path %q references unknown condition %q", p.Label(), cn)
				}
				if condKind[cn] == "src" {
					return fmt.Errorf("netschema: path %q uses src_in condition %q on a userspace node (src_in is kernel-only)", p.Label(), cn)
				}
			}
			if br.Egress == "" {
				return fmt.Errorf("netschema: path %q has a branch with no egress", p.Label())
			}
			// br.Gateway was derived by inferGateways (the terminus of the last up-link, "" for
			// a local branch); it also validated up/down link existence and consistency.
			for _, ln := range append(append([]string{}, br.Up...), br.Down...) {
				if _, ok := links[ln]; !ok {
					return fmt.Errorf("netschema: path %q references unknown link %q", p.Label(), ln)
				}
			}
		}
		if !sawDefault {
			return fmt.Errorf("netschema: path %q needs a `default` branch (the always-last catch-all)", p.Label())
		}
	}
	for name, b := range n.Builds {
		if err := b.validate(name); err != nil {
			return err
		}
	}
	for name, nd := range n.Nodes {
		if nd.Deploy != nil {
			if err := nd.Deploy.validate(name, n.Builds); err != nil {
				return err
			}
		}
	}
	return nil
}

// ArchBuild expands a schema arch value into the facts a cross-compile and a container build
// need: GOARCH, GOARM ("" when not arm), and the docker `--platform`. ok is false for an
// unknown arch. This is the single source of truth for the supported arch set — validate()
// and internal/release both go through it (release imports netschema, not the reverse). The
// arm variants map to Go's GOARM float levels: v5=softfloat (no VFP), v6=VFPv2, v7=VFPv3 —
// pick v5 for a CPU whose /proc/cpuinfo Features has no `vfp`, or GOARM=7 code faults (SIGILL).
func ArchBuild(arch string) (goarch, goarm, platform string, ok bool) {
	switch arch {
	case "amd64":
		return "amd64", "", "linux/amd64", true
	case "arm64":
		return "arm64", "", "linux/arm64", true
	case "arm/v5":
		return "arm", "5", "linux/arm/v5", true
	case "arm/v6":
		return "arm", "6", "linux/arm/v6", true
	case "arm/v7":
		return "arm", "7", "linux/arm/v7", true
	default:
		return "", "", "", false
	}
}

// validate checks a build recipe. Errors use the netschema: prefix and the first-error style.
func (b BuildSpec) validate(name string) error {
	if _, _, _, ok := ArchBuild(b.Arch); !ok {
		return fmt.Errorf("netschema: build %q arch %q must be amd64, arm64, arm/v5, arm/v6, or arm/v7", name, b.Arch)
	}
	return nil
}

// validate checks a DeploySpec for mode-appropriate fields against the mesh's build recipes,
// mirroring the imperative, first-error style of the rest of netschema (and config.validateEgresses).
func (d *DeploySpec) validate(node string, builds map[string]BuildSpec) error {
	if d.Build == "" {
		return fmt.Errorf("netschema: node %q deploy has no build", node)
	}
	if _, ok := builds[d.Build]; !ok {
		return fmt.Errorf("netschema: node %q deploy references unknown build %q", node, d.Build)
	}
	switch d.Mode {
	case "ssh":
		if d.Context != "" || d.Namespace != "" || d.Image != "" || d.Method != "" ||
			d.ImportHost != "" || d.Manifest != "" || d.DeploymentName != "" {
			return fmt.Errorf("netschema: node %q deploy mode ssh sets k8s-only fields", node)
		}
		switch d.Daemonize {
		case "", "none", "systemd":
		default:
			return fmt.Errorf("netschema: node %q deploy daemonize %q must be none or systemd", node, d.Daemonize)
		}
	case "k8s":
		if d.Host != "" || d.User != "" || d.Port != 0 || d.Key != "" || d.BinPath != "" ||
			d.ConfigPath != "" || d.FilesDir != "" || d.Daemonize != "" || d.Unit != "" || d.RestartCmd != "" {
			return fmt.Errorf("netschema: node %q deploy mode k8s sets ssh-only fields", node)
		}
		if d.Image == "" {
			return fmt.Errorf("netschema: node %q deploy mode k8s needs an image", node)
		}
		switch d.Method {
		case "", "registry", "ctr":
		default:
			return fmt.Errorf("netschema: node %q deploy method %q must be registry or ctr", node, d.Method)
		}
		switch d.Manifest {
		case "", "hostNetwork", "service":
		default:
			return fmt.Errorf("netschema: node %q deploy manifest %q must be hostNetwork or service", node, d.Manifest)
		}
	default:
		return fmt.Errorf("netschema: node %q deploy mode %q must be ssh or k8s", node, d.Mode)
	}
	return nil
}

// filesDir is the remote directory a node's condition data files (dst_in) are copied into,
// defaulting to the directory of the config path (so they sit next to node.yaml).
func (d *DeploySpec) filesDir() string {
	if d.FilesDir != "" {
		return d.FilesDir
	}
	cfg := d.ConfigPath
	if cfg == "" {
		cfg = "/etc/dualnet/node.yaml"
	}
	return path.Dir(cfg)
}

// remoteConditionFile maps a dst_in condition's data file — a LOCAL source path in the schema
// — to where it will live on the node at runtime: <files_dir>/<basename> when the node is
// deployed (deploy.sh copies it there), else the local path unchanged (for a locally-run node).
func (n *Network) remoteConditionFile(node, localFile string) string {
	nd := n.Nodes[node]
	if nd.Deploy == nil {
		return localFile
	}
	return nd.Deploy.filesDir() + "/" + path.Base(localFile)
}

// originTun returns the connection name of the node's origin tun for path routing: a
// capture-default tun if present, else the sole tun. ok is false if the node has no tun, or
// several tuns with none capturing the default (ambiguous — which one sources the path?).
func (nd Node) originTun() (string, bool) {
	capture, sole, n := "", "", 0
	for name, c := range nd.Connections {
		if !c.isTun() {
			continue
		}
		n++
		sole = name
		if c.CaptureDefault {
			capture = name
		}
	}
	if capture != "" {
		return capture, true
	}
	if n == 1 {
		return sole, true
	}
	return "", false
}

// resolveIface maps a connection name to its device, or returns the value unchanged if it is
// not a declared connection (a raw device name). "" stays "".
func (nd Node) resolveIface(name string) string {
	iface, _ := nd.resolveSource(name)
	return iface
}

// resolveSource maps a connection name to its (device, ip). A raw device name (not a declared
// connection) resolves to (name, ""). "" stays ("", "").
func (nd Node) resolveSource(name string) (iface, ip string) {
	if name == "" {
		return "", ""
	}
	if c, ok := nd.Connections[name]; ok {
		return c.Iface, c.IP
	}
	return name, ""
}

// kernelLANIfaces returns a kernel node's LAN-facing devices: every (non-tun) connection device
// that is not used as an egress exit (those are its WANs), deduplicated and sorted.
func (nd Node) kernelLANIfaces() []string {
	wan := map[string]bool{}
	for _, eg := range nd.Egresses {
		wan[nd.resolveIface(eg.ExtIface)] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range nd.Connections {
		if c.isTun() || c.Iface == "" || wan[c.Iface] || seen[c.Iface] {
			continue
		}
		seen[c.Iface] = true
		out = append(out, c.Iface)
	}
	sort.Strings(out)
	return out
}

// senderOf returns the node that sends inner packets on link l (its data source).
func senderOf(l Link) string {
	if l.Dataflow == toAcceptor {
		return l.Dialer
	}
	return l.Acceptor
}

// validateKernelPath checks a kernel node's forwarding path: local-egress branches only (no
// gateway), each conditional branch names exactly one src_in/dst_in condition and an egress on
// the node, and branches are ordered src_in*, dst_in*, then exactly one default (no `when`).
func (n *Network) validateKernelPath(p Path, condKind map[string]string) error {
	origin := p.OriginNode()
	egresses := n.Nodes[origin].Egresses
	phase := 0 // 0=src_in, 1=dst_in, 2=default seen
	defaults := 0
	for _, br := range p.Routes {
		if len(br.Up) != 0 || len(br.Down) != 0 {
			return fmt.Errorf("netschema: path %q (kernel node %q) cannot forward to a gateway (no up/down links)", p.Label(), origin)
		}
		if br.Egress == "" {
			return fmt.Errorf("netschema: path %q has a branch with no egress", p.Label())
		}
		if _, ok := egresses[br.Egress]; !ok {
			return fmt.Errorf("netschema: path %q branch egress %q is not an egress on kernel node %q", p.Label(), br.Egress, origin)
		}
		if len(br.When) == 0 {
			defaults++
			phase = 2
			continue
		}
		if phase == 2 {
			return fmt.Errorf("netschema: path %q has a branch after the default branch", p.Label())
		}
		if len(br.When) != 1 {
			return fmt.Errorf("netschema: path %q kernel branch must name exactly one condition", p.Label())
		}
		switch condKind[br.When[0]] {
		case "src":
			if phase > 0 {
				return fmt.Errorf("netschema: path %q src_in branch must come before dst_in branches", p.Label())
			}
		case "dst":
			phase = 1
		default:
			return fmt.Errorf("netschema: path %q kernel branch condition %q must be src_in or dst_in", p.Label(), br.When[0])
		}
	}
	if defaults != 1 {
		return fmt.Errorf("netschema: path %q (kernel node %q) needs exactly one default branch (got %d)", p.Label(), origin, defaults)
	}
	return nil
}

// validSourceIP reports whether s is a valid source address: a bare IP or an ip/mask prefix.
func validSourceIP(s string) bool {
	if strings.ContainsRune(s, '/') {
		_, err := netip.ParsePrefix(s)
		return err == nil
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}
