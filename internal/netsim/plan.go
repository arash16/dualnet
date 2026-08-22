package netsim

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/netschema"
	"github.com/arash16/dualnet/internal/netsim/siminit"
	"gopkg.in/yaml.v3"
)

// Fixed addresses of the simulated internet. Every egress ultimately reaches the hub, which
// owns these two service IPs on `lo`; IranDst is written into every generated dst_in prefix
// file, WorldDst is not — so a dst_in branch is selected by probing one vs the other.
const (
	echoNet   = "10.200.0.0/24"
	worldDst  = "10.200.0.10"
	iranDst   = "10.200.0.20"
	hubName   = "internet" // the hub container name
	hubOctet  = 254        // the hub's host octet on every fabric it joins
	statsPath = "/var/log/dualnet-stats.jsonl"
	configDir = "/etc/dualnet"
	specPath  = "/etc/sim/init.json"
)

// PlanOptions tunes a plan; the zero value is filled with deterministic defaults.
type PlanOptions struct {
	Image string // test image tag (default "dualnet-sim:test")
	PSK   string // uniform mesh PSK (default "netsim")
	// PSKOverride sets a node's PSK to something other than PSK (for the PSK-mismatch check).
	PSKOverride map[string]string
	// Fast healthcheck timing so failover/self-heal converge in seconds (default 1/3/1).
	HealthcheckInterval, HealthcheckTimeout, HealthcheckUpGrace int
	StatsInterval                                               int    // stats snapshot cadence, seconds (default 1)
	NetBase                                                     string // fabric address base, "A.B" (default "172.30")
}

func (o *PlanOptions) applyDefaults() {
	if o.Image == "" {
		o.Image = "dualnet-sim:test"
	}
	if o.PSK == "" {
		o.PSK = "netsim"
	}
	if o.HealthcheckInterval == 0 {
		o.HealthcheckInterval = 1
	}
	if o.HealthcheckTimeout == 0 {
		o.HealthcheckTimeout = 3
	}
	if o.HealthcheckUpGrace == 0 {
		o.HealthcheckUpGrace = 1
	}
	if o.StatsInterval == 0 {
		o.StatsInterval = 1
	}
	if o.NetBase == "" {
		o.NetBase = "172.30"
	}
}

// endpoint identifies one NIC: a node plus a device key. An explicit device shares a key
// ("dev:<name>") across every link/egress/lan that names it (so one NIC = one fabric); an
// unspecified link side gets a per-link synthetic key so it becomes its own NIC.
type endpoint struct {
	node string
	key  string
}

func epKey(dev, link, side string) string {
	if dev != "" {
		return "dev:" + dev
	}
	return "auto:" + link + ":" + side
}

// Plan derives the full simulation for a network schema. It is pure (no I/O) and
// deterministic: fabrics and addresses are ordered by sorted signatures, so the same schema
// always yields the same plan.
func Plan(net *netschema.Network, opts PlanOptions) (*SimPlan, error) {
	opts.applyDefaults()
	nodes, err := net.Compile()
	if err != nil {
		return nil, fmt.Errorf("netsim: compile: %w", err)
	}
	for node, cn := range nodes {
		for name, eg := range cn.Egresses {
			// A kernel-datapath warp egress IS simulable: the hub terminates a real kernel
			// WireGuard tunnel and netsim generates the wgcf-style profile. The userspace warp
			// dialer stays unsimulated — it would drag netstack/reserved-bytes behavior in for
			// no coverage the kernel path doesn't already give.
			if eg.Mode == "warp" && cn.Datapath != "kernel" {
				return nil, fmt.Errorf("netsim: node %q egress %q uses warp mode on a userspace node; only kernel-datapath warp is simulated (a kernel WireGuard peer on the hub)", node, name)
			}
		}
	}

	linksByName := map[string]netschema.Link{}
	for _, l := range net.Links {
		linksByName[l.Name] = l
	}

	// 1. Build the endpoint graph and union link sides.
	u := newUF()
	for _, l := range net.Links {
		dEP := endpoint{l.Dialer, epKey(resolveIface(net.Nodes[l.Dialer], l.DialerSource), l.Name, "d")}
		aEP := endpoint{l.Acceptor, epKey(resolveIface(net.Nodes[l.Acceptor], l.AcceptorSource), l.Name, "a")}
		u.union(dEP, aEP)
	}
	// Egress and LAN NICs: add (they may coincide with a link NIC by key) and mark roles.
	egressEP := map[endpoint]bool{}
	captureOf := map[endpoint]string{}
	for _, name := range sortedKeys(net.Nodes) {
		nd := net.Nodes[name]
		for _, eg := range nodes[name].Egresses {
			ep := endpoint{name, "dev:" + eg.ExtIface} // ExtIface already resolved by Compile
			u.add(ep)
			egressEP[ep] = true
		}
		if _, tc, ok := captureTun(nd); ok && tc.LAN != "" {
			ep := endpoint{name, "dev:" + resolveIface(nd, tc.LAN)}
			u.add(ep)
			captureOf[ep] = name
		}
		// A kernel node forwards from its (first) LAN device; model it as a fabric with a LAN
		// client behind it, the same way a capture-tun node's LAN is modeled.
		if cn := nodes[name]; cn.Datapath == "kernel" && len(cn.LANIfaces) > 0 {
			ep := endpoint{name, "dev:" + cn.LANIfaces[0]}
			u.add(ep)
			captureOf[ep] = name
		}
	}

	// 2. Materialise fabrics from union-find components, ordered by a canonical signature.
	comps := u.components()
	type comp struct {
		sig       string
		root      endpoint
		nodes     []string // schema nodes on this fabric (sorted, unique)
		egress    bool     // hub joins
		lanFor    string   // capture node (client joins), or ""
		endpoints []endpoint
	}
	var cs []comp
	for root, eps := range comps {
		nodeSet := map[string]bool{}
		var sigParts []string
		egress, lanFor := false, ""
		for _, e := range eps {
			nodeSet[e.node] = true
			sigParts = append(sigParts, e.node+"|"+e.key)
			if egressEP[e] {
				egress = true
			}
			if c, ok := captureOf[e]; ok {
				lanFor = c
			}
		}
		sort.Strings(sigParts)
		cs = append(cs, comp{sig: strings.Join(sigParts, ","), root: root, nodes: sortedSet(nodeSet), egress: egress, lanFor: lanFor, endpoints: eps})
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].sig < cs[j].sig })

	fabricOf := map[endpoint]string{} // endpoint -> fabric name
	fabrics := make([]Fabric, 0, len(cs))
	for i, c := range cs {
		subnet := fmt.Sprintf("%s.%d.0/24", opts.NetBase, i+1)
		host := func(octet int) string { return fmt.Sprintf("%s.%d.%d", opts.NetBase, i+1, octet) }
		f := Fabric{Name: fmt.Sprintf("net%d", i), Subnet: subnet, IPs: map[string]string{}}
		octet := 2
		for _, n := range c.nodes {
			f.IPs[n] = host(octet)
			octet++
		}
		if c.egress {
			f.IPs[hubName] = host(hubOctet)
		}
		if c.lanFor != "" {
			f.IPs[clientName(c.lanFor)] = host(octet)
			octet++
		}
		for _, e := range c.endpoints {
			fabricOf[e] = f.Name
		}
		fabrics = append(fabrics, f)
	}
	fabricByName := map[string]*Fabric{}
	for i := range fabrics {
		fabricByName[fabrics[i].Name] = &fabrics[i]
	}

	sp := &SimPlan{
		Image: opts.Image, Fabrics: fabrics,
		EchoNet: echoNet, WorldDst: worldDst, IranDst: iranDst,
		egressIP: map[string]map[string]string{}, nodeContainer: map[string]string{},
		lanClient: map[string]string{}, selfCapture: map[string]bool{}, debugTun: map[string]bool{},
		conditionFile: map[string]map[string]string{},
	}

	// 3. Per-node dn-name assignment for every NIC the config binds to (needs renaming).
	simDev := map[string]map[string]string{} // node -> fabric -> dnN
	renames := map[string][]siminit.Rename{} // node -> renames
	assignDev := func(node, fabric string) string {
		if simDev[node] == nil {
			simDev[node] = map[string]string{}
		}
		if d, ok := simDev[node][fabric]; ok {
			return d
		}
		d := fmt.Sprintf("dn%d", len(simDev[node]))
		simDev[node][fabric] = d
		renames[node] = append(renames[node], siminit.Rename{Subnet: fabricByName[fabric].Subnet, Name: d})
		return d
	}
	// Pre-assign deterministically: collect referenced fabrics per node, sorted, then assign.
	refFabs := map[string]map[string]bool{}
	markRef := func(node, fabric string) {
		if refFabs[node] == nil {
			refFabs[node] = map[string]bool{}
		}
		refFabs[node][fabric] = true
	}
	for _, node := range sortedKeys(nodes) {
		cn := nodes[node]
		for _, c := range cn.Connections {
			switch c.Type {
			case "connect":
				l := linksByName[c.Name]
				if l.DialerSource != "" {
					markRef(node, fabricOf[endpoint{node, epKey(resolveIface(net.Nodes[node], l.DialerSource), l.Name, "d")}])
				}
			case "listen":
				l := linksByName[c.Name]
				if l.AcceptorSource != "" {
					markRef(node, fabricOf[endpoint{node, "dev:" + resolveIface(net.Nodes[node], l.AcceptorSource)}])
				}
			case "tun":
				if c.LANIface != "" {
					markRef(node, fabricOf[endpoint{node, "dev:" + c.LANIface}])
				}
			}
		}
		for _, eg := range cn.Egresses {
			markRef(node, fabricOf[endpoint{node, "dev:" + eg.ExtIface}])
		}
		if cn.Datapath == "kernel" && len(cn.LANIfaces) > 0 {
			markRef(node, fabricOf[endpoint{node, "dev:" + cn.LANIfaces[0]}])
		}
	}
	for _, node := range sortedKeys(refFabs) {
		for _, fab := range sortedSet(refFabs[node]) {
			assignDev(node, fab)
		}
	}

	// 3b. Leg-return routes. When a link's DIALER binds a source IP that is not on the link's
	// fabric (an asymmetric-bond up-leg, e.g. laptop.iran = 10.99.0.1/32), the acceptor has no
	// route back to it — in a real mesh the intermediate router owns/steers that leg, but the sim
	// collapses the link to a direct fabric with no router. Give the acceptor an on-link /32
	// return route to the leg (via the dialer's fabric IP, which the dialer answers ARP for since
	// dualnet created the leg address on that NIC), so the leg-sourced flow round-trips. This
	// models exactly the return path the router provides, decoupled from testing the router itself.
	legReturnRoutes := map[string][]siminit.Route{}
	for _, l := range net.Links {
		host := legSourceHost(net.Nodes[l.Dialer], l.DialerSource)
		if host == "" {
			continue
		}
		aFab := fabricOf[endpoint{l.Acceptor, epKey(resolveIface(net.Nodes[l.Acceptor], l.AcceptorSource), l.Name, "a")}]
		if dialerIP := fabricByName[aFab].IPs[l.Dialer]; dialerIP != "" {
			legReturnRoutes[l.Acceptor] = append(legReturnRoutes[l.Acceptor], siminit.Route{Dst: host, Via: dialerIP})
		}
	}

	// WARP hub state: the hub plays Cloudflare for every kernel-warp egress with a single
	// WireGuard device; each egress becomes one peer with a CGNAT tunnel address.
	hubPriv, hubPub := warpKeys("hub")
	var hubPeers []siminit.WGPeer
	warpOctet := 2 // 100.64.0.1 is the hub; nodes start at .2

	// 4. Rewrite each node's compiled config for the sim, and build its container.
	for _, node := range sortedKeys(nodes) {
		cn := nodes[node]
		sp.nodeContainer[node] = node
		sp.debugTun[node] = isDebugTun(net.Nodes[node])
		// A capture-tun node with no `lan:` captures its own traffic (a client, not a LAN
		// router): it is driven by an HTTP probe inside its own container, not a separate client.
		if _, tc, ok := captureTun(net.Nodes[node]); ok && tc.LAN == "" {
			sp.selfCapture[node] = true
		}

		hi := opts.HealthcheckInterval
		cn.Healthcheck, cn.HealthcheckTimeout, cn.HealthcheckUpGrace = &hi, opts.HealthcheckTimeout, opts.HealthcheckUpGrace
		cn.StatsFile, cn.StatsInterval, cn.StatsMaxMB = statsPath, opts.StatsInterval, 50
		psk := opts.PSK
		if o, ok := opts.PSKOverride[node]; ok {
			psk = o
		}
		cn.PSK = psk

		attachFabs := map[string]bool{}
		var routes []siminit.Route
		for i := range cn.Connections {
			c := &cn.Connections[i]
			switch c.Type {
			case "connect":
				l := linksByName[c.Name]
				fab := fabricOf[endpoint{node, epKey(resolveIface(net.Nodes[node], l.DialerSource), l.Name, "d")}]
				attachFabs[fab] = true
				c.IP = fabricByName[fab].IPs[l.Acceptor]
				if l.DialerSource != "" {
					c.Interface = simDev[node][fab]
				}
			case "listen":
				l := linksByName[c.Name]
				fab := fabricOf[endpoint{node, epKey(resolveIface(net.Nodes[node], l.AcceptorSource), l.Name, "a")}]
				attachFabs[fab] = true
				if l.AcceptorSource != "" {
					c.Interface = simDev[node][fab]
				}
			case "tun":
				if c.LANIface != "" {
					fab := fabricOf[endpoint{node, "dev:" + c.LANIface}]
					attachFabs[fab] = true
					// No LAN NAT injected here: dualnet's own ConfigureLANForward must SNAT LAN
					// hosts into the capture tun so the gateway's (inner-subnet-scoped) MASQUERADE
					// covers them. Faking it here would hide a router that fails to do so — the
					// LAN-client-can't-egress-via-gateway bug this sim now genuinely exercises.
					c.LANIface = simDev[node][fab]
				}
			}
		}
		warpFiles := map[string][]byte{} // wgcf profiles for this node's kernel-warp egresses
		for _, name := range sortedKeys(cn.Egresses) {
			eg := cn.Egresses[name]
			fab := fabricOf[endpoint{node, "dev:" + eg.ExtIface}]
			attachFabs[fab] = true
			if sp.egressIP[node] == nil {
				sp.egressIP[node] = map[string]string{}
			}
			dev := simDev[node][fab]
			hub := fabricByName[fab].IPs[hubName]
			sp.egressIP[node][name] = fabricByName[fab].IPs[node]
			eg.ExtIface = dev
			switch {
			case eg.Mode == "warp":
				// Kernel-warp: the node tunnels to the hub (playing Cloudflare) over the underlay
				// fabric. Its oracle is the generated CGNAT tunnel address the hub observes once
				// the node masquerades LAN traffic out the wg device — distinct from every underlay
				// IP, so a scenario can tell "went through the tunnel" from "leaked out the underlay".
				tunIP := fmt.Sprintf("100.64.0.%d", warpOctet)
				warpOctet++
				sp.egressIP[node][name] = tunIP
				priv, pub := warpKeys(node + "/" + name)
				conf := configDir + "/warp-" + name + ".conf"
				warpFiles[conf] = warpINI(priv, hubPub, fmt.Sprintf("%s:%d", hub, warpPort), tunIP)
				eg.WARPConfig, eg.WARPCache = conf, ""
				hubPeers = append(hubPeers, siminit.WGPeer{PublicKey: pub.String(), AllowedIPs: []string{tunIP + "/32"}})
				sp.NeedsWireGuard = true
			case cn.Datapath == "kernel":
				// A kernel node's WAN reaches the hub (and the echo net beyond it) via an explicit
				// gateway; resolveWANs uses it for the egress table's default route, so the sim
				// container needs no live default route the way a real router has.
				eg.Gateway = hub
			case eg.Mode == "direct":
				eg.Gateway = hub // dualnet's PinIfaceDefault routes bound sockets via the hub
			default: // userspace kernel egress (tun-NAT finalizer): route the echo net via the hub
				routes = append(routes, siminit.Route{Dst: echoNet, Via: hub, Dev: dev})
			}
			cn.Egresses[name] = eg
		}
		// Kernel node: attach its LAN fabric and rewrite its LAN device(s) to the sim NIC name.
		if cn.Datapath == "kernel" && len(cn.LANIfaces) > 0 {
			fab := fabricOf[endpoint{node, "dev:" + cn.LANIfaces[0]}]
			attachFabs[fab] = true
			cn.LANIfaces = []string{simDev[node][fab]}
		}

		files := map[string][]byte{}
		cfgYAML, err := yaml.Marshal(cn)
		if err != nil {
			return nil, fmt.Errorf("netsim: marshal config for %q: %w", node, err)
		}
		files[configDir+"/"+node+".yaml"] = cfgYAML
		for path, content := range warpFiles {
			files[path] = content
		}
		// dst_in prefix files: put the iran service IP in each referenced file, at the compiled
		// runtime path (which is what dualnet reads). Record it so the SIGHUP scenario appends
		// to the same file rather than the raw schema path.
		for _, cond := range cn.Conditions {
			if cond.DstIn != nil {
				files[cond.DstIn.File] = []byte(fmt.Sprintf("# generated by netsim\n%s/32\n", iranDst))
				if sp.conditionFile[node] == nil {
					sp.conditionFile[node] = map[string]string{}
				}
				sp.conditionFile[node][cond.Name] = cond.DstIn.File
			}
		}
		routes = append(routes, legReturnRoutes[node]...) // return routes to any leg the node accepts
		spec := siminit.Spec{Renames: renames[node], Routes: routes}
		files[specPath] = mustJSON(spec)

		dualnetArgs := []string{"dualnet", "-config", configDir + "/" + node + ".yaml"}
		if sp.debugTun[node] {
			dualnetArgs = append(dualnetArgs, "-debug-tun")
		}
		ctr := Container{
			Name: node, Role: RoleNode, Node: node,
			Cmd:     append([]string{"sim", "init", "-spec", specPath, "--"}, dualnetArgs...),
			CapAdd:  []string{"NET_ADMIN", "NET_RAW"},
			Sysctls: map[string]string{"net.ipv4.ip_forward": "1"},
			Env:     map[string]string{"DUALNET_PSK": psk},
			Files:   files,
		}
		if nodeNeedsTun(net.Nodes[node], nodes[node], sp.debugTun[node]) {
			ctr.Devices = []string{"/dev/net/tun"}
		}
		for _, fab := range sortedSet(attachFabs) {
			ctr.Attach = append(ctr.Attach, Attachment{Fabric: fab, IP: fabricByName[fab].IPs[node]})
		}
		sp.Containers = append(sp.Containers, ctr)
	}

	// 5. The hub: joins every egress fabric at .254, owns the echo service IPs on lo.
	hub := Container{
		Name: hubName, Role: RoleHub,
		Cmd:    []string{"sim", "init", "-spec", specPath, "--", "sim", "echo"},
		CapAdd: []string{"NET_ADMIN"},
	}
	hubSpec := siminit.Spec{LoAddrs: []string{worldDst + "/32", iranDst + "/32"}}
	if len(hubPeers) > 0 {
		hubSpec.WGDevices = []siminit.WGDevice{{
			Name: warpHubDev, PrivateKey: hubPriv.String(), ListenPort: warpPort,
			Addrs: []string{warpHubIP + "/24"}, Peers: hubPeers,
		}}
	}
	for i := range fabrics {
		if ip, ok := fabrics[i].IPs[hubName]; ok {
			hub.Attach = append(hub.Attach, Attachment{Fabric: fabrics[i].Name, IP: ip})
		}
	}
	hub.Files = map[string][]byte{specPath: mustJSON(hubSpec)}
	sp.Containers = append(sp.Containers, hub)

	// 6. A LAN client behind each capture-tun node.
	for _, c := range cs {
		if c.lanFor == "" {
			continue
		}
		node := c.lanFor
		fab := fabricByName[fabricOf[c.root]]
		routerIP := fab.IPs[node]
		cn := clientName(node)
		sp.lanClient[node] = cn
		clientSpec := siminit.Spec{Routes: []siminit.Route{{Dst: "default", Via: routerIP}}}
		// A kernel node's LAN client owns the leg source IPs it must probe FROM (the src_in test):
		// on lo, so with default arp_ignore it still answers ARP for them on the LAN NIC and the
		// router's on-link /32 return route reaches it.
		clientSpec.LoAddrs = append(clientSpec.LoAddrs, legSourceIPs(nodes[node])...)
		sp.Containers = append(sp.Containers, Container{
			Name: cn, Role: RoleClient, Node: node,
			Cmd:    []string{"sim", "init", "-spec", specPath, "--", "sim", "idle"},
			CapAdd: []string{"NET_ADMIN"},
			Attach: []Attachment{{Fabric: fab.Name, IP: fab.IPs[cn]}},
			Files:  map[string][]byte{specPath: mustJSON(clientSpec)},
		})
	}

	sort.Slice(sp.Containers, func(i, j int) bool { return sp.Containers[i].Name < sp.Containers[j].Name })
	for i := range sp.Containers {
		sp.Containers[i].Image = opts.Image
	}
	return sp, nil
}

func clientName(node string) string { return "client-" + node }

// legSourceHost returns the host /32 of a link source alias's bound IP on nd (e.g. a
// "10.99.0.1/29" leg → "10.99.0.1/32"), or "" if the alias binds no IP. Used to give a link's
// acceptor a return route to a bonded up-leg source.
func legSourceHost(nd netschema.Node, alias string) string {
	if alias == "" {
		return ""
	}
	c, ok := nd.Connections[alias]
	if !ok || c.IP == "" {
		return ""
	}
	ip := c.IP
	if i := strings.IndexByte(ip, '/'); i >= 0 {
		ip = ip[:i]
	}
	return ip + "/32"
}

// resolveIface maps a source alias to its device (mirrors netschema's unexported helper,
// using the exported Sources map so netsim needn't change the domain package).
func resolveIface(nd netschema.Node, alias string) string {
	if alias == "" {
		return ""
	}
	if s, ok := nd.Connections[alias]; ok {
		return s.Iface
	}
	return alias
}

// captureTun returns a node's capture-default tun connection (name + spec), if any.
func captureTun(nd netschema.Node) (string, netschema.Conn, bool) {
	for _, name := range sortedKeys(nd.Connections) {
		if c := nd.Connections[name]; c.Type == "tun" && c.CaptureDefault {
			return name, c, true
		}
	}
	return "", netschema.Conn{}, false
}

// anyTun returns a node's first tun connection (sorted by name), if any.
func anyTun(nd netschema.Node) (string, netschema.Conn, bool) {
	for _, name := range sortedKeys(nd.Connections) {
		if c := nd.Connections[name]; c.Type == "tun" {
			return name, c, true
		}
	}
	return "", netschema.Conn{}, false
}

// hasTun reports whether a node declares any tun connection.
func hasTun(nd netschema.Node) bool { _, _, ok := anyTun(nd); return ok }

// isDebugTun reports whether a node's only tun(s) are locally fed (no capture, no LAN) —
// modelled by -debug-tun, since the sim has no v2ray-style feeder to source real traffic in.
func isDebugTun(nd netschema.Node) bool {
	fed := false
	for _, c := range nd.Connections {
		if c.Type != "tun" {
			continue
		}
		if c.CaptureDefault || c.LAN != "" {
			return false // a capture tun is driven by a real LAN client, not injection
		}
		fed = true
	}
	return fed
}

// legSourceIPs returns the inline src_in leg addresses (as ip/mask, bare → /32) a kernel node
// steers, so the sim's LAN client can own them and probe from them. File-based src_in sets are
// skipped (Plan is pure — it does not read condition files).
func legSourceIPs(cn *config.Node) []string {
	if cn.Datapath != "kernel" {
		return nil
	}
	var out []string
	for _, c := range cn.Conditions {
		if c.SrcIn == nil {
			continue
		}
		for _, tok := range c.SrcIn.List {
			if !strings.ContainsRune(tok, '/') {
				tok += "/32"
			}
			out = append(out, tok)
		}
	}
	return out
}

// nodeNeedsTun reports whether the container must expose /dev/net/tun: it opens a real tun
// (a non-debug tun connection) or a kernel egress (which opens its own NAT tun). A
// kernel-datapath node forwards via policy routing + iptables and opens no tun at all.
func nodeNeedsTun(nd netschema.Node, cn *config.Node, debugTun bool) bool {
	if cn.Datapath == "kernel" {
		return false
	}
	if hasTun(nd) && !debugTun {
		return true
	}
	for _, eg := range cn.Egresses {
		if eg.Mode == "" || eg.Mode == "kernel" {
			return true
		}
	}
	return false
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

// --- helpers ---------------------------------------------------------------

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func sortedSet(m map[string]bool) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// --- union-find ------------------------------------------------------------

type unionFind struct{ parent map[endpoint]endpoint }

func newUF() *unionFind { return &unionFind{parent: map[endpoint]endpoint{}} }

func (u *unionFind) add(e endpoint) {
	if _, ok := u.parent[e]; !ok {
		u.parent[e] = e
	}
}

func (u *unionFind) find(e endpoint) endpoint {
	u.add(e)
	for u.parent[e] != e {
		u.parent[e] = u.parent[u.parent[e]]
		e = u.parent[e]
	}
	return e
}

func (u *unionFind) union(a, b endpoint) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u.parent[ra] = rb
	}
}

func (u *unionFind) components() map[endpoint][]endpoint {
	out := map[endpoint][]endpoint{}
	for e := range u.parent {
		r := u.find(e)
		out[r] = append(out[r], e)
	}
	return out
}
