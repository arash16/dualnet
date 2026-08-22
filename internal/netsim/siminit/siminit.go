// Package siminit is the serialization contract between the netsim engine (which generates
// a per-container setup spec) and the `sim init` entrypoint (which applies it inside the
// container). It is intentionally dependency-free — both sides import it and nothing else,
// so the contract stays a single source of truth without coupling the engine to the image.
package siminit

// Spec tells `sim init` how to shape a container's network namespace before the real process
// starts: rename each Docker-assigned NIC to a stable name by matching its IPv4 to a fabric
// subnet, add routes, and add loopback service addresses. This is what lets generated node
// configs reference fixed device names (dn0, dn1, …) even though Docker only ever creates
// eth0..N in an unspecified order.
type Spec struct {
	Renames   []Rename   `json:"renames,omitempty"`
	Routes    []Route    `json:"routes,omitempty"`
	LoAddrs   []string   `json:"lo_addrs,omitempty"`   // e.g. "10.200.0.10/32", added to `lo`
	WGDevices []WGDevice `json:"wg_devices,omitempty"` // kernel WireGuard devices (the hub's simulated "Cloudflare")
}

// Rename maps the NIC whose IPv4 falls in Subnet to a stable device Name.
type Rename struct {
	Subnet string `json:"subnet"`
	Name   string `json:"name"`
}

// WGDevice is one kernel WireGuard device to create and program. Its Addrs' subnet doubles
// as the connected return route to the peers' tunnel addresses.
type WGDevice struct {
	Name       string   `json:"name"`
	PrivateKey string   `json:"private_key"` // base64
	ListenPort int      `json:"listen_port,omitempty"`
	Addrs      []string `json:"addrs"` // e.g. "100.64.0.1/24"
	Peers      []WGPeer `json:"peers"`
}

// WGPeer is one WireGuard peer on a WGDevice.
type WGPeer struct {
	PublicKey  string   `json:"public_key"` // base64
	AllowedIPs []string `json:"allowed_ips"`
}

// Route is one `ip route replace` to install (after renames, so Dev is a renamed name).
type Route struct {
	// Dst is a CIDR or "default".
	Dst string `json:"dst"`
	// Via is the next-hop IP, or "" for an on-link/point-to-point route.
	Via string `json:"via,omitempty"`
	Dev string `json:"dev"`
}
