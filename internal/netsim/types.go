// Package netsim turns any dualnet network schema into a deterministic, offline,
// containerised simulation and a test matrix derived from the network's own paths — so a
// user can validate that a mesh routes the way its config claims, without a real internet
// and without hand-writing a topology.
//
// Layering (dependencies point inward; the node runtime never learns about this package):
//
//	Plan(net)       — pure: schema  → SimPlan (fabrics, IP plan, per-container files)
//	Scenarios(...)  — pure: schema  → []Scenario (one per path branch + extended cases)
//	Run(...)        — orchestration: drives a Driver to stand up the SimPlan and assert
//	Driver          — the IoC seam a backend implements (dockerdriver is the only one today)
//
// Plan and Scenarios are dependency-free and unit-tested against a fake Driver; the Docker
// SDK lives only in internal/netsim/dockerdriver.
package netsim

import "context"

// Role classifies a container.
type Role string

const (
	RoleNode   Role = "node"   // runs dualnet from a generated config
	RoleHub    Role = "hub"    // the simulated internet (sim echo + service IPs on lo)
	RoleClient Role = "client" // a LAN host behind a capture-tun node; drives real probes
)

// SimPlan is the fully-derived simulation: what networks and containers to create, and the
// facts scenarios assert against (per-node/egress IPs). Everything is decided by the engine
// (static IPs included) so a run is reproducible and needs no read-back from the backend.
type SimPlan struct {
	Image      string      // test image tag (built from test/sim/Dockerfile)
	Fabrics    []Fabric    // docker networks, sorted deterministically
	Containers []Container // nodes + hub + clients, sorted by name

	// EchoNet is the /24 all egresses ultimately reach on the hub; WorldDst/IranDst are two
	// service IPs in it (IranDst is added to every generated dst_in prefix file).
	EchoNet  string
	WorldDst string
	IranDst  string

	// egressIP[node][egressName] is the source IP the hub will observe for a flow that exits
	// through that egress — the oracle for "which egress fired".
	egressIP map[string]map[string]string
	// nodeContainer[node] is the container name running that node (== node name).
	nodeContainer map[string]string
	// lanClient[node] is the client container behind a capture-tun node that forwards a LAN
	// (its tun has `lan:`); the probe drives that separate client. Empty for a self-capturing
	// node — see selfCapture.
	lanClient map[string]string
	// selfCapture[node] is true for a capture-tun node with NO `lan:` — it captures its OWN
	// traffic (a client machine, not a LAN router), so there is no separate LAN host to probe
	// from; the HTTP probe runs inside the node's own container, whose default route its tun grabs.
	selfCapture map[string]bool
	// conditionFile[node][conditionName] is the RUNTIME path of a dst_in prefix file inside
	// that node's container — the compiled path (compile rewrites a schema dst_in file to its
	// deploy files_dir), which is where the sim writes it AND where dualnet reads it. The
	// SIGHUP reload scenario must append to this, not the raw schema path.
	conditionFile map[string]map[string]string
	// tunNode[node] is true if the node runs with -debug-tun (locally-fed tun, e.g. vps).
	debugTun map[string]bool

	// NeedsWireGuard is true when any kernel-warp egress is present: the hub terminates a real
	// kernel WireGuard tunnel, so the Docker host kernel must provide the wireguard module.
	NeedsWireGuard bool
}

// Fabric is one simulated L2 segment (a docker network).
type Fabric struct {
	Name   string            // stable, unique
	Subnet string            // e.g. "172.30.1.0/24"
	IPs    map[string]string // container name -> its static IP on this fabric
}

// Container is one container to create.
type Container struct {
	Name       string
	Role       Role
	Image      string            // image tag to run (== SimPlan.Image)
	Node       string            // the schema node this represents (RoleNode only)
	Cmd        []string          // full argv (starts with "sim init -spec … --")
	Attach     []Attachment      // networks to join, with static IPs
	CapAdd     []string          // e.g. NET_ADMIN, NET_RAW
	Devices    []string          // e.g. /dev/net/tun
	Sysctls    map[string]string // e.g. net.ipv4.ip_forward=1
	Env        map[string]string // e.g. DUALNET_PSK
	Files      map[string][]byte // absolute path -> content, placed before start
	Privileged bool
}

// Attachment joins a container to a fabric at a fixed address.
type Attachment struct {
	Fabric string
	IP     string
}

// ExecResult is the outcome of a Driver.Exec.
type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// Driver is the backend seam: the engine describes what to build; a Driver realises it.
// dockerdriver is the production implementation; tests use a fake. All methods must be safe
// to call after a partial failure, and Cleanup must remove everything the driver created.
type Driver interface {
	// Acquire ensures exclusive access before a run: it must fail fast if another sim is
	// already running (so two runs never fight over the same fabrics/subnets), and otherwise
	// clear any resources a previous crashed run left behind.
	Acquire(ctx context.Context) error
	BuildImage(ctx context.Context, tag, dockerfile, contextDir string) error
	CreateNetwork(ctx context.Context, name, subnet string) error
	CreateContainer(ctx context.Context, c Container) error
	Start(ctx context.Context, name string) error
	Exec(ctx context.Context, name string, cmd []string) (ExecResult, error)
	Pause(ctx context.Context, name string) error
	Unpause(ctx context.Context, name string) error
	Signal(ctx context.Context, name, signal string) error
	Logs(ctx context.Context, name string) (string, error)
	Cleanup(ctx context.Context) error
}
