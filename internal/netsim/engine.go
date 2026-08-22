package netsim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/arash16/dualnet/internal/netschema"
)

// ErrNoKernelWireGuard means the Docker host kernel cannot create WireGuard links, which a
// kernel-warp plan requires (the hub terminates a real kernel tunnel). Docker Desktop and
// OrbStack ship the module; a custom colima/lima VM may not.
var ErrNoKernelWireGuard = errors.New("netsim: docker host kernel lacks the WireGuard module (a kernel-warp simulation needs it); verify with: docker run --rm --cap-add NET_ADMIN <image> ip link add wg-probe type wireguard")

// RunOptions tunes a run.
type RunOptions struct {
	Plan       PlanOptions
	Build      bool          // build the image before standing the mesh up (default true via Run)
	Dockerfile string        // Dockerfile path for BuildImage (default test/sim/Dockerfile)
	ContextDir string        // build context (default repo root ".")
	Keep       bool          // leave the mesh running after the run (for `docker exec` debugging)
	Only       string        // if set, run only scenarios whose name contains this substring
	Settle     time.Duration // pause after Start before the first probe (Run defaults it to 2s)
	Log        func(string)  // progress sink (default: discard)
}

// Result is the outcome of one scenario.
type Result struct {
	Scenario    string
	Description string
	Pass        bool
	Detail      string // failure reason, or a short success note
}

// Report collects scenario results.
type Report struct {
	Results []Result
}

// Failed returns the number of failed scenarios.
func (r *Report) Failed() int {
	n := 0
	for _, res := range r.Results {
		if !res.Pass {
			n++
		}
	}
	return n
}

// Run plans the simulation for net, derives its scenarios, and executes them against driver.
func Run(ctx context.Context, net *netschema.Network, driver Driver, opts RunOptions) (*Report, error) {
	sp, err := Plan(net, opts.Plan)
	if err != nil {
		return nil, err
	}
	if opts.Settle == 0 {
		opts.Settle = 2 * time.Second
	}
	return RunPlan(ctx, net, sp, Scenarios(net, sp), driver, opts)
}

// RunPlan stands up an already-derived plan, runs the given scenarios, and (unless Keep)
// tears everything down. It is the seam the e2e test and cmd/netsim share, and lets callers
// run a custom plan/scenarios (e.g. the PSK-mismatch negative check).
func RunPlan(ctx context.Context, net *netschema.Network, sp *SimPlan, scenarios []Scenario, driver Driver, opts RunOptions) (*Report, error) {
	log := opts.Log
	if log == nil {
		log = func(string) {}
	}

	// Refuse to run alongside another sim (they would collide on fabrics/subnets), and clear
	// any leftovers from a previously-killed run.
	if err := driver.Acquire(ctx); err != nil {
		return nil, err
	}

	if opts.Build {
		df := opts.Dockerfile
		if df == "" {
			df = "test/sim/Dockerfile"
		}
		cd := opts.ContextDir
		if cd == "" {
			cd = "."
		}
		log(fmt.Sprintf("building image %s", sp.Image))
		if err := driver.BuildImage(ctx, sp.Image, df, cd); err != nil {
			return nil, fmt.Errorf("build image: %w", err)
		}
	}

	if !opts.Keep {
		defer func() { _ = driver.Cleanup(context.WithoutCancel(ctx)) }()
	}

	if sp.NeedsWireGuard {
		log("probing host kernel for WireGuard support")
		if err := checkKernelWireGuard(ctx, driver, sp.Image); err != nil {
			return nil, err
		}
	}

	log(fmt.Sprintf("creating %d fabrics", len(sp.Fabrics)))
	for _, f := range sp.Fabrics {
		if err := driver.CreateNetwork(ctx, f.Name, f.Subnet); err != nil {
			return nil, fmt.Errorf("create network %s: %w", f.Name, err)
		}
	}
	log(fmt.Sprintf("creating %d containers", len(sp.Containers)))
	for _, c := range sp.Containers {
		if err := driver.CreateContainer(ctx, c); err != nil {
			return nil, fmt.Errorf("create container %s: %w", c.Name, err)
		}
	}
	for _, c := range sp.Containers {
		if err := driver.Start(ctx, c.Name); err != nil {
			return nil, fmt.Errorf("start container %s: %w", c.Name, err)
		}
	}
	// Brief settle so nodes bind sockets and print their debug-tun ports before probing.
	if err := sleep(ctx, opts.Settle); err != nil {
		return nil, err
	}

	rep := &Report{}
	for _, sc := range scenarios {
		if opts.Only != "" && !strings.Contains(sc.Name, opts.Only) {
			continue
		}
		log("scenario: " + sc.Name)
		if sc.Description != "" {
			log("  " + sc.Description)
		}
		res := runScenario(ctx, sc, driver, sp)
		if res.Pass {
			log("  PASS " + sc.Name)
		} else {
			log("  FAIL " + sc.Name + ": " + res.Detail)
		}
		rep.Results = append(rep.Results, res)
	}
	return rep, nil
}

// pskMismatchWrongValue is a PSK guaranteed to differ from any default/likely-chosen one.
const pskMismatchWrongValue = "netsim-WRONG-psk-do-not-match"

// RunPSKMismatch stands up a mesh with one node's PSK broken and asserts a no-fallback flow
// fails at that node with decode drops. It targets a path that is a single gateway branch
// (no healthcheck fallback), because breaking a gateway with a fallback would just fail the
// healthcheck and self-heal onto the fallback, masking the error. Returns an empty report if
// the network has no such path (nothing to prove).
func RunPSKMismatch(ctx context.Context, net *netschema.Network, driver Driver, opts RunOptions) (*Report, error) {
	broken, p, ok := noFallbackGatewayPath(net)
	if !ok {
		return &Report{}, nil
	}
	if opts.Plan.PSKOverride == nil {
		opts.Plan.PSKOverride = map[string]string{}
	}
	opts.Plan.PSKOverride[broken] = pskMismatchWrongValue
	sp, err := Plan(net, opts.Plan)
	if err != nil {
		return nil, err
	}
	// The same path round-trips with the correct PSK (the main suite's route scenario); a
	// failure here — same plan, only this node's PSK changed — is attributable to the PSK.
	ps := probeFor(net, sp, p.OriginNode(), sp.WorldDst, "", true, false)
	sc := Scenario{
		Name:        "psk-mismatch/" + p.Name,
		Description: fmt.Sprintf("wrong PSK on %q → path %q does not round-trip", broken, p.Name),
		Steps:       []Step{{Op: OpProbe, Probe: ps}},
	}
	if opts.Settle == 0 {
		opts.Settle = 2 * time.Second
	}
	return RunPlan(ctx, net, sp, []Scenario{sc}, driver, opts)
}

// noFallbackGatewayPath returns a path whose only route is a single gateway branch (so a
// broken gateway cannot be masked by a fallback), and that gateway node.
func noFallbackGatewayPath(net *netschema.Network) (gateway string, p netschema.Path, ok bool) {
	for _, path := range net.Paths {
		if len(path.Routes) == 1 && path.Routes[0].Gateway != "" {
			return path.Routes[0].Gateway, path, true
		}
	}
	return "", netschema.Path{}, false
}

// checkKernelWireGuard verifies the Docker host kernel can create WireGuard links, in a
// throwaway probe container (NET_ADMIN, no fabric): kernel-warp fails fast with a clear error
// here instead of hanging on a handshake that can never complete. The probe is removed by the
// prefix-scoped Cleanup like every other container this driver creates.
func checkKernelWireGuard(ctx context.Context, driver Driver, image string) error {
	const probe = "wg-probe"
	c := Container{Name: probe, Role: RoleClient, Image: image, Cmd: []string{"sim", "idle"}, CapAdd: []string{"NET_ADMIN"}}
	if err := driver.CreateContainer(ctx, c); err != nil {
		return fmt.Errorf("create wireguard probe: %w", err)
	}
	if err := driver.Start(ctx, probe); err != nil {
		return fmt.Errorf("start wireguard probe: %w", err)
	}
	r, err := driver.Exec(ctx, probe, []string{"ip", "link", "add", "wg-probe0", "type", "wireguard"})
	if err != nil {
		return fmt.Errorf("wireguard probe exec: %w", err)
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("%w: %s", ErrNoKernelWireGuard, oneLine(r.Stderr))
	}
	return nil
}

func runScenario(ctx context.Context, sc Scenario, driver Driver, sp *SimPlan) Result {
	res := Result{Scenario: sc.Name, Description: sc.Description, Pass: true}
	fail := func(format string, a ...any) Result {
		res.Pass, res.Detail = false, fmt.Sprintf(format, a...)
		return res
	}
	for _, st := range sc.Steps {
		switch st.Op {
		case OpPause:
			if err := driver.Pause(ctx, st.Target); err != nil {
				return fail("pause %s: %v", st.Target, err)
			}
		case OpUnpause:
			if err := driver.Unpause(ctx, st.Target); err != nil {
				return fail("unpause %s: %v", st.Target, err)
			}
		case OpSignal:
			if err := driver.Signal(ctx, st.Target, st.Signal); err != nil {
				return fail("signal %s %s: %v", st.Target, st.Signal, err)
			}
		case OpAppendFile:
			cmd := []string{"sh", "-c", fmt.Sprintf("echo %s >> %s", shellQuote(st.Content), shellQuote(st.File))}
			if r, err := driver.Exec(ctx, st.Target, cmd); err != nil || r.ExitCode != 0 {
				return fail("append to %s on %s: %v (%s)", st.File, st.Target, err, r.Stderr)
			}
		case OpSleep:
			if err := sleep(ctx, st.Wait); err != nil {
				return fail("sleep: %v", err)
			}
		case OpProbe:
			if d := runProbe(ctx, st.Probe, driver, sp); d != "" {
				return fail("%s", d)
			}
		}
	}
	if res.Detail == "" {
		res.Detail = "ok"
	}
	return res
}

var debugTunPort = regexp.MustCompile(`listening on 127\.0\.0\.1:(\d+)`)

// runProbe executes a probe step and returns "" on success or a failure description.
func runProbe(ctx context.Context, p *ProbeStep, driver Driver, sp *SimPlan) string {
	var container string
	var cmd []string
	if p.Inject {
		container = sp.nodeContainer[p.Node]
		port, err := debugTunPortOf(ctx, driver, container)
		if err != nil {
			return fmt.Sprintf("find debug-tun port on %s: %v", container, err)
		}
		cmd = []string{"sim", "probe", "inject", "-tun", "127.0.0.1:" + port, "-src", p.Src, "-dst", p.Dst}
	} else {
		container = sp.lanClient[p.Node]
		if container == "" && sp.selfCapture[p.Node] {
			// A self-capturing node (capture tun, no LAN) is driven from its own container: the
			// capture tun grabs the container's default route, so a local `sim probe http` flows
			// through the node exactly as one of its own apps would.
			container = sp.nodeContainer[p.Node]
		}
		if container == "" {
			return fmt.Sprintf("node %s has no LAN client or self-capture origin to probe from", p.Node)
		}
		cmd = []string{"sim", "probe", "http", "-url", "http://" + p.Dst + "/"}
		if p.SrcIP != "" {
			// Bind the client's socket to a leg source IP, so the kernel router's `ip rule from`
			// steers it — exercising a src_in branch.
			cmd = append(cmd, "-src-ip", p.SrcIP)
		}
	}
	// When we assert a specific egress, let the probe loop until the path converges to it,
	// so a transient fallback reply during startup/failover doesn't decide the assertion.
	if p.ExpectSrc != "" {
		cmd = append(cmd, "-expect-src", p.ExpectSrc)
	}
	if p.Hold > 0 {
		cmd = append(cmd, "-hold", p.Hold.String())
	}

	// Baseline drop counts before the probe, so the no-leak check measures what THIS flow
	// caused — mesh bring-up can produce a one-off no_route/decode blip that is not a leak.
	var baseline map[string]drops
	if p.CheckNoDrops {
		baseline = readDrops(ctx, driver, sp)
	}

	r, err := driver.Exec(ctx, container, cmd)
	if err != nil {
		return fmt.Sprintf("probe exec on %s: %v", container, err)
	}
	if p.ExpectFail {
		if r.ExitCode == 0 {
			return fmt.Sprintf("expected the flow to FAIL but it returned %q", strings.TrimSpace(r.Stdout))
		}
		return ""
	}
	if r.ExitCode != 0 {
		return fmt.Sprintf("probe failed (exit %d): %s", r.ExitCode, oneLine(r.Stderr))
	}
	if p.ExpectSrc != "" {
		got := parseSrc(r.Stdout)
		if got != p.ExpectSrc {
			return fmt.Sprintf("egress source = %q, want %q (wrong path)", got, p.ExpectSrc)
		}
	}
	if p.CheckNoDrops {
		if err := sleep(ctx, time.Second); err != nil { // let the last stats snapshot flush
			return err.Error()
		}
		for name, after := range readDrops(ctx, driver, sp) {
			b := baseline[name]
			if dn := after.NoRoute - b.NoRoute; dn != 0 {
				return fmt.Sprintf("%s leaked %d packet(s) to no route during the flow", name, dn)
			}
			if dd := after.Decode - b.Decode; dd != 0 {
				return fmt.Sprintf("%s failed to decode %d packet(s) during the flow", name, dd)
			}
		}
	}
	return ""
}

func debugTunPortOf(ctx context.Context, driver Driver, container string) (string, error) {
	deadline := time.Now().Add(15 * time.Second)
	for {
		logs, err := driver.Logs(ctx, container)
		if err == nil {
			if m := debugTunPort.FindStringSubmatch(logs); m != nil {
				return m[1], nil
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no debug-tun port in logs")
		}
		if err := sleep(ctx, 300*time.Millisecond); err != nil {
			return "", err
		}
	}
}

// drops is a node's cumulative dropped-packet counters.
type drops struct {
	NoRoute uint64
	Decode  uint64
}

// readDrops reads each node's latest drop counters (missing/unflushed stats read as zero).
func readDrops(ctx context.Context, driver Driver, sp *SimPlan) map[string]drops {
	out := map[string]drops{}
	for _, c := range sp.Containers {
		if c.Role != RoleNode {
			continue
		}
		out[c.Name] = drops{}
		r, err := driver.Exec(ctx, c.Name, []string{"cat", statsPath})
		if err != nil || r.ExitCode != 0 {
			continue
		}
		if snap, ok := lastSnapshot(r.Stdout); ok {
			out[c.Name] = drops{NoRoute: snap.Drops.NoRoute, Decode: snap.Drops.Decode}
		}
	}
	return out
}

type statsSnap struct {
	Drops struct {
		NoRoute uint64 `json:"no_route"`
		Decode  uint64 `json:"decode"`
	} `json:"drops"`
}

func lastSnapshot(jsonl string) (statsSnap, bool) {
	var last statsSnap
	found := false
	for _, line := range strings.Split(jsonl, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var s statsSnap
		if json.Unmarshal([]byte(line), &s) == nil {
			last, found = s, true
		}
	}
	return last, found
}

func parseSrc(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "src=") {
			return strings.TrimPrefix(line, "src=")
		}
	}
	return strings.TrimSpace(out)
}

func oneLine(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), "\n", " | ") }

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
