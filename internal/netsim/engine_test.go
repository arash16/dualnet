package netsim

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// fakeDriver records lifecycle calls and answers Exec/Logs from programmable hooks, so the
// engine's orchestration and assertion logic can be tested with no Docker daemon.
type fakeDriver struct {
	mu         sync.Mutex
	built      bool
	networks   []string
	created    []string
	started    []string
	paused     []string
	unpaused   []string
	signals    []string
	cleaned    bool
	logsByName map[string]string
	onExec     func(name string, cmd []string) ExecResult
}

func (d *fakeDriver) Acquire(_ context.Context) error                    { return nil }
func (d *fakeDriver) BuildImage(_ context.Context, _, _, _ string) error { d.built = true; return nil }
func (d *fakeDriver) CreateNetwork(_ context.Context, name, _ string) error {
	d.networks = append(d.networks, name)
	return nil
}
func (d *fakeDriver) CreateContainer(_ context.Context, c Container) error {
	d.created = append(d.created, c.Name)
	return nil
}
func (d *fakeDriver) Start(_ context.Context, name string) error {
	d.started = append(d.started, name)
	return nil
}
func (d *fakeDriver) Exec(_ context.Context, name string, cmd []string) (ExecResult, error) {
	return d.onExec(name, cmd), nil
}
func (d *fakeDriver) Pause(_ context.Context, name string) error {
	d.paused = append(d.paused, name)
	return nil
}
func (d *fakeDriver) Unpause(_ context.Context, name string) error {
	d.unpaused = append(d.unpaused, name)
	return nil
}
func (d *fakeDriver) Signal(_ context.Context, name, sig string) error {
	d.signals = append(d.signals, name+":"+sig)
	return nil
}
func (d *fakeDriver) Logs(_ context.Context, name string) (string, error) {
	return d.logsByName[name], nil
}
func (d *fakeDriver) Cleanup(_ context.Context) error { d.cleaned = true; return nil }

// miniPlan is a hand-built 1-node plan (node "a" with a LAN client) for engine tests.
func miniPlan() *SimPlan {
	return &SimPlan{
		Image:   "img",
		Fabrics: []Fabric{{Name: "net0", Subnet: "172.30.1.0/24"}},
		Containers: []Container{
			{Name: "a", Role: RoleNode, Node: "a"},
			{Name: "client-a", Role: RoleClient, Node: "a"},
		},
		WorldDst: "10.200.0.10", IranDst: "10.200.0.20",
		egressIP:      map[string]map[string]string{"a": {"e": "1.2.3.4"}},
		nodeContainer: map[string]string{"a": "a"},
		lanClient:     map[string]string{"a": "client-a"},
		debugTun:      map[string]bool{},
	}
}

func cleanStats() ExecResult {
	return ExecResult{ExitCode: 0, Stdout: `{"drops":{"no_route":0,"decode":0}}`}
}

func run(t *testing.T, sp *SimPlan, scs []Scenario, d *fakeDriver) *Report {
	t.Helper()
	rep, err := RunPlan(context.Background(), nil, sp, scs, d, RunOptions{Build: true})
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}
	return rep
}

func TestEngineLifecycle(t *testing.T) {
	d := &fakeDriver{onExec: func(_ string, cmd []string) ExecResult {
		if cmd[0] == "cat" {
			return cleanStats()
		}
		return ExecResult{Stdout: "src=1.2.3.4"}
	}}
	sc := Scenario{Name: "route/ok", Steps: []Step{{Op: OpProbe, Probe: &ProbeStep{Node: "a", Dst: "10.200.0.10", ExpectSrc: "1.2.3.4", CheckNoDrops: true}}}}
	rep := run(t, miniPlan(), []Scenario{sc}, d)

	if !d.built {
		t.Error("image not built")
	}
	if len(d.networks) != 1 || len(d.created) != 2 || len(d.started) != 2 {
		t.Errorf("lifecycle calls: nets=%v created=%v started=%v", d.networks, d.created, d.started)
	}
	if !d.cleaned {
		t.Error("cleanup not called")
	}
	if rep.Failed() != 0 {
		t.Errorf("expected pass, got %+v", rep.Results)
	}
}

func TestEngineWrongEgressFails(t *testing.T) {
	d := &fakeDriver{onExec: func(_ string, cmd []string) ExecResult {
		if cmd[0] == "cat" {
			return cleanStats()
		}
		return ExecResult{Stdout: "src=9.9.9.9"} // wrong egress
	}}
	sc := Scenario{Name: "route/x", Steps: []Step{{Op: OpProbe, Probe: &ProbeStep{Node: "a", Dst: "10.200.0.10", ExpectSrc: "1.2.3.4"}}}}
	rep := run(t, miniPlan(), []Scenario{sc}, d)
	if rep.Failed() != 1 || !strings.Contains(rep.Results[0].Detail, "wrong path") {
		t.Errorf("expected wrong-path failure, got %+v", rep.Results)
	}
}

func TestEngineDropsFail(t *testing.T) {
	// The no-leak check is delta-based: a decode drop that appears DURING the probe fails it,
	// while a pre-existing (bring-up) count does not. Simulate the counter rising 0 → 2.
	var cats int
	d := &fakeDriver{onExec: func(_ string, cmd []string) ExecResult {
		if cmd[0] == "cat" {
			cats++
			if cats == 1 {
				return ExecResult{Stdout: `{"drops":{"no_route":0,"decode":0}}`} // baseline
			}
			return ExecResult{Stdout: `{"drops":{"no_route":0,"decode":2}}`} // after the flow
		}
		return ExecResult{Stdout: "src=1.2.3.4"}
	}}
	sc := Scenario{Name: "route/leak", Steps: []Step{{Op: OpProbe, Probe: &ProbeStep{Node: "a", Dst: "10.200.0.10", ExpectSrc: "1.2.3.4", CheckNoDrops: true}}}}
	rep := run(t, miniPlan(), []Scenario{sc}, d)
	if rep.Failed() != 1 || !strings.Contains(rep.Results[0].Detail, "decode 2") {
		t.Errorf("expected drop failure, got %+v", rep.Results)
	}
}

func TestEnginePreexistingDropsIgnored(t *testing.T) {
	// A non-zero drop count that does NOT change during the probe (a bring-up transient) must
	// not fail the scenario.
	d := &fakeDriver{onExec: func(_ string, cmd []string) ExecResult {
		if cmd[0] == "cat" {
			return ExecResult{Stdout: `{"drops":{"no_route":1,"decode":0}}`} // constant
		}
		return ExecResult{Stdout: "src=1.2.3.4"}
	}}
	sc := Scenario{Name: "route/ok", Steps: []Step{{Op: OpProbe, Probe: &ProbeStep{Node: "a", Dst: "10.200.0.10", ExpectSrc: "1.2.3.4", CheckNoDrops: true}}}}
	rep := run(t, miniPlan(), []Scenario{sc}, d)
	if rep.Failed() != 0 {
		t.Errorf("a constant (pre-existing) drop count should not fail: %+v", rep.Results)
	}
}

func TestEnginePauseUnpauseAndExpectFail(t *testing.T) {
	d := &fakeDriver{onExec: func(_ string, cmd []string) ExecResult {
		if cmd[0] == "cat" {
			return cleanStats()
		}
		return ExecResult{ExitCode: 1} // probe fails to round-trip
	}}
	sc := Scenario{Name: "failover/x", Steps: []Step{
		{Op: OpPause, Target: "gw"},
		{Op: OpProbe, Probe: &ProbeStep{Node: "a", Dst: "10.200.0.10", ExpectFail: true}},
		{Op: OpUnpause, Target: "gw"},
	}}
	rep := run(t, miniPlan(), []Scenario{sc}, d)
	if rep.Failed() != 0 {
		t.Errorf("expect-fail probe with exit!=0 should pass: %+v", rep.Results)
	}
	if len(d.paused) != 1 || d.paused[0] != "gw" || len(d.unpaused) != 1 {
		t.Errorf("pause/unpause not recorded: paused=%v unpaused=%v", d.paused, d.unpaused)
	}
}

func TestEngineInjectUsesDebugTunPort(t *testing.T) {
	sp := miniPlan()
	sp.debugTun["a"] = true
	var injectCmd []string
	d := &fakeDriver{
		logsByName: map[string]string{"a": `dualnet debug-tun: "V2Ray" listening on 127.0.0.1:54321 (send inner IP packets here)`},
		onExec: func(_ string, cmd []string) ExecResult {
			if cmd[0] == "cat" {
				return cleanStats()
			}
			injectCmd = cmd
			return ExecResult{Stdout: "src=1.2.3.4"}
		},
	}
	sc := Scenario{Name: "route/inject", Steps: []Step{{Op: OpProbe, Probe: &ProbeStep{Node: "a", Inject: true, Src: "10.9.0.5", Dst: "10.200.0.10", ExpectSrc: "1.2.3.4"}}}}
	rep := run(t, sp, []Scenario{sc}, d)
	if rep.Failed() != 0 {
		t.Fatalf("inject scenario failed: %+v", rep.Results)
	}
	if !hasArg(injectCmd, "127.0.0.1:54321") || !hasArg(injectCmd, "inject") {
		t.Errorf("inject cmd did not use the parsed debug-tun port: %v", injectCmd)
	}
}
