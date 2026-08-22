package netsim

import "testing"

func TestScenariosDerivedFromExample(t *testing.T) {
	net := exampleNet(t)
	sp, err := Plan(net, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	scs := Scenarios(net, sp)

	byName := map[string]Scenario{}
	for _, s := range scs {
		byName[s.Name] = s
	}
	// The example's paths + conditions must derive exactly these scenarios.
	wantNames := []string{
		"route/lan/egress-ftth",         // is-iran → FTTH direct
		"route/lan/gw-turkish-internet", // turkey healthy → tunnel
		"failover/lan/egress-starlink",  // turkey down → Starlink; then self-heal
		"route/vps/gw-turkish-internet", // vps origin → tunnel (via inject)
		"sighup/lan",                    // prefix reload flips WorldDst to geo-direct
	}
	for _, n := range wantNames {
		if _, ok := byName[n]; !ok {
			t.Errorf("missing derived scenario %q; got %v", n, names(scs))
		}
	}
	if len(scs) != len(wantNames) {
		t.Errorf("scenario count = %d, want %d: %v", len(scs), len(wantNames), names(scs))
	}

	ftthSrc := sp.egressIP["router"]["ftth"]
	starSrc := sp.egressIP["router"]["starlink"]
	turkSrc := sp.egressIP["turkish"]["internet"]

	// is-iran routing: HTTP from the LAN client to the iran dst, expect the FTTH source.
	if p := firstProbe(byName["route/lan/egress-ftth"]); p == nil {
		t.Fatal("no probe in is-iran scenario")
	} else {
		if p.Inject || p.Node != "router" || p.Dst != sp.IranDst || p.ExpectSrc != ftthSrc {
			t.Errorf("is-iran probe = %+v (want http router→%s src %s)", p, sp.IranDst, ftthSrc)
		}
		if !p.CheckNoDrops {
			t.Error("clean routing scenario should assert no drops")
		}
	}

	// turkey healthy: WorldDst tunnels, source == turkish.
	if p := firstProbe(byName["route/lan/gw-turkish-internet"]); p == nil || p.Dst != sp.WorldDst || p.ExpectSrc != turkSrc {
		t.Errorf("tunnel probe = %+v (want WorldDst src %s)", p, turkSrc)
	}

	// vps origin is driven by injection at its debug-tun with its inner tun address.
	if p := firstProbe(byName["route/vps/gw-turkish-internet"]); p == nil || !p.Inject || p.Node != "vps" || p.Src != "10.9.0.5" || p.ExpectSrc != turkSrc {
		t.Errorf("vps probe = %+v (want inject vps src 10.9.0.5 → %s)", p, turkSrc)
	}

	// failover: pause turkish, expect Starlink, then unpause and recover to turkish.
	fo := byName["failover/lan/egress-starlink"]
	if !hasStep(fo, OpPause, "turkish") || !hasStep(fo, OpUnpause, "turkish") {
		t.Errorf("failover scenario must pause+unpause turkish: %+v", fo.Steps)
	}
	probes := allProbes(fo)
	if len(probes) != 2 {
		t.Fatalf("failover should have 2 probes, got %d", len(probes))
	}
	if probes[0].ExpectSrc != starSrc {
		t.Errorf("failover first probe src = %s, want starlink %s", probes[0].ExpectSrc, starSrc)
	}
	// The down-probe must HOLD: drive sustained fallback traffic (> the healthcheck up-grace)
	// and assert the egress does not drift back to the paused gateway. Without this, the sim
	// would miss a healthcheck that false-heals off the fallback's own return traffic.
	if probes[0].Hold <= 0 {
		t.Errorf("failover down-probe must hold sustained traffic to surface a false-heal; Hold=%v", probes[0].Hold)
	}
	if probes[1].ExpectSrc != turkSrc {
		t.Errorf("self-heal probe src = %s, want turkish %s", probes[1].ExpectSrc, turkSrc)
	}

	// sighup: two probes (before/after) with a signal + append in between; src flips.
	sh := byName["sighup/lan"]
	if !hasStep(sh, OpSignal, sp.nodeContainer["router"]) {
		t.Errorf("sighup scenario must SIGHUP the router: %+v", sh.Steps)
	}
	shp := allProbes(sh)
	if len(shp) != 2 || shp[0].ExpectSrc != turkSrc || shp[1].ExpectSrc != ftthSrc {
		t.Errorf("sighup probes = %+v (want before=turkish %s, after=ftth %s)", shp, turkSrc, ftthSrc)
	}
}

func names(scs []Scenario) []string {
	var out []string
	for _, s := range scs {
		out = append(out, s.Name)
	}
	return out
}

func firstProbe(s Scenario) *ProbeStep {
	for _, st := range s.Steps {
		if st.Op == OpProbe {
			return st.Probe
		}
	}
	return nil
}

func allProbes(s Scenario) []*ProbeStep {
	var out []*ProbeStep
	for _, st := range s.Steps {
		if st.Op == OpProbe {
			out = append(out, st.Probe)
		}
	}
	return out
}

func hasStep(s Scenario, op StepOp, target string) bool {
	for _, st := range s.Steps {
		if st.Op == op && st.Target == target {
			return true
		}
	}
	return false
}
