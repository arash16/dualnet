package node

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/egress"
	"github.com/arash16/dualnet/internal/stats"
)

// TestGeoSplitRoutesByDestination is a near-end-to-end behavioral test of destination-based
// routing across the whole userspace datapath: tun read → router guard (lazy dst parse +
// ipmatch) → the selected finalizer → egress → reflected reply → back to the tun. One node with
// two local egresses split by a dst_in condition; a packet to the geo set exits one egress, and
// everything else exits the other — asserted by which reflecting egress observed the packet.
func TestGeoSplitRoutesByDestination(t *testing.T) {
	cfg := &config.Node{
		PSK: testPSK, Subnet: "10.9.0.0/24", MTU: 1360,
		Egresses: map[string]config.Egress{
			"geo":   {Mode: "direct", ExtIface: "lo"},
			"world": {Mode: "direct", ExtIface: "lo"},
		},
		Conditions: []config.Condition{
			{Name: "is-geo", DstIn: &config.IPSet{List: []string{"100.64.0.0/10"}}},
		},
		Connections: []config.Connection{
			{Name: "Tun", Type: "tun", Address: "10.9.0.2", CaptureDefault: true},
		},
		Routes: []config.Route{
			{Match: config.Match{Source: "Tun", Processed: pfalse(), Conditions: []string{"is-geo"}}, Action: config.Action{Egress: "geo", Target: "Tun"}},
			{Match: config.Match{Source: "Tun", Processed: pfalse()}, Action: config.Action{Egress: "world", Target: "Tun"}},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	geoEg, worldEg := newCountEgress(), newCountEgress()
	tun := newFakeTun()
	startSplitNode(t, ctx, cfg, map[string]*fakeTun{"": tun}, // capture tun: OpenTun name is the device (empty here)
		map[string]egress.Egress{"geo": geoEg, "world": worldEg})

	// A packet to the geo set must exit the geo egress and nowhere else.
	if !driveUntilReply(t, tun, "10.9.0.2", "100.64.0.5", 8*time.Second) {
		t.Fatal("geo-destined packet: no reply at the tun")
	}
	if geoEg.count() == 0 {
		t.Fatal("geo-destined packet did not exit the geo egress")
	}
	if worldEg.count() != 0 {
		t.Fatalf("geo-destined packet leaked to the world egress: %d", worldEg.count())
	}

	// A packet outside the geo set falls through to the world egress.
	if !driveUntilReply(t, tun, "10.9.0.2", "8.8.8.8", 8*time.Second) {
		t.Fatal("world-destined packet: no reply at the tun")
	}
	if worldEg.count() == 0 {
		t.Fatal("world-destined packet did not exit the world egress")
	}
}

// TestStatsEndToEnd drives a round-trip through a node with stats enabled and asserts the
// on-disk JSONL reflects the traffic: the tun's originated packet is counted as recv, the
// reflected reply is counted as sent (the finalizer reply path, which bypasses the router), a
// routing rule matched, and the clean path reports zero no_route/decode drops. Spans tun +
// router recorder + finalizer sent-hook + the stats writer.
func TestStatsEndToEnd(t *testing.T) {
	statsFile := filepath.Join(t.TempDir(), "stats.jsonl")
	cfg := &config.Node{
		PSK: testPSK, Subnet: "10.9.0.0/24", MTU: 1360,
		StatsFile: statsFile, StatsInterval: 1, StatsMaxMB: 10,
		Egresses: map[string]config.Egress{"world": {Mode: "direct", ExtIface: "lo"}},
		Connections: []config.Connection{
			{Name: "Tun", Type: "tun", Address: "10.9.0.2", CaptureDefault: true},
		},
		Routes: []config.Route{
			{Match: config.Match{Source: "Tun", Processed: pfalse()}, Action: config.Action{Egress: "world", Target: "Tun"}},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tun := newFakeTun()
	startSplitNode(t, ctx, cfg, map[string]*fakeTun{"": tun}, map[string]egress.Egress{"world": newCountEgress()})

	if !driveUntilReply(t, tun, "10.9.0.2", "8.8.8.8", 8*time.Second) {
		t.Fatal("no reply at the tun")
	}

	// Poll the stats file (written every interval) until a snapshot reflects the round-trip.
	deadline := time.After(6 * time.Second)
	for {
		snap, ok := lastSnapshot(statsFile)
		if ok {
			tunC := snap.Conns["Tun"]
			if tunC.Recv >= 1 && tunC.Sent >= 1 {
				if snap.Drops.NoRoute != 0 || snap.Drops.Decode != 0 {
					t.Fatalf("clean path reported drops: %+v", snap.Drops)
				}
				if len(snap.Routes) == 0 {
					t.Fatal("no routing rule was recorded as matched")
				}
				return
			}
		}
		select {
		case <-deadline:
			s, _ := lastSnapshot(statsFile)
			t.Fatalf("stats never reflected the round-trip; last snapshot: %+v", s)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// lastSnapshot reads the final JSONL line of the stats file as a Snapshot.
func lastSnapshot(path string) (stats.Snapshot, bool) {
	f, err := os.Open(path)
	if err != nil {
		return stats.Snapshot{}, false
	}
	defer f.Close()
	var last string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		if t := sc.Text(); t != "" {
			last = t
		}
	}
	if last == "" {
		return stats.Snapshot{}, false
	}
	var s stats.Snapshot
	if err := json.Unmarshal([]byte(last), &s); err != nil {
		return stats.Snapshot{}, false
	}
	return s, true
}
