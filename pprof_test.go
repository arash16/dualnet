package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The opt-in profiler must expose the standard pprof endpoints so a pegged node can be
// analyzed empirically with `go tool pprof`. These guard the route wiring (a dropped
// HandleFunc would silently break profile collection on the box).

func TestPprofHandlerServesIndexAndProfiles(t *testing.T) {
	srv := httptest.NewServer(pprofHandler())
	defer srv.Close()

	// The index lists the available runtime.Lookup profiles.
	body := getOK(t, srv.URL+"/debug/pprof/")
	for _, name := range []string{"goroutine", "heap", "mutex", "block", "allocs"} {
		if !strings.Contains(body, name) {
			t.Errorf("index does not list the %q profile", name)
		}
	}

	// A Lookup profile served via pprof.Index returns actual sample data.
	if got := getOK(t, srv.URL+"/debug/pprof/goroutine?debug=1"); !strings.Contains(got, "goroutine") {
		t.Errorf("goroutine profile did not contain goroutine data: %q", got)
	}
}

// The wall-clock (off-CPU) profiler is the tool for a throughput cap at idle CPU, so its route
// must be reachable and stream a non-empty profile.
func TestPprofHandlerServesFgprof(t *testing.T) {
	srv := httptest.NewServer(pprofHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/debug/fgprof?seconds=1")
	if err != nil {
		t.Fatalf("GET fgprof: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fgprof status = %d, want 200", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading fgprof: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("fgprof body is empty")
	}
}

// The CPU profiler (the primary tool for a pegged core) has its own route, distinct from the
// Lookup profiles, and must stream a non-empty profile.
func TestPprofHandlerServesCPUProfile(t *testing.T) {
	srv := httptest.NewServer(pprofHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/debug/pprof/profile?seconds=1")
	if err != nil {
		t.Fatalf("GET cpu profile: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cpu profile status = %d, want 200", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading cpu profile: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("cpu profile body is empty")
	}
}

func TestStartPprofEmptyAddrIsNoop(t *testing.T) {
	// An empty address must not start any listener; startPprof returning without spawning the
	// server goroutine is the whole contract of the opt-in gate.
	started := false
	startPprof("", func(string, ...any) { started = true })
	if started {
		t.Fatal("startPprof logged a startup line for an empty address")
	}
}

func getOK(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", url, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", url, err)
	}
	return string(b)
}
