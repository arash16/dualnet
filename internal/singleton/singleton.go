// Package singleton enforces that only one dualnet process runs from a given binary at a
// time. On startup a node finds every other running process whose executable is the same
// file, asks it to exit (SIGTERM), and waits for it to go before proceeding — so a
// restart (systemd, a manual re-launch, an rsync redeploy) cleanly hands over ownership
// of the tun, routes, and listening sockets instead of two instances fighting over them.
//
// Matching is by executable path, not process name, so an unrelated tool never matches.
// Enumeration is per-OS (see singleton_linux.go / singleton_darwin.go); on unsupported
// systems it degrades to a no-op.
package singleton

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// forceGrace is how long, after escalating to SIGKILL, we keep waiting before giving up
// and starting anyway — so an unkillable survivor never wedges startup forever.
const forceGrace = 3 * time.Second

// TakeExclusive terminates every other running process that shares this process's
// executable path. Each is sent SIGTERM and given up to grace to exit gracefully; a
// straggler is then escalated to SIGKILL. It returns once no such process remains (or a
// stubborn one has outlived even the kill grace). Cancelling ctx aborts the wait and
// returns ctx.Err(). With no other instance running it is a cheap no-op.
func TakeExclusive(ctx context.Context, grace time.Duration, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	self, pids, err := others()
	if err != nil {
		return err
	}
	if len(pids) == 0 {
		return nil
	}

	logf("singleton: %s already running as pid(s) %v; sending SIGTERM and waiting for graceful shutdown", self, pids)
	for _, pid := range pids {
		if err := terminate(pid); err != nil {
			logf("singleton: SIGTERM pid %d: %v", pid, err)
		}
	}
	return waitGone(ctx, pids, grace, logf)
}

// Others returns the pids of every other running process launched from the same
// executable file as this one — exactly the set TakeExclusive would terminate. A caller
// that would rather refuse than take over (e.g. a run that must not start twice because
// two copies would collide on shared external resources) can report these and abort
// instead of killing them.
func Others() ([]int, error) {
	_, pids, err := others()
	return pids, err
}

// others resolves this process's executable and returns it alongside the pids of every
// other process running from the same file.
func others() (self string, pids []int, err error) {
	exe, err := os.Executable()
	if err != nil {
		return "", nil, fmt.Errorf("singleton: resolve own executable: %w", err)
	}
	self = resolvePath(exe)
	pids, err = sameBinaryPIDs(self)
	if err != nil {
		return "", nil, fmt.Errorf("singleton: scan running processes: %w", err)
	}
	return self, pids, nil
}

// waitGone blocks until every pid has exited. After grace it escalates any survivor to
// SIGKILL; after a further forceGrace it gives up and returns nil so an unkillable
// process never blocks startup indefinitely.
func waitGone(ctx context.Context, pids []int, grace time.Duration, logf func(string, ...any)) error {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	termDeadline := time.Now().Add(grace)
	var killDeadline time.Time
	forced := false
	for {
		alive := live(pids)
		if len(alive) == 0 {
			return nil
		}
		now := time.Now()
		switch {
		case !forced && now.After(termDeadline):
			for _, pid := range alive {
				logf("singleton: pid %d ignored SIGTERM after %s; sending SIGKILL", pid, grace)
				_ = forceKill(pid)
			}
			forced, killDeadline = true, now.Add(forceGrace)
		case forced && now.After(killDeadline):
			logf("singleton: pid(s) %v still present after SIGKILL; proceeding anyway", alive)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

func live(pids []int) []int {
	var out []int
	for _, pid := range pids {
		if alivePID(pid) {
			out = append(out, pid)
		}
	}
	return out
}

// resolvePath canonicalises an executable path so two references to the same binary
// compare equal: it strips the " (deleted)" marker Linux appends to /proc/<pid>/exe when
// a running binary has been replaced in place (exactly what an rsync redeploy does — the
// path is then re-created, so symlink resolution lands on the new file), then resolves
// symlinks.
func resolvePath(path string) string {
	path = strings.TrimSuffix(path, " (deleted)")
	if r, err := filepath.EvalSymlinks(path); err == nil {
		return r
	}
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}
