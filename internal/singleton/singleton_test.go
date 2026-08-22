package singleton

import (
	"context"
	"strings"
	"testing"
	"time"
)

// unusedPID is above the default pid_max, so no live process can hold it.
const unusedPID = 0x7fffffff

func TestResolvePathStripsDeleted(t *testing.T) {
	const base = "/nonexistent/path/dualnet"
	got := resolvePath(base + " (deleted)")
	if strings.Contains(got, "(deleted)") {
		t.Fatalf("resolvePath kept the (deleted) marker: %q", got)
	}
	// The path does not exist, so it cannot be symlink-resolved; it should come back as the
	// stripped, absolute form.
	if got != base {
		t.Fatalf("resolvePath = %q, want %q", got, base)
	}
}

func TestSameBinaryPIDsNoMatch(t *testing.T) {
	// Nothing is running from this made-up path, so enumeration must come back empty (and,
	// crucially, without error) on every supported OS.
	pids, err := sameBinaryPIDs("/nonexistent/path/there-is-no-such-binary-xyz")
	if err != nil {
		t.Fatalf("sameBinaryPIDs: %v", err)
	}
	if len(pids) != 0 {
		t.Fatalf("sameBinaryPIDs(bogus) = %v, want empty", pids)
	}
}

func TestLiveDropsDeadPIDs(t *testing.T) {
	if got := live([]int{unusedPID}); len(got) != 0 {
		t.Fatalf("live(dead) = %v, want empty", got)
	}
}

func TestWaitGoneReturnsWhenAllDead(t *testing.T) {
	// All pids are already gone, so waitGone must return promptly without ever escalating.
	start := time.Now()
	if err := waitGone(context.Background(), []int{unusedPID}, time.Second, nil); err != nil {
		t.Fatalf("waitGone = %v, want nil", err)
	}
	if el := time.Since(start); el > 500*time.Millisecond {
		t.Fatalf("waitGone took %s, expected it to return immediately", el)
	}
}

func TestOthers(t *testing.T) {
	// The test binary runs from a unique path, so no other process shares it: Others must
	// succeed and (crucially, for a netsim guard that would refuse on a non-empty result)
	// report none.
	pids, err := Others()
	if err != nil {
		t.Fatalf("Others() error = %v", err)
	}
	if len(pids) != 0 {
		t.Fatalf("Others() = %v, want empty for a uniquely-pathed test binary", pids)
	}
}

func TestTakeExclusiveNoPriorInstance(t *testing.T) {
	// The test binary runs from a unique path with no sibling instance, so this must be a
	// clean no-op — and must never signal an unrelated process.
	if err := TakeExclusive(context.Background(), time.Second, nil); err != nil {
		t.Fatalf("TakeExclusive = %v, want nil", err)
	}
}
