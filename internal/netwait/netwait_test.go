package netwait

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestWaitEmptyReturnsImmediately(t *testing.T) {
	if err := Wait(context.Background(), nil, nil); err != nil {
		t.Fatalf("Wait(nil) = %v, want nil", err)
	}
	if err := Wait(context.Background(), []string{"", ""}, nil); err != nil {
		t.Fatalf("Wait(empties) = %v, want nil", err)
	}
}

func TestWaitCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A bogus interface will never be ready, so Wait must block — and then unblock on the
	// already-cancelled context rather than spin forever.
	err := Wait(ctx, []string{"dn-nope-xyz0"}, nil)
	if err != context.Canceled {
		t.Fatalf("Wait(cancelled) = %v, want context.Canceled", err)
	}
}

func TestWaitReadyInterface(t *testing.T) {
	name := aReadyInterface(t)
	// Already up with a usable address, so Wait must return promptly.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Wait(ctx, []string{name, name}, nil); err != nil {
		t.Fatalf("Wait(%q) = %v, want nil", name, err)
	}
}

func TestReadyMissing(t *testing.T) {
	if Ready("dn-definitely-not-an-interface") {
		t.Fatal("Ready(bogus) = true, want false")
	}
}

func TestReadyLoopbackNotReady(t *testing.T) {
	// Loopback is up but only carries 127.0.0.1/::1, which Ready deliberately rejects.
	for _, n := range []string{"lo", "lo0"} {
		if _, err := net.InterfaceByName(n); err == nil && Ready(n) {
			t.Fatalf("Ready(%q) = true, want false (loopback addr)", n)
		}
	}
}

func TestDedup(t *testing.T) {
	got := dedup([]string{"b", "", "a", "b", "a", ""})
	if want := []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("dedup = %v, want %v", got, want)
	}
}

// aReadyInterface returns the name of some real interface this host has that satisfies
// Ready (up, with a usable IPv4), skipping the test if none exists.
func aReadyInterface(t *testing.T) string {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Skipf("net.Interfaces: %v", err)
	}
	for _, ifi := range ifs {
		if Ready(ifi.Name) {
			return ifi.Name
		}
	}
	t.Skip("no ready (up + usable IPv4) interface on this host")
	return ""
}
