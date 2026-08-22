package netbind

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
)

func loopbackName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 && ifi.Flags&net.FlagUp != 0 {
			return ifi.Name
		}
	}
	t.Skip("no loopback interface found")
	return ""
}

// TestBindsRealInterface exercises the actual IP_BOUND_IF setsockopt path on
// this host. It is darwin-only because Linux's SO_BINDTODEVICE requires root.
func TestBindsRealInterface(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("positive bind test is darwin-specific (Linux SO_BINDTODEVICE needs root)")
	}
	name := loopbackName(t)
	pc, err := ListenPacket(context.Background(), name, "udp4", ":0")
	if err != nil {
		t.Fatalf("bind UDP to %q: %v", name, err)
	}
	_ = pc.Close()
}

// TestUnknownInterfaceFails ensures binding to a nonexistent interface errors (rather than
// silently binding nowhere). The old unconditional assertion passed for the WRONG reason
// on non-root Linux — SO_BINDTODEVICE needs CAP_NET_RAW, so the setsockopt fails with EPERM for
// ANY name before interface existence is consulted, meaning the test could not distinguish
// "nonexistent" from "no permission". Split the intent per platform so EPERM can no longer
// satisfy it.
func TestUnknownInterfaceFails(t *testing.T) {
	switch runtime.GOOS {
	case "darwin":
		// IP_BOUND_IF resolves the name via InterfaceByName, which fails for a nonexistent
		// interface regardless of privilege — a genuine test of the not-found path.
		if _, err := ListenPacket(context.Background(), "nope-not-real0", "udp4", ":0"); err == nil {
			t.Fatal("expected error binding to a nonexistent interface")
		}
	case "linux":
		if os.Geteuid() != 0 {
			t.Skip("Linux SO_BINDTODEVICE needs root; without CAP_NET_RAW it fails with EPERM for any name, masking the not-found result")
		}
		// As root, a real up interface binds and a nonexistent one errors (ENODEV, not EPERM).
		real := loopbackName(t)
		pc, err := ListenPacket(context.Background(), real, "udp4", ":0")
		if err != nil {
			t.Fatalf("binding to a real interface %q should succeed as root: %v", real, err)
		}
		_ = pc.Close()
		if _, err := ListenPacket(context.Background(), "nope-not-real0", "udp4", ":0"); err == nil {
			t.Fatal("expected error binding to a nonexistent interface")
		}
	default:
		t.Skipf("interface binding is platform-specific (GOOS=%s)", runtime.GOOS)
	}
}

// TestParseSourceAddr covers that source binding depends on parseSourceAddr returning the HOST
// address of an "ip/mask" (not the masked network) — a regression to p.Masked().Addr() would
// bind sockets to an address the box does not own (dial EADDRNOTAVAIL) or make `ip rule from
// <legIP>` never match, silently steering the leg out the wrong WAN. Untested until now.
func TestParseSourceAddr(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" = expect an error
	}{
		{"10.99.0.1/32", "10.99.0.1"},
		{"10.0.0.5/24", "10.0.0.5"}, // host, NOT the masked 10.0.0.0
		{"192.168.1.7", "192.168.1.7"},
		{"::1", "::1"},
		{"2001:db8::5/64", "2001:db8::5"}, // host, not the masked ::
		{"not-an-ip", ""},
		{"10.0.0.1/33", ""},
		{"", ""},
	}
	for _, c := range cases {
		got, err := parseSourceAddr(c.in)
		if c.want == "" {
			if err == nil {
				t.Errorf("parseSourceAddr(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSourceAddr(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != netip.MustParseAddr(c.want) {
			t.Errorf("parseSourceAddr(%q) = %v, want %s (host, not masked)", c.in, got, c.want)
		}
	}
}

// TestLocalAddr covers that localAddr must return the transport-appropriate net.Addr type with
// the source IP and a zero port, or nil for an unrecognized network (letting the OS choose). A
// wrong type or a nil for tcp/udp silently disables source binding.
func TestLocalAddr(t *testing.T) {
	ip := netip.MustParseAddr("10.99.0.1")
	std := net.IP(ip.AsSlice())

	if a, ok := localAddr("udp4", ip).(*net.UDPAddr); !ok || !a.IP.Equal(std) || a.Port != 0 {
		t.Errorf("localAddr(udp4) = %#v, want *net.UDPAddr{IP:10.99.0.1, Port:0}", localAddr("udp4", ip))
	}
	if a, ok := localAddr("udp", ip).(*net.UDPAddr); !ok || !a.IP.Equal(std) {
		t.Errorf("localAddr(udp) not a *net.UDPAddr with the ip: %#v", localAddr("udp", ip))
	}
	if a, ok := localAddr("tcp6", ip).(*net.TCPAddr); !ok || !a.IP.Equal(std) || a.Port != 0 {
		t.Errorf("localAddr(tcp6) = %#v, want *net.TCPAddr{IP, Port:0}", localAddr("tcp6", ip))
	}
	if got := localAddr("ip4:icmp", ip); got != nil {
		t.Errorf("localAddr(ip4:icmp) = %#v, want nil (OS chooses)", got)
	}
}

// TestEmptyInterfaceIsNoop ensures an empty interface name binds normally.
func TestEmptyInterfaceIsNoop(t *testing.T) {
	pc, err := ListenPacket(context.Background(), "", "udp4", ":0")
	if err != nil {
		t.Fatalf("empty iface should be a no-op: %v", err)
	}
	_ = pc.Close()
}
