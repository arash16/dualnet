package netschema

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseLink(t *testing.T) {
	cases := map[string]struct {
		def  string
		want Link
	}{
		"basic to-acceptor": {
			"pi -> turkish (covert, 8443)",
			Link{Dialer: "pi", Acceptor: "turkish", Dataflow: toAcceptor, Protocol: "covert", Port: 8443},
		},
		"to-dialer with dialer source": {
			"pi.auto <- turkish (fast, 8444)",
			Link{Dialer: "pi", DialerSource: "auto", Acceptor: "turkish", Dataflow: toDialer, Protocol: "fast", Port: 8444},
		},
		"acceptor source": {
			"a -> b.wan (udp, 1)",
			Link{Dialer: "a", Acceptor: "b", AcceptorSource: "wan", Dataflow: toAcceptor, Protocol: "udp", Port: 1},
		},
		"multiple downlink": {
			"leaf <<- mid (udp, 4)",
			Link{Dialer: "leaf", Acceptor: "mid", Dataflow: toDialer, Multiple: true, Protocol: "udp", Port: 4},
		},
		"id-setter downlink (names the tun)": {
			"leaf <utun9- mid (udp, 4)",
			Link{Dialer: "leaf", Acceptor: "mid", Dataflow: toDialer, IDSetter: "utun9", Protocol: "udp", Port: 4},
		},
		"multiple + id-setter downlink": {
			"leaf <<tuna- mid (udp, 4)",
			Link{Dialer: "leaf", Acceptor: "mid", Dataflow: toDialer, Multiple: true, IDSetter: "tuna", Protocol: "udp", Port: 4},
		},
		"multiple uplink": {
			"a ->> b (udp, 2)",
			Link{Dialer: "a", Acceptor: "b", Dataflow: toAcceptor, Multiple: true, Protocol: "udp", Port: 2},
		},
		"id-setter uplink": {
			"a -tun5> b (udp, 2)",
			Link{Dialer: "a", Acceptor: "b", Dataflow: toAcceptor, IDSetter: "tun5", Protocol: "udp", Port: 2},
		},
		"both uplink": {
			"a -tun5>> b (udp, 2)",
			Link{Dialer: "a", Acceptor: "b", Dataflow: toAcceptor, Multiple: true, IDSetter: "tun5", Protocol: "udp", Port: 2},
		},
	}
	for name, tc := range cases {
		got, err := parseLink("L", tc.def)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		tc.want.Name = "L"
		if got != tc.want {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, tc.want)
		}
	}
}

func TestParseLinkRejects(t *testing.T) {
	for name, def := range map[string]string{
		"no arrow":     "pi turkish (covert, 8443)",
		"no parens":    "pi -> turkish covert 8443",
		"no acceptor":  "pi -> (covert, 8443)",
		"bad port":     "pi -> turkish (covert, http)",
		"missing port": "pi -> turkish (covert)",
		"extra param":  "pi -> turkish (covert, 80, multiple)",
	} {
		if _, err := parseLink("L", def); err == nil {
			t.Errorf("%s: expected error for %q", name, def)
		}
	}
}

// TestParseLinkNames checks the arrow scan is robust to arbitrary alphanumeric node/connection
// names, including hyphenated names and a connection literally named "tun" (which must NOT be
// mistaken for the `-tun>` / `<tun-` assigns_id arrows — those need a hyphen adjacent to "tun").
func TestParseLinkNames(t *testing.T) {
	cases := map[string]struct {
		def  string
		want Link
	}{
		"digits everywhere": {
			"lap2.wan0 -> gw3 (proto7, 8443)",
			Link{Dialer: "lap2", DialerSource: "wan0", Acceptor: "gw3", Dataflow: toAcceptor, Protocol: "proto7", Port: 8443},
		},
		"connection named tun": {
			"a.tun -> b (udp, 1)",
			Link{Dialer: "a", DialerSource: "tun", Acceptor: "b", Dataflow: toAcceptor, Protocol: "udp", Port: 1},
		},
		"hyphenated node names": {
			"home-pi <- edge-gw (udp, 2)",
			Link{Dialer: "home-pi", Acceptor: "edge-gw", Dataflow: toDialer, Protocol: "udp", Port: 2},
		},
		"macos utun-style device name as acceptor conn": {
			"laptop.iran -> turkish.utun9 (covert, 8443)",
			Link{Dialer: "laptop", DialerSource: "iran", Acceptor: "turkish", AcceptorSource: "utun9", Dataflow: toAcceptor, Protocol: "covert", Port: 8443},
		},
	}
	for name, tc := range cases {
		got, err := parseLink("L", tc.def)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		tc.want.Name = "L"
		if got != tc.want {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, tc.want)
		}
	}
}

// scalar builds a scalar yaml.Node for a route value.
func scalar(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Value: s} }

func TestParseBranch(t *testing.T) {
	cases := map[string]struct {
		cond, dsl string
		want      Branch
	}{
		"local parenthesized": {"is-iran", "(ftth)", Branch{When: []string{"is-iran"}, Egress: "ftth"}},
		"local bare":          {"is-iran", "local", Branch{When: []string{"is-iran"}, Egress: "local"}},
		"default local":       {"default", "(starlink)", Branch{Egress: "starlink"}},
		"gateway chain": {
			"default", "vps-turkish > (internet) > turkish-pi > pi-vps",
			Branch{Egress: "internet", Up: []string{"vps-turkish"}, Down: []string{"turkish-pi", "pi-vps"}},
		},
		"up only": {
			"turkey", "router-up > (internet)",
			Branch{When: []string{"turkey"}, Egress: "internet", Up: []string{"router-up"}},
		},
	}
	for name, tc := range cases {
		got, err := parseBranch(tc.cond, scalar(tc.dsl))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.Egress != tc.want.Egress || strings.Join(got.When, ",") != strings.Join(tc.want.When, ",") ||
			strings.Join(got.Up, ",") != strings.Join(tc.want.Up, ",") || strings.Join(got.Down, ",") != strings.Join(tc.want.Down, ",") {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, tc.want)
		}
	}
}

func TestParseBranchRejects(t *testing.T) {
	for name, dsl := range map[string]string{
		"two egresses":        "a > (x) > (y) > b",
		"chain without paren": "a > b > c",
	} {
		if _, err := parseBranch("c", scalar(dsl)); err == nil {
			t.Errorf("%s: expected error for %q", name, dsl)
		}
	}
	// A sequence value (the old `[egress]` YAML quirk) is rejected — parentheses are required.
	if _, err := parseBranch("c", &yaml.Node{Kind: yaml.SequenceNode}); err == nil {
		t.Error("expected error for a non-scalar route value")
	}
}
