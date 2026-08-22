package config

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleYAML = `
psk: secret
subnet: 10.9.0.0/24
egresses:
  internet: { mode: kernel, exit: eth0 }
connections:
  - { name: ClientIn, type: listen, direction: incoming, transport: http, port: 8443 }
  - { name: HPiOut,   type: listen, direction: outgoing, transport: udp,  port: 8444 }
  - name: Tun
    type: tun
    address: 10.9.0.1
routes:
  - { match: { source: "", processed: false }, action: { egress: internet, target: HPiOut } }
  - { match: { source: ClientIn, processed: true }, action: { target: Tun } }
`

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "node.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	n, err := Load(writeTemp(t, sampleYAML))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n.MTU != 1360 {
		t.Fatalf("default MTU not applied: %d", n.MTU)
	}
	if n.Connections[0].Cipher != "none" {
		t.Fatalf("default cipher not applied: %q", n.Connections[0].Cipher)
	}
}

// TestForArtifactStripsPSK pins that a config serialized for a deployment artifact carries no
// global PSK (delivered via DUALNET_PSK instead) but keeps per-connection PSK overrides (which
// have no env-delivery), and does not mutate the caller's config.
func TestForArtifactStripsPSK(t *testing.T) {
	n := Node{
		PSK: "the-real-secret",
		Connections: []Connection{
			{Name: "A", Type: "listen", Direction: "outgoing", Transport: "udp", Port: 1, PSK: "per-conn-override"},
		},
	}
	a := n.ForArtifact()
	if a.PSK != "" {
		t.Fatalf("ForArtifact PSK = %q, want empty (delivered via DUALNET_PSK)", a.PSK)
	}
	if len(a.Connections) != 1 || a.Connections[0].PSK != "per-conn-override" {
		t.Fatalf("per-connection PSK override must be preserved: %+v", a.Connections)
	}
	if n.PSK != "the-real-secret" {
		t.Fatalf("ForArtifact must not mutate the caller's config; PSK = %q", n.PSK)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	if _, err := Load(writeTemp(t, sampleYAML+"\nbogus: 1\n")); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

// TestKernelWarpEgress pins the kernel-datapath warp egress contract: exit (the underlay WAN
// the tunnel's endpoint UDP leaves through) is required, the WireGuard device name defaults to
// warp-<egress> and stays overridable, and an explicit underlay gateway is accepted.
func TestKernelWarpEgress(t *testing.T) {
	n, err := Load(writeTemp(t, `
datapath: kernel
egresses:
  wan: { mode: kernel, exit: eth0 }
  cf:  { mode: warp, exit: eth0, gateway: 192.0.2.1, warp_cache: /var/lib/dualnet/warp.json }
forward:
  - { egress: cf }
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := n.Egresses["cf"].TunName; got != "warp-cf" {
		t.Fatalf("warp device name = %q, want warp-cf", got)
	}

	n, err = Load(writeTemp(t, `
datapath: kernel
egresses:
  cf: { mode: warp, exit: ppp0, tun_name: wgcf, warp_insecure: true }
forward:
  - { egress: cf }
`))
	if err != nil {
		t.Fatalf("load with explicit tun_name: %v", err)
	}
	if got := n.Egresses["cf"].TunName; got != "wgcf" {
		t.Fatalf("explicit warp device name = %q, want wgcf", got)
	}
	if !n.Egresses["cf"].WARPInsecure {
		t.Fatalf("warp_insecure not carried through")
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]string{
		"finalize via unknown egress": `
psk: s
connections:
  - { name: A, type: listen, direction: outgoing, transport: udp, port: 1 }
routes:
  - { match: { processed: false }, action: { egress: nope, target: A } }
`,
		"finalize on processed": `
psk: s
egresses: { internet: { mode: kernel, exit: eth0 } }
connections:
  - { name: A, type: listen, direction: outgoing, transport: udp, port: 1 }
routes:
  - { match: { processed: true }, action: { egress: internet, target: A } }
`,
		"dst_in without file": `
psk: s
conditions:
  - { name: is-x, dst_in: {} }
connections:
  - { name: A, type: listen, direction: outgoing, transport: udp, port: 1 }
`,
		"dst condition on processed rule": `
psk: s
conditions:
  - { name: is-x, dst_in: { file: /tmp/x } }
connections:
  - { name: A, type: listen, direction: outgoing, transport: udp, port: 1 }
routes:
  - { match: { processed: true, conditions: [is-x] }, action: { target: A } }
`,
		"warpped udp": `
psk: s
connections:
  - { name: A, type: connect, direction: outgoing, transport: udp, ip: 1.2.3.4, port: 1, warpped: true }
`,
		"id_setter on outgoing": `
psk: s
connections:
  - { name: T, type: tun, address: 10.9.0.2 }
  - { name: A, type: connect, direction: outgoing, transport: http, ip: 1.2.3.4, port: 1, id_setter: T }
`,
		"unknown target": `
psk: s
connections:
  - { name: A, type: listen, direction: incoming, transport: udp, port: 1 }
routes:
  - { match: { processed: false }, action: { target: Nope } }
`,
		"missing psk": `
connections:
  - { name: A, type: listen, direction: incoming, transport: udp, port: 1 }
`,
		// A malformed source_ip must be rejected at load time (like the sibling ip field),
		// not deferred to node bring-up where `ip addr replace` fails.
		"bad source_ip address": `
psk: s
connections:
  - { name: A, type: connect, direction: outgoing, transport: udp, ip: 1.2.3.4, port: 1, source_ip: 10.0.0.256 }
`,
		"bad source_ip mask": `
psk: s
connections:
  - { name: A, type: connect, direction: outgoing, transport: udp, ip: 1.2.3.4, port: 1, source_ip: 1.2.3.4/33 }
`,
		"kernel warp egress without exit": `
datapath: kernel
egresses:
  cf: { mode: warp }
forward:
  - { egress: cf }
`,
		"kernel warp device name too long": `
datapath: kernel
egresses:
  cf: { mode: warp, exit: eth0, tun_name: this-name-is-16c }
forward:
  - { egress: cf }
`,
		"kernel warp duplicate device names": `
datapath: kernel
egresses:
  a: { mode: warp, exit: eth0, tun_name: wg0 }
  b: { mode: warp, exit: eth0, tun_name: wg0 }
forward:
  - { egress: a }
`,
		"kernel node direct egress": `
datapath: kernel
egresses:
  d: { mode: direct, exit: eth0 }
forward:
  - { egress: d }
`,
		"kernel egress with tun_name": `
datapath: kernel
egresses:
  wan: { mode: kernel, exit: eth0, tun_name: dn0 }
forward:
  - { egress: wan }
`,
		"kernel egress with warp_cache": `
datapath: kernel
egresses:
  wan: { mode: kernel, exit: eth0, warp_cache: /tmp/x }
forward:
  - { egress: wan }
`,
		"kernel egress with warp_insecure": `
datapath: kernel
egresses:
  wan: { mode: kernel, exit: eth0, warp_insecure: true }
forward:
  - { egress: wan }
`,
		"kernel egress bad gateway": `
datapath: kernel
egresses:
  cf: { mode: warp, exit: eth0, gateway: not-an-ip }
forward:
  - { egress: cf }
`,
		"userspace warp egress with tun_name": `
psk: s
egresses:
  w: { mode: warp, tun_name: wg0 }
connections:
  - { name: A, type: listen, direction: outgoing, transport: udp, port: 1 }
routes:
  - { match: { processed: false }, action: { egress: w, target: A } }
`,
		// A healthcheck up[0] naming a receiver (incoming) connection is not a Sender; the
		// probe cannot be injected on it. This must fail validation, not only at node build.
		"healthcheck up0 is a receiver": `
psk: s
conditions:
  - { name: hc, healthcheck: { up: [Down], tun: T } }
connections:
  - { name: T,    type: tun, address: 10.9.0.2 }
  - { name: Down, type: connect, direction: incoming, transport: udp, ip: 1.2.3.4, port: 1, id_setter: T }
  - { name: Up,   type: connect, direction: outgoing, transport: udp, ip: 1.2.3.4, port: 2 }
`,
	}
	for name, body := range cases {
		if _, err := Load(writeTemp(t, body)); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}
