package warp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// b64Key returns a syntactically valid base64 WireGuard key filled with b. Tests use fixed
// literal keys (not generated ones) so assertions are deterministic and need no crypto.
func b64Key(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

// testAccount is a WARP account with an IP-literal endpoint so DeviceConfig needs no DNS.
func testAccount() *Account {
	return &Account{
		PrivateKey:    b64Key(1),
		PeerPublicKey: b64Key(2),
		EndpointHost:  "162.159.192.1:2408",
		V4:            "172.16.0.2",
		V6:            "2606:4700:110:8949::1",
	}
}

// TestDeviceConfigMapsAccount pins the Account -> kernel WireGuard mapping: key round-trips,
// the resolved endpoint, the keepalive shared with the userspace dialer, a v4-only catch-all
// allowed-ips set (the kernel datapath routes no IPv6), and the Replace flags that make
// re-programming an existing device idempotent.
func TestDeviceConfigMapsAccount(t *testing.T) {
	acct := testAccount()
	cfg, err := DeviceConfig(acct)
	if err != nil {
		t.Fatalf("DeviceConfig: %v", err)
	}
	if got := cfg.PrivateKey.String(); got != acct.PrivateKey {
		t.Errorf("private key = %q, want %q", got, acct.PrivateKey)
	}
	if !cfg.ReplacePeers || len(cfg.Peers) != 1 {
		t.Fatalf("want exactly one peer with ReplacePeers; got %+v", cfg)
	}
	p := cfg.Peers[0]
	if got := p.PublicKey.String(); got != acct.PeerPublicKey {
		t.Errorf("peer key = %q, want %q", got, acct.PeerPublicKey)
	}
	if got := p.Endpoint.String(); got != "162.159.192.1:2408" {
		t.Errorf("endpoint = %q, want 162.159.192.1:2408", got)
	}
	if p.PersistentKeepaliveInterval == nil || *p.PersistentKeepaliveInterval != 25*time.Second {
		t.Errorf("keepalive = %v, want 25s", p.PersistentKeepaliveInterval)
	}
	if !p.ReplaceAllowedIPs || len(p.AllowedIPs) != 1 || p.AllowedIPs[0].String() != "0.0.0.0/0" {
		t.Errorf("allowed ips = %v (replace=%v), want exactly [0.0.0.0/0]", p.AllowedIPs, p.ReplaceAllowedIPs)
	}
}

// TestDeviceMTU pins the kernel WireGuard device's MTU clamp: 1280 by default and as a hard
// ceiling (a larger inner MTU fragments over the WARP tunnel), but a smaller configured value
// is honored so an operator can lower it further on a still-fragmenting path.
func TestDeviceMTU(t *testing.T) {
	cases := map[int]int{
		0:    MTU,  // unset -> default 1280
		-1:   MTU,  // invalid -> default 1280
		1280: MTU,  // exactly the ceiling
		1360: MTU,  // node default (proto.DefaultMTU) capped down to 1280
		9000: MTU,  // anything larger capped to 1280
		1200: 1200, // a smaller configured MTU is honored
		576:  576,  // the minimum a config allows
	}
	for in, want := range cases {
		if got := deviceMTU(in); got != want {
			t.Errorf("deviceMTU(%d) = %d, want %d", in, got, want)
		}
	}
}

// TestReservedToCfID pins the client_id → reserved-bytes → WGDEVICE_A_CF_ID packing against a
// real registered account's value (client_id "3pbo" decodes to DE 96 E8). The kernel patch and
// this encoding must agree, so this locks the convention.
func TestReservedToCfID(t *testing.T) {
	r := (&Account{ClientID: "3pbo"}).Reserved()
	if r != [3]byte{0xDE, 0x96, 0xE8} {
		t.Fatalf("Reserved() = % x, want DE 96 E8", r[:])
	}
	if got := reservedToCfID(r); got != 0xDE96E8 {
		t.Errorf("reservedToCfID = %#x, want 0xDE96E8", got)
	}
	if reservedToCfID([3]byte{}) != 0 {
		t.Error("an absent client_id must pack to 0 so no CF_ID is set")
	}
}

func TestDeviceConfigBadKey(t *testing.T) {
	acct := testAccount()
	acct.PrivateKey = "not-a-key"
	if _, err := DeviceConfig(acct); err == nil {
		t.Error("expected error for bad private key")
	}
	acct = testAccount()
	acct.PeerPublicKey = "not-a-key"
	if _, err := DeviceConfig(acct); err == nil {
		t.Error("expected error for bad peer key")
	}
}

// TestDeviceConfigEndpointPrecedence pins the endpoint choice: the account's preferred
// endpoint (host) is used when it resolves to IPv4, and a v6-literal preferred endpoint falls
// back to the account's v4 endpoint because the kernel datapath cannot route the tunnel's
// outer UDP over IPv6.
func TestDeviceConfigEndpointPrecedence(t *testing.T) {
	acct := testAccount()
	acct.EndpointHost = ""
	acct.EndpointV4 = "162.159.192.7:2408"
	cfg, err := DeviceConfig(acct)
	if err != nil {
		t.Fatalf("DeviceConfig: %v", err)
	}
	if got := cfg.Peers[0].Endpoint.String(); got != "162.159.192.7:2408" {
		t.Errorf("endpoint = %q, want the v4 endpoint", got)
	}

	acct = testAccount()
	acct.EndpointHost = "[2606:4700:d0::a29f:c001]:2408"
	acct.EndpointV4 = "162.159.192.7:2408"
	cfg, err = DeviceConfig(acct)
	if err != nil {
		t.Fatalf("DeviceConfig: %v", err)
	}
	if got := cfg.Peers[0].Endpoint.String(); got != "162.159.192.7:2408" {
		t.Errorf("endpoint = %q, want fallback to the v4 endpoint", got)
	}
}

// TestDeviceConfigFromWgcfProfile drives the wgcf-INI path end-to-end: LoadConfig parses the
// profile a user would point warp_config at, and DeviceConfig turns it into a device config.
func TestDeviceConfigFromWgcfProfile(t *testing.T) {
	ini := `[Interface]
PrivateKey = ` + b64Key(3) + `
Address = 172.16.0.2/32, 2606:4700:110:8949::1/128
[Peer]
PublicKey = ` + b64Key(4) + `
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 162.159.192.1:2408
`
	p := filepath.Join(t.TempDir(), "wgcf-profile.conf")
	if err := os.WriteFile(p, []byte(ini), 0o600); err != nil {
		t.Fatal(err)
	}
	acct, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg, err := DeviceConfig(acct)
	if err != nil {
		t.Fatalf("DeviceConfig: %v", err)
	}
	if got := cfg.PrivateKey.String(); got != b64Key(3) {
		t.Errorf("private key = %q, want the profile's", got)
	}
	if got := cfg.Peers[0].PublicKey.String(); got != b64Key(4) {
		t.Errorf("peer key = %q, want the profile's", got)
	}
	if got := cfg.Peers[0].Endpoint.String(); got != "162.159.192.1:2408" {
		t.Errorf("endpoint = %q, want the profile's", got)
	}
}

// TestCredentialsPrecedence pins the credential source order shared by both datapaths: an
// explicit wgcf profile wins over the cached account, and a valid cache is returned without
// any registration attempt (no HTTP happens in this test).
func TestCredentialsPrecedence(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "warp-cache.json")
	cached, _ := json.Marshal(Account{PrivateKey: b64Key(5), PeerPublicKey: b64Key(6), V4: "172.16.0.9"})
	if err := os.WriteFile(cachePath, cached, 0o600); err != nil {
		t.Fatal(err)
	}

	acct, err := Credentials("", cachePath, false)
	if err != nil {
		t.Fatalf("Credentials(cache): %v", err)
	}
	if acct.PrivateKey != b64Key(5) || acct.V4 != "172.16.0.9" {
		t.Fatalf("cache account not returned: %+v", acct)
	}

	confPath := filepath.Join(dir, "profile.conf")
	ini := "PrivateKey = " + b64Key(7) + "\nPublicKey = " + b64Key(8) + "\nAddress = 172.16.0.2/32\nEndpoint = 162.159.192.1:2408\n"
	if err := os.WriteFile(confPath, []byte(ini), 0o600); err != nil {
		t.Fatal(err)
	}
	acct, err = Credentials(confPath, cachePath, false)
	if err != nil {
		t.Fatalf("Credentials(config+cache): %v", err)
	}
	if acct.PrivateKey != b64Key(7) {
		t.Fatalf("wgcf profile must win over the cache; got key %q", acct.PrivateKey)
	}
}
