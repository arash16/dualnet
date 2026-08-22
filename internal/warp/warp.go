// Package warp routes the relay's egress through Cloudflare WARP using an
// in-process userspace WireGuard device (no kernel interface, no routing-table
// changes). It can auto-register a free WARP account with Cloudflare and cache
// it, or load an existing wgcf-style WireGuard profile.
package warp

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	apiBase         = "https://api.cloudflareclient.com/v0a1922"
	userAgent       = "okhttp/3.12.1"
	cfClientVersion = "a-6.3-1922"

	// WARP's well-known WireGuard endpoint (used when a profile omits one).
	defaultEndpoint = "engage.cloudflareclient.com:2408"
)

// Account holds everything needed to bring up the WARP WireGuard device.
type Account struct {
	PrivateKey    string `json:"private_key"`     // ours, base64
	PublicKey     string `json:"public_key"`      // ours, base64 (reference)
	PeerPublicKey string `json:"peer_public_key"` // Cloudflare's, base64
	EndpointHost  string `json:"endpoint_host"`   // host:port
	EndpointV4    string `json:"endpoint_v4"`     // ip:port (fallback)
	V4            string `json:"v4"`              // assigned tunnel IPv4
	V6            string `json:"v6"`              // assigned tunnel IPv6
	ClientID      string `json:"client_id"`       // base64, -> 3 reserved bytes
	DeviceID      string `json:"device_id"`
	Token         string `json:"token"`
	License       string `json:"license"`
}

// Reserved returns the 3 WireGuard "reserved" bytes derived from the WARP
// client_id (zero if none).
func (a *Account) Reserved() [3]byte {
	var r [3]byte
	if b, err := base64.StdEncoding.DecodeString(a.ClientID); err == nil && len(b) >= 3 {
		copy(r[:], b[:3])
	}
	return r
}

// endpoint returns the best host:port to dial for the WARP peer.
func (a *Account) endpoint() string {
	if a.EndpointHost != "" {
		return a.EndpointHost
	}
	if a.EndpointV4 != "" {
		return a.EndpointV4
	}
	return defaultEndpoint
}

var (
	httpClient = &http.Client{Timeout: 20 * time.Second}
	// insecureHTTPClient skips TLS verification for the registration call on a minimal router
	// image that ships no CA bundle (see Register's insecure parameter). The WireGuard tunnel
	// this account brings up is unaffected — it authenticates with Noise, not TLS.
	insecureHTTPClient = &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
)

// regClient returns the HTTP client used for the Cloudflare registration call.
func regClient(insecure bool) *http.Client {
	if insecure {
		return insecureHTTPClient
	}
	return httpClient
}

// Register creates a fresh anonymous WARP account with Cloudflare. When insecure is set the
// registration HTTPS call skips certificate verification (for a router with no CA bundle).
func Register(insecure bool) (*Account, error) {
	priv, pub, err := genKeyPair()
	if err != nil {
		return nil, err
	}
	reqBody, _ := json.Marshal(map[string]any{
		"key":        pub,
		"install_id": "",
		"fcm_token":  "",
		"tos":        time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"type":       "Android",
		"model":      "PC",
		"locale":     "en_US",
	})
	req, err := http.NewRequest(http.MethodPost, apiBase+"/reg", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("CF-Client-Version", cfClientVersion)
	req.Header.Set("Content-Type", "application/json")
	resp, err := regClient(insecure).Do(req)
	if err != nil {
		return nil, fmt.Errorf("warp: registration request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("warp: registration failed: %s: %s", resp.Status, bytes.TrimSpace(body))
	}

	var r struct {
		ID      string `json:"id"`
		Token   string `json:"token"`
		Account struct {
			License string `json:"license"`
		} `json:"account"`
		Config struct {
			ClientID string `json:"client_id"`
			Peers    []struct {
				PublicKey string `json:"public_key"`
				Endpoint  struct {
					V4   string `json:"v4"`
					V6   string `json:"v6"`
					Host string `json:"host"`
				} `json:"endpoint"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("warp: parse registration: %w", err)
	}
	if len(r.Config.Peers) == 0 {
		return nil, fmt.Errorf("warp: registration returned no peers")
	}
	p := r.Config.Peers[0]
	return &Account{
		PrivateKey:    priv,
		PublicKey:     pub,
		PeerPublicKey: p.PublicKey,
		EndpointHost:  p.Endpoint.Host,
		EndpointV4:    p.Endpoint.V4,
		V4:            r.Config.Interface.Addresses.V4,
		V6:            r.Config.Interface.Addresses.V6,
		ClientID:      r.Config.ClientID,
		DeviceID:      r.ID,
		Token:         r.Token,
		License:       r.Account.License,
	}, nil
}

// LoadOrRegister returns a cached account from cachePath, or registers a new one
// and caches it. An empty cachePath disables caching (always registers). insecure is
// forwarded to Register for the registration HTTPS call.
func LoadOrRegister(cachePath string, insecure bool) (*Account, error) {
	if cachePath != "" {
		if b, err := os.ReadFile(cachePath); err == nil {
			var a Account
			if json.Unmarshal(b, &a) == nil && a.PrivateKey != "" && a.V4 != "" {
				return &a, nil
			}
		}
	}
	a, err := Register(insecure)
	if err != nil {
		return nil, err
	}
	if cachePath != "" {
		_ = os.MkdirAll(filepath.Dir(cachePath), 0o700)
		if b, mErr := json.MarshalIndent(a, "", "  "); mErr == nil {
			_ = os.WriteFile(cachePath, b, 0o600)
		}
	}
	return a, nil
}

// LoadConfig parses a wgcf-style WireGuard profile (INI) into an Account. Reserved
// bytes are not part of the standard format, so they default to zero.
func LoadConfig(path string) (*Account, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	a := &Account{PeerPublicKey: "", EndpointHost: ""}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "privatekey":
			a.PrivateKey = v
		case "publickey":
			a.PeerPublicKey = v
		case "endpoint":
			a.EndpointHost = v
		case "address":
			for _, part := range strings.Split(v, ",") {
				part = strings.TrimSpace(part)
				ip, _, _ := strings.Cut(part, "/")
				if strings.Contains(ip, ":") {
					a.V6 = ip
				} else if ip != "" {
					a.V4 = ip
				}
			}
		case "reserved": // non-standard convenience: "a,b,c" decimal or base64
			a.ClientID = parseReservedToClientID(v)
		}
	}
	if a.PrivateKey == "" || a.PeerPublicKey == "" || a.V4 == "" {
		return nil, fmt.Errorf("warp: config %s missing PrivateKey/PublicKey/Address", path)
	}
	if a.EndpointHost == "" {
		a.EndpointHost = defaultEndpoint
	}
	return a, nil
}

// parseReservedToClientID accepts "a,b,c" (decimals) or a base64 string and
// returns the base64 client_id form used by Account.
func parseReservedToClientID(v string) string {
	if strings.Contains(v, ",") {
		var b []byte
		for _, p := range strings.Split(v, ",") {
			var n int
			if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &n); err == nil {
				b = append(b, byte(n))
			}
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	return v // assume already base64
}

func genKeyPair() (priv, pub string, err error) {
	var p [32]byte
	if _, err = rand.Read(p[:]); err != nil {
		return "", "", err
	}
	p[0] &= 248
	p[31] &= 127
	p[31] |= 64
	pubB, err := curve25519.X25519(p[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(p[:]), base64.StdEncoding.EncodeToString(pubB), nil
}

// b64ToHex converts a base64 WireGuard key to the hex form the UAPI expects.
func b64ToHex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
