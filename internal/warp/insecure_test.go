package warp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRegClientTLSVerification pins the warp_insecure behavior: the default registration client
// rejects a server whose certificate a bare host (no CA bundle) cannot verify, while the
// insecure client accepts it. httptest.NewTLSServer uses a self-signed cert, which stands in
// for exactly the "certificate signed by unknown authority" failure a certless router hits.
func TestRegClientTLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := regClient(false).Get(srv.URL); err == nil {
		t.Error("the default client must reject an unverifiable (self-signed) certificate")
	}
	resp, err := regClient(true).Get(srv.URL)
	if err != nil {
		t.Fatalf("the insecure client must accept a self-signed certificate: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("insecure client status = %d, want 200", resp.StatusCode)
	}
}
