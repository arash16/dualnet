package cipher

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func testKey(s string) [32]byte { return sha256.Sum256([]byte("dualnet-test:" + s)) }

// TestNoneRoundTrip checks the identity ciphers pass data through unchanged.
func TestNoneRoundTrip(t *testing.T) {
	sc, _ := NewStream("none", testKey("x"))
	var buf bytes.Buffer
	w, _ := sc.WrapWriter(&buf)
	_, _ = w.Write([]byte("plain"))
	if buf.String() != "plain" {
		t.Fatalf("none stream altered data: %q", buf.String())
	}

	pc, _ := NewPacket("none", testKey("x"))
	sealed, _ := pc.Seal(nil, []byte("plain"))
	if string(sealed) != "plain" {
		t.Fatalf("none packet altered data: %q", sealed)
	}
	got, _ := pc.Open(sealed)
	if string(got) != "plain" {
		t.Fatalf("none open mismatch: %q", got)
	}
}

func TestUnknownCipher(t *testing.T) {
	if _, err := NewStream("bogus", testKey("x")); err == nil {
		t.Fatal("expected error for unknown stream cipher")
	}
	if _, err := NewPacket("bogus", testKey("x")); err == nil {
		t.Fatal("expected error for unknown packet cipher")
	}
}
