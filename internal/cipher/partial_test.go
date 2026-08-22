package cipher

import (
	"bytes"
	"strings"
	"testing"

	"github.com/arash16/dualnet/internal/wire"
)

func TestParseName(t *testing.T) {
	cases := []struct {
		in      string
		base    string
		head    int
		wantErr bool
	}{
		{"", "none", 0, false},
		{"none", "none", 0, false},
		{"chacha4", "chacha4", 0, false},
		{"chacha4:16", "chacha4", 16, false},
		{"chacha4:256", "chacha4", 256, false},
		{"chacha4:0", "", 0, true},   // below the minimum head
		{"chacha4:8", "", 0, true},   // below minObfsHead (16)
		{"chacha4:-4", "", 0, true},  // negative
		{"chacha4:abc", "", 0, true}, // not an integer
		{"none:16", "", 0, true},     // none takes no head
		{"aes", "", 0, true},         // unknown base
	}
	for _, c := range cases {
		base, head, err := ParseName(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseName(%q) = (%q,%d,nil), want error", c.in, base, head)
			}
			continue
		}
		if err != nil || base != c.base || head != c.head {
			t.Errorf("ParseName(%q) = (%q,%d,%v), want (%q,%d,nil)", c.in, base, head, err, c.base, c.head)
		}
	}
}

// TestPartialObfuscationRoundTrip proves a chacha4:N packet cipher obfuscates only the first N
// bytes of each payload, leaves the tail in cleartext, and round-trips: the receiver, configured
// with the same N, recovers the whole payload.
func TestPartialObfuscationRoundTrip(t *testing.T) {
	const head = 32
	key := testKey("partial")
	pc, err := NewPacket("chacha4:32", key)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(strings.Repeat("H", head) + strings.Repeat("T", 400)) // head + tail
	sealed, err := pc.Seal(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	body := sealed[pc.Overhead():]
	if bytes.Equal(body[:head], payload[:head]) {
		t.Fatal("head region was not obfuscated")
	}
	if !bytes.Equal(body[head:], payload[head:]) {
		t.Fatal("tail region must be verbatim cleartext under a head limit")
	}
	got, err := pc.Open(append([]byte(nil), sealed...))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("partial round-trip did not recover the payload")
	}
}

// TestPartialShorterThanHead: a payload shorter than the head limit is fully obfuscated (the
// limit is a ceiling, not a requirement), and still round-trips.
func TestPartialShorterThanHead(t *testing.T) {
	pc, _ := NewPacket("chacha4:256", testKey("short-head"))
	payload := []byte("only forty-ish bytes, well under the head")
	sealed, _ := pc.Seal(nil, payload)
	if bytes.Equal(sealed[pc.Overhead():], payload) {
		t.Fatal("short payload should be fully obfuscated")
	}
	got, _ := pc.Open(sealed)
	if !bytes.Equal(got, payload) {
		t.Fatal("round-trip failed for a payload shorter than head")
	}
}

// TestPartialStreamRoundTrip proves a chacha4:N stream cipher obfuscates each frame's length +
// first N payload bytes, leaves the tail in cleartext, and round-trips through the frame codec —
// the CPU-saving path for a cipher-bound TCP node. A frame shorter than N is fully obfuscated.
func TestPartialStreamRoundTrip(t *testing.T) {
	const head = 32
	sc, err := NewStream("chacha4:32", testKey("stream-partial"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := sc.WrapWriter(&buf) // emits the leading nonce
	if err != nil {
		t.Fatal(err)
	}
	small := []byte(strings.Repeat("s", 10))                            // < head: fully obfuscated
	big := []byte(strings.Repeat("H", head) + strings.Repeat("T", 200)) // head + cleartext tail
	for _, f := range [][]byte{small, big} {
		if err := wire.WriteFrame(w, f); err != nil {
			t.Fatal(err)
		}
	}

	// The last 200 wire bytes are big's tail; under partial obfuscation they must be verbatim.
	onWire := append([]byte(nil), buf.Bytes()...)
	if tail := onWire[len(onWire)-200:]; !bytes.Equal(tail, []byte(strings.Repeat("T", 200))) {
		t.Fatal("payload tail beyond head was not left in cleartext")
	}

	r, err := sc.WrapReader(&buf) // consumes the nonce
	if err != nil {
		t.Fatal(err)
	}
	rbuf := make([]byte, wire.MaxPacket)
	for i, want := range [][]byte{small, big} {
		n, err := wire.ReadFrame(r, rbuf)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(rbuf[:n], want) {
			t.Fatalf("frame %d round-trip mismatch", i)
		}
	}
}
