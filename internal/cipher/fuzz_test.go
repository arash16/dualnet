package cipher

import (
	"bytes"
	"testing"
)

// Open runs on datagram bytes an attacker fully controls (the UDP carrier is unauthenticated).
// It must never panic on a truncated, empty, or nonce-only datagram, and a Seal→Open round-trip
// must recover any payload.

func cipherSeeds(f *testing.F) {
	for _, c := range [][]byte{
		nil, {}, {0x00}, make([]byte, 11), make([]byte, 12), make([]byte, 13),
		bytes.Repeat([]byte{0xff}, 2048),
	} {
		f.Add(c)
	}
}

func FuzzChacha4Open(f *testing.F) {
	cipherSeeds(f)
	pc, _ := NewPacket("chacha4", testKey("fuzz-open"))
	f.Fuzz(func(t *testing.T, datagram []byte) {
		_, _ = pc.Open(append([]byte(nil), datagram...)) // must not panic
	})
}

func FuzzNoneOpen(f *testing.F) {
	cipherSeeds(f)
	pc, _ := NewPacket("none", [32]byte{})
	f.Fuzz(func(t *testing.T, datagram []byte) {
		_, _ = pc.Open(append([]byte(nil), datagram...)) // must not panic
	})
}

func FuzzChacha4SealOpenRoundTrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte("x"), 4096))
	pc, _ := NewPacket("chacha4", testKey("fuzz-rt"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		sealed, err := pc.Seal(nil, payload)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if len(sealed) != pc.Overhead()+len(payload) {
			t.Fatalf("sealed length %d, want overhead+payload %d", len(sealed), pc.Overhead()+len(payload))
		}
		got, err := pc.Open(sealed)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("round-trip mismatch: got %x want %x", got, payload)
		}
	})
}
