package cipher

import (
	"bytes"
	"testing"
)

// TestSealInPlaceRoundTrip checks that a datagram built as [prefix][nonce][body] and sealed in
// place is decoded back to the original body by Open, for both ciphers. This is the exact path
// the UDP senders take.
func TestSealInPlaceRoundTrip(t *testing.T) {
	for _, name := range []string{"chacha4", "none"} {
		t.Run(name, func(t *testing.T) {
			pc, err := NewPacket(name, testKey(name))
			if err != nil {
				t.Fatal(err)
			}
			body := []byte("owner+flags+inner IP packet bytes, of some length")
			const prefix = 1 // a MsgData-style leading byte the seal must not touch
			buf := make([]byte, prefix+pc.Overhead()+len(body))
			buf[0] = 0x7F
			copy(buf[prefix+pc.Overhead():], body)

			if err := pc.SealInPlace(buf[prefix:]); err != nil {
				t.Fatalf("SealInPlace: %v", err)
			}
			if buf[0] != 0x7F {
				t.Fatal("SealInPlace overwrote the prefix byte")
			}
			if name == "chacha4" && bytes.Equal(buf[prefix+pc.Overhead():], body) {
				t.Fatal("chacha4 SealInPlace left the body in cleartext")
			}
			// Open reverses it: it reads the nonce and XORs the body back.
			got, err := pc.Open(buf[prefix:])
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, body) {
				t.Fatalf("round-trip mismatch: got %q want %q", got, body)
			}
		})
	}
}

// TestSealInPlaceMatchesSeal proves SealInPlace and Seal are wire-compatible: a datagram sealed
// either way opens to the same plaintext under the same key (nonces differ, so the ciphertext
// bytes differ, but both decode correctly). This guards the in-place refactor against drift.
func TestSealInPlaceMatchesSeal(t *testing.T) {
	pc, _ := NewPacket("chacha4", testKey("compat"))
	body := bytes.Repeat([]byte("x"), 200)

	sealed, _ := pc.Seal(nil, body)
	viaSeal, _ := pc.Open(append([]byte(nil), sealed...))

	buf := make([]byte, pc.Overhead()+len(body))
	copy(buf[pc.Overhead():], body)
	_ = pc.SealInPlace(buf)
	viaInPlace, _ := pc.Open(buf)

	if !bytes.Equal(viaSeal, body) || !bytes.Equal(viaInPlace, body) {
		t.Fatalf("both paths must decode to the original body")
	}
}

// TestSealInPlaceTooShort: a region shorter than the nonce is rejected, not a panic.
func TestSealInPlaceTooShort(t *testing.T) {
	pc, _ := NewPacket("chacha4", testKey("short"))
	if err := pc.SealInPlace(make([]byte, pc.Overhead()-1)); err == nil {
		t.Fatal("expected error sealing a region shorter than the nonce")
	}
}
