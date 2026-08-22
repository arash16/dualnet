package cipher

import (
	"bytes"
	"io"
	"math/bits"
	"testing"
)

// TestChacha4StreamRoundTrip verifies the obfuscated stream de-XORs correctly
// and that the wire bytes don't contain the plaintext.
func TestChacha4StreamRoundTrip(t *testing.T) {
	sc, _ := NewStream("chacha4", testKey("stream"))

	var wire bytes.Buffer
	w, err := sc.WrapWriter(&wire)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("packet-one"), 40)
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire.Bytes(), []byte("packet-one")) {
		t.Fatal("plaintext leaked into obfuscated stream")
	}

	r, err := sc.WrapReader(bytes.NewReader(wire.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("stream round-trip mismatch")
	}
}

// TestChacha4StreamWrongKey ensures a reader with the wrong key gets garbage.
func TestChacha4StreamWrongKey(t *testing.T) {
	sc, _ := NewStream("chacha4", testKey("real"))
	var wire bytes.Buffer
	w, _ := sc.WrapWriter(&wire)
	payload := bytes.Repeat([]byte("SENSITIVE"), 20)
	_, _ = w.Write(payload)

	bad, _ := NewStream("chacha4", testKey("wrong"))
	r, _ := bad.WrapReader(bytes.NewReader(wire.Bytes()))
	got := make([]byte, len(payload))
	_, _ = io.ReadFull(r, got)
	if bytes.Equal(got, payload) {
		t.Fatal("wrong key recovered plaintext")
	}
}

// TestChacha4PacketSealOpen round-trips a datagram, checks distinct nonces
// don't leak plaintext, and that a wrong key yields garbage.
func TestChacha4PacketSealOpen(t *testing.T) {
	pc, _ := NewPacket("chacha4", testKey("packet"))
	payload := bytes.Repeat([]byte("PACKET-DATA"), 100)

	sealed, err := pc.Seal(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	if pc.Overhead() != 12 {
		t.Fatalf("overhead = %d, want 12", pc.Overhead())
	}
	if bytes.Contains(sealed[pc.Overhead():], []byte("PACKET-DATA")) {
		t.Fatal("plaintext leaked into sealed datagram")
	}

	got, err := pc.Open(append([]byte(nil), sealed...))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("packet round-trip mismatch")
	}

	// Two seals must use distinct nonces (counter advances).
	sealed2, _ := pc.Seal(nil, payload)
	if bytes.Equal(sealed[:pc.Overhead()], sealed2[:pc.Overhead()]) {
		t.Fatal("nonce did not advance between seals")
	}

	bad, _ := NewPacket("chacha4", testKey("other"))
	garbled, err := bad.Open(append([]byte(nil), sealed...))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(garbled, payload) {
		t.Fatal("wrong key recovered plaintext")
	}

	if _, err := pc.Open(make([]byte, pc.Overhead()-1)); err == nil {
		t.Fatal("expected error on short datagram")
	}
}

// TestChacha4ByteDistribution is a coarse sanity check that the keystream
// doesn't collapse into an obviously non-uniform pattern (the property DPI
// resistance actually depends on) — not a cryptographic randomness
// certification, just a smoke test against a broken quarter-round.
func TestChacha4ByteDistribution(t *testing.T) {
	pc, _ := NewPacket("chacha4", testKey("distribution"))
	payload := make([]byte, 64*1024)
	sealed, err := pc.Seal(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	body := sealed[pc.Overhead():]

	var counts [256]int
	for _, b := range body {
		counts[b]++
	}
	want := len(body) / 256
	for b, c := range counts {
		if c < want/2 || c > want*3/2 {
			t.Fatalf("byte 0x%02x occurs %d times, want ~%d (skewed keystream)", b, c, want)
		}
	}
}

// TestChacha4Avalanche is a coarse sanity check, NOT a cryptanalytic result —
// flipping single input bits one at a time and checking the output looks
// ~50%-changed catches a gross diffusion failure (e.g. a round count so low
// that some output byte is still a direct function of one input byte), but
// it is nowhere near real cryptanalysis of reduced-round ChaCha: differential
// attacks search across many rounds for a *correlated combination* of many
// input bits, not a single flipped bit. The actual evidence for using 4
// rounds here is that this is a single-operator, no-live-deployment protocol
// with no need for ChaCha20's cryptanalytic margin — see chacha4.go's doc
// comment for the published cryptanalysis figures that informed that call.
// This test just guards against a broken quarter-round shipping silently.
//
// Covers every bit of the 96-bit nonce (not just one byte) and averages over
// several random bases to cut single-sample noise.
func TestChacha4Avalanche(t *testing.T) {
	keystream := func(key [32]byte, nonce [chachaNonceLen]byte) []byte {
		c := newChacha4Cipher(key, nonce[:])
		out := make([]byte, chachaBlockSize)
		c.XORKeyStream(out, out) // XOR against zeros = raw keystream
		return out
	}

	bases := []string{"base-a", "base-b", "base-c"}

	minFrac, maxFrac := 1.0, 0.0
	for _, baseName := range bases {
		key := testKey("avalanche-" + baseName)
		var baseNonce [chachaNonceLen]byte
		copy(baseNonce[:], []byte(baseName+"-nonce12"))
		base := keystream(key, baseNonce)

		for byteIdx := 0; byteIdx < chachaNonceLen; byteIdx++ {
			for bit := 0; bit < 8; bit++ {
				flipped := baseNonce
				flipped[byteIdx] ^= 1 << bit
				out := keystream(key, flipped)

				diffBits := 0
				for i := range base {
					diffBits += bits.OnesCount8(base[i] ^ out[i])
				}
				frac := float64(diffBits) / float64(len(base)*8)
				if frac < minFrac {
					minFrac = frac
				}
				if frac > maxFrac {
					maxFrac = frac
				}
			}
		}
	}
	t.Logf("chacha4: single-bit-flip avalanche range across full nonce [%.1f%%, %.1f%%] (ideal ~50%%)", minFrac*100, maxFrac*100)
	// A generous band (not a tight cryptographic bound) — this only catches a
	// gross failure, see the doc comment above.
	if minFrac < 0.3 || maxFrac > 0.7 {
		t.Errorf("chacha4: avalanche out of band [%.1f%%, %.1f%%], want within [30%%, 70%%] of 50%%", minFrac*100, maxFrac*100)
	}
}
