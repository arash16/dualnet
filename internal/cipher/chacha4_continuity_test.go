package cipher

import (
	"bytes"
	"io"
	"testing"
)

// TestChacha4KeystreamContinuityAcrossCalls pins the load-bearing property that the
// production HTTP carrier depends on: WriteFrame emits a frame as a 2-byte length header
// then the body in TWO separate writes through one long-lived chacha4Writer, and the reader
// re-splits the stream at arbitrary net.Conn boundaries. Correct decryption therefore hinges
// entirely on XORKeyStream's leftover-buffer branch (c.len != 0) producing one seamless
// keystream regardless of how the byte stream is chunked. Every other test drives a fresh
// cipher with a single XORKeyStream call, so that branch is otherwise never exercised.
func TestChacha4KeystreamContinuityAcrossCalls(t *testing.T) {
	key := testKey("continuity")
	var nonce [chachaNonceLen]byte
	copy(nonce[:], "nonce-12byte")

	const n = 1000
	// Reference: whole keystream in one call.
	ref := make([]byte, n)
	newChacha4Cipher(key, nonce[:]).XORKeyStream(ref, ref)

	// Chunk sizes deliberately straddle the 64-byte block boundary in every way: sub-block,
	// exact block, block+1, spanning multiple blocks, and odd remainders.
	chunks := []int{1, 1, 2, 60, 3, 64, 5, 63, 1, 128, 200, 63, 65, 1, 15, 200}
	got := make([]byte, n)
	c := newChacha4Cipher(key, nonce[:])
	off := 0
	for _, sz := range chunks {
		if off >= n {
			break
		}
		if off+sz > n {
			sz = n - off
		}
		c.XORKeyStream(got[off:off+sz], got[off:off+sz])
		off += sz
	}
	// Fill any tail past the listed chunk budget so the whole buffer is covered.
	if off < n {
		c.XORKeyStream(got[off:], got[off:])
	}
	if !bytes.Equal(ref, got) {
		t.Fatalf("chunked keystream != single-call keystream (leftover-buffer bug)\n ref=%x\n got=%x", ref[:32], got[:32])
	}
}

// TestChacha4StreamChunkedWriteAndByteReads exercises the real carrier shape end to end:
// header+body written as separate frames through WrapWriter, and read back one byte at a
// time through WrapReader. A leftover-continuation bug would corrupt this even though the
// single-shot round-trip test stays green.
func TestChacha4StreamChunkedWriteAndByteReads(t *testing.T) {
	sc, _ := NewStream("chacha4", testKey("chunked-stream"))
	var netw bytes.Buffer
	w, err := sc.WrapWriter(&netw)
	if err != nil {
		t.Fatal(err)
	}
	// Emit several frames, each a 2-byte header write followed by a body write (like
	// wire.WriteFrame) so the writer takes the leftover branch on every body write.
	var want []byte
	for i, body := range [][]byte{[]byte("a"), bytes.Repeat([]byte("bc"), 40), []byte("de"), bytes.Repeat([]byte("z"), 130)} {
		hdr := []byte{byte(len(body) >> 8), byte(len(body))}
		if _, err := w.Write(hdr); err != nil {
			t.Fatalf("frame %d header: %v", i, err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatalf("frame %d body: %v", i, err)
		}
		want = append(want, hdr...)
		want = append(want, body...)
	}

	r, err := sc.WrapReader(bytes.NewReader(netw.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	// One byte per Read: forces the reader's XORKeyStream to be called with size 1 repeatedly,
	// which only decodes correctly if the leftover keystream carries across calls.
	for i := range got {
		if _, err := io.ReadFull(r, got[i:i+1]); err != nil {
			t.Fatalf("byte read %d: %v", i, err)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("chunked write / 1-byte read round-trip mismatch\n want=%x\n got =%x", want, got)
	}
}

// TestChacha4PacketNonceFullyRandom proves that a packet cipher must draw a fresh random
// nonce per datagram, not a fixed per-instance random prefix plus a counter that resets to
// 0. Under the old scheme two datagrams from one instance shared an identical 4-byte prefix
// (only the counter advanced), and two instances built from the same PSK-derived key both
// started their counter at 0 — so any prefix collision reused the entire keystream. A fully
// random nonce removes that structure.
func TestChacha4PacketNonceFullyRandom(t *testing.T) {
	pc := newChacha4Packet(testKey("nonce-random"), 0)
	s1, _ := pc.Seal(nil, []byte("hello"))
	s2, _ := pc.Seal(nil, []byte("hello"))
	// The first 4 bytes were a fixed per-instance prefix in the counter scheme, so they were
	// identical across seals; a random nonce makes them differ (flake ~2^-32).
	if bytes.Equal(s1[:4], s2[:4]) {
		t.Fatalf("nonce prefix identical across two seals from one instance: %x vs %x (counter-based, not random)", s1[:4], s2[:4])
	}

	// Two instances from the SAME key must not both emit a zero/sequential counter region:
	// the whole nonce must be independent (flake ~2^-64).
	a := newChacha4Packet(testKey("shared"), 0)
	b := newChacha4Packet(testKey("shared"), 0)
	sa, _ := a.Seal(nil, []byte("x"))
	sb, _ := b.Seal(nil, []byte("x"))
	if bytes.Equal(sa[:chachaNonceLen], sb[:chachaNonceLen]) {
		t.Fatalf("two same-key instances produced identical first-datagram nonces: %x", sa[:chachaNonceLen])
	}
}
