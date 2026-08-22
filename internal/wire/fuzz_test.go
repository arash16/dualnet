package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Attacker-mindset robustness: every wire parser runs on bytes an off-path or on-path adversary
// fully controls (the wire is unauthenticated for data). None may panic, hang, or over-allocate
// on truncated, oversized, or adversarially-shaped input. These fuzz targets also run their seed
// corpus under a plain `go test`, so they are regression tests even without -fuzz.

// adversarialCorpus is a set of hostile byte shapes reused as fuzz seeds.
func adversarialCorpus() [][]byte {
	return [][]byte{
		nil, {}, {0x00}, {0x45}, {0xff},
		make([]byte, 4), make([]byte, 5), make([]byte, 19), make([]byte, 20), make([]byte, 40),
		bytes.Repeat([]byte{0xff}, 65535),
		{0x45, 0, 0, 28, 0, 0, 0, 0, 64, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // ping-ish header
		{0x60, 0, 0, 0, 0, 0, 0, 0},                                         // v6-ish, too short
	}
}

func seed(f *testing.F) {
	for _, c := range adversarialCorpus() {
		f.Add(c)
	}
}

// FuzzParseEnvelope: parsing must never panic and must respect the length gate; a successful
// parse must return a payload that is a strict suffix of the input (no aliasing past the end).
func FuzzParseEnvelope(f *testing.F) {
	seed(f)
	f.Fuzz(func(t *testing.T, blob []byte) {
		e, inner, ok := ParseEnvelope(blob)
		if !ok {
			if len(blob) >= EnvelopeLen {
				t.Fatalf("not ok on a blob long enough for the envelope: %d", len(blob))
			}
			return
		}
		if len(blob) < EnvelopeLen {
			t.Fatalf("ok on a blob shorter than the envelope: %d", len(blob))
		}
		// The payload is exactly the bytes after the 5-byte envelope (the important property:
		// no truncation, no aliasing past the end). The flags byte has reserved bits beyond
		// bit 0 that are intentionally ignored, so the raw byte need not round-trip.
		if !bytes.Equal(inner, blob[EnvelopeLen:]) {
			t.Fatalf("inner %x != blob suffix %x", inner, blob[EnvelopeLen:])
		}
		// Canonical idempotence: serializing the parsed (envelope, inner) and re-parsing yields
		// the same envelope and payload.
		e2, inner2, ok2 := ParseEnvelope(PutEnvelope(nil, e, inner))
		if !ok2 || e2 != e || !bytes.Equal(inner2, inner) {
			t.Fatalf("parse∘put not idempotent: (%v,%x) -> (%v,%x)", e, inner, e2, inner2)
		}
	})
}

// FuzzReadFrame: a hostile length prefix must yield a clean error (ErrShortBuffer when the
// claimed length exceeds the buffer), never an over-read, panic, or hang.
func FuzzReadFrame(f *testing.F) {
	seed(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		buf := make([]byte, MaxPacket)
		n, err := ReadFrame(bytes.NewReader(data), buf)
		if err == nil {
			if n < 0 || n > len(buf) {
				t.Fatalf("ReadFrame returned n=%d out of range", n)
			}
			if len(data) >= 2 {
				want := int(binary.BigEndian.Uint16(data[:2]))
				if n != want {
					t.Fatalf("ReadFrame n=%d, want the prefixed length %d", n, want)
				}
			}
		}
	})
}

// FuzzPlausibleIP / FuzzDstSrcIP: the wrong-key tripwire and the finalizer's address extraction
// run on adversarial payloads and must never panic.
func FuzzPlausibleIP(f *testing.F) {
	seed(f)
	f.Fuzz(func(t *testing.T, p []byte) {
		_ = PlausibleIP(p)
		_, _ = DstIP(p)
		_, _ = SrcIP(p)
		_ = IsPing(p)
	})
}

// FuzzVerifyTag: tag verification on attacker bytes must never panic and must reject a tag that
// is not the keyed MAC of the message.
func FuzzVerifyTag(f *testing.F) {
	key := KeyFromPSK("fuzz-key")
	f.Add([]byte("msg"), make([]byte, 8))
	f.Fuzz(func(t *testing.T, msg, tagBytes []byte) {
		var tag [8]byte
		copy(tag[:], tagBytes)
		got := VerifyTag(key, msg, tag)
		// A random/attacker tag must only verify if it equals the real MAC (vanishingly rare).
		if got && tag != Tag(key, msg) {
			t.Fatal("VerifyTag accepted a tag that is not the keyed MAC")
		}
	})
}

// TestPingRoundTripAndNoFalsePositive pins that EncodePing/IsPing agree and that a plain data
// packet (TCP) is not mistaken for a healthcheck ping (which would let it be reflected / falsely
// signal liveness instead of being forwarded).
func TestPingRoundTripAndNoFalsePositive(t *testing.T) {
	if !IsPing(EncodePing(0)) || !IsPing(EncodePing(1<<63)) {
		t.Fatal("EncodePing output must satisfy IsPing")
	}
	// A well-formed IPv4 TCP packet must NOT read as a ping.
	tcp := make([]byte, 40)
	tcp[0] = 0x45
	tcp[9] = 6 // TCP
	if IsPing(tcp) {
		t.Fatal("a TCP packet was misclassified as a healthcheck ping")
	}
	// Too-short inputs are never pings and never panic.
	for i := 0; i < pingLen; i++ {
		if IsPing(make([]byte, i)) {
			t.Fatalf("a %d-byte packet must not be a ping", i)
		}
	}
}
