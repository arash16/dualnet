package wire

import (
	"bytes"
	"io"
	"net/netip"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	pkts := [][]byte{
		[]byte("hello"),
		{},
		bytes.Repeat([]byte{0xAB}, 1400),
		bytes.Repeat([]byte{0x00}, MaxPacket),
	}
	var buf bytes.Buffer
	for _, p := range pkts {
		if err := WriteFrame(&buf, p); err != nil {
			t.Fatalf("WriteFrame(%d bytes): %v", len(p), err)
		}
	}
	rbuf := make([]byte, MaxPacket)
	for i, want := range pkts {
		n, err := ReadFrame(&buf, rbuf)
		if err != nil {
			t.Fatalf("ReadFrame #%d: %v", i, err)
		}
		if !bytes.Equal(rbuf[:n], want) {
			t.Fatalf("ReadFrame #%d mismatch: got %d bytes want %d", i, n, len(want))
		}
	}
}

func TestReadFrameShortBuffer(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, bytes.Repeat([]byte{1}, 100)); err != nil {
		t.Fatal(err)
	}
	small := make([]byte, 10)
	if _, err := ReadFrame(&buf, small); err != io.ErrShortBuffer {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}

func TestTag(t *testing.T) {
	key := KeyFromPSK("psk")
	msg := []byte("register:abc123")
	tag := Tag(key, msg)
	if !VerifyTag(key, msg, tag) {
		t.Fatal("VerifyTag rejected a valid tag")
	}
	if VerifyTag(key, []byte("register:tampered"), tag) {
		t.Fatal("VerifyTag accepted a tampered message")
	}
	if VerifyTag(KeyFromPSK("other"), msg, tag) {
		t.Fatal("VerifyTag accepted under wrong key")
	}
}

func TestDstSrcIP(t *testing.T) {
	// Minimal IPv4 header: version/IHL, src 10.0.0.1 at [12:16], dst 10.0.0.2 at [16:20].
	p := make([]byte, 20)
	p[0] = 0x45
	copy(p[12:16], []byte{10, 0, 0, 1})
	copy(p[16:20], []byte{10, 0, 0, 2})
	if dst, ok := DstIP(p); !ok || dst != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("DstIP = %v %v", dst, ok)
	}
	if src, ok := SrcIP(p); !ok || src != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("SrcIP = %v %v", src, ok)
	}
	if _, ok := DstIP(make([]byte, 10)); ok {
		t.Fatal("DstIP accepted a too-short packet")
	}
	if PlausibleIP(make([]byte, 10)) {
		t.Fatal("PlausibleIP accepted a too-short packet")
	}
	if !PlausibleIP(p) {
		t.Fatal("PlausibleIP rejected a valid IPv4 header")
	}
}

func TestPing(t *testing.T) {
	p := EncodePing(42)
	if !IsPing(p) {
		t.Fatal("EncodePing output not recognized by IsPing")
	}
	if !PlausibleIP(p) {
		t.Fatal("ping packet should look like a plausible IP packet")
	}
	// A normal data packet must not be mistaken for a ping.
	data := make([]byte, 40)
	data[0] = 0x45
	data[9] = 6 // TCP
	if IsPing(data) {
		t.Fatal("TCP packet misidentified as a ping")
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	inner := []byte("inner-ip-packet-bytes")
	for _, tc := range []Envelope{
		{Owner: Owner{1, 2, 3, 4}, Processed: false},
		{Owner: Owner{0xff, 0, 0xab, 0x10}, Processed: true},
		{}, // zero owner, unprocessed
	} {
		blob := PutEnvelope(nil, tc, inner)
		if len(blob) != EnvelopeLen+len(inner) {
			t.Fatalf("blob len = %d, want %d", len(blob), EnvelopeLen+len(inner))
		}
		e, payload, ok := ParseEnvelope(blob)
		if !ok {
			t.Fatal("ParseEnvelope failed on a well-formed blob")
		}
		if e != tc {
			t.Fatalf("envelope round-trip: got %+v want %+v", e, tc)
		}
		if !bytes.Equal(payload, inner) {
			t.Fatalf("payload round-trip mismatch")
		}
	}
	if _, _, ok := ParseEnvelope(make([]byte, EnvelopeLen-1)); ok {
		t.Fatal("ParseEnvelope accepted a too-short blob")
	}
}
