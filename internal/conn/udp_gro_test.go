package conn

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/cipher"
	"github.com/arash16/dualnet/internal/wire"
)

// splitSegments mirrors the segment loop the UDP receive loops run, so the split arithmetic can
// be checked in isolation: segSize<=0 is one datagram, else back-to-back segSize chunks with a
// possibly-shorter tail.
func splitSegments(buf []byte, segSize int) [][]byte {
	var out [][]byte
	for off := 0; off < len(buf); {
		dlen := len(buf) - off
		if segSize > 0 && dlen > segSize {
			dlen = segSize
		}
		out = append(out, buf[off:off+dlen])
		off += dlen
	}
	return out
}

func TestUDPSegmentSplit(t *testing.T) {
	data := []byte("AAABBBCCCD") // 10 bytes
	cases := []struct {
		segSize int
		want    []string
	}{
		{0, []string{"AAABBBCCCD"}},             // not coalesced: whole buffer is one datagram
		{-1, []string{"AAABBBCCCD"}},            // treated like 0
		{3, []string{"AAA", "BBB", "CCC", "D"}}, // 3 full + short tail
		{5, []string{"AAABB", "BCCCD"}},         // exact multiple
		{100, []string{"AAABBBCCCD"}},           // segSize >= len → one datagram
	}
	for _, c := range cases {
		got := splitSegments(data, c.segSize)
		if len(got) != len(c.want) {
			t.Fatalf("segSize=%d: got %d segments, want %d", c.segSize, len(got), len(c.want))
		}
		for i := range c.want {
			if string(got[i]) != c.want[i] {
				t.Fatalf("segSize=%d seg %d = %q, want %q", c.segSize, i, got[i], c.want[i])
			}
		}
	}
}

// TestUDPListenInGRODelivery drives real datagrams through udpListenIn end to end (loopback UDP
// socket). Whether or not the kernel coalesces them, every sealed packet must be de-obfuscated
// and delivered exactly once — this exercises the GRO read + segment split with the real socket
// path (segSize is 0 on loopback, so it also covers the un-coalesced fallback).
func TestUDPListenInGRODelivery(t *testing.T) {
	port := freeUDPPort(t)
	key := wire.KeyFromPSK("gro-test")
	pc, _ := cipher.NewPacket("chacha4", key)
	uc, err := bindUDP(context.Background(), "", ":"+itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	li := &udpListenIn{name: "in", conn: uc, cipher: pc}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan wire.Owner, 64)
	_ = li.Start(ctx, func(_ string, e wire.Envelope, payload []byte) {
		if !wire.PlausibleIP(payload) {
			t.Error("delivered an implausible payload")
		}
		got <- e.Owner
	})
	defer li.Close()

	conn, _ := net.Dial("udp", "127.0.0.1:"+itoa(port))
	defer conn.Close()
	const n = 20
	inner := make([]byte, 40)
	inner[0] = 0x45
	inner[9] = 6
	for i := 0; i < n; i++ {
		owner := wire.Owner{byte(i), 0xBE, 0xEF, 0x01}
		blob := wire.PutEnvelope(nil, wire.Envelope{Owner: owner}, inner)
		sealed, _ := pc.Seal(nil, blob)
		if _, err := conn.Write(sealed); err != nil {
			t.Fatal(err)
		}
	}

	seen := map[wire.Owner]bool{}
	deadline := time.After(3 * time.Second)
	for len(seen) < n {
		select {
		case o := <-got:
			seen[o] = true
		case <-deadline:
			t.Fatalf("only %d/%d datagrams delivered", len(seen), n)
		}
	}
	for i := 0; i < n; i++ {
		if !seen[wire.Owner{byte(i), 0xBE, 0xEF, 0x01}] {
			t.Fatalf("datagram %d not delivered", i)
		}
	}
}

// TestReadGROFallback: on a non-UDP conn readGRO uses Read and reports segSize 0.
func TestReadGROFallback(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _, _ = a.Write([]byte("hello")) }()
	buf := make([]byte, 64)
	oob := make([]byte, groReadBufOOB)
	n, segSize, err := readGRO(b, buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	if segSize != 0 {
		t.Fatalf("non-UDP conn should report segSize 0, got %d", segSize)
	}
	if !bytes.Equal(buf[:n], []byte("hello")) {
		t.Fatalf("readGRO returned %q", buf[:n])
	}
}
