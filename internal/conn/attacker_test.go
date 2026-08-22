package conn

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/cipher"
	"github.com/arash16/dualnet/internal/peers"
	"github.com/arash16/dualnet/internal/proto"
	"github.com/arash16/dualnet/internal/wire"
)

func itoa(n int) string { return strconv.Itoa(n) }

// FuzzDecodeControl: the control codec is the sole anti-spoof gate for UDP peer registration.
// On attacker bytes it must never panic and must never accept a datagram not authenticated under
// the key.
func FuzzDecodeControl(f *testing.F) {
	key := wire.KeyFromPSK("fuzz")
	f.Add(encodeControl(proto.MsgRegister, wire.Owner{1, 2, 3, 4}, 0, 42, key))
	for _, c := range [][]byte{nil, {}, {proto.MsgRegister}, make([]byte, controlLen), make([]byte, controlLen-1), make([]byte, controlLen+1)} {
		f.Add(c)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _, err := decodeControl(data, key)
		if err == nil && len(data) != controlLen {
			t.Fatalf("accepted a control datagram of wrong length %d", len(data))
		}
	})
}

// freeUDPPort returns a free localhost UDP port (closing the probe socket so the listener can
// take it).
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return p
}

// TestScannerCannotRegister proves the auth boundary that MUST hold: an off-path scanner with no
// PSK cannot register a peer on a Multiple listen-out. It exercises the live UDP read loop +
// decodeControl + peers registry together. A datagram with a wrong tag (or raw garbage) is
// dropped; only a correctly-tagged register is accepted.
func TestScannerCannotRegister(t *testing.T) {
	port := freeUDPPort(t)
	key := wire.KeyFromPSK("the-real-psk")
	pc, err := cipher.NewPacket("none", key)
	if err != nil {
		t.Fatal(err)
	}
	uc, err := bindUDP(context.Background(), "", ":"+itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	lo := &udpListenOut{name: "down", conn: uc, cipher: pc, key: key, multiple: true, reg: peers.New(true, time.Minute, 0)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := lo.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	defer lo.Close()

	send := func(b []byte) {
		conn, err := net.Dial("udp", "127.0.0.1:"+itoa(port))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = conn.Write(b)
	}

	victim := wire.Owner{9, 9, 9, 9}
	// (a) raw garbage — not even control-shaped.
	send([]byte("not a control datagram at all"))
	// (b) a register claiming the victim owner, tagged with the WRONG key.
	send(encodeControl(proto.MsgRegister, victim, 0, 1, wire.KeyFromPSK("attacker-guess")))
	// (c) a correctly-shaped register body but a zeroed tag.
	forged := encodeControl(proto.MsgRegister, victim, 0, 2, key)
	for i := len(forged) - 8; i < len(forged); i++ {
		forged[i] = 0
	}
	send(forged)

	// Give the read loop time to process; the spoofed owner must never become routable.
	deadline := time.After(2 * time.Second)
	for {
		if lo.Accepts(victim) {
			t.Fatal("scanner registered a peer without the PSK — auth boundary broken")
		}
		select {
		case <-deadline:
			goto legit
		case <-time.After(50 * time.Millisecond):
		}
	}
legit:
	// A correctly-tagged register from a legitimate peer IS accepted (the listener still works).
	send(encodeControl(proto.MsgRegister, victim, 0, 3, key))
	ok := false
	for i := 0; i < 40 && !ok; i++ {
		ok = lo.Accepts(victim)
		time.Sleep(25 * time.Millisecond)
	}
	if !ok {
		t.Fatal("a correctly-tagged register was not accepted (listener broken)")
	}
}

// TestControlReplayGetsNoReply proves the anti-replay wiring end to end over live sockets: a single-mode
// listen-out replies MsgPong to a fresh, correctly-tagged register, but a verbatim REPLAY of that
// same datagram (identical bytes → identical valid tag) from a different source is rejected on
// freshness and draws NO reply — so a captured control datagram cannot re-bind the return path.
func TestControlReplayGetsNoReply(t *testing.T) {
	port := freeUDPPort(t)
	key := wire.KeyFromPSK("the-real-psk")
	pc, _ := cipher.NewPacket("none", key)
	uc, err := bindUDP(context.Background(), "", ":"+itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	lo := &udpListenOut{name: "down", conn: uc, cipher: pc, key: key, multiple: false, reg: peers.New(false, time.Minute, 0)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := lo.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	defer lo.Close()

	// Capture a valid register (as an on-path observer would) and send it from a legit socket.
	datagram := encodeControl(proto.MsgRegister, wire.Owner{}, 0, 12345, key)
	legit, _ := net.Dial("udp", "127.0.0.1:"+itoa(port))
	defer legit.Close()
	_, _ = legit.Write(datagram)
	_ = legit.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if n, err := legit.Read(buf); err != nil || n < 1 || buf[0] != proto.MsgPong {
		t.Fatalf("fresh register should draw a MsgPong: n=%d err=%v", n, err)
	}

	// Replay the exact same bytes from the attacker's socket — must be rejected (no reply).
	attacker, _ := net.Dial("udp", "127.0.0.1:"+itoa(port))
	defer attacker.Close()
	_, _ = attacker.Write(datagram)
	_ = attacker.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, err := attacker.Read(buf); err == nil && n >= 1 {
		t.Fatalf("replayed (stale) control drew a reply (%d bytes) — anti-replay not enforced", n)
	}
}

// TestWrongPSKDataIsDropped proves the wrong-key tripwire: a data packet sealed under one PSK,
// delivered to a receiver keyed with a different PSK, is de-obfuscated to garbage and fails the
// PlausibleIP tripwire, so onDrop fires and it is not handed to ingress. Spans cipher +
// wire.PlausibleIP + the udpListenIn receive path.
//
// The data plane is unauthenticated by design (see AGENTS.md), so PlausibleIP is a statistical
// tripwire, not a cryptographic gate: garbage passes only when its first de-obfuscated byte
// happens to look like an IP version nibble (~1 in 8 of uniformly random bytes). We therefore
// send many packets and assert the tripwire rejects the overwhelming majority — a single-packet
// "delivered==0" assertion would be ~1/8 flaky. Even a packet that slips through carries a
// garbage owner and routes nowhere.
func TestWrongPSKDataIsDropped(t *testing.T) {
	port := freeUDPPort(t)
	recvKey := wire.KeyFromPSK("receiver-psk")
	recvCipher, _ := cipher.NewPacket("chacha4", recvKey)
	uc, err := bindUDP(context.Background(), "", ":"+itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	var delivered, drops atomic.Int64
	li := &udpListenIn{name: "in", conn: uc, cipher: recvCipher, onDrop: func() { drops.Add(1) }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = li.Start(ctx, func(string, wire.Envelope, []byte) { delivered.Add(1) })
	defer li.Close()

	// Attacker/mismatched sender seals a perfectly valid inner packet under the WRONG key. Each
	// Seal draws a fresh random nonce, so the receiver de-obfuscates each to independent garbage.
	senderCipher, _ := cipher.NewPacket("chacha4", wire.KeyFromPSK("sender-psk"))
	inner := make([]byte, 40)
	inner[0] = 0x45
	inner[9] = 6

	conn, _ := net.Dial("udp", "127.0.0.1:"+itoa(port))
	defer conn.Close()
	const sent = 512
	for i := 0; i < sent; i++ {
		blob := wire.PutEnvelope(nil, wire.Envelope{Owner: wire.Owner{1}}, inner)
		sealed, _ := senderCipher.Seal(nil, blob)
		_, _ = conn.Write(sealed)
	}

	// Wait for the receiver to account for a solid sample (loopback may drop a few under burst).
	deadline := time.Now().Add(3 * time.Second)
	var recv int64
	for time.Now().Before(deadline) {
		recv = delivered.Load() + drops.Load()
		if recv >= sent {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if recv < sent/2 {
		t.Fatalf("receiver only accounted for %d/%d packets — stalled?", recv, sent)
	}
	if drops.Load() == 0 {
		t.Fatal("no wrong-PSK packet was dropped — the tripwire never fired")
	}
	// Expected pass rate on random garbage is ~1/8; anything near half means the tripwire is
	// effectively off. This bound is ~12 std devs above the mean, so it is not flaky.
	if got := delivered.Load(); got*4 >= recv {
		t.Fatalf("tripwire too weak: %d/%d wrong-PSK packets slipped through (want well under 25%%)", got, recv)
	}
}
