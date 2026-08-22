package conn

import (
	"testing"

	"github.com/arash16/dualnet/internal/proto"
	"github.com/arash16/dualnet/internal/wire"
)

// TestDecodeControl covers that decodeControl is the sole anti-spoof gate that stops an
// internet scanner from registering a fake peer on a Multiple udpListenOut. Only its happy
// path was exercised (indirectly, via the mesh test); its length gate, tag-offset slicing,
// and rejection branches had no direct coverage. A regression here (dropping the exact-length
// check, an off-by-one in the tag split, or accepting on tag mismatch) would let unauthenticated
// datagrams mint/refresh peers.
func TestDecodeControl(t *testing.T) {
	key := wire.KeyFromPSK("a-shared-secret")
	id := wire.Owner{1, 2, 3, 4}

	// Happy path: a valid datagram round-trips, carrying the freshness timestamp.
	good := encodeControl(proto.MsgRegister, id, 0x07, 0xdeadbeef, key)
	if len(good) != controlLen {
		t.Fatalf("encodeControl length = %d, want %d", len(good), controlLen)
	}
	typ, gotID, flags, ts, err := decodeControl(good, key)
	if err != nil {
		t.Fatalf("valid datagram rejected: %v", err)
	}
	if typ != proto.MsgRegister || gotID != id || flags != 0x07 || ts != 0xdeadbeef {
		t.Fatalf("decoded typ=%#x id=%v flags=%#x ts=%#x, want %#x/%v/0x07/0xdeadbeef", typ, gotID, flags, ts, proto.MsgRegister, id)
	}

	// Wrong length: one byte short and one byte long must both be rejected (no panic on the slice).
	if _, _, _, _, err := decodeControl(good[:controlLen-1], key); err == nil {
		t.Fatal("truncated datagram accepted")
	}
	if _, _, _, _, err := decodeControl(append(append([]byte(nil), good...), 0x00), key); err == nil {
		t.Fatal("over-long datagram accepted")
	}
	if _, _, _, _, err := decodeControl(nil, key); err == nil {
		t.Fatal("empty datagram accepted")
	}

	// Flipped tag byte: authentication must fail.
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 0xff
	if _, _, _, _, err := decodeControl(tampered, key); err == nil {
		t.Fatal("datagram with a corrupted tag accepted")
	}

	// Flipped body byte (the id) without recomputing the tag: must fail.
	body := append([]byte(nil), good...)
	body[1] ^= 0xff
	if _, _, _, _, err := decodeControl(body, key); err == nil {
		t.Fatal("datagram with a tampered body but stale tag accepted")
	}

	// Flipped timestamp byte without recomputing the tag: must fail (ts is covered by the tag).
	tsFlip := append([]byte(nil), good...)
	tsFlip[1+wire.OwnerLen+1] ^= 0xff
	if _, _, _, _, err := decodeControl(tsFlip, key); err == nil {
		t.Fatal("datagram with a tampered timestamp but stale tag accepted")
	}

	// Wrong key: a datagram authenticated under a different PSK must be rejected.
	if _, _, _, _, err := decodeControl(good, wire.KeyFromPSK("different-secret")); err == nil {
		t.Fatal("datagram accepted under the wrong key (peer spoofable)")
	}
}
