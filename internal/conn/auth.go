package conn

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/arash16/dualnet/internal/wire"
)

// Authenticated tokens for the HTTP download carrier's control headers. The UDP carrier
// authenticates peer registration and id-assignment with an HMAC tag over the control datagram
// (see control.go); the HTTP carrier's registration (the download GET) and id-assignment (the
// response header) ride in plaintext HTTP headers, so without this an off-path client could
// register/hijack a downlink and a MITM could force a peer to adopt an attacker-chosen owner.
//
// A token is hex(ts:8 || tag:8), tag = wire.Tag(psk, domain || id || ts). The domain string
// separates the two uses so a registration token can't be replayed as an id-assignment (or vice
// versa); ts is a freshness stamp the verifier uses to reject replays.
const (
	authDomainReg    = "dn-http-reg" // client → server: "I hold the PSK, register me under this id"
	authDomainAssign = "dn-http-id"  // server → client: "the PSK-holder assigns you this id"
	authTokenLen     = 8 + 8         // ts || tag
)

func authMsg(domain string, id wire.Owner, ts uint64) []byte {
	msg := make([]byte, 0, len(domain)+wire.OwnerLen+8)
	msg = append(msg, domain...)
	msg = append(msg, id[:]...)
	return binary.BigEndian.AppendUint64(msg, ts)
}

// authToken builds the hex header value proving PSK knowledge over (domain, id, ts).
func authToken(key [32]byte, domain string, id wire.Owner, ts uint64) string {
	tag := wire.Tag(key, authMsg(domain, id, ts))
	out := make([]byte, authTokenLen)
	binary.BigEndian.PutUint64(out[:8], ts)
	copy(out[8:], tag[:])
	return hex.EncodeToString(out)
}

// verifyAuthToken checks a hex token for (domain, id) and returns its freshness stamp. ok is
// false on any decode/length/tag mismatch — i.e. the presenter did not hold the PSK.
func verifyAuthToken(key [32]byte, domain string, id wire.Owner, hexTok string) (ts uint64, ok bool) {
	raw, err := hex.DecodeString(hexTok)
	if err != nil || len(raw) != authTokenLen {
		return 0, false
	}
	ts = binary.BigEndian.Uint64(raw[:8])
	var tag [8]byte
	copy(tag[:], raw[8:])
	if !wire.VerifyTag(key, authMsg(domain, id, ts), tag) {
		return 0, false
	}
	return ts, true
}

// sigHeaderName derives the auth header name from the (shared) id header, so both ends agree
// without extra configuration. E.g. "X-Upload-Tag" → "X-Upload-Tag-Sig".
func sigHeaderName(idHeader string) string { return idHeader + "-Sig" }
