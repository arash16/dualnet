package wire

import (
	"crypto/hmac"
	"crypto/sha256"
)

// KeyFromPSK derives a 32-byte obfuscation/tag key from the user's pre-shared
// key. The PSK is a shared secret, so a plain hash is sufficient here.
func KeyFromPSK(psk string) [32]byte {
	return sha256.Sum256([]byte("dualnet:v1:" + psk))
}

// Tag returns the first 8 bytes of HMAC-SHA256(key, msg). It is used to make
// control datagrams (register/keepalive) non-trivial to spoof by internet
// scanners. It is a lightweight integrity check, not strong authentication.
func Tag(key [32]byte, msg []byte) [8]byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write(msg)
	sum := mac.Sum(nil)
	var out [8]byte
	copy(out[:], sum[:8])
	return out
}

// VerifyTag reports whether tag matches Tag(key, msg) in constant time.
func VerifyTag(key [32]byte, msg []byte, tag [8]byte) bool {
	want := Tag(key, msg)
	return hmac.Equal(want[:], tag[:])
}
