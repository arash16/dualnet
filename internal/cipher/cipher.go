// Package cipher provides dualnet's pluggable wire obfuscation/encryption,
// decoupled from the transports that use it. Two shapes are offered because the
// two transport families need different things:
//
//   - StreamCipher transforms a continuous, ordered byte stream (used by stream
//     channels such as the HTTP carrier). It owns its own handshake prefix (e.g.
//     a nonce emitted at stream start) so channels stay oblivious to it.
//   - PacketCipher seals/opens independent datagrams that may be lost or
//     reordered (used by datagram channels such as the UDP carrier). Each sealed
//     datagram is self-describing (it carries its own nonce).
//
// A channel's stream-vs-datagram nature fixes which shape it needs; the concrete
// cipher (chacha4, none) is selected by name via NewStream/NewPacket. An unset
// name selects none — raw, unencrypted transfer — so chacha4 is only ever used
// when explicitly requested.
//
// Security note: "chacha4" is a reduced-round ChaCha keystream XOR (see
// chacha4.go) — obfuscation to defeat content DPI, not authenticated
// encryption. Authenticated() reports false for it, so channels keep their
// wrong-key tripwires. Control-datagram authentication (the HMAC tag) is a
// separate concern and lives in package wire.
package cipher

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// minObfsHead is the smallest partial-obfuscation length "chacha4:N" accepts. It guarantees
// the tunnel envelope ([owner:4][flags:1]) and the first bytes of the inner IP header are always
// under the keystream, so the routing header is never exposed and the wrong-key tripwire still
// sees garbage in the version nibble.
const minObfsHead = 16

// ParseName splits a cipher selector into its base name and optional partial-obfuscation head
// length. "chacha4" → ("chacha4", 0) meaning obfuscate the whole payload; "chacha4:256" →
// ("chacha4", 256) meaning obfuscate only the first 256 bytes (see NewPacket). "none"/"" →
// ("none", 0). A malformed selector, unknown base, or out-of-range head is an error.
func ParseName(name string) (base string, head int, err error) {
	base, rest, hasHead := strings.Cut(name, ":")
	switch base {
	case "", "none":
		if hasHead {
			return "", 0, fmt.Errorf("cipher: %q takes no :head", name)
		}
		return "none", 0, nil
	case "chacha4":
	default:
		return "", 0, fmt.Errorf("cipher: unknown cipher %q", name)
	}
	if !hasHead {
		return "chacha4", 0, nil
	}
	head, err = strconv.Atoi(rest)
	if err != nil || head < minObfsHead {
		return "", 0, fmt.Errorf("cipher: %q: head must be an integer >= %d", name, minObfsHead)
	}
	return "chacha4", head, nil
}

// StreamCipher obfuscates a continuous byte stream.
type StreamCipher interface {
	// WrapWriter returns a writer that obfuscates everything written to it,
	// emitting any handshake prefix (nonce) to w first.
	WrapWriter(w io.Writer) (io.Writer, error)
	// WrapReader returns a reader that de-obfuscates r, consuming the handshake
	// prefix first. Pair with a WrapWriter on the far end.
	WrapReader(r io.Reader) (io.Reader, error)
	// Authenticated reports whether the cipher provides integrity. False for
	// chacha4/none, so callers keep any plausibility tripwire against a wrong key.
	Authenticated() bool
}

// PacketCipher seals/opens independent datagrams. Implementations own any nonce
// state and MUST be safe for concurrent Seal.
type PacketCipher interface {
	// Overhead is the number of bytes Seal adds to a payload (nonce [+ tag]).
	Overhead() int
	// Seal writes the sealed form (nonce || ciphertext) into dst and returns the
	// written slice. dst is grown/allocated if it lacks room for
	// Overhead()+len(payload) bytes; pass a buffer with that capacity for a
	// zero-allocation path.
	Seal(dst, payload []byte) ([]byte, error)
	// SealInPlace seals a datagram whose plaintext body is already positioned at
	// region[Overhead():]: it writes the nonce into region[:Overhead()] and XORs the
	// body with the keystream in place, producing the same nonce||ciphertext bytes as
	// Seal but without a second buffer. The caller lays the buffer out as
	// [any prefix][nonce (Overhead bytes)][plaintext body] and passes the sub-slice
	// starting at the nonce. len(region) must be >= Overhead().
	SealInPlace(region []byte) error
	// Open reverses Seal in place and returns the payload slice (aliasing
	// datagram's backing array).
	Open(datagram []byte) ([]byte, error)
	// Authenticated reports whether the cipher provides integrity.
	Authenticated() bool
}

// NewStream builds a StreamCipher by name. "" and "none" select an identity
// passthrough (raw, unencrypted; wire-incompatible with a chacha4 peer);
// "chacha4" selects the reduced-round ChaCha keystream obfuscator over the whole
// frame; "chacha4:N" obfuscates each frame's 2-byte length prefix plus the first N
// payload bytes and leaves the tail in cleartext — the same CPU saving the packet
// cipher gets, for the stream (tcp/http) carriers. It stays safe for a covert stream
// because the frame length and the inner headers (envelope + inner IP/TCP/TLS record)
// remain under the keystream and the cleartext tail is inner ciphertext (high-entropy).
func NewStream(name string, key [32]byte) (StreamCipher, error) {
	base, head, err := ParseName(name)
	if err != nil {
		return nil, err
	}
	switch base {
	case "none":
		return noneStream{}, nil
	default: // chacha4
		return newChacha4Stream(key, head), nil
	}
}

// NewPacket builds a PacketCipher by name. "" and "none" select an identity
// passthrough (raw, unencrypted); "chacha4" selects the per-datagram
// reduced-round ChaCha keystream obfuscator over the whole payload; "chacha4:N"
// obfuscates only the first N bytes of each datagram's payload and leaves the tail
// in cleartext — far less per-packet CPU when the tail is already high-entropy
// (e.g. TLS ciphertext) and only the header region needs to be hidden from DPI.
func NewPacket(name string, key [32]byte) (PacketCipher, error) {
	base, head, err := ParseName(name)
	if err != nil {
		return nil, err
	}
	switch base {
	case "none":
		return nonePacket{}, nil
	default: // chacha4
		return newChacha4Packet(key, head), nil
	}
}
