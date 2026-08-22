package cipher

import "io"

// noneStream is an identity StreamCipher: no nonce prefix, no transformation.
// Selectable for debugging; it strips all obfuscation and is wire-incompatible
// with an xor peer. Do not use it on the censored uplink.
type noneStream struct{}

func (noneStream) Authenticated() bool                       { return false }
func (noneStream) WrapWriter(w io.Writer) (io.Writer, error) { return w, nil }
func (noneStream) WrapReader(r io.Reader) (io.Reader, error) { return r, nil }

// nonePacket is an identity PacketCipher: the payload is the datagram.
type nonePacket struct{}

func (nonePacket) Authenticated() bool { return false }
func (nonePacket) Overhead() int       { return 0 }

func (nonePacket) Seal(dst, payload []byte) ([]byte, error) {
	if cap(dst) < len(payload) {
		dst = make([]byte, len(payload))
	}
	dst = dst[:len(payload)]
	copy(dst, payload)
	return dst, nil
}

// SealInPlace is a no-op for the identity cipher: Overhead is 0, so region is the body
// itself and there is no nonce to write nor keystream to apply.
func (nonePacket) SealInPlace([]byte) error { return nil }

func (nonePacket) Open(datagram []byte) ([]byte, error) { return datagram, nil }
