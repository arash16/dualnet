// Package wire holds dualnet's transport-agnostic wire helpers: length-prefixed
// packet framing for stream carriers, PSK-based key derivation and a short keyed
// tag for authenticating control datagrams, and inner-IP parsing helpers.
//
// Obfuscation/encryption of the framed bytes is a separate, pluggable concern in
// package cipher; this package is about structure, not secrecy.
package wire

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MaxPacket is the largest single packet (inner IP datagram) we frame. The
// tunnel MTU is well below this; the u16 length prefix caps us at 65535 anyway.
const MaxPacket = 65535

// FrameWriter is implemented by stream writers that can length-prefix and emit a frame
// in a single operation using their own reused scratch. WriteFrame delegates to it when
// available. The generic io.Writer path below cannot: a 2-byte length header written to
// an interface escapes to the heap, one allocation per packet. Stream ciphers implement
// this so the steady-state packet send path stays allocation-free.
type FrameWriter interface {
	// WriteFrame length-prefixes p and writes it as one frame. len(p) is guaranteed
	// <= MaxPacket (WriteFrame checks before delegating).
	WriteFrame(p []byte) error
}

// WriteFrame writes p to w as a big-endian uint16 length followed by the bytes.
func WriteFrame(w io.Writer, p []byte) error {
	if len(p) > MaxPacket {
		return fmt.Errorf("wire: packet too large (%d > %d)", len(p), MaxPacket)
	}
	if fw, ok := w.(FrameWriter); ok {
		return fw.WriteFrame(p)
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

// FrameReader is implemented by stream readers that can read a whole length-prefixed frame in
// one operation. ReadFrame delegates to it when available, so a reader that obfuscates only part
// of each frame (partial obfuscation) can XOR exactly the span its writer did — the generic
// io.Reader path below cannot, because it would de-obfuscate the length and payload as separate
// undelimited reads and could not stop the keystream at the frame's obfuscated prefix.
type FrameReader interface {
	// ReadFrame reads one frame into buf and returns its length. len(buf) must be >= MaxPacket.
	ReadFrame(buf []byte) (int, error)
}

// ReadFrame reads one length-prefixed frame from r into buf and returns its length. buf
// must be large enough to hold the frame (>= MaxPacket to be safe); otherwise
// io.ErrShortBuffer is returned. The 2-byte length header is read into the head of buf
// (then overwritten by the payload) rather than a local array, so a hot receive loop
// reusing buf allocates nothing per frame.
func ReadFrame(r io.Reader, buf []byte) (int, error) {
	if fr, ok := r.(FrameReader); ok {
		return fr.ReadFrame(buf)
	}
	if len(buf) < 2 {
		return 0, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(buf[:2]))
	if n > len(buf) {
		return 0, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}
