package cipher

import (
	"encoding/binary"
	"io"
	"math/bits"
	mrand "math/rand/v2"
)

// chacha4 is dualnet's obfuscation cipher: a ChaCha keystream XOR with 2
// double-rounds (4 rounds) instead of ChaCha20's 10 (20 rounds). It exists
// purely to keep DPI content-matching blind, not to resist a targeted
// cryptanalytic adversary — dualnet is a single-operator protocol with no
// live deployment yet, so there's no wire-compat reason to carry ChaCha20's
// cryptanalytic margin, only its CPU cost. golang.org/x/crypto/chacha20 has
// no ARM32 assembly and no configurable round count, so this is a small
// hand-rolled core rather than a parameter on that package.
//
// Why 4 rounds and not fewer or more: chacha4_test.go's avalanche test found
// no gross diffusion failure even at 4 rounds (or 2, informally) — the real
// ceiling on how low to go isn't diffusion, it's published cryptanalysis.
// Aumasson/Fischer/Khazaei/Meier/Rechberger ("New Features of Latin Dances",
// 2008) broke ChaCha6 at ~2^139 work and ChaCha7 at ~2^248 — both fully
// infeasible, and no attack on ChaCha4 specifically changes the calculus here
// since none of these figures matter for an obfuscation-only, single-user
// protocol. 4 rounds won a direct benchmark against 6 and 8 rounds (roughly
// 1.4x and 1.6x faster respectively at 1280B, natively and cross-compiled to
// this project's ARMv7 target) with no measured downside for this use case.
//
// The block function is deliberately built like x/crypto's own pure-Go
// fallback (chacha_generic.go's xorKeyStreamBlocksGeneric, which is what
// actually runs on 32-bit ARM — chacha_noasm.go selects it there, there being
// no arm32 assembly): named scalar state words, not an indexed array, and the
// three counter-independent quarter-rounds of the first round precomputed once
// per cipher instead of redone every block. A first attempt at this file used
// a [16]uint32 array threaded through the round function by pointer and
// benchmarked ~4x *slower* than ChaCha20 despite doing less arithmetic —
// taking the array's address defeats the compiler's ability to keep the words
// in registers across calls, which costs far more than fewer rounds saves.
// Uses a 12-byte IETF-shaped nonce — no XChaCha/HChaCha20 subkey derivation,
// since a random 12-byte nonce is already far past the collision bar this needs.
//
// Nonce generation uses math/rand/v2's top-level functions (not crypto/rand):
// since Go 1.20 the global source is auto-seeded from OS entropy at process
// start and is non-reproducible from outside, so it costs nothing we need
// here — no syscall per call, unlike crypto/rand.Read. (Tried backing the
// keystream itself with math/rand/v2.ChaCha8 too — it lost on both counts,
// slower than this and the only variant that allocates, because its internal
// design is a long-lived generator, not a "construct fresh, get N bytes,
// discard" per-packet source.) The nonce still has to be *unique per stream/
// packet* though, not for confidentiality margin but because reusing a
// keystream (same key+nonce twice) XORs two plaintexts together, which leaks
// visible structure — precisely the failure mode a DPI obfuscator can't afford.
const chachaDoubleRounds = 2 // 4 rounds total
const chachaNonceLen = 12
const chachaBlockSize = 64

const (
	chachaConst0 uint32 = 0x61707865 // "expa"
	chachaConst1 uint32 = 0x3320646e // "nd 3"
	chachaConst2 uint32 = 0x79622d32 // "2-by"
	chachaConst3 uint32 = 0x6b206574 // "te k"
)

func chachaQR(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)
	return a, b, c, d
}

// chachaAddXor reads a little-endian uint32 from src, XORs it with the keystream word (a+b),
// and writes the little-endian result to dst as a single word load/store — faster than four
// byte-wise shifts-and-stores on any 32/64-bit target.
func chachaAddXor(dst, src []byte, a, b uint32) {
	binary.LittleEndian.PutUint32(dst, binary.LittleEndian.Uint32(src)^(a+b))
}

// chacha4Cipher is a minimal reduced-round keystream generator with the same
// call contract as golang.org/x/crypto/chacha20.Cipher: XORKeyStream may be
// called repeatedly with any chunk sizes and the keystream continues
// seamlessly across calls.
type chacha4Cipher struct {
	key     [8]uint32
	nonce   [3]uint32
	counter uint32

	buf [chachaBlockSize]byte
	len int // leftover keystream bytes at the tail of buf

	precompDone      bool
	p1, p5, p9, p13  uint32
	p2, p6, p10, p14 uint32
	p3, p7, p11, p15 uint32
}

func newChacha4Cipher(key [32]byte, nonce []byte) *chacha4Cipher {
	c := &chacha4Cipher{}
	for i := 0; i < 8; i++ {
		c.key[i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	for i := 0; i < 3; i++ {
		c.nonce[i] = binary.LittleEndian.Uint32(nonce[i*4:])
	}
	return c
}

// block generates keystream for len(src) (a multiple of chachaBlockSize)
// bytes, XORs it with src, and writes the result to dst.
func (c *chacha4Cipher) block(dst, src []byte) {
	var (
		c0, c1, c2, c3   = chachaConst0, chachaConst1, chachaConst2, chachaConst3
		c4, c5, c6, c7   = c.key[0], c.key[1], c.key[2], c.key[3]
		c8, c9, c10, c11 = c.key[4], c.key[5], c.key[6], c.key[7]
		_, c13, c14, c15 = c.counter, c.nonce[0], c.nonce[1], c.nonce[2]
	)

	// Three quarters of the first round don't depend on the counter, so they
	// can be computed once and reused for every block this cipher ever emits.
	if !c.precompDone {
		c.p1, c.p5, c.p9, c.p13 = chachaQR(c1, c5, c9, c13)
		c.p2, c.p6, c.p10, c.p14 = chachaQR(c2, c6, c10, c14)
		c.p3, c.p7, c.p11, c.p15 = chachaQR(c3, c7, c11, c15)
		c.precompDone = true
	}

	for len(src) >= chachaBlockSize && len(dst) >= chachaBlockSize {
		// The remainder of the first column round, then the first diagonal round.
		fcr0, fcr4, fcr8, fcr12 := chachaQR(c0, c4, c8, c.counter)
		x0, x5, x10, x15 := chachaQR(fcr0, c.p5, c.p10, c.p15)
		x1, x6, x11, x12 := chachaQR(c.p1, c.p6, c.p11, fcr12)
		x2, x7, x8, x13 := chachaQR(c.p2, c.p7, fcr8, c.p13)
		x3, x4, x9, x14 := chachaQR(c.p3, fcr4, c.p9, c.p14)

		// The remaining rounds (chachaDoubleRounds-1 double-rounds).
		for i := 0; i < chachaDoubleRounds-1; i++ {
			x0, x4, x8, x12 = chachaQR(x0, x4, x8, x12)
			x1, x5, x9, x13 = chachaQR(x1, x5, x9, x13)
			x2, x6, x10, x14 = chachaQR(x2, x6, x10, x14)
			x3, x7, x11, x15 = chachaQR(x3, x7, x11, x15)

			x0, x5, x10, x15 = chachaQR(x0, x5, x10, x15)
			x1, x6, x11, x12 = chachaQR(x1, x6, x11, x12)
			x2, x7, x8, x13 = chachaQR(x2, x7, x8, x13)
			x3, x4, x9, x14 = chachaQR(x3, x4, x9, x14)
		}

		chachaAddXor(dst[0:4], src[0:4], x0, c0)
		chachaAddXor(dst[4:8], src[4:8], x1, c1)
		chachaAddXor(dst[8:12], src[8:12], x2, c2)
		chachaAddXor(dst[12:16], src[12:16], x3, c3)
		chachaAddXor(dst[16:20], src[16:20], x4, c4)
		chachaAddXor(dst[20:24], src[20:24], x5, c5)
		chachaAddXor(dst[24:28], src[24:28], x6, c6)
		chachaAddXor(dst[28:32], src[28:32], x7, c7)
		chachaAddXor(dst[32:36], src[32:36], x8, c8)
		chachaAddXor(dst[36:40], src[36:40], x9, c9)
		chachaAddXor(dst[40:44], src[40:44], x10, c10)
		chachaAddXor(dst[44:48], src[44:48], x11, c11)
		chachaAddXor(dst[48:52], src[48:52], x12, c.counter)
		chachaAddXor(dst[52:56], src[52:56], x13, c13)
		chachaAddXor(dst[56:60], src[56:60], x14, c14)
		chachaAddXor(dst[60:64], src[60:64], x15, c15)

		c.counter++
		src, dst = src[chachaBlockSize:], dst[chachaBlockSize:]
	}
}

func (c *chacha4Cipher) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	dst = dst[:len(src)]

	if c.len != 0 {
		keyStream := c.buf[chachaBlockSize-c.len:]
		if len(src) < len(keyStream) {
			keyStream = keyStream[:len(src)]
		}
		for i, b := range keyStream {
			dst[i] = src[i] ^ b
		}
		c.len -= len(keyStream)
		dst, src = dst[len(keyStream):], src[len(keyStream):]
	}
	if len(src) == 0 {
		return
	}

	full := len(src) - len(src)%chachaBlockSize
	if full > 0 {
		c.block(dst[:full], src[:full])
	}
	dst, src = dst[full:], src[full:]

	if len(src) > 0 {
		c.buf = [chachaBlockSize]byte{}
		copy(c.buf[:], src)
		c.block(c.buf[:], c.buf[:])
		c.len = chachaBlockSize - copy(dst, c.buf[:])
	}
}

// mrandNonce fills nonce (chachaNonceLen bytes) via math/rand/v2's top-level
// generator instead of crypto/rand — see the package-level doc comment above
// for why that's fine here.
func mrandNonce(nonce []byte) {
	binary.LittleEndian.PutUint64(nonce[0:8], mrand.Uint64())
	binary.LittleEndian.PutUint32(nonce[8:12], mrand.Uint32())
}

// --- Stream (ChaCha4 keystream XOR over an ordered byte stream) ------------

type chacha4Stream struct {
	key  [32]byte
	head int // if >0, obfuscate only the first head bytes of each frame's payload; 0 = whole payload
}

func newChacha4Stream(key [32]byte, head int) chacha4Stream {
	return chacha4Stream{key: key, head: head}
}

func (x chacha4Stream) Authenticated() bool { return false }

func (x chacha4Stream) WrapWriter(w io.Writer) (io.Writer, error) {
	nonce := make([]byte, chachaNonceLen)
	mrandNonce(nonce)
	if _, err := w.Write(nonce); err != nil {
		return nil, err
	}
	return &chacha4Writer{w: w, c: newChacha4Cipher(x.key, nonce), head: x.head}, nil
}

func (x chacha4Stream) WrapReader(r io.Reader) (io.Reader, error) {
	nonce := make([]byte, chachaNonceLen)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}
	return &chacha4Reader{r: r, c: newChacha4Cipher(x.key, nonce), head: x.head}, nil
}

// streamObfsLen is how many of a frame's n payload bytes are XORed: the whole payload unless a
// head limit is set and shorter. The 2-byte length prefix is always XORed on top of this, so a
// reader and writer with the same head consume the same amount of keystream per frame and stay
// in sync; the payload tail beyond head rides in cleartext (its inner traffic — e.g. TLS
// ciphertext — is already high-entropy). head 0 means the whole payload (identical to the
// previous full-stream behavior and wire-compatible with it).
func streamObfsLen(head, n int) int {
	if head > 0 && head < n {
		return head
	}
	return n
}

type chacha4Writer struct {
	w    io.Writer
	c    *chacha4Cipher
	buf  []byte
	head int
}

func (o *chacha4Writer) Write(p []byte) (int, error) {
	if cap(o.buf) < len(p) {
		o.buf = make([]byte, len(p))
	}
	dst := o.buf[:len(p)]
	o.c.XORKeyStream(dst, p)
	n, err := o.w.Write(dst)
	if err != nil && n < len(p) {
		// Partial writes desync the stream cipher; treat as fatal.
		return n, err
	}
	return len(p), err
}

// WriteFrame implements wire.FrameWriter: it length-prefixes p and XORs the 2-byte header plus
// the first streamObfsLen(head, len(p)) payload bytes into the reused scratch (leaving any tail
// beyond head in cleartext), then writes the whole frame in one call. This keeps the send path
// allocation-free — the generic wire.WriteFrame path escapes a per-call [2]byte header — and
// halves the underlying writes. The keystream is position-based; a reader with the same head
// consumes the same span and decodes identically. len(p) is validated <= MaxPacket by
// wire.WriteFrame before it delegates here.
func (o *chacha4Writer) WriteFrame(p []byte) error {
	need := 2 + len(p)
	if cap(o.buf) < need {
		o.buf = make([]byte, need)
	}
	dst := o.buf[:need]
	binary.BigEndian.PutUint16(dst[:2], uint16(len(p)))
	o.c.XORKeyStream(dst[:2], dst[:2])
	m := streamObfsLen(o.head, len(p))
	o.c.XORKeyStream(dst[2:2+m], p[:m])
	copy(dst[2+m:], p[m:]) // cleartext tail (no-op when m == len(p))
	n, err := o.w.Write(dst)
	if err != nil && n < need {
		// Partial writes desync the stream cipher; treat as fatal.
		return err
	}
	return err
}

type chacha4Reader struct {
	r    io.Reader
	c    *chacha4Cipher
	head int
}

func (o *chacha4Reader) Read(p []byte) (int, error) {
	n, err := o.r.Read(p)
	if n > 0 {
		o.c.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// ReadFrame implements wire.FrameReader, the counterpart to WriteFrame: it reads one length-
// prefixed frame from the underlying stream, XORs the length and the first streamObfsLen(head, n)
// payload bytes, and leaves the tail as-is. It reads raw from o.r (not through Read) so the
// keystream advances by exactly the obfuscated span — the same amount WriteFrame consumed — and
// the two directions stay in sync under partial obfuscation. buf must be >= MaxPacket.
func (o *chacha4Reader) ReadFrame(buf []byte) (int, error) {
	if len(buf) < 2 {
		return 0, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(o.r, buf[:2]); err != nil {
		return 0, err
	}
	o.c.XORKeyStream(buf[:2], buf[:2])
	n := int(binary.BigEndian.Uint16(buf[:2]))
	if n > len(buf) {
		return 0, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(o.r, buf[:n]); err != nil {
		return 0, err
	}
	m := streamObfsLen(o.head, n)
	o.c.XORKeyStream(buf[:m], buf[:m])
	return n, nil
}

// --- Packet (per-datagram ChaCha4 keystream XOR) ---------------------------

// chacha4Packet draws a fresh, fully-random 12-byte nonce for every datagram (the nonce is
// carried in the sealed output, so the peer needs no shared counter). A random nonce — not a
// per-instance prefix plus a from-zero counter — is what the package doc claims and what the
// obfuscation needs: two datagrams (whether from one instance or two instances sharing the
// PSK-derived key) collide their keystream only on a full 96-bit nonce collision, a birthday
// bound far past anything this reaches, rather than on a mere 32-bit prefix collision.
// Stateless, so Seal is naturally safe for concurrent use with no lock.
type chacha4Packet struct {
	key  [32]byte
	head int // if >0, obfuscate only the first head bytes of the payload; 0 = whole payload
}

func newChacha4Packet(key [32]byte, head int) *chacha4Packet {
	return &chacha4Packet{key: key, head: head}
}

func (p *chacha4Packet) Authenticated() bool { return false }

func (p *chacha4Packet) Overhead() int { return chachaNonceLen }

// obfsLen is how many leading bytes of a body of length n are XORed: the whole body unless a
// head limit is set and shorter. A random nonce still covers every datagram, so even a body
// shorter than head reuses no keystream. Both ends derive the same span from the same head, so
// the receiver de-obfuscates exactly the range the sender obfuscated.
func (p *chacha4Packet) obfsLen(n int) int {
	if p.head > 0 && p.head < n {
		return p.head
	}
	return n
}

func (p *chacha4Packet) Seal(dst, payload []byte) ([]byte, error) {
	need := chachaNonceLen + len(payload)
	if cap(dst) < need {
		dst = make([]byte, need)
	}
	dst = dst[:need]

	mrandNonce(dst[:chachaNonceLen])
	n := p.obfsLen(len(payload))
	c := newChacha4Cipher(p.key, dst[:chachaNonceLen])
	c.XORKeyStream(dst[chachaNonceLen:chachaNonceLen+n], payload[:n])
	copy(dst[chachaNonceLen+n:], payload[n:]) // cleartext tail (no-op when n == len(payload))
	return dst, nil
}

// SealInPlace seals a datagram whose plaintext body already sits at region[chachaNonceLen:]:
// it writes a fresh random nonce into region[:chachaNonceLen] and XORs the body in place. The
// nonce region and the body do not overlap, and the body is XORed against itself (dst==src), so
// the in-place transform is safe and produces bytes identical to Seal.
func (p *chacha4Packet) SealInPlace(region []byte) error {
	if len(region) < chachaNonceLen {
		return io.ErrUnexpectedEOF
	}
	mrandNonce(region[:chachaNonceLen])
	c := newChacha4Cipher(p.key, region[:chachaNonceLen])
	body := region[chachaNonceLen:]
	n := p.obfsLen(len(body))
	c.XORKeyStream(body[:n], body[:n])
	return nil
}

func (p *chacha4Packet) Open(datagram []byte) ([]byte, error) {
	if len(datagram) < chachaNonceLen {
		return nil, io.ErrUnexpectedEOF
	}
	nonce := datagram[:chachaNonceLen]
	body := datagram[chachaNonceLen:]
	n := p.obfsLen(len(body))
	c := newChacha4Cipher(p.key, nonce)
	c.XORKeyStream(body[:n], body[:n])
	return body, nil
}
