package cipher

import "testing"

// BenchmarkPacketCipher measures chacha4 at an MTU-sized (1280B) payload —
// the shape of a real dualnet datagram.
func BenchmarkPacketCipher(b *testing.B) {
	payload := make([]byte, 1280)
	pc, err := NewPacket("chacha4", testKey("bench"))
	if err != nil {
		b.Fatal(err)
	}
	var dst []byte
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, err = pc.Seal(dst[:0], payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}
