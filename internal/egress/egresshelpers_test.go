package egress

// egressReader returns a function that reads one reply packet from eg via the batched Fill API,
// copying it out (views alias the batch). It replaces the old per-packet ReadPacket in tests.
func egressReader(eg *Netstack) func() ([]byte, error) {
	b := eg.NewReadBatch()
	return func() ([]byte, error) {
		b.Reset()
		if err := eg.Fill(b); err != nil {
			return nil, err
		}
		v := b.Views()[0]
		return append([]byte(nil), v...), nil
	}
}

// injectOnePacket injects a single client packet via the batched Write API (test convenience for
// the removed per-packet WritePacket).
func injectOnePacket(eg *Netstack, p []byte) { _ = eg.Write([][]byte{p}) }
