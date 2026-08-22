package conn

import (
	"io"
	"testing"
	"time"

	"github.com/arash16/dualnet/internal/pktbuf"
	"github.com/arash16/dualnet/internal/wire"
)

// nopTunDev is a TunDevice that records writes and never yields reads.
type nopTunDev struct{ written [][]byte }

func (d *nopTunDev) NewReadBatch() *pktbuf.Batch { return pktbuf.NewBatch(1, 65535, 1) }
func (d *nopTunDev) Fill(*pktbuf.Batch) error    { return io.EOF }
func (d *nopTunDev) Write(pkts [][]byte) error {
	for _, p := range pkts {
		d.written = append(d.written, append([]byte(nil), p...))
	}
	return nil
}
func (d *nopTunDev) Close() error { return nil }

// TestTunLivenessOnlyFromReflectedPing pins the healthcheck's core contract: ONLY a reflected
// healthcheck ping — which round-tripped the specific probed path (up-links → gateway →
// reflection → down) — may signal liveness. Ordinary return data can arrive via a DIFFERENT
// branch than the one being probed (e.g. a router whose is-iran traffic exits FTTH and whose
// fallback exits Starlink while the tunnel gateway is down), so counting data as liveness lets
// a dead gateway read "healthy" whenever any other path returns traffic — a false positive
// that then routes real traffic into the black hole. This is exactly the failure observed in
// the field: the turkish gateway was down (CrashLoopBackOff) yet `turkey` went healthy.
func TestTunLivenessOnlyFromReflectedPing(t *testing.T) {
	owner := wire.Owner{1, 2, 3, 4}
	dev := &nopTunDev{}
	fg := pktbuf.NewFlushGroup(time.Millisecond)
	tc := NewTun("lan", dev, owner, false, fg)

	seen := 0
	tc.SetHooks(func() { seen++ }, nil)

	// A data packet returning to the tun must NOT count as healthcheck liveness, and must be
	// written through to the device.
	data := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6 /* TCP, not a ping */, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := tc.Send(wire.Envelope{Owner: owner}, data); err != nil {
		t.Fatalf("send data: %v", err)
	}
	if seen != 0 {
		t.Errorf("data return signalled healthcheck liveness (false positive): seen=%d, want 0", seen)
	}
	// Send buffers into the write batch; the packet reaches the device when the batch is flushed
	// (here forced directly; in the node the flush group's ticker does it on an interval).
	if err := tc.w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(dev.written) != 1 {
		t.Errorf("data packet must be delivered to the device: got %d writes, want 1", len(dev.written))
	}

	// A reflected healthcheck ping IS liveness, and is consumed (never written to the device).
	if _, err := tc.Send(wire.Envelope{Owner: owner}, wire.EncodePing(1)); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	if seen != 1 {
		t.Errorf("reflected ping must signal liveness: seen=%d, want 1", seen)
	}
	if len(dev.written) != 1 {
		t.Errorf("reflected ping must be consumed, not written to the device: got %d writes, want 1", len(dev.written))
	}
}
