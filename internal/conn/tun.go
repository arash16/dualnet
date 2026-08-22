package conn

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/arash16/dualnet/internal/pktbuf"
	"github.com/arash16/dualnet/internal/wire"
)

// TunDevice is the subset of tundev.Device that a TunConn needs. Faked in tests.
type TunDevice interface {
	// Fill reads a batch of inner IP packets into b, and NewReadBatch makes a device-sized
	// batch; together they drive the uplink pktbuf.Reader.
	Fill(b *pktbuf.Batch) error
	NewReadBatch() *pktbuf.Batch
	// Write writes a batch of inner packets in as few syscalls as the driver allows (the
	// downlink pktbuf.Writer flush). Copies the slices, so the caller may reuse them.
	Write(pkts [][]byte) error
	Close() error
}

const (
	// tunWriteArena / tunWriteBatch bound the downlink write buffer: a burst coalesces into one
	// batched device write, buffered memory stays fixed, and the flush group flushes a partial
	// batch on its tick. tunWriteArena must exceed the largest single inner packet (wire.MaxPacket).
	tunWriteArena = 128 * 1024
	tunWriteBatch = 64
)

// TunConn is a local tun. It originates packets stamped with its owner id
// (Processed=false) and consumes packets addressed to that id (writing them to the
// device, or, for a reflected healthcheck ping, recording liveness and dropping it).
//
// The id is either self-random (assigned at construction) or set by a remote via a
// ConnectIn's id_setter. When the id is pending (some ConnectIn will set it), the read
// loop blocks until SetID so early packets don't go out with an id no ListenOut knows.
type TunConn struct {
	name string
	dev  TunDevice

	// hook holds the healthcheck liveness callbacks, swapped atomically so the per-packet
	// read/send paths load them without taking a lock.
	hook atomic.Pointer[hookSet]

	id    atomic.Pointer[wire.Owner]
	ready chan struct{} // closed once id is available
	once  sync.Once

	// Downlink write batching. Send buffers a copy of each packet into w; w flushes the batch to
	// the device in one Write when full or when the flush group's tick catches an idle partial.
	// Copying (rather than aliasing the carrier's reused read buffer) keeps it safe when several
	// carriers feed one tun concurrently. Uplink reads come through r (started after the id gate).
	fg *pktbuf.FlushGroup
	w  *pktbuf.Writer
	r  *pktbuf.Reader
}

// hookSet bundles the liveness callbacks so both can be published in one atomic store.
// seen fires when any packet arrives back at the tun (data or reflected ping); sent fires
// when a packet is read from the device (outbound), gating lazy-mode probing. Either may be nil.
type hookSet struct {
	seen func()
	sent func()
}

// NewTun builds a tun connection. If pending is true the id is left unset (SetID must
// supply it, from a remote assignment); otherwise initial is used immediately. fg flushes
// the downlink write batch on an interval so a partial batch is never stuck.
func NewTun(name string, dev TunDevice, initial wire.Owner, pending bool, fg *pktbuf.FlushGroup) *TunConn {
	t := &TunConn{name: name, dev: dev, ready: make(chan struct{}), fg: fg}
	t.w = pktbuf.NewWriter(dev.Write, tunWriteArena, tunWriteBatch)
	t.r = pktbuf.NewReader(dev.Fill, nil, dev.NewReadBatch)
	fg.Add(t.w)
	if !pending {
		t.setID(initial)
	}
	return t
}

// SetHooks wires the healthcheck driver's liveness callbacks. Either may be nil.
func (t *TunConn) SetHooks(seen, sent func()) {
	t.hook.Store(&hookSet{seen: seen, sent: sent})
}

func (t *TunConn) Name() string { return t.name }
func (t *TunConn) Kind() Kind   { return KindTun }

// SetID assigns (or reassigns) the tun's owner id and unblocks the read loop. Called
// by a ConnectIn when a Multiple listener mints an id for this tun.
func (t *TunConn) SetID(id wire.Owner) { t.setID(id) }

func (t *TunConn) setID(id wire.Owner) {
	v := id
	t.id.Store(&v)
	t.once.Do(func() { close(t.ready) })
}

// ID returns the current owner id, if set.
func (t *TunConn) ID() (wire.Owner, bool) {
	if p := t.id.Load(); p != nil {
		return *p, true
	}
	return wire.Owner{}, false
}

// Start launches the read loop, which waits (in the background) until the tun's id is
// available, then injects device packets into routing as unprocessed packets owned by
// that id. Start returns immediately so a pending tun does not stall node startup —
// the connection that assigns the id must be started too.
func (t *TunConn) Start(ctx context.Context, in Ingress) error {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-t.ready:
		}
		t.r.Start(ctx)
		for {
			pkt, ok := t.r.Next()
			if !ok {
				return // device closed / context cancelled
			}
			if h := t.hook.Load(); h != nil && h.sent != nil {
				h.sent()
			}
			id, _ := t.ID()
			in(t.name, wire.Envelope{Owner: id}, pkt)
		}
	}()
	return nil
}

// Accepts reports whether owner matches this tun's id.
func (t *TunConn) Accepts(owner wire.Owner) bool {
	id, ok := t.ID()
	return ok && id == owner
}

// Send writes an inner packet to the device (buffered into the downlink batch), or
// consumes a reflected healthcheck ping.
func (t *TunConn) Send(e wire.Envelope, payload []byte) (bool, error) {
	if !t.Accepts(e.Owner) {
		return false, nil
	}
	if wire.IsPing(payload) {
		// ONLY a reflected healthcheck ping signals liveness. It round-tripped the specific
		// probed path (up-links → gateway → reflection → back), so it proves THAT path is live.
		// Data can return via a different branch than the one being probed (a multi-branch tun
		// routes is-iran, tunnel, and fallback separately), so counting data would let a dead
		// gateway read healthy whenever any other path returns traffic — a false positive that
		// routes real traffic into the black hole. Consume the ping; never write it out.
		if h := t.hook.Load(); h != nil && h.seen != nil {
			h.seen()
		}
		return true, nil
	}
	// Copy into the write batch (never aliasing the carrier's reused read buffer, so several
	// carriers can feed one tun concurrently). The batch reaches the device on flush.
	dst := t.w.Reserve(len(payload))
	n := copy(dst, payload)
	t.w.Commit(n)
	return true, nil
}

func (t *TunConn) Close() error {
	t.fg.Remove(t.w)
	_ = t.w.Close()      // flush any buffered downlink packets while the device is still open
	_ = t.r.Close()      // stop the prefetch goroutine
	return t.dev.Close() // unblock a Fill blocked in the device read
}

var (
	_ Conn   = (*TunConn)(nil)
	_ Sender = (*TunConn)(nil)
)
