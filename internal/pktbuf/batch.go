package pktbuf

// Batch is a fixed-capacity, reusable holder of packet byte-views backed by
// storage allocated once at construction. A FillFunc populates a Batch; the
// Reader then hands each view to the consumer one at a time. A Batch is owned by
// exactly one goroutine at a time (the Reader's ready/spent handoff guarantees
// this), so it needs no locking.
type Batch struct {
	slots [][]byte // fixed backing buffers a fill reads into
	sizes []int    // reusable []int out-param scratch (e.g. tun dev.Read lengths)
	views [][]byte // published packet views; cap == maxViews so Add never reallocs
}

// NewBatch allocates a Batch with numSlots backing buffers of slotCap bytes each
// (one contiguous allocation, sub-sliced) and room to publish up to maxViews
// packet views. Nothing here grows at steady state; reset only rewinds views.
// A source passes a func returning NewBatch(...) to NewReader so it owns its own
// sizing (slot count/capacity, max packets per batch) without exposing constants.
func NewBatch(numSlots, slotCap, maxViews int) *Batch {
	b := &Batch{
		slots: make([][]byte, numSlots),
		sizes: make([]int, numSlots),
		views: make([][]byte, 0, maxViews),
	}
	backing := make([]byte, numSlots*slotCap)
	for i := range b.slots {
		lo := i * slotCap
		b.slots[i] = backing[lo : lo+slotCap : lo+slotCap]
	}
	return b
}

// Reset rewinds the batch to empty for reuse (the backing storage is retained). The Reader calls
// it before each Fill; a caller driving Fill directly does the same.
func (b *Batch) Reset() { b.views = b.views[:0] }

// Views returns the packet views published by the last Fill (via Add), in order.
func (b *Batch) Views() [][]byte { return b.views }

// Slots returns the fixed backing buffers a fill reads into. A readv-style fill
// (tun dev.Read) fills several at once; a single-buffer fill (a stream frame, a
// UDP GRO read) uses only Slots()[0].
func (b *Batch) Slots() [][]byte { return b.slots }

// Sizes returns a reusable len-numSlots []int for a fill that needs a per-slot
// size out-param (tun dev.Read writes each packet's length here).
func (b *Batch) Sizes() []int { return b.sizes }

// Add publishes one packet view, which must alias a Slots() buffer. A fill must
// not publish more than the maxViews it was sized for, so Add never grows views.
func (b *Batch) Add(view []byte) { b.views = append(b.views, view) }
