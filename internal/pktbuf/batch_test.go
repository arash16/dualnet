package pktbuf

import "testing"

func TestBatchDimsAndReset(t *testing.T) {
	b := NewBatch(4, 8, 4)
	if len(b.Slots()) != 4 {
		t.Fatalf("slots = %d, want 4", len(b.Slots()))
	}
	if len(b.Sizes()) != 4 {
		t.Fatalf("sizes = %d, want 4", len(b.Sizes()))
	}
	for i, s := range b.Slots() {
		if cap(s) != 8 {
			t.Fatalf("slot %d cap = %d, want 8", i, cap(s))
		}
	}
	// Slots must be independent regions (a write to one must not touch another).
	b.Slots()[0][0], b.Slots()[1][0] = 1, 2
	if b.Slots()[0][0] != 1 || b.Slots()[1][0] != 2 {
		t.Fatal("slots overlap")
	}
	b.Add(b.Slots()[0][:3])
	b.Add(b.Slots()[1][:5])
	if len(b.views) != 2 {
		t.Fatalf("views = %d, want 2", len(b.views))
	}
	b.Reset()
	if len(b.views) != 0 {
		t.Fatalf("views after reset = %d, want 0", len(b.views))
	}
}

// Adding up to maxViews must never reallocate the views slice — that would be a
// per-packet heap allocation on the hot path.
func TestBatchAddNoRealloc(t *testing.T) {
	b := NewBatch(4, 8, 4)
	c := cap(b.views)
	for i := 0; i < 4; i++ {
		b.Add(b.Slots()[i][:1])
	}
	if cap(b.views) != c {
		t.Fatalf("views reallocated: cap %d -> %d", c, cap(b.views))
	}
}
