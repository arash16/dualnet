package pktbuf

import (
	"context"
	"testing"
)

func BenchmarkReaderNext(b *testing.B) {
	fill := func(bt *Batch) error {
		for i := 0; i < 32; i++ {
			bt.Slots()[i][0] = byte(i)
			bt.Add(bt.Slots()[i][:1])
		}
		return nil
	}
	r := NewReader(fill, nil, func() *Batch { return NewBatch(32, 64, 32) })
	r.Start(context.Background())
	defer r.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Next()
	}
}

func BenchmarkWriterReserveCommit(b *testing.B) {
	flush := func(views [][]byte) error { return nil }
	w := NewWriter(flush, 64*1024, 64)
	pkt := make([]byte, 1400)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst := w.Reserve(len(pkt))
		copy(dst, pkt)
		w.Commit(len(pkt))
	}
}
