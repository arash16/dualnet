package stats

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCountersAndSnapshot(t *testing.T) {
	r := New([]string{"tun", "up"})
	r.SetRoutes([]string{"unproc/tun→up"})

	r.Recv("tun", 100)
	r.Recv("tun", 40)
	r.Sent("up", 1200)
	r.Route("unproc/tun→up")
	r.Route("unproc/tun→up")
	r.NoRouteDrop()
	r.DecodeDrop()
	r.DecodeDrop()

	// Unknown connection / route names are no-ops (must not panic or count).
	r.Recv("ghost", 5)
	r.Sent("ghost", 5)
	r.Route("ghost")

	s := r.snapshot()
	if s.Conns["tun"].Recv != 2 || s.Conns["tun"].RecvBytes != 140 {
		t.Fatalf("tun recv = %d/%d bytes, want 2/140", s.Conns["tun"].Recv, s.Conns["tun"].RecvBytes)
	}
	if s.Conns["up"].Sent != 1 || s.Conns["up"].SentBytes != 1200 {
		t.Fatalf("up sent = %d/%d bytes, want 1/1200", s.Conns["up"].Sent, s.Conns["up"].SentBytes)
	}
	if _, ok := s.Conns["ghost"]; ok {
		t.Fatal("ghost connection should not be registered")
	}
	if s.Routes["unproc/tun→up"] != 2 {
		t.Fatalf("route count = %d, want 2", s.Routes["unproc/tun→up"])
	}
	if s.Drops.NoRoute != 1 || s.Drops.Decode != 2 {
		t.Fatalf("drops = %+v, want {1 2}", s.Drops)
	}
}

func TestMemoryWindowResets(t *testing.T) {
	r := New(nil)
	r.sample()
	s1 := r.snapshot()
	if s1.MaxHeapMB <= 0 {
		t.Fatalf("expected nonzero heap peak, got %v", s1.MaxHeapMB)
	}
	// A snapshot consumes the window; with no sample since, the next window is empty.
	s2 := r.snapshot()
	if s2.MaxHeapMB != 0 {
		t.Fatalf("expected window reset to 0, got %v", s2.MaxHeapMB)
	}
}

func TestRunWritesFinalSnapshotOnCancel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.jsonl")
	r := New([]string{"tun"})
	r.Recv("tun", 64)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: Run writes exactly one final snapshot, then returns.
	if err := r.Run(ctx, path, time.Hour, 0); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatal("no snapshot line written")
	}
	var snap Snapshot
	if err := json.Unmarshal(sc.Bytes(), &snap); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if snap.Conns["tun"].Recv != 1 {
		t.Fatalf("recv = %d, want 1", snap.Conns["tun"].Recv)
	}
	if snap.Time == "" {
		t.Fatal("snapshot has no timestamp")
	}
}

func TestRotatedName(t *testing.T) {
	cases := map[string]string{
		"/var/log/dualnet-stats.jsonl": "/var/log/dualnet-stats-old.jsonl",
		"stats.jsonl":                  "stats-old.jsonl",
		"/tmp/noext":                   "/tmp/noext-old",
	}
	for in, want := range cases {
		if got := rotatedName(in); got != want {
			t.Errorf("rotatedName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRotatingWriterRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.jsonl")
	w, err := newRotatingWriter(path, 20) // 20-byte cap
	if err != nil {
		t.Fatal(err)
	}
	// 7 + 7 = 14 (<=20, no rotate); the third write (14+7=21 > 20) rotates first.
	for _, line := range []string{"line-1\n", "line-2\n", "line-3\n"} {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	old, err := os.ReadFile(filepath.Join(dir, "stats-old.jsonl"))
	if err != nil {
		t.Fatalf("expected rotated file: %v", err)
	}
	if string(old) != "line-1\nline-2\n" {
		t.Fatalf("rotated file = %q, want the first two lines", old)
	}
	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(cur) != "line-3\n" {
		t.Fatalf("current file = %q, want just line-3", cur)
	}
}

func TestRotatingWriterDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.jsonl")
	w, err := newRotatingWriter(path, 0) // rotation disabled
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		_, _ = w.Write([]byte("some line of stats\n"))
	}
	_ = w.Close()
	if _, err := os.Stat(filepath.Join(dir, "stats-old.jsonl")); !os.IsNotExist(err) {
		t.Fatal("no rotation expected when max<=0")
	}
}
