package debugtun

import (
	"net"
	"testing"
	"time"
)

func TestDebugTunInjectAndReply(t *testing.T) {
	d, err := New("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	client, err := net.Dial("udp", d.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Inject a packet; Fill should publish it.
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	b := d.NewReadBatch()
	if err := d.Fill(b); err != nil {
		t.Fatal(err)
	}
	if got := b.Views()[0]; string(got) != "hello" {
		t.Fatalf("Fill = %q, want hello", got)
	}

	// Write should deliver back to the injector.
	if err := d.Write([][]byte{[]byte("world")}); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "world" {
		t.Fatalf("reply = %q, want world", buf[:n])
	}
}
