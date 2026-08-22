// Package tundev wraps golang.zx2c4.com/wireguard/tun with a simple
// per-packet interface. It hides the batched read/write API, the buffer
// headroom (macOS utun's 4-byte address-family header, Linux's virtio header)
// and GSO batching so callers just read and write inner IP packets.
//
// The device still reads up to BatchSize packets per syscall (128 on Linux, 1 on
// macOS) internally and hands them out one at a time; ReadPacket amortizes the read
// syscall across a whole batch without copying each packet out (see ReadPacket).
package tundev

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/arash16/dualnet/internal/pktbuf"
	"golang.zx2c4.com/wireguard/tun"
)

// normalizeDarwinTunName maps a requested name to what the macOS utun driver
// accepts: "utunN" is kept, and anything else (incl. "" or a Linux-style name)
// becomes the literal "utun", which auto-selects a free unit.
func normalizeDarwinTunName(name string) string {
	var n int
	if name == "utun" {
		return name
	}
	if _, err := fmt.Sscanf(name, "utun%d", &n); err == nil && n >= 0 {
		return name
	}
	return "utun"
}

// offset is the headroom left at the front of every buffer. It must be >= 4 for
// macOS utun (AF header) and >= 10 for Linux (virtio header); 16 covers both.
const offset = 16

// maxFrame is the largest single read the underlying device may deliver into the
// first buffer (a Linux GSO superframe before it is split).
const maxFrame = 65535

// Device is a tunnel interface exposing packet-at-a-time read/write.
type Device struct {
	dev   tun.Device
	name  string
	mtu   int
	batch int

	// write side (guarded; may be called from a different goroutine). The read side is
	// stateless here — Fill reads straight into a pktbuf.Batch's slots (see Fill).
	wmu   sync.Mutex
	wbufs [][]byte // per-slot batch buffers, each offset+maxFrame, reused across Write
	wview [][]byte // reused header slice handed to dev.Write (views into wbufs)
}

// Open creates (or attaches to) a TUN device named name with the given MTU. On
// macOS name should be "" or "utunN"; on Linux any name works.
func Open(name string, mtu int) (*Device, error) {
	// On macOS the driver only accepts the literal "utun" (auto-select a free
	// unit) or "utunN"; anything else — including "" and the Linux-style default
	// "dualnet0" — is rejected. Normalize so the same flags work on both platforms.
	if runtime.GOOS == "darwin" {
		name = normalizeDarwinTunName(name)
	}
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("tundev: create %q: %w", name, err)
	}
	realName, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	if actualMTU, err := dev.MTU(); err == nil && actualMTU > 0 {
		mtu = actualMTU
	}
	d := newDevice(dev, realName, mtu)
	// Drain device events so the driver's event goroutine never blocks.
	go func() {
		for range dev.Events() {
		}
	}()
	return d, nil
}

// newDevice builds a Device around an already-opened tun.Device. Split out from Open
// so tests can inject a fake device without touching the OS.
func newDevice(dev tun.Device, name string, mtu int) *Device {
	batch := dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	d := &Device{
		dev:   dev,
		name:  name,
		mtu:   mtu,
		batch: batch,
		wbufs: make([][]byte, batch),
		wview: make([][]byte, 0, batch),
	}
	for i := range d.wbufs {
		d.wbufs[i] = make([]byte, offset+maxFrame)
	}
	return d
}

// BatchSize is the number of packets the device reads/writes per syscall (128 on Linux, 1 on
// macOS); it bounds a useful Write batch and sizes the Fill read batch.
func (d *Device) BatchSize() int { return d.batch }

// Name returns the OS interface name (e.g. "utun6" or "dualnet0").
func (d *Device) Name() string { return d.name }

// MTU returns the interface MTU.
func (d *Device) MTU() int { return d.mtu }

// NewReadBatch makes a pktbuf.Batch sized for this device: BatchSize slots, each with the driver
// headroom plus the largest frame a read can deliver, so Fill can read a whole batch in one
// syscall. A pktbuf.Reader draining the tun passes this as its batch factory.
func (d *Device) NewReadBatch() *pktbuf.Batch {
	return pktbuf.NewBatch(d.batch, offset+maxFrame, d.batch)
}

// Fill reads a batch of inner IP packets into b in one syscall, publishing one view per packet.
// Each view aliases b's storage (same contract as ReadPacket): valid until b is refilled, so the
// pktbuf.Reader's double-buffering keeps a batch stable while the consumer drains it.
func (d *Device) Fill(b *pktbuf.Batch) error {
	slots, sizes := b.Slots(), b.Sizes()
	n, err := d.dev.Read(slots, sizes, offset)
	if err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		if sz := sizes[i]; sz > 0 {
			b.Add(slots[i][offset : offset+sz])
		}
	}
	return nil
}

// Write writes a batch of inner IP packets in as few syscalls as the driver allows: on Linux the
// packets are handed to the device together so consecutive same-flow TCP/UDP runs are GRO-coalesced
// into GSO superframes (fewer, larger writes). Packets beyond BatchSize are written in successive
// chunks. Each packet is copied into per-slot scratch (with the driver headroom), so the caller may
// reuse its slices once Write returns; safe for concurrent use. It is the pktbuf.Writer flush for
// the downlink tun.
func (d *Device) Write(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	d.wmu.Lock()
	defer d.wmu.Unlock()
	for start := 0; start < len(pkts); start += d.batch {
		end := start + d.batch
		if end > len(pkts) {
			end = len(pkts)
		}
		bufs := d.wview[:0]
		for _, pkt := range pkts[start:end] {
			if len(pkt) == 0 || len(pkt) > maxFrame {
				continue
			}
			slot := d.wbufs[len(bufs)]
			copy(slot[offset:], pkt)
			bufs = append(bufs, slot[:offset+len(pkt)])
		}
		if len(bufs) == 0 {
			continue
		}
		if _, err := d.dev.Write(bufs, offset); err != nil {
			return err
		}
	}
	return nil
}

// Close shuts down the device.
func (d *Device) Close() error { return d.dev.Close() }
