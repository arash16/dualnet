// Package debugtun provides a fake tun device backed by a local UDP socket instead of
// a real OS tun. It lets a node run WITHOUT root (no /dev/net/tun, no utun) for
// testing: inject an inner IP packet by sending it as a UDP datagram to the device's
// port, and receive tun-bound packets back at the sender's address. Even with no
// injected traffic, the node's healthcheck still round-trips (proving the tunnel path
// end-to-end), so `-debug-tun` is enough to smoke-test connectivity to real peers.
package debugtun

import (
	"net"
	"sync"

	"github.com/arash16/dualnet/internal/pktbuf"
)

// Device is a UDP-backed conn.TunDevice.
type Device struct {
	conn *net.UDPConn

	mu   sync.Mutex
	peer *net.UDPAddr // most recent sender; where Write delivers
}

// New binds a UDP socket on listen (e.g. "127.0.0.1:0" for an auto port).
func New(listen string) (*Device, error) {
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return &Device{conn: c}, nil
}

// LocalAddr is the bound "host:port" a test injects packets to / reads replies from.
func (d *Device) LocalAddr() string { return d.conn.LocalAddr().String() }

// writeOne sends one tun-bound inner IP packet to the last injector, dropping it if nothing has
// injected yet (no return address known).
func (d *Device) writeOne(pkt []byte) error {
	d.mu.Lock()
	peer := d.peer
	d.mu.Unlock()
	if peer == nil {
		return nil
	}
	_, err := d.conn.WriteToUDP(pkt, peer)
	return err
}

// NewReadBatch makes a single-packet pktbuf.Batch for a Reader draining this device (UDP has no
// vectored read of many inner packets here).
func (d *Device) NewReadBatch() *pktbuf.Batch { return pktbuf.NewBatch(1, 65535, 1) }

// Fill reads the next injected inner IP packet into b (one packet), remembering the sender as the
// Write destination. The view aliases b's storage.
func (d *Device) Fill(b *pktbuf.Batch) error {
	dst := b.Slots()[0]
	n, addr, err := d.conn.ReadFromUDP(dst)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.peer = addr
	d.mu.Unlock()
	b.Add(dst[:n])
	return nil
}

// Write writes a batch of tun-bound packets, one UDP send each (debugtun has no batched syscall).
func (d *Device) Write(pkts [][]byte) error {
	for _, p := range pkts {
		if err := d.writeOne(p); err != nil {
			return err
		}
	}
	return nil
}

// Close shuts down the socket.
func (d *Device) Close() error { return d.conn.Close() }
