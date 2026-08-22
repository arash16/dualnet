package warp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Dialer is an in-process WARP egress: a userspace WireGuard device whose
// netstack dials destinations through Cloudflare WARP.
type Dialer struct {
	net *netstack.Net
	dev *device.Device
}

// NewDialer brings up the userspace WARP WireGuard device from acct.
func NewDialer(acct *Account, verbose bool) (*Dialer, error) {
	v4, err := netip.ParseAddr(acct.V4)
	if err != nil {
		return nil, fmt.Errorf("warp: bad v4 addr %q: %w", acct.V4, err)
	}
	addrs := []netip.Addr{v4}
	if acct.V6 != "" {
		if v6, e := netip.ParseAddr(acct.V6); e == nil {
			addrs = append(addrs, v6)
		}
	}
	tunDev, tnet, err := netstack.CreateNetTUN(addrs, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, MTU)
	if err != nil {
		return nil, err
	}

	level := device.LogLevelError
	if verbose {
		level = device.LogLevelVerbose
	}
	dev := device.NewDevice(tunDev, newReservedBind(acct.Reserved()), device.NewLogger(level, "warp "))

	privHex, err := b64ToHex(acct.PrivateKey)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("warp: private key: %w", err)
	}
	peerHex, err := b64ToHex(acct.PeerPublicKey)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("warp: peer key: %w", err)
	}
	ep, err := resolveEndpoint(acct.endpoint())
	if err != nil {
		dev.Close()
		return nil, err
	}

	uapi := "private_key=" + privHex + "\n" +
		"public_key=" + peerHex + "\n" +
		"endpoint=" + ep.String() + "\n" +
		"persistent_keepalive_interval=" + strconv.Itoa(int(keepalive.Seconds())) + "\n" +
		"allowed_ip=0.0.0.0/0\n" +
		"allowed_ip=::/0\n"
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("warp: ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("warp: device up: %w", err)
	}
	return &Dialer{net: tnet, dev: dev}, nil
}

// DialContext dials network/address through WARP, satisfying conn.SocketDialer so a
// warpped Connect connection can tunnel its transport socket through WARP (hiding the
// node's IP from the remote). NOTE: the WARP device's own outer UDP socket to
// Cloudflare is not yet pinned to a physical interface (see internal/warp/bind.go);
// on a multi-link node a warpped connection egresses via the OS default route.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.net.DialContext(ctx, network, address)
}

// DialTCP dials a TCP connection to addr through WARP.
func (d *Dialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return d.net.DialContextTCPAddrPort(ctx, addr)
}

// DialUDP opens a UDP connection to addr through WARP.
func (d *Dialer) DialUDP(addr netip.AddrPort) (net.Conn, error) {
	return d.net.DialUDPAddrPort(netip.AddrPort{}, addr)
}

// Close tears down the WARP device.
func (d *Dialer) Close() error {
	d.dev.Close()
	return nil
}

func resolveEndpoint(hostPort string) (*net.UDPAddr, error) {
	if ap, err := netip.ParseAddrPort(hostPort); err == nil {
		return net.UDPAddrFromAddrPort(ap), nil
	}
	ua, err := net.ResolveUDPAddr("udp", hostPort)
	if err != nil {
		return nil, fmt.Errorf("warp: resolve endpoint %q: %w", hostPort, err)
	}
	return ua, nil
}
