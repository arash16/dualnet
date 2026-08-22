package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// runProbe drives traffic and prints the echoed "src=<ip>" line, exiting 0 only on a real
// round-trip. Both modes poll-until-deadline because peer bring-up (id assignment, dial
// retries, healthcheck up-grace) takes a few seconds — a single shot would flake.
func runProbe(args []string) {
	if len(args) < 1 {
		fatal("usage: sim probe <http|inject> [flags]")
	}
	switch args[0] {
	case "http":
		probeHTTP(args[1:])
	case "inject":
		probeInject(args[1:])
	default:
		fatal("probe: unknown mode %q (want http|inject)", args[0])
	}
}

// probeHTTP issues a real TCP GET (from a LAN client it traverses the router's
// capture/forward + the gateway NAT + the TCPMSS clamp). With -expect-src it loops until the
// reply comes from that egress, so a routing assertion waits for the mesh to converge
// (healthchecks up) rather than grabbing a transient fallback reply.
func probeHTTP(args []string) {
	fs := flag.NewFlagSet("http", flag.ExitOnError)
	url := fs.String("url", "", "target URL, e.g. http://10.200.0.10/")
	expect := fs.String("expect-src", "", "require the echoed src to equal this")
	srcIP := fs.String("src-ip", "", "bind the socket to this source IP (exercises the router's src_in policy routing)")
	timeout := fs.Duration("timeout", 20*time.Second, "overall deadline")
	hold := fs.Duration("hold", 0, "after converging to -expect-src, drive continuous traffic for this long; every reply must STILL come from -expect-src. Surfaces a path that drifts under sustained load — e.g. a down gateway whose healthcheck false-heals from the fallback's own return traffic.")
	_ = fs.Parse(args)
	if *url == "" {
		fatal("probe http: -url is required")
	}
	// Disable keep-alives so each attempt is a fresh flow — the router routes per-flow, so a
	// reused connection would pin us to the egress chosen at connect time and hide convergence.
	// With -src-ip the dialer binds that local address, so the flow's source is the leg IP the
	// router policy-routes on (the client owns it on lo, so it still answers ARP for it).
	dialer := &net.Dialer{}
	if *srcIP != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(*srcIP)}
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, DialContext: dialer.DialContext}}
	deadline := time.Now().Add(*timeout)
	lastErr, lastSrc := "no reply", ""
	for time.Now().Before(deadline) {
		resp, err := client.Get(*url)
		if err != nil {
			lastErr = err.Error()
			time.Sleep(300 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			lastErr = fmt.Sprintf("status %d", resp.StatusCode)
			time.Sleep(300 * time.Millisecond)
			continue
		}
		out := strings.TrimSpace(string(body))
		if lastSrc = srcOf(out); *expect == "" || lastSrc == *expect {
			if *hold > 0 {
				holdEgress(client, *url, *expect, *hold)
			}
			fmt.Println(out)
			return
		}
		time.Sleep(300 * time.Millisecond) // right reachability, wrong egress: wait to converge
	}
	fatal("probe http: no matching reply within %s (last src=%q, err=%s)", *timeout, lastSrc, lastErr)
}

// holdEgress drives continuous traffic for d after the path converged to expect, asserting the
// egress never drifts. The continuous return traffic itself is the test: a correct healthcheck
// only counts its own reflected pings, so a down gateway's branch stays failed over; a broken
// one that counts ANY return as liveness will false-heal off this traffic and start routing
// into the (down) gateway — which this loop catches as a wrong src or a dropped reply.
func holdEgress(client *http.Client, url, expect string, d time.Duration) {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		resp, err := client.Get(url)
		if err != nil {
			fatal("probe http: path dropped under sustained load after converging to %s: %v", expect, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			fatal("probe http: status %d under sustained load (converged to %s)", resp.StatusCode, expect)
		}
		if s := srcOf(strings.TrimSpace(string(body))); s != expect {
			fatal("probe http: egress drifted to %q under sustained load, want %s — healthcheck false-heal?", s, expect)
		}
		// Pace so the return traffic is steady (faster than the healthcheck tick, so a
		// false-heal has fresh liveness every tick) without flooding the path.
		time.Sleep(250 * time.Millisecond)
	}
}

// probeInject crafts an inner IPv4/UDP packet and sends it as a datagram to a node's
// -debug-tun socket, then reads the reply that returns down the tunnel. Used for tun-origin
// nodes (e.g. vps) that have no LAN client.
func probeInject(args []string) {
	fs := flag.NewFlagSet("inject", flag.ExitOnError)
	tun := fs.String("tun", "", "debug-tun UDP address host:port")
	src := fs.String("src", "", "inner source IP")
	dst := fs.String("dst", "", "inner destination IP (echo service IP)")
	dport := fs.Int("dport", 9999, "inner UDP destination port")
	expect := fs.String("expect-src", "", "require the echoed src to equal this")
	timeout := fs.Duration("timeout", 20*time.Second, "overall deadline")
	hold := fs.Duration("hold", 0, "after converging, keep injecting for this long; every reply must still match -expect-src")
	_ = fs.Parse(args)
	if *tun == "" || *src == "" || *dst == "" {
		fatal("probe inject: -tun, -src and -dst are required")
	}
	sip, dip := net.ParseIP(*src).To4(), net.ParseIP(*dst).To4()
	if sip == nil || dip == nil {
		fatal("probe inject: -src/-dst must be IPv4")
	}
	raddr, err := net.ResolveUDPAddr("udp", *tun)
	if err != nil {
		fatal("probe inject: resolve %q: %v", *tun, err)
	}
	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		fatal("probe inject: dial %q: %v", *tun, err)
	}
	defer c.Close()

	pkt := udpPacket(sip, dip, 40000, uint16(*dport), []byte("probe"))
	buf := make([]byte, 65535)
	deadline := time.Now().Add(*timeout)
	lastSrc := ""
	for time.Now().Before(deadline) {
		if _, err := c.Write(pkt); err != nil {
			fatal("probe inject: write: %v", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := c.Read(buf)
		if err != nil {
			continue // timeout: retransmit
		}
		payload := udpPayload(buf[:n])
		if payload == nil {
			continue // not a UDP reply (e.g. a reflected healthcheck ping): keep trying
		}
		out := strings.TrimSpace(string(payload))
		if lastSrc = srcOf(out); *expect == "" || lastSrc == *expect {
			if *hold > 0 {
				holdInject(c, pkt, buf, *expect, *hold)
			}
			fmt.Println(out)
			return
		}
	}
	fatal("probe inject: no matching reply within %s (last src=%q)", *timeout, lastSrc)
}

// holdInject is probeInject's counterpart to holdEgress: after converging, keep injecting for
// d and require every reply to still come from expect (a drift or a stall means the path moved).
func holdInject(c *net.UDPConn, pkt, buf []byte, expect string, d time.Duration) {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if _, err := c.Write(pkt); err != nil {
			fatal("probe inject: write under sustained load: %v", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(buf)
		if err != nil {
			fatal("probe inject: path went silent under sustained load after converging to %s", expect)
		}
		payload := udpPayload(buf[:n])
		if payload == nil {
			continue // a reflected healthcheck ping etc.; keep driving
		}
		if s := srcOf(strings.TrimSpace(string(payload))); s != expect {
			fatal("probe inject: egress drifted to %q under sustained load, want %s — healthcheck false-heal?", s, expect)
		}
		time.Sleep(250 * time.Millisecond) // steady, not a flood (see holdEgress)
	}
}

// srcOf extracts X from a "src=X" echo reply.
func srcOf(s string) string {
	if strings.HasPrefix(s, "src=") {
		return strings.TrimPrefix(s, "src=")
	}
	return s
}

// udpPacket builds an IPv4/UDP datagram (UDP checksum 0 = not computed, legal over IPv4).
func udpPacket(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	total := 20 + udpLen
	p := make([]byte, total)
	p[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(p[2:], uint16(total))
	p[8] = 64 // TTL
	p[9] = 17 // UDP
	copy(p[12:16], src)
	copy(p[16:20], dst)
	binary.BigEndian.PutUint16(p[10:], checksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:], sport)
	binary.BigEndian.PutUint16(p[22:], dport)
	binary.BigEndian.PutUint16(p[24:], uint16(udpLen))
	copy(p[28:], payload)
	return p
}

// udpPayload extracts the UDP payload from an inner IPv4/UDP packet, or nil if it is not one.
func udpPayload(p []byte) []byte {
	if len(p) < 20 || p[0]>>4 != 4 {
		return nil
	}
	ihl := int(p[0]&0x0f) * 4
	if p[9] != 17 || len(p) < ihl+8 {
		return nil
	}
	return p[ihl+8:]
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
