package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
)

// runEcho is the simulated internet. It answers on every address it can reach and reports
// the SOURCE IP it observed — which is exactly what proves, offline and deterministically,
// which egress a flow took (the gateway's post-MASQUERADE address ⇒ tunnel path; the
// router's FTTH/Starlink address ⇒ that direct egress). The engine adds the service IPs to
// `lo` in this container and points every egress fabric's default route here, so all of
// those IPs are local and echo — bound to 0.0.0.0 — answers them all.
func runEcho(args []string) {
	fs := flag.NewFlagSet("echo", flag.ExitOnError)
	httpAddr := fs.String("http", ":80", "HTTP listen address")
	udpPort := fs.Int("udp", 9999, "UDP echo port")
	_ = fs.Parse(args)

	// Bind a UDP socket per local IPv4 rather than 0.0.0.0: a reply from an unbound socket
	// takes the egress NIC's source IP, but a NAT'd flow's reply must come FROM the exact
	// address the request was sent TO, or the gateway's conntrack won't recognise it. (TCP
	// is fine on 0.0.0.0 — an accept socket inherits the right local address.)
	for _, ip := range localIPv4s() {
		go echoUDP(ip, *udpPort)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "src=%s\n", hostOf(r.RemoteAddr))
	})
	log.Printf("echo: HTTP on %s, UDP echo on the local IPv4s :%d", *httpAddr, *udpPort)
	log.Fatal(http.ListenAndServe(*httpAddr, nil))
}

func echoUDP(ip net.IP, port int) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		log.Printf("echo: udp listen %s:%d: %v", ip, port, err)
		return
	}
	buf := make([]byte, 65535)
	for {
		_, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			log.Printf("echo: udp read: %v", err)
			continue
		}
		if _, err := c.WriteToUDP([]byte("src="+addr.IP.String()), addr); err != nil {
			log.Printf("echo: udp write: %v", err)
		}
	}
}

// localIPv4s returns every non-nil IPv4 assigned to any interface (lo included), so echo can
// bind each and answer for it.
func localIPv4s() []net.IP {
	var out []net.IP
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if v4 := ipn.IP.To4(); v4 != nil {
					out = append(out, v4)
				}
			}
		}
	}
	return out
}

// hostOf strips the port from a "host:port" remote address.
func hostOf(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return remote
}
