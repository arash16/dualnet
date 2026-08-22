// Command sim is the netsim in-container helper. One static binary provides every piece of
// tooling the simulated mesh needs, so the test image stays minimal (dualnet + sim +
// iproute2/iptables, no shell/awk gymnastics):
//
//	sim init  -spec /etc/sim/init.json -- <cmd> [args...]
//	    The container entrypoint. Renames each data NIC to a stable name by matching its IP
//	    to a fabric subnet, adds routes and loopback addresses, then execs <cmd>. This is why
//	    generated configs can reference fixed device names (dn0, dn1, …) even though Docker
//	    only ever creates eth0..N in an unspecified order.
//
//	sim echo  [-http :80] [-udp 9999]
//	    The simulated internet: answers HTTP and UDP with the observed source IP.
//
//	sim probe http   -url http://10.200.0.10/ [-timeout 20s]
//	sim probe inject -tun 127.0.0.1:PORT -src 10.9.0.5 -dst 10.200.0.10 [-dport 9999] [-timeout]
//	    The traffic drivers; both poll-until-deadline and exit 0 only on a real round-trip.
//
// It never contacts a real host.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	log.SetPrefix("sim ")
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fatal("usage: sim <init|echo|probe> ...")
	}
	switch os.Args[1] {
	case "init":
		runInit(os.Args[2:])
	case "echo":
		runEcho(os.Args[2:])
	case "probe":
		runProbe(os.Args[2:])
	case "idle":
		runIdle()
	default:
		fatal("unknown subcommand %q (want init|echo|probe|idle)", os.Args[1])
	}
}

// runIdle keeps a container alive (the LAN client, which the engine drives via exec) until
// it is signalled to stop.
func runIdle() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "sim: "+format+"\n", a...)
	os.Exit(1)
}
