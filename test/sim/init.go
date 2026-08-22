package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/arash16/dualnet/internal/netsim/siminit"
)

// runInit is the container entrypoint. It applies a siminit.Spec (rename NICs by
// subnet-match, add routes, add loopback service addresses) then execs the real command
// (via syscall.Exec, so it becomes PID 1 and receives SIGHUP/SIGTERM directly — the SIGHUP
// prefix-reload scenario and clean shutdown depend on that).
//
//	sim init -spec /etc/sim/init.json -- dualnet -config /etc/dualnet/node.yaml
func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	specPath := fs.String("spec", "", "path to a siminit.Spec JSON file")
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		fatal("init: nothing to exec (usage: sim init -spec f -- cmd args...)")
	}

	if *specPath != "" {
		spec, err := loadSpec(*specPath)
		if err != nil {
			fatal("init: %v", err)
		}
		if err := applySpec(spec); err != nil {
			fatal("init: %v", err)
		}
	}

	bin, err := exec.LookPath(rest[0])
	if err != nil {
		fatal("init: exec %q: %v", rest[0], err)
	}
	if err := syscall.Exec(bin, rest, os.Environ()); err != nil {
		fatal("init: exec %q: %v", bin, err)
	}
}

func loadSpec(path string) (*siminit.Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s siminit.Spec
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &s, nil
}

func applySpec(s *siminit.Spec) error {
	for _, r := range s.Renames {
		dev, err := ifaceInSubnet(r.Subnet)
		if err != nil {
			return fmt.Errorf("rename %s→%s: %w", r.Subnet, r.Name, err)
		}
		if dev == r.Name {
			continue
		}
		// Down/rename/up. Addresses and (ifindex-keyed) routes survive the rename.
		for _, argv := range [][]string{
			{"link", "set", dev, "down"},
			{"link", "set", dev, "name", r.Name},
			{"link", "set", r.Name, "up"},
		} {
			if err := ipCmd(argv...); err != nil {
				return err
			}
		}
	}
	if err := applyWGDevices(s.WGDevices); err != nil {
		return fmt.Errorf("wireguard: %w", err)
	}
	for _, a := range s.LoAddrs {
		// Best-effort: a re-run (container restart) may find it already present.
		_ = ipCmd("addr", "add", a, "dev", "lo")
	}
	for _, r := range s.Routes {
		argv := []string{"route", "replace", r.Dst}
		if r.Via != "" {
			argv = append(argv, "via", r.Via)
		}
		if r.Dev != "" {
			argv = append(argv, "dev", r.Dev)
		}
		if err := ipCmd(argv...); err != nil {
			return err
		}
	}
	return nil
}

// ifaceInSubnet returns the name of the interface holding an IPv4 address inside cidr.
func ifaceInSubnet(cidr string) (string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			if ipnet.Contains(ipn.IP) {
				return ifc.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface with an address in %s", cidr)
}

func ipCmd(args ...string) error { return run("ip", args...) }

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, out)
	}
	return nil
}
