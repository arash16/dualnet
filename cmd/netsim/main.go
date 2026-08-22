// Command netsim stands up any dualnet network schema as a deterministic, offline Docker
// simulation and runs the test matrix derived from that network's own paths — no real
// internet, no hand-written topology. It is a separate binary from `dualnet` so the shipped
// node binary never carries the Docker SDK.
//
//	netsim -network docs/examples/network-old.yaml        # build image, run all scenarios
//	netsim -network net.yaml -only failover               # run a subset
//	netsim -network net.yaml -keep                        # leave the mesh up for `docker exec`
//	netsim -network net.yaml -no-build                    # reuse an existing image
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/arash16/dualnet/internal/netschema"
	"github.com/arash16/dualnet/internal/netsim"
	"github.com/arash16/dualnet/internal/netsim/dockerdriver"
)

func main() {
	log.SetFlags(0)
	network := flag.String("network", "", "network schema path (required)")
	only := flag.String("only", "", "run only scenarios whose name contains this substring")
	keep := flag.Bool("keep", false, "leave the mesh running after the run (for docker exec)")
	noBuild := flag.Bool("no-build", false, "reuse the existing image instead of building it")
	psk := flag.String("psk", "", "mesh PSK (default netsim)")
	image := flag.String("image", "", "test image tag (default dualnet-sim:test)")
	skipPSK := flag.Bool("no-psk-check", false, "skip the PSK-mismatch negative run")
	flag.Parse()

	if *network == "" {
		fmt.Fprintln(os.Stderr, "netsim: -network is required")
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*network, *only, *keep, !*noBuild, *psk, *image, !*skipPSK); err != nil {
		log.Fatalf("netsim: %v", err)
	}
}

func run(network, only string, keep, build bool, psk, image string, pskCheck bool) error {
	net, err := netschema.Load(network)
	if err != nil {
		return err
	}
	driver, err := dockerdriver.New("netsim")
	if err != nil {
		return fmt.Errorf("connect to docker (is it running? DOCKER_HOST=%q): %w", os.Getenv("DOCKER_HOST"), err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	opts := netsim.RunOptions{
		Build: build, Keep: keep, Only: only,
		Plan: netsim.PlanOptions{PSK: psk, Image: image},
		Log:  func(s string) { log.Println(s) },
	}

	rep, err := netsim.Run(ctx, net, driver, opts)
	if err != nil {
		return err
	}

	// The PSK-mismatch negative uses its own broken mesh; skip if -keep (it would tear the
	// kept mesh down) or when explicitly disabled.
	if pskCheck && !keep {
		opts.Build = false // image already built by the run above
		pskRep, err := netsim.RunPSKMismatch(ctx, net, driver, opts)
		if err != nil {
			return err
		}
		rep.Results = append(rep.Results, pskRep.Results...)
	}

	fmt.Println()
	for _, r := range rep.Results {
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
		}
		fmt.Printf("[%s] %s\n", status, r.Scenario)
		if r.Description != "" {
			fmt.Printf("       %s\n", r.Description)
		}
		if !r.Pass {
			fmt.Printf("       ✗ %s\n", r.Detail)
		}
	}
	failed := rep.Failed()
	fmt.Printf("\n%d scenarios, %d failed\n", len(rep.Results), failed)
	if keep {
		fmt.Println("mesh left running (-keep); remove with: docker rm -f $(docker ps -aqf name=netsim-)")
	}
	if failed > 0 {
		os.Exit(1)
	}
	return nil
}
