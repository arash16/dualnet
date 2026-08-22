// Command dualnet is a generalized asymmetric link-bonding VPN. A single binary runs
// one node, defined by a YAML config: a list of connections (tun / connect / listen)
// plus a routing table. Client, router, and internet-gateway are all just different
// connection+route configurations of the same node runtime.
//
//	dualnet [-config node.yaml] [-psk secret]        run a node
//	dualnet compile -network net.yaml -out ./cfg/    expand a network into per-node configs
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arash16/dualnet/internal/config"
	"github.com/arash16/dualnet/internal/conn"
	"github.com/arash16/dualnet/internal/debugtun"
	"github.com/arash16/dualnet/internal/kernelnode"
	"github.com/arash16/dualnet/internal/netwait"
	"github.com/arash16/dualnet/internal/node"
	"github.com/arash16/dualnet/internal/singleton"
	"github.com/felixge/fgprof"
)

// singletonHandoverGrace is how long a prior instance of this binary is given to shut
// down gracefully after SIGTERM before we escalate to SIGKILL (see internal/singleton).
const singletonHandoverGrace = 10 * time.Second

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("dualnet ")

	if len(os.Args) >= 2 && os.Args[1] == "compile" {
		if err := runCompile(os.Args[2:]); err != nil {
			log.Fatalf("fatal: %v", err)
		}
		return
	}
	if len(os.Args) >= 2 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help") {
		usage()
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := runNode(ctx, os.Args[1:]); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func runNode(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("dualnet", flag.ExitOnError)
	configFlag := fs.String("config", "", "node config path (default: ~/.config/dualnet/node.yaml or /etc/dualnet/node.yaml)")
	pskFlag := fs.String("psk", "", "global PSK override (or set DUALNET_PSK)")
	statsFlag := fs.String("stats", "", "append runtime stats (JSONL) to this file (or set DUALNET_STATS)")
	statsInterval := fs.Int("stats-interval", 0, "stats write interval in seconds (default 10)")
	debugTun := fs.Bool("debug-tun", false, "back tun connections with local UDP sockets instead of real OS tuns (run without sudo for testing)")
	pprofFlag := fs.String("pprof", "", "serve Go runtime profilers on this address for `go tool pprof` (or set DUALNET_PPROF); e.g. 127.0.0.1:6060 — never expose publicly")
	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return err
	}

	path, ok := config.ResolveConfigPath(*configFlag)
	if !ok {
		if *configFlag != "" {
			return fmt.Errorf("config file not found: %s", *configFlag)
		}
		return fmt.Errorf("no config file found (pass -config, or place one at ~/.config/dualnet/node.yaml)")
	}
	cfg, err := config.Parse(path)
	if err != nil {
		return err
	}
	log.Printf("loaded config from %s", path)

	// PSK precedence: -psk flag > DUALNET_PSK env > node.psk in the file.
	if env := os.Getenv("DUALNET_PSK"); env != "" {
		cfg.PSK = env
	}
	if *pskFlag != "" {
		cfg.PSK = *pskFlag
	}
	// Stats output precedence: -stats flag > DUALNET_STATS env > stats_file in the file.
	if env := os.Getenv("DUALNET_STATS"); env != "" {
		cfg.StatsFile = env
	}
	if *statsFlag != "" {
		cfg.StatsFile = *statsFlag
	}
	if *statsInterval > 0 {
		cfg.StatsInterval = *statsInterval
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Hand over from any prior instance of this same binary before touching the network,
	// so two nodes never fight over the tun/routes/sockets.
	if err := singleton.TakeExclusive(ctx, singletonHandoverGrace, log.Printf); err != nil {
		if ctx.Err() != nil {
			return nil // interrupted mid-handover
		}
		return fmt.Errorf("ensuring single instance: %w", err)
	}
	// Wait for the physical interfaces this node binds to / egresses through to come up
	// (e.g. a PPPoE uplink that appears only once its session is established).
	if err := netwait.Wait(ctx, cfg.RequiredInterfaces(), log.Printf); err != nil {
		if ctx.Err() != nil {
			return nil // interrupted while waiting
		}
		return err
	}

	// On a small no-swap router, Go's default GC lets the heap roughly double before
	// collecting; a burst of forwarded flows can then overshoot physical RAM and OOM the whole
	// box (a hard hang, no swap to fall back on). A soft memory limit makes the GC push back
	// (and the egress flow cap shed load) instead. Best-effort; skipped if RAM is unknown or an
	// explicit GOMEMLIMIT was given.
	applyMemoryLimit(log.Printf)

	// Opt-in runtime profiling for empirical hot-path analysis (pprof addr precedence:
	// -pprof flag > DUALNET_PPROF env). Off unless an address is given.
	pprofAddr := os.Getenv("DUALNET_PPROF")
	if *pprofFlag != "" {
		pprofAddr = *pprofFlag
	}
	startPprof(pprofAddr, log.Printf)

	// Dispatch on datapath: a kernel node programs policy routing + iptables (no userspace
	// forwarding, no tun); a userspace node runs the packet router. The -debug-tun seam is
	// userspace-only.
	if cfg.Datapath == "kernel" {
		if *debugTun {
			log.Printf("debug-tun: ignored for a kernel-datapath node")
		}
		return kernelnode.New(cfg).Run(ctx)
	}

	var opt node.Options
	if *debugTun {
		log.Printf("debug-tun: tuns backed by local UDP sockets (no OS tun, no sudo)")
		opt.OpenTun = func(name string, _ int) (conn.TunDevice, error) {
			d, err := debugtun.New("127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			log.Printf("debug-tun: %q listening on %s (send inner IP packets here)", name, d.LocalAddr())
			return d, nil
		}
	}
	return node.New(cfg, opt).Run(ctx)
}

// startPprof serves Go's runtime profilers (CPU, heap, goroutine, mutex, block) on addr for
// offline analysis with `go tool pprof`. It is opt-in — an empty addr is a no-op — because the
// endpoint exposes internal state and allows dumping profiles: bind it to localhost or a trusted
// LAN address and reach it over SSH, never the public internet. Enabling it also turns on mutex
// and block sampling so lock contention and pipeline stalls (a goroutine parked on a channel or
// socket) show up alongside on-CPU time; the sampling cost is negligible next to the packet path.
// A pegged core with no cryptography is usually one of those two, and the CPU profile alone can't
// see time spent blocked.
func startPprof(addr string, logf func(string, ...any)) {
	if addr == "" {
		return
	}
	runtime.SetMutexProfileFraction(5)  // report ~1/5 of mutex contention events
	runtime.SetBlockProfileRate(10_000) // one sample per ~10µs a goroutine spends blocked

	srv := &http.Server{Addr: addr, Handler: pprofHandler()}
	go func() {
		logf("pprof: serving profilers on http://%s/debug/pprof/ — do NOT expose publicly", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logf("pprof: server stopped: %v", err)
		}
	}()
}

// pprofHandler wires the standard pprof routes onto a dedicated mux (not http.DefaultServeMux)
// so the debug surface stays confined to the profiling listener and off any http-transport
// server. pprof.Index dispatches the runtime.Lookup profiles (goroutine/heap/mutex/block/allocs);
// profile/trace/cmdline/symbol are not Lookup profiles and need their own routes.
//
// /debug/fgprof adds a wall-clock profile (fgprof): unlike the CPU profile, it attributes
// off-CPU time too (blocked in syscalls, network I/O, channels). That is the profile to read
// when throughput is capped while the CPU sits idle — the packet path is then waiting, not
// computing, and only a wall-clock view shows where.
func pprofHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.Handle("/debug/fgprof", fgprof.Handler())
	return mux
}

// memLimitFraction of physical RAM is used as the soft heap limit: enough headroom for the
// kernel, other processes, and Go's own non-heap memory on a no-swap box.
const memLimitFraction = 0.55

// memLimitFloor is the smallest RAM for which we impose a limit; below it a limit would fight
// steady-state allocation more than it protects, so we leave the default.
const memLimitFloor = 48 << 20

// applyMemoryLimit sets GOMEMLIMIT from physical RAM unless the operator set it explicitly.
// Linux-only in practice (reads /proc/meminfo); a no-op elsewhere or when RAM is unknown.
func applyMemoryLimit(logf func(string, ...any)) {
	if os.Getenv("GOMEMLIMIT") != "" {
		return // respect an explicit override (the Go runtime already applied it)
	}
	total, ok := memTotalBytes()
	if !ok || total < memLimitFloor {
		return
	}
	limit := int64(float64(total) * memLimitFraction)
	debug.SetMemoryLimit(limit)
	logf("memory: GOMEMLIMIT=%dMiB (%.0f%% of %dMiB RAM) — soft cap to avoid OOM on no-swap hosts",
		limit>>20, memLimitFraction*100, total>>20)
}

// memTotalBytes reads MemTotal from /proc/meminfo (kB) and returns it in bytes.
func memTotalBytes() (int64, bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		f := strings.Fields(line) // ["MemTotal:", "123456", "kB"]
		if len(f) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}

func usage() {
	fmt.Fprint(os.Stderr, `dualnet - generalized asymmetric link-bonding VPN

usage:
  dualnet [-config node.yaml] [-psk secret]         run a node from its config
  dualnet compile -network net.yaml -out ./configs  expand a network into per-node configs

Run "dualnet compile -h" for compile flags. The PSK may be provided via -psk or the
DUALNET_PSK environment variable, overriding the file's global psk.
`)
}
