# Performance

How dualnet's packet **hot path** is kept fast, what was optimized and why, the invariants a
change must not break, and what a new transport / cipher / datapath is expected to do. Read
[docs/protocol.md](protocol.md) and [docs/data-flow.md](data-flow.md) first for the model;
this doc is only about speed.

## 1. What the hot path is

Steady-state packet forwarding, two directions:

- **Uplink** — a local tun originates a packet: the tun read loop pulls it from a `pktbuf.Reader`
  (over `tundev.Device.Fill`) → `router` dispatch → a `Sender` (`ConnectOut` push, or a gateway
  `finalizer.Submit` to egress).
- **Downlink** — an inter-node datagram arrives: a transport read loop pulls it from a
  `pktbuf.Reader`, de-obfuscates + parses → `router` dispatch → a `Sender` (`TunConn` write to the
  device, or a `ListenOut` send to a peer).

Reads and writes both go through **`internal/pktbuf`**, which hides syscall batching behind a
one-packet-at-a-time API (see §4); the processing between a read and a send is otherwise direct.
There is **no channel handoff and no worker pool** on the routing path itself — a packet is routed
start-to-finish by the goroutine that dequeued it, through direct synchronous calls. The one
background goroutine a `pktbuf.Reader` adds only *prefetches the next batch*; it never touches the
packet in flight. One receive goroutine per connection; per-connection mutexes guard the senders.
The kernel datapath (`internal/kernelnode`, `datapath: kernel`) does *no* per-packet userspace
work and is out of scope here — it exists for line-rate boxes; this doc is the **userspace**
datapath.

The workload is **cipher-bound**: with a real cipher, the ChaCha keystream XOR dominates
in-process CPU. Everything else on the path is bookkeeping that must stay cheap and, above all,
**allocation-free**.

## 2. The two invariants — do not break these

### 2a. The steady-state datapath allocates nothing

`go test -run '^$' -bench 'BenchmarkNode|BenchmarkHot_' -benchmem ./internal/node/` must report
**0 B/op, 0 allocs/op** for every routed/seal/open/route/finalize step. A single per-packet
allocation shows up as GC pressure at Mpps. How it is achieved:

- Every sender owns a **reused scratch buffer** (or draws one from a `sync.Pool`), sized once and
  refilled in place. `wire.PutEnvelope(dst[:0], …)` appends into that buffer without allocating
  when `dst` has capacity. A batching sender writes straight into its `pktbuf.Writer` arena via
  `Reserve`/`Commit`, which is the reused buffer.
- The receive path de-obfuscates **in place** and the parsed payload **aliases** the read buffer
  (`conn.Ingress` contract) — no defensive copy, because routing consumes it synchronously before
  the buffer is reused.
- A `pktbuf.Reader` reads into fixed batch storage allocated once at construction (`NewBatch`) and
  reused for the life of the connection; `Next()` returns a slice **aliasing** that storage instead
  of a fresh `make`+copy per packet. This is what turned the tun/egress uplink read — historically
  the one steady-state allocation — allocation-free.

If you add a step that must allocate, move it **off** the per-packet path (do it per-connection,
per-flow, or on a timer), or pool the allocation and return it.

### 2b. Buffer-aliasing contracts are load-bearing

Several APIs return slices that alias a reused buffer, valid **only until the next call**; a
caller that retains one must copy it. This is what makes 2a possible — don't "fix" them into
copies:

- `conn.Ingress`'s `payload` (aliases the transport read buffer).
- `pktbuf.Reader.Next()` (aliases the current batch's storage; valid until the next `Next()`). The
  Reader is **double-buffered** — the prefetch goroutine fills a *second* batch while the consumer
  drains the current one — so a whole batch stays stable while it is being drained, and the fill
  never races the reader. A source's `Fill` (`tundev.Device.Fill`, `egress.Netstack.Fill`, a
  transport's frame/GRO fill) publishes views that alias the batch it was handed; those inherit the
  same lifetime.
- The `pktbuf.Writer` flush hands the sink a `views [][]byte` that alias the writer's arena and are
  valid only for the duration of the flush call; a flush that must retain bytes past its return
  (e.g. `tundev.Device.Write` copies into per-slot scratch) copies them.

## 3. Measures taken

Benchmarks below are `internal/node/hotpath_bench_test.go` on an Apple M2 Max (darwin/arm64),
1280-byte packets, discard transports (so numbers are dualnet's own CPU only, no syscalls). Two
sub-suites: `BenchmarkNode/<node>/<dir>` runs the real compiled example mesh; `BenchmarkHot_*`
isolates one primitive. ns/op, before → after:

| step | before | after | change |
|---|---|---|---|
| `Node/router/uplink` (tun→finalize) | 76 | 40 | bound router + finalizer coarse-clock |
| `Node/router/downlink` (recv→tun) | 591 | 386 | cipher word-wise XOR |
| `Node/vps/uplink` (tun→http egress) | 623 | 421 | cipher + finalizer |
| `Node/vps/downlink` (recv→tun) | 586 | 384 | cipher word-wise XOR |
| `Hot_PacketSeal` (chacha4 full, 1280B) | 541 | 337 | word-wise XOR |
| `Hot_PacketSealPartial` (chacha4:256) | — | 101 | partial obfuscation |
| `Hot_PacketOpen` | 545 | 338 | word-wise XOR |
| `Hot_TCPConnectOutSend` | 562 | 365 | word-wise XOR (stream) |
| `Hot_StreamDecode` | 1125 | 712 | word-wise XOR (stream) |
| `Hot_RouteLookup` (unbound, map hash) | 16 | 18 | unchanged path |
| `Hot_RouteLookupBound` (production path) | — | 8 | bound source router |
| `Hot_FinalizerSubmit` | 53 | 18 | coarse-clock + skip rewrite |
| `Hot_GatewayDownlinkSerialize` | 592 | 372 | single-buffer in-place seal + word-wise XOR |

### Cipher — the dominant cost (`internal/cipher/chacha4.go`)

- **Word-wise keystream XOR.** `chachaAddXor` now reads/writes a 32-bit word
  (`binary.LittleEndian`) instead of four byte shifts-and-stores. ~1.6× on full-packet
  seal/open, and it also speeds the TCP/HTTP stream carriers, which share the core. **Keystream
  bytes are unchanged** — a wire-compatible, drop-in speedup.
- **Partial obfuscation — `chacha4:N`. This is the lever for a cipher-bound node** (e.g. a
  Raspberry Pi relaying a speed test at ~90% CPU): the cipher, not syscalls, is the wall, and this
  cuts per-byte cipher work directly. Because chacha4 is *obfuscation, not encryption* (it only has
  to blind content-DPI — see the security note in [data-flow.md](data-flow.md) §8), a connection
  may obfuscate just the first `N` bytes of each packet and leave the tail in cleartext. Works on
  **both** carrier families:
  - *Packet (UDP)* — `cipher.NewPacket("chacha4:256", …)` XORs the first `N` bytes of each
    datagram's payload; the random per-datagram nonce still covers the whole packet, so the head
    differs every time.
  - *Stream (TCP/HTTP)* — `cipher.NewStream("chacha4:256", …)` XORs each frame's 2-byte length
    prefix plus the first `N` payload bytes, leaving the tail cleartext. Writer and reader consume
    the same keystream span per frame (via `wire.FrameWriter`/`FrameReader`), so they stay in sync;
    `N=0` (plain `chacha4`) is byte-identical to and wire-compatible with the old full-stream path.

  At 1280B with `N=256` it is ~3.3× cheaper (packet seal 101 ns vs 337 ns; stream frame write 104
  ns vs 342 ns). `N` is a floor-checked minimum (`minObfsHead`) so the tunnel envelope and inner IP
  header are always hidden and the wrong-key tripwire still sees garbage; the cleartext tail is
  inner ciphertext (e.g. TLS), already high-entropy, so it exposes no recognizable structure to
  DPI. **Both ends must set the same `cipher:` string** (e.g. `cipher: chacha4:256` on a covert
  link's protocol). Validated end-to-end over the TCP covert carrier in netsim.
- **Multi-block ILP was deliberately not pursued.** In pure Go, interleaving several ChaCha
  blocks to fill the pipeline spills the 16+ live state words to the stack and loses more than the
  extra ILP wins — the package comment already records a `[16]uint32`-array attempt that ran ~4×
  *slower*. The 4 quarter-rounds within a round are already independent (intra-block ILP), and
  partial obfuscation cuts the byte count far more than block interleaving would. If you want more
  cipher throughput, add a SIMD assembly core (`_amd64.s`/`_arm64.s`) behind the same
  `XORKeyStream` contract — do not restructure the pure-Go core into indexed arrays.

### Router (`internal/router/router.go`)

Each connection binds its two compiled target lists (unprocessed / processed) **once** at start
via `Router.SourceRouter(name)` (wired in `node.boundIngress`); the per-packet path then indexes
by the `processed` flag instead of hashing a `{bool, source-string}` map key every packet (18 →
8 ns). The finalize function is resolved into the `target` at compile time, removing the
per-packet `finalizers[egress]` map lookup on the gateway path.

### Finalizer (`internal/finalizer/finalizer.go`)

The return-flow map is the gateway's per-packet state in both directions. Now:

- A **coarse clock** (`atomic.Int64`, refreshed on a 250 ms ticker in `Run`) stamps `lastSeen`,
  so the per-packet paths never call `time.Now`. Tests drive it with `refreshClock()`.
- **Skip the map write** when a flow is unchanged and its coarse `lastSeen` has not advanced;
  `RWMutex` lets simultaneous upload (`Submit`) and download (`Run`) reads run concurrently. 53 →
  18 ns.

### UDP send — one buffer, seal in place (`internal/conn/udp.go`, `cipher.SealInPlace`)

Both UDP send paths build `[MsgData?][nonce][envelope+inner]` in a **single** buffer and XOR the
body in place (`PacketCipher.SealInPlace`) instead of serializing into a blob buffer and copying
into a separate sealed buffer. The downlink looks the peer up first (`peers.Registry.SinkFor`) so
it only serializes+seals when there is somewhere to send, and takes **one** pool round-trip
instead of two.

### Locks and hooks

- `TunConn`'s healthcheck hooks are an `atomic.Pointer[hookSet]` — no mutex on the per-packet
  read/send path (`internal/conn/tun.go`).
- `peers.Registry` uses `RWMutex`: `Send`/`Accepts`/`SinkFor` (per-packet) take the read lock;
  `Register`/`GC` (control-rate) take the write lock.

### Sockets (`internal/conn/udp.go`)

UDP carrier sockets request a few-MiB `SO_RCVBUF`/`SO_SNDBUF` (`setUDPBuffers`) so a burst that
arrives while the single reader is busy in the cipher is absorbed rather than silently dropped.
The OS clamps this to `net.core.rmem_max`/`wmem_max` (Linux) or `kern.ipc.maxsockbuf` (macOS) —
**to actually get several MiB, raise those sysctls on the box.** TCP is left to autotune (pinning
`SO_*BUF` there fixes the window and hurts). The gVisor egress emits each reply into reused
`pktbuf.Batch` storage (`egress.Netstack.Fill`, `internal/egress/netstack.go`), so the gateway
download path allocates nothing per reply.

## 4. Batched syscalls (`internal/pktbuf`)

The benchmarks above exclude syscalls; in production each packet costs one or two, and at high
pps that, not the cipher, is the wall on a bulk transfer (a speed test). All batching lives in one
package — **`internal/pktbuf`** — so transports contain no batching, ordering, or flush logic; a
transport supplies one `FillFunc` (read side) or one `FlushFunc` (write side) and the package does
the rest. Both sides are allocation-free at steady state and use fixed memory allocated once.

- **`Reader`** turns a batched source into a one-packet-at-a-time stream (`Next()`). A background
  goroutine prefetches the *next* batch while the caller drains the current one, so the caller
  blocks only when it has emptied the current batch and the next is not yet filled. Two batches
  total, handed back and forth over channels — no per-packet allocation, no lock on the hot path.
- **`Writer`** buffers packets built directly into its arena via `Reserve`/`Commit` and flushes
  them together. It flushes **inline** when the arena or the packet-count cap fills, and a shared
  **`FlushGroup`** (one node-wide goroutine, `flushInterval` = 500 µs) flushes an idle *partial*
  batch so a trickle is never stuck — a full batch never waits, and a single trickled packet adds
  at most one tick of latency. A single arena under one mutex makes flushes serialize in **commit
  order** — the ordering a stateful stream cipher requires — with no per-`Writer` goroutine.

A per-packet fallback is automatic: with `BatchSize == 1` (macOS tun, non-GRO UDP, a stream's
one-frame batch) or a trickle, a batch is one packet and behaves exactly as the old path did.

### Receive side (fewer read syscalls)

Each receive loop is a `pktbuf.Reader` over a transport `FillFunc`:

- **Tun read (`internal/tundev/tundev.go`).** `Device.Fill` reads up to `BatchSize` packets — 128
  on Linux, 1 on macOS — in one syscall (the wireguard driver's vectored `Read`) straight into the
  batch's slots, publishing one aliasing view per packet. The Reader hands them out one at a time
  and prefetches the next syscall's worth while routing drains this one.
- **UDP GRO (`internal/conn/udp_gro_linux.go`).** On Linux the UDP fills set `UDP_GRO` and read
  with `ReadMsgUDPAddrPort` (netpoller-safe — *not* a hand-rolled `recvmmsg` fighting the poller).
  When the kernel coalesces a run of equal-sized datagrams from one flow, the OOB cmsg reports the
  segment size and one `recvmsg` returns the whole run; `splitGRO` publishes each segment as its
  own view (each carries its own nonce, de-obfuscated independently). `ReadMsgUDPAddrPort` returns
  a value-type `AddrPort`, so the read stays free of the per-datagram `*net.UDPAddr` allocation.
  Off Linux (`udp_gro_other.go`) and for a WARP userspace conn, `readGRO` falls back to a
  single-datagram read (`segSize == 0`) — byte-for-byte the old path. Coalescing is opportunistic
  (it only fires when same-size datagrams arrive back-to-back, i.e. a bulk download); correctness
  does not depend on it.
- **Buffered stream reads (`internal/conn/tcp.go`).** The TCP carrier's frame `Fill` sits on a
  `bufio.Reader` (`tcpReadBufSize`), so a burst of frames is pulled from the kernel in one read
  instead of two syscalls per frame (the 2-byte length, then the body). The stall-reaping read
  deadline is refreshed only when `br` is empty (about to block), so frames already buffered from
  one socket read cost no extra `SetReadDeadline` syscall. The HTTP carrier gets the same kernel
  buffering from `net/http`'s body. A stream batch is one frame (net/http and bufio expose no
  portable "read many frames" primitive), but the Reader still overlaps decrypt of the next frame
  with routing of the current one.

There is no aliasing-lifetime hazard: the Reader's double-buffering keeps a batch stable while it
is drained, and each datagram/frame is de-obfuscated and routed before the next `Next()`.

### Batched writes (the download win, and the upload hop)

A bulk download to a userspace node ends at a tun write; a relay's forward hop is a carrier send.
Historically both were one `write` syscall per packet. Each is now a `pktbuf.Writer`; the sender's
`Send` builds the packet into the writer's arena and the writer flushes a whole batch at once:

- **Tun downlink (`internal/conn/tun.go`).** `TunConn.Send` copies the packet into the writer arena
  (copying, not aliasing the carrier's reused read buffer, keeps it safe when several carriers feed
  one tun concurrently). The flush is `tundev.Device.Write`, which hands the driver up to
  `BatchSize` packets at once so it **GRO-coalesces same-flow runs into GSO superframes** — far
  fewer, larger tun writes for a bulk TCP/UDP download. (`tunWriteArena` = 128 KiB, `tunWriteBatch`
  = 64.)
- **Gateway reply path (`internal/finalizer/finalizer.go`).** The finalizer reads egress replies
  through a `pktbuf.Reader` over `egress.Fill` and routes each straight to its owner's reply target,
  which buffers into *its own* writer and self-flushes — so a gateway that reflects replies to its
  **own** tun (e.g. the vps V2Ray tun) batches them via the tun writer above, with no special-case
  flush plumbing. The uplink `Submit` also buffers into an inject writer (flush = `egress.Write`)
  for uniformity, though the userspace gVisor egress still injects one packet at a time
  (`InjectInbound`, no OS batch), so that side coalesces lock/flush overhead, not syscalls.
- **Stream sends (`internal/conn/tcp.go`, `internal/conn/http.go`).** The TCP connect-out uplink
  and the TCP/HTTP listen-out downlink (one writer *per peer stream*) buffer enveloped blobs and
  flush a whole batch of length-prefixed frames through a `bufio.Writer` over the socket (or one
  `ResponseController.Flush` for HTTP), coalescing into a few large socket writes and larger TCP
  segments. A partial flush would desync the stateful stream cipher, so the single-arena-under-one-
  mutex commit ordering (§4 intro) is load-bearing here; a write error tears the stream down and
  the client reconnects fresh. `streamWriteBatch` = 64 packets, `tcpWriteBufSize` = 128 KiB.

A stream carrier **never dials from a flush**: `tcpConnectOut.flush` runs on the shared
`FlushGroup` goroutine, where a blocking dial (up to `tcpDialTimeout`) would freeze every other
`Writer` on the node — stalling unrelated tun-downlink partials and, worse, healthcheck pings
buffered in sibling carriers, which can false-trip a path to dead. So a disconnected flush kicks a
**background** dial and drops the batch (`ErrBackoff`; the inner TCP retransmits); the dial installs
the socket off the flush path when it completes.

### Still on the table — UDP send GSO

The UDP send paths (connect-out uplink, listen-out downlink) still do one `WriteTo` per packet.
Coalescing them needs `UDP_SEGMENT` GSO / `sendmmsg` to group equal-sized datagrams — a different
mechanism than `pktbuf.Writer`'s stream/tun batching — so it is left as a follow-up. The stream and
tun write paths (the download and forward-hop headline) are already batched.

## 5. Rules for new code on the hot path

**A new transport (`internal/conn`)** should **not** hand-roll batching or flushing: drive its
receive loop with a `pktbuf.Reader` (supply a `FillFunc` + a `NewBatch` factory) and its send with
a `pktbuf.Writer` registered on the node's `FlushGroup` (supply a `FlushFunc`). Then it must reuse
the writer arena / a pooled send buffer (never `make` per packet); de-obfuscate in place and
deliver a payload that aliases the read buffer; take at most one lock per packet; keep `time.Now`,
`rand`, logging, and map writes off the per-packet path; **never block in a `FlushFunc`** (it runs
on the shared flush goroutine — dial/reconnect asynchronously, drop the batch); and add a
`BenchmarkHot_*` proving 0 allocs/op for its steady send/receive. Framed (stream) carriers
implement `wire.FrameWriter` so the length prefix does not escape to the heap.

**A new cipher (`internal/cipher`)** implements `Seal`/`SealInPlace`/`Open` (packet) or
`WrapWriter`/`WrapReader` (stream) with reused/in-place buffers, and must be safe for concurrent
`Seal` (the packet cipher is stateless per datagram). Keep the pure-Go core in scalar locals, not
indexed arrays (register pressure); ship SIMD as build-tagged assembly behind the same contract.

**A new routing/finalizer feature** must stay off the per-packet path unless it is a pointer load
or an integer compare. Coarse-clock anything time-based; skip redundant map writes; prefer a bound
per-source closure over a per-packet map lookup.

**Verifying a hot-path change:**

```
go test -race ./...
go test -run '^$' -bench 'BenchmarkNode|BenchmarkHot_' -benchmem ./internal/node/   # 0 allocs/op
GOOS=linux GOARCH=amd64 go build ./...   # gateway cross-compiles
```

For datapath/syscall changes, also drive the real OS stack end-to-end:
`go run ./cmd/netsim -network <a direct-egress network doc>` (netsim cannot simulate a `warp`
egress) and `go test -tags e2e ./test/e2e`, then an iperf3 pass through netsim to measure the
actual pps/throughput delta. Profile with the recipe in the `hotpath_bench_test.go` header
(`-cpuprofile`/`-memprofile`, `go tool pprof -top [-alloc_objects]`).
