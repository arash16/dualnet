# AGENTS.md

Orientation for agents working in this repo. High-level only.

## What this is

**dualnet** is a single Go binary that runs one **node** in an asymmetric link-bonding VPN mesh.
A node is defined entirely by YAML: a list of **connections** and a **routing table**. *Client*,
*router*, and *gateway* are just different configurations of the same runtime, not different
programs. The headline use case is sending traffic up one link (fast but censored) and receiving
it down another (clean), via a relay that reaches the internet — see [README.md](README.md).

Read these before non-trivial work (don't rely on this file alone):

- [README.md](README.md) — features, config surface, build/run, security posture, layout table.
- [docs/protocol.md](docs/protocol.md) — the wire protocol, implementation-independent: owners,
  the envelope, the finalizer, healthcheck, the kernel datapath, and the security note.
- [docs/data-flow.md](docs/data-flow.md) — how a config becomes a running node; identity,
  routing, finalizer, peer id assignment; **§9 is a file map**; §8 is the security model.
- [docs/netsim.md](docs/netsim.md) — the offline Docker end-to-end simulator.
- [docs/performance.md](docs/performance.md) — the packet hot path: the zero-allocation and
  buffer-aliasing invariants, what was optimized, and the rules for new transports/ciphers.

## Core design decisions

- **Routing is by `owner` (a random 4-byte id) + a `processed` bit, not by IP.** Each inter-node
  packet carries a tiny obfuscated envelope `[owner:4][flags:1]`; the routing table matches
  `{processed, source-connection}` → `target`. One `finalizer` per gateway egress flips
  `processed` false→true and remembers where each flow's reply goes.
- **Data plane is obfuscation, not cryptography; control plane is authenticated.** Inner data
  packets are unauthenticated by design (a PSK holder can spoof owners — the one deliberate gap);
  the optional `chacha4` cipher only defeats content-DPI. But peer registration / id-assignment
  (UDP datagrams and HTTP headers alike) carry a PSK-keyed HMAC tag **plus a monotonic freshness
  stamp**, so scanners can't register and captured control records can't be replayed. Resource
  use is bounded against floods; the userspace egress refuses SSRF destinations. See data-flow §8.
- **Two datapaths.** `userspace` (the packet router above) and `kernel` (a policy-routing +
  iptables forwarder for line-rate boxes, `internal/kernelnode`). A node picks one.
- **Whole-mesh schema → per-node configs.** `internal/netschema` compiles one network document
  (`docs/examples/*.yaml`) into per-node `config.Node`s and a deploy bundle (`internal/release`).
  **The PSK is never baked into a generated artifact** — it is delivered via `DUALNET_PSK`, which
  overrides the file at runtime.
- **Transports are pluggable behind `internal/conn`** (`http`, `udp`, `tcp` — the last a
  plain framed byte stream, the http stream carrier minus its request/response dressing);
  ciphers behind `internal/cipher`. The rest of the stack is transport/cipher agnostic.

## Project state

**Greenfield: no live deployment, single-operator, no users yet.** There is **no
backward-compatibility obligation** — wire formats, config schema, and APIs may change freely.
Prefer fixing and cleaning over preserving old behavior or dead code.

## How to work here

- **Test before fixing.** For a bug, first write a test that *proves* it (watch it fail), then
  fix and watch it pass. Don't add only-failing tests; also add coverage for correct-but-untested
  behavior (edge/corner cases, both good and bad paths) so future changes can't silently regress.
  A passing test that asserts the wrong thing is worse than none — avoid false positives.
- **Keep it green.** No backward-compatibility obligation — `go test -race ./...`, `go vet ./...`, 
  and `gofmt -l` must all be clean, and the gateway target must cross-compile: `GOOS=linux GOARCH=amd64
  go build ./...`. Linux-only code lives in `*_linux.go` (e.g. `kernelnode/run_linux.go`); keep its
  pure logic in cross-platform files so it stays testable on any host.
- **NEVER EVER Repeat yourself.** Always research for existing code, whether it could be refactored,
  reused, or extended first.
- No obvious comments, no comments of what you're going to do, or task descriptions. Comments 
  should explain *why* the code is that way, not *what* it does. The code itself should be clear 
  enough to read without a comment.
- **Tests are self-contained.** Name test files after the unit/behavior they cover; write comments
  that make sense to a future reader with no knowledge of the change that introduced them (no
  ticket/finding IDs, no "this session", no dated references — convert relative dates to absolute).
- When a task and implementations is complete and finished, in the end suggest to review and update
  documents. Only do so once approved by the user.
- **The hot path is packet forwarding and it is cipher-bound.** Keep the steady-state data path
  **allocation-free** (it largely is — see benchmarks in `internal/node/hotpath_bench_test.go`,
  run with `-benchmem`). Put per-connection / per-flow / control work off the per-packet path.
- **netsim / e2e need Docker** and exercise the real OS stack (`go run ./cmd/netsim -network …`,
  or `go test -tags e2e ./test/e2e`); plain `go test ./...` skips them. Only touch them
  deliberately.
- **Deploy / outward-facing actions** (compiling+shipping configs, k8s manifests) are generated by
  `internal/release`; the PSK must stay out of every artifact.
- Your internet connection is through the same `router` defined in network schema. Always be extra
  careful when deploying changes to it — you can easily lock yourself out of your own network.

## Layout

The README has a package table and data-flow.md §9 a concern→file map. In short: `internal/wire`
(envelope/framing/psk/ping), `internal/cipher`, `internal/conn` (+`auth.go`, `control.go`),
`internal/peers`, `internal/router`, `internal/finalizer`, `internal/healthcheck`,
`internal/egress`, `internal/netcfg`/`netbind`/`tundev`, `internal/config`, `internal/node`
(userspace runtime), `internal/kernelnode` (kernel runtime), `internal/netschema` (compiler),
`internal/release` (deploy bundle), `internal/netsim` (+`cmd/netsim`, `test/`).
