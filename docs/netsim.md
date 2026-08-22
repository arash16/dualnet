# netsim — deterministic, offline network simulation & testing

`netsim` takes **any** dualnet network schema (`docs/examples/network-old.yaml` or your own) and
stands it up as a fully-containerised, **offline** simulation on a local Docker daemon, then
runs a test matrix **derived from that network's own paths and conditions**. It exercises the
*real* node runtime and the *real* OS networking (tun devices, `iptables` MASQUERADE,
`ip route`/`ip rule`, LAN forwarding, default-route capture, per-interface + source-IP socket
binding) against a **simulated internet** — no real hosts, no `1.1.1.1`, nothing outside Docker.

This is the real-stack complement to the in-process `internal/node` mesh tests (which fake
tuns/egress and skip all OS config).

## Run it

```sh
# Test the 3-node example network (builds the image the first time):
go run ./cmd/netsim -network docs/examples/network-old.yaml

# Test your own network — the scenarios adapt automatically:
go run ./cmd/netsim -network my-network.yaml

# Useful flags:
#   -only failover     run only scenarios whose name contains this
#   -keep              leave the mesh running for `docker exec` debugging
#   -no-build          reuse the existing dualnet-sim:test image
#   -no-psk-check      skip the PSK-mismatch negative run
```

As a Go test (skips cleanly when Docker is unavailable, so plain `go test ./...` is unaffected):

```sh
go test -tags e2e ./test/e2e
```

## What it asserts (derived from the schema)

For each **path branch** it builds a scenario:

- a branch reachable with all gateways healthy → a **routing** assertion: drive a probe that
  selects that branch and confirm — via the source IP the simulated internet echoes back —
  that the flow left through the branch's egress (tunnel gateway vs a local direct egress);
- a branch only reachable once an upstream **healthcheck** fails → a **failover + self-heal**
  assertion: pause the gateway container, confirm the fallback egress fires, unpause, confirm
  it heals back;
- a locally-fed (v2ray-style) tun origin is driven by **packet injection** at its debug-tun
  instead of a LAN client;
- a **kernel-datapath** node (policy-routing forwarder) gets one probe per forward branch — a
  `src_in` branch driven from a LAN client bound to the leg source IP, a `dst_in` branch to the
  geo destination, the default to the world destination — each asserting the observed egress
  source IP (which WAN the kernel steered it out), plus a SIGHUP reload for its geo set;
- a kernel-datapath **`warp`** egress is simulated as a real kernel WireGuard tunnel: the hub
  also plays Cloudflare, so a branch exiting through it asserts the observed source is the
  generated tunnel address (not the underlay IP) — confirming the wg device came up, handshook,
  and masqueraded LAN traffic through the tunnel.

Plus: a **SIGHUP prefix-reload** assertion for every `dst_in` condition, a **PSK-mismatch**
negative (one node's key broken → its no-fallback path stops round-tripping), and a
**no-leak** stats check (every node reports zero `no_route`/`decode` drops on the clean paths).

For the 3-node `network-old.yaml` this derives exactly: `route/lan/egress-ftth` (geo/`is-iran`
→ FTTH direct), `route/lan/gw-turkish-internet` (tunnel), `failover/lan/egress-starlink`
(Turkey down → Starlink, then heal), `route/vps/gw-turkish-internet` (vps origin round-trip),
`sighup/lan`, and `psk-mismatch/vps`.

## How it works (architecture)

The engine is **decoupled** from the node runtime — dependencies point inward, and the
production `dualnet` binary never imports it or the Docker SDK:

```
cmd/netsim / test/e2e ─→ internal/netsim (engine, no docker dep) ─→ internal/netschema (schema)
                                    │ Driver interface (IoC)
                                    └─→ internal/netsim/dockerdriver  (the only Docker SDK user)
```

- **`netsim.Plan(net)`** is a pure function: it derives the L2 fabrics (a union-find over
  link/egress/LAN interfaces), a deterministic IP plan, per-node sim configs (acceptor IPs and
  interface names rewritten to fixed `dnN` devices), and the per-container setup specs — with
  no I/O, so it is unit-tested with no Docker.
- **`netsim.Scenarios(net, plan)`** derives the test matrix above, also pure.
- **`netsim.Run(...)`** drives a `Driver` to build the image, create the fabrics + containers,
  and execute the scenarios. `dockerdriver` is the only backend today; the `Driver` seam keeps
  a compose/netns backend possible without touching the engine.
- **`test/sim`** is the in-container helper image (`dualnet` + a `sim` binary): `sim init`
  (entrypoint: rename NICs by subnet, add routes/addresses, bring up any kernel WireGuard
  devices the spec carries, then exec), `sim echo` (the simulated internet — echoes the observed
  source IP over HTTP and UDP), and `sim probe` (HTTP — optionally bound to a source IP via
  `-src-ip` for the kernel `src_in` test — or a debug-tun injector; both poll-until-converged).
  For a kernel-`warp` egress the engine generates a deterministic wgcf-style profile per egress
  and programs a matching WireGuard peer on the hub (device `wg-sim`, CGNAT tunnel addresses in
  `100.64.0.0/24`), so the node's `warp` egress dials the hub instead of the real Cloudflare.

## One run at a time, always cleaned up

Every run creates Docker networks on shared fixed subnets, so two concurrent runs would
collide. Before starting, a run scans the process list (no lock files — a crash never strands
a lock): if another sim is already running it **exits immediately**; otherwise it first
**removes any leftover `netsim-*` resources** from an earlier crashed run, then proceeds. On
completion — including on `SIGINT`/`SIGTERM` — it force-removes every network and container it
created (matched by name prefix, so teardown is complete even after a partial run). A
hard-`SIGKILL` can't clean up, but the next run's pre-clean sweeps it. `-keep` opts out of the
final teardown for debugging (the next run cleans it up).

## Requirements

A reachable Docker daemon (Docker Desktop, OrbStack, or colima all work; `DOCKER_HOST` and
the active Docker CLI context are both honoured). Containers run with `NET_ADMIN`/`NET_RAW`;
those that open a tun also get `/dev/net/tun` (a kernel-datapath node forwards in the kernel and
does not).

A **userspace** `warp` egress is rejected — it needs the real Cloudflare WARP and cannot be
simulated. A **kernel-datapath** `warp` egress *is* simulated (the hub terminates a real kernel
WireGuard tunnel), but this requires the **Docker host kernel** to provide the `wireguard`
module — Docker Desktop and OrbStack ship it, a custom colima/lima VM may not. A run that needs
it probes the host up-front and fails fast with `ErrNoKernelWireGuard` (the `-tags e2e` test
skips instead of failing) rather than hanging on a handshake that can never complete. Verify a
host manually with:

```sh
docker run --rm --cap-add NET_ADMIN dualnet-sim:test ip link add wg0 type wireguard
```
