# dualnet

A **generalized asymmetric link-bonding VPN**. dualnet is a single Go binary that runs
one **node** in a mesh. Each node is defined entirely by a YAML config — a list of
**connections** and a **routing table** — so *client*, *router*, and *internet-gateway*
are just different configurations of the same runtime, not different programs.

It was built for this situation, and it still does it best:

- **FTTH (fiber)** — fast **uplink**, but **censored** (government DPI). Used to *send*.
- **Starlink** — fast **downlink** (uplink jammed), **not censored**. Used to *receive*.

Send your traffic up one link and receive it down another, via a relay that reaches the
real internet — so heavy flows ride a fast link in **both** directions (a download comes
down Starlink while its TCP ACKs go up FTTH). The generalization lets you chain this across
many nodes (phone → in-country VPS → out-of-country gateway, each hop picking its own
link), not just one client and one relay.

```
              uplink   (censored FTTH, HTTP POST — looks like a big upload)
   ┌──────────┐  ═══════════════════════════════════════════════►  ┌───────────┐
   │  client  │                                                     │  gateway  │ ═► internet
   │  (tun)   │  ◄═══════════════════════════════════════════════  │  (NAT)    │ ◄═
   └──────────┘  downlink (clean Starlink, UDP datagrams)           └───────────┘
```

## The model in one paragraph

A node opens its **connections** and routes packets between them by a **routing table**.
Identity is not an IP address: each **tun** connection has a random 4-byte **owner** id,
and every inter-node packet carries a tiny obfuscated envelope `[owner:4][flags:1]` (the
flag marks whether it has been *processed* — i.e. been to the internet). A routing row
matches on `{processed, source-connection}` and forwards to a `target` connection; a row
with an `egress:` name hands the packet to the node's **finalizer** (that named internet
egress) and remembers where that flow's reply should go. Connections come in three types — `tun`
(local device), `connect` (we dial), `listen` (we accept) — each with a direction
(`outgoing` = we send, `incoming` = we receive) and a transport (`http`, `udp`, or `tcp`). A
`listen`+`outgoing` connection marked `multiple` tracks many downstream peers, minting a
4-byte id for each and handing it back so return traffic can be demultiplexed by owner.

> **Security posture:** the **data plane is obfuscation, not cryptography**; the **control
> plane is authenticated**. By default a connection uses **no** cipher — inner packets ride the
> wire as raw data. The opt-in `chacha4` cipher is a reduced-round (4 instead of ChaCha20's 20)
> ChaCha keystream XOR — enough to beat content-matching DPI, *not* confidentiality or data
> authentication; there's no cryptanalytic margin to defend here since dualnet is currently a
> single-operator protocol with no live deployment. Inner *data* packets are therefore
> unauthenticated (a PSK holder can inject arbitrary owners — the one deliberate gap). But the
> **control channel is not**: peer registration / id-assignment (UDP datagrams and HTTP headers
> alike) carry a PSK-keyed HMAC tag plus a monotonic freshness stamp, so an off-path scanner
> cannot register a peer and a captured control record cannot be **replayed** to hijack a return
> path. Resource use is **bounded** against floods (finalizer flows, peers, egress flows, HTTP
> connections; stalled bodies and undecodable-frame floods are torn down), and the userspace
> egress refuses **SSRF** destinations (link-local / `169.254.169.254` metadata / loopback /
> multicast). For stronger DPI resistance, add a TLS/WebSocket/QUIC carrier behind the connection
> interfaces in `internal/conn` — nothing else in the stack changes.

## Config

A node config is YAML: a global `psk`/`mtu`/`subnet`, a list of `connections`, an optional
`egress` (the finalizer), and a `routes` table. See [docs/examples/](docs/examples/) for a
complete, runnable five-node mesh (turkish gateway, hpi router, vps router+tun, phone,
laptop). A minimal client:

```yaml
psk: choose-a-shared-secret          # or provide via DUALNET_PSK / -psk
subnet: 10.9.0.0/24
connections:
  - name: Down                        # receive over the clean link
    type: connect
    direction: incoming
    transport: udp
    ip: 203.0.113.9
    port: 8081
    interface: en0                    # Starlink
    id_setter: Tun                    # the gateway mints this tun's owner id
  - name: Up                          # send over the censored link
    type: connect
    direction: outgoing
    transport: http
    ip: 203.0.113.9
    port: 8080
    interface: en12                   # FTTH
  - { name: Tun, type: tun, address: 10.9.0.2, capture_default: true }
routes:
  - { match: { source: Tun,  processed: false }, action: { target: Up } }
  - { match: { source: Down, processed: true  }, action: { target: Tun } }
```

Per-connection fields: `type`, `direction`, `transport` (`http`|`udp`|`tcp`), `port`, `ip`
(connect), `interface` (physical link to pin, or tun device name), `cipher`
(`chacha4`|`none`), `psk` (override the global), `warpped` (connect: dial the transport
through WARP; http only), `multiple` (listen+outgoing: track many peers), `id_setter`
(connect+incoming: the local tun a Multiple remote assigns an id to), an optional `http`
block on `transport: http` connections (`upload_path`, `download_path`, `host`,
`user_agent`, `id_header`, `headers`) that dresses the carrier up as an ordinary web
service, and for tuns `address` (inner IP, unique per owner) and `capture_default` (route
all traffic into the tun).

The three transports carry the same obfuscated frames: `udp` is a per-datagram carrier;
`http` is a stream carrier dressed as a long-lived upload/download so it blends into web
traffic; `tcp` is that same stream with the HTTP dressing stripped — a plain framed byte
stream for links that only need to pass raw TCP (some middleboxes) and want neither the
per-packet chunk framing nor the header overhead. `tcp` and `http` share every internal —
framing, cipher, the authenticated register/id-assign handshake — so they behave
identically apart from what rides on the wire.

In the whole-mesh [network schema](docs/examples/network.yaml) these carrier settings
(plus `cipher`/`warpped`) live on a **named protocol** in the root `protocols:` map that a
link references by name, so both ends of a link share one definition; `dualnet compile`
resolves the name and writes the concrete `transport`/`http` fields into each node config.

**Links & routes are one-liners.** A link is `<name>: <dialer>[.<conn>] <arrow>
<acceptor>[.<conn>] (<protocol>, <port>)` — the arrow gives direction (the dialer is always on
the left): `->` the dialer sends, `<-` the acceptor sends; double the point (`->>`/`<<-`) for
`multiple`, and embed a dialer tun-connection name (`-utun9>`/`<utun9-`, or with `multiple`
`-utun9>>`/`<<utun9-`) to have the acceptor assign that tun's owner id (the multi-client
downlink pattern). A path's `routes` is an ordered switch-case, `<condition>: <up-link> > … >
(<egress>) > <down-link> > …`
(a lone `(egress)` is a local exit): tokens before the parenthesized egress are up-links, tokens
after are down-links, the gateway is inferred as the up-path's terminus, and a final `default`
key is the always-last catch-all. A path's `name:` is optional — set it only so a healthcheck
condition can reference the path. (The link/route DSL parsers live in `internal/netschema/dsl.go`.)

**Datapaths & source-IP routing** ([docs/examples/home-bond.yaml](docs/examples/home-bond.yaml)).
A node's `datapath` is `userspace` (default — the packet router above) or `kernel`. A **kernel
node** does no per-packet userspace work: it programs `ip rule`/`ip route` + iptables
MASQUERADE so the box forwards near line rate (hardware-offload-friendly) — the right choice
for a plain fast router that only needs geo/policy splitting, where a userspace gVisor egress
would cap a slow CPU at tens of Mbps. It declares no tun/links/cipher; only `connections`,
`egresses`, and `paths` whose branches pick an egress by condition. A node's **`connections`**
map names its attachments (the key is the name). Each is an interface binding — `name: { iface:
<device>, ip?: <addr/mask> }`, referenced by an egress's `exit` and a link's `.conn` — or a
**tun** — `name: { type: tun, iface?: <device>, ip: <addr>, capture_default?, lan? }` (a node
may declare several). A binding with an `ip` is one dualnet **creates** on that device so a link
can bind it as its socket source (`dialer_source`/`acceptor_source`) — the mechanism behind
asymmetric bonding: an up-leg bound to a marked source IP that the router policy-routes onto the
fast-upload WAN. Conditions are `dst_in` (match destination) or `src_in`
(match source; kernel-only, lowered to `ip rule from`), each an IP set given as a `file`
(reloadable on SIGHUP) or an inline `list`. On a `kernel` node's path, branch order is fixed:
`src_in` branches, then `dst_in`, then one default.

**Tun routing.** `capture_default` is per-tun and defaults to `false`: dualnet creates and
addresses the device but does **not** make it the system default route, so your apps' egress
is untouched (only the tun's own subnet is routed into it). Set it `true` on a client that
should send *everything* through the tunnel. Omit `address` entirely for a **raw** tun:
dualnet just creates and brings the device up and touches no addressing/routing, leaving all
of that to an external tool (e.g. a v2ray server that consumes the tun directly).

**Stats.** Stats are **off unless `stats_file` is set** (no file → no collection, zero
hot-path overhead). When set, each node appends a JSON snapshot every `stats_interval`
(default 10s): per-connection `recv`/`sent` packets **and bytes** (including the gateway's
finalizer reply path, so the download direction is visible), per-rule match counts,
dropped-packet totals (`no_route` vs `decode`), and the peak heap / `Sys` / goroutine count
over each interval — so a slow leak shows as a rising max. The file is **rotated** to
`<base>-old<ext>` once it reaches `stats_max_mb` (default 10; `<0` disables), keeping only
the current file plus one previous rotation. Writing is best-effort (a node that can't open
the file logs and keeps running). Override at runtime with `-stats <path>` / `DUALNET_STATS`
and `-stats-interval <sec>`. To see throughput per link (bytes/interval → the real
bottleneck), e.g.:
`jq '{t:.time, up:.conns."hpi-up".recv_bytes, down:.conns."turkish-laptop".sent_bytes, drops:.drops}' stats.jsonl`.

Config precedence for the global PSK: `-psk` flag > `DUALNET_PSK` env > `psk:` in the file.

## Build

```sh
go build -o dualnet .

# static Linux gateway binary from macOS
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dualnet-linux .
```

## Run

```sh
export DUALNET_PSK='choose-a-shared-secret'
sudo ./dualnet -config /etc/dualnet/node.yaml
```

Default config search order (if `-config` is omitted): `~/.config/dualnet/node.yaml` then
`/etc/dualnet/node.yaml`. Under `sudo` it still reads the invoking user's `~/.config`.

Notes:
- Use the remote's **IP** (not a hostname) for a `connect`'s `ip` when a local tun captures
  the default route — DNS would otherwise try to resolve through the not-yet-up tunnel.
- On macOS a tun with `capture_default` installs the two `/1` routes (def1 trick) and pins a
  scoped `/32` to each `connect` remote via its link, so the `IP_BOUND_IF` sockets keep a
  route after the default is redirected. Per-link egress is forced with `IP_BOUND_IF`
  (macOS) / `SO_BINDTODEVICE` (Linux), **not** the routing table.
- `mtu` defaults to 1360; the 5-byte envelope plus per-hop carrier overhead sit under it.

### Startup

Before it configures anything, a node runs two preflight steps so a restart (systemd
`Restart=always`, a manual re-launch, or an rsync redeploy) is clean:

- **Single instance.** It finds any other running process started from the *same binary
  path*, sends it `SIGTERM`, and waits for it to shut down gracefully (escalating to
  `SIGKILL` only after a grace period) before continuing — so two nodes never fight over the
  tun, routes, and listening sockets. Matching is by executable path, so unrelated tools are
  never touched.
- **Wait for interfaces.** It blocks until every physical interface it binds to or egresses
  through (a connection's `interface`, a capture tun's `lan_iface`, an egress's `exit`, plus a
  kernel node's LAN devices) is up with a usable IPv4 address. This lets a node started at boot wait for a slow uplink —
  notably a PPPoE link (`ppp1`) that only exists once its session is established — instead of
  failing to bind. It waits indefinitely (logging what it is waiting for) and exits cleanly on
  `SIGINT`/`SIGTERM`.

### Reliability

- **Per-tun healthcheck.** A tun periodically injects a reflected ping that travels its full
  path to the gateway and back; the gateway reflects it at the process point without
  egressing it. If no reply arrives within the timeout, the node reconnects **that path's**
  `connect` connections (scoped to the path, so one path's outage never tears down another's).
  Cadence via `healthcheck` (seconds: `-1` never, `0` lazy, `N` fixed; default 15) and
  `healthcheck_timeout` (default 90). Lazy mode (`0`) probes only while traffic flows and does
  not spuriously fail over when traffic resumes after an idle gap.
- **Channel upkeep.** A UDP `connect`+`incoming` connection re-primes its CGNAT mapping
  (fast warm-up then every 15s) so replies keep arriving; an HTTP `connect`+`outgoing`
  recycles its long POST periodically to look like ordinary finite uploads.
- A `multiple` listener supersedes a reconnecting peer's stale handler, so there is no
  server-side connection/goroutine leak across reconnects.

## Hide the gateway IP with Cloudflare WARP

Set `egress.mode: warp` on a gateway node and its internet egress goes out through
**Cloudflare WARP**, so sites see a Cloudflare IP instead of your server's.

```yaml
egress:
  mode: warp
  warp_cache: /var/lib/dualnet/warp.json   # auto-registers a free account on first run
  # warp_config: /path/to/wgcf-profile.conf  # or use an existing wgcf profile
```

On a **userspace** node this is fully in-process (an embedded userspace WireGuard device) —
**no `wg`/`wg-quick`, no kernel TUN, no NAT, no routing-table changes**.

On a **`datapath: kernel`** node the same egress becomes a **kernel WireGuard device** (created
with `ip link add … type wireguard`, programmed via netlink) so the tunnel runs at in-kernel
line rate. Two things differ from the userspace form:

- `exit:` is **required** — it names the underlay WAN the tunnel's own encrypted UDP leaves
  through. dualnet pins the resolved endpoint as a `/32` host route via that underlay so the
  tunnel can never be routed back into itself. `tun_name:` overrides the device name (default
  `warp-<egress>`).
- The host kernel must provide the **`wireguard` module** (containers cannot `modprobe`, so it
  is a host prerequisite for a k8s/container deploy). Kernel WireGuard sends the header's
  reserved bytes zeroed — which wgcf-registered WARP accounts accept, the same way a wgcf
  profile works with a stock WireGuard client. Point `warp_cache` at a **persistent** path so
  the node reuses one account instead of re-registering (and risking rate limits) each boot.
- `warp_insecure: true` skips TLS verification on the one-time Cloudflare **registration** call,
  for a minimal router image that ships no CA bundle (the symptom is `x509: certificate signed
  by unknown authority` on first boot). It affects only that HTTPS handshake — the WireGuard
  tunnel authenticates with Noise, not TLS. Prefer installing CA certificates, or pre-registering
  once and shipping the account via `warp_config`/`warp_cache`, where it can be omitted.

A per-connection `warpped: true` is a *different* use of WARP: it tunnels that connection's
**transport** through WARP (hiding the node's IP from the remote). It is restricted to
`http` because WARP's 1280 MTU would fragment UDP.

## Verify

```sh
go test ./...
```

Covers: envelope/framing/obfuscation round-trips (incl. cross-call keystream continuity) and
wrong-key rejection; the routing engine (compile-time validation, target selection, drop); the
finalizer's owner/target return routing, ping reflection, GC and flow cap; the peer registry's
id minting, replay rejection and cap; config parse/validation and the shipped example configs;
and — the headline — an in-process **full five-node mesh round-trip**
(`internal/node/mesh_test.go`) over real loopback HTTP/UDP with faked tuns and a reflecting fake
egress, asserting the phone-, laptop-, and vps-origin flows complete with the correct
owner/processed state at every hop, including id-assignment. Behavioral near-e2e tests add
destination-based (geo) routing and a stats round-trip.

**Adversarial coverage.** An attacker-mindset suite asserts the security boundaries hold: a
no-PSK scanner cannot register a peer; a captured control datagram / download GET cannot be
**replayed** to hijack a return path; a MITM cannot force a tun to adopt a forged owner; a
wrong-PSK peer's data is dropped; resource maps (finalizer flows, peers) stay bounded under a
flood; the egress refuses SSRF destinations; and `go` **fuzz** targets (run their seed corpus
under a plain `go test`) prove the wire/cipher/control parsers never panic on hostile input.

For a **real-stack, offline** end-to-end test — the actual node binary exercising real tun
devices, `iptables` NAT, routing, LAN capture/forward and per-interface binding against a
*simulated* internet — use the **netsim** engine, which derives its test matrix from any
network schema's own paths and conditions:

```sh
go run ./cmd/netsim -network docs/examples/network-old.yaml   # needs a local Docker daemon
go test -tags e2e ./test/e2e                                  # same, as a Go test
```

It covers the tunnel happy path, geo/`dst_in` direct routing, healthcheck failover + self-heal,
the vps-origin round-trip, SIGHUP prefix reload, a PSK-mismatch negative, and a zero-drop
no-leak check — all deterministic and with no dependency on the real internet. See
[docs/netsim.md](docs/netsim.md).

## MSS clamping (fallback, if large transfers stall)

- **Linux gateway:** `iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`
- **macOS client (pf):** `scrub out on utunN proto tcp all max-mss 1320` in an anchor, loaded with `pfctl`.

## Layout

| Path | Role |
|---|---|
| `internal/wire` | envelope (`owner`+`processed`), length-prefix framing, PSK key/tag, inner-IP + ping helpers |
| `internal/cipher` | pluggable obfuscation: `StreamCipher`/`PacketCipher` + `chacha4`, `none` |
| `internal/conn` | connections by kind (tun / connect±in/out / listen±in/out) over `http`/`udp`/`tcp`; `Conn`+`Sender`, factory |
| `internal/peers` | per-`listen+outgoing` registry: mint/track downstream peers by owner id |
| `internal/router` | compiles the routing table to ordered target lists; evaluates per packet |
| `internal/finalizer` | internet egress wrapper: owner/target return conntrack + ping reflection |
| `internal/healthcheck` | per-tun end-to-end reflected-ping liveness + reconnect |
| `internal/egress` | egress backends: kernel TUN+NAT, or userspace WARP netstack |
| `internal/warp` | Cloudflare WARP: register/cache + userspace WireGuard dialer + kernel WireGuard device (kernel datapath) |
| `internal/netbind` | per-interface + source-IP socket binding (`IP_BOUND_IF` / `SO_BINDTODEVICE` + `LocalAddr`) |
| `internal/pktbuf` | batched packet I/O: prefetching `Reader`, buffering `Writer`, shared `FlushGroup` — hides syscall batching from transports |
| `internal/tundev` | tun read/write over `wireguard/tun` |
| `internal/netcfg` | OS network setup/teardown: tun addr, def1 routes, scoped pins, NAT |
| `internal/config` | YAML node config: schema + validation + loader |
| `internal/node` | userspace datapath: build connections + router + finalizer + healthchecks |
| `internal/kernelnode` | kernel datapath: lower a config to `ip rule`/`ip route` + iptables MASQUERADE (fast forwarder) |
| `internal/netschema` | whole-mesh schema → per-node configs (`dualnet compile`) |
| `internal/netsim` | offline Docker simulation + schema-derived test matrix (engine; `dockerdriver` is the only Docker SDK user) |
| `test/sim` | in-container helper image: `sim init`/`echo`/`probe` (see [docs/netsim.md](docs/netsim.md)) |
| `cmd/netsim` | CLI to simulate & test any network schema |

## Status & limits

- Obscurity-grade security only (see above).
- Uplinks are typically TCP (HTTP), so tunneled TCP is TCP-over-TCP — fine on a low-loss
  fiber uplink; chaining several stream hops compounds it, so prefer UDP carriers on
  non-censored hops.
- A `multiple` listener assumes each downstream peer originates a single owner (its assigned
  id) — true for leaf clients; deep multi-owner aggregation behind one peer is future work.
- Inner tun addresses must be unique across the mesh (the finalizer recovers a reply's owner
  from its inner destination IP).
