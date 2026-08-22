# dualnet — Data Flow, Routing & Identity

How a node is configured, how a packet is identified and routed between connections,
how a gateway reaches the internet and returns replies, and how peers are assigned
identities — for the generalized multi-node model.

> This replaces the old client/server + virtual-IP documentation. Identity is now a
> 4-byte **owner** id, not a tunnel vIP; there is a single **node** runtime, not
> separate client/server modes.

---

## 1. The one idea to hold onto

Packets are routed by **owner** and **processed state**, not by IP address. A `tun`
connection stamps every packet it originates with its 4-byte owner id and
`processed=false`. That metadata rides between nodes in a 5-byte envelope. Each node's
routing table forwards a packet by matching `{processed, source-connection}` to a
`target` connection. A gateway's **finalizer** is the one place `processed` flips
`false → true` (a packet went to the internet and a reply came back), and it remembers
where each flow's reply should go. Everything below elaborates on that.

---

## 2. Identity & the packet envelope

| Thing | What it is | Where it lives |
|---|---|---|
| **owner** | random 4-byte id of the originating tun | `wire.Owner`; minted by a tun ([`wire`](../internal/wire/envelope.go)) or by a Multiple listener ([`peers`](../internal/peers/peers.go)) |
| **processed** | 1 bit: has this packet been to the internet? | envelope flag ([`wire/envelope.go`](../internal/wire/envelope.go)) |
| **inner IP** | the tun's address (unique per owner) | a tun connection's `ip` in config; used only by the finalizer's NAT + return lookup |
| **PSK** | per-connection (or global) secret | seeds the cipher keystream + control-datagram tag ([`wire/psk.go`](../internal/wire/psk.go)) |

Every inter-node packet is `cipher( [owner:4][flags:1][ inner IP packet ] )`. The
envelope is prefixed **before** the cipher, so it rides under the XOR keystream /
per-datagram nonce — there is no constant on-wire marker to fingerprint. It is
serialized at an outgoing send and parsed at an incoming receive
([`wire.PutEnvelope`/`ParseEnvelope`](../internal/wire/envelope.go)); inside a node
packets travel as `(Envelope, payload)` and a tun never sees the envelope bytes. The
wrong-key tripwire (`wire.PlausibleIP`) runs on the *payload* after the envelope is
stripped.

---

## 3. Connections: five kinds

A connection is `(type × direction)`, per protocol
([`internal/conn/conn.go`](../internal/conn/conn.go)):

| Kind | type / direction | Role | Old analogue |
|---|---|---|---|
| `KindTun` | `tun` | originate/consume packets by owner id | the utun |
| `KindConnectOut` | `connect` / `outgoing` | we dial, we push packets | TXClient |
| `KindConnectIn` | `connect` / `incoming` | we dial, we receive; we register & apply an assigned id | RXClient |
| `KindListenIn` | `listen` / `incoming` | we accept, we receive | RXServer |
| `KindListenOut` | `listen` / `outgoing` | we accept, we send by owner; mint ids if `multiple` | TXServer |

Three of them (`Tun`, `ConnectOut`, `ListenOut`) implement `conn.Sender` — they can be a
routing **target**. `Sender.Accepts(owner)` reports whether a packet with that owner is
deliverable right now (tun → owner==id; connect-out → always; listen-out → the peer is
registered), and `Send` delivers it. Receivers (`ConnectIn`, `ListenIn`) are not Senders,
so a rule targeting one is skipped. Each protocol carrier lives in
[`http.go`](../internal/conn/http.go) / [`udp.go`](../internal/conn/udp.go) /
[`tcp.go`](../internal/conn/tcp.go) (the last a plain framed byte stream — the http
stream carrier without its request/response dressing).

---

## 4. The routing engine

The table is a list of rows: `match {processed, source, conditions}` → `action {egress,
target}`. Rows still compile into an **ordered list of targets** per `(processed, source)`
([`router.Compile`](../internal/router/router.go)); wildcard rows (`source: ""`) merge in
table order. `egress` (empty = plain forward, else the name of a local egress to finalize
through) replaces the old boolean `process`. `conditions` names **guards** that must all
hold for the target to be chosen — this is how one source's traffic is *split*.

A **guard** is a per-target predicate ([`router.Guard`](../internal/router/router.go)),
resolved from a named condition (§4a). Two kinds exist: a packet predicate (destination-IP
set membership, `ipmatch`) and a healthcheck liveness bool. A guard that fails behaves
exactly like a rejected owner — the packet falls through to the next target.

Routing one packet ([`Router.Route`](../internal/router/router.go)):

```
for each target in list(processed, source):
    if target is not a Sender, or !target.Accepts(owner):  continue   # skip
    if target has guards and not all pass(owner, dstIP):   continue   # skip
    if target.egress != "":  finalizer[egress].Submit(owner, target, payload); return
    if target.Send(owner-envelope, payload) delivered:      return
drop
```

The inner destination IP is parsed **lazily** — only when a guarded target is reached — so
nodes with no guarded rows never inspect the payload. The `Accepts` gate runs before
committing a finalize rule, so a reply target that can't take the owner falls through
instead of black-holing the reply.

## 4a. Conditions & named egresses

A node declares zero or more **named egresses** (`egresses:` map) and zero or more **named
conditions** (`conditions:`), and a finalize rule references an egress by name while a
match references conditions by name. Both are the generic building blocks that express
per-destination routing and in-process failover without special-casing:

| Concept | What it is |
|---|---|
| **egress** | a named finalizer exit: `kernel` (TUN+NAT), `direct` (userspace netstack dialed out a bound interface, no kernel NAT), or `warp` |
| **dst_in condition** | packet predicate: destination IP ∈ an IP set given as `dst_in: {file}` (SIGHUP/`reload`-reloadable, cached longest-prefix table — [`ipmatch`](../internal/ipmatch/ipmatch.go)) or `dst_in: {list: […]}` (inline) |
| **src_in condition** | packet predicate on the **source** IP (same `{file}`/`{list}` set). A **kernel-datapath** mechanism (§10), lowered to `ip rule from`; it is not used by the userspace router. |
| **healthcheck condition** | a liveness bool for a **full round-trip** — `healthcheck: {path}` probes that path's gateway branch (up-path → gateway → reflected reply back to the tun). Runs whether or not a rule references it (§Healthcheck). Not a single-link keepalive. |

A rule gated on `dst_in` sends matching destinations to one egress/target and everything
else falls through to the next row — a geo split. A rule gated on a healthcheck sends
traffic through a gateway while that round-trip is up, and falls through to a local
fallback egress when it goes down — **in-process failover**, with no OS route changes.
The compiler derives the healthcheck's up-path from the named path's gateway branch, so
the round-trip is declared once (in the path), not repeated in the condition.

---

## 5. The finalizer (internet egress + return routing)

A node builds **one finalizer per named egress** referenced by a finalize rule
([`internal/finalizer`](../internal/finalizer/finalizer.go)); a rule's `egress` name
selects which one. Each wraps an egress backend — kernel TUN+NAT (a `tundev.Device`), a
userspace `direct`/WARP netstack ([`internal/egress`](../internal/egress/netstack.go)) —
and adds return-routing state, because an internet reply carries no owner:

- **Submit(owner, target, payload):** if the payload is a healthcheck ping, reflect it
  immediately to `target` marked processed (never egress it). Otherwise record
  `track[innerSrcIP] = {owner, target}` (bounded — a brand-new flow past the cap is still
  egressed but not tracked, so a spoofed-inner-source flood cannot grow the map without bound)
  and write the packet to the egress.
- **Run (reply loop):** read a reply from the egress; its destination is the originating
  inner IP, so look up `track[innerDstIP]` to recover `{owner, target}`, stamp the packet
  `processed=true` with that owner, and `target.Send` it — one hop. Downstream nodes then
  route it with ordinary `processed: true` rows.

This is why a gateway needs no explicit `processed` rows: the reply's next hop is the
`target` of the process row that sent the request. Idle flows are GC'd.

---

## 6. Peer identity assignment

A `listen`+`outgoing`+`multiple` connection must tell its downstream peers apart to
demultiplex return traffic. It mints a random 4-byte id per peer and hands it back over
the peer's `connect`+`incoming` connection; the peer's `id_setter` names the local tun to
stamp with it, so all that tun's packets carry that owner
([`peers.Registry`](../internal/peers/peers.go), control codec in
[`conn/control.go`](../internal/conn/control.go)):

- **UDP:** the `connect`+`incoming` side sends a `MsgRegister` (its current id, `0` if none)
  carrying an HMAC tag over `[type][id][flags][ts]` — the PSK-keyed tag proves membership and
  the monotonic `ts` defeats replay; the Multiple listener mints/adopts an id, replies
  `MsgAssignID`, and the peer applies it via `id_setter`. Minting is idempotent per source
  address, so a lost reply re-returns the same id.
- **HTTP:** the peer's long-lived `GET` carries its id **and a PSK-keyed signature header**
  (id+ts); the Multiple listener verifies it before registering (an unauthenticated GET is
  refused, a replayed one rejected on freshness) and returns the minted id **with its own
  signature** in a response header, which the peer verifies before adopting — so a MITM on the
  plaintext response cannot stamp the tun with an attacker owner. Both directions mirror the UDP
  control tag ([`conn/auth.go`](../internal/conn/auth.go)).

A tun not targeted by any `id_setter` gets a self-random id and starts immediately; a tun
that *is* targeted holds its read loop until the id arrives (so early packets don't go out
with an id no listener knows).

---

## 7. Worked example — the home-router split (userspace)

Config: [docs/examples/network-old.yaml](examples/network-old.yaml) (out-of-country `turkish`
gateway, home `router`, in-country `vps`) — a fully **userspace** mesh, so it illustrates the
routing engine above. (The shipped [network.yaml](examples/network.yaml) makes the router a
**kernel-datapath** node instead — see §10.) The router captures the LAN default and splits its
traffic three ways; the vps sends up to Turkey and receives back through the router.

Router LAN routes (owner **R** is the router tun; the `is-iran`/`turkey` guards decide):

1. **Iran destination** — rule `unproc from Tun [is-iran] → egress ftth, reply=Tun`:
   `finalizer[ftth].Submit(R, Tun, pkt)`; the netstack dials out FTTH; the reply is
   reflected to `Tun` and written to the device. Independent of Turkey's health. ✔
2. **Other destination, Turkey healthy** — rule `unproc from Tun [turkey] → router-up`:
   sent up to `turkish`, which `finalizer[internet].Submit`s it (NAT), remembers
   `track[srcIP] = {R, turkish-router}`, and on the reply sends it down `turkish-router`
   (Starlink) → router → `proc from turkish-router → Tun` (owner **R**). ✔
3. **Other destination, Turkey unhealthy** — the `turkey` guard fails, so #2 is skipped and
   the packet falls through to `unproc from Tun → egress starlink, reply=Tun`: finalized
   locally out Starlink. In-process failover; the tun keeps the default route. ✔

VPS round-trip: `V2Ray → vps-up → turkish (finalizer[internet]) → turkish-router → router`.
The router receives owner **V** on the shared Starlink downlink; `proc from turkish-router
→ Tun` is skipped (**V** ≠ **R**), then `proc from turkish-router → router-vps` (a single
connect-out, accepts any owner) → `vps` → `proc from router-vps → V2Ray`. ✔ The one
downlink thus carries both **R** and **V**; the router demuxes by owner.

The `turkey` healthcheck ping rides #2's up-link (injected directly on `router-up`), is
reflected at `turkish`'s finalizer without egressing, and returns via the `proc` down
rules to `Tun` as liveness — so it probes Turkey even while #2 is gated down.

---

## 8. Security & correctness caveats

The threat model is a network adversary: an off-path scanner, an on-path observer/injector,
and (semi-trusted, single-operator) peers that hold the PSK. The **data plane is
obfuscation-only**; the **control plane is authenticated and replay-resistant**.

- **Obscurity, not encryption (data).** XOR keystream deters scanners and content-DPI; it is
  not confidentiality. Inner *data* packets are unauthenticated by design — with `cipher: none`
  they ride in the clear, and even with `chacha4` a PSK holder can inject arbitrary inner
  packets. The wrong-key tripwire (`wire.PlausibleIP`) drops a mismatched peer's garbage.
- **Control is authenticated + fresh.** Peer registration/keepalive/id-assignment carry an
  HMAC-SHA256 tag keyed by the PSK **and** a monotonic freshness stamp. An off-path scanner
  cannot register a peer (no tag), and a captured control record cannot be **replayed** to
  re-bind a peer's return path — the listener rejects any stamp not newer than the last it
  accepted (`peers.Registry`, [`conn/control.go`](../internal/conn/control.go)). Both carriers
  enforce this: the UDP path in the control datagram, the HTTP download path in signed request/
  response headers ([`conn/auth.go`](../internal/conn/auth.go)) — so a MITM cannot force a peer
  to adopt an attacker-chosen owner either.
- **Owner is unverified upstream (data).** A party that knows a connection's PSK can send inner
  packets with an arbitrary owner. Per-peer isolation would require binding an authenticated
  identity to the owner on the uplink — future work; this is the one deliberate gap left.
- **Resource bounds.** Attacker-driven growth is capped, not unbounded: the finalizer's
  return-tracking map (per spoofable inner-source), a Multiple listener's peer registry, the
  netstack egress's concurrent flows, and each HTTP listener's concurrent connections all have
  ceilings; stalled HTTP bodies and undecodable-frame floods are torn down.
- **No SSRF via the userspace egress.** The `direct`/WARP netstack refuses to dial link-local
  (incl. `169.254.169.254` cloud metadata), loopback, unspecified, and multicast destinations —
  a client cannot reach the gateway's on-link services through the tunnel.
- **Inner tun addresses must be unique across the mesh** — the finalizer recovers a
  reply's owner from its inner destination IP.
- **A dropped return path is silent.** Replies for an owner whose peer hasn't registered
  (or has expired), or that exceed a resource cap, are dropped; inner TCP retransmits.
- **The PSK is never baked into generated artifacts.** `dualnet compile` strips the global PSK
  from every emitted config / k8s ConfigMap; it is delivered out-of-band via `DUALNET_PSK`,
  which overrides the file at runtime.

---

## 9. File map

| Concern | File |
|---|---|
| Node composition root | [`internal/node/node.go`](../internal/node/node.go) |
| Connection kinds & interfaces | [`internal/conn/conn.go`](../internal/conn/conn.go) |
| HTTP / UDP / TCP carriers | [`internal/conn/http.go`](../internal/conn/http.go), [`udp.go`](../internal/conn/udp.go), [`tcp.go`](../internal/conn/tcp.go) |
| Batched packet I/O (reader / writer / flush group) | [`internal/pktbuf`](../internal/pktbuf) |
| Peer id registry | [`internal/peers/peers.go`](../internal/peers/peers.go) |
| Routing engine & guards | [`internal/router/router.go`](../internal/router/router.go) |
| Destination-IP set matcher (bart + cache) | [`internal/ipmatch/ipmatch.go`](../internal/ipmatch/ipmatch.go) |
| Finalizer (egress + return conntrack) | [`internal/finalizer/finalizer.go`](../internal/finalizer/finalizer.go) |
| Healthcheck (probe + healthy⇄unhealthy edge) | [`internal/healthcheck/healthcheck.go`](../internal/healthcheck/healthcheck.go) |
| Envelope / ping / PSK / inner-IP | [`internal/wire`](../internal/wire) |
| Config schema & validation (egresses, sets, conditions) | [`internal/config/config.go`](../internal/config/config.go), [`validate.go`](../internal/config/validate.go) |
| OS net config (capture, iface pins, LAN forward, NAT) | [`internal/netcfg`](../internal/netcfg) |
| Network schema → per-node compiler | [`internal/netschema`](../internal/netschema) |
| Kernel-datapath runtime (ip rule/route + iptables) | [`internal/kernelnode`](../internal/kernelnode) |

---

## 10. The kernel datapath (bypassing everything above)

Everything above is the **userspace** datapath: a node terminates each flow, wraps it in the
envelope, and routes it by owner through the finalizer. That is the right model for tunnelling
and asymmetric bonding, but it costs a userspace TCP/IP pass per packet — on a slow router a
plain gVisor `direct` egress caps around tens of Mbps.

A node with `datapath: kernel` ([`internal/kernelnode`](../internal/kernelnode)) does **none** of
that. It is a pure OS forwarder: no tun, no owner, no envelope, no cipher, no finalizer. The
compiler lowers its `egresses` + `conditions` + `forward` policy into Linux policy routing that
the kernel (and its hardware offload) executes at line rate:

- each egress → a routing table with `default via <WAN>` + `iptables … MASQUERADE` out it;
- a **`warp`** egress → a kernel WireGuard device brought up from a WARP account (`ip link add
  … type wireguard`, programmed via netlink); it becomes that egress's WAN device (`default dev
  <wg>`, MASQUERADE/clamp out it — identical to a physical WAN), and its resolved endpoint is
  pinned as a `/32` host route in the main table via the egress's underlay `exit:` so the
  tunnel's own encrypted UDP escapes rather than looping back into the tunnel (the `/32` beats
  the `suppress_prefixlength 0` rule below, so no fwmark is needed);
- a **`src_in`** branch → `ip rule from <src> lookup <egress-table>` (consulted before the main
  table) — this is how a marked leg is steered onto a chosen WAN;
- a **`dst_in`** branch → its prefixes as routes in a per-branch table consulted by one
  `ip rule` (FIB longest-prefix, reloadable on SIGHUP);
- the default branch → the default egress's table;
- plus a mandatory `ip rule … lookup main suppress_prefixlength 0` first, so connected/LAN/
  management routes still win and only internet-bound traffic hits the policy rules (without it
  the box black-holes its own replies).

Fixed precedence: `src_in` (ip rule) > `dst_in` (FIB route) > default. Source-IP is used rather
than DSCP because the target router's kernel (4.4) masks the DS field, so `ip rule dsfield` is
rejected. The shipped [network.yaml](examples/network.yaml) uses this for its `router`; the rest
of the mesh (the bonding `laptop`, the relay `pi`) stays userspace and speaks the protocol above.
