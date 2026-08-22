# The dualnet protocol

This document describes **only the protocol** — how packets are identified, carried,
routed, and returned across a network of nodes. It is deliberately independent of any
implementation or configuration format.

## Nodes, connections, and owners

A **network** is a set of **nodes**. A node has no identity of its own. Instead it holds
a set of **connections** to other nodes and a **routing table**. Three kinds of endpoint
exist:

- a **tun** — where real (inner) IP packets enter and leave the tunnel;
- an **outgoing** connection — carries inner packets away from this node;
- an **incoming** connection — carries inner packets into this node.

Each tun has a random **owner** — a 4-byte identifier. It is the *only* identity in the
protocol; nodes and IP addresses are not identities. Every packet that a tun originates is
stamped with its owner and travels the network under that owner until it is delivered to a
tun with the same owner.

## The envelope

Between nodes, each inner IP packet is wrapped in a small **envelope**:

```
[ owner : 4 bytes ] [ flags : 1 byte ] [ inner IP packet ... ]
                      └─ bit 0: "processed"
```

The whole thing — envelope **and** inner packet — is obfuscated as one blob before it
goes on the wire (a keystream cipher for stream transports, a per-datagram sealed form for
datagram transports). Because the envelope rides *under* the obfuscation, there is no
fixed byte pattern on the wire to fingerprint. A wrong key de-obfuscates to garbage that
fails a plausibility check and is dropped.

The **processed** flag is the second half of identity: it records whether the packet has
already been to the internet.

- `processed = false` — a raw packet still travelling *toward* a gateway.
- `processed = true` — a reply coming *back* from the internet.

## Routing

Every node forwards packets by matching the **processed** flag and the **source** it
arrived from (a tun or an incoming connection), and optionally a set of named
**conditions**. A routing rule says: *for a packet with this processed-state arriving from
this source (and for which these conditions hold), send it to that target connection* (or
*finalize it through this named egress*). Rules are tried in order; the first target that
**can carry** the packet's owner **and whose conditions all hold** wins; if none, the
packet is dropped.

A target "can carry" an owner when:

- it is a **tun** whose owner equals the packet's owner (deliver to the local tunnel), or
- it is an outgoing connection to a **single** peer (always), or
- it is an outgoing connection serving **many** peers and the packet's owner is one it
  currently tracks.

## Conditions

A **condition** is a named boolean the rule engine can require. Three kinds exist:

- a **destination predicate** — the inner packet's *destination* falls in a set of IP prefixes
  (given as a static file or an inline list). This splits one source's traffic by where it is
  going: matching destinations take one rule, the rest fall through to the next.
- a **source predicate** — the same, on the packet's *source* IP. It exists for the kernel
  datapath (below), where it selects an exit by who sent the packet.
- a **healthcheck** (below) — a liveness bool for a **full round-trip** (not a single
  link). Gating a rule on it lets a node send traffic through a gateway while that
  round-trip is alive and **fall through to a different rule** (e.g. a local egress) when
  it is not — failover decided purely by the routing engine, changing nothing in the
  host's own network configuration.

A condition that does not hold makes its rule skip, exactly as an owner that cannot be
carried does. Conditions are the single mechanism behind destination-based routing and
in-process failover; they are meant to extend to other packet properties over time.

## Egresses

A node may reach the internet through more than one **egress**, each named. A finalize
rule names the egress it uses, so different traffic can leave by different exits — for
example a home router that sends in-country destinations straight out one uplink and
everything else through a distant gateway. Each named egress keeps its own return-routing
state (below).

## The finalizer (reaching the internet)

Exactly one point in a packet's journey turns `processed` from false to true: the
**finalizer** at a gateway node. When a rule marks a packet for processing, the gateway:

1. sends the inner packet to the real internet (translating its address as a NAT would),
   and **remembers**, for that flow, both the packet's owner and the return path chosen by
   the rule;
2. when a reply arrives from the internet, restores the remembered owner, sets
   `processed = true`, and sends it back along that return path — one hop. Downstream nodes
   then route the reply by their ordinary `processed = true` rules.

This is why the up-path and the down-path can differ completely: the gateway records where
each flow's reply should go, so the return route is decided once, at the moment of
processing.

## Peer identity assignment

A connection that serves **many** peers must be able to tell their return traffic apart.
It does so by **owner**: it mints a fresh 4-byte owner for each peer that attaches, and
sends that owner back to the peer over the same connection. The peer adopts it as the
owner of its tun, so from then on every packet it originates carries that owner — and the
serving node can demultiplex replies by it. A tun that is not assigned an owner this way
simply chooses a random one for itself.

The attach handshake is **authenticated and replay-resistant**, so return-path binding is not
part of the obscurity-only data plane. Each attach/refresh — and the owner assignment sent back
— carries a tag keyed by the shared secret plus a monotonic freshness stamp: a party without the
secret cannot attach a peer, and a captured attach message cannot be replayed later to re-point
a peer's return traffic at the replayer (the serving node honors a refresh only with a stamp
newer than the last it accepted for that owner). Data packets themselves remain unauthenticated
— see the security note below.

## Healthcheck

Liveness is tested end-to-end, across whatever path a tun's traffic takes. A **healthcheck
condition** periodically emits a **healthcheck** packet — a marked, well-formed packet with
the tun's owner, `processed = false` — sent on the up-link it probes. The gateway
recognizes it at the processing point and, instead of sending it to the internet,
**reflects** it: stamps it `processed = true` and returns it along the same path the flow's
replies use. It arrives back at the origin tun, which consumes it as proof the round-trip
is alive. If reflections stop arriving, the origin re-establishes the connections it dials.

The condition exposes this as a bool with hysteresis — it starts **down**, goes down
immediately on silence (the safe direction), and goes up only after sustained liveness (so
a brief blip never flaps it). A rule gated on the condition therefore routes through the
probed path only while it is healthy, falling through otherwise. The probe runs whether or
not any rule references the condition.

## Worked example

Five nodes: a **phone**, a home router **hpi**, an in-country **vps**, an out-of-country
gateway **turkish**, and the internet beyond turkish. The phone sends over a fast but
censored uplink and receives over a fast clean downlink — an asymmetric split — and its
reply travels a different path than its request.

**Setup.** The vps serves many peers on the downlink; when the phone attaches, the vps
mints owner **P** and hands it back, and the phone stamps its tun with **P**.

**A packet's round-trip:**

```
                        (processed=false, owner=P)                         ┌──────────┐
  phone.tun ─────────────────────────────────────────────────────────────►│ turkish  │──► internet
        ▲   up: phone ──► turkish                                          │ finalizer│
        │                                                                   └────┬─────┘
        │   (processed=true, owner=P)                                            │ remembers {P → down path}
        └───────────── phone ◄── vps ◄── hpi ◄──────────────────────────────────┘
            down: turkish ──► hpi ──► vps ──► phone
```

1. An app packet leaves `phone.tun` — owner **P**, unprocessed. The phone's rule *"from tun
   → uplink"* sends it up to **turkish**.
2. **turkish** matches *"from the phone's uplink → process"*. Its finalizer NATs the packet
   out to the internet and remembers: *this flow's owner is **P**, and its reply exits
   toward **hpi***.
3. The internet reply comes back. The finalizer restores owner **P**, marks it processed,
   and sends it to **hpi**.
4. **hpi** matches *"processed, from turkish → vps"* and forwards it to **vps**.
5. **vps** matches *"processed, from hpi → phone"*; owner **P** is a peer it serves, so it
   sends the reply down to the **phone**.
6. **phone** matches *"processed, from vps → tun"*; owner **P** equals its tun's owner, so
   it delivers the packet to the local tunnel. ✔

A healthcheck from the phone follows steps 1–2, is reflected by turkish's finalizer at step
2 (never touching the internet), and returns via steps 3–6 to prove the path is alive.

## A node that speaks none of this: the kernel datapath

Everything above is the tunnel protocol — the envelope, the owner, the finalizer. A node may
instead be a plain **kernel forwarder**: it runs no tunnel, mints no owner, wraps nothing. It
just programs the operating system's own policy routing (source/destination rules + per-exit
NAT) so the kernel forwards raw IP packets between a LAN and several exits at native speed. The
same *conditions* select the exit — a destination-set match becomes a routing-table entry, a
source-set match becomes a source-based rule — but there is no envelope on any wire, because such
a node never tunnels; it is a fast on-ramp that steers traffic toward whichever exit (or toward
another node that *does* tunnel). One of those exits may itself be a Cloudflare WARP tunnel — a
kernel WireGuard device the node brings up and forwards through — but that is standard WireGuard
to Cloudflare, still with zero dualnet protocol on the wire. It participates in a dualnet only as
a router of ordinary packets, not as a peer in the protocol above.

## Security note

The protocol's security is deliberately split. The **data plane is obscurity, not cryptography**:
the on-wire blob is (optionally) run through a keystream cipher that defeats content-fingerprinting
DPI, but inner packets are not confidential and — the one deliberate gap — not authenticated, so a
party holding the shared secret can originate packets under an arbitrary owner. A wrong-key peer's
traffic de-obfuscates to garbage and is dropped by a plausibility check. The **control plane is
authenticated and replay-resistant** (see *Peer identity assignment*): attaching or refreshing a
peer, and adopting an assigned owner, require the shared secret and a fresh stamp, so an off-path
observer can neither attach a peer nor replay a captured message to steal a return path, over any
carrier. Resource use is bounded against floods (tracked flows, attached peers, forwarded exit
flows), and a node that reaches the internet through a userspace exit refuses to dial link-local
(including cloud-metadata), loopback, and multicast destinations on a client's behalf.
