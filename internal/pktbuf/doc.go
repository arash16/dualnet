// Package pktbuf provides batched packet I/O as drop-in replacements for a plain
// read or write on a connection's data path.
//
// A node's connections are one-way: a connect-out/listen-out only writes, a
// connect-in/listen-in only reads; only the local tun and the gateway egress do
// both, and they do so as two independent objects. So a connection uses exactly
// one of these types, and the two never reference each other.
//
//   - Reader turns a batched source into a one-packet-at-a-time stream. A
//     background goroutine prefetches the next batch while the caller drains the
//     current one, so the caller blocks only when it has emptied the current batch
//     and the next is not yet filled.
//   - Writer buffers packets and flushes them together (fewer, larger syscalls).
//     It flushes inline when its buffer fills and, via a shared FlushGroup ticker,
//     flushes an idle partial batch so a trickle is never stuck. A single buffer
//     guarded by one mutex makes flushes serialize in commit order — the ordering
//     a stateful stream cipher requires — with no per-Writer goroutine.
//
// Both are allocation-free on the steady per-packet path and use fixed memory:
// storage is allocated once at construction and reused. Adding a transport means
// writing one FillFunc (read side) or one FlushFunc (write side); batching,
// ordering, and flushing are handled here, not in transport code.
package pktbuf
