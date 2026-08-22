package conn

import (
	"encoding/binary"
	"errors"

	"github.com/arash16/dualnet/internal/wire"
)

// Control datagram codec for the UDP ConnectIn ↔ ListenOut path (the demux/return
// direction). A ConnectIn sends register/keepalive datagrams so the ListenOut learns
// its source address; a Multiple ListenOut answers with the minted id.
//
// Layout: [type:1][id:4][flags:1][ts:8][tag:8]
// tag = wire.Tag(connKey, everything-before-tag). The tag proves knowledge of the connection's
// PSK so a ListenOut won't register spoofed peers from scanners. `ts` is a monotonic freshness
// stamp (the sender's unix-nanos) covered by the tag: the ListenOut rejects a register/keepalive
// whose ts is not newer than the last it accepted for that peer, so a verbatim on-path REPLAY of
// a captured (already-valid) datagram cannot re-bind the peer's return path to the replayer.
//
// A register carrying the zero id asks the ListenOut to mint one; a non-zero id is a
// reconnecting peer refreshing its existing id.

const controlLen = 1 + wire.OwnerLen + 1 + 8 + 8

var errBadControl = errors.New("conn: malformed control datagram")

func encodeControl(typ byte, id wire.Owner, flags byte, ts uint64, key [32]byte) []byte {
	body := make([]byte, 0, controlLen)
	body = append(body, typ)
	body = append(body, id[:]...)
	body = append(body, flags)
	body = binary.BigEndian.AppendUint64(body, ts)
	tag := wire.Tag(key, body)
	return append(body, tag[:]...)
}

func decodeControl(data []byte, key [32]byte) (typ byte, id wire.Owner, flags byte, ts uint64, err error) {
	if len(data) != controlLen {
		return 0, wire.Owner{}, 0, 0, errBadControl
	}
	body := data[:len(data)-8]
	var tag [8]byte
	copy(tag[:], data[len(data)-8:])
	if !wire.VerifyTag(key, body, tag) {
		return 0, wire.Owner{}, 0, 0, errBadControl
	}
	typ = body[0]
	copy(id[:], body[1:1+wire.OwnerLen])
	flags = body[1+wire.OwnerLen]
	ts = binary.BigEndian.Uint64(body[1+wire.OwnerLen+1:])
	return typ, id, flags, ts, nil
}
