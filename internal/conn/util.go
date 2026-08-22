package conn

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/arash16/dualnet/internal/wire"
)

// randomOwner returns a random non-zero 4-byte owner id.
func randomOwner() wire.Owner {
	for {
		var o wire.Owner
		_, _ = rand.Read(o[:])
		if !o.IsZero() {
			return o
		}
	}
}

// ownerHex encodes an owner as an 8-char hex string (for HTTP headers).
func ownerHex(o wire.Owner) string { return hex.EncodeToString(o[:]) }

// parseOwnerHex decodes an owner from hex; returns the zero owner on any error.
func parseOwnerHex(s string) wire.Owner {
	var o wire.Owner
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != wire.OwnerLen {
		return wire.Owner{}
	}
	copy(o[:], b)
	return o
}
