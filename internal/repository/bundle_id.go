package repository

import (
	"crypto/rand"
	"encoding/binary"
)

// NewBundleID returns a random bundle id in [2^32, 2^52). Bundle ids are
// returned to anonymous uploaders, so a sequential id would let anyone
// count how many bundles others create (bad in Ghost mode). The range keeps
// ids exact as JavaScript numbers.
func NewBundleID() (int64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	const lo, span = int64(1) << 32, (int64(1) << 52) - (int64(1) << 32)
	return lo + int64(binary.BigEndian.Uint64(b[:])%uint64(span)), nil
}
