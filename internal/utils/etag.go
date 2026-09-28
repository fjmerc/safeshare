package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// ComputeClaimETag returns a strong ETag for a claim download, per ADR-017.
//
// It is a SHA-256 over a fixed-prefix, NUL-separated tuple of fields that
// identify this exact stored byte sequence:
//
//   - storedFilename — ties the ETag to a specific on-disk blob. Every
//     upload (including a re-upload of byte-identical content) gets a
//     freshly generated StoredFilename, so this alone already makes the
//     ETag unique per file row in practice.
//   - fileSize — the DB-recorded plaintext length.
//   - createdAt.UnixNano() — the file row's creation time, included so the
//     ETag is explicitly tied to "this row", not just "this path" (belt and
//     suspenders alongside storedFilename's own uniqueness).
//
// Only the first 16 bytes of the digest are kept: a strong validator here
// only needs to be collision-resistant against SafeShare's own generated
// byte streams, not cryptographically unforgeable by a third party, and 16
// bytes keeps the header short. The result is quoted and has no `W/`
// prefix — it is always a strong validator, satisfying If-Range and
// If-Match per RFC 9110.
func ComputeClaimETag(storedFilename string, fileSize int64, createdAt time.Time) string {
	var b strings.Builder
	b.WriteString("safeshare-etag-v1\x00")
	b.WriteString(storedFilename)
	b.WriteByte(0)
	b.WriteString(strconv.FormatInt(fileSize, 10))
	b.WriteByte(0)
	b.WriteString(strconv.FormatInt(createdAt.UnixNano(), 10))

	sum := sha256.Sum256([]byte(b.String()))
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}
