package utils

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RangeKind is the outcome of resolving a request's Range/If-Range headers
// against a resource's current size, ETag, and modification time.
type RangeKind int

const (
	// RangeFull means the caller should serve the entire resource — either
	// no Range header was sent, If-Range didn't match, or the Range header
	// was syntactically invalid (per RFC 9110, an unparsable Range header
	// is ignored, not rejected).
	RangeFull RangeKind = iota
	// RangePartial means Start/End (inclusive, clamped to size) identify a
	// single satisfiable byte range to serve as a 206.
	RangePartial
	// RangeUnsatisfiable means the Range header was well-formed but
	// describes a range that cannot be satisfied against the current size
	// (should produce a 416 with Content-Range: bytes */size).
	RangeUnsatisfiable
)

// String returns a short lowercase name for k, used in log lines.
func (k RangeKind) String() string {
	switch k {
	case RangeFull:
		return "full"
	case RangePartial:
		return "partial"
	case RangeUnsatisfiable:
		return "unsatisfiable"
	default:
		return "unknown"
	}
}

// RangeDecision is the result of ResolveRange.
type RangeDecision struct {
	Kind  RangeKind
	Start int64
	End   int64 // inclusive
}

// ResolveRange evaluates r's Range and If-Range headers against a resource
// of the given size/etag/modTime and returns what to serve. It implements
// RFC 9110 §13.1.5 (If-Range) and §14.2 (Range), deliberately narrowed to
// what a single-file claim download needs:
//
//   - If-Range is honored: a strong ETag must match exactly, or the value
//     must parse as an HTTP-date equal (to the second) to modTime. A weak
//     ETag (ours or the request's) never satisfies If-Range. Any mismatch
//     (or an unparsable value) falls back to Full, per spec.
//   - The "bytes" unit is matched case-insensitively.
//   - Any syntax error, first-byte-pos > last-byte-pos (when both are given
//     explicitly), or more than one range-spec all fall back to Full — RFC
//     9110 treats a malformed Range header as if it were absent, and this
//     implementation additionally declines to support multi-range
//     responses (no multipart/byteranges support), matching the pre-3c
//     ParseRange behavior.
//   - A syntactically valid but unsatisfiable range (first-byte-pos beyond
//     size, "bytes=-0", or any range at all against a zero-byte resource)
//     resolves to RangeUnsatisfiable.
//   - Everything else resolves to RangePartial with Start/End clamped to
//     size.
//
// ResolveRange does not mutate r.
func ResolveRange(r *http.Request, size int64, etag string, modTime time.Time) RangeDecision {
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		return RangeDecision{Kind: RangeFull}
	}

	if ifRange := r.Header.Get("If-Range"); ifRange != "" && !ifRangeSatisfied(ifRange, etag, modTime) {
		return RangeDecision{Kind: RangeFull}
	}

	const bytesPrefix = "bytes="
	if len(rangeHeader) < len(bytesPrefix) || !strings.EqualFold(rangeHeader[:len(bytesPrefix)], bytesPrefix) {
		return RangeDecision{Kind: RangeFull}
	}
	spec := rangeHeader[len(bytesPrefix):]

	if strings.Contains(spec, ",") {
		// Multiple ranges: unsupported, RFC 9110 treats "ignore Range" as a
		// safe fallback for a request this server can't satisfy in one part.
		return RangeDecision{Kind: RangeFull}
	}

	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return RangeDecision{Kind: RangeFull}
	}
	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	isSuffix := startStr == ""
	if isSuffix && endStr == "" {
		return RangeDecision{Kind: RangeFull} // "bytes=-" — nothing on either side
	}

	var (
		start           int64
		end             int64
		haveExplicitEnd bool
		suffixLen       int64
	)

	if isSuffix {
		v, err := strconv.ParseInt(endStr, 10, 64)
		if err != nil || v < 0 {
			return RangeDecision{Kind: RangeFull}
		}
		suffixLen = v
	} else {
		v, err := strconv.ParseInt(startStr, 10, 64)
		if err != nil || v < 0 {
			return RangeDecision{Kind: RangeFull}
		}
		start = v
		if endStr != "" {
			v, err := strconv.ParseInt(endStr, 10, 64)
			if err != nil || v < 0 {
				return RangeDecision{Kind: RangeFull}
			}
			end = v
			haveExplicitEnd = true
			if start > end {
				// Invalid byte-range-spec (RFC 9110 §14.1.2): last-byte-pos
				// present and less than first-byte-pos. Ignore the header.
				return RangeDecision{Kind: RangeFull}
			}
		}
	}

	// A zero-byte resource cannot satisfy any range, well-formed or not.
	if size <= 0 {
		return RangeDecision{Kind: RangeUnsatisfiable}
	}

	if isSuffix {
		if suffixLen == 0 {
			return RangeDecision{Kind: RangeUnsatisfiable}
		}
		start = size - suffixLen
		if start < 0 {
			start = 0
		}
		end = size - 1
	} else {
		if start >= size {
			return RangeDecision{Kind: RangeUnsatisfiable}
		}
		if !haveExplicitEnd || end >= size {
			end = size - 1
		}
	}

	return RangeDecision{Kind: RangePartial, Start: start, End: end}
}

// ifRangeSatisfied reports whether the If-Range validator matches the
// resource's current strong ETag or modTime, per RFC 9110 §13.1.5. Weak
// validators (either side) never satisfy If-Range.
func ifRangeSatisfied(ifRange, etag string, modTime time.Time) bool {
	if strings.HasPrefix(ifRange, "W/") {
		return false
	}
	if t, err := http.ParseTime(ifRange); err == nil {
		// A zero or Unix-epoch-zero modTime means the caller has no real
		// last-modified value (e.g. a not-yet-populated field) — an
		// If-Range date can never legitimately match "no known time", so
		// treat it as a mismatch (Full) rather than risk a coincidental
		// t.Unix()==0 match on 1970-01-01T00:00:00Z.
		if modTime.IsZero() || modTime.Unix() == 0 {
			return false
		}
		return t.Unix() == modTime.Unix()
	}
	if etag == "" || strings.HasPrefix(etag, "W/") {
		return false
	}
	return ifRange == etag
}

// CanonicalRangeHeader formats d as a normalized single-range "bytes=S-E"
// Range header value. Intended for handlers to rewrite an incoming request
// to a single canonical range before delegating to http.ServeContent.
func CanonicalRangeHeader(d RangeDecision) string {
	return fmt.Sprintf("bytes=%d-%d", d.Start, d.End)
}
