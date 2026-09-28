package utils

import (
	"net/http"
	"strings"
	"time"
)

// unixEpochTime is net/http's own sentinel for "no real modification time
// known" (its unexported isZeroTime treats either the Go zero Time or this
// value the same way). Matched here so a zero or Unix-epoch modTime is
// treated identically by EvaluatePreconditions and by http.ServeContent.
var unixEpochTime = time.Unix(0, 0)

func isZeroTime(t time.Time) bool {
	return t.IsZero() || t.Equal(unixEpochTime)
}

// condResult mirrors net/http's own unexported three-state precondition
// result (condNone/condTrue/condFalse in net/http/fs.go).
type condResult int

const (
	condNone condResult = iota
	condTrue
	condFalse
)

// PreconditionOutcome is the result of EvaluatePreconditions.
type PreconditionOutcome struct {
	// Status is the response status this precondition chain requires —
	// http.StatusPreconditionFailed or http.StatusNotModified — or 0 if
	// nothing in the chain fired (the caller should proceed as if there
	// were no conditional headers at all).
	Status int
}

// EvaluatePreconditions is a line-for-line port of Go 1.27's net/http
// unexported checkPreconditions (together with its scanETag/checkIfMatch/
// checkIfNoneMatch/checkIfModifiedSince/checkIfUnmodifiedSince helpers, all
// in net/http/fs.go), narrowed to just the precondition decision (the
// caller already knows what to do with Range itself). etag must be the
// resource's current strong ETag (already quoted, e.g. `"abc123..."`);
// modTime its current Last-Modified value.
//
// This exists for exactly one caller: serveFileWithRangeSupport's
// RangeUnsatisfiable path in internal/handlers/claim_range.go (ADR-017),
// which must apply RFC 9110 §13.2.2's precedence — If-Match/
// If-Unmodified-Since (412 on failure) before If-None-Match/
// If-Modified-Since (304 for GET/HEAD, 412 otherwise, on a match), and
// Range only after all of that — BEFORE falling back to a 416: a client
// whose cached copy already matches (a 304-worthy If-None-Match) or who
// asserted a precondition that fails (a 412-worthy If-Match/
// If-Unmodified-Since) must get that answer, not a 416, even though the
// Range header it also sent happens to be unsatisfiable. http.ServeContent
// itself only reaches its own equivalent logic once a satisfiable (or
// absent) Range has already been decided — 416-vs-200 and 412/304-vs-200
// are two independent decisions in the stdlib's own control flow, so
// ServeContent can't be reused directly for "the range turned out to be
// unsatisfiable, but a precondition might still take precedence." Hence
// this port rather than a probe through ServeContent (an alternative
// considered and rejected — see ADR-017 §8: a probe still has to fully
// replicate ServeContent's status-code decision anyway just to interpret
// its side effects correctly, for no less code than porting the ~40-line
// precedence chain directly).
//
// A permanent differential test (TestEvaluatePreconditions_MatchesStdlibServeContent
// in preconditions_test.go) runs a table of header combinations through
// both this function and the real http.ServeContent (on a Range-satisfiable
// request, so only precondition handling can explain any difference) and
// asserts they agree — catching drift if a future Go version changes this
// logic.
func EvaluatePreconditions(r *http.Request, etag string, modTime time.Time) PreconditionOutcome {
	ch := checkIfMatch(r, etag)
	if ch == condNone {
		ch = checkIfUnmodifiedSince(r, modTime)
	}
	if ch == condFalse {
		return PreconditionOutcome{Status: http.StatusPreconditionFailed}
	}

	switch checkIfNoneMatch(r, etag) {
	case condFalse:
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			return PreconditionOutcome{Status: http.StatusNotModified}
		}
		return PreconditionOutcome{Status: http.StatusPreconditionFailed}
	case condNone:
		if checkIfModifiedSince(r, modTime) == condFalse {
			return PreconditionOutcome{Status: http.StatusNotModified}
		}
	}

	return PreconditionOutcome{}
}

// checkIfMatch ports net/http's checkIfMatch (net/http/fs.go), reading the
// current ETag from etag directly (our caller already knows it, rather than
// reading it back from a ResponseWriter the way net/http's version does —
// same result, since we set that header from this same value).
func checkIfMatch(r *http.Request, etag string) condResult {
	im := r.Header.Get("If-Match")
	if im == "" {
		return condNone
	}
	for {
		im = trimOWS(im)
		if len(im) == 0 {
			break
		}
		if im[0] == ',' {
			im = im[1:]
			continue
		}
		if im[0] == '*' {
			return condTrue
		}
		candidate, remain := scanETag(im)
		if candidate == "" {
			break
		}
		if etagStrongMatch(candidate, etag) {
			return condTrue
		}
		im = remain
	}
	return condFalse
}

// checkIfUnmodifiedSince ports net/http's checkIfUnmodifiedSince.
func checkIfUnmodifiedSince(r *http.Request, modTime time.Time) condResult {
	ius := r.Header.Get("If-Unmodified-Since")
	if ius == "" || isZeroTime(modTime) {
		return condNone
	}
	t, err := http.ParseTime(ius)
	if err != nil {
		return condNone
	}

	// Last-Modified truncates sub-second precision, so the precondition
	// must be applied with the same truncation.
	modTime = modTime.Truncate(time.Second)
	if modTime.Compare(t) <= 0 {
		return condTrue
	}
	return condFalse
}

// checkIfNoneMatch ports net/http's checkIfNoneMatch.
func checkIfNoneMatch(r *http.Request, etag string) condResult {
	inm := r.Header.Get("If-None-Match")
	if inm == "" {
		return condNone
	}
	buf := inm
	for {
		buf = trimOWS(buf)
		if len(buf) == 0 {
			break
		}
		if buf[0] == ',' {
			buf = buf[1:]
			continue
		}
		if buf[0] == '*' {
			return condFalse
		}
		candidate, remain := scanETag(buf)
		if candidate == "" {
			break
		}
		if etagWeakMatch(candidate, etag) {
			return condFalse
		}
		buf = remain
	}
	return condTrue
}

// checkIfModifiedSince ports net/http's checkIfModifiedSince.
func checkIfModifiedSince(r *http.Request, modTime time.Time) condResult {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return condNone
	}
	ims := r.Header.Get("If-Modified-Since")
	if ims == "" || isZeroTime(modTime) {
		return condNone
	}
	t, err := http.ParseTime(ims)
	if err != nil {
		return condNone
	}
	modTime = modTime.Truncate(time.Second)
	if modTime.Compare(t) <= 0 {
		return condFalse
	}
	return condTrue
}

// scanETag ports net/http's scanETag (net/http/fs.go) verbatim: it
// determines if a syntactically valid ETag is present at s, returning the
// ETag and the remaining text after consuming it, or "", "" if none.
func scanETag(s string) (etag string, remain string) {
	s = trimOWS(s)
	start := 0
	if strings.HasPrefix(s, "W/") {
		start = 2
	}
	if len(s[start:]) < 2 || s[start] != '"' {
		return "", ""
	}
	// ETag is either W/"text" or "text".
	// See RFC 9110 §8.8.3.
	for i := start + 1; i < len(s); i++ {
		c := s[i]
		switch {
		// Character values allowed in ETags.
		case c == 0x21 || c >= 0x23 && c <= 0x7E || c >= 0x80:
		case c == '"':
			return s[:i+1], s[i+1:]
		default:
			return "", ""
		}
	}
	return "", ""
}

// etagStrongMatch ports net/http's etagStrongMatch.
func etagStrongMatch(a, b string) bool {
	return a == b && a != "" && a[0] == '"'
}

// etagWeakMatch ports net/http's etagWeakMatch.
func etagWeakMatch(a, b string) bool {
	return strings.TrimPrefix(a, "W/") == strings.TrimPrefix(b, "W/")
}

// trimOWS trims RFC 9110 "optional whitespace" (a run of space and/or
// horizontal tab) from both ends of s — what net/http's own scanETag/
// checkIfMatch/checkIfNoneMatch use textproto.TrimString for. Implemented
// locally (rather than importing net/textproto for one call) since OWS is
// specifically SP/HTAB only, not the broader set strings.TrimSpace strips.
func trimOWS(s string) string {
	return strings.Trim(s, " \t")
}
