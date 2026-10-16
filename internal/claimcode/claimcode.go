// Package claimcode holds the claim-code format rules shared by validation,
// generation bounds, config, request-path redaction and short-link routing.
// It is a leaf package (stdlib only) so that low-level packages such as
// privacy and config can use it without import cycles.
package claimcode

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// MinLength is the shortest claim code accepted anywhere. Claim codes are
	// bearer secrets, so short ones are guessable; this floor matches the
	// {8,32} format enforced on every user-dashboard endpoint.
	MinLength = 8
	// MaxLength is the longest accepted claim code.
	MaxLength = 32
	// DefaultLength is the length of newly generated codes (96 bits of entropy).
	DefaultLength = 16
)

// reservedRootNames are single-segment root paths that are application routes
// (or route prefixes) and therefore never short claim links. Only names of
// MinLength or more characters are load-bearing: shorter names (e.g. "api",
// "login") can never be valid codes anyway, and dotted names such as
// "service-worker.js" are rejected by Valid. The rest are listed so the
// intent is explicit and survives a future change to MinLength.
var reservedRootNames = map[string]struct{}{
	"admin":     {},
	"api":       {},
	"assets":    {},
	"dashboard": {},
	"health":    {},
	"login":     {},
	"metrics":   {},
}

// Valid reports whether code has a valid claim-code format: MinLength to
// MaxLength characters from the URL-safe base64 alphabet (a-z, A-Z, 0-9, -, _).
func Valid(code string) bool {
	if len(code) < MinLength || len(code) > MaxLength {
		return false
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// ShortPath reports whether a request path has the short claim link form
// "/<code>": a single segment that is a valid claim code and not a reserved
// application route. It performs no lookup; callers must not treat a match as
// proof that the file exists.
func ShortPath(path string) (code string, ok bool) {
	if len(path) < 2 || path[0] != '/' {
		return "", false
	}
	code = path[1:]
	if strings.IndexByte(code, '/') >= 0 || !Valid(code) {
		return "", false
	}
	if _, reserved := reservedRootNames[code]; reserved {
		return "", false
	}
	return code, true
}

// ValidLength reports whether n is an acceptable claim-code length.
func ValidLength(n int) bool {
	return n >= MinLength && n <= MaxLength
}

// ParseLength parses a claim-code length from a string (an environment
// variable or flag value). Surrounding whitespace is ignored; a non-integer or
// out-of-range value is an error.
func ParseLength(s string) (int, error) {
	v := strings.TrimSpace(s)
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("must be an integer between %d and %d, got %q", MinLength, MaxLength, s)
	}
	if !ValidLength(n) {
		return 0, fmt.Errorf("must be between %d and %d, got %d", MinLength, MaxLength, n)
	}
	return n, nil
}

// LooseShortPath is ShortPath for log redaction: it also recognises
// non-canonical spellings of a short link such as "//<code>" and "/<code>/",
// which the router would not redirect but which still carry the secret.
func LooseShortPath(path string) (code string, ok bool) {
	return ShortPath("/" + strings.Trim(path, "/"))
}

// Mask returns a log-safe form of a claim code that reveals only as much as
// the code's length can afford: 16+ characters keep the first 3 and last 2
// ("Xy9...wE"), 12-15 keep the first 2, shorter codes keep the first
// character, and anything of 5 characters or fewer is fully hidden.
func Mask(code string) string {
	n := len(code)
	switch {
	case n >= 16:
		return code[:3] + "..." + code[n-2:]
	case n >= 12:
		return code[:2] + "..."
	case n > 5:
		return code[:1] + "..."
	default:
		return "***"
	}
}
