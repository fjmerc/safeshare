package safeshare

import (
	"errors"
	"testing"
)

// TestNewAPIError_TokenRefusals: a 403 for a token that lacks a scope, or
// for a route that needs a browser session, is not a quota error.
func TestNewAPIError_TokenRefusals(t *testing.T) {
	for _, code := range []string{"INSUFFICIENT_SCOPE", "SESSION_REQUIRED"} {
		err := newAPIError(403, "refused", code)
		if !errors.Is(err, ErrInsufficientScope) {
			t.Errorf("%s: %v is not ErrInsufficientScope", code, err)
		}
		if errors.Is(err, ErrQuotaExceeded) {
			t.Errorf("%s: reported as a quota error", code)
		}
	}
}
