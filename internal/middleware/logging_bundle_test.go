package middleware

import (
	"strings"
	"testing"
)

// TestRedactPathClaimCodes_BundlePaths: bundle codes are as secret as claim
// codes, so request logs must mask them the same way.
func TestRedactPathClaimCodes_BundlePaths(t *testing.T) {
	const code = "Xy9kLm8pQz4vDwEa"
	for _, path := range []string{
		"/api/bundle/" + code + "/info",
		"/api/bundle/" + code + "/files/0",
		"/api/bundle/" + code,
	} {
		got := redactPathClaimCodes(path)
		if strings.Contains(got, code) {
			t.Errorf("%s logged as %s: bundle code not masked", path, got)
		}
		if !strings.HasPrefix(got, "/api/bundle/") {
			t.Errorf("%s logged as %s: prefix lost", path, got)
		}
	}
	// The management routes carry a numeric id, not a secret; leave them readable.
	if got := redactPathClaimCodes("/api/bundles/42/publish"); got != "/api/bundles/42/publish" {
		t.Errorf("/api/bundles/42/publish logged as %s", got)
	}
}
