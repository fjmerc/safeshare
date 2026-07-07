package middleware

import (
	"net/http"

	"github.com/fjmerc/safeshare/internal/utils"
)

// getClientIP returns the client IP address using the process-wide proxy
// trust settings configured at startup (TRUST_PROXY_HEADERS / TRUSTED_PROXY_IPS).
// Used by middleware functions that don't have access to config.
func getClientIP(r *http.Request) string {
	return utils.GetClientIP(r)
}
