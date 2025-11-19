package middleware

import (
	"net/http"

	"github.com/fjmerc/safeshare/internal/utils"
)

// getClientIP returns the client IP address with default trusted proxy settings
// This is used by middleware functions that don't have access to config
// Uses auto mode with RFC1918 + localhost ranges for backward compatibility
func getClientIP(r *http.Request) string {
	return utils.GetClientIPWithTrust(r, "auto", "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
}
