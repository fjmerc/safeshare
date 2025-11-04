package handlers

import (
	"net/http"
	"strings"

	"github.com/yourusername/safeshare/internal/config"
)

// buildDownloadURL constructs the full download URL for a claim code
// Respects PUBLIC_URL config and reverse proxy headers
func buildDownloadURL(r *http.Request, cfg *config.Config, claimCode string) string {
	// If PUBLIC_URL is configured, use it
	if cfg.PublicURL != "" {
		baseURL := strings.TrimSuffix(cfg.PublicURL, "/")
		return baseURL + "/api/claim/" + claimCode
	}

	// Otherwise, auto-detect from request headers
	scheme := getScheme(r)
	host := getHost(r)
	return scheme + "://" + host + "/api/claim/" + claimCode
}

// getScheme returns the scheme (http/https) respecting reverse proxy headers
func getScheme(r *http.Request) string {
	// Check X-Forwarded-Proto first (set by reverse proxies)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}

	// Check if TLS is terminated at this server
	if r.TLS != nil {
		return "https"
	}

	return "http"
}

// getHost returns the host respecting reverse proxy headers
func getHost(r *http.Request) string {
	// Check X-Forwarded-Host first (set by reverse proxies)
	if host := r.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}

	// Fall back to Host header
	return r.Host
}

// getClientIP returns the client IP address respecting reverse proxy headers
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (standard for reverse proxies)
	// Format: "client, proxy1, proxy2"
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Get the first IP (the original client)
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header (used by nginx)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr (direct connection)
	// RemoteAddr format is "IP:port", we just want the IP
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}

	return r.RemoteAddr
}

// getUserAgent returns the client User-Agent header
func getUserAgent(r *http.Request) string {
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		return "unknown"
	}
	return ua
}

// redactClaimCode redacts claim codes for secure logging
// Shows first 3 and last 2 characters only (e.g., "Xy9...wE")
// Claim codes are like passwords and should not be logged in full
func redactClaimCode(code string) string {
	if len(code) <= 5 {
		return "***"
	}
	return code[:3] + "..." + code[len(code)-2:]
}
