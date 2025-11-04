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
