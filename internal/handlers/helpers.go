package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/static"
	"github.com/fjmerc/safeshare/internal/utils"
)

// buildDownloadURL constructs the full download URL for a claim code
// Priority order: DOWNLOAD_URL > PUBLIC_URL > auto-detect from request headers
//
// DOWNLOAD_URL: Optional dedicated domain for downloads (bypasses CDN timeouts)
// PUBLIC_URL: General base URL for the application
// Auto-detect: Falls back to request headers (X-Forwarded-Host, X-Forwarded-Proto)
func buildDownloadURL(r *http.Request, cfg *config.Config, claimCode string) string {
	// Priority 1: Use DOWNLOAD_URL if configured (for CDN bypass)
	if cfg.DownloadURL != "" {
		baseURL := strings.TrimSuffix(cfg.DownloadURL, "/")
		return baseURL + "/api/claim/" + claimCode
	}

	// Priority 2: Use PUBLIC_URL if configured
	if cfg.PublicURL != "" {
		baseURL := strings.TrimSuffix(cfg.PublicURL, "/")
		return baseURL + "/api/claim/" + claimCode
	}

	// Priority 3: Auto-detect from request headers (reverse proxy support)
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

// getClientIPWithConfig returns the client IP address with trusted proxy validation
func getClientIPWithConfig(r *http.Request, cfg *config.Config) string {
	return utils.GetClientIPWithTrust(r, cfg.GetTrustProxyHeaders(), cfg.GetTrustedProxyIPs())
}

// getClientIP returns the client IP address with default trusted proxy settings
// This function uses auto mode with RFC1918 + localhost ranges for backward compatibility
func getClientIP(r *http.Request) string {
	// Use auto mode with standard private IP ranges
	return utils.GetClientIPWithTrust(r, "auto", "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
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

// isHTMLRequest checks if the client accepts HTML responses
// Browsers send Accept: text/html,application/xhtml+xml,...
// API clients typically send Accept: application/json or */*
func isHTMLRequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	// Check if Accept header contains text/html
	return strings.Contains(accept, "text/html")
}

// sendError sends a JSON error response
// This is used for API clients
func sendError(w http.ResponseWriter, message, code string, statusCode int) {
	sendErrorWithRetry(w, message, code, statusCode, nil, nil)
}

// sendErrorWithRetry sends a JSON error response with retry recommendations
// This is used for API clients with retry guidance
func sendErrorWithRetry(w http.ResponseWriter, message, code string, statusCode int, retryRecommended *bool, retryAfter *int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(models.ErrorResponse{
		Error:            message,
		Code:             code,
		RetryRecommended: retryRecommended,
		RetryAfter:       retryAfter,
	})
}

// sendHTMLError sends an HTML error page
// This is used for browser clients
func sendHTMLError(w http.ResponseWriter, title, message, code string, statusCode int) {
	// Read error.html template from embedded filesystem
	fs := static.FileSystem()
	file, err := fs.Open("error.html")
	if err != nil {
		// Fallback to plain text error if template not found
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(statusCode)
		fmt.Fprintf(w, "%s\n\n%s\n\nError Code: %s", title, message, code)
		return
	}
	defer file.Close()

	// Read template content
	templateBytes, err := io.ReadAll(file)
	if err != nil {
		// Fallback to plain text error if read fails
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(statusCode)
		fmt.Fprintf(w, "%s\n\n%s\n\nError Code: %s", title, message, code)
		return
	}

	template := string(templateBytes)

	// Replace placeholders
	template = strings.ReplaceAll(template, "{{TITLE}}", title)
	template = strings.ReplaceAll(template, "{{MESSAGE}}", message)
	template = strings.ReplaceAll(template, "{{CODE}}", code)

	// Send response
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	w.Write([]byte(template))
}

// sendErrorResponse sends either HTML or JSON error based on client preference
// This provides smart error handling for both browsers and API clients
func sendErrorResponse(w http.ResponseWriter, r *http.Request, title, message, code string, statusCode int) {
	if isHTMLRequest(r) {
		sendHTMLError(w, title, message, code, statusCode)
	} else {
		sendError(w, message, code, statusCode)
	}
}

// shouldRetryError determines if an error code should recommend retry to client
// Returns (shouldRetry, retryAfterSeconds)
func shouldRetryError(code string) (bool, int) {
	retryableErrors := map[string]int{
		"INTERNAL_ERROR":       5,  // Internal errors - retry after 5s
		"DATABASE_ERROR":       3,  // Database errors - retry after 3s
		"INSUFFICIENT_STORAGE": 30, // Storage issues - retry after 30s
		"RATE_LIMITED":         60, // Rate limiting - retry after 60s
		"QUOTA_EXCEEDED":       0,  // Quota exceeded - retry won't help
		"NETWORK_ERROR":        2,  // Network issues - retry after 2s
		"TIMEOUT":              5,  // Timeout - retry after 5s
	}

	nonRetryableErrors := map[string]bool{
		"INVALID_JSON":        true,
		"MISSING_FILENAME":    true,
		"INVALID_FILENAME":    true,
		"BLOCKED_EXTENSION":   true,
		"INVALID_TOTAL_SIZE":  true,
		"FILE_TOO_LARGE":      true,
		"TOO_MANY_CHUNKS":     true,
		"EXPIRATION_TOO_LONG": true,
		"METHOD_NOT_ALLOWED":  true,
		"FEATURE_DISABLED":    true,
		"UNAUTHORIZED":        true,
		"FORBIDDEN":           true,
		"INVALID_CHUNK":       true,
		"CHECKSUM_MISMATCH":   true, // Retry won't help - data corruption
	}

	// Check if explicitly non-retryable
	if nonRetryableErrors[code] {
		return false, 0
	}

	// Check if explicitly retryable
	if retryAfter, ok := retryableErrors[code]; ok {
		return true, retryAfter
	}

	// Default: unknown errors are retryable after 5s
	return true, 5
}

// sendSmartError sends an error with automatic retry recommendation
// based on the error code
func sendSmartError(w http.ResponseWriter, message, code string, statusCode int) {
	shouldRetry, retryAfter := shouldRetryError(code)

	var retryRecommended *bool
	var retryAfterPtr *int

	retryRecommended = &shouldRetry
	if shouldRetry && retryAfter > 0 {
		retryAfterPtr = &retryAfter
	}

	sendErrorWithRetry(w, message, code, statusCode, retryRecommended, retryAfterPtr)
}
