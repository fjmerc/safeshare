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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(models.ErrorResponse{
		Error: message,
		Code:  code,
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
