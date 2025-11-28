package metrics

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Middleware instruments HTTP handlers with request metrics
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // Default to 200 if WriteHeader not called
		}

		// Call next handler
		next.ServeHTTP(wrapped, r)

		// Record metrics
		duration := time.Since(start).Seconds()
		path := normalizePath(r.URL.Path)
		method := r.Method
		status := strconv.Itoa(wrapped.statusCode)

		HTTPRequestDuration.WithLabelValues(method, path).Observe(duration)
		HTTPRequestsTotal.WithLabelValues(method, path, status).Inc()
	})
}

// pathPattern represents a URL pattern with a prefix and normalized form
type pathPattern struct {
	prefix     string
	normalized string
	hasInfo    bool // Special handling for /info suffix
}

// Static paths that map directly to themselves
var exactPaths = map[string]string{
	"/":                  "/",
	"/health":            "/health",
	"/metrics":           "/metrics",
	"/api/upload":        "/api/upload",
	"/api/config":        "/api/config",
	"/api/upload/init":   "/api/upload/init",
	"/admin/login":       "/admin/login",
	"/admin/dashboard":   "/admin/dashboard",
	"/login":             "/login",
	"/dashboard":         "/dashboard",
}

// Dynamic path patterns with prefix matching
// Ordered by specificity (longest/most specific first)
var prefixPatterns = []pathPattern{
	{prefix: "/api/upload/complete/", normalized: "/api/upload/complete/:id"},
	{prefix: "/api/upload/status/", normalized: "/api/upload/status/:id"},
	{prefix: "/api/upload/chunk/", normalized: "/api/upload/chunk/:id/:number"},
	{prefix: "/api/claim/", normalized: "/api/claim/:code", hasInfo: true},
	{prefix: "/admin/assets/", normalized: "/admin/assets/*"},
	{prefix: "/admin/api", normalized: "/admin/api/*"},
	{prefix: "/api/auth", normalized: "/api/auth/*"},
	{prefix: "/api/user", normalized: "/api/user/*"},
	{prefix: "/assets/", normalized: "/assets/*"},
}

// normalizePath normalizes URL paths for metric labels to avoid cardinality explosion
// Replaces dynamic segments (UUIDs, claim codes) with placeholders
func normalizePath(path string) string {
	// Check exact matches first
	if normalized, ok := exactPaths[path]; ok {
		return normalized
	}

	// Check prefix patterns
	normalized := matchPrefixPattern(path)
	if normalized != "" {
		return normalized
	}

	// Default fallback
	return "/other"
}

// matchPrefixPattern checks if path matches any prefix pattern and returns normalized form
func matchPrefixPattern(path string) string {
	for _, pattern := range prefixPatterns {
		if strings.HasPrefix(path, pattern.prefix) {
			// Special handling for /api/claim/:code/info
			if pattern.hasInfo && strings.HasSuffix(path, "/info") {
				return "/api/claim/:code/info"
			}
			return pattern.normalized
		}
	}
	return ""
}
