package metrics

import (
	"net/http"
	"strconv"
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

// normalizePath normalizes URL paths for metric labels to avoid cardinality explosion
// Replaces dynamic segments (UUIDs, claim codes) with placeholders
func normalizePath(path string) string {
	// Map specific paths to normalized versions
	switch {
	case path == "/":
		return "/"
	case path == "/health":
		return "/health"
	case path == "/metrics":
		return "/metrics"
	case path == "/api/upload":
		return "/api/upload"
	case path == "/api/config":
		return "/api/config"
	case path == "/admin/login":
		return "/admin/login"
	case path == "/admin/dashboard":
		return "/admin/dashboard"
	case path == "/login":
		return "/login"
	case path == "/dashboard":
		return "/dashboard"

	// API patterns with dynamic segments
	case len(path) > 11 && path[:11] == "/api/claim/":
		if len(path) > 16 && path[len(path)-5:] == "/info" {
			return "/api/claim/:code/info"
		}
		return "/api/claim/:code"

	case path == "/api/upload/init":
		return "/api/upload/init"

	case len(path) > 18 && path[:18] == "/api/upload/chunk/":
		return "/api/upload/chunk/:id/:number"

	case len(path) > 21 && path[:21] == "/api/upload/complete/":
		return "/api/upload/complete/:id"

	case len(path) > 19 && path[:19] == "/api/upload/status/":
		return "/api/upload/status/:id"

	// Admin API patterns
	case len(path) > 10 && path[:10] == "/admin/api":
		return "/admin/api/*"

	// User API patterns
	case len(path) > 9 && path[:9] == "/api/auth":
		return "/api/auth/*"

	case len(path) > 9 && path[:9] == "/api/user":
		return "/api/user/*"

	// Static assets
	case len(path) > 8 && path[:8] == "/assets/":
		return "/assets/*"

	case len(path) > 14 && path[:14] == "/admin/assets/":
		return "/admin/assets/*"

	default:
		return "/other"
	}
}
