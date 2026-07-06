package middleware

import (
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/fjmerc/safeshare/internal/privacy"
)

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	if !rw.written {
		rw.statusCode = statusCode
		rw.ResponseWriter.WriteHeader(statusCode)
		rw.written = true
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer; without it
// per-request deadline extensions (and Flush/Hijack upgrades) silently fail.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// claimCodeRegex matches claim codes in URLs (e.g., /api/claim/ABC123xyz or /api/claim/ABC-123-xyz/info)
var claimCodeRegex = regexp.MustCompile(`(/api/claim/)([^/\s]+)`)

// redactPathClaimCodes redacts claim codes from URL paths for secure logging
// Example: /api/claim/Xy9kLm8pQz4vDwE/info -> /api/claim/Xy9...wE/info
func redactPathClaimCodes(path string) string {
	return claimCodeRegex.ReplaceAllStringFunc(path, func(match string) string {
		// Extract the claim code part
		submatches := claimCodeRegex.FindStringSubmatch(match)
		if len(submatches) < 3 {
			return match
		}
		prefix := submatches[1]    // "/api/claim/"
		claimCode := submatches[2] // The actual claim code

		// Redact the claim code (show first 3 and last 2 chars)
		var redacted string
		if len(claimCode) > 5 {
			redacted = claimCode[:3] + "..." + claimCode[len(claimCode)-2:]
		} else {
			redacted = "***"
		}

		return prefix + redacted
	})
}

// LoggingMiddleware logs HTTP requests with method, path, status, duration, and IP.
// When anonymousMode is true, IP addresses are redacted from log output.
func LoggingMiddleware(anonymousMode bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap the response writer to capture status code
			wrapped := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				written:        false,
			}

			// Call the next handler
			next.ServeHTTP(wrapped, r)

			// Log request details
			duration := time.Since(start)
			ip := getClientIP(r)

			slog.Info("http request",
				"method", r.Method,
				"path", redactPathClaimCodes(r.URL.Path),
				"status", wrapped.statusCode,
				"duration", duration,
				"ip", privacy.RedactIP(ip, anonymousMode),
				"user_agent", r.UserAgent(),
			)
		})
	}
}
