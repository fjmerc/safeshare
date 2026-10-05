package middleware

import (
	"io"
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

// ReadFrom lets a claim download reach the real ResponseWriter's sendfile
// fast path (ADR-017 T33): http.ServeContent's io.CopyN hands the
// ResponseWriter a bounded io.Reader (an *io.LimitedReader) via ReadFrom
// when it's available, and net/http's own writer specially recognizes that
// reader — when it wraps an *os.File, as it does for a plaintext download —
// to drive sendfile. Go's struct embedding only promotes methods declared
// on the embedded http.ResponseWriter *interface*; io.ReaderFrom isn't one
// of them, so without this override a type assertion for it on this
// wrapper always fails even when the concrete writer underneath supports
// it, silently downgrading every wrapped response to a buffered copy loop.
func (rw *responseWriter) ReadFrom(src io.Reader) (int64, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	if rf, ok := rw.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(onlyWriter{rw.ResponseWriter}, src)
}

// onlyWriter strips every method except Write from w, so passing it as
// io.Copy's dst can never rediscover a ReadFrom method (on this type or
// whatever it wraps) and recurse back into responseWriter.ReadFrom.
type onlyWriter struct{ io.Writer }

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
				"path", privacy.RedactPath(redactPathClaimCodes(r.URL.Path), anonymousMode),
				"status", wrapped.statusCode,
				"duration", duration,
				"ip", privacy.RedactIP(ip, anonymousMode),
				"user_agent", privacy.RedactUserAgent(r.UserAgent(), anonymousMode),
			)
		})
	}
}

// logPath returns a request path for log output: claim codes are masked, and
// in anonymous mode (process-wide switch) only the route prefix is kept.
func logPath(path string) string {
	return privacy.RedactPath(redactPathClaimCodes(path), privacy.AnonymousMode())
}
