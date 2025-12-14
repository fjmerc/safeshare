package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/fjmerc/safeshare/internal/repository"
)

// statusCapturingWriter wraps http.ResponseWriter to capture the status code
type statusCapturingWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// WriteHeader captures the status code before writing it
func (w *statusCapturingWriter) WriteHeader(code int) {
	if !w.written {
		w.statusCode = code
		w.written = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write captures the default status (200) if WriteHeader wasn't called
func (w *statusCapturingWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.statusCode = http.StatusOK
		w.written = true
	}
	return w.ResponseWriter.Write(b)
}

// APITokenAuditLog middleware logs API token usage after the request completes.
// It should be applied to routes that support API token authentication.
// This middleware captures the HTTP response status code and logs it along with
// the request details for audit purposes.
func APITokenAuditLog(repos *repository.Repositories) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Wrap the response writer to capture status code
			captured := &statusCapturingWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK, // Default if WriteHeader is never called
			}

			// Call the next handler
			next.ServeHTTP(captured, r)

			// After request completes, check if this was API token auth
			tokenID := GetTokenIDFromContext(r)
			if tokenID <= 0 {
				// Not API token auth, nothing to log
				return
			}

			// Log the usage asynchronously to not delay the response
			endpoint := r.URL.Path
			clientIP := getClientIP(r)
			userAgent := r.Header.Get("User-Agent")
			status := captured.statusCode

			go func() {
				// Use background context since request context may be cancelled
				if err := repos.APITokens.LogUsage(context.Background(), tokenID, endpoint, clientIP, userAgent, status); err != nil {
					slog.Error("failed to log API token usage",
						"error", err,
						"token_id", tokenID,
						"endpoint", endpoint,
					)
				}
			}()
		})
	}
}

// GetTokenIDFromContext retrieves the API token ID from the request context.
// Returns 0 if no token ID is set (e.g., session auth or unauthenticated).
func GetTokenIDFromContext(r *http.Request) int64 {
	tokenID, ok := r.Context().Value(ContextKeyTokenID).(int64)
	if !ok {
		return 0
	}
	return tokenID
}
