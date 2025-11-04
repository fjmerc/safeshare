package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/yourusername/safeshare/internal/models"
)

// RecoveryMiddleware recovers from panics and returns a 500 error
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log the panic with stack trace
				stack := debug.Stack()
				slog.Error("panic recovered",
					"error", err,
					"path", r.URL.Path,
					"method", r.Method,
					"stack", string(stack),
				)

				// Return 500 error response
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)

				errResp := models.ErrorResponse{
					Error: "Internal server error",
					Code:  "INTERNAL_ERROR",
				}

				json.NewEncoder(w).Encode(errResp)
			}
		}()

		next.ServeHTTP(w, r)
	})
}
