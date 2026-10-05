package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/privacy"
)

// RecoveryMiddleware recovers from panics and returns a 500 error
func RecoveryMiddleware(next http.Handler) http.Handler {
	return NewRecoveryMiddleware(false)(next)
}

// NewRecoveryMiddleware is RecoveryMiddleware with anonymous-mode awareness:
// when anonymousMode is true the panic log carries only the route prefix of the
// request path, because paths contain claim codes (bearer secrets).
func NewRecoveryMiddleware(anonymousMode bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return recoveryHandler(next, anonymousMode)
	}
}

func recoveryHandler(next http.Handler, anonymousMode bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log the panic with stack trace
				stack := debug.Stack()
				slog.Error("panic recovered",
					"error", err,
					"path", privacy.RedactPath(r.URL.Path, anonymousMode),
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
