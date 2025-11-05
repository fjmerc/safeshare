package middleware

import (
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/yourusername/safeshare/internal/database"
)

// IPBlockCheck middleware checks if the client IP is blocked
func IPBlockCheck(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)

			// Check if IP is blocked
			blocked, err := database.IsIPBlocked(db, clientIP)
			if err != nil {
				slog.Error("failed to check IP block status",
					"ip", clientIP,
					"error", err,
				)
				// On error, allow the request to proceed (fail open)
				// but log the error for investigation
				next.ServeHTTP(w, r)
				return
			}

			if blocked {
				slog.Warn("blocked IP attempted access",
					"ip", clientIP,
					"path", r.URL.Path,
					"method", r.Method,
					"user_agent", r.Header.Get("User-Agent"),
				)
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
