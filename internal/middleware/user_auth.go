package middleware

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/yourusername/safeshare/internal/database"
)

// UserAuth middleware checks for valid user session
func UserAuth(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get session token from cookie
			cookie, err := r.Cookie("user_session")
			if err != nil {
				slog.Warn("user authentication failed - no session cookie",
					"path", r.URL.Path,
					"ip", getClientIP(r),
				)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Validate session
			session, err := database.GetUserSession(db, cookie.Value)
			if err != nil {
				slog.Error("failed to validate user session",
					"error", err,
					"ip", getClientIP(r),
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if session == nil {
				slog.Warn("user authentication failed - invalid session token",
					"path", r.URL.Path,
					"ip", getClientIP(r),
				)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Get user info
			user, err := database.GetUserByID(db, session.UserID)
			if err != nil {
				slog.Error("failed to get user",
					"error", err,
					"user_id", session.UserID,
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if user == nil {
				slog.Warn("user authentication failed - user not found",
					"user_id", session.UserID,
				)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if user is active
			if !user.IsActive {
				slog.Warn("user authentication failed - account disabled",
					"user_id", user.ID,
					"username", user.Username,
				)
				http.Error(w, "Account has been disabled", http.StatusForbidden)
				return
			}

			// Update session activity
			if err := database.UpdateUserSessionActivity(db, cookie.Value); err != nil {
				slog.Error("failed to update user session activity", "error", err)
				// Don't fail the request, just log the error
			}

			// Add user to context for handlers to access
			ctx := context.WithValue(r.Context(), "user", user)

			// Session is valid, proceed
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalUserAuth middleware checks for a user session but doesn't require it
// If a valid session exists, it adds the user to the context
// If no session or invalid session, it continues without error
func OptionalUserAuth(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try to get session token from cookie
			cookie, err := r.Cookie("user_session")
			if err != nil {
				// No session cookie, continue without user
				next.ServeHTTP(w, r)
				return
			}

			// Try to validate session
			session, err := database.GetUserSession(db, cookie.Value)
			if err != nil || session == nil {
				// Invalid session, continue without user
				next.ServeHTTP(w, r)
				return
			}

			// Try to get user info
			user, err := database.GetUserByID(db, session.UserID)
			if err != nil || user == nil || !user.IsActive {
				// Invalid or inactive user, continue without user
				next.ServeHTTP(w, r)
				return
			}

			// Update session activity
			database.UpdateUserSessionActivity(db, cookie.Value)

			// Add user to context
			ctx := context.WithValue(r.Context(), "user", user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
