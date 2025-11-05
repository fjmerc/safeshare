package middleware

import (
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/yourusername/safeshare/internal/database"
	"github.com/yourusername/safeshare/internal/utils"
)

// AdminAuth middleware checks for valid admin session
func AdminAuth(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get session token from cookie
			cookie, err := r.Cookie("admin_session")
			if err != nil {
				slog.Warn("admin authentication failed - no session cookie",
					"path", r.URL.Path,
					"ip", getClientIP(r),
				)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Validate session
			session, err := database.GetSession(db, cookie.Value)
			if err != nil {
				slog.Error("failed to validate session",
					"error", err,
					"ip", getClientIP(r),
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if session == nil {
				slog.Warn("admin authentication failed - invalid session token",
					"path", r.URL.Path,
					"ip", getClientIP(r),
				)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Update session activity
			if err := database.UpdateSessionActivity(db, cookie.Value); err != nil {
				slog.Error("failed to update session activity", "error", err)
				// Don't fail the request, just log the error
			}

			// Session is valid, proceed
			next.ServeHTTP(w, r)
		})
	}
}

// CSRFProtection middleware validates CSRF tokens for state-changing requests
func CSRFProtection(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only check CSRF for state-changing methods
			if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" || r.Method == "PATCH" {
				// Get CSRF token from header or form
				csrfToken := r.Header.Get("X-CSRF-Token")
				if csrfToken == "" {
					csrfToken = r.FormValue("csrf_token")
				}

				// Get session token from cookie
				cookie, err := r.Cookie("admin_session")
				if err != nil {
					slog.Warn("CSRF validation failed - no session cookie",
						"path", r.URL.Path,
						"ip", getClientIP(r),
					)
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}

				// Get session
				session, err := database.GetSession(db, cookie.Value)
				if err != nil || session == nil {
					slog.Warn("CSRF validation failed - invalid session",
						"path", r.URL.Path,
						"ip", getClientIP(r),
					)
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}

				// Get CSRF token from cookie
				csrfCookie, err := r.Cookie("csrf_token")
				if err != nil || csrfToken == "" || csrfCookie.Value != csrfToken {
					slog.Warn("CSRF validation failed - token mismatch",
						"path", r.URL.Path,
						"ip", getClientIP(r),
						"has_csrf_header", csrfToken != "",
						"has_csrf_cookie", csrfCookie != nil,
					)
					http.Error(w, "Forbidden - Invalid CSRF token", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SetCSRFCookie sets a CSRF token cookie for admin pages
func SetCSRFCookie(w http.ResponseWriter) (string, error) {
	token, err := utils.GenerateCSRFToken()
	if err != nil {
		return "", err
	}

	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/admin",
		HttpOnly: false, // JavaScript needs to read this
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 hours
	}

	http.SetCookie(w, cookie)
	return token, nil
}

// RateLimitAdminLogin rate limits admin login attempts
func RateLimitAdminLogin() func(http.Handler) http.Handler {
	type loginAttempt struct {
		count      int
		lastAttempt time.Time
	}

	attempts := make(map[string]*loginAttempt)
	maxAttempts := 5
	windowMinutes := 15

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)

			// Clean up old entries
			now := time.Now()
			for ip, attempt := range attempts {
				if now.Sub(attempt.lastAttempt) > time.Duration(windowMinutes)*time.Minute {
					delete(attempts, ip)
				}
			}

			// Check rate limit
			if attempt, exists := attempts[clientIP]; exists {
				if attempt.count >= maxAttempts {
					if now.Sub(attempt.lastAttempt) < time.Duration(windowMinutes)*time.Minute {
						slog.Warn("admin login rate limit exceeded",
							"ip", clientIP,
							"attempts", attempt.count,
						)
						http.Error(w, "Too many login attempts. Please try again later.", http.StatusTooManyRequests)
						return
					}
					// Reset if window has passed
					attempt.count = 0
				}
			}

			// Increment attempt counter after the request completes
			// We'll do this in a deferred function
			defer func() {
				if attempts[clientIP] == nil {
					attempts[clientIP] = &loginAttempt{}
				}
				attempts[clientIP].count++
				attempts[clientIP].lastAttempt = now
			}()

			next.ServeHTTP(w, r)
		})
	}
}
