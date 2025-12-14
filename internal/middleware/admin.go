package middleware

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
)

// AdminAuth middleware checks for valid admin session
func AdminAuth(repos *repository.Repositories) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Try admin_session first
			adminCookie, adminErr := r.Cookie("admin_session")
			if adminErr == nil {
				// Validate admin session
				session, err := repos.Admin.GetSession(ctx, adminCookie.Value)
				if err != nil {
					slog.Error("failed to validate admin session",
						"error", err,
						"ip", getClientIP(r),
					)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}

				if session != nil {
					// Update session activity
					if err := repos.Admin.UpdateSessionActivity(ctx, adminCookie.Value); err != nil {
						slog.Error("failed to update admin session activity", "error", err)
					}
					// Session is valid, proceed
					next.ServeHTTP(w, r)
					return
				}
			}

			// Fall back to user_session with role check
			userCookie, userErr := r.Cookie("user_session")
			if userErr != nil {
				slog.Warn("admin authentication failed - no session cookie",
					"path", r.URL.Path,
					"ip", getClientIP(r),
				)
				// Redirect HTML requests to admin login page
				if isAdminHTMLRequest(r) {
					http.Redirect(w, r, "/admin/login", http.StatusFound)
					return
				}
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Validate user session
			userSession, err := repos.Users.GetSession(ctx, userCookie.Value)
			if err != nil {
				slog.Error("failed to validate user session",
					"error", err,
					"ip", getClientIP(r),
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if userSession == nil {
				slog.Warn("admin authentication failed - invalid session token",
					"path", r.URL.Path,
					"ip", getClientIP(r),
				)
				// Redirect HTML requests to admin login page
				if isAdminHTMLRequest(r) {
					http.Redirect(w, r, "/admin/login", http.StatusFound)
					return
				}
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Get user and check role
			user, err := repos.Users.GetByID(ctx, userSession.UserID)
			if err != nil || user == nil {
				slog.Error("failed to get user for admin check",
					"error", err,
					"user_id", userSession.UserID,
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if user.Role != "admin" {
				slog.Warn("admin authentication failed - insufficient permissions",
					"path", r.URL.Path,
					"user_id", user.ID,
					"username", user.Username,
					"role", user.Role,
				)
				// Redirect HTML requests to admin login page
				if isAdminHTMLRequest(r) {
					http.Redirect(w, r, "/admin/login", http.StatusFound)
					return
				}
				http.Error(w, "Forbidden - Admin access required", http.StatusForbidden)
				return
			}

			// Update session activity
			if err := repos.Users.UpdateSessionActivity(ctx, userCookie.Value); err != nil {
				slog.Error("failed to update user session activity", "error", err)
			}

			// User has admin role, proceed
			next.ServeHTTP(w, r)
		})
	}
}

// CSRFProtection middleware validates CSRF tokens for state-changing requests
func CSRFProtection(repos *repository.Repositories) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only check CSRF for state-changing methods
			if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" || r.Method == "PATCH" {
				ctx := r.Context()

				// Get CSRF token from header or form
				csrfToken := r.Header.Get("X-CSRF-Token")
				if csrfToken == "" {
					csrfToken = r.FormValue("csrf_token")
				}

				// Try to get session from either admin_session or user_session
				hasValidSession := false

				// Check admin_session first
				adminCookie, adminErr := r.Cookie("admin_session")
				if adminErr == nil {
					session, err := repos.Admin.GetSession(ctx, adminCookie.Value)
					if err == nil && session != nil {
						hasValidSession = true
					}
				}

				// If no admin session, check user_session with admin role
				if !hasValidSession {
					userCookie, userErr := r.Cookie("user_session")
					if userErr == nil {
						userSession, err := repos.Users.GetSession(ctx, userCookie.Value)
						if err == nil && userSession != nil {
							// Verify user has admin role
							user, err := repos.Users.GetByID(ctx, userSession.UserID)
							if err == nil && user != nil && user.Role == "admin" {
								hasValidSession = true
							}
						}
					}
				}

				if !hasValidSession {
					slog.Warn("CSRF validation failed - no valid session",
						"path", r.URL.Path,
						"ip", getClientIP(r),
					)
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}

				// Get CSRF token from cookie
				csrfCookie, err := r.Cookie("csrf_token")
				if err != nil || csrfToken == "" || csrfCookie == nil {
					slog.Warn("CSRF validation failed - missing token",
						"path", r.URL.Path,
						"ip", getClientIP(r),
						"has_csrf_header", csrfToken != "",
						"has_csrf_cookie", csrfCookie != nil,
					)
					http.Error(w, "Forbidden - Invalid CSRF token", http.StatusForbidden)
					return
				}

				// Use constant-time comparison to prevent timing attacks
				if subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(csrfToken)) != 1 {
					slog.Warn("CSRF validation failed - token mismatch",
						"path", r.URL.Path,
						"ip", getClientIP(r),
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
func SetCSRFCookie(w http.ResponseWriter, cfg *config.Config) (string, error) {
	token, err := utils.GenerateCSRFToken()
	if err != nil {
		return "", err
	}

	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/admin",
		HttpOnly: false, // JavaScript needs to read this
		Secure:   cfg.HTTPSEnabled,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 hours
	}

	http.SetCookie(w, cookie)
	return token, nil
}

// SetUserCSRFCookie sets a CSRF token cookie for user pages (site-wide scope)
func SetUserCSRFCookie(w http.ResponseWriter, cfg *config.Config) (string, error) {
	token, err := utils.GenerateCSRFToken()
	if err != nil {
		return "", err
	}

	cookie := &http.Cookie{
		Name:     "user_csrf_token",
		Value:    token,
		Path:     "/", // Site-wide for user routes
		HttpOnly: false, // JavaScript needs to read this
		Secure:   cfg.HTTPSEnabled,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 hours
	}

	http.SetCookie(w, cookie)
	return token, nil
}

// UserCSRFProtection middleware validates CSRF tokens for user routes (non-admin)
// This accepts any valid user session, not just admin sessions
func UserCSRFProtection(repos *repository.Repositories) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only check CSRF for state-changing methods
			if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" || r.Method == "PATCH" {
				ctx := r.Context()

				// Get CSRF token from header or form
				csrfToken := r.Header.Get("X-CSRF-Token")
				if csrfToken == "" {
					csrfToken = r.FormValue("csrf_token")
				}

				// Check user_session (accepts any authenticated user)
				hasValidSession := false
				userCookie, userErr := r.Cookie("user_session")
				if userErr == nil {
					userSession, err := repos.Users.GetSession(ctx, userCookie.Value)
					if err == nil && userSession != nil {
						hasValidSession = true
					}
				}

				if !hasValidSession {
					slog.Warn("user CSRF validation failed - no valid session",
						"path", r.URL.Path,
						"ip", getClientIP(r),
					)
					http.Error(w, "Forbidden - No valid session", http.StatusForbidden)
					return
				}

				// Get CSRF token from cookie (user-specific cookie)
				csrfCookie, err := r.Cookie("user_csrf_token")
				if err != nil || csrfToken == "" || csrfCookie == nil {
					slog.Warn("user CSRF validation failed - missing token",
						"path", r.URL.Path,
						"ip", getClientIP(r),
						"has_csrf_header", csrfToken != "",
						"has_csrf_cookie", csrfCookie != nil,
					)
					http.Error(w, "Forbidden - Missing CSRF token", http.StatusForbidden)
					return
				}

				// Use constant-time comparison to prevent timing attacks
				if subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(csrfToken)) != 1 {
					slog.Warn("user CSRF validation failed - token mismatch",
						"path", r.URL.Path,
						"ip", getClientIP(r),
					)
					http.Error(w, "Forbidden - Invalid CSRF token", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitTOTPVerify rate limits TOTP verification attempts per user/IP
// Prevents brute-force attacks on 6-digit TOTP codes
func RateLimitTOTPVerify() func(http.Handler) http.Handler {
	type verifyAttempt struct {
		count       int
		lastAttempt time.Time
	}

	attempts := make(map[string]*verifyAttempt)
	maxAttempts := 5      // Max attempts before lockout
	windowMinutes := 15   // Lockout window

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)

			// Clean up old entries
			now := time.Now()
			for key, attempt := range attempts {
				if now.Sub(attempt.lastAttempt) > time.Duration(windowMinutes)*time.Minute {
					delete(attempts, key)
				}
			}

			// Check rate limit
			if attempt, exists := attempts[clientIP]; exists {
				if attempt.count >= maxAttempts {
					if now.Sub(attempt.lastAttempt) < time.Duration(windowMinutes)*time.Minute {
						slog.Warn("TOTP verification rate limit exceeded",
							"ip", clientIP,
							"attempts", attempt.count,
						)
						http.Error(w, "Too many verification attempts. Please try again later.", http.StatusTooManyRequests)
						return
					}
					// Reset if window has passed
					attempt.count = 0
				}
			}

			// Increment attempt counter after the request completes
			defer func() {
				if attempts[clientIP] == nil {
					attempts[clientIP] = &verifyAttempt{}
				}
				attempts[clientIP].count++
				attempts[clientIP].lastAttempt = now
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitAdminLogin rate limits admin login attempts
func RateLimitAdminLogin() func(http.Handler) http.Handler {
	type loginAttempt struct {
		count       int
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

// RateLimitUserLogin rate limits user login attempts
func RateLimitUserLogin() func(http.Handler) http.Handler {
	type loginAttempt struct {
		count       int
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
						slog.Warn("user login rate limit exceeded",
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

// isAdminHTMLRequest detects if the request is for an HTML page vs an API endpoint
func isAdminHTMLRequest(r *http.Request) bool {
	// Admin API requests start with /admin/api/
	if strings.HasPrefix(r.URL.Path, "/admin/api/") {
		return false
	}
	// Check Accept header for HTML
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/html")
}
