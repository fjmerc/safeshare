package middleware

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/privacy"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
)

// AdminAuth middleware checks for valid admin session
func AdminAuth(repos *repository.Repositories, anonymousMode bool) func(http.Handler) http.Handler {
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
						"ip", privacy.RedactIP(getClientIP(r), anonymousMode),
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
					"ip", privacy.RedactIP(getClientIP(r), anonymousMode),
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
					"ip", privacy.RedactIP(getClientIP(r), anonymousMode),
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if userSession == nil {
				slog.Warn("admin authentication failed - invalid session token",
					"path", r.URL.Path,
					"ip", privacy.RedactIP(getClientIP(r), anonymousMode),
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
func CSRFProtection(repos *repository.Repositories, anonymousMode bool) func(http.Handler) http.Handler {
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
						"ip", privacy.RedactIP(getClientIP(r), anonymousMode),
					)
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}

				// Get CSRF token from cookie
				csrfCookie, err := r.Cookie("csrf_token")
				if err != nil || csrfToken == "" || csrfCookie == nil {
					slog.Warn("CSRF validation failed - missing token",
						"path", r.URL.Path,
						"ip", privacy.RedactIP(getClientIP(r), anonymousMode),
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
						"ip", privacy.RedactIP(getClientIP(r), anonymousMode),
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
func UserCSRFProtection(repos *repository.Repositories, anonymousMode bool) func(http.Handler) http.Handler {
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
						"ip", privacy.RedactIP(getClientIP(r), anonymousMode),
					)
					http.Error(w, "Forbidden - No valid session", http.StatusForbidden)
					return
				}

				// Get CSRF token from cookie (user-specific cookie)
				csrfCookie, err := r.Cookie("user_csrf_token")
				if err != nil || csrfToken == "" || csrfCookie == nil {
					slog.Warn("user CSRF validation failed - missing token",
						"path", r.URL.Path,
						"ip", privacy.RedactIP(getClientIP(r), anonymousMode),
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
						"ip", privacy.RedactIP(getClientIP(r), anonymousMode),
					)
					http.Error(w, "Forbidden - Invalid CSRF token", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// maxTrackedLoginAttempts caps how many distinct client IPs a single
// rate-limiter instance (see newLoginRateLimiter) will track at once. This
// bounds the attempts map's memory under an attacker spraying requests from
// many source addresses. It's a var, not a const, so tests can shrink it to
// exercise the cap without allocating 100k entries.
var maxTrackedLoginAttempts = 100_000

// loginAttempt tracks one client IP's recent attempts against a rate
// limiter built by newLoginRateLimiter.
type loginAttempt struct {
	count       int
	lastAttempt time.Time
}

// loginRateLimitConfig parameterizes newLoginRateLimiter for each of the
// three call sites (admin login, user login, TOTP verify), which were
// previously near-identical copies of the same logic.
type loginRateLimitConfig struct {
	// label names the limiter in log messages, e.g. "admin login" produces
	// the log message "admin login rate limit exceeded".
	label string
	// limitedBody is the response body written on a 429.
	limitedBody   string
	maxAttempts   int
	windowMinutes int
}

// newLoginRateLimiter builds rate-limiting middleware that tracks failed
// attempts per client IP in memory.
//
// The returned middleware is meant to be constructed once by the caller and
// reused across every request - never inside a per-request handler closure,
// which would allocate a fresh, empty attempts map each time and the
// lockout could never trigger (this was a real bug: see hotfix v1.7.1).
// Because a single instance is shared across concurrent HTTP requests:
//
//   - Access to the attempts map is guarded by mu.
//   - The attempt is reserved (count incremented, lastAttempt set) under
//     the same lock as the limit check, before next.ServeHTTP is called.
//     Incrementing only after the handler returned - the original
//     behavior - let a burst of parallel requests from one IP all pass the
//     check before any of them finished (e.g. a slow password hash) and
//     incremented the count, bypassing the lockout entirely.
//   - The expired-entry sweep runs at most once a minute rather than on
//     every request, so per-request cost doesn't grow with the number of
//     tracked IPs.
//   - The number of distinct tracked IPs is capped at
//     maxTrackedLoginAttempts; once reached, a request from a new IP is
//     rejected (fails closed) with the same 429 used for a real lockout,
//     and a Warn is logged at most once per sweep interval.
func newLoginRateLimiter(anonymousMode bool, cfg loginRateLimitConfig) func(http.Handler) http.Handler {
	window := time.Duration(cfg.windowMinutes) * time.Minute

	var (
		mu          sync.Mutex
		attempts    = make(map[string]*loginAttempt)
		lastSweep   time.Time
		lastCapWarn time.Time
	)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)
			now := time.Now()

			mu.Lock()

			// Sweep expired entries at most once a minute.
			if now.Sub(lastSweep) >= time.Minute {
				for ip, attempt := range attempts {
					if now.Sub(attempt.lastAttempt) > window {
						delete(attempts, ip)
					}
				}
				lastSweep = now
			}

			attempt, exists := attempts[clientIP]

			// The sweep above only runs once a minute, so an entry can
			// outlive its window by up to that long; reset it here so an
			// expired window never counts toward the limit.
			if exists && now.Sub(attempt.lastAttempt) >= window {
				attempt.count = 0
			}

			if exists && attempt.count >= cfg.maxAttempts {
				attemptCount := attempt.count
				mu.Unlock()
				slog.Warn(cfg.label+" rate limit exceeded",
					"ip", privacy.RedactIP(clientIP, anonymousMode),
					"attempts", attemptCount,
				)
				http.Error(w, cfg.limitedBody, http.StatusTooManyRequests)
				return
			}

			if !exists {
				if len(attempts) >= maxTrackedLoginAttempts {
					shouldWarn := now.Sub(lastCapWarn) >= time.Minute
					if shouldWarn {
						lastCapWarn = now
					}
					mu.Unlock()
					if shouldWarn {
						slog.Warn(cfg.label+" rate limiter tracked-IP cap reached, rejecting new IP",
							"ip", privacy.RedactIP(clientIP, anonymousMode),
							"tracked", maxTrackedLoginAttempts,
						)
					}
					http.Error(w, cfg.limitedBody, http.StatusTooManyRequests)
					return
				}
				attempt = &loginAttempt{}
				attempts[clientIP] = attempt
			}

			// Reserve this attempt now, under the same lock as the check
			// above, before calling the (possibly slow) handler.
			attempt.count++
			attempt.lastAttempt = now
			mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitTOTPVerify rate limits TOTP verification attempts per user/IP.
// Prevents brute-force attacks on 6-digit TOTP codes.
func RateLimitTOTPVerify(anonymousMode bool) func(http.Handler) http.Handler {
	return newLoginRateLimiter(anonymousMode, loginRateLimitConfig{
		label:         "TOTP verification",
		limitedBody:   "Too many verification attempts. Please try again later.",
		maxAttempts:   5,
		windowMinutes: 15,
	})
}

// RateLimitAdminLogin rate limits admin login attempts.
func RateLimitAdminLogin(anonymousMode bool) func(http.Handler) http.Handler {
	return newLoginRateLimiter(anonymousMode, loginRateLimitConfig{
		label:         "admin login",
		limitedBody:   "Too many login attempts. Please try again later.",
		maxAttempts:   5,
		windowMinutes: 15,
	})
}

// RateLimitUserLogin rate limits user login attempts.
//
// The caller must construct this once and reuse the returned middleware
// across all requests, including both the MFA and non-MFA login branches,
// so an attacker can't dodge the lockout by switching branches.
func RateLimitUserLogin(anonymousMode bool) func(http.Handler) http.Handler {
	return newLoginRateLimiter(anonymousMode, loginRateLimitConfig{
		label:         "user login",
		limitedBody:   "Too many login attempts. Please try again later.",
		maxAttempts:   5,
		windowMinutes: 15,
	})
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
