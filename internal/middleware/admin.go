package middleware

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strconv"
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

// maxTrackedLoginAttempts caps how many distinct keys (client IPs, or user
// IDs - see attemptTracker) a single attemptTracker will track at once.
// This bounds the attempts map's memory under an attacker spraying
// requests from many source addresses. It's a var, not a const, so tests
// can shrink it to exercise the cap without allocating 100k entries.
var maxTrackedLoginAttempts = 100_000

// maxAttemptCount is a cheap hardening cap on loginAttempt.count, applied
// after every increment in attemptTracker.reserve. In normal operation
// count can never exceed maxAttempts (reserve stops incrementing once a
// key is over limit - see reserve's doc comment), so this should never
// actually bind; it exists purely as defense in depth against a future
// change to that invariant letting count grow without bound.
const maxAttemptCountMultiplier = 2

// loginAttempt tracks one key's (client IP or user ID) recent attempts
// against a rate limiter, plus the generation (epoch) its current window
// belongs to - see attemptTracker.reserve and .refund.
type loginAttempt struct {
	count       int
	lastAttempt time.Time
	epoch       uint64
}

// attemptTracker is a lock-protected map of loginAttempt entries keyed by
// an arbitrary string. The various rate limiters below each own one or
// more instances, one per tracked dimension (e.g. one per-IP).
type attemptTracker struct {
	mu          sync.Mutex
	attempts    map[string]*loginAttempt
	lastSweep   time.Time
	lastCapWarn time.Time
	window      time.Duration
	// nextEpoch hands out window generations. It only ever increases, so an
	// entry that is swept and later recreated never reuses an epoch that a
	// refund from its previous life could still be carrying.
	nextEpoch uint64
}

func newAttemptTracker(window time.Duration) *attemptTracker {
	return &attemptTracker{
		attempts: make(map[string]*loginAttempt),
		window:   window,
	}
}

// reserveResult reports the outcome of attemptTracker.reserve.
type reserveResult int

const (
	// reserveAllowed means the attempt was recorded; the caller may proceed.
	reserveAllowed reserveResult = iota
	// reserveOverLimit means key is already at or over maxAttempts.
	reserveOverLimit
	// reserveCapReached means key is new and the tracker's key cap
	// (maxTrackedLoginAttempts) has already been reached.
	reserveCapReached
)

// reserve records one attempt against key, before the caller's handler
// runs, and returns the outcome plus key's current epoch (a generation
// counter, bumped whenever the entry's window resets - see refund).
//
// A key already at or over maxAttempts is rejected WITHOUT incrementing
// count or touching lastAttempt (reserveOverLimit) - matching the original
// v1.7.1 design. This matters: lastAttempt is what the window-expiry check
// below measures from, so a lockout must expire exactly `window` after the
// last COUNTED attempt. Incrementing (or touching lastAttempt) on a
// rejected, over-limit request - which an earlier version of this design
// did - let an attacker who keeps sending requests faster than the window
// keep sliding the window's start forward indefinitely, extending their
// own victim's lockout (and, transitively, the victim's own IP, once their
// legitimate login attempts also start getting rejected) far past the
// intended 15 minutes.
//
// Only failures should ever be reserve()'d without a matching refund (see
// attemptTracker.refund): a success refunds its own one reservation, so an
// attacker who already controls one account can't interleave failed
// guesses at a victim with logins to their own account to wipe the
// victim-guess count for free (a full reset-to-zero-on-success design was
// tried and rejected in review for exactly this reason).
//
// The reservation happens under the same lock as the limit check, before
// next.ServeHTTP is called, so a burst of parallel requests from one key
// can't all pass the check before any of them finished (e.g. a slow
// password hash) and bypass the lockout (see hotfix v1.7.1).
//
// The expired-entry sweep runs at most once a minute rather than on every
// request, so per-request cost doesn't grow with the number of tracked
// keys. The number of distinct tracked keys is capped at
// maxTrackedLoginAttempts; once reached, a new key is rejected
// (reserveCapReached) rather than growing the map without bound.
func (t *attemptTracker) reserve(key string, maxAttempts int) (reserveResult, uint64) {
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	// Sweep expired entries at most once a minute.
	if now.Sub(t.lastSweep) >= time.Minute {
		for k, attempt := range t.attempts {
			if now.Sub(attempt.lastAttempt) > t.window {
				delete(t.attempts, k)
			}
		}
		t.lastSweep = now
	}

	attempt, exists := t.attempts[key]

	// The sweep above only runs once a minute, so an entry can outlive its
	// window by up to that long; reset it here so an expired window never
	// counts toward the limit. Bumping epoch invalidates any refund still
	// in flight from the window that just ended - see refund.
	if exists && now.Sub(attempt.lastAttempt) >= t.window {
		attempt.count = 0
		t.nextEpoch++
		attempt.epoch = t.nextEpoch
	}

	if exists && attempt.count >= maxAttempts {
		// Over limit: do not record this attempt at all (see doc comment).
		return reserveOverLimit, attempt.epoch
	}

	if !exists {
		if len(t.attempts) >= maxTrackedLoginAttempts {
			return reserveCapReached, 0
		}
		t.nextEpoch++
		attempt = &loginAttempt{epoch: t.nextEpoch}
		t.attempts[key] = attempt
	}

	attempt.count++
	if maxCount := maxAttempts * maxAttemptCountMultiplier; attempt.count > maxCount {
		attempt.count = maxCount
	}
	attempt.lastAttempt = now
	return reserveAllowed, attempt.epoch
}

// refund gives back exactly one previously reserved attempt for key
// (count--, never below 0), but only if epoch still matches the entry's
// current generation - i.e. the window hasn't reset since the matching
// reserve() call. Called after a response proves success, so a caller who
// eventually authenticates correctly isn't penalized for that one attempt.
//
// The epoch check guards against a refund arriving late (e.g. a very slow
// handler) after the key's window has already reset: without it, that
// stale refund would decrement the NEW window's count, silently forgiving
// one of the new window's real failures - a success from one window
// reaching backward (well, forward) to erase a failure that has nothing to
// do with it.
func (t *attemptTracker) refund(key string, epoch uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	attempt, ok := t.attempts[key]
	if !ok || attempt.epoch != epoch {
		return
	}
	if attempt.count > 0 {
		attempt.count--
	}
}

// shouldWarnCap reports whether a cap-reached warning should be logged now,
// rate-limited to once a minute (mirroring the sweep interval) so a
// sustained attack against the key cap doesn't spam the log.
func (t *attemptTracker) shouldWarnCap(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.lastCapWarn) < time.Minute {
		return false
	}
	t.lastCapWarn = now
	return true
}

// DefaultLoginSuccess is the default success predicate: any response that
// isn't a client or server error counts as success. Every login handler in
// this codebase follows the same convention - success falls through to the
// default 200 OK, failure calls WriteHeader with an explicit 4xx/5xx - so
// this one predicate is correct for all of them except the SSO callback
// (see ssoLoginSuccess). Exported so main.go can pass it to
// MFALoginLimiter.Wrap.
func DefaultLoginSuccess(status int, _ http.Header) bool {
	return status < http.StatusBadRequest
}

// MFAVerifyLoginSuccess is the success predicate for /api/auth/mfa/verify
// in the MFALoginLimiter group: like DefaultLoginSuccess, but a 429 from the
// handler is refunded too. The handler's own 429s (the per-user MFA failure
// limit, an exhausted challenge) don't represent a guessed code - the
// guesses behind them were already counted - and counting them here would
// let a legitimate owner retrying during a per-user lockout exhaust their
// own IP's budget for the whole group, locking them out of WebAuthn login
// as well. The group's own 429 never reaches this predicate: it's written
// before the handler runs.
func MFAVerifyLoginSuccess(status int, header http.Header) bool {
	return status == http.StatusTooManyRequests || DefaultLoginSuccess(status, header)
}

// AlwaysRefund always reports success, regardless of the response. Used for
// a route whose response proves nothing about the caller either way (e.g.
// webauthn/begin, which only starts a challenge) - see MFALoginLimiter.Wrap.
// Such a route still participates in the shared reserve/cap check (so it's
// blocked like everything else once the group is over its limit), but
// never itself adds to, or subtracts from, the group's failure count.
func AlwaysRefund(int, http.Header) bool {
	return true
}

// ssoLoginSuccess is the success predicate for RateLimitSSOCallback.
//
// SSOCallbackHandler (internal/handlers/sso_auth.go) responds with
// http.StatusFound for every outcome, success and failure alike: a failure
// redirects to "/login?error=<code>", a success redirects to the validated
// post-login return URL (or "/dashboard" by default). Status code alone
// can't tell them apart, so this also inspects the Location header.
func ssoLoginSuccess(status int, header http.Header) bool {
	if status >= http.StatusBadRequest {
		return false
	}
	if status >= 300 && status < 400 {
		return !strings.HasPrefix(header.Get("Location"), "/login?error=")
	}
	return true
}

// loginRateLimitConfig parameterizes newLoginRateLimiter for the two
// password-login call sites (admin login, user login), which were
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

// newLoginRateLimiter builds rate-limiting middleware for a password-login
// route: it tracks failed attempts per client IP.
//
// This is per-IP only - there is currently no per-username limit. A
// per-username (per-account) limit needs a way to distinguish a distributed
// attacker from the account's legitimate owner (e.g. a signed "known
// device" bypass cookie) to avoid becoming a denial-of-service vector in
// its own right: an earlier version of this limiter let an attacker who
// kept requesting faster than the per-username throttle's delay keep
// pushing that schedule more than the throttle's give-up threshold ahead of
// real time, so every login for that username - including the account
// owner's own correct password - got rejected, and since those rejections
// weren't refunded at the IP layer either, the victim's own IP eventually
// locked out too. That's a separate design; this change is per-IP only.
//
// The returned middleware is meant to be constructed once by the caller and
// reused across every request - never inside a per-request handler closure,
// which would allocate a fresh, empty attempts map each time and the
// lockout could never trigger (this was a real bug: see hotfix v1.7.1).
//
// Only failures count: a successful response (DefaultLoginSuccess) refunds
// this one request's own reservation rather than resetting the counter to
// zero (see attemptTracker.reserve's doc comment for why a full reset is
// unsafe). Any non-success response counts as a failure, including a 405
// (wrong method) or 400 (malformed body); this is the conservative choice
// named in the design brief - anything that isn't a proven-good credential
// exchange should count against the limiter, since silently ignoring it
// would open a way to probe the endpoint for free.
func newLoginRateLimiter(anonymousMode bool, cfg loginRateLimitConfig) func(http.Handler) http.Handler {
	ipTracker := newAttemptTracker(time.Duration(cfg.windowMinutes) * time.Minute)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawIP := getClientIP(r)
			// T43: group IPv6 clients by the configured prefix for the
			// lockout bucket key; logging below still uses the full rawIP.
			ipKey := utils.RateLimitKey(rawIP)

			result, epoch := ipTracker.reserve(ipKey, cfg.maxAttempts)
			switch result {
			case reserveOverLimit:
				slog.Warn(cfg.label+" rate limit exceeded",
					"ip", privacy.RedactIP(rawIP, anonymousMode),
				)
				http.Error(w, cfg.limitedBody, http.StatusTooManyRequests)
				return
			case reserveCapReached:
				if ipTracker.shouldWarnCap(time.Now()) {
					slog.Warn(cfg.label+" rate limiter tracked-IP cap reached, rejecting new IP",
						"ip", privacy.RedactIP(rawIP, anonymousMode),
						"tracked", maxTrackedLoginAttempts,
					)
				}
				http.Error(w, cfg.limitedBody, http.StatusTooManyRequests)
				return
			}

			captured := &statusCapturingWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(captured, r)

			if DefaultLoginSuccess(captured.statusCode, captured.Header()) {
				ipTracker.refund(ipKey, epoch)
			}
		})
	}
}

// RateLimitAdminLogin rate limits admin login attempts, per client IP. Only
// failed attempts count (a successful login refunds this request's own
// reservation) - see newLoginRateLimiter's doc comment.
func RateLimitAdminLogin(anonymousMode bool) func(http.Handler) http.Handler {
	return newLoginRateLimiter(anonymousMode, loginRateLimitConfig{
		label:         "admin login",
		limitedBody:   "Too many login attempts. Please try again later.",
		maxAttempts:   5,
		windowMinutes: 15,
	})
}

// RateLimitUserLogin rate limits user login attempts, per client IP.
//
// The caller must construct this once and reuse the returned middleware
// across all requests, including both the MFA and non-MFA login branches,
// so an attacker can't dodge the lockout by switching branches.
//
// Only failed attempts count; a successful login refunds this request's own
// reservation - see newLoginRateLimiter's doc comment.
func RateLimitUserLogin(anonymousMode bool) func(http.Handler) http.Handler {
	return newLoginRateLimiter(anonymousMode, loginRateLimitConfig{
		label:         "user login",
		limitedBody:   "Too many login attempts. Please try again later.",
		maxAttempts:   5,
		windowMinutes: 15,
	})
}

// MFALoginLimiter rate-limits the unauthenticated MFA-login-verification
// routes (/api/auth/mfa/verify, .../webauthn/begin, .../webauthn/finish)
// against one shared per-IP budget - matching the pre-refactor design where
// a single totpRateLimit instance covered all three, so a burst spread
// across them from one IP still draws from one pool (rather than each
// route getting its own separate 5-attempt allowance, which would let an
// attacker multiply their effective budget by switching routes). Each
// route supplies its own success predicate via Wrap, since a response
// doesn't mean the same thing on all three - see Wrap and AlwaysRefund.
type MFALoginLimiter struct {
	tracker       *attemptTracker
	maxAttempts   int
	anonymousMode bool
}

// NewMFALoginLimiter builds an MFALoginLimiter. Like the other limiters in
// this package, construct it once and reuse it - see newLoginRateLimiter's
// doc comment for why.
func NewMFALoginLimiter(anonymousMode bool) *MFALoginLimiter {
	return &MFALoginLimiter{
		tracker:       newAttemptTracker(15 * time.Minute),
		maxAttempts:   5,
		anonymousMode: anonymousMode,
	}
}

// Wrap builds the middleware for one route in the group. label names it in
// log messages; isSuccess decides whether a response refunds this
// request's reservation. Pass DefaultLoginSuccess for a route whose
// response genuinely proves the caller supplied correct credentials
// (/mfa/verify, webauthn/finish), or AlwaysRefund for one that doesn't
// (webauthn/begin - see AlwaysRefund).
func (l *MFALoginLimiter) Wrap(label string, isSuccess func(int, http.Header) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawIP := getClientIP(r)
			key := utils.RateLimitKey(rawIP)

			result, epoch := l.tracker.reserve(key, l.maxAttempts)
			switch result {
			case reserveOverLimit:
				slog.Warn(label+" rate limit exceeded", "ip", privacy.RedactIP(rawIP, l.anonymousMode))
				http.Error(w, "Too many verification attempts. Please try again later.", http.StatusTooManyRequests)
				return
			case reserveCapReached:
				if l.tracker.shouldWarnCap(time.Now()) {
					slog.Warn(label+" rate limiter tracked-IP cap reached, rejecting new IP",
						"ip", privacy.RedactIP(rawIP, l.anonymousMode),
						"tracked", maxTrackedLoginAttempts,
					)
				}
				http.Error(w, "Too many verification attempts. Please try again later.", http.StatusTooManyRequests)
				return
			}

			captured := &statusCapturingWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(captured, r)
			if isSuccess(captured.statusCode, captured.Header()) {
				l.tracker.refund(key, epoch)
			}
		})
	}
}

// ipLoginKey is a simpleLimiter keyFn that tracks by client IP alone.
func ipLoginKey(_ *http.Request, rawIP string) string {
	return utils.RateLimitKey(rawIP)
}

// authenticatedUserKey is a simpleLimiter keyFn for the authenticated-route
// limiters (RateLimitMFAEnrollment, RateLimitChangePassword): it tracks by
// authenticated user ID when one is available in context - these routes
// always run behind UserAuth, so this is the normal case - falling back to
// client IP only if somehow no user is in context, so the limiter still
// fails closed rather than not tracking the request at all.
func authenticatedUserKey(r *http.Request, rawIP string) string {
	if user := GetUserFromContext(r); user != nil {
		return "user:" + strconv.FormatInt(user.ID, 10)
	}
	return "ip:" + utils.RateLimitKey(rawIP)
}

// simpleLimiter is the common reserve/refund pattern shared by the
// remaining constructors below (SSO initiation, SSO callback, MFA
// enrollment), which don't need per-username tracking. keyFn derives the
// tracked key from the request; isSuccess decides whether a response
// refunds the reservation - nil means never refund (every request counts,
// regardless of outcome; see RateLimitSSOInitiation).
func simpleLimiter(anonymousMode bool, label, limitedBody string, maxAttempts int, window time.Duration, keyFn func(r *http.Request, rawIP string) string, isSuccess func(int, http.Header) bool) func(http.Handler) http.Handler {
	tracker := newAttemptTracker(window)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawIP := getClientIP(r)
			key := keyFn(r, rawIP)

			result, epoch := tracker.reserve(key, maxAttempts)
			switch result {
			case reserveOverLimit:
				slog.Warn(label+" rate limit exceeded", "ip", privacy.RedactIP(rawIP, anonymousMode))
				http.Error(w, limitedBody, http.StatusTooManyRequests)
				return
			case reserveCapReached:
				if tracker.shouldWarnCap(time.Now()) {
					slog.Warn(label+" rate limiter tracked-key cap reached, rejecting new key",
						"ip", privacy.RedactIP(rawIP, anonymousMode),
						"tracked", maxTrackedLoginAttempts,
					)
				}
				http.Error(w, limitedBody, http.StatusTooManyRequests)
				return
			}

			if isSuccess == nil {
				next.ServeHTTP(w, r)
				return
			}

			captured := &statusCapturingWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(captured, r)
			if isSuccess(captured.statusCode, captured.Header()) {
				tracker.refund(key, epoch)
			}
		})
	}
}

// RateLimitSSOInitiation rate-limits the SSO login-initiation route
// (.../sso/{provider}/login). Every request counts, regardless of outcome -
// there's no success/failure distinction here: even a "successful"
// initiation (redirecting to the IdP) doesn't prove anything about the
// caller, and every initiation call inserts an SSO-state row that must
// itself be bounded regardless of what happens next. This is a flat
// per-IP cap, higher than the credential-login limiters (20/15min) since
// legitimate repeated visits (retrying a broken SSO flow, multiple tabs)
// are common and shouldn't need special-casing.
func RateLimitSSOInitiation(anonymousMode bool) func(http.Handler) http.Handler {
	return simpleLimiter(anonymousMode, "SSO login initiation", "Too many login attempts. Please try again later.", 20, 15*time.Minute, ipLoginKey, nil)
}

// RateLimitSSOCallback rate-limits the SSO callback route
// (.../sso/{provider}/callback), kept separate from RateLimitSSOInitiation
// so a burst of initiations can't also exhaust the callback's budget (or
// vice versa). Refund-only on success - see ssoLoginSuccess for why
// success/failure here is judged by the redirect Location, not the
// (always-3xx) status code.
func RateLimitSSOCallback(anonymousMode bool) func(http.Handler) http.Handler {
	return simpleLimiter(anonymousMode, "SSO callback", "Too many login attempts. Please try again later.", 5, 15*time.Minute, ipLoginKey, ssoLoginSuccess)
}

// RateLimitMFAEnrollment rate-limits the *authenticated* MFA-enrollment
// routes (TOTP verify-and-enable, TOTP disable) - separate from
// MFALoginLimiter's unauthenticated login-verification group, and keyed by
// authenticated user ID rather than IP (see authenticatedUserKey), since these
// routes always run behind UserAuth. Refund-only on success.
func RateLimitMFAEnrollment(anonymousMode bool) func(http.Handler) http.Handler {
	return simpleLimiter(anonymousMode, "MFA enrollment", "Too many attempts. Please try again later.", 5, 15*time.Minute, authenticatedUserKey, DefaultLoginSuccess)
}

// onlyUnauthorizedFails is the success predicate for the password-change
// limiters: only a 401 (wrong current password) counts as a failure. These
// routes already sit behind an authenticated session, and their handlers
// reject malformed input (e.g. a too-short new password, 400) before ever
// checking the current password - counting those would let a user's own
// typos lock them out of changing their password without the
// current-password check ever being probed.
func onlyUnauthorizedFails(status int, _ http.Header) bool {
	return status != http.StatusUnauthorized
}

// RateLimitChangePassword rate-limits the user password-change route
// (/api/auth/change-password), keyed by authenticated user ID (see
// authenticatedUserKey), so a stolen session can't be used to guess the
// account's current password - which it needs for a password change, and
// which may be reused elsewhere. 5 wrong current passwords per 15 minutes;
// only a wrong current password counts (see onlyUnauthorizedFails).
func RateLimitChangePassword(anonymousMode bool) func(http.Handler) http.Handler {
	return simpleLimiter(anonymousMode, "password change", "Too many attempts. Please try again later.", 5, 15*time.Minute, authenticatedUserKey, onlyUnauthorizedFails)
}

// legacyAdminPasswordKey is the simpleLimiter keyFn for
// RateLimitAdminChangePassword: one shared key for every caller. The route
// checks the single legacy admin password, and any admin session -
// including a users-table admin's, which doesn't know that password - can
// reach it, so keying by IP would let a stolen session guess it from as
// many addresses as the attacker has. A shared key caps guesses globally;
// only admin sessions can spend that budget.
func legacyAdminPasswordKey(*http.Request, string) string {
	return "legacy-admin-password"
}

// RateLimitAdminChangePassword rate-limits the admin password-change route
// (/admin/api/settings/password) with one global budget (see
// legacyAdminPasswordKey). Same budget and failure rule as
// RateLimitChangePassword.
func RateLimitAdminChangePassword(anonymousMode bool) func(http.Handler) http.Handler {
	return simpleLimiter(anonymousMode, "admin password change", "Too many attempts. Please try again later.", 5, 15*time.Minute, legacyAdminPasswordKey, onlyUnauthorizedFails)
}

// KeyedAttemptLimiter exposes the same reserve/refund failure counting the
// login limiters above use (see attemptTracker) to code outside this
// package that can only learn the key to limit by from inside a handler -
// e.g. the user ID behind an MFA login challenge (T48), which no HTTP
// middleware wrapping that handler can see. Construct once and share it
// across requests.
type KeyedAttemptLimiter struct {
	tracker     *attemptTracker
	maxAttempts int
}

// NewKeyedAttemptLimiter builds a KeyedAttemptLimiter allowing maxAttempts
// unrefunded attempts per key within window.
func NewKeyedAttemptLimiter(maxAttempts int, window time.Duration) *KeyedAttemptLimiter {
	return &KeyedAttemptLimiter{
		tracker:     newAttemptTracker(window),
		maxAttempts: maxAttempts,
	}
}

// Reserve records one attempt against key before the caller checks the
// credential, so parallel requests can't all pass before any of them is
// counted. ok is false when key is already at its limit, or when the
// tracker is full and key is new (fail closed). Pass token to Refund if
// the attempt turns out not to be a failure.
func (l *KeyedAttemptLimiter) Reserve(key string) (ok bool, token uint64) {
	result, epoch := l.tracker.reserve(key, l.maxAttempts)
	return result == reserveAllowed, epoch
}

// Refund gives back one attempt previously reserved for key, unless key's
// window has reset since (see attemptTracker.refund).
func (l *KeyedAttemptLimiter) Refund(key string, token uint64) {
	l.tracker.refund(key, token)
}

// Reset forgets every tracked key. For tests only, which share one
// package-level limiter across cases; never call it from a request path.
func (l *KeyedAttemptLimiter) Reset() {
	l.tracker.mu.Lock()
	defer l.tracker.mu.Unlock()
	l.tracker.attempts = make(map[string]*loginAttempt)
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
