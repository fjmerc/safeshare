package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
)

// DBRateLimiter manages rate limiting using database-backed storage.
// This enables rate limiting to work across multiple application instances.
type DBRateLimiter struct {
	config    ConfigProvider
	repo      repository.RateLimitRepository
	cleanup   *time.Ticker
	stopChan  chan struct{}
}

// NewDBRateLimiter creates a new database-backed rate limiter.
func NewDBRateLimiter(config ConfigProvider, repo repository.RateLimitRepository) *DBRateLimiter {
	rl := &DBRateLimiter{
		config:   config,
		repo:     repo,
		cleanup:  time.NewTicker(1 * time.Hour),
		stopChan: make(chan struct{}),
	}

	// Start cleanup goroutine to remove expired entries
	go rl.cleanupWorker()

	return rl
}

// cleanupWorker periodically removes expired rate limit entries from the database.
func (rl *DBRateLimiter) cleanupWorker() {
	for {
		select {
		case <-rl.cleanup.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			count, err := rl.repo.CleanupExpired(ctx)
			if err != nil {
				slog.Error("failed to cleanup expired rate limits", "error", err)
			} else if count > 0 {
				slog.Debug("cleaned up expired rate limit entries", "count", count)
			}
			cancel()
		case <-rl.stopChan:
			rl.cleanup.Stop()
			return
		}
	}
}

// Stop stops the cleanup goroutine.
func (rl *DBRateLimiter) Stop() {
	close(rl.stopChan)
}

// checkLimit checks if the request is within rate limits using the database.
func (rl *DBRateLimiter) checkLimit(ctx context.Context, ip string, limitType string, limit int) bool {
	// Standard rate limit window is 1 hour
	windowDuration := time.Hour

	allowed, count, err := rl.repo.IncrementAndCheck(ctx, ip, limitType, limit, windowDuration)
	if err != nil {
		// On database error, log and allow the request (fail open for availability)
		// This is a deliberate choice to prefer availability over strict enforcement
		slog.Error("rate limit check failed, allowing request",
			"error", err,
			"ip", ip,
			"limit_type", limitType,
		)
		return true
	}

	if !allowed {
		slog.Warn("rate limit exceeded",
			"ip", ip,
			"limit_type", limitType,
			"limit", limit,
			"count", count,
		)
	}

	return allowed
}

// DBRateLimitMiddleware creates a middleware that enforces rate limits using database storage.
func DBRateLimitMiddleware(rl *DBRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ip := getClientIPForRateLimit(r, rl.config)

			// Determine which limit to apply based on path
			var limit int
			var limitType string

			if r.URL.Path == "/api/upload" || r.URL.Path == "/api/upload/init" {
				limit = rl.config.GetRateLimitUpload()
				limitType = "upload"
			} else if strings.HasPrefix(r.URL.Path, "/api/upload/chunk/") {
				// Rate limit chunk uploads (more lenient: 10x upload limit)
				limit = rl.config.GetRateLimitUpload() * 10
				limitType = "chunk"
			} else if strings.HasPrefix(r.URL.Path, "/api/claim/") && !strings.HasSuffix(r.URL.Path, "/info") {
				limit = rl.config.GetRateLimitDownload()
				limitType = "download"
			} else if r.URL.Path == "/api/user/files/regenerate-claim-code" {
				limit = 10 // Hardcoded: 10 regenerations per hour per IP
				limitType = "regeneration"
			} else {
				// No rate limit for other endpoints
				next.ServeHTTP(w, r)
				return
			}

			// Check rate limit
			if !rl.checkLimit(ctx, ip, limitType, limit) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "3600") // 1 hour in seconds
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"Rate limit exceeded. Please try again later.","code":"RATE_LIMIT_EXCEEDED"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIPForRateLimit extracts the client IP address from the request with trusted proxy validation.
func getClientIPForRateLimit(r *http.Request, config ConfigProvider) string {
	remoteIP := utils.ExtractIP(r.RemoteAddr)

	trustProxyHeaders := config.GetTrustProxyHeaders()
	trustedProxyIPs := config.GetTrustedProxyIPs()

	shouldTrust := false

	switch trustProxyHeaders {
	case "true":
		shouldTrust = true
		slog.Warn("rate limiter trusting all proxy headers without validation",
			"trust_mode", "true",
			"remote_ip", remoteIP,
			"x_forwarded_for", r.Header.Get("X-Forwarded-For"),
			"security_risk", "IP spoofing possible - consider using 'auto' mode",
		)
	case "false":
		shouldTrust = false
	case "auto":
		shouldTrust = utils.IsTrustedProxyIP(remoteIP, trustedProxyIPs)
	default:
		shouldTrust = utils.IsTrustedProxyIP(remoteIP, trustedProxyIPs)
	}

	if !shouldTrust {
		return remoteIP
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if trustProxyHeaders == "true" {
				slog.Debug("accepting X-Forwarded-For header without validation",
					"client_ip", clientIP,
					"remote_ip", remoteIP,
					"full_xff_chain", xff,
				)
			}
			return clientIP
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	return remoteIP
}

// securityCriticalLimitTypes defines limit types that should fail-closed on errors.
var securityCriticalLimitTypes = map[string]bool{
	"admin_login": true,
	"user_login":  true,
}

// CreateLoginRateLimiter returns the appropriate login rate limiter middleware.
// If repo is non-nil and useDBRateLimiting is true, uses database-backed rate limiting.
// Otherwise, falls back to in-memory rate limiting.
//
// Parameters:
// - repo: RateLimitRepository for database-backed limiting (can be nil)
// - useDBRateLimiting: whether to use database-backed rate limiting
// - limitType: "admin_login" or "user_login"
// - maxAttempts: maximum login attempts allowed
// - windowMinutes: rate limit window duration
// - config: configuration provider for proxy settings
func CreateLoginRateLimiter(repo repository.RateLimitRepository, useDBRateLimiting bool, limitType string, maxAttempts int, windowMinutes int, config ConfigProvider) func(http.Handler) http.Handler {
	if repo != nil && useDBRateLimiting {
		return DBRateLimitLoginMiddleware(repo, limitType, maxAttempts, windowMinutes, config)
	}

	// Fall back to in-memory rate limiting
	if limitType == "admin_login" {
		return RateLimitAdminLogin()
	}
	return RateLimitUserLogin()
}

// DBRateLimitLoginMiddleware creates a rate limit middleware for login endpoints using database storage.
// It tracks login attempts by IP address with configurable limits.
// SECURITY: Uses atomic increment-before-request to prevent TOCTOU race conditions.
// SECURITY: Fails closed for security-critical operations to prevent brute force during DB issues.
func DBRateLimitLoginMiddleware(repo repository.RateLimitRepository, limitType string, maxAttempts int, windowMinutes int, config ConfigProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			clientIP := getClientIPForRateLimit(r, config)
			windowDuration := time.Duration(windowMinutes) * time.Minute

			// Atomically increment and check BEFORE processing request
			// This prevents TOCTOU race conditions where multiple concurrent requests
			// could all pass the check before any counter is incremented.
			allowed, count, err := repo.IncrementAndCheck(ctx, clientIP, limitType, maxAttempts, windowDuration)
			if err != nil {
				slog.Error("failed to check login rate limit", "error", err, "ip", clientIP)

				// Security-critical limits should fail closed to prevent brute force
				// attacks during database issues
				if securityCriticalLimitTypes[limitType] {
					slog.Warn("failing closed for security-critical limit type",
						"limit_type", limitType,
						"ip", clientIP,
					)
					http.Error(w, "Service temporarily unavailable. Please try again later.", http.StatusServiceUnavailable)
					return
				}

				// Non-security operations fail open for availability
				next.ServeHTTP(w, r)
				return
			}

			if !allowed {
				slog.Warn("login rate limit exceeded",
					"ip", clientIP,
					"limit_type", limitType,
					"attempts", count,
				)
				http.Error(w, "Too many login attempts. Please try again later.", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
