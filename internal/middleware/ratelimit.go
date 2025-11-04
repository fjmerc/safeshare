package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	UploadLimit   int // requests per hour
	DownloadLimit int // requests per hour
}

// requestRecord tracks requests for an IP
type requestRecord struct {
	timestamps []time.Time
	mu         sync.Mutex
}

// RateLimiter manages rate limiting per IP address
type RateLimiter struct {
	config  RateLimitConfig
	records sync.Map // map[string]*requestRecord
	cleanup *time.Ticker
}

// NewRateLimiter creates a new rate limiter with the given configuration
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		config:  config,
		cleanup: time.NewTicker(1 * time.Hour),
	}

	// Start cleanup goroutine to remove old entries
	go rl.cleanupOldEntries()

	return rl
}

// cleanupOldEntries removes entries older than 1 hour
func (rl *RateLimiter) cleanupOldEntries() {
	for range rl.cleanup.C {
		now := time.Now()
		rl.records.Range(func(key, value interface{}) bool {
			record := value.(*requestRecord)
			record.mu.Lock()
			defer record.mu.Unlock()

			// Remove timestamps older than 1 hour
			cutoff := now.Add(-1 * time.Hour)
			filtered := make([]time.Time, 0)
			for _, ts := range record.timestamps {
				if ts.After(cutoff) {
					filtered = append(filtered, ts)
				}
			}
			record.timestamps = filtered

			// Remove empty records
			if len(record.timestamps) == 0 {
				rl.records.Delete(key)
			}

			return true
		})
	}
}

// Stop stops the cleanup goroutine
func (rl *RateLimiter) Stop() {
	rl.cleanup.Stop()
}

// checkLimit checks if the request is within rate limits
func (rl *RateLimiter) checkLimit(ip string, limit int) bool {
	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)

	// Get or create record for this IP
	value, _ := rl.records.LoadOrStore(ip, &requestRecord{
		timestamps: make([]time.Time, 0),
	})
	record := value.(*requestRecord)

	record.mu.Lock()
	defer record.mu.Unlock()

	// Remove timestamps older than 1 hour
	filtered := make([]time.Time, 0)
	for _, ts := range record.timestamps {
		if ts.After(oneHourAgo) {
			filtered = append(filtered, ts)
		}
	}
	record.timestamps = filtered

	// Check if limit exceeded
	if len(record.timestamps) >= limit {
		return false
	}

	// Add current timestamp
	record.timestamps = append(record.timestamps, now)
	return true
}

// RateLimitMiddleware creates a middleware that enforces rate limits
func RateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getClientIP(r)

			// Determine which limit to apply based on path
			var limit int
			var limitType string

			if r.URL.Path == "/api/upload" {
				limit = rl.config.UploadLimit
				limitType = "upload"
			} else if strings.HasPrefix(r.URL.Path, "/api/claim/") && !strings.HasSuffix(r.URL.Path, "/info") {
				limit = rl.config.DownloadLimit
				limitType = "download"
			} else {
				// No rate limit for other endpoints (health, info, static files)
				next.ServeHTTP(w, r)
				return
			}

			// Check rate limit
			if !rl.checkLimit(ip, limit) {
				slog.Warn("rate limit exceeded",
					"ip", ip,
					"limit_type", limitType,
					"limit", limit,
					"path", r.URL.Path,
				)

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

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr (strip port)
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}

	return r.RemoteAddr
}
