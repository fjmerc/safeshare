package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fjmerc/safeshare/internal/utils"
)

// ConfigProvider interface allows RateLimiter to read current rate limit values
type ConfigProvider interface {
	GetRateLimitUpload() int
	GetRateLimitDownload() int
	GetTrustProxyHeaders() string
	GetTrustedProxyIPs() string
}

// requestRecord tracks requests for an IP
type requestRecord struct {
	timestamps []time.Time
	mu         sync.Mutex
}

// RateLimiter manages rate limiting per IP address
type RateLimiter struct {
	config  ConfigProvider
	records sync.Map // map[string]*requestRecord
	cleanup *time.Ticker
}

// NewRateLimiter creates a new rate limiter with the given configuration provider
func NewRateLimiter(config ConfigProvider) *RateLimiter {
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

				// Remove timestamps older than 1 hour (optimized to reuse backing array)
		cutoff := now.Add(-1 * time.Hour)
		oldCount := len(record.timestamps)
		newTimestamps := record.timestamps[:0] // Reuse backing array
		for _, ts := range record.timestamps {
		 if ts.After(cutoff) {
		 newTimestamps = append(newTimestamps, ts)
		}
		}

				// Only allocate new slice if we removed many items (>50%) and can reclaim significant memory (>100 items)
		if len(newTimestamps) < oldCount/2 && oldCount > 100 {
		 record.timestamps = append([]time.Time(nil), newTimestamps...)
		} else {
		 record.timestamps = newTimestamps
		}

				// Remove empty records
		if len(record.timestamps) == 0 {
		 rl.records.Delete(key)
		}

				// Explicitly unlock before returning (fixes memory leak from defer in loop)
		record.mu.Unlock()
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

	// Remove timestamps older than 1 hour (optimized to reuse backing array)
	oldCount := len(record.timestamps)
	newTimestamps := record.timestamps[:0] // Reuse backing array
	for _, ts := range record.timestamps {
		if ts.After(oneHourAgo) {
			newTimestamps = append(newTimestamps, ts)
		}
	}

	// Only allocate new slice if we removed many items (>50%) and can reclaim significant memory (>100 items)
	if len(newTimestamps) < oldCount/2 && oldCount > 100 {
		record.timestamps = append([]time.Time(nil), newTimestamps...)
	} else {
		record.timestamps = newTimestamps
	}

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
			ip := rl.getClientIP(r)

			// Determine which limit to apply based on path
			// Read current limit values from config (allows runtime updates)
			var limit int
			var limitType string

			if r.URL.Path == "/api/upload" || r.URL.Path == "/api/upload/init" {
				limit = rl.config.GetRateLimitUpload()
				limitType = "upload"
			} else if strings.HasPrefix(r.URL.Path, "/api/upload/chunk/") {
				// Rate limit chunk uploads (more lenient: 10x upload limit)
				// Rationale: Single file can have hundreds of chunks
				limit = rl.config.GetRateLimitUpload() * 10
				limitType = "chunk"
			} else if strings.HasPrefix(r.URL.Path, "/api/upload/complete/") {
				limit = rl.config.GetRateLimitUpload()
				limitType = "upload"
			} else if strings.HasPrefix(r.URL.Path, "/api/claim/") && !strings.HasSuffix(r.URL.Path, "/info") {
				limit = rl.config.GetRateLimitDownload()
				limitType = "download"
			} else if r.URL.Path == "/api/user/files/regenerate-claim-code" {
				limit = 10 // Hardcoded: 10 regenerations per hour per IP
				limitType = "regeneration"
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

// getClientIP extracts the client IP address from the request with trusted proxy validation
func (rl *RateLimiter) getClientIP(r *http.Request) string {
	// Extract IP from RemoteAddr (the immediate connection source)
	remoteIP := utils.ExtractIP(r.RemoteAddr)

	// Get proxy trust settings
	trustProxyHeaders := rl.config.GetTrustProxyHeaders()
	trustedProxyIPs := rl.config.GetTrustedProxyIPs()

	// Determine if we should trust proxy headers
	shouldTrust := false

	switch trustProxyHeaders {
	case "true":
		// Always trust proxy headers (SECURITY WARNING: vulnerable to IP spoofing)
		shouldTrust = true
		slog.Warn("rate limiter trusting all proxy headers without validation",
			"trust_mode", "true",
			"remote_ip", remoteIP,
			"x_forwarded_for", r.Header.Get("X-Forwarded-For"),
			"security_risk", "IP spoofing possible - consider using 'auto' mode",
		)
	case "false":
		// Never trust proxy headers
		shouldTrust = false
	case "auto":
		// Trust only if request comes from a trusted proxy IP
		shouldTrust = utils.IsTrustedProxyIP(remoteIP, trustedProxyIPs)
	default:
		// Default to auto mode for safety
		shouldTrust = utils.IsTrustedProxyIP(remoteIP, trustedProxyIPs)
	}

	// If we shouldn't trust proxy headers, return RemoteAddr directly
	if !shouldTrust {
		return remoteIP
	}

	// Trust proxy headers - check X-Forwarded-For first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain (the original client)
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if trustProxyHeaders == "true" {
				// Log when accepting unvalidated proxy headers (security audit trail)
				slog.Debug("accepting X-Forwarded-For header without validation",
					"client_ip", clientIP,
					"remote_ip", remoteIP,
					"full_xff_chain", xff,
				)
			}
			return clientIP
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return remoteIP
}
