package middleware

import (
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fjmerc/safeshare/internal/privacy"
	"github.com/fjmerc/safeshare/internal/utils"
)

// ConfigProvider interface allows RateLimiter to read current rate limit values
type ConfigProvider interface {
	GetRateLimitUpload() int
	GetRateLimitDownload() int
	GetMaxFileSize() int64
	GetTrustProxyHeaders() string
	GetTrustedProxyIPs() string
	IsAnonymousMode() bool
}

// chunkRequestLimit is the hourly limit on chunk requests per client
// address. RATE_LIMIT_UPLOAD allows that many uploads an hour and
// MAX_FILE_SIZE says how big each may be, so the chunk allowance covers that
// many maximum-size uploads plus room for retries: a quarter more chunks,
// plus 10. It is never below the old fixed allowance of 10 chunks per
// permitted upload. A fixed multiple of the upload limit broke large uploads:
// at 10 uploads an hour that allowed 100 chunks, but a 2 GB file is 103
// chunks of 20 MB, so it ran out partway through.
func chunkRequestLimit(cfg ConfigProvider) int {
	uploads := int64(max(cfg.GetRateLimitUpload(), 0))
	perUpload := utils.MaxChunksForFileSize(cfg.GetMaxFileSize())
	perUpload += perUpload/4 + 10 // retries; also keeps it at least 10
	// The upload limit has no upper bound; saturate rather than overflow.
	if uploads > math.MaxInt32/perUpload {
		return math.MaxInt32
	}
	return int(uploads * perUpload)
}

// requestRecord tracks requests for an IP
type requestRecord struct {
	timestamps []time.Time
	// coarse holds per-minute request counts over the last hour, used
	// instead of timestamps for limits above coarseLimitThreshold (see
	// checkLimit): a fixed ~1 KB per bucket instead of a timestamp per
	// request. Allocated only for buckets that use it.
	coarse *coarseWindow
	mu     sync.Mutex
}

// coarseWindow is a ring of per-minute request counts, slot = minute % 60.
type coarseWindow struct {
	minutes [60]int64
	counts  [60]uint32
}

// inWindow reports whether a slot stamped with slotMinute counts toward the
// hour ending at nowMinute. A slot stamped after nowMinute (the wall clock
// stepped backwards) doesn't count, rather than counting until real time
// catches up.
func inWindow(nowMinute, slotMinute int64) bool {
	d := nowMinute - slotMinute
	return d >= 0 && d < 60
}

// coarseLimitThreshold is the hourly limit above which a bucket counts
// requests per minute rather than storing a timestamp per request. Keeping
// every timestamp costs ~24-48 bytes per request for an hour - ~150 KB per
// client IP at the upload-status limit - so a flood spread across many
// addresses could otherwise grow memory with request volume. Per-minute
// counts make the window approximate to within a minute, which doesn't
// matter at these limits.
const coarseLimitThreshold = 1000

// coarseActive reports whether r has any per-minute count within the hour
// ending at nowMinute. Caller holds r.mu.
func (r *requestRecord) coarseActive(nowMinute int64) bool {
	if r.coarse == nil {
		return false
	}
	for i := range r.coarse.minutes {
		if r.coarse.counts[i] > 0 && inWindow(nowMinute, r.coarse.minutes[i]) {
			return true
		}
	}
	return false
}

// RateLimiter manages rate limiting per IP address and limit type
type RateLimiter struct {
	config  ConfigProvider
	records sync.Map // map[string]*requestRecord, keyed by bucketKey
	cleanup *time.Ticker
}

// bucketKey returns the record key for an IP within a limit type. Each limit
// type needs its own bucket: sharing one slice per IP meant the chunks of a
// single large upload counted against the upload and download limits, locking
// the IP out of new uploads and downloads for an hour.
//
// ip is expected to already be grouped via utils.RateLimitKey (T43) so IPv6
// clients within the same configured prefix share one bucket.
func bucketKey(limitType, ip string) string {
	return limitType + "|" + ip
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
			if len(record.timestamps) == 0 && !record.coarseActive(now.Unix()/60) {
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

// checkLimit checks if the request is within rate limits for the given limit type
func (rl *RateLimiter) checkLimit(ip, limitType string, limit int) bool {
	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)

	// Get or create record for this IP and limit type
	value, _ := rl.records.LoadOrStore(bucketKey(limitType, ip), &requestRecord{
		timestamps: make([]time.Time, 0),
	})
	record := value.(*requestRecord)

	record.mu.Lock()
	defer record.mu.Unlock()

	// A bucket's limit can cross coarseLimitThreshold at runtime (limits
	// derived from admin-editable settings, such as chunkRequestLimit).
	// The two modes keep separate counts, so carry the count across instead
	// of starting the bucket afresh: moving to per-minute counting folds
	// the timestamps in, and a bucket with per-minute counts keeps using
	// them until they age out of the hour.
	if limit > coarseLimitThreshold || record.coarseActive(now.Unix()/60) {
		record.foldTimestampsIntoCoarse(now)
		return record.checkCoarse(now, limit)
	}

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

// foldTimestampsIntoCoarse moves r's per-request timestamps from the last
// hour into its per-minute counts and clears them. Caller holds r.mu.
func (r *requestRecord) foldTimestampsIntoCoarse(now time.Time) {
	if len(r.timestamps) == 0 {
		return
	}
	if r.coarse == nil {
		r.coarse = &coarseWindow{}
	}
	c := r.coarse
	nowMinute := now.Unix() / 60
	for _, ts := range r.timestamps {
		minute := ts.Unix() / 60
		if !inWindow(nowMinute, minute) {
			continue
		}
		slot := minute % 60
		if c.minutes[slot] != minute {
			c.minutes[slot] = minute
			c.counts[slot] = 0
		}
		c.counts[slot]++
	}
	r.timestamps = nil
}

// checkCoarse is checkLimit's per-minute-count variant (see
// coarseLimitThreshold). Caller holds r.mu.
func (r *requestRecord) checkCoarse(now time.Time, limit int) bool {
	if r.coarse == nil {
		r.coarse = &coarseWindow{}
	}
	c := r.coarse
	minute := now.Unix() / 60
	slot := minute % 60
	if c.minutes[slot] != minute {
		c.minutes[slot] = minute
		c.counts[slot] = 0
	}
	total := 0
	for i := range c.minutes {
		if inWindow(minute, c.minutes[i]) {
			total += int(c.counts[i])
		}
	}
	if total >= limit {
		return false
	}
	c.counts[slot]++
	return true
}

// minStatusRateLimitPerHour is the floor for the upload-status rate limit
// (see RateLimitMiddleware): enough for a client polling every 2 seconds
// (~1800/hour) on several uploads at once.
const minStatusRateLimitPerHour = 6000

// claimInfoLimitMultiplier sets the /api/claim/{code}/info limit relative to
// RATE_LIMIT_DOWNLOAD: room for a lookup before every download plus mistyped
// codes, while still bounding claim-code guessing per IP.
const claimInfoLimitMultiplier = 2

// RateLimitMiddleware creates a middleware that enforces rate limits
// isOwnerDownloadPath reports whether path is an owner download:
// /api/user/files/{code}/download or /api/user/bundles/{id}/files/{pos}/download.
func isOwnerDownloadPath(path string) bool {
	for _, prefix := range []string{"/api/user/files/", "/api/user/bundles/"} {
		if rest, ok := strings.CutPrefix(path, prefix); ok && len(rest) > len("/download") && strings.HasSuffix(rest, "/download") {
			return true
		}
	}
	return false
}

func RateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := rl.getClientIP(r)

			// Determine which limit to apply based on path
			// Read current limit values from config (allows runtime updates)
			var limit int
			var limitType string

			// A drop (POST /drop) is an upload too; GET is just the form.
			if r.URL.Path == "/api/upload" || r.URL.Path == "/api/upload/init" || (r.URL.Path == "/drop" && r.Method == http.MethodPost) {
				limit = rl.config.GetRateLimitUpload()
				limitType = "upload"
			} else if strings.HasPrefix(r.URL.Path, "/api/upload/chunk/") {
				// Enough chunks for RATE_LIMIT_UPLOAD maximum-size uploads
				// (see chunkRequestLimit).
				limit = chunkRequestLimit(rl.config)
				limitType = "chunk"
			} else if strings.HasPrefix(r.URL.Path, "/api/upload/complete/") {
				// SH-1.4: rate-limit the complete endpoint so a single IP
				// cannot generate a DB-write storm via repeated saturation
				// 503s. 10× the upload limit (the old chunk cap) — a polite
				// client polling complete on a many-chunk upload after
				// reconnect should not get throttled, but a malicious client
				// spamming the endpoint will. The previous "already rate
				// limited via init" assumption was wrong: a single /init
				// call grants unbounded /complete attempts.
				limit = rl.config.GetRateLimitUpload() * 10
				limitType = "complete"
			} else if strings.HasPrefix(r.URL.Path, "/api/upload/status/") {
				// T32: status was unlimited, and each call lists the
				// upload's chunk directory. Clients poll it every ~2s while
				// an upload assembles (~1800/hour per upload), so the cap
				// is far above that - 600x the upload limit, and never under
				// 6000/hour, so a low RATE_LIMIT_UPLOAD can't break a
				// client's own polling - leaving room for several large
				// uploads assembling at once from one address, while still
				// bounding a client that hammers it. (The sliding window
				// keeps one timestamp per request: ~150 KB for a full bucket.)
				limit = max(rl.config.GetRateLimitUpload()*600, minStatusRateLimitPerHour)
				limitType = "status"
			} else if strings.HasPrefix(r.URL.Path, "/api/claim/") && strings.HasSuffix(r.URL.Path, "/info") {
				// The info endpoint answers "does this claim code exist?",
				// so leaving it unlimited let a client guess codes at full
				// speed and spend its download budget only on hits. It gets
				// its own bucket, at claimInfoLimitMultiplier times the
				// download limit, because the download page calls it once
				// before each download.
				limit = rl.config.GetRateLimitDownload() * claimInfoLimitMultiplier
				limitType = "claim_info"
			} else if strings.HasPrefix(r.URL.Path, "/api/bundle/") && strings.HasSuffix(r.URL.Path, "/info") {
				// A bundle code lookup is the same kind of "does this code
				// exist?" probe as a claim info lookup: same bucket.
				limit = rl.config.GetRateLimitDownload() * claimInfoLimitMultiplier
				limitType = "claim_info"
			} else if strings.HasPrefix(r.URL.Path, "/api/claim/") || strings.HasPrefix(r.URL.Path, "/api/bundle/") {
				// Each file of a bundle is a download, like a single-file claim.
				limit = rl.config.GetRateLimitDownload()
				limitType = "download"
			} else if r.URL.Path == "/api/bundles" || strings.HasPrefix(r.URL.Path, "/api/bundles/") {
				// Creating, publishing and deleting a bundle: one bucket at
				// the upload limit. The member files themselves go through
				// /api/upload and /api/upload/init and count as uploads.
				limit = rl.config.GetRateLimitUpload()
				limitType = "bundle_manage"
			} else if isOwnerDownloadPath(r.URL.Path) {
				// A signed-in user downloading their own file: the download
				// rate, in its own bucket so it never eats into recipients'.
				// The dashboard's HEAD check before each download moves no
				// file data: it gets its own larger budget, like claim info.
				if r.Method == http.MethodHead {
					limit = rl.config.GetRateLimitDownload() * claimInfoLimitMultiplier
					limitType = "owner_download_check"
				} else {
					limit = rl.config.GetRateLimitDownload()
					limitType = "owner_download"
				}
			} else if r.URL.Path == "/api/user/files/regenerate-claim-code" ||
				(strings.HasPrefix(r.URL.Path, "/api/user/bundles/") && strings.HasSuffix(r.URL.Path, "/regenerate-code")) {
				limit = 10 // Hardcoded: 10 regenerations per hour per IP
				limitType = "regeneration"
			} else {
				// No rate limit for other endpoints:
				// - health, static files
				next.ServeHTTP(w, r)
				return
			}

			// Check rate limit. T43: the bucket key groups IPv6 clients by
			// the configured prefix (default /64) so address rotation
			// within one allocation doesn't grant a fresh budget; logging
			// below still uses the full ip, not this grouped key.
			if !rl.checkLimit(utils.RateLimitKey(ip), limitType, limit) {
				slog.Warn("rate limit exceeded",
					"ip", privacy.RedactIP(ip, rl.config.IsAnonymousMode()),
					"limit_type", limitType,
					"limit", limit,
					"path", logPath(r.URL.Path),
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

// getClientIP extracts the client IP address from the request with trusted
// proxy validation. Delegates to the single shared implementation in
// internal/utils (T41: this used to duplicate a leftmost-XFF-entry bug that
// let clients spoof their rate-limit/audit IP through a trusted proxy).
func (rl *RateLimiter) getClientIP(r *http.Request) string {
	return utils.GetClientIPWithTrust(r, rl.config.GetTrustProxyHeaders(), rl.config.GetTrustedProxyIPs(), rl.config.IsAnonymousMode())
}
