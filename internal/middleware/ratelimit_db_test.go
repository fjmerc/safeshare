package middleware

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
)

// fakeRateLimitRepo is a minimal in-memory repository.RateLimitRepository
// for exercising DBRateLimitMiddleware without a real database.
type fakeRateLimitRepo struct {
	mu     sync.Mutex
	counts map[string]int // key: ipAddress|limitType
}

func newFakeRateLimitRepo() *fakeRateLimitRepo {
	return &fakeRateLimitRepo{counts: make(map[string]int)}
}

func (f *fakeRateLimitRepo) IncrementAndCheck(ctx context.Context, ipAddress, limitType string, limit int, windowDuration time.Duration) (bool, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := ipAddress + "|" + limitType
	f.counts[key]++
	count := f.counts[key]
	return count <= limit, count, nil
}

func (f *fakeRateLimitRepo) GetEntry(ctx context.Context, ipAddress, limitType string) (*repository.RateLimitEntry, error) {
	return nil, nil
}

func (f *fakeRateLimitRepo) ResetEntry(ctx context.Context, ipAddress, limitType string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.counts, ipAddress+"|"+limitType)
	return nil
}

func (f *fakeRateLimitRepo) CleanupExpired(ctx context.Context) (int64, error) {
	return 0, nil
}

func (f *fakeRateLimitRepo) GetAllEntriesForIP(ctx context.Context, ipAddress string) ([]repository.RateLimitEntry, error) {
	return nil, nil
}

// TestGetClientIPForRateLimit_IgnoresSpoofedLeftmostXFF is a direct,
// T41-focused unit test of this call site's IP resolution: a client that
// controls the leftmost X-Forwarded-For entry must not be able to make the
// database-backed rate limiter bucket requests under an IP of its choosing.
func TestGetClientIPForRateLimit_IgnoresSpoofedLeftmostXFF(t *testing.T) {
	cfg := &mockConfigProvider{
		trustProxyHeaders: "auto",
		trustedProxyIPs:   "10.0.0.0/8,cloudflare",
	}

	const realClient = "203.0.113.42"
	const cfEdge = "172.64.1.1" // within Cloudflare's published ranges

	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.RemoteAddr = "10.0.0.5:54321" // trusted proxy peer
	req.Header.Set("X-Forwarded-For", "6.6.6.6, "+realClient+", "+cfEdge)
	// A Cloudflare hop is consumed here, so the CF-Connecting-IP veto
	// applies: the real edge would set this to the real client's IP. See
	// TestGetClientIPWithTrust_CFConnectingIPVeto in internal/utils for
	// what happens without it.
	req.Header.Set("CF-Connecting-IP", realClient)

	got := getClientIPForRateLimit(req, cfg)
	if got != realClient {
		t.Errorf("getClientIPForRateLimit() = %q, want %q", got, realClient)
	}
}

// TestDBRateLimiter_checkLimit_RedactsIPInAnonymousMode is a bug-hunter
// follow-up on T41: checkLimit used to log the raw client IP unconditionally
// (unlike the login rate limiter path in this same file, which already
// respected anonymous mode via privacy.RedactIP). Both the "exceeded"
// warning and the "repo error" log line must redact the IP when the
// configured ConfigProvider reports anonymous mode.
func TestDBRateLimiter_checkLimit_RedactsIPInAnonymousMode(t *testing.T) {
	const realIP = "203.0.113.42"

	captureLog := func(t *testing.T, fn func()) string {
		t.Helper()
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
		t.Cleanup(func() { slog.SetDefault(prev) })
		fn()
		return buf.String()
	}

	t.Run("rate limit exceeded warning redacts the IP", func(t *testing.T) {
		cfg := &mockConfigProvider{anonymousMode: true}
		repo := newFakeRateLimitRepo()
		rl := NewDBRateLimiter(cfg, repo)
		defer rl.Stop()

		// Exhaust the limit (1) so the second call logs "exceeded".
		rl.checkLimit(context.Background(), realIP, "upload", 1)
		out := captureLog(t, func() {
			rl.checkLimit(context.Background(), realIP, "upload", 1)
		})

		if strings.Contains(out, realIP) {
			t.Errorf("log output contains unredacted IP %q in anonymous mode: %s", realIP, out)
		}
		if !strings.Contains(out, "redacted") {
			t.Errorf("log output missing redacted IP marker: %s", out)
		}
	})

	t.Run("repo error log redacts the IP", func(t *testing.T) {
		cfg := &mockConfigProvider{anonymousMode: true}
		rl := NewDBRateLimiter(cfg, &erroringRateLimitRepo{})
		defer rl.Stop()

		out := captureLog(t, func() {
			rl.checkLimit(context.Background(), realIP, "upload", 1)
		})

		if strings.Contains(out, realIP) {
			t.Errorf("log output contains unredacted IP %q in anonymous mode: %s", realIP, out)
		}
		if !strings.Contains(out, "redacted") {
			t.Errorf("log output missing redacted IP marker: %s", out)
		}
	})
}

// erroringRateLimitRepo always fails IncrementAndCheck, to exercise
// checkLimit's fail-open error-logging path.
type erroringRateLimitRepo struct {
	fakeRateLimitRepo
}

func (e *erroringRateLimitRepo) IncrementAndCheck(ctx context.Context, ipAddress, limitType string, limit int, windowDuration time.Duration) (bool, int, error) {
	return false, 0, context.DeadlineExceeded
}

// TestDBRateLimiter_ProductionChainSpoofResistant proves the T41 fix at the
// database-backed rate limiter's call site, mirroring the production chain:
// client -> Cloudflare -> Traefik -> SafeShare. Rotating the
// attacker-controlled leftmost XFF entry must not let a client evade the
// rate limit; only the real client IP (rightmost, untrusted) should
// determine the bucket.
func TestDBRateLimiter_ProductionChainSpoofResistant(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:       2,
		downloadLimit:     50,
		trustProxyHeaders: "auto",
		trustedProxyIPs:   "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,cloudflare",
	}
	repo := newFakeRateLimitRepo()
	rl := NewDBRateLimiter(cfg, repo)
	defer rl.Stop()

	handler := DBRateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	const realClient = "203.0.113.42"
	const cfEdge = "172.64.1.1"
	spoofedLeftmost := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}

	for i, spoofed := range spoofedLeftmost {
		req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
		req.RemoteAddr = "172.20.0.5:54321" // Traefik peer, within trusted RFC1918 range
		req.Header.Set("X-Forwarded-For", spoofed+", "+realClient+", "+cfEdge)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if i < 2 {
			if rr.Code != http.StatusOK {
				t.Errorf("request %d: got status %d, want 200", i+1, rr.Code)
			}
		} else {
			if rr.Code != http.StatusTooManyRequests {
				t.Errorf("request %d: got status %d, want 429 (spoofed leftmost XFF must not evade rate limiting)", i+1, rr.Code)
			}
		}
	}
}
