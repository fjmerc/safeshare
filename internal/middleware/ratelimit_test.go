package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/utils"
)

// mockConfigProvider implements ConfigProvider for testing
type mockConfigProvider struct {
	uploadLimit   int
	downloadLimit int
	mu            sync.RWMutex

	// trustProxyHeaders and trustedProxyIPs override the "auto" + default
	// RFC1918 trust settings below when non-empty. Left unset, existing
	// tests keep their original behavior.
	trustProxyHeaders string
	trustedProxyIPs   string

	anonymousMode bool
}

func (m *mockConfigProvider) GetRateLimitUpload() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.uploadLimit
}

func (m *mockConfigProvider) GetRateLimitDownload() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.downloadLimit
}

func (m *mockConfigProvider) GetTrustProxyHeaders() string {
	if m.trustProxyHeaders != "" {
		return m.trustProxyHeaders
	}
	return "auto"
}

func (m *mockConfigProvider) GetTrustedProxyIPs() string {
	if m.trustedProxyIPs != "" {
		return m.trustedProxyIPs
	}
	return "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
}

func (m *mockConfigProvider) SetUploadLimit(limit int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uploadLimit = limit
}

func (m *mockConfigProvider) SetDownloadLimit(limit int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.downloadLimit = limit
}

func (m *mockConfigProvider) IsAnonymousMode() bool {
	return m.anonymousMode
}

func TestRateLimiter_UploadLimit(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   10,
		downloadLimit: 50,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 10 requests (should all succeed)
	for i := 1; i <= 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: got status %d, want 200", i, rr.Code)
		}
	}

	// 11th request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("request 11: got status %d, want 429", rr.Code)
	}

	// Check Retry-After header
	retryAfter := rr.Header().Get("Retry-After")
	if retryAfter != "3600" {
		t.Errorf("Retry-After = %q, want 3600", retryAfter)
	}
}

func TestRateLimiter_DownloadLimit(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   10,
		downloadLimit: 5,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 5 download requests (should all succeed)
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/claim/test123", nil)
		req.RemoteAddr = "192.168.1.2:12345"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: got status %d, want 200", i, rr.Code)
		}
	}

	// 6th request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/api/claim/test123", nil)
	req.RemoteAddr = "192.168.1.2:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("request 6: got status %d, want 429", rr.Code)
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   3,
		downloadLimit: 50,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Each IP should have independent rate limits
	ips := []string{
		"192.168.1.1:12345",
		"192.168.1.2:12345",
		"192.168.1.3:12345",
	}

	for _, ip := range ips {
		// Each IP can make 3 requests
		for i := 1; i <= 3; i++ {
			req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
			req.RemoteAddr = ip
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("IP %s request %d: got status %d, want 200", ip, i, rr.Code)
			}
		}

		// 4th request should fail for each IP
		req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusTooManyRequests {
			t.Errorf("IP %s request 4: got status %d, want 429", ip, rr.Code)
		}
	}
}

func TestRateLimiter_XForwardedFor(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   2,
		downloadLimit: 50,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test X-Forwarded-For header
	for i := 1; i <= 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
		req.RemoteAddr = "10.0.0.1:12345"                // Proxy IP
		req.Header.Set("X-Forwarded-For", "203.0.113.1") // Real client IP
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: got status %d, want 200", i, rr.Code)
		}
	}

	// 3rd request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("request 3: got status %d, want 429", rr.Code)
	}
}

func TestRateLimiter_NoRateLimitForOtherPaths(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   1,
		downloadLimit: 1,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Paths that should NOT be rate limited
	paths := []string{
		"/health",
		"/api/claim/test123/info",
		"/",
		"/static/style.css",
	}

	for _, path := range paths {
		// Make 10 requests to each path (should all succeed)
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("path %s request %d: got status %d, want 200", path, i, rr.Code)
			}
		}
	}
}

func TestRateLimiter_DynamicConfigUpdate(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   2,
		downloadLimit: 50,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 2 requests (at limit)
	for i := 1; i <= 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: got status %d, want 200", i, rr.Code)
		}
	}

	// Update limit to 5
	cfg.SetUploadLimit(5)

	// Now we should be able to make 3 more requests
	for i := 1; i <= 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("after config update request %d: got status %d, want 200", i, rr.Code)
		}
	}

	// 6th total request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("request 6: got status %d, want 429", rr.Code)
	}
}

func TestRateLimiter_Concurrency(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   100,
		downloadLimit: 100,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 100 concurrent requests
	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code == http.StatusOK {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// All 100 should succeed (within limit)
	if successCount != 100 {
		t.Errorf("successful requests = %d, want 100", successCount)
	}

	// 101st request should fail
	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("request 101: got status %d, want 429", rr.Code)
	}
}

func TestRateLimiter_MemoryCleanup(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   10,
		downloadLimit: 50,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make request from IP1
	req1 := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	// Verify IP1 is tracked
	count := 0
	rl.records.Range(func(key, value interface{}) bool {
		count++
		return true
	})

	if count != 1 {
		t.Errorf("tracked IPs = %d, want 1", count)
	}

	// Note: Actual cleanup happens on 1-hour ticker
	// This test just verifies the structure is in place
}

func TestRateLimiter_Stop(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   10,
		downloadLimit: 50,
	}

	rl := NewRateLimiter(cfg)

	// Stop should not panic
	rl.Stop()

	// Calling Stop again should not panic
	rl.Stop()
}

func TestRateLimiter_EdgeCases(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   0,  // Zero limit
		downloadLimit: -1, // Negative limit
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name string
		path string
		want int
	}{
		{
			name: "zero upload limit",
			path: "/api/upload",
			want: http.StatusTooManyRequests, // First request should fail
		},
		{
			name: "negative download limit",
			path: "/api/claim/test",
			want: http.StatusTooManyRequests, // Should treat as 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.want {
				t.Errorf("got status %d, want %d", rr.Code, tt.want)
			}
		})
	}
}

// TestRateLimiter_MultipleXForwardedFor is a T41 regression test: a chain
// with several comma-separated hops must bucket by the rightmost *untrusted*
// hop (walking from the right, skipping entries that are themselves trusted
// proxies), never by the leftmost, client-controlled entry. A client that
// varies the spoofable leftmost entry on every request must not be able to
// evade the rate limit by doing so.
func TestRateLimiter_MultipleXForwardedFor(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   2,
		downloadLimit: 50,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Same real client (rightmost, untrusted) on every request; only the
	// attacker-controlled leftmost entry changes.
	const realClient = "198.51.100.77"
	spoofedLeftmost := []string{"203.0.113.11", "203.0.113.22", "203.0.113.33"}

	for i, spoofed := range spoofedLeftmost {
		req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
		req.RemoteAddr = "10.0.0.1:12345" // trusted proxy peer
		req.Header.Set("X-Forwarded-For", spoofed+", "+realClient)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if i < 2 {
			if rr.Code != http.StatusOK {
				t.Errorf("request %d: got status %d, want 200", i+1, rr.Code)
			}
		} else {
			if rr.Code != http.StatusTooManyRequests {
				t.Errorf("request %d: got status %d, want 429 (spoofed leftmost XFF entry must not evade rate limiting)", i+1, rr.Code)
			}
		}
	}
}

func TestRateLimiter_XRealIP(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   2,
		downloadLimit: 50,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test X-Real-IP header (nginx style)
	for i := 1; i <= 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Real-IP", "203.0.113.5")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: got status %d, want 200", i, rr.Code)
		}
	}

	// 3rd request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Real-IP", "203.0.113.5")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("request 3: got status %d, want 429", rr.Code)
	}
}

func TestRateLimiter_IPv6(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   2,
		downloadLimit: 50,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test IPv6 address
	for i := 1; i <= 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
		req.RemoteAddr = "[2001:db8::1]:12345"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: got status %d, want 200", i, rr.Code)
		}
	}

	// 3rd request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.RemoteAddr = "[2001:db8::1]:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("request 3: got status %d, want 429", rr.Code)
	}
}

// TestRateLimiter_IPv6PrefixGrouping is a T43 test: two IPv6 addresses
// within the same configured prefix share a rate-limit bucket, addresses in
// different prefixes don't, and configuring 128 (per-address) restores the
// pre-T43 behavior.
func TestRateLimiter_IPv6PrefixGrouping(t *testing.T) {
	t.Cleanup(func() { utils.ConfigureRateLimitIPv6Prefix(64) })

	newHandler := func(cfg *mockConfigProvider) (http.Handler, *RateLimiter) {
		rl := NewRateLimiter(cfg)
		return RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})), rl
	}

	t.Run("same /64 shares a bucket at default prefix", func(t *testing.T) {
		utils.ConfigureRateLimitIPv6Prefix(64)
		cfg := &mockConfigProvider{uploadLimit: 2, downloadLimit: 50}
		handler, rl := newHandler(cfg)
		defer rl.Stop()

		addrs := []string{"[2001:db8:1234:5678::1]:1", "[2001:db8:1234:5678:aaaa:bbbb:cccc:dddd]:1"}
		for i, addr := range addrs {
			req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
			req.RemoteAddr = addr
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("request %d (%s): got status %d, want 200", i, addr, rr.Code)
			}
		}

		// The bucket (shared across both addresses) is now exhausted.
		req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
		req.RemoteAddr = "[2001:db8:1234:5678::2]:1"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusTooManyRequests {
			t.Errorf("3rd request from same /64: got status %d, want 429", rr.Code)
		}
	})

	t.Run("different /64s get separate buckets", func(t *testing.T) {
		utils.ConfigureRateLimitIPv6Prefix(64)
		cfg := &mockConfigProvider{uploadLimit: 1, downloadLimit: 50}
		handler, rl := newHandler(cfg)
		defer rl.Stop()

		for _, addr := range []string{"[2001:db8:1111::1]:1", "[2001:db8:2222::1]:1"} {
			req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
			req.RemoteAddr = addr
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("first request from %s: got status %d, want 200", addr, rr.Code)
			}
		}
	})

	t.Run("prefix 128 restores per-address behavior", func(t *testing.T) {
		utils.ConfigureRateLimitIPv6Prefix(128)
		cfg := &mockConfigProvider{uploadLimit: 1, downloadLimit: 50}
		handler, rl := newHandler(cfg)
		defer rl.Stop()

		// Same /64, different host -- must NOT share a bucket at prefix=128.
		for _, addr := range []string{"[2001:db8:1234:5678::1]:1", "[2001:db8:1234:5678::2]:1"} {
			req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
			req.RemoteAddr = addr
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("first request from %s at prefix=128: got status %d, want 200", addr, rr.Code)
			}
		}
	})
}

// Benchmark rate limiter
func BenchmarkRateLimiter(b *testing.B) {
	cfg := &mockConfigProvider{
		uploadLimit:   1000000, // Very high limit
		downloadLimit: 1000000,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}

func BenchmarkRateLimiter_Parallel(b *testing.B) {
	cfg := &mockConfigProvider{
		uploadLimit:   1000000,
		downloadLimit: 1000000,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		for pb.Next() {
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
		}
	})
}

// TestRateLimiter_SeparateBucketsPerLimitType is a regression test: all limit
// types used to share one timestamp slice per IP, so the chunks of one large
// upload exhausted the upload and download limits for the rest of the hour.
func TestRateLimiter_SeparateBucketsPerLimitType(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:   10,
		downloadLimit: 5,
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func(method, path string) int {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	// One init plus 60 chunks: well over the upload (10) and download (5)
	// limits, but within the chunk limit (10 × 10 = 100).
	if code := do(http.MethodPost, "/api/upload/init"); code != http.StatusOK {
		t.Fatalf("init: got status %d, want 200", code)
	}
	for i := 0; i < 60; i++ {
		if code := do(http.MethodPost, "/api/upload/chunk/abc/"+string(rune('0'+i%10))); code != http.StatusOK {
			t.Fatalf("chunk %d: got status %d, want 200", i, code)
		}
	}

	// Chunk traffic must not consume the upload or download buckets.
	if code := do(http.MethodPost, "/api/upload/init"); code != http.StatusOK {
		t.Errorf("second init after chunks: got status %d, want 200", code)
	}
	for i := 1; i <= 5; i++ {
		if code := do(http.MethodGet, "/api/claim/code123"); code != http.StatusOK {
			t.Errorf("download %d after chunks: got status %d, want 200", i, code)
		}
	}

	// The download bucket still enforces its own limit.
	if code := do(http.MethodGet, "/api/claim/code123"); code != http.StatusTooManyRequests {
		t.Errorf("download over limit: got status %d, want 429", code)
	}
}

// TestRateLimiter_ProductionChainSpoofResistant proves the T41 fix at this
// call site: client -> Cloudflare -> Traefik -> SafeShare. Traefik forwards
// whatever XFF the client sent plus the Cloudflare edge IP it saw; Cloudflare
// appends the real client IP to whatever XFF the client sent. So the header
// this middleware sees is "<attacker-controlled>, <real client>, <cf edge>".
// Rotating the attacker-controlled leftmost entry must not let a client
// evade the rate limit; only the real client IP should determine the bucket.
func TestRateLimiter_ProductionChainSpoofResistant(t *testing.T) {
	cfg := &mockConfigProvider{
		uploadLimit:       2,
		downloadLimit:     50,
		trustProxyHeaders: "auto",
		trustedProxyIPs:   "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,cloudflare",
	}

	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	const realClient = "203.0.113.42"
	const cfEdge = "172.64.1.1" // within Cloudflare's published ranges
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

// TestRateLimiter_UploadStatusLimit covers T32: /api/upload/status/ is rate
// limited at 600x the upload limit (here 600 x 10), in its own bucket.
func TestRateLimiter_UploadStatusLimit(t *testing.T) {
	cfg := &mockConfigProvider{uploadLimit: 10, downloadLimit: 1}
	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	send := func(path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "192.168.1.77:12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	for i := 1; i <= 6000; i++ {
		if code := send("/api/upload/status/550e8400-e29b-41d4-a716-446655440000"); code != http.StatusOK {
			t.Fatalf("status request %d: got %d, want 200", i, code)
		}
	}
	if code := send("/api/upload/status/550e8400-e29b-41d4-a716-446655440000"); code != http.StatusTooManyRequests {
		t.Fatalf("status request 6001: got %d, want 429", code)
	}

	// Separate bucket: the upload budget is untouched.
	if code := send("/api/upload"); code != http.StatusOK {
		t.Fatalf("upload after exhausting status budget: got %d, want 200", code)
	}
}

// TestRateLimiter_UploadStatusLimitFloor checks a low RATE_LIMIT_UPLOAD
// can't push the status limit below what a polling client needs.
func TestRateLimiter_UploadStatusLimitFloor(t *testing.T) {
	cfg := &mockConfigProvider{uploadLimit: 1, downloadLimit: 1}
	rl := NewRateLimiter(cfg)
	defer rl.Stop()
	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 1; i <= minStatusRateLimitPerHour; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/upload/status/550e8400-e29b-41d4-a716-446655440000", nil)
		req.RemoteAddr = "192.168.1.78:12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200 (floor is %d)", i, rr.Code, minStatusRateLimitPerHour)
		}
	}
}

// TestRequestRecord_CheckCoarse covers the per-minute window: it enforces
// the limit, frees budget once an hour has passed, and ignores slots
// stamped in the future (a wall-clock step backwards).
func TestRequestRecord_CheckCoarse(t *testing.T) {
	r := &requestRecord{}
	base := time.Unix(1_800_000_000, 0)

	for i := 0; i < 3; i++ {
		if !r.checkCoarse(base, 3) {
			t.Fatalf("request %d rejected under limit", i+1)
		}
	}
	if r.checkCoarse(base.Add(30*time.Minute), 3) {
		t.Fatal("4th request within the hour allowed")
	}
	if !r.checkCoarse(base.Add(61*time.Minute), 3) {
		t.Fatal("request after the window rejected")
	}

	// Clock steps back two hours: the "future" slots no longer count.
	if !r.checkCoarse(base.Add(-2*time.Hour), 1) {
		t.Fatal("future-stamped slots counted after a clock step back")
	}
	if !r.coarseActive(base.Add(-2*time.Hour).Unix() / 60) {
		t.Fatal("record with a current count reported inactive")
	}
	if (&requestRecord{}).coarseActive(base.Unix() / 60) {
		t.Fatal("record without a coarse window reported active")
	}
}
