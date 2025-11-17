package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// mockConfigProvider implements ConfigProvider for testing
type mockConfigProvider struct {
	uploadLimit   int
	downloadLimit int
	mu            sync.RWMutex
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
	return "auto"
}

func (m *mockConfigProvider) GetTrustedProxyIPs() string {
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
		req.RemoteAddr = "10.0.0.1:12345" // Proxy IP
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
		uploadLimit:   0, // Zero limit
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

	// Test with multiple IPs in X-Forwarded-For (should use first)
	for i := 1; i <= 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.1, 192.0.2.1")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: got status %d, want 200", i, rr.Code)
		}
	}

	// 3rd request with same first IP should fail
	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.1")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("request 3: got status %d, want 429", rr.Code)
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
