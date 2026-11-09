package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRateLimit_BundlePaths: creating, publishing and deleting bundles share
// one bucket at the upload limit, separate from member uploads (which stay
// in the "upload" bucket).
func TestRateLimit_BundlePaths(t *testing.T) {
	cfg := &mockConfigProvider{uploadLimit: 2, downloadLimit: 50}
	rl := NewRateLimiter(cfg)
	defer rl.Stop()
	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	send := func(method, path, ip string) int {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = ip + ":12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	ip := "192.168.7.1"
	if c := send(http.MethodPost, "/api/bundles", ip); c != http.StatusOK {
		t.Fatalf("create 1: %d", c)
	}
	if c := send(http.MethodPost, "/api/bundles/5/publish", ip); c != http.StatusOK {
		t.Fatalf("publish: %d", c)
	}
	if c := send(http.MethodDelete, "/api/bundles/5", ip); c != http.StatusTooManyRequests {
		t.Fatalf("third bundle call: %d, want 429", c)
	}
	// Member uploads have their own budget.
	if c := send(http.MethodPost, "/api/upload", ip); c != http.StatusOK {
		t.Fatalf("upload after bundle budget spent: %d", c)
	}
}

// TestRateLimit_BundleReceivePaths: bundle info shares the claim-info
// multiplier; bundle file downloads count as downloads.
func TestRateLimit_BundleReceivePaths(t *testing.T) {
	cfg := &mockConfigProvider{uploadLimit: 10, downloadLimit: 2}
	rl := NewRateLimiter(cfg)
	defer rl.Stop()
	handler := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	send := func(path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "192.168.8.1:12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}
	for i := 0; i < 2*claimInfoLimitMultiplier; i++ {
		if c := send("/api/bundle/AbCd1234/info"); c != http.StatusOK {
			t.Fatalf("info %d: %d", i, c)
		}
	}
	if c := send("/api/bundle/AbCd1234/info"); c != http.StatusTooManyRequests {
		t.Fatalf("info over limit: %d", c)
	}
	for i := 0; i < 2; i++ {
		if c := send(fmt.Sprintf("/api/bundle/AbCd1234/files/%d", i)); c != http.StatusOK {
			t.Fatalf("file %d: %d", i, c)
		}
	}
	if c := send("/api/bundle/AbCd1234/files/2"); c != http.StatusTooManyRequests {
		t.Fatalf("file over limit: %d", c)
	}
	// Bundle downloads share the download bucket with single-file claims.
	if c := send("/api/claim/AbCd1234"); c != http.StatusTooManyRequests {
		t.Fatalf("claim after bundle downloads spent the budget: %d", c)
	}
}
