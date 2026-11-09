package middleware

import (
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
