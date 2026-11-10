package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Owner downloads (a signed-in user downloading their own file from the
// dashboard) are limited at the download rate, in their own bucket, by both
// limiters.
func TestRateLimit_OwnerDownloads(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mem := NewRateLimiter(&mockConfigProvider{uploadLimit: 10, downloadLimit: 2})
	defer mem.Stop()
	db := NewDBRateLimiter(&mockConfigProvider{uploadLimit: 10, downloadLimit: 2}, newFakeRateLimitRepo())
	defer db.Stop()

	for name, handler := range map[string]http.Handler{
		"memory":   RateLimitMiddleware(mem)(ok),
		"database": DBRateLimitMiddleware(db)(ok),
	} {
		t.Run(name, func(t *testing.T) {
			sendMethod := func(method, path string) int {
				req := httptest.NewRequest(method, path, nil)
				req.RemoteAddr = "192.168.9.1:12345"
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)
				return rr.Code
			}
			send := func(path string) int { return sendMethod(http.MethodGet, path) }
			// The dashboard checks with HEAD before each download: those
			// checks have their own, larger budget (like claim info) and
			// don't use up the download budget.
			for i := 0; i < 2*claimInfoLimitMultiplier; i++ {
				if c := sendMethod(http.MethodHead, "/api/user/files/Xk3pQ9aB/download"); c != http.StatusOK {
					t.Fatalf("HEAD %d: %d", i, c)
				}
			}
			if c := sendMethod(http.MethodHead, "/api/user/files/Xk3pQ9aB/download"); c != http.StatusTooManyRequests {
				t.Fatalf("HEAD past its budget: %d, want 429", c)
			}
			if c := send("/api/user/files/Xk3pQ9aB/download"); c != http.StatusOK {
				t.Fatalf("owner download 1: %d", c)
			}
			if c := send("/api/user/bundles/4/files/0/download"); c != http.StatusOK {
				t.Fatalf("owner download 2: %d", c)
			}
			if c := send("/api/user/files/Xk3pQ9aB/download"); c != http.StatusTooManyRequests {
				t.Fatalf("owner download 3: %d, want 429", c)
			}
			// Recipient downloads keep their own budget.
			if c := send("/api/claim/AbCd1234"); c != http.StatusOK {
				t.Fatalf("claim after owner budget spent: %d", c)
			}
			// Other owner routes stay unlimited.
			if c := send("/api/user/files"); c != http.StatusOK {
				t.Fatalf("file list: %d", c)
			}
		})
	}
}
