package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLoginRateLimiter_ParallelBurstOnlyAllowsMaxAttemptsThrough is a
// regression test for the v1.7.1 hotfix follow-up: the attempt count used
// to be incremented in a defer that ran *after* next.ServeHTTP returned, so
// a burst of parallel requests from one IP could all pass the "am I locked
// out" check before any of them finished (e.g. a slow password hash) and
// incremented the count - bypassing the lockout entirely. The attempt is
// now reserved under the same lock as the check, before the handler runs,
// so out of a 50-way parallel burst from a single IP, exactly maxAttempts
// (5) may reach the handler.
func TestLoginRateLimiter_ParallelBurstOnlyAllowsMaxAttemptsThrough(t *testing.T) {
	tests := []struct {
		name  string
		build func(bool) func(http.Handler) http.Handler
	}{
		{"admin", RateLimitAdminLogin},
		{"user", RateLimitUserLogin},
		{"totp", RateLimitTOTPVerify},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reached int32
			handler := tt.build(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&reached, 1)
				time.Sleep(50 * time.Millisecond) // simulate a slow handler (e.g. password hashing)
				w.WriteHeader(http.StatusOK)
			}))

			const n = 50
			var wg sync.WaitGroup
			wg.Add(n)
			for i := 0; i < n; i++ {
				go func() {
					defer wg.Done()
					req := httptest.NewRequest(http.MethodPost, "/x", nil)
					req.RemoteAddr = "198.51.100.5:1234" // same IP for every request
					rr := httptest.NewRecorder()
					handler.ServeHTTP(rr, req)
				}()
			}
			wg.Wait()

			if got := atomic.LoadInt32(&reached); got != 5 {
				t.Errorf("%s: handler reached %d times out of %d parallel requests from one IP, want exactly 5 (the lockout threshold)", tt.name, got, n)
			}
		})
	}
}

// TestLoginRateLimiter_ConcurrentDistinctIPs_NoRace drives many distinct IPs
// concurrently against the TOTP and user login limiters. This is the test
// that would have caught the v1.7.0 crash: RateLimitTOTPVerify was already
// built once (shared across every request) but had no synchronization
// around its attempts map, so concurrent requests from different IPs hit
// "fatal error: concurrent map iteration and map write" in production.
// Must be run with -race to be meaningful.
func TestLoginRateLimiter_ConcurrentDistinctIPs_NoRace(t *testing.T) {
	tests := []struct {
		name  string
		build func(bool) func(http.Handler) http.Handler
	}{
		{"totp", RateLimitTOTPVerify},
		{"user", RateLimitUserLogin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := tt.build(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			const numIPs = 200
			const requestsPerIP = 5

			var wg sync.WaitGroup
			wg.Add(numIPs)
			for i := 0; i < numIPs; i++ {
				go func(i int) {
					defer wg.Done()
					ip := fmt.Sprintf("10.%d.%d.%d:1234", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
					for j := 0; j < requestsPerIP; j++ {
						req := httptest.NewRequest(http.MethodPost, "/x", nil)
						req.RemoteAddr = ip
						rr := httptest.NewRecorder()
						handler.ServeHTTP(rr, req)
					}
				}(i)
			}
			wg.Wait()
		})
	}
}

// TestLoginRateLimiter_TrackedIPCap verifies the map of tracked IPs is
// bounded: once maxTrackedLoginAttempts distinct IPs are being tracked, a
// request from a new IP fails closed with 429 instead of growing the map
// further, while requests from already-tracked IPs keep working.
func TestLoginRateLimiter_TrackedIPCap(t *testing.T) {
	original := maxTrackedLoginAttempts
	maxTrackedLoginAttempts = 3
	t.Cleanup(func() { maxTrackedLoginAttempts = original })

	handler := RateLimitUserLogin(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	trackedIPs := []string{"10.0.0.1:1", "10.0.0.2:1", "10.0.0.3:1"}
	for _, ip := range trackedIPs {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("ip %s: status = %d, want %d (below cap)", ip, rr.Code, http.StatusOK)
		}
	}

	// A 4th distinct IP should be rejected: the tracked-IP cap is reached.
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.RemoteAddr = "10.0.0.4:1"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("4th distinct IP: status = %d, want %d (tracked-IP cap reached, fail closed)", rr.Code, http.StatusTooManyRequests)
	}

	// An already-tracked IP must still work even though the cap is reached.
	req2 := httptest.NewRequest(http.MethodPost, "/x", nil)
	req2.RemoteAddr = trackedIPs[0]
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("existing tracked IP: status = %d, want %d even with the cap reached", rr2.Code, http.StatusOK)
	}
}
