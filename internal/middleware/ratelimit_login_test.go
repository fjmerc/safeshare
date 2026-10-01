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
//
// The handler returns 401 (a failure), not 200: since a successful response
// now refunds this request's own reservation (see the login-lockout
// refinement follow-up to v1.7.1), a "succeeding" handler would let
// reservations drain back down mid-burst and could admit more than 5
// through in a race between the burst's own dispatch and the first handler
// call finishing - this test is specifically about the
// reservation-before-handler property, which is orthogonal to
// success/failure, so it isolates that property with a response that never
// triggers a refund.
func TestLoginRateLimiter_ParallelBurstOnlyAllowsMaxAttemptsThrough(t *testing.T) {
	tests := []struct {
		name  string
		build func(bool) func(http.Handler) http.Handler
	}{
		{"admin", RateLimitAdminLogin},
		{"user", RateLimitUserLogin},
		{"mfa enrollment", RateLimitMFAEnrollment},
		{"sso callback", RateLimitSSOCallback},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reached int32
			handler := tt.build(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&reached, 1)
				time.Sleep(50 * time.Millisecond) // simulate a slow handler (e.g. password hashing)
				w.WriteHeader(http.StatusUnauthorized)
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
// concurrently against the MFA-enrollment and user login limiters. This is
// the test that would have caught the v1.7.0 crash: the shared instance was
// already built once (shared across every request) but had no
// synchronization around its attempts map, so concurrent requests from
// different IPs hit "fatal error: concurrent map iteration and map write"
// in production. Must be run with -race to be meaningful.
func TestLoginRateLimiter_ConcurrentDistinctIPs_NoRace(t *testing.T) {
	tests := []struct {
		name  string
		build func(bool) func(http.Handler) http.Handler
	}{
		{"mfa enrollment", RateLimitMFAEnrollment},
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

// TestAttemptTracker_OverLimitDoesNotSlideWindow is a regression test for
// the MEDIUM finding (a regression vs. v1.7.1) that reserve() used to
// increment count and advance lastAttempt even for a rejected, over-limit
// attempt. Since the window-expiry check measures from lastAttempt, that
// let an attacker who keeps poking a locked key slide the window's start
// forward indefinitely - the lockout (and, transitively, a legitimate
// owner's own lockout once their real attempts started being rejected too)
// never actually expired as long as the attacker kept polling faster than
// the window. reserve() must leave count and lastAttempt untouched once a
// key is already over its limit.
func TestAttemptTracker_OverLimitDoesNotSlideWindow(t *testing.T) {
	tracker := newAttemptTracker(time.Hour) // window irrelevant here; not exercising expiry
	const key = "k"
	const maxAttempts = 3

	// Use up the budget.
	for i := 0; i < maxAttempts; i++ {
		if result, _ := tracker.reserve(key, maxAttempts); result != reserveAllowed {
			t.Fatalf("attempt %d: result = %v, want reserveAllowed", i+1, result)
		}
	}

	tracker.mu.Lock()
	wantCount := tracker.attempts[key].count
	wantLastAttempt := tracker.attempts[key].lastAttempt
	tracker.mu.Unlock()

	// Poke the locked key repeatedly - none of these may extend the window
	// or grow the count.
	for i := 0; i < 5; i++ {
		if result, _ := tracker.reserve(key, maxAttempts); result != reserveOverLimit {
			t.Fatalf("poke %d: result = %v, want reserveOverLimit", i+1, result)
		}
	}

	tracker.mu.Lock()
	gotCount := tracker.attempts[key].count
	gotLastAttempt := tracker.attempts[key].lastAttempt
	tracker.mu.Unlock()

	if gotCount != wantCount {
		t.Errorf("count = %d after over-limit pokes, want unchanged %d", gotCount, wantCount)
	}
	if !gotLastAttempt.Equal(wantLastAttempt) {
		t.Errorf("lastAttempt = %v after over-limit pokes, want unchanged %v (the window was extended)", gotLastAttempt, wantLastAttempt)
	}
}

// TestAttemptTracker_LockoutExpiresOneWindowAfterLastCountedAttempt proves
// the lockout actually ends: exactly `window` after the last COUNTED
// (reserveAllowed) attempt - not after the last request of any kind, and
// not extended by the over-limit pokes in between (see
// TestAttemptTracker_OverLimitDoesNotSlideWindow).
func TestAttemptTracker_LockoutExpiresOneWindowAfterLastCountedAttempt(t *testing.T) {
	const window = 80 * time.Millisecond
	tracker := newAttemptTracker(window)
	const key = "k"
	const maxAttempts = 2

	for i := 0; i < maxAttempts; i++ {
		if result, _ := tracker.reserve(key, maxAttempts); result != reserveAllowed {
			t.Fatalf("attempt %d: result = %v, want reserveAllowed", i+1, result)
		}
	}
	if result, _ := tracker.reserve(key, maxAttempts); result != reserveOverLimit {
		t.Fatal("expected reserveOverLimit immediately after using up the budget")
	}

	// Poke mid-window (must still be locked out) - these pokes must not
	// push the expiry out (see TestAttemptTracker_OverLimitDoesNotSlideWindow).
	time.Sleep(window / 2)
	if result, _ := tracker.reserve(key, maxAttempts); result != reserveOverLimit {
		t.Fatal("expected still locked out mid-window")
	}

	// Now past `window` since the LAST COUNTED attempt (not since the pokes
	// above, which never counted).
	time.Sleep(window/2 + 30*time.Millisecond)
	if result, _ := tracker.reserve(key, maxAttempts); result != reserveAllowed {
		t.Error("expected the lockout to have expired one window after the last counted attempt")
	}
}

// TestAttemptTracker_RefundAfterWindowResetIsNoop is a regression test for
// the refund-generation guard (code review finding): a refund must only
// apply if the window it was reserved in is still current. Without the
// epoch check, a refund arriving after the key's window has already reset
// (e.g. a very slow handler call spanning the reset) would decrement the
// NEW window's count, silently forgiving one of ITS real failures - a
// success from a stale, already-expired window reaching forward to erase a
// failure that has nothing to do with it.
func TestAttemptTracker_RefundAfterWindowResetIsNoop(t *testing.T) {
	const window = 60 * time.Millisecond
	tracker := newAttemptTracker(window)
	const key = "k"
	const maxAttempts = 3

	result, staleEpoch := tracker.reserve(key, maxAttempts)
	if result != reserveAllowed {
		t.Fatalf("first reserve: result = %v, want reserveAllowed", result)
	}

	// Let the window fully expire.
	time.Sleep(window + 30*time.Millisecond)

	// A new failure in the new window/epoch.
	result2, newEpoch := tracker.reserve(key, maxAttempts)
	if result2 != reserveAllowed {
		t.Fatalf("reserve in new window: result = %v, want reserveAllowed", result2)
	}
	if newEpoch == staleEpoch {
		t.Fatal("epoch did not advance across the window reset - the guard can't distinguish the two windows")
	}

	// A stale refund carrying the OLD epoch must be a no-op against the new
	// window's count.
	tracker.refund(key, staleEpoch)

	tracker.mu.Lock()
	count := tracker.attempts[key].count
	tracker.mu.Unlock()
	if count != 1 {
		t.Errorf("count = %d after a stale-epoch refund, want 1 (the refund must not have forgiven the new window's failure)", count)
	}

	// A refund with the CURRENT epoch must still work normally.
	tracker.refund(key, newEpoch)
	tracker.mu.Lock()
	count = tracker.attempts[key].count
	tracker.mu.Unlock()
	if count != 0 {
		t.Errorf("count = %d after a current-epoch refund, want 0", count)
	}
}

// TestAttemptTracker_RefundAfterSweepRecreateIsNoop covers the sweep path
// of the epoch guard: an entry deleted by the periodic sweep and later
// recreated must not reuse the epoch a refund from its previous life still
// carries.
func TestAttemptTracker_RefundAfterSweepRecreateIsNoop(t *testing.T) {
	const window = 15 * time.Minute
	tracker := newAttemptTracker(window)
	const key = "k"
	const maxAttempts = 5

	result, staleEpoch := tracker.reserve(key, maxAttempts)
	if result != reserveAllowed {
		t.Fatalf("first reserve: result = %v, want reserveAllowed", result)
	}

	// Age the entry past its window and make the next reserve run the
	// sweep, which deletes it before recreating it.
	tracker.mu.Lock()
	tracker.attempts[key].lastAttempt = time.Now().Add(-window - time.Minute)
	tracker.lastSweep = time.Now().Add(-2 * time.Minute)
	tracker.mu.Unlock()

	var newEpoch uint64
	for i := 0; i < maxAttempts; i++ {
		var res reserveResult
		res, newEpoch = tracker.reserve(key, maxAttempts)
		if res != reserveAllowed {
			t.Fatalf("reserve %d in new window: result = %v, want reserveAllowed", i+1, res)
		}
	}
	if newEpoch == staleEpoch {
		t.Fatal("recreated entry reused the stale epoch")
	}

	tracker.refund(key, staleEpoch)

	tracker.mu.Lock()
	count := tracker.attempts[key].count
	tracker.mu.Unlock()
	if count != maxAttempts {
		t.Errorf("count = %d after a stale refund on a recreated entry, want %d", count, maxAttempts)
	}
}

// TestLoginRateLimiter_SSOCallbackRedirectCountsAsSuccess is a regression
// test for RateLimitSSOCallback's success predicate. SSOCallbackHandler
// (internal/handlers/sso_auth.go) redirects with http.StatusFound for both
// success and failure - a failure redirects to "/login?error=<code>", a
// success redirects to the post-login destination - so this proves the
// limiter tells them apart by Location, not by status code.
func TestLoginRateLimiter_SSOCallbackRedirectCountsAsSuccess(t *testing.T) {
	// next simulates SSOCallbackHandler: redirect to /login?error=... on
	// failure, to the post-login destination on success.
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("outcome") == "fail" {
			http.Redirect(w, r, "/login?error=auth_failed", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})
	handler := RateLimitSSOCallback(false)(next)

	const ip = "203.0.113.50:1"

	// 5 failed callbacks reach the lockout threshold; the 6th is rejected.
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/okta/callback?outcome=fail", nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if i < 5 {
			if rr.Code != http.StatusFound {
				t.Fatalf("failed callback %d: status = %d, want %d", i+1, rr.Code, http.StatusFound)
			}
		} else if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("callback %d: status = %d, want %d (lockout should have triggered on repeated failures)", i+1, rr.Code, http.StatusTooManyRequests)
		}
	}

	// A fresh IP with successful callbacks must never be locked out, no
	// matter how many times it succeeds.
	const successIP = "203.0.113.51:1"
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/okta/callback", nil)
		req.RemoteAddr = successIP
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusFound {
			t.Fatalf("successful callback %d: status = %d, want %d (successes must never be locked out)", i+1, rr.Code, http.StatusFound)
		}
		if loc := rr.Header().Get("Location"); loc != "/dashboard" {
			t.Fatalf("successful callback %d: Location = %q, want /dashboard", i+1, loc)
		}
	}
}

// TestLoginRateLimiter_SSOInitiationCountsEveryRequest is a regression test
// for the bug-hunter finding that SSOLoginHandler always redirects with
// http.StatusFound to the IdP, so under the old shared-instance design
// (reusing the user-login limiter with the default 2xx/3xx success
// predicate) every initiation "succeeded" and reset the counter, making the
// limit disappear entirely and allowing unbounded SSO-state row inserts.
// RateLimitSSOInitiation counts every request, success or not.
func TestLoginRateLimiter_SSOInitiationCountsEveryRequest(t *testing.T) {
	handler := RateLimitSSOInitiation(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://idp.example.com/authorize", http.StatusFound)
	}))

	const ip = "203.0.113.60:1"

	// The configured limit is 20/15min; repeated "successful" (302)
	// initiations must still count and eventually lock out.
	for i := 0; i < 21; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/okta/login", nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if i < 20 {
			if rr.Code != http.StatusFound {
				t.Fatalf("initiation %d: status = %d, want %d", i+1, rr.Code, http.StatusFound)
			}
		} else if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("initiation %d: status = %d, want %d (every initiation should count, even this 302)", i+1, rr.Code, http.StatusTooManyRequests)
		}
	}
}
