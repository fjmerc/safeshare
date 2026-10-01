package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// TestRegisterUserLoginRoute_LocksOutAfterFiveAttempts is a regression test
// for the v1.7.1 hotfix: middleware.RateLimitUserLogin was previously
// constructed inside the /api/auth/login handler closure, so every request
// got a brand new, empty attempts map and the lockout never engaged. This
// test drives the real wiring used by main() (registerUserLoginRoute) with
// six bad logins from the same IP and asserts the 6th is rejected with 429.
func TestRegisterUserLoginRoute_LocksOutAfterFiveAttempts(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	passwordHash, err := utils.HashPassword("correct-password")
	testutil.AssertNoError(t, err)
	if _, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	mux := http.NewServeMux()
	registerUserLoginRoute(mux, repos, cfg, false)

	loginReq := models.UserLoginRequest{Username: "testuser", Password: "wrong-password"}
	body, err := json.Marshal(loginReq)
	testutil.AssertNoError(t, err)

	for i := 1; i <= 6; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.7:5555"
		rr := httptest.NewRecorder()

		mux.ServeHTTP(rr, req)

		switch {
		case i < 6 && rr.Code != http.StatusUnauthorized:
			t.Fatalf("attempt %d: status = %d, want %d (bad credentials)", i, rr.Code, http.StatusUnauthorized)
		case i == 6 && rr.Code != http.StatusTooManyRequests:
			t.Fatalf("attempt %d: status = %d, want %d (lockout should have triggered)", i, rr.Code, http.StatusTooManyRequests)
		}
	}
}

// TestRegisterUserLoginRoute_MFABranchSharesLimiter proves the MFA and
// non-MFA branches of /api/auth/login share one limiter instance, so an
// attacker cannot dodge the lockout by flipping cfg.MFA between requests.
func TestRegisterUserLoginRoute_MFABranchSharesLimiter(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	passwordHash, err := utils.HashPassword("correct-password")
	testutil.AssertNoError(t, err)
	if _, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	mux := http.NewServeMux()
	registerUserLoginRoute(mux, repos, cfg, false)

	loginReq := models.UserLoginRequest{Username: "testuser", Password: "wrong-password"}
	body, err := json.Marshal(loginReq)
	testutil.AssertNoError(t, err)

	// First 3 attempts hit the non-MFA branch, then MFA is enabled and the
	// remaining attempts hit the MFA branch. The 6th attempt overall must
	// still be locked out.
	for i := 1; i <= 6; i++ {
		if i == 4 {
			cfg.MFA = &config.MFAConfig{Enabled: true}
		}

		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.8:5556"
		rr := httptest.NewRecorder()

		mux.ServeHTTP(rr, req)

		switch {
		case i < 6 && rr.Code != http.StatusUnauthorized:
			t.Fatalf("attempt %d: status = %d, want %d (bad credentials)", i, rr.Code, http.StatusUnauthorized)
		case i == 6 && rr.Code != http.StatusTooManyRequests:
			t.Fatalf("attempt %d: status = %d, want %d (lockout should have triggered across branches)", i, rr.Code, http.StatusTooManyRequests)
		}
	}
}

// TestRegisterUserLoginRoute_SuccessRefundsOnlyOneAttempt is a regression
// test for the login-lockout refinement (follow-up to hotfix v1.7.1 /
// audit finding T45). An earlier version of this fix reset the whole
// per-IP counter to zero on any success; code review and a security audit
// found that let an attacker who already controls one account interleave
// failed guesses at a victim with logins to their own account, wiping out
// the failed-guess count for free every time and defeating the lockout
// entirely (see TestRegisterUserLoginRoute_OwnAccountInterleaveStillLocksOut
// for that exact scenario). The fix is refund-only: a success reserves its
// own attempt (count 4->5, still within the 5-attempt limit) and then
// refunds that same reservation (count 5->4) - net zero, leaving the four
// real failures' contribution untouched. So exactly ONE more failure is
// admitted after the success (count 4->5, still <=5) before the next one
// is locked out (count 5->6) - not four, which a full reset would have
// allowed.
func TestRegisterUserLoginRoute_SuccessRefundsOnlyOneAttempt(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	passwordHash, err := utils.HashPassword("correct-password")
	testutil.AssertNoError(t, err)
	if _, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	mux := http.NewServeMux()
	registerUserLoginRoute(mux, repos, cfg, false)

	postLogin := func(password string) int {
		loginReq := models.UserLoginRequest{Username: "testuser", Password: password}
		body, err := json.Marshal(loginReq)
		testutil.AssertNoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.20:5555"
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code
	}

	for i := 1; i <= 4; i++ {
		if code := postLogin("wrong-password"); code != http.StatusUnauthorized {
			t.Fatalf("pre-success failure %d: status = %d, want %d", i, code, http.StatusUnauthorized)
		}
	}

	if code := postLogin("correct-password"); code != http.StatusOK {
		t.Fatalf("successful login: status = %d, want %d", code, http.StatusOK)
	}

	if code := postLogin("wrong-password"); code != http.StatusUnauthorized {
		t.Fatalf("post-success failure 1: status = %d, want %d (the success's own reservation nets to zero, leaving room for exactly one more failure)", code, http.StatusUnauthorized)
	}

	if code := postLogin("wrong-password"); code != http.StatusTooManyRequests {
		t.Fatalf("post-success failure 2: status = %d, want %d (the success refunded only its own one attempt, not the whole counter - this one should now be locked out)", code, http.StatusTooManyRequests)
	}
}

// TestRegisterUserLoginRoute_OwnAccountInterleaveStillLocksOut is a
// regression test for the HIGH-severity finding from code review and the
// security audit: with a full reset-on-success design, an attacker who
// already controls one valid account (here, "attacker") could interleave
// failed guesses at a victim's username with successful logins to their
// own account. Every attacker login reset the shared per-IP counter to
// zero, wiping out the victim-guess failures for free - the lockout never
// engaged regardless of how many wrong guesses were made, an effectively
// unlimited brute force. With the refund-only fix, each attacker login
// only cancels its own one reservation, so the victim-guess failures
// accumulate net gains every cycle and the per-IP lockout still triggers.
func TestRegisterUserLoginRoute_OwnAccountInterleaveStillLocksOut(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	victimHash, err := utils.HashPassword("victim-password")
	testutil.AssertNoError(t, err)
	if _, err := repos.Users.Create(ctx, "victim", "victim@example.com", victimHash, "user", false); err != nil {
		t.Fatalf("failed to create victim: %v", err)
	}

	attackerHash, err := utils.HashPassword("attacker-password")
	testutil.AssertNoError(t, err)
	if _, err := repos.Users.Create(ctx, "attacker", "attacker@example.com", attackerHash, "user", false); err != nil {
		t.Fatalf("failed to create attacker: %v", err)
	}

	mux := http.NewServeMux()
	registerUserLoginRoute(mux, repos, cfg, false)

	post := func(username, password string) int {
		loginReq := models.UserLoginRequest{Username: username, Password: password}
		body, err := json.Marshal(loginReq)
		testutil.AssertNoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.30:7777"
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code
	}

	locked := false
	for cycle := 0; cycle < 10 && !locked; cycle++ {
		for i := 0; i < 4; i++ {
			if code := post("victim", "wrong-guess"); code == http.StatusTooManyRequests {
				locked = true
				break
			}
		}
		if locked {
			break
		}
		if code := post("attacker", "attacker-password"); code != http.StatusOK {
			t.Fatalf("cycle %d: attacker's own correct login: status = %d, want %d", cycle, code, http.StatusOK)
		}
	}

	if !locked {
		t.Fatal("interleaving failed victim guesses with the attacker's own successful logins never triggered the per-IP lockout - the refund-only fix did not take effect")
	}
}

// TestRegisterAdminLoginRoute_LocksOutAfterFiveAttempts is the admin-login
// counterpart of TestRegisterUserLoginRoute_LocksOutAfterFiveAttempts.
func TestRegisterAdminLoginRoute_LocksOutAfterFiveAttempts(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	if err := repos.Admin.InitializeCredentials(ctx, "admin", "correct-password"); err != nil {
		t.Fatalf("failed to initialize admin credentials: %v", err)
	}

	mux := http.NewServeMux()
	registerAdminLoginRoute(mux, repos, cfg, false)

	loginReq := map[string]string{"username": "admin", "password": "wrong-password"}
	body, err := json.Marshal(loginReq)
	testutil.AssertNoError(t, err)

	for i := 1; i <= 6; i++ {
		req := httptest.NewRequest(http.MethodPost, "/admin/api/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.9:6666"
		rr := httptest.NewRecorder()

		mux.ServeHTTP(rr, req)

		switch {
		case i < 6 && rr.Code != http.StatusUnauthorized:
			t.Fatalf("attempt %d: status = %d, want %d (bad credentials)", i, rr.Code, http.StatusUnauthorized)
		case i == 6 && rr.Code != http.StatusTooManyRequests:
			t.Fatalf("attempt %d: status = %d, want %d (lockout should have triggered)", i, rr.Code, http.StatusTooManyRequests)
		}
	}
}

