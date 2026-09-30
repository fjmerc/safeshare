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
