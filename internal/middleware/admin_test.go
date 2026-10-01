package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// TestAdminAuth_ValidSession tests AdminAuth middleware with valid admin session
func TestAdminAuth_ValidSession(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create admin session
	token := "test-admin-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repos.Admin.CreateSession(ctx, token, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	handler := AdminAuth(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest("GET", "/admin/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if rr.Body.String() != "success" {
		t.Errorf("body = %q, want %q", rr.Body.String(), "success")
	}
}

// TestAdminAuth_NoSession tests AdminAuth middleware with no session cookie
func TestAdminAuth_NoSession(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := AdminAuth(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test API request (no session)
	req := httptest.NewRequest("GET", "/admin/api/dashboard", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("API request status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}

	// Test HTML request (should redirect)
	req = httptest.NewRequest("GET", "/admin/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	rr = httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("HTML request status = %d, want %d", rr.Code, http.StatusFound)
	}
	location := rr.Header().Get("Location")
	if location != "/admin/login" {
		t.Errorf("redirect location = %q, want %q", location, "/admin/login")
	}
}

// TestAdminAuth_ExpiredSession tests AdminAuth middleware with expired session
func TestAdminAuth_ExpiredSession(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create expired session
	token := "expired-admin-session"
	expiresAt := time.Now().Add(-1 * time.Hour) // expired
	err = repos.Admin.CreateSession(ctx, token, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	handler := AdminAuth(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/api/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// TestAdminAuth_UserSessionWithAdminRole tests AdminAuth fallback to user session with admin role
func TestAdminAuth_UserSessionWithAdminRole(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create admin user
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	adminUser, err := repos.Users.Create(ctx, "admin@test.com", "admin@test.com", passwordHash, "admin", false)
	if err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}

	// Create user session
	token := "user-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repos.Users.CreateSession(ctx, adminUser.ID, token, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create user session: %v", err)
	}

	handler := AdminAuth(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest("GET", "/admin/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestAdminAuth_UserSessionWithoutAdminRole tests AdminAuth with non-admin user
func TestAdminAuth_UserSessionWithoutAdminRole(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create regular user (not admin)
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "user@test.com", "user@test.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create user session
	token := "user-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repos.Users.CreateSession(ctx, user.ID, token, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create user session: %v", err)
	}

	handler := AdminAuth(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test API request
	req := httptest.NewRequest("GET", "/admin/api/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	// Test HTML request (should redirect)
	req = httptest.NewRequest("GET", "/admin/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "user_session", Value: token})
	rr = httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("HTML request status = %d, want %d", rr.Code, http.StatusFound)
	}
}

// TestCSRFProtection_ValidToken tests CSRF protection with valid token
func TestCSRFProtection_ValidToken(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create admin session
	sessionToken := "admin-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repos.Admin.CreateSession(ctx, sessionToken, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	csrfToken := "test-csrf-token"

	handler := CSRFProtection(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest("POST", "/admin/api/files/delete", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: sessionToken})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	req.Header.Set("X-CSRF-Token", csrfToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestCSRFProtection_MissingToken tests CSRF protection with missing token
func TestCSRFProtection_MissingToken(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create admin session
	sessionToken := "admin-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repos.Admin.CreateSession(ctx, sessionToken, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	handler := CSRFProtection(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/admin/api/files/delete", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: sessionToken})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// TestCSRFProtection_TokenMismatch tests CSRF protection with mismatched tokens
func TestCSRFProtection_TokenMismatch(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create admin session
	sessionToken := "admin-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repos.Admin.CreateSession(ctx, sessionToken, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	handler := CSRFProtection(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/admin/api/files/delete", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: sessionToken})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "token-in-cookie"})
	req.Header.Set("X-CSRF-Token", "different-token-in-header")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// TestCSRFProtection_GetRequest tests CSRF protection doesn't block GET requests
func TestCSRFProtection_GetRequest(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := CSRFProtection(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest("GET", "/admin/dashboard", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestCSRFProtection_NoSession tests CSRF protection with no session
func TestCSRFProtection_NoSession(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := CSRFProtection(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/admin/api/files/delete", nil)
	req.Header.Set("X-CSRF-Token", "some-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// TestSetCSRFCookie tests CSRF cookie generation
func TestSetCSRFCookie(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)
	cfg.HTTPSEnabled = false

	rr := httptest.NewRecorder()

	token, err := SetCSRFCookie(rr, cfg)
	if err != nil {
		t.Fatalf("failed to set CSRF cookie: %v", err)
	}

	if token == "" {
		t.Error("expected non-empty token")
	}

	// Check cookie was set
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected cookie to be set")
	}

	cookie := cookies[0]
	if cookie.Name != "csrf_token" {
		t.Errorf("cookie name = %q, want %q", cookie.Name, "csrf_token")
	}
	if cookie.Value != token {
		t.Errorf("cookie value = %q, want %q", cookie.Value, token)
	}
	if cookie.HttpOnly {
		t.Error("csrf_token cookie should not be HttpOnly (JavaScript needs to read it)")
	}
	if cookie.Path != "/admin" {
		t.Errorf("cookie path = %q, want %q", cookie.Path, "/admin")
	}
}

// TestRateLimitAdminLogin_BelowLimit tests rate limiting when below threshold
func TestRateLimitAdminLogin_BelowLimit(t *testing.T) {
	handler := RateLimitAdminLogin(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	// Make 4 requests (below the 5 limit)
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest("POST", "/admin/api/login", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusOK)
		}
	}
}

// TestRateLimitAdminLogin_ExceedsLimit tests rate limiting when exceeding
// threshold. The handler returns 401 (not 200): only failures count toward
// the lockout now, so a handler that always "succeeds" could never trigger
// it - see TestRateLimitAdminLogin_SuccessNeverLocksOut for that case.
func TestRateLimitAdminLogin_ExceedsLimit(t *testing.T) {
	handler := RateLimitAdminLogin(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	// Make 6 requests (exceeds the 5 limit)
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("POST", "/admin/api/login", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if i < 5 {
			// First 5 should reach the handler (bad credentials)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusUnauthorized)
			}
		} else {
			// 6th request should be rate limited
			if rr.Code != http.StatusTooManyRequests {
				t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusTooManyRequests)
			}
		}
	}
}

// TestRateLimitAdminLogin_SuccessNeverLocksOut is a regression test for the
// login-lockout refinement (follow-up to hotfix v1.7.1): only failed
// attempts count toward the per-IP lockout. A client that logs in
// successfully every time - however many times - must never be locked out,
// which matters most on a shared-IP deployment (Tor hidden service,
// untrusted proxy, large NAT) where every visitor appears to share one IP.
func TestRateLimitAdminLogin_SuccessNeverLocksOut(t *testing.T) {
	handler := RateLimitAdminLogin(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("POST", "/admin/api/login", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d (successful logins must never be locked out)", i+1, rr.Code, http.StatusOK)
		}
	}
}

// TestRateLimitAdminLogin_DifferentIPs tests rate limiting with different IPs
func TestRateLimitAdminLogin_DifferentIPs(t *testing.T) {
	handler := RateLimitAdminLogin(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Each IP should have its own rate limit counter
	ips := []string{"192.168.1.1:1234", "192.168.1.2:1234", "192.168.1.3:1234"}

	for _, ip := range ips {
		for i := 0; i < 4; i++ {
			req := httptest.NewRequest("POST", "/admin/api/login", nil)
			req.RemoteAddr = ip
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("IP %s request %d: status = %d, want %d", ip, i+1, rr.Code, http.StatusOK)
			}
		}
	}
}

// TestRateLimitUserLogin_BelowLimit tests user login rate limiting when below threshold
func TestRateLimitUserLogin_BelowLimit(t *testing.T) {
	handler := RateLimitUserLogin(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	// Make 4 requests (below the 5 limit)
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = "192.168.1.100:5678"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusOK)
		}
	}
}

// TestRateLimitUserLogin_ExceedsLimit tests user login rate limiting when
// exceeding threshold. The handler returns 401 (not 200): only failures
// count toward the lockout now - see
// TestRateLimitUserLogin_SuccessNeverLocksOut for the success case.
func TestRateLimitUserLogin_ExceedsLimit(t *testing.T) {
	handler := RateLimitUserLogin(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	// Make 6 requests (exceeds the 5 limit)
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = "192.168.1.100:5678"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if i < 5 {
			// First 5 should reach the handler (bad credentials)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusUnauthorized)
			}
		} else {
			// 6th request should be rate limited
			if rr.Code != http.StatusTooManyRequests {
				t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusTooManyRequests)
			}
		}
	}
}

// TestRateLimitUserLogin_SuccessNeverLocksOut mirrors
// TestRateLimitAdminLogin_SuccessNeverLocksOut for the user login limiter.
func TestRateLimitUserLogin_SuccessNeverLocksOut(t *testing.T) {
	handler := RateLimitUserLogin(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = "192.168.1.100:5678"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d (successful logins must never be locked out)", i+1, rr.Code, http.StatusOK)
		}
	}
}

// TestSetUserCSRFCookie tests user CSRF cookie generation
func TestSetUserCSRFCookie(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)
	cfg.HTTPSEnabled = false

	rr := httptest.NewRecorder()

	token, err := SetUserCSRFCookie(rr, cfg)
	if err != nil {
		t.Fatalf("failed to set user CSRF cookie: %v", err)
	}

	if token == "" {
		t.Error("expected non-empty token")
	}

	// Check cookie was set
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected cookie to be set")
	}

	cookie := cookies[0]
	if cookie.Name != "user_csrf_token" {
		t.Errorf("cookie name = %q, want %q", cookie.Name, "user_csrf_token")
	}
	if cookie.Value != token {
		t.Errorf("cookie value = %q, want %q", cookie.Value, token)
	}
	if cookie.HttpOnly {
		t.Error("user_csrf_token cookie should not be HttpOnly (JavaScript needs to read it)")
	}
	if cookie.Path != "/" {
		t.Errorf("cookie path = %q, want %q", cookie.Path, "/")
	}
}

// TestSetUserCSRFCookie_HTTPS tests user CSRF cookie with HTTPS enabled
func TestSetUserCSRFCookie_HTTPS(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)
	cfg.HTTPSEnabled = true

	rr := httptest.NewRecorder()

	token, err := SetUserCSRFCookie(rr, cfg)
	if err != nil {
		t.Fatalf("failed to set user CSRF cookie: %v", err)
	}

	if token == "" {
		t.Error("expected non-empty token")
	}

	// Check cookie was set with Secure flag
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected cookie to be set")
	}

	cookie := cookies[0]
	if !cookie.Secure {
		t.Error("cookie should be Secure when HTTPS is enabled")
	}
}

// TestUserCSRFProtection_ValidToken tests user CSRF protection with valid token
func TestUserCSRFProtection_ValidToken(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create user
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create user session
	sessionToken := "user-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repos.Users.CreateSession(ctx, user.ID, sessionToken, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	csrfToken := "test-user-csrf-token"

	handler := UserCSRFProtection(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest("POST", "/api/user/files/delete", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: sessionToken})
	req.AddCookie(&http.Cookie{Name: "user_csrf_token", Value: csrfToken})
	req.Header.Set("X-CSRF-Token", csrfToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestUserCSRFProtection_MissingToken tests user CSRF protection with missing token
func TestUserCSRFProtection_MissingToken(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create user
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create user session
	sessionToken := "user-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repos.Users.CreateSession(ctx, user.ID, sessionToken, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	handler := UserCSRFProtection(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/user/files/delete", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: sessionToken})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// TestUserCSRFProtection_TokenMismatch tests user CSRF protection with mismatched tokens
func TestUserCSRFProtection_TokenMismatch(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create user
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create user session
	sessionToken := "user-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repos.Users.CreateSession(ctx, user.ID, sessionToken, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	handler := UserCSRFProtection(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/user/files/delete", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: sessionToken})
	req.AddCookie(&http.Cookie{Name: "user_csrf_token", Value: "token-in-cookie"})
	req.Header.Set("X-CSRF-Token", "different-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// TestUserCSRFProtection_NoSession tests user CSRF protection with no session
func TestUserCSRFProtection_NoSession(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := UserCSRFProtection(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/user/files/delete", nil)
	req.Header.Set("X-CSRF-Token", "some-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// TestUserCSRFProtection_GetRequest tests user CSRF protection doesn't block GET requests
func TestUserCSRFProtection_GetRequest(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := UserCSRFProtection(repos, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest("GET", "/api/user/files", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestRateLimitMFAEnrollment_BelowLimit tests the authenticated MFA
// enrollment limiter (TOTP verify-and-enable / disable) when below
// threshold. No user is in context in these bare-handler tests, so it
// falls back to the per-IP key (see mfaEnrollmentKey).
func TestRateLimitMFAEnrollment_BelowLimit(t *testing.T) {
	handler := RateLimitMFAEnrollment(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	// Make 4 requests (below the 5 limit)
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest("POST", "/api/user/mfa/totp/verify", nil)
		req.RemoteAddr = "192.168.1.50:1234"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusOK)
		}
	}
}

// TestRateLimitMFAEnrollment_ExceedsLimit tests the limiter when exceeding
// threshold. The handler returns 401 (not 200): only failures count toward
// the lockout - see TestRateLimitMFAEnrollment_SuccessNeverLocksOut for the
// success case.
func TestRateLimitMFAEnrollment_ExceedsLimit(t *testing.T) {
	handler := RateLimitMFAEnrollment(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	// Make 6 requests (exceeds the 5 limit)
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("POST", "/api/user/mfa/totp/verify", nil)
		req.RemoteAddr = "192.168.1.51:1234"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if i < 5 {
			// First 5 should reach the handler (bad code)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusUnauthorized)
			}
		} else {
			// 6th request should be rate limited
			if rr.Code != http.StatusTooManyRequests {
				t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusTooManyRequests)
			}
		}
	}
}

// TestRateLimitMFAEnrollment_SuccessNeverLocksOut mirrors
// TestRateLimitAdminLogin_SuccessNeverLocksOut for the MFA enrollment
// limiter.
func TestRateLimitMFAEnrollment_SuccessNeverLocksOut(t *testing.T) {
	handler := RateLimitMFAEnrollment(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("POST", "/api/user/mfa/totp/verify", nil)
		req.RemoteAddr = "192.168.1.51:1234"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d (successful verifications must never be locked out)", i+1, rr.Code, http.StatusOK)
		}
	}
}

// TestRateLimitMFAEnrollment_DifferentIPs tests the limiter with different IPs
func TestRateLimitMFAEnrollment_DifferentIPs(t *testing.T) {
	handler := RateLimitMFAEnrollment(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Each IP should have its own rate limit counter
	ips := []string{"192.168.2.1:1234", "192.168.2.2:1234", "192.168.2.3:1234"}

	for _, ip := range ips {
		for i := 0; i < 4; i++ {
			req := httptest.NewRequest("POST", "/api/user/mfa/totp/verify", nil)
			req.RemoteAddr = ip
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("IP %s request %d: status = %d, want %d", ip, i+1, rr.Code, http.StatusOK)
			}
		}
	}
}

// TestRateLimitMFAEnrollment_KeyedByUserID proves that when a user is
// present in context (the normal case - these routes always run behind
// UserAuth), the limiter keys by user ID rather than IP: two different
// users sharing one IP get independent budgets, and the same user seen
// from two different IPs shares one budget.
func TestRateLimitMFAEnrollment_KeyedByUserID(t *testing.T) {
	handler := RateLimitMFAEnrollment(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	withUser := func(id int64, remoteAddr string) *http.Request {
		req := httptest.NewRequest("POST", "/api/user/mfa/totp/verify", nil)
		req.RemoteAddr = remoteAddr
		ctx := context.WithValue(req.Context(), ContextKeyUser, &models.User{ID: id})
		return req.WithContext(ctx)
	}

	// User 1 exhausts their own budget (5) from one IP.
	const sharedIP = "192.168.3.1:1234"
	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, withUser(1, sharedIP))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("user 1 attempt %d: status = %d, want %d", i+1, rr.Code, http.StatusUnauthorized)
		}
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, withUser(1, sharedIP))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("user 1's 6th attempt: status = %d, want %d (should be locked out)", rr.Code, http.StatusTooManyRequests)
	}

	// User 2, sharing the exact same IP, must be unaffected.
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, withUser(2, sharedIP))
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("user 2 (different user, same IP): status = %d, want %d (own budget, not locked out)", rr2.Code, http.StatusUnauthorized)
	}

	// User 1, now from a different IP, is still locked out - the budget
	// follows the user ID, not the IP.
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, withUser(1, "192.168.3.99:1234"))
	if rr3.Code != http.StatusTooManyRequests {
		t.Fatalf("user 1 from a different IP: status = %d, want %d (budget should follow the user, not the IP)", rr3.Code, http.StatusTooManyRequests)
	}
}

// TestMFALoginLimiter_SharedBudgetAcrossRoutes proves /api/auth/mfa/verify
// and webauthn/finish - both wrapped with DefaultLoginSuccess - draw from
// the same shared per-IP budget when built from one MFALoginLimiter,
// matching the pre-refactor design (a single totpRateLimit instance
// covered both), so an attacker can't multiply their effective attempt
// budget by switching between them.
func TestMFALoginLimiter_SharedBudgetAcrossRoutes(t *testing.T) {
	limiter := NewMFALoginLimiter(false)
	verify := limiter.Wrap("MFA login verification", DefaultLoginSuccess)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	finish := limiter.Wrap("WebAuthn login finish", DefaultLoginSuccess)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	const ip = "192.168.4.1:1234"

	// 3 failures via verify, 2 via finish - 5 total, still under the limit.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/api/auth/mfa/verify", nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		verify.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("verify failure %d: status = %d, want %d", i+1, rr.Code, http.StatusUnauthorized)
		}
	}
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/api/auth/mfa/webauthn/finish", nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		finish.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("finish failure %d: status = %d, want %d", i+1, rr.Code, http.StatusUnauthorized)
		}
	}

	// The 6th failure overall, on either route, should now be locked out.
	req := httptest.NewRequest("POST", "/api/auth/mfa/verify", nil)
	req.RemoteAddr = ip
	rr := httptest.NewRecorder()
	verify.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("6th failure (shared budget across routes): status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}
}

// TestMFALoginLimiter_WebAuthnBeginNeverMasksVerifyFailures is a regression
// test for the bug-hunter finding that a shared totpRateLimit instance let
// webauthn/begin - which always used to return 200 and reset the whole
// group's counter - erase real /mfa/verify failures, making TOTP brute
// force practical. webauthn/begin is now wrapped with AlwaysRefund, so it
// never adds to or subtracts from the group's failure count beyond its own
// reservation. Interleaving failed verify attempts with begin calls must
// still eventually lock out the shared budget.
func TestMFALoginLimiter_WebAuthnBeginNeverMasksVerifyFailures(t *testing.T) {
	limiter := NewMFALoginLimiter(false)
	verify := limiter.Wrap("MFA login verification", DefaultLoginSuccess)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // simulate a wrong TOTP code
	}))
	begin := limiter.Wrap("WebAuthn login begin", AlwaysRefund)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // begin "succeeds" trivially - it only issues a challenge
	}))

	const ip = "192.168.5.1:1234"

	locked := false
	for i := 0; i < 20 && !locked; i++ {
		req := httptest.NewRequest("POST", "/api/auth/mfa/verify", nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		verify.ServeHTTP(rr, req)
		if rr.Code == http.StatusTooManyRequests {
			locked = true
			break
		}
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("verify call %d: unexpected status %d", i, rr.Code)
		}

		req2 := httptest.NewRequest("POST", "/api/auth/mfa/webauthn/begin", nil)
		req2.RemoteAddr = ip
		rr2 := httptest.NewRecorder()
		begin.ServeHTTP(rr2, req2)
		if rr2.Code == http.StatusTooManyRequests {
			locked = true
			break
		}
		if rr2.Code != http.StatusOK {
			t.Fatalf("begin call %d: unexpected status %d", i, rr2.Code)
		}
	}

	if !locked {
		t.Fatal("interleaving failed /mfa/verify attempts with neutral webauthn/begin calls never triggered the shared lockout - begin is masking verify's failures")
	}
}

// TestIsAdminHTMLRequest tests the admin HTML request detection helper
func TestIsAdminHTMLRequest(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		accept   string
		expected bool
	}{
		{
			name:     "HTML request to dashboard",
			path:     "/admin/dashboard",
			accept:   "text/html,application/xhtml+xml",
			expected: true,
		},
		{
			name:     "API request",
			path:     "/admin/api/dashboard",
			accept:   "application/json",
			expected: false,
		},
		{
			name:     "API request with HTML accept",
			path:     "/admin/api/login",
			accept:   "text/html",
			expected: false,
		},
		{
			name:     "HTML request without accept header",
			path:     "/admin/dashboard",
			accept:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}

			result := isAdminHTMLRequest(req)
			if result != tt.expected {
				t.Errorf("isAdminHTMLRequest() = %v, want %v", result, tt.expected)
			}
		})
	}
}
