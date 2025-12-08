package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

	handler := AdminAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	handler := AdminAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	handler := AdminAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	handler := AdminAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	handler := AdminAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	handler := CSRFProtection(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	handler := CSRFProtection(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	handler := CSRFProtection(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	handler := CSRFProtection(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	handler := CSRFProtection(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	handler := RateLimitAdminLogin()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// TestRateLimitAdminLogin_ExceedsLimit tests rate limiting when exceeding threshold
func TestRateLimitAdminLogin_ExceedsLimit(t *testing.T) {
	handler := RateLimitAdminLogin()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 6 requests (exceeds the 5 limit)
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("POST", "/admin/api/login", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if i < 5 {
			// First 5 should succeed
			if rr.Code != http.StatusOK {
				t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusOK)
			}
		} else {
			// 6th request should be rate limited
			if rr.Code != http.StatusTooManyRequests {
				t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusTooManyRequests)
			}
		}
	}
}

// TestRateLimitAdminLogin_DifferentIPs tests rate limiting with different IPs
func TestRateLimitAdminLogin_DifferentIPs(t *testing.T) {
	handler := RateLimitAdminLogin()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	handler := RateLimitUserLogin()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// TestRateLimitUserLogin_ExceedsLimit tests user login rate limiting when exceeding threshold
func TestRateLimitUserLogin_ExceedsLimit(t *testing.T) {
	handler := RateLimitUserLogin()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 6 requests (exceeds the 5 limit)
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = "192.168.1.100:5678"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if i < 5 {
			// First 5 should succeed
			if rr.Code != http.StatusOK {
				t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusOK)
			}
		} else {
			// 6th request should be rate limited
			if rr.Code != http.StatusTooManyRequests {
				t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusTooManyRequests)
			}
		}
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
