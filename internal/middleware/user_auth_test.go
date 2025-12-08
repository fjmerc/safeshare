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

// TestUserAuth_ValidSession tests UserAuth middleware with valid session
func TestUserAuth_ValidSession(t *testing.T) {
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

	// Create session
	token := "valid-user-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repos.Users.CreateSession(ctx, user.ID, token, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	handler := UserAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that user is in context using typed key
		ctxUser := r.Context().Value(ContextKeyUser)
		if ctxUser == nil {
			t.Error("expected user in context")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestUserAuth_NoSession tests UserAuth middleware with no session cookie
func TestUserAuth_NoSession(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := UserAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test API request (no session)
	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("API request status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}

	// Test HTML request (should redirect)
	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	rr = httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("HTML request status = %d, want %d", rr.Code, http.StatusFound)
	}
	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("redirect location = %q, want %q", location, "/login")
	}
}

// TestUserAuth_InvalidSession tests UserAuth middleware with invalid session token
func TestUserAuth_InvalidSession(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := UserAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: "invalid-token"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// TestUserAuth_ExpiredSession tests UserAuth middleware with expired session
func TestUserAuth_ExpiredSession(t *testing.T) {
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

	// Create expired session
	token := "expired-user-session"
	expiresAt := time.Now().Add(-1 * time.Hour) // expired
	err = repos.Users.CreateSession(ctx, user.ID, token, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	handler := UserAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// TestUserAuth_InactiveUser tests UserAuth middleware with inactive user
func TestUserAuth_InactiveUser(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create inactive user
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "inactiveuser", "inactive@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Deactivate the user
	err = repos.Users.SetActive(ctx, user.ID, false)
	if err != nil {
		t.Fatalf("failed to deactivate user: %v", err)
	}

	// Create session
	token := "inactive-user-session"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repos.Users.CreateSession(ctx, user.ID, token, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	handler := UserAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test API request
	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	// Test HTML request (inactive users get 403 Forbidden, not redirect)
	// This is intentional security behavior - disabled accounts should not be redirected to login
	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "user_session", Value: token})
	rr = httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("HTML request status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// TestOptionalUserAuth_ValidSession tests OptionalUserAuth with valid session
func TestOptionalUserAuth_ValidSession(t *testing.T) {
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

	// Create session
	token := "valid-user-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repos.Users.CreateSession(ctx, user.ID, token, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	handler := OptionalUserAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that user is in context using typed key
		ctxUser := r.Context().Value(ContextKeyUser)
		if ctxUser == nil {
			t.Error("expected user in context")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestOptionalUserAuth_NoSession tests OptionalUserAuth without session (should continue)
func TestOptionalUserAuth_NoSession(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := OptionalUserAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// User should not be in context using typed key
		ctxUser := r.Context().Value(ContextKeyUser)
		if ctxUser != nil {
			t.Error("expected no user in context")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestOptionalUserAuth_InvalidSession tests OptionalUserAuth with invalid session (should continue)
func TestOptionalUserAuth_InvalidSession(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := OptionalUserAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// User should not be in context using typed key
		ctxUser := r.Context().Value(ContextKeyUser)
		if ctxUser != nil {
			t.Error("expected no user in context")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: "invalid-token"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestOptionalUserAuth_InactiveUser tests OptionalUserAuth with inactive user (should continue without user)
func TestOptionalUserAuth_InactiveUser(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create inactive user
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "inactiveuser", "inactive@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Deactivate the user
	err = repos.Users.SetActive(ctx, user.ID, false)
	if err != nil {
		t.Fatalf("failed to deactivate user: %v", err)
	}

	// Create session
	token := "inactive-user-session"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repos.Users.CreateSession(ctx, user.ID, token, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	handler := OptionalUserAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// User should not be in context (inactive) using typed key
		ctxUser := r.Context().Value(ContextKeyUser)
		if ctxUser != nil {
			t.Error("expected no user in context for inactive user")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestIsHTMLRequest tests the HTML request detection helper
func TestIsHTMLRequest(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		accept   string
		expected bool
	}{
		{
			name:     "HTML request to dashboard",
			path:     "/dashboard",
			accept:   "text/html,application/xhtml+xml",
			expected: true,
		},
		{
			name:     "API request",
			path:     "/api/user/files",
			accept:   "application/json",
			expected: false,
		},
		{
			name:     "API request with HTML accept",
			path:     "/api/auth/login",
			accept:   "text/html",
			expected: false,
		},
		{
			name:     "HTML request without accept header",
			path:     "/dashboard",
			accept:   "",
			expected: false,
		},
		{
			name:     "Root path with HTML accept",
			path:     "/",
			accept:   "text/html",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}

			result := isHTMLRequest(req)
			if result != tt.expected {
				t.Errorf("isHTMLRequest() = %v, want %v", result, tt.expected)
			}
		})
	}
}
