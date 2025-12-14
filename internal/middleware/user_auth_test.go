package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
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

// =============================================================================
// Token Expiration Warning Header Tests (Task 3.3.7)
// =============================================================================

// createTestAPIToken creates an API token for testing with the given expiration
func createTestAPIToken(t *testing.T, repos *repository.Repositories, userID int64, expiresAt *time.Time) (string, string) {
	t.Helper()
	ctx := context.Background()

	// Generate a valid token using the official utility function
	tokenPlaintext, tokenPrefix, err := utils.GenerateAPIToken()
	if err != nil {
		t.Fatalf("failed to generate API token: %v", err)
	}
	tokenHash := utils.HashAPIToken(tokenPlaintext)

	_, err = repos.APITokens.Create(ctx, userID, "test-token", tokenHash, tokenPrefix, "files:read", "127.0.0.1", expiresAt)
	if err != nil {
		t.Fatalf("failed to create API token: %v", err)
	}

	return tokenPlaintext, tokenHash
}

// TestUserAuth_APIToken_ExpirationHeaders tests that expiration warning headers are added for API tokens
func TestUserAuth_APIToken_ExpirationHeaders(t *testing.T) {
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

	// Token that expires in 30 days (not soon)
	expiresIn30Days := time.Now().Add(30 * 24 * time.Hour)
	tokenNotSoon, _ := createTestAPIToken(t, repos, user.ID, &expiresIn30Days)

	// Token that expires in 3 days (soon - within 7 day threshold)
	expiresIn3Days := time.Now().Add(3 * 24 * time.Hour)
	tokenSoon, _ := createTestAPIToken(t, repos, user.ID, &expiresIn3Days)

	// Token that never expires
	tokenNoExpiry, _ := createTestAPIToken(t, repos, user.ID, nil)

	tests := []struct {
		name               string
		token              string
		wantExpiresAt      bool
		wantExpiresSoon    bool
		expectedExpiration *time.Time
	}{
		{
			name:               "token expires in 30 days - not soon",
			token:              tokenNotSoon,
			wantExpiresAt:      true,
			wantExpiresSoon:    false,
			expectedExpiration: &expiresIn30Days,
		},
		{
			name:               "token expires in 3 days - soon",
			token:              tokenSoon,
			wantExpiresAt:      true,
			wantExpiresSoon:    true,
			expectedExpiration: &expiresIn3Days,
		},
		{
			name:               "token never expires - no headers",
			token:              tokenNoExpiry,
			wantExpiresAt:      false,
			wantExpiresSoon:    false,
			expectedExpiration: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := UserAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
			}

			// Check X-Token-Expires-At header
			expiresAtHeader := rr.Header().Get(HeaderTokenExpiresAt)
			if tt.wantExpiresAt {
				if expiresAtHeader == "" {
					t.Error("expected X-Token-Expires-At header, got empty")
				} else {
					// Parse and compare (allow some tolerance)
					parsedTime, err := time.Parse(time.RFC3339, expiresAtHeader)
					if err != nil {
						t.Errorf("failed to parse X-Token-Expires-At header: %v", err)
					} else {
						// Allow 1 second tolerance for time comparison
						diff := parsedTime.Sub(*tt.expectedExpiration)
						if diff < -time.Second || diff > time.Second {
							t.Errorf("X-Token-Expires-At = %v, want ~%v", parsedTime, *tt.expectedExpiration)
						}
					}
				}
			} else {
				if expiresAtHeader != "" {
					t.Errorf("expected no X-Token-Expires-At header, got %q", expiresAtHeader)
				}
			}

			// Check X-Token-Expires-Soon header
			expiresSoonHeader := rr.Header().Get(HeaderTokenExpiresSoon)
			if tt.wantExpiresSoon {
				if expiresSoonHeader != "true" {
					t.Errorf("X-Token-Expires-Soon = %q, want %q", expiresSoonHeader, "true")
				}
			} else {
				if expiresSoonHeader != "" {
					t.Errorf("expected no X-Token-Expires-Soon header, got %q", expiresSoonHeader)
				}
			}
		})
	}
}

// TestOptionalUserAuth_APIToken_ExpirationHeaders tests expiration headers with OptionalUserAuth
func TestOptionalUserAuth_APIToken_ExpirationHeaders(t *testing.T) {
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

	// Token that expires in 5 days (within 7 day threshold - "expires soon")
	expiresIn5Days := time.Now().Add(5 * 24 * time.Hour)
	tokenSoon, _ := createTestAPIToken(t, repos, user.ID, &expiresIn5Days)

	handler := OptionalUserAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.Header.Set("Authorization", "Bearer "+tokenSoon)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Should have expiration header
	expiresAtHeader := rr.Header().Get(HeaderTokenExpiresAt)
	if expiresAtHeader == "" {
		t.Error("expected X-Token-Expires-At header")
	}

	// Should have expires-soon header (within 7 days)
	expiresSoonHeader := rr.Header().Get(HeaderTokenExpiresSoon)
	if expiresSoonHeader != "true" {
		t.Errorf("X-Token-Expires-Soon = %q, want %q", expiresSoonHeader, "true")
	}
}

// TestUserAuth_APIToken_ExpirationThreshold tests the exact boundary of the 7-day threshold
func TestUserAuth_APIToken_ExpirationThreshold(t *testing.T) {
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

	// Note: Adding 1 minute buffer to "exactly 7 days" test to account for test execution time.
	// The implementation uses time.Until() which recalculates at check time, so a token
	// created with 7 days exactly will be slightly less than 7 days by the time we check.
	tests := []struct {
		name            string
		expiresIn       time.Duration
		wantExpiresSoon bool
	}{
		{
			name:            "7 days plus buffer - not soon",
			expiresIn:       7*24*time.Hour + time.Minute, // Add buffer for test execution time
			wantExpiresSoon: false,                       // >= 7 days is not "soon"
		},
		{
			name:            "6 days 23 hours - soon",
			expiresIn:       6*24*time.Hour + 23*time.Hour,
			wantExpiresSoon: true, // < 7 days is "soon"
		},
		{
			name:            "1 hour - soon",
			expiresIn:       1 * time.Hour,
			wantExpiresSoon: true,
		},
		{
			name:            "8 days - not soon",
			expiresIn:       8 * 24 * time.Hour,
			wantExpiresSoon: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiresAt := time.Now().Add(tt.expiresIn)
			token, _ := createTestAPIToken(t, repos, user.ID, &expiresAt)

			handler := UserAuth(repos)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
			}

			// All tokens with expiration should have X-Token-Expires-At
			expiresAtHeader := rr.Header().Get(HeaderTokenExpiresAt)
			if expiresAtHeader == "" {
				t.Error("expected X-Token-Expires-At header")
			}

			// Check X-Token-Expires-Soon header
			expiresSoonHeader := rr.Header().Get(HeaderTokenExpiresSoon)
			if tt.wantExpiresSoon {
				if expiresSoonHeader != "true" {
					t.Errorf("X-Token-Expires-Soon = %q, want %q", expiresSoonHeader, "true")
				}
			} else {
				if expiresSoonHeader != "" {
					t.Errorf("expected no X-Token-Expires-Soon header, got %q", expiresSoonHeader)
				}
			}
		})
	}
}

// TestUserAuth_SessionAuth_NoExpirationHeaders tests that session auth doesn't add token expiration headers
func TestUserAuth_SessionAuth_NoExpirationHeaders(t *testing.T) {
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
	token := "valid-session-token-for-headers-test"
	expiresAt := time.Now().Add(24 * time.Hour)
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

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Session auth should NOT have token expiration headers
	expiresAtHeader := rr.Header().Get(HeaderTokenExpiresAt)
	if expiresAtHeader != "" {
		t.Errorf("expected no X-Token-Expires-At header for session auth, got %q", expiresAtHeader)
	}

	expiresSoonHeader := rr.Header().Get(HeaderTokenExpiresSoon)
	if expiresSoonHeader != "" {
		t.Errorf("expected no X-Token-Expires-Soon header for session auth, got %q", expiresSoonHeader)
	}
}

// TestAddTokenExpirationHeaders_Unit tests the addTokenExpirationHeaders function directly
func TestAddTokenExpirationHeaders_Unit(t *testing.T) {
	tests := []struct {
		name            string
		expiresAt       *time.Time
		wantExpiresAt   bool
		wantExpiresSoon bool
	}{
		{
			name:            "nil expiration",
			expiresAt:       nil,
			wantExpiresAt:   false,
			wantExpiresSoon: false,
		},
		{
			name:            "expiration far in future",
			expiresAt:       func() *time.Time { t := time.Now().Add(30 * 24 * time.Hour); return &t }(),
			wantExpiresAt:   true,
			wantExpiresSoon: false,
		},
		{
			name:            "expiration within 7 days",
			expiresAt:       func() *time.Time { t := time.Now().Add(3 * 24 * time.Hour); return &t }(),
			wantExpiresAt:   true,
			wantExpiresSoon: true,
		},
		{
			name:            "expiration in 1 hour",
			expiresAt:       func() *time.Time { t := time.Now().Add(1 * time.Hour); return &t }(),
			wantExpiresAt:   true,
			wantExpiresSoon: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create context with expiration
			ctx := context.Background()
			if tt.expiresAt != nil {
				ctx = context.WithValue(ctx, ContextKeyTokenExpiresAt, tt.expiresAt)
			}

			rr := httptest.NewRecorder()
			addTokenExpirationHeaders(rr, ctx)

			// Check X-Token-Expires-At header
			expiresAtHeader := rr.Header().Get(HeaderTokenExpiresAt)
			if tt.wantExpiresAt {
				if expiresAtHeader == "" {
					t.Error("expected X-Token-Expires-At header")
				}
			} else {
				if expiresAtHeader != "" {
					t.Errorf("expected no X-Token-Expires-At header, got %q", expiresAtHeader)
				}
			}

			// Check X-Token-Expires-Soon header
			expiresSoonHeader := rr.Header().Get(HeaderTokenExpiresSoon)
			if tt.wantExpiresSoon {
				if expiresSoonHeader != "true" {
					t.Errorf("X-Token-Expires-Soon = %q, want %q", expiresSoonHeader, "true")
				}
			} else {
				if expiresSoonHeader != "" {
					t.Errorf("expected no X-Token-Expires-Soon header, got %q", expiresSoonHeader)
				}
			}
		})
	}
}

// TestRequireScope_SessionAuth tests that session auth bypasses scope checks
func TestRequireScope_SessionAuth(t *testing.T) {
	handler := RequireScope("files:write")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	// Create request with session auth type
	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	ctx := context.WithValue(req.Context(), ContextKeyAuthType, AuthTypeSession)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (session auth should bypass scope)", rr.Code, http.StatusOK)
	}
}

// TestRequireScope_APIToken_HasScope tests API token with required scope
func TestRequireScope_APIToken_HasScope(t *testing.T) {
	handler := RequireScope("files:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	ctx := context.WithValue(req.Context(), ContextKeyAuthType, AuthTypeAPIToken)
	ctx = context.WithValue(ctx, ContextKeyTokenScopes, "files:read,files:write")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (token has required scope)", rr.Code, http.StatusOK)
	}
}

// TestRequireScope_APIToken_MissingScope tests API token without required scope
func TestRequireScope_APIToken_MissingScope(t *testing.T) {
	handler := RequireScope("files:write")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	ctx := context.WithValue(req.Context(), ContextKeyAuthType, AuthTypeAPIToken)
	ctx = context.WithValue(ctx, ContextKeyTokenScopes, "files:read") // Only has read, not write
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (token missing required scope)", rr.Code, http.StatusForbidden)
	}
}

// TestRequireScope_NoAuthType tests when no auth type is set
func TestRequireScope_NoAuthType(t *testing.T) {
	handler := RequireScope("files:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (no auth type)", rr.Code, http.StatusUnauthorized)
	}
}

// TestRequireScope_APIToken_NoScopes tests API token auth with no scopes in context
func TestRequireScope_APIToken_NoScopes(t *testing.T) {
	handler := RequireScope("files:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	ctx := context.WithValue(req.Context(), ContextKeyAuthType, AuthTypeAPIToken)
	// Note: No scopes set in context
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d (no scopes in context)", rr.Code, http.StatusInternalServerError)
	}
}

// TestGetUserFromContext tests the context helper function
func TestGetUserFromContext(t *testing.T) {
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

	tests := []struct {
		name     string
		setup    func(r *http.Request) *http.Request
		wantNil  bool
		wantUser string
	}{
		{
			name: "user in context",
			setup: func(r *http.Request) *http.Request {
				ctx := context.WithValue(r.Context(), ContextKeyUser, user)
				return r.WithContext(ctx)
			},
			wantNil:  false,
			wantUser: "testuser",
		},
		{
			name: "no user in context",
			setup: func(r *http.Request) *http.Request {
				return r
			},
			wantNil: true,
		},
		{
			name: "wrong type in context",
			setup: func(r *http.Request) *http.Request {
				ctx := context.WithValue(r.Context(), ContextKeyUser, "not-a-user")
				return r.WithContext(ctx)
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req = tt.setup(req)

			result := GetUserFromContext(req)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
			} else {
				if result == nil {
					t.Error("expected non-nil result")
				} else if result.Username != tt.wantUser {
					t.Errorf("username = %s, want %s", result.Username, tt.wantUser)
				}
			}
		})
	}
}

// TestGetAuthTypeFromContext tests the auth type context helper
func TestGetAuthTypeFromContext(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(r *http.Request) *http.Request
		want     string
	}{
		{
			name: "session auth type",
			setup: func(r *http.Request) *http.Request {
				ctx := context.WithValue(r.Context(), ContextKeyAuthType, AuthTypeSession)
				return r.WithContext(ctx)
			},
			want: AuthTypeSession,
		},
		{
			name: "api token auth type",
			setup: func(r *http.Request) *http.Request {
				ctx := context.WithValue(r.Context(), ContextKeyAuthType, AuthTypeAPIToken)
				return r.WithContext(ctx)
			},
			want: AuthTypeAPIToken,
		},
		{
			name: "no auth type in context",
			setup: func(r *http.Request) *http.Request {
				return r
			},
			want: "",
		},
		{
			name: "wrong type in context",
			setup: func(r *http.Request) *http.Request {
				ctx := context.WithValue(r.Context(), ContextKeyAuthType, 12345)
				return r.WithContext(ctx)
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req = tt.setup(req)

			result := GetAuthTypeFromContext(req)
			if result != tt.want {
				t.Errorf("GetAuthTypeFromContext() = %q, want %q", result, tt.want)
			}
		})
	}
}

// TestGetTokenScopesFromContext tests the token scopes context helper
func TestGetTokenScopesFromContext(t *testing.T) {
	tests := []struct {
		name  string
		setup func(r *http.Request) *http.Request
		want  string
	}{
		{
			name: "scopes in context",
			setup: func(r *http.Request) *http.Request {
				ctx := context.WithValue(r.Context(), ContextKeyTokenScopes, "files:read,files:write")
				return r.WithContext(ctx)
			},
			want: "files:read,files:write",
		},
		{
			name: "no scopes in context",
			setup: func(r *http.Request) *http.Request {
				return r
			},
			want: "",
		},
		{
			name: "wrong type in context",
			setup: func(r *http.Request) *http.Request {
				ctx := context.WithValue(r.Context(), ContextKeyTokenScopes, 12345)
				return r.WithContext(ctx)
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req = tt.setup(req)

			result := GetTokenScopesFromContext(req)
			if result != tt.want {
				t.Errorf("GetTokenScopesFromContext() = %q, want %q", result, tt.want)
			}
		})
	}
}

// TestAuthError tests the authError type
func TestAuthError(t *testing.T) {
	err := &authError{
		message:    "Test error message",
		statusCode: http.StatusUnauthorized,
	}

	if err.Error() != "Test error message" {
		t.Errorf("Error() = %q, want %q", err.Error(), "Test error message")
	}
}

// TestHandleAuthError tests the auth error handler
func TestHandleAuthError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		isHTML     bool
		wantStatus int
	}{
		{
			name:       "forbidden error",
			err:        &authError{message: "Account disabled", statusCode: http.StatusForbidden},
			isHTML:     false,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unauthorized API request",
			err:        &authError{message: "Invalid token", statusCode: http.StatusUnauthorized},
			isHTML:     false,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "unauthorized HTML request redirects",
			err:        &authError{message: "Invalid token", statusCode: http.StatusUnauthorized},
			isHTML:     true,
			wantStatus: http.StatusFound,
		},
		{
			name:       "internal server error",
			err:        &authError{message: "Database error", statusCode: http.StatusInternalServerError},
			isHTML:     false,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "generic error",
			err:        context.DeadlineExceeded,
			isHTML:     false,
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
			if tt.isHTML {
				req.Header.Set("Accept", "text/html")
			}
			rr := httptest.NewRecorder()

			handleAuthError(rr, req, tt.err)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
		})
	}
}

// TestGetTokenExpiresAtFromContext tests the context helper function
func TestGetTokenExpiresAtFromContext(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt *time.Time
		wantNil   bool
	}{
		{
			name:      "no expiration in context",
			expiresAt: nil,
			wantNil:   true,
		},
		{
			name:      "expiration in context",
			expiresAt: func() *time.Time { t := time.Now().Add(24 * time.Hour); return &t }(),
			wantNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.expiresAt != nil {
				ctx := context.WithValue(req.Context(), ContextKeyTokenExpiresAt, tt.expiresAt)
				req = req.WithContext(ctx)
			}

			result := GetTokenExpiresAtFromContext(req)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
			} else {
				if result == nil {
					t.Error("expected non-nil result")
				} else {
					// Compare times (allow 1 second tolerance)
					diff := result.Sub(*tt.expiresAt)
					if diff < -time.Second || diff > time.Second {
						t.Errorf("result = %v, want ~%v", result, tt.expiresAt)
					}
				}
			}
		})
	}
}
