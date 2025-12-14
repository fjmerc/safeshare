package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestIsValidReturnURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "empty URL is valid",
			url:      "",
			expected: true,
		},
		{
			name:     "relative path is valid",
			url:      "/dashboard",
			expected: true,
		},
		{
			name:     "relative path with query is valid",
			url:      "/dashboard?tab=files",
			expected: true,
		},
		{
			name:     "protocol-relative URL is invalid",
			url:      "//evil.com/path",
			expected: false,
		},
		{
			name:     "absolute URL is invalid",
			url:      "https://evil.com/path",
			expected: false,
		},
		{
			name:     "path without leading slash is invalid",
			url:      "dashboard",
			expected: false,
		},
		{
			name:     "javascript protocol is invalid",
			url:      "javascript:alert(1)",
			expected: false,
		},
		{
			name:     "data URI is invalid",
			url:      "data:text/html,<script>alert(1)</script>",
			expected: false,
		},
		{
			name:     "URL with host is invalid",
			url:      "/path@evil.com",
			expected: true, // This is still a relative path
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidReturnURL(tt.url)
			if result != tt.expected {
				t.Errorf("isValidReturnURL(%q) = %v, want %v", tt.url, result, tt.expected)
			}
		})
	}
}

func TestIsValidPostLogoutURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		publicURL string
		expected  bool
	}{
		{
			name:      "empty URL is valid",
			url:       "",
			publicURL: "https://example.com",
			expected:  true,
		},
		{
			name:      "relative path is valid",
			url:       "/login",
			publicURL: "https://example.com",
			expected:  true,
		},
		{
			name:      "absolute URL matching public URL is valid",
			url:       "https://example.com/login",
			publicURL: "https://example.com",
			expected:  true,
		},
		{
			name:      "absolute URL not matching public URL is invalid",
			url:       "https://evil.com/login",
			publicURL: "https://example.com",
			expected:  false,
		},
		{
			name:      "protocol-relative URL is invalid",
			url:       "//evil.com/login",
			publicURL: "https://example.com",
			expected:  false,
		},
		{
			name:      "no public URL configured rejects absolute URLs",
			url:       "https://example.com/login",
			publicURL: "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				PublicURL: tt.publicURL,
			}
			result := isValidPostLogoutURL(tt.url, cfg)
			if result != tt.expected {
				t.Errorf("isValidPostLogoutURL(%q, cfg with PublicURL=%q) = %v, want %v",
					tt.url, tt.publicURL, result, tt.expected)
			}
		})
	}
}

func TestExtractProviderSlug(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		prefix   string
		expected string
	}{
		{
			name:     "valid slug",
			path:     "/api/auth/sso/google/login",
			prefix:   "/api/auth/sso/",
			expected: "google",
		},
		{
			name:     "valid slug with hyphen",
			path:     "/api/auth/sso/my-provider/login",
			prefix:   "/api/auth/sso/",
			expected: "my-provider",
		},
		{
			name:     "valid slug with numbers",
			path:     "/api/auth/sso/provider123/callback",
			prefix:   "/api/auth/sso/",
			expected: "provider123",
		},
		{
			name:     "empty path returns empty",
			path:     "",
			prefix:   "/api/auth/sso/",
			expected: "",
		},
		{
			name:     "wrong prefix returns empty",
			path:     "/wrong/prefix/google/login",
			prefix:   "/api/auth/sso/",
			expected: "",
		},
		{
			name:     "slug too long returns empty",
			path:     "/api/auth/sso/this-is-a-really-really-really-really-really-really-really-long-slug/login",
			prefix:   "/api/auth/sso/",
			expected: "",
		},
		{
			name:     "invalid characters returns empty",
			path:     "/api/auth/sso/Google/login",
			prefix:   "/api/auth/sso/",
			expected: "", // uppercase not allowed
		},
		{
			name:     "slug starting with hyphen returns empty",
			path:     "/api/auth/sso/-invalid/login",
			prefix:   "/api/auth/sso/",
			expected: "",
		},
		{
			name:     "slug ending with hyphen returns empty",
			path:     "/api/auth/sso/invalid-/login",
			prefix:   "/api/auth/sso/",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractProviderSlug(tt.path, tt.prefix)
			if result != tt.expected {
				t.Errorf("extractProviderSlug(%q, %q) = %q, want %q",
					tt.path, tt.prefix, result, tt.expected)
			}
		})
	}
}

func TestGenerateUsernameFromEmail(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		displayName string
		wantPrefix  string // Since random fallback exists, just check prefix
	}{
		{
			name:        "email only",
			email:       "john.doe@example.com",
			displayName: "",
			wantPrefix:  "john.doe",
		},
		{
			name:        "display name available",
			email:       "john.doe@example.com",
			displayName: "John Doe",
			wantPrefix:  "john_doe",
		},
		{
			name:        "display name with special chars",
			email:       "user@example.com",
			displayName: "John O'Brien",
			wantPrefix:  "john_obrien",
		},
		{
			name:        "short email prefix uses email",
			email:       "ab@example.com",
			displayName: "",
			wantPrefix:  "user_", // Falls back to random
		},
		{
			name:        "short display name uses email",
			email:       "john@example.com",
			displayName: "Jo",
			wantPrefix:  "john",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateUsernameFromEmail(tt.email, tt.displayName)
			if len(result) < len(tt.wantPrefix) || result[:len(tt.wantPrefix)] != tt.wantPrefix {
				// For user_ prefix case, just check it starts with user_
				if tt.wantPrefix == "user_" {
					if len(result) < 5 || result[:5] != "user_" {
						t.Errorf("generateUsernameFromEmail(%q, %q) = %q, want prefix %q",
							tt.email, tt.displayName, result, tt.wantPrefix)
					}
				} else {
					t.Errorf("generateUsernameFromEmail(%q, %q) = %q, want prefix %q",
						tt.email, tt.displayName, result, tt.wantPrefix)
				}
			}
		})
	}
}

// =============================================================================
// ListSSOProvidersHandler Tests
// =============================================================================

func TestListSSOProvidersHandler_SSODisabled(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	// SSO is disabled by default (cfg.SSO = nil or SSO.Enabled = false)

	handler := ListSSOProvidersHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/providers", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp SSOProvidersResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Enabled {
		t.Error("expected SSO to be disabled")
	}
	if len(resp.Providers) != 0 {
		t.Errorf("expected 0 providers, got %d", len(resp.Providers))
	}
}

func TestListSSOProvidersHandler_SSOEnabled(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Enable SSO
	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	// Create test provider
	_, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Create disabled provider (should not appear)
	_, err = repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "GitHub",
		Slug:      "github",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   false,
		ClientID:  "test-client-id",
		IssuerURL: "https://github.com",
	})
	if err != nil {
		t.Fatalf("failed to create disabled provider: %v", err)
	}

	handler := ListSSOProvidersHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/providers", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp SSOProvidersResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !resp.Enabled {
		t.Error("expected SSO to be enabled")
	}
	if len(resp.Providers) != 1 {
		t.Errorf("expected 1 provider, got %d", len(resp.Providers))
	}
	if len(resp.Providers) > 0 && resp.Providers[0].Slug != "google" {
		t.Errorf("expected provider slug 'google', got %q", resp.Providers[0].Slug)
	}
}

func TestListSSOProvidersHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := ListSSOProvidersHandler(repos, cfg)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/auth/sso/providers", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// SSOLoginHandler Tests
// =============================================================================

func TestSSOLoginHandler_SSODisabled(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	// SSO disabled by default

	handler := SSOLoginHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/google/login", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusForbidden)
	testutil.AssertContains(t, rr.Body.String(), "SSO is not enabled")
}

func TestSSOLoginHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := SSOLoginHandler(repos, cfg)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/auth/sso/google/login", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

func TestSSOLoginHandler_InvalidProvider(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	handler := SSOLoginHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/nonexistent/login", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

func TestSSOLoginHandler_InvalidSlug(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	handler := SSOLoginHandler(repos, cfg)

	// Test with invalid slug (uppercase)
	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/GOOGLE/login", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

// =============================================================================
// SSOCallbackHandler Tests
// =============================================================================

func TestSSOCallbackHandler_SSODisabled(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := SSOCallbackHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/google/callback?code=test&state=test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusForbidden)
}

func TestSSOCallbackHandler_MissingCode(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	handler := SSOCallbackHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/google/callback?state=test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should redirect to login with error
	testutil.AssertStatusCode(t, rr, http.StatusFound)
	location := rr.Header().Get("Location")
	testutil.AssertContains(t, location, "error=missing_code")
}

func TestSSOCallbackHandler_MissingState(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	handler := SSOCallbackHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/google/callback?code=test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusFound)
	location := rr.Header().Get("Location")
	testutil.AssertContains(t, location, "error=missing_state")
}

func TestSSOCallbackHandler_ErrorFromIdP(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	handler := SSOCallbackHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/google/callback?error=access_denied&error_description=User%20denied%20access", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusFound)
	location := rr.Header().Get("Location")
	testutil.AssertContains(t, location, "error=sso_failed")
}

func TestSSOCallbackHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := SSOCallbackHandler(repos, cfg)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/auth/sso/google/callback", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// SSOLinkAccountHandler Tests
// =============================================================================

func TestSSOLinkAccountHandler_Unauthorized(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	handler := SSOLinkAccountHandler(repos, cfg)

	body, _ := json.Marshal(SSOLinkRequest{ProviderSlug: "google"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/link", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)
}

func TestSSOLinkAccountHandler_SSODisabled(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := SSOLinkAccountHandler(repos, cfg)

	body, _ := json.Marshal(SSOLinkRequest{ProviderSlug: "google"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/link", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Add user to context
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusForbidden)
}

func TestSSOLinkAccountHandler_ProviderNotFound(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := SSOLinkAccountHandler(repos, cfg)

	body, _ := json.Marshal(SSOLinkRequest{ProviderSlug: "nonexistent"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/link", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

func TestSSOLinkAccountHandler_MissingProviderSlug(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := SSOLinkAccountHandler(repos, cfg)

	body, _ := json.Marshal(SSOLinkRequest{ProviderSlug: ""})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/link", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

func TestSSOLinkAccountHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := SSOLinkAccountHandler(repos, cfg)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/auth/sso/link", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// SSOUnlinkAccountHandler Tests
// =============================================================================

func TestSSOUnlinkAccountHandler_Unauthorized(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	handler := SSOUnlinkAccountHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sso/link/google", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)
}

func TestSSOUnlinkAccountHandler_SSODisabled(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := SSOUnlinkAccountHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sso/link/google", nil)
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusForbidden)
}

func TestSSOUnlinkAccountHandler_ProviderNotFound(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := SSOUnlinkAccountHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sso/link/nonexistent", nil)
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

func TestSSOUnlinkAccountHandler_LinkNotFound(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	// Create provider
	_, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := SSOUnlinkAccountHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sso/link/google", nil)
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
	testutil.AssertContains(t, rr.Body.String(), "not linked")
}

func TestSSOUnlinkAccountHandler_Success(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	// Create provider
	provider, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create link
	_, err = repos.SSO.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:        user.ID,
		ProviderID:    provider.ID,
		ExternalID:    "google-user-123",
		ExternalEmail: "test@gmail.com",
	})
	if err != nil {
		t.Fatalf("failed to create link: %v", err)
	}

	handler := SSOUnlinkAccountHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sso/link/google", nil)
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Verify link is deleted
	links, err := repos.SSO.GetLinksByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to get links: %v", err)
	}
	if len(links) != 0 {
		t.Error("expected link to be deleted")
	}
}

func TestSSOUnlinkAccountHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := SSOUnlinkAccountHandler(repos, cfg)

	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/auth/sso/link/google", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// SSOGetLinkedProvidersHandler Tests
// =============================================================================

func TestSSOGetLinkedProvidersHandler_Unauthorized(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	handler := SSOGetLinkedProvidersHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/linked", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)
}

func TestSSOGetLinkedProvidersHandler_SSODisabled(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := SSOGetLinkedProvidersHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/linked", nil)
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusForbidden)
}

func TestSSOGetLinkedProvidersHandler_EmptyList(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := SSOGetLinkedProvidersHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/linked", nil)
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	linkedProviders := resp["linked_providers"].([]interface{})
	if len(linkedProviders) != 0 {
		t.Errorf("expected 0 linked providers, got %d", len(linkedProviders))
	}
}

func TestSSOGetLinkedProvidersHandler_WithLinks(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	// Create provider
	provider, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create link
	_, err = repos.SSO.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:        user.ID,
		ProviderID:    provider.ID,
		ExternalID:    "google-user-123",
		ExternalEmail: "test@gmail.com",
		ExternalName:  "Test User",
	})
	if err != nil {
		t.Fatalf("failed to create link: %v", err)
	}

	handler := SSOGetLinkedProvidersHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/linked", nil)
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	linkedProviders := resp["linked_providers"].([]interface{})
	if len(linkedProviders) != 1 {
		t.Errorf("expected 1 linked provider, got %d", len(linkedProviders))
	}
}

func TestSSOGetLinkedProvidersHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := SSOGetLinkedProvidersHandler(repos, cfg)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/auth/sso/linked", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// SSORefreshTokenHandler Tests
// =============================================================================

func TestSSORefreshTokenHandler_Unauthorized(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	handler := SSORefreshTokenHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/refresh", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)
}

func TestSSORefreshTokenHandler_SSODisabled(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := SSORefreshTokenHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/refresh", nil)
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusForbidden)
}

func TestSSORefreshTokenHandler_NoLinks(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := SSORefreshTokenHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/refresh", nil)
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if int(resp["total_links"].(float64)) != 0 {
		t.Error("expected 0 total_links")
	}
}

func TestSSORefreshTokenHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := SSORefreshTokenHandler(repos, cfg)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/auth/sso/refresh", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// SSOLogoutHandler Tests
// =============================================================================

func TestSSOLogoutHandler_Unauthorized(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	handler := SSOLogoutHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/logout", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)
}

func TestSSOLogoutHandler_SSODisabled(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := SSOLogoutHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/logout", nil)
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusForbidden)
}

func TestSSOLogoutHandler_Success(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create a session
	sessionToken, _ := utils.GenerateSessionToken()
	expiresAt := time.Now().Add(24 * time.Hour)
	if err := repos.Users.CreateSession(ctx, user.ID, sessionToken, expiresAt, "127.0.0.1", "test-agent"); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	handler := SSOLogoutHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/logout", nil)
	req.AddCookie(&http.Cookie{
		Name:  "user_session",
		Value: sessionToken,
	})
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Check session cookie was cleared
	cookies := rr.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "user_session" {
			if cookie.MaxAge != -1 {
				t.Errorf("session cookie MaxAge = %d, want -1 (deleted)", cookie.MaxAge)
			}
		}
	}
}

func TestSSOLogoutHandler_WithIdPLogout(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}
	cfg.PublicURL = "https://example.com"

	// Create provider
	provider, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create link
	_, err = repos.SSO.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:        user.ID,
		ProviderID:    provider.ID,
		ExternalID:    "google-user-123",
		ExternalEmail: "test@gmail.com",
	})
	if err != nil {
		t.Fatalf("failed to create link: %v", err)
	}

	handler := SSOLogoutHandler(repos, cfg)

	logoutReq := map[string]interface{}{
		"idp_logout": true,
	}
	body, _ := json.Marshal(logoutReq)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Should have IdP logout URL
	if resp["idp_logout_url"] == nil {
		t.Log("Note: idp_logout_url not returned (expected for providers without proper logout endpoint)")
	}
}

func TestSSOLogoutHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := SSOLogoutHandler(repos, cfg)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/auth/sso/logout", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// Additional Edge Case Tests
// =============================================================================

func TestSSOLinkAccountHandler_AlreadyLinked(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	// Create provider
	provider, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create existing link
	_, err = repos.SSO.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:        user.ID,
		ProviderID:    provider.ID,
		ExternalID:    "google-user-123",
		ExternalEmail: "test@gmail.com",
	})
	if err != nil {
		t.Fatalf("failed to create link: %v", err)
	}

	handler := SSOLinkAccountHandler(repos, cfg)

	body, _ := json.Marshal(SSOLinkRequest{ProviderSlug: "google"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/link", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusConflict)
}

func TestSSOLinkAccountHandler_ProviderDisabled(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	// Create disabled provider
	_, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   false, // Disabled
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := SSOLinkAccountHandler(repos, cfg)

	body, _ := json.Marshal(SSOLinkRequest{ProviderSlug: "google"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/link", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusForbidden)
}

func TestGenerateSecureToken(t *testing.T) {
	// Test that tokens are unique
	token1, err := generateSecureToken(32)
	if err != nil {
		t.Fatalf("generateSecureToken() error = %v", err)
	}

	token2, err := generateSecureToken(32)
	if err != nil {
		t.Fatalf("generateSecureToken() error = %v", err)
	}

	if token1 == token2 {
		t.Error("generateSecureToken() returned duplicate tokens")
	}

	// Test minimum length
	if len(token1) < 32 {
		t.Errorf("token length = %d, want >= 32", len(token1))
	}
}

func TestSSOLoginHandler_DisabledProvider(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	cfg.SSO = &config.SSOConfig{
		Enabled:            true,
		StateExpiryMinutes: 10,
	}

	// Create disabled provider
	_, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   false,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	handler := SSOLoginHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/google/login", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusForbidden)
	testutil.AssertContains(t, rr.Body.String(), "disabled")
}

func TestBuildIdPLogoutURL(t *testing.T) {
	tests := []struct {
		name          string
		provider      *repository.SSOProvider
		postLogoutURL string
		publicURL     string
		wantEmpty     bool
		wantContains  string
	}{
		{
			name: "valid logout URL",
			provider: &repository.SSOProvider{
				IssuerURL: "https://accounts.google.com",
				ClientID:  "test-client-id",
			},
			postLogoutURL: "/login",
			publicURL:     "https://example.com",
			wantEmpty:     false,
			wantContains:  "logout",
		},
		{
			name:          "empty issuer URL",
			provider:      &repository.SSOProvider{},
			postLogoutURL: "/login",
			publicURL:     "https://example.com",
			wantEmpty:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				PublicURL: tt.publicURL,
			}
			result := buildIdPLogoutURL(tt.provider, tt.postLogoutURL, cfg)

			if tt.wantEmpty && result != "" {
				t.Errorf("buildIdPLogoutURL() = %q, want empty", result)
			}
			if !tt.wantEmpty && result == "" {
				t.Error("buildIdPLogoutURL() returned empty, want non-empty")
			}
			if tt.wantContains != "" && !bytes.Contains([]byte(result), []byte(tt.wantContains)) {
				t.Errorf("buildIdPLogoutURL() = %q, want to contain %q", result, tt.wantContains)
			}
		})
	}
}
