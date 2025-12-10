package sso

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
)

// mockSSORepository implements repository.SSORepository for testing
type mockSSORepository struct {
	states       map[string]*repository.SSOState
	createErr    error
	getErr       error
	deleteErr    error
	stateDeleted bool
}

func newMockSSORepository() *mockSSORepository {
	return &mockSSORepository{
		states: make(map[string]*repository.SSOState),
	}
}

func (m *mockSSORepository) CreateState(ctx context.Context, state, nonce string, providerID int64, returnURL, createdIP string, userID *int64, expiresAt time.Time) (*repository.SSOState, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	s := &repository.SSOState{
		ID:         1,
		State:      state,
		Nonce:      nonce,
		ProviderID: providerID,
		ReturnURL:  returnURL,
		UserID:     userID,
		CreatedIP:  createdIP,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
	}
	m.states[state] = s
	return s, nil
}

func (m *mockSSORepository) GetState(ctx context.Context, state string) (*repository.SSOState, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	s, ok := m.states[state]
	if !ok {
		return nil, repository.ErrSSOStateNotFound
	}
	if time.Now().After(s.ExpiresAt) {
		return nil, repository.ErrSSOStateExpired
	}
	return s, nil
}

func (m *mockSSORepository) DeleteState(ctx context.Context, state string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.states, state)
	m.stateDeleted = true
	return nil
}

// Implement remaining SSORepository interface methods (unused in tests)
func (m *mockSSORepository) CreateProvider(ctx context.Context, input *repository.CreateSSOProviderInput) (*repository.SSOProvider, error) {
	return nil, nil
}
func (m *mockSSORepository) GetProvider(ctx context.Context, id int64) (*repository.SSOProvider, error) {
	return nil, nil
}
func (m *mockSSORepository) GetProviderBySlug(ctx context.Context, slug string) (*repository.SSOProvider, error) {
	return nil, nil
}
func (m *mockSSORepository) GetEnabledProviderBySlug(ctx context.Context, slug string) (*repository.SSOProvider, error) {
	return nil, nil
}
func (m *mockSSORepository) UpdateProvider(ctx context.Context, id int64, input *repository.UpdateSSOProviderInput) (*repository.SSOProvider, error) {
	return nil, nil
}
func (m *mockSSORepository) DeleteProvider(ctx context.Context, id int64) error {
	return nil
}
func (m *mockSSORepository) ListProviders(ctx context.Context, enabledOnly bool) ([]repository.SSOProvider, error) {
	return nil, nil
}
func (m *mockSSORepository) ListProvidersWithStats(ctx context.Context) ([]repository.SSOProviderWithStats, error) {
	return nil, nil
}
func (m *mockSSORepository) GetProviderCount(ctx context.Context) (int64, error) {
	return 0, nil
}
func (m *mockSSORepository) CreateLink(ctx context.Context, input *repository.CreateUserSSOLinkInput) (*repository.UserSSOLink, error) {
	return nil, nil
}
func (m *mockSSORepository) GetLink(ctx context.Context, id int64) (*repository.UserSSOLink, error) {
	return nil, nil
}
func (m *mockSSORepository) GetLinkByExternalID(ctx context.Context, providerID int64, externalID string) (*repository.UserSSOLink, error) {
	return nil, nil
}
func (m *mockSSORepository) GetLinksByUserID(ctx context.Context, userID int64) ([]repository.UserSSOLink, error) {
	return nil, nil
}
func (m *mockSSORepository) GetLinksByProviderID(ctx context.Context, providerID int64) ([]repository.UserSSOLink, error) {
	return nil, nil
}
func (m *mockSSORepository) UpdateLinkTokens(ctx context.Context, id int64, accessToken, refreshToken string, expiresAt *time.Time) error {
	return nil
}
func (m *mockSSORepository) UpdateLinkLastLogin(ctx context.Context, id int64) error {
	return nil
}
func (m *mockSSORepository) DeleteLink(ctx context.Context, id int64) error {
	return nil
}
func (m *mockSSORepository) DeleteLinksByUserID(ctx context.Context, userID int64) error {
	return nil
}
func (m *mockSSORepository) DeleteLinksByProviderID(ctx context.Context, providerID int64) error {
	return nil
}
func (m *mockSSORepository) CountLinksByProviderID(ctx context.Context, providerID int64) (int64, error) {
	return 0, nil
}
func (m *mockSSORepository) CleanupExpiredStates(ctx context.Context) (int64, error) {
	return 0, nil
}
func (m *mockSSORepository) GetLinkByUserAndProvider(ctx context.Context, userID, providerID int64) (*repository.UserSSOLink, error) {
	return nil, nil
}
func (m *mockSSORepository) FindUserByExternalEmail(ctx context.Context, email string) ([]int64, error) {
	return nil, nil
}

// setupMockOIDCServer creates a mock OIDC discovery server
func setupMockOIDCServer() *httptest.Server {
	mux := http.NewServeMux()

	// OIDC discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]interface{}{
			"issuer":                 "", // Will be set dynamically
			"authorization_endpoint": "/authorize",
			"token_endpoint":         "/token",
			"userinfo_endpoint":      "/userinfo",
			"jwks_uri":               "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	})

	// JWKS endpoint
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	server := httptest.NewServer(mux)

	// Update the discovery config with the actual server URL
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Fallback handler
		http.NotFound(w, r)
	})

	return server
}

func TestValidateOIDCURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		fieldName string
		wantErr   bool
	}{
		{
			name:      "empty URL is valid",
			url:       "",
			fieldName: "test",
			wantErr:   false,
		},
		{
			name:      "HTTPS URL is valid",
			url:       "https://example.com/oidc",
			fieldName: "test",
			wantErr:   false,
		},
		{
			name:      "HTTP localhost is valid",
			url:       "http://localhost:8080/oidc",
			fieldName: "test",
			wantErr:   false,
		},
		{
			name:      "HTTP 127.0.0.1 is valid",
			url:       "http://127.0.0.1:8080/oidc",
			fieldName: "test",
			wantErr:   false,
		},
		{
			name:      "HTTP IPv6 localhost is valid",
			url:       "http://[::1]:8080/oidc",
			fieldName: "test",
			wantErr:   false,
		},
		{
			name:      "HTTP non-localhost is invalid",
			url:       "http://example.com/oidc",
			fieldName: "test",
			wantErr:   true,
		},
		{
			name:      "javascript URL is invalid",
			url:       "javascript:alert(1)",
			fieldName: "test",
			wantErr:   true,
		},
		{
			name:      "file URL is invalid",
			url:       "file:///etc/passwd",
			fieldName: "test",
			wantErr:   true,
		},
		{
			name:      "ftp URL is invalid",
			url:       "ftp://example.com/file",
			fieldName: "test",
			wantErr:   true,
		},
		{
			name:      "invalid URL format",
			url:       "://invalid",
			fieldName: "test",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOIDCURL(tt.url, tt.fieldName)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOIDCURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateEmailDomain(t *testing.T) {
	tests := []struct {
		name            string
		email           string
		domainAllowlist string
		wantErr         bool
		errType         error
	}{
		{
			name:            "empty allowlist allows all domains",
			email:           "user@example.com",
			domainAllowlist: "",
			wantErr:         false,
		},
		{
			name:            "email in allowlist",
			email:           "user@example.com",
			domainAllowlist: "example.com,test.com",
			wantErr:         false,
		},
		{
			name:            "email not in allowlist",
			email:           "user@other.com",
			domainAllowlist: "example.com,test.com",
			wantErr:         true,
			errType:         repository.ErrEmailDomainNotAllowed,
		},
		{
			name:            "case insensitive matching",
			email:           "user@EXAMPLE.COM",
			domainAllowlist: "example.com",
			wantErr:         false,
		},
		{
			name:            "whitespace in email is trimmed",
			email:           "  user@example.com  ",
			domainAllowlist: "example.com",
			wantErr:         false,
		},
		{
			name:            "trailing dot in domain is normalized",
			email:           "user@example.com.",
			domainAllowlist: "example.com",
			wantErr:         false,
		},
		{
			name:            "invalid email format - no @",
			email:           "userexample.com",
			domainAllowlist: "example.com",
			wantErr:         true,
		},
		{
			name:            "invalid email format - multiple @",
			email:           "user@foo@example.com",
			domainAllowlist: "example.com",
			wantErr:         true,
		},
		{
			name:            "whitespace around allowlist domains",
			email:           "user@example.com",
			domainAllowlist: " example.com , test.com ",
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &OIDCProvider{
				provider: &repository.SSOProvider{
					DomainAllowlist: tt.domainAllowlist,
				},
			}

			err := provider.ValidateEmailDomain(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmailDomain() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errType != nil && err != tt.errType {
				t.Errorf("ValidateEmailDomain() error = %v, want error type %v", err, tt.errType)
			}
		})
	}
}

func TestNewOIDCProvider_ValidationErrors(t *testing.T) {
	ctx := context.Background()
	repo := newMockSSORepository()

	tests := []struct {
		name     string
		provider *repository.SSOProvider
		wantErr  string
	}{
		{
			name:     "nil provider",
			provider: nil,
			wantErr:  "provider cannot be nil",
		},
		{
			name: "empty issuer URL",
			provider: &repository.SSOProvider{
				IssuerURL: "",
				ClientID:  "client-id",
			},
			wantErr: "issuer URL is required",
		},
		{
			name: "invalid issuer URL scheme",
			provider: &repository.SSOProvider{
				IssuerURL: "http://external.com/oidc",
				ClientID:  "client-id",
			},
			wantErr: "issuer URL must use HTTPS",
		},
		{
			name: "empty client ID",
			provider: &repository.SSOProvider{
				IssuerURL: "http://localhost:8080/oidc",
				ClientID:  "",
			},
			wantErr: "client ID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewOIDCProvider(ctx, tt.provider, repo)
			if err == nil {
				t.Fatalf("NewOIDCProvider() expected error containing %q, got nil", tt.wantErr)
			}
			if err.Error() == "" || !containsString(err.Error(), tt.wantErr) {
				t.Errorf("NewOIDCProvider() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestOIDCProvider_GetProvider(t *testing.T) {
	provider := &repository.SSOProvider{
		ID:   1,
		Name: "Test Provider",
		Slug: "test",
	}

	oidcProvider := &OIDCProvider{
		provider: provider,
	}

	got := oidcProvider.GetProvider()
	if got != provider {
		t.Errorf("GetProvider() = %v, want %v", got, provider)
	}
}



func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && (s[:len(substr)] == substr || containsString(s[1:], substr)))
}

func TestUserInfo_Fields(t *testing.T) {
	info := &UserInfo{
		Subject:  "user123",
		Email:    "user@example.com",
		Name:     "Test User",
		Verified: true,
	}

	if info.Subject != "user123" {
		t.Errorf("Subject = %v, want %v", info.Subject, "user123")
	}
	if info.Email != "user@example.com" {
		t.Errorf("Email = %v, want %v", info.Email, "user@example.com")
	}
	if info.Name != "Test User" {
		t.Errorf("Name = %v, want %v", info.Name, "Test User")
	}
	if !info.Verified {
		t.Errorf("Verified = %v, want %v", info.Verified, true)
	}
}

// =============================================================================
// OIDCProvider GetAuthorizationURL Tests
// =============================================================================

func TestOIDCProvider_GetAuthorizationURL_Validation(t *testing.T) {
	repo := newMockSSORepository()
	ctx := context.Background()

	oidcProvider := &OIDCProvider{
		provider: &repository.SSOProvider{
			ID:        1,
			Name:      "Test",
			Slug:      "test",
			ClientID:  "client-id",
			IssuerURL: "https://example.com",
		},
		repo: repo,
	}

	tests := []struct {
		name    string
		state   string
		nonce   string
		wantErr bool
	}{
		{
			name:    "empty state",
			state:   "",
			nonce:   "test-nonce",
			wantErr: true,
		},
		{
			name:    "empty nonce",
			state:   "test-state",
			nonce:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := oidcProvider.GetAuthorizationURL(ctx, tt.state, tt.nonce, "/dashboard", "127.0.0.1", nil, 10)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAuthorizationURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOIDCProvider_GetAuthorizationURL_CreatesState(t *testing.T) {
	repo := newMockSSORepository()
	ctx := context.Background()

	// Create a mock OIDC server - we need to capture the server URL to use as the issuer
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]interface{}{
				"issuer":                 serverURL,
				"authorization_endpoint": serverURL + "/authorize",
				"token_endpoint":         serverURL + "/token",
				"userinfo_endpoint":      serverURL + "/userinfo",
				"jwks_uri":               serverURL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(config)
			return
		}
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	serverURL = server.URL

	provider, err := NewOIDCProvider(ctx, &repository.SSOProvider{
		ID:        1,
		Name:      "Test",
		Slug:      "test",
		ClientID:  "client-id",
		IssuerURL: server.URL,
	}, repo)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error = %v", err)
	}

	authURL, err := provider.GetAuthorizationURL(ctx, "test-state", "test-nonce", "/dashboard", "127.0.0.1", nil, 10)
	if err != nil {
		t.Fatalf("GetAuthorizationURL() error = %v", err)
	}

	// Verify URL is not empty
	if authURL == "" {
		t.Error("GetAuthorizationURL() returned empty URL")
	}

	// Verify state was created in repository
	state, err := repo.GetState(ctx, "test-state")
	if err != nil {
		t.Errorf("state not created in repository: %v", err)
	}
	if state.Nonce != "test-nonce" {
		t.Errorf("state nonce = %v, want test-nonce", state.Nonce)
	}
	if state.ReturnURL != "/dashboard" {
		t.Errorf("state returnURL = %v, want /dashboard", state.ReturnURL)
	}
}

func TestOIDCProvider_GetAuthorizationURL_WithUserID(t *testing.T) {
	repo := newMockSSORepository()
	ctx := context.Background()

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]interface{}{
				"issuer":                 serverURL,
				"authorization_endpoint": serverURL + "/authorize",
				"token_endpoint":         serverURL + "/token",
				"userinfo_endpoint":      serverURL + "/userinfo",
				"jwks_uri":               serverURL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(config)
			return
		}
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	serverURL = server.URL

	provider, err := NewOIDCProvider(ctx, &repository.SSOProvider{
		ID:        1,
		Name:      "Test",
		Slug:      "test",
		ClientID:  "client-id",
		IssuerURL: server.URL,
	}, repo)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error = %v", err)
	}

	userID := int64(123)
	_, err = provider.GetAuthorizationURL(ctx, "test-state-2", "test-nonce-2", "/settings", "127.0.0.1", &userID, 10)
	if err != nil {
		t.Fatalf("GetAuthorizationURL() error = %v", err)
	}

	// Verify state includes user ID
	state, err := repo.GetState(ctx, "test-state-2")
	if err != nil {
		t.Fatalf("state not created: %v", err)
	}
	if state.UserID == nil || *state.UserID != 123 {
		t.Error("state should have user ID set")
	}
}

// =============================================================================
// OIDCProvider ExchangeCodeForToken Tests
// =============================================================================

func TestOIDCProvider_ExchangeCodeForToken_EmptyCode(t *testing.T) {
	repo := newMockSSORepository()
	ctx := context.Background()

	oidcProvider := &OIDCProvider{
		provider: &repository.SSOProvider{
			ID:        1,
			ClientID:  "client-id",
			IssuerURL: "https://example.com",
		},
		repo: repo,
	}

	_, _, _, err := oidcProvider.ExchangeCodeForToken(ctx, "", "test-state")
	if err == nil {
		t.Error("ExchangeCodeForToken() expected error for empty code")
	}
}

func TestOIDCProvider_ExchangeCodeForToken_EmptyState(t *testing.T) {
	repo := newMockSSORepository()
	ctx := context.Background()

	oidcProvider := &OIDCProvider{
		provider: &repository.SSOProvider{
			ID:        1,
			ClientID:  "client-id",
			IssuerURL: "https://example.com",
		},
		repo: repo,
	}

	_, _, _, err := oidcProvider.ExchangeCodeForToken(ctx, "test-code", "")
	if err == nil {
		t.Error("ExchangeCodeForToken() expected error for empty state")
	}
}

func TestOIDCProvider_ExchangeCodeForToken_InvalidState(t *testing.T) {
	repo := newMockSSORepository()
	ctx := context.Background()

	oidcProvider := &OIDCProvider{
		provider: &repository.SSOProvider{
			ID:        1,
			ClientID:  "client-id",
			IssuerURL: "https://example.com",
		},
		repo: repo,
	}

	_, _, _, err := oidcProvider.ExchangeCodeForToken(ctx, "test-code", "nonexistent-state")
	if err == nil {
		t.Error("ExchangeCodeForToken() expected error for invalid state")
	}
	if !containsString(err.Error(), "invalid state") {
		t.Errorf("ExchangeCodeForToken() error = %v, want error containing 'invalid state'", err)
	}
}

func TestOIDCProvider_ExchangeCodeForToken_ExpiredState(t *testing.T) {
	repo := newMockSSORepository()
	ctx := context.Background()

	// Create an expired state
	repo.states["expired-state"] = &repository.SSOState{
		ID:         1,
		State:      "expired-state",
		Nonce:      "test-nonce",
		ProviderID: 1,
		ExpiresAt:  time.Now().Add(-1 * time.Hour), // Expired
		CreatedAt:  time.Now().Add(-2 * time.Hour),
	}

	oidcProvider := &OIDCProvider{
		provider: &repository.SSOProvider{
			ID:        1,
			ClientID:  "client-id",
			IssuerURL: "https://example.com",
		},
		repo: repo,
	}

	_, _, _, err := oidcProvider.ExchangeCodeForToken(ctx, "test-code", "expired-state")
	if err == nil {
		t.Error("ExchangeCodeForToken() expected error for expired state")
	}
	if !containsString(err.Error(), "expired") {
		t.Errorf("ExchangeCodeForToken() error = %v, want error containing 'expired'", err)
	}
}

func TestOIDCProvider_ExchangeCodeForToken_WrongProvider(t *testing.T) {
	repo := newMockSSORepository()
	ctx := context.Background()

	// Create a state for a different provider
	repo.states["wrong-provider-state"] = &repository.SSOState{
		ID:         1,
		State:      "wrong-provider-state",
		Nonce:      "test-nonce",
		ProviderID: 999, // Different provider ID
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		CreatedAt:  time.Now(),
	}

	oidcProvider := &OIDCProvider{
		provider: &repository.SSOProvider{
			ID:        1, // Our provider ID
			ClientID:  "client-id",
			IssuerURL: "https://example.com",
		},
		repo: repo,
	}

	_, _, _, err := oidcProvider.ExchangeCodeForToken(ctx, "test-code", "wrong-provider-state")
	if err == nil {
		t.Error("ExchangeCodeForToken() expected error for wrong provider")
	}
	if !containsString(err.Error(), "does not belong") {
		t.Errorf("ExchangeCodeForToken() error = %v, want error about provider mismatch", err)
	}
}

// =============================================================================
// OIDCProvider GetUserInfo Tests
// =============================================================================

func TestOIDCProvider_GetUserInfo_NilToken(t *testing.T) {
	ctx := context.Background()

	oidcProvider := &OIDCProvider{
		provider: &repository.SSOProvider{
			ID:        1,
			ClientID:  "client-id",
			IssuerURL: "https://example.com",
		},
	}

	_, err := oidcProvider.GetUserInfo(ctx, nil)
	if err == nil {
		t.Error("GetUserInfo() expected error for nil token")
	}
}

// =============================================================================
// OIDCProvider GetUserInfoFromIDToken Tests
// =============================================================================

func TestOIDCProvider_GetUserInfoFromIDToken_NilToken(t *testing.T) {
	oidcProvider := &OIDCProvider{
		provider: &repository.SSOProvider{
			ID:        1,
			ClientID:  "client-id",
			IssuerURL: "https://example.com",
		},
	}

	_, err := oidcProvider.GetUserInfoFromIDToken(nil)
	if err == nil {
		t.Error("GetUserInfoFromIDToken() expected error for nil ID token")
	}
}

// =============================================================================
// OIDCProvider RefreshToken Tests
// =============================================================================

func TestOIDCProvider_RefreshToken_EmptyToken(t *testing.T) {
	ctx := context.Background()

	oidcProvider := &OIDCProvider{
		provider: &repository.SSOProvider{
			ID:        1,
			ClientID:  "client-id",
			IssuerURL: "https://example.com",
		},
	}

	_, err := oidcProvider.RefreshToken(ctx, "")
	if err == nil {
		t.Error("RefreshToken() expected error for empty refresh token")
	}
}

// =============================================================================
// OIDCProvider Getter Tests
// =============================================================================

func TestOIDCProvider_GetScopes(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]interface{}{
				"issuer":                 serverURL,
				"authorization_endpoint": serverURL + "/authorize",
				"token_endpoint":         serverURL + "/token",
				"userinfo_endpoint":      serverURL + "/userinfo",
				"jwks_uri":               serverURL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(config)
			return
		}
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	serverURL = server.URL

	ctx := context.Background()
	repo := newMockSSORepository()

	provider, err := NewOIDCProvider(ctx, &repository.SSOProvider{
		ID:        1,
		Name:      "Test",
		Slug:      "test",
		ClientID:  "client-id",
		IssuerURL: server.URL,
		Scopes:    "openid profile email",
	}, repo)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error = %v", err)
	}

	scopes := provider.GetScopes()
	if len(scopes) == 0 {
		t.Error("GetScopes() returned empty slice")
	}

	// Check that openid is in scopes
	foundOpenID := false
	for _, s := range scopes {
		if s == "openid" {
			foundOpenID = true
			break
		}
	}
	if !foundOpenID {
		t.Error("GetScopes() should include 'openid'")
	}
}

func TestOIDCProvider_GetRedirectURL(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]interface{}{
				"issuer":                 serverURL,
				"authorization_endpoint": serverURL + "/authorize",
				"token_endpoint":         serverURL + "/token",
				"userinfo_endpoint":      serverURL + "/userinfo",
				"jwks_uri":               serverURL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(config)
			return
		}
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	serverURL = server.URL

	ctx := context.Background()
	repo := newMockSSORepository()

	expectedRedirectURL := "https://example.com/callback"
	provider, err := NewOIDCProvider(ctx, &repository.SSOProvider{
		ID:          1,
		Name:        "Test",
		Slug:        "test",
		ClientID:    "client-id",
		IssuerURL:   server.URL,
		RedirectURL: expectedRedirectURL,
	}, repo)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error = %v", err)
	}

	if provider.GetRedirectURL() != expectedRedirectURL {
		t.Errorf("GetRedirectURL() = %v, want %v", provider.GetRedirectURL(), expectedRedirectURL)
	}
}

// =============================================================================
// Additional Domain Validation Tests
// =============================================================================

func TestValidateEmailDomain_EdgeCases(t *testing.T) {
	tests := []struct {
		name            string
		email           string
		domainAllowlist string
		wantErr         bool
	}{
		{
			name:            "empty email",
			email:           "",
			domainAllowlist: "example.com",
			wantErr:         true,
		},
		{
			name:            "email with only @",
			email:           "@",
			domainAllowlist: "example.com",
			wantErr:         true,
		},
		{
			name:            "subdomain not in allowlist",
			email:           "user@sub.example.com",
			domainAllowlist: "example.com",
			wantErr:         true,
		},
		{
			name:            "subdomain in allowlist",
			email:           "user@sub.example.com",
			domainAllowlist: "sub.example.com",
			wantErr:         false,
		},
		{
			name:            "empty entries in allowlist",
			email:           "user@example.com",
			domainAllowlist: ",,example.com,,",
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &OIDCProvider{
				provider: &repository.SSOProvider{
					DomainAllowlist: tt.domainAllowlist,
				},
			}

			err := provider.ValidateEmailDomain(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmailDomain(%q) error = %v, wantErr %v", tt.email, err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// URL Validation Edge Cases
// =============================================================================

func TestValidateOIDCURL_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "HTTPS with port",
			url:     "https://example.com:8443/oidc",
			wantErr: false,
		},
		{
			name:    "HTTP localhost without port",
			url:     "http://localhost/oidc",
			wantErr: false,
		},
		{
			name:    "HTTPS localhost",
			url:     "https://localhost:8443/oidc",
			wantErr: false,
		},
		{
			name:    "data URL",
			url:     "data:text/html,test",
			wantErr: true,
		},
		{
			name:    "URL with credentials",
			url:     "https://user:pass@example.com/oidc",
			wantErr: false, // URL is valid HTTPS, credentials are allowed
		},
		{
			name:    "URL with fragment",
			url:     "https://example.com/oidc#fragment",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOIDCURL(tt.url, "test")
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOIDCURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Mock Repository State Tests
// =============================================================================

func TestMockSSORepository_CreateState(t *testing.T) {
	repo := newMockSSORepository()
	ctx := context.Background()

	userID := int64(42)
	expiresAt := time.Now().Add(10 * time.Minute)

	state, err := repo.CreateState(ctx, "test-state", "test-nonce", 1, "/return", "192.168.1.1", &userID, expiresAt)
	if err != nil {
		t.Fatalf("CreateState() error = %v", err)
	}

	if state.State != "test-state" {
		t.Errorf("state.State = %v, want test-state", state.State)
	}
	if state.Nonce != "test-nonce" {
		t.Errorf("state.Nonce = %v, want test-nonce", state.Nonce)
	}
	if state.UserID == nil || *state.UserID != 42 {
		t.Error("state.UserID should be 42")
	}
}

func TestMockSSORepository_GetState_NotFound(t *testing.T) {
	repo := newMockSSORepository()
	ctx := context.Background()

	_, err := repo.GetState(ctx, "nonexistent")
	if err != repository.ErrSSOStateNotFound {
		t.Errorf("GetState() error = %v, want ErrSSOStateNotFound", err)
	}
}

func TestMockSSORepository_DeleteState(t *testing.T) {
	repo := newMockSSORepository()
	ctx := context.Background()

	// Create a state
	_, _ = repo.CreateState(ctx, "to-delete", "nonce", 1, "", "127.0.0.1", nil, time.Now().Add(time.Hour))

	// Delete it
	err := repo.DeleteState(ctx, "to-delete")
	if err != nil {
		t.Fatalf("DeleteState() error = %v", err)
	}

	// Verify it's gone
	_, err = repo.GetState(ctx, "to-delete")
	if err != repository.ErrSSOStateNotFound {
		t.Error("state should be deleted")
	}

	if !repo.stateDeleted {
		t.Error("stateDeleted flag should be true")
	}
}
