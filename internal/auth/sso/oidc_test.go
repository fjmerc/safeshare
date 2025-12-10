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
