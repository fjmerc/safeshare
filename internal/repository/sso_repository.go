// Package repository provides interfaces for data access operations.
package repository

import (
	"context"
	"errors"
	"time"
)

// SSO-related errors
var (
	// ErrSSOProviderNotFound is returned when an SSO provider is not found.
	ErrSSOProviderNotFound = errors.New("SSO provider not found")

	// ErrSSOProviderDisabled is returned when an SSO provider is disabled.
	ErrSSOProviderDisabled = errors.New("SSO provider is disabled")

	// ErrSSOProviderSlugExists is returned when a provider with the same slug already exists.
	ErrSSOProviderSlugExists = errors.New("SSO provider slug already exists")

	// ErrSSOLinkNotFound is returned when a user SSO link is not found.
	ErrSSOLinkNotFound = errors.New("SSO link not found")

	// ErrSSOLinkExists is returned when a user SSO link already exists.
	ErrSSOLinkExists = errors.New("SSO link already exists for this provider and external ID")

	// ErrSSOStateNotFound is returned when an SSO state is not found.
	ErrSSOStateNotFound = errors.New("SSO state not found")

	// ErrSSOStateExpired is returned when an SSO state has expired.
	ErrSSOStateExpired = errors.New("SSO state has expired")

	// ErrEmailDomainNotAllowed is returned when the user's email domain is not in the provider's allowlist.
	ErrEmailDomainNotAllowed = errors.New("email domain not allowed for this SSO provider")
)

// SSOProviderType represents the type of SSO provider.
type SSOProviderType string

const (
	// SSOProviderTypeOIDC represents an OpenID Connect provider.
	SSOProviderTypeOIDC SSOProviderType = "oidc"

	// SSOProviderTypeSAML represents a SAML provider.
	SSOProviderTypeSAML SSOProviderType = "saml"
)

// SSOProvider represents an SSO provider configuration.
type SSOProvider struct {
	ID                int64           `json:"id"`
	Name              string          `json:"name"`
	Slug              string          `json:"slug"`
	Type              SSOProviderType `json:"type"`
	Enabled           bool            `json:"enabled"`

	// OIDC/OAuth2 Configuration
	ClientID          string `json:"client_id,omitempty"`
	ClientSecret      string `json:"-"` // Never expose in JSON
	IssuerURL         string `json:"issuer_url,omitempty"`

	// Optional custom endpoints (override discovery)
	AuthorizationURL  string `json:"authorization_url,omitempty"`
	TokenURL          string `json:"token_url,omitempty"`
	UserinfoURL       string `json:"userinfo_url,omitempty"`
	JWKSURL           string `json:"jwks_url,omitempty"`

	// OAuth2 Configuration
	Scopes            string `json:"scopes"`
	RedirectURL       string `json:"redirect_url,omitempty"`

	// User provisioning settings
	AutoProvision     bool   `json:"auto_provision"`
	DefaultRole       string `json:"default_role"`
	DomainAllowlist   string `json:"domain_allowlist,omitempty"` // Comma-separated

	// Display settings
	IconURL           string `json:"icon_url,omitempty"`
	ButtonColor       string `json:"button_color,omitempty"`
	ButtonTextColor   string `json:"button_text_color,omitempty"`
	DisplayOrder      int    `json:"display_order"`

	// Timestamps
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// UserSSOLink represents a link between a local user and an SSO provider identity.
type UserSSOLink struct {
	ID              int64      `json:"id"`
	UserID          int64      `json:"user_id"`
	ProviderID      int64      `json:"provider_id"`
	ExternalID      string     `json:"external_id"` // Subject claim from provider
	ExternalEmail   string     `json:"external_email,omitempty"`
	ExternalName    string     `json:"external_name,omitempty"`

	// Token storage (encrypted)
	AccessToken     string     `json:"-"` // Never expose in JSON
	RefreshToken    string     `json:"-"` // Never expose in JSON
	TokenExpiresAt  *time.Time `json:"token_expires_at,omitempty"`

	// Metadata
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// SSOState represents a temporary OAuth2 state token for CSRF protection.
type SSOState struct {
	ID          int64      `json:"id"`
	State       string     `json:"state"`
	Nonce       string     `json:"nonce"`
	ProviderID  int64      `json:"provider_id"`
	ReturnURL   string     `json:"return_url,omitempty"`
	UserID      *int64     `json:"user_id,omitempty"` // If linking existing account
	CreatedIP   string     `json:"created_ip,omitempty"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// SSOProviderWithStats includes provider info with usage statistics.
type SSOProviderWithStats struct {
	SSOProvider
	LinkedUsersCount int `json:"linked_users_count"`
	LoginCount24h    int `json:"login_count_24h,omitempty"`
}

// CreateSSOProviderInput represents input for creating a new SSO provider.
type CreateSSOProviderInput struct {
	Name              string          `json:"name"`
	Slug              string          `json:"slug"`
	Type              SSOProviderType `json:"type"`
	Enabled           bool            `json:"enabled"`
	ClientID          string          `json:"client_id"`
	ClientSecret      string          `json:"client_secret"` // Will be encrypted before storage
	IssuerURL         string          `json:"issuer_url"`
	AuthorizationURL  string          `json:"authorization_url,omitempty"`
	TokenURL          string          `json:"token_url,omitempty"`
	UserinfoURL       string          `json:"userinfo_url,omitempty"`
	JWKSURL           string          `json:"jwks_url,omitempty"`
	Scopes            string          `json:"scopes"`
	RedirectURL       string          `json:"redirect_url,omitempty"`
	AutoProvision     bool            `json:"auto_provision"`
	DefaultRole       string          `json:"default_role"`
	DomainAllowlist   string          `json:"domain_allowlist,omitempty"`
	IconURL           string          `json:"icon_url,omitempty"`
	ButtonColor       string          `json:"button_color,omitempty"`
	ButtonTextColor   string          `json:"button_text_color,omitempty"`
	DisplayOrder      int             `json:"display_order"`
}

// UpdateSSOProviderInput represents input for updating an SSO provider.
type UpdateSSOProviderInput struct {
	Name              *string `json:"name,omitempty"`
	Enabled           *bool   `json:"enabled,omitempty"`
	ClientID          *string `json:"client_id,omitempty"`
	ClientSecret      *string `json:"client_secret,omitempty"` // Will be encrypted before storage
	IssuerURL         *string `json:"issuer_url,omitempty"`
	AuthorizationURL  *string `json:"authorization_url,omitempty"`
	TokenURL          *string `json:"token_url,omitempty"`
	UserinfoURL       *string `json:"userinfo_url,omitempty"`
	JWKSURL           *string `json:"jwks_url,omitempty"`
	Scopes            *string `json:"scopes,omitempty"`
	RedirectURL       *string `json:"redirect_url,omitempty"`
	AutoProvision     *bool   `json:"auto_provision,omitempty"`
	DefaultRole       *string `json:"default_role,omitempty"`
	DomainAllowlist   *string `json:"domain_allowlist,omitempty"`
	IconURL           *string `json:"icon_url,omitempty"`
	ButtonColor       *string `json:"button_color,omitempty"`
	ButtonTextColor   *string `json:"button_text_color,omitempty"`
	DisplayOrder      *int    `json:"display_order,omitempty"`
}

// CreateUserSSOLinkInput represents input for creating a user SSO link.
type CreateUserSSOLinkInput struct {
	UserID         int64      `json:"user_id"`
	ProviderID     int64      `json:"provider_id"`
	ExternalID     string     `json:"external_id"`
	ExternalEmail  string     `json:"external_email,omitempty"`
	ExternalName   string     `json:"external_name,omitempty"`
	AccessToken    string     `json:"-"` // Will be encrypted before storage
	RefreshToken   string     `json:"-"` // Will be encrypted before storage
	TokenExpiresAt *time.Time `json:"token_expires_at,omitempty"`
}

// SSORepository defines the interface for SSO database operations.
// All methods accept a context for cancellation and timeout support.
type SSORepository interface {
	// ===========================================================================
	// SSO Provider Operations
	// ===========================================================================

	// CreateProvider creates a new SSO provider.
	// Returns ErrSSOProviderSlugExists if a provider with the same slug exists.
	CreateProvider(ctx context.Context, input *CreateSSOProviderInput) (*SSOProvider, error)

	// GetProvider retrieves an SSO provider by ID.
	// Returns ErrSSOProviderNotFound if not found.
	GetProvider(ctx context.Context, id int64) (*SSOProvider, error)

	// GetProviderBySlug retrieves an SSO provider by slug.
	// Returns ErrSSOProviderNotFound if not found.
	GetProviderBySlug(ctx context.Context, slug string) (*SSOProvider, error)

	// GetEnabledProviderBySlug retrieves an SSO provider by slug, ensuring it's enabled.
	// Returns ErrSSOProviderNotFound if not found.
	// Returns ErrSSOProviderDisabled if the provider exists but is disabled.
	// Use this method for login flows to ensure disabled providers cannot be used.
	GetEnabledProviderBySlug(ctx context.Context, slug string) (*SSOProvider, error)

	// UpdateProvider updates an SSO provider.
	// Returns ErrSSOProviderNotFound if not found.
	UpdateProvider(ctx context.Context, id int64, input *UpdateSSOProviderInput) (*SSOProvider, error)

	// DeleteProvider deletes an SSO provider.
	// Also deletes all user SSO links and states for this provider.
	// Returns ErrSSOProviderNotFound if not found.
	DeleteProvider(ctx context.Context, id int64) error

	// ListProviders retrieves all SSO providers.
	// If enabledOnly is true, only returns enabled providers.
	ListProviders(ctx context.Context, enabledOnly bool) ([]SSOProvider, error)

	// ListProvidersWithStats retrieves all SSO providers with usage statistics.
	ListProvidersWithStats(ctx context.Context) ([]SSOProviderWithStats, error)

	// GetProviderCount returns the total number of SSO providers.
	GetProviderCount(ctx context.Context) (int64, error)

	// ===========================================================================
	// User SSO Link Operations
	// ===========================================================================

	// CreateLink creates a new user SSO link.
	// Returns ErrSSOLinkExists if a link already exists for this provider and external ID.
	CreateLink(ctx context.Context, input *CreateUserSSOLinkInput) (*UserSSOLink, error)

	// GetLink retrieves a user SSO link by ID.
	// Returns ErrSSOLinkNotFound if not found.
	GetLink(ctx context.Context, id int64) (*UserSSOLink, error)

	// GetLinkByExternalID retrieves a user SSO link by provider ID and external ID.
	// Returns ErrSSOLinkNotFound if not found.
	GetLinkByExternalID(ctx context.Context, providerID int64, externalID string) (*UserSSOLink, error)

	// GetLinksByUserID retrieves all SSO links for a user.
	GetLinksByUserID(ctx context.Context, userID int64) ([]UserSSOLink, error)

	// GetLinksByProviderID retrieves all SSO links for a provider.
	GetLinksByProviderID(ctx context.Context, providerID int64) ([]UserSSOLink, error)

	// UpdateLinkTokens updates the access/refresh tokens for a user SSO link.
	UpdateLinkTokens(ctx context.Context, id int64, accessToken, refreshToken string, expiresAt *time.Time) error

	// UpdateLinkLastLogin updates the last login time for a user SSO link.
	UpdateLinkLastLogin(ctx context.Context, id int64) error

	// DeleteLink deletes a user SSO link.
	// Returns ErrSSOLinkNotFound if not found.
	DeleteLink(ctx context.Context, id int64) error

	// DeleteLinksByUserID deletes all SSO links for a user.
	DeleteLinksByUserID(ctx context.Context, userID int64) error

	// DeleteLinksByProviderID deletes all SSO links for a provider.
	DeleteLinksByProviderID(ctx context.Context, providerID int64) error

	// CountLinksByProviderID returns the number of users linked to a provider.
	CountLinksByProviderID(ctx context.Context, providerID int64) (int64, error)

	// ===========================================================================
	// SSO State Operations (OAuth2 CSRF protection)
	// ===========================================================================

	// CreateState creates a new SSO state token.
	CreateState(ctx context.Context, state, nonce string, providerID int64, returnURL, createdIP string, userID *int64, expiresAt time.Time) (*SSOState, error)

	// GetState retrieves an SSO state by state value.
	// Returns ErrSSOStateNotFound if not found.
	// Returns ErrSSOStateExpired if expired.
	GetState(ctx context.Context, state string) (*SSOState, error)

	// DeleteState deletes an SSO state.
	DeleteState(ctx context.Context, state string) error

	// CleanupExpiredStates removes all expired SSO states.
	// Returns the number of states deleted.
	CleanupExpiredStates(ctx context.Context) (int64, error)

	// ===========================================================================
	// Utility Operations
	// ===========================================================================

	// GetLinkByUserAndProvider retrieves a user SSO link by user ID and provider ID.
	// Returns ErrSSOLinkNotFound if not found.
	GetLinkByUserAndProvider(ctx context.Context, userID, providerID int64) (*UserSSOLink, error)

	// FindUserByExternalEmail finds users with matching email for JIT provisioning.
	// Returns nil slice if no users found.
	FindUserByExternalEmail(ctx context.Context, email string) ([]int64, error)
}
