// Package sso provides Single Sign-On authentication providers.
package sso

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/fjmerc/safeshare/internal/repository"
)

// UserInfo represents standardized user claims from an OIDC provider.
type UserInfo struct {
	Subject  string // "sub" claim - unique user identifier
	Email    string // User's email address
	Name     string // User's display name
	Verified bool   // Email verification status
}

// OIDCProvider handles OIDC authentication for an SSO provider.
type OIDCProvider struct {
	provider     *repository.SSOProvider
	oidcProvider *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config *oauth2.Config
	repo         repository.SSORepository
}

// NewOIDCProvider creates a new OIDC provider instance with discovery.
// Uses provider.IssuerURL for OIDC discovery (/.well-known/openid-configuration).
// If custom endpoints are set (AuthorizationURL, TokenURL, UserinfoURL), they override discovery.
func NewOIDCProvider(ctx context.Context, provider *repository.SSOProvider, repo repository.SSORepository) (*OIDCProvider, error) {
	if provider == nil {
		return nil, fmt.Errorf("provider cannot be nil")
	}

	if provider.IssuerURL == "" {
		return nil, fmt.Errorf("issuer URL is required for OIDC provider")
	}

	// Validate issuer URL scheme (must be HTTPS in production)
	if err := validateOIDCURL(provider.IssuerURL, "issuer URL"); err != nil {
		return nil, err
	}

	// Validate redirect URL scheme if provided
	if provider.RedirectURL != "" {
		if err := validateOIDCURL(provider.RedirectURL, "redirect URL"); err != nil {
			return nil, err
		}
	}

	if provider.ClientID == "" {
		return nil, fmt.Errorf("client ID is required for OIDC provider")
	}

	// Perform OIDC discovery
	oidcProvider, err := oidc.NewProvider(ctx, provider.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to perform OIDC discovery for %s: %w", provider.IssuerURL, err)
	}

	// Create ID token verifier
	verifier := oidcProvider.Verifier(&oidc.Config{
		ClientID: provider.ClientID,
	})

	// Build OAuth2 endpoint from discovery or custom endpoints
	endpoint := oidcProvider.Endpoint()
	if provider.AuthorizationURL != "" {
		endpoint.AuthURL = provider.AuthorizationURL
	}
	if provider.TokenURL != "" {
		endpoint.TokenURL = provider.TokenURL
	}

	// Parse scopes
	scopes := []string{oidc.ScopeOpenID}
	if provider.Scopes != "" {
		for _, scope := range strings.Split(provider.Scopes, " ") {
			scope = strings.TrimSpace(scope)
			if scope != "" && scope != oidc.ScopeOpenID {
				scopes = append(scopes, scope)
			}
		}
	} else {
		// Default scopes if none specified
		scopes = append(scopes, "profile", "email")
	}

	// Build OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		Endpoint:     endpoint,
		Scopes:       scopes,
		RedirectURL:  provider.RedirectURL,
	}

	return &OIDCProvider{
		provider:     provider,
		oidcProvider: oidcProvider,
		verifier:     verifier,
		oauth2Config: oauth2Config,
		repo:         repo,
	}, nil
}

// GetProvider returns the underlying SSO provider configuration.
func (p *OIDCProvider) GetProvider() *repository.SSOProvider {
	return p.provider
}

// GetAuthorizationURL generates OAuth2 authorization URL with state/nonce.
// Creates SSO state in database for CSRF protection.
// Returns authorization URL and error.
func (p *OIDCProvider) GetAuthorizationURL(ctx context.Context, state, nonce, returnURL, clientIP string, userID *int64, stateExpiryMinutes int) (string, error) {
	if state == "" {
		return "", fmt.Errorf("state is required")
	}

	if nonce == "" {
		return "", fmt.Errorf("nonce is required")
	}

	// Calculate state expiry time
	expiresAt := time.Now().Add(time.Duration(stateExpiryMinutes) * time.Minute)

	// Create state in database for CSRF protection
	_, err := p.repo.CreateState(ctx, state, nonce, p.provider.ID, returnURL, clientIP, userID, expiresAt)
	if err != nil {
		return "", fmt.Errorf("failed to create SSO state: %w", err)
	}

	// Generate authorization URL with state and nonce
	authURL := p.oauth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
	)

	return authURL, nil
}

// ExchangeCodeForToken exchanges authorization code for tokens.
// Validates state and verifies ID token signature/claims.
// Returns access token, ID token claims, and error.
func (p *OIDCProvider) ExchangeCodeForToken(ctx context.Context, code, state string) (*oauth2.Token, *oidc.IDToken, *repository.SSOState, error) {
	if code == "" {
		return nil, nil, nil, fmt.Errorf("authorization code is required")
	}

	if state == "" {
		return nil, nil, nil, fmt.Errorf("state is required")
	}

	// Retrieve and validate state from database
	ssoState, err := p.repo.GetState(ctx, state)
	if err != nil {
		if err == repository.ErrSSOStateNotFound {
			return nil, nil, nil, fmt.Errorf("invalid state: %w", err)
		}
		if err == repository.ErrSSOStateExpired {
			// Clean up expired state
			_ = p.repo.DeleteState(ctx, state)
			return nil, nil, nil, fmt.Errorf("state has expired: %w", err)
		}
		return nil, nil, nil, fmt.Errorf("failed to validate state: %w", err)
	}

	// Verify state belongs to this provider
	if ssoState.ProviderID != p.provider.ID {
		_ = p.repo.DeleteState(ctx, state)
		return nil, nil, nil, fmt.Errorf("state does not belong to this provider")
	}

	// Delete state immediately (one-time use)
	if err := p.repo.DeleteState(ctx, state); err != nil {
		// Log but don't fail - state validation succeeded
		// The cleanup job will remove it eventually
	}

	// Exchange authorization code for tokens
	token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Extract raw ID token from response
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("no id_token in token response")
	}

	// Verify ID token
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Verify nonce to prevent replay attacks using constant-time comparison
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(ssoState.Nonce)) != 1 {
		return nil, nil, nil, fmt.Errorf("nonce mismatch: ID token nonce does not match expected value")
	}

	return token, idToken, ssoState, nil
}

// GetUserInfo retrieves user profile information from provider.
// Returns standardized user claims: sub, email, name.
func (p *OIDCProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	if token == nil {
		return nil, fmt.Errorf("token is required")
	}

	// Create token source for API calls
	tokenSource := p.oauth2Config.TokenSource(ctx, token)

	// Fetch user info from provider
	userInfo, err := p.oidcProvider.UserInfo(ctx, tokenSource)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Parse claims into struct
	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
	}

	if err := userInfo.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse user info claims: %w", err)
	}

	// Build display name from available claims
	name := claims.Name
	if name == "" {
		if claims.GivenName != "" || claims.FamilyName != "" {
			name = strings.TrimSpace(claims.GivenName + " " + claims.FamilyName)
		}
	}

	return &UserInfo{
		Subject:  userInfo.Subject,
		Email:    claims.Email,
		Name:     name,
		Verified: claims.EmailVerified,
	}, nil
}

// GetUserInfoFromIDToken extracts user info directly from the ID token claims.
// Use this when you don't need to make an additional userinfo endpoint call.
func (p *OIDCProvider) GetUserInfoFromIDToken(idToken *oidc.IDToken) (*UserInfo, error) {
	if idToken == nil {
		return nil, fmt.Errorf("ID token is required")
	}

	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	// Build display name from available claims
	name := claims.Name
	if name == "" {
		if claims.GivenName != "" || claims.FamilyName != "" {
			name = strings.TrimSpace(claims.GivenName + " " + claims.FamilyName)
		}
	}

	return &UserInfo{
		Subject:  claims.Sub,
		Email:    claims.Email,
		Name:     name,
		Verified: claims.EmailVerified,
	}, nil
}

// RefreshToken refreshes an expired access token using refresh token.
// Returns new OAuth2 token with updated access token and expiry.
func (p *OIDCProvider) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	// Create a token with just the refresh token
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	// Create token source that will refresh the token
	tokenSource := p.oauth2Config.TokenSource(ctx, token)

	// Get new token (this triggers the refresh)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return newToken, nil
}

// ValidateEmailDomain checks if user's email domain is allowed.
// Returns ErrEmailDomainNotAllowed if domain not in provider's allowlist.
// Returns nil if no domain allowlist is configured (all domains allowed).
func (p *OIDCProvider) ValidateEmailDomain(email string) error {
	// If no domain allowlist is configured, all domains are allowed
	if p.provider.DomainAllowlist == "" {
		return nil
	}

	// Normalize email
	email = strings.TrimSpace(email)

	// Extract domain from email
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid email format")
	}

	// Normalize domain: lowercase, remove trailing dot
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parts[1]), "."))

	// Parse domain allowlist
	allowedDomains := strings.Split(p.provider.DomainAllowlist, ",")
	for _, allowed := range allowedDomains {
		allowed = strings.TrimSpace(strings.ToLower(allowed))
		if allowed == "" {
			continue
		}
		if domain == allowed {
			return nil
		}
	}

	return repository.ErrEmailDomainNotAllowed
}

// GetScopes returns the configured OAuth2 scopes.
func (p *OIDCProvider) GetScopes() []string {
	return p.oauth2Config.Scopes
}

// GetRedirectURL returns the configured redirect URL.
func (p *OIDCProvider) GetRedirectURL() string {
	return p.oauth2Config.RedirectURL
}

// validateOIDCURL validates that a URL uses HTTPS scheme (or HTTP for localhost).
// This prevents SSRF attacks and ensures secure communication with identity providers.
func validateOIDCURL(urlStr, fieldName string) error {
	if urlStr == "" {
		return nil
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid %s: %v", fieldName, err)
	}

	// HTTPS is required in production
	if parsed.Scheme == "https" {
		return nil
	}

	// Allow HTTP only for localhost development
	if parsed.Scheme == "http" {
		host := parsed.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}

	return fmt.Errorf("%s must use HTTPS scheme (HTTP allowed only for localhost)", fieldName)
}
