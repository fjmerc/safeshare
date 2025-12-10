// Package handlers provides HTTP request handlers for the SafeShare application.
package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/auth/sso"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
)

// SSOProviderInfo represents public SSO provider information for the login page.
type SSOProviderInfo struct {
	Name            string `json:"name"`
	Slug            string `json:"slug"`
	IconURL         string `json:"icon_url,omitempty"`
	ButtonColor     string `json:"button_color,omitempty"`
	ButtonTextColor string `json:"button_text_color,omitempty"`
}

// SSOProvidersResponse is the response for listing SSO providers.
type SSOProvidersResponse struct {
	Providers []SSOProviderInfo `json:"providers"`
	Enabled   bool              `json:"enabled"`
}

// SSOLinkRequest is the request body for initiating SSO account linking.
type SSOLinkRequest struct {
	ProviderSlug string `json:"provider_slug"`
	ReturnURL    string `json:"return_url,omitempty"`
}

// SSOLinkResponse is the response for SSO link initiation.
type SSOLinkResponse struct {
	AuthorizationURL string `json:"authorization_url"`
}

// generateSecureToken generates a cryptographically secure random token.
// Returns a URL-safe base64-encoded string of n random bytes.
func generateSecureToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// providerSlugRegex validates that provider slugs contain only safe characters.
// Prevents log injection and path manipulation attacks.
var providerSlugRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// extractProviderSlug extracts the provider slug from a URL path.
// For example, "/api/auth/sso/google/login" with prefix "/api/auth/sso/" returns "google".
// Returns empty string for invalid or malformed slugs.
func extractProviderSlug(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}

	// Remove the prefix
	remaining := strings.TrimPrefix(path, prefix)

	// Split by "/" and get the first segment
	parts := strings.SplitN(remaining, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}

	slug := parts[0]

	// Validate slug format (lowercase alphanumeric + hyphen, 1-64 chars)
	// This prevents log injection and path manipulation
	if len(slug) > 64 || !providerSlugRegex.MatchString(slug) {
		return ""
	}

	return slug
}

// ListSSOProvidersHandler returns a handler that lists enabled SSO providers.
// GET /api/auth/sso/providers
// Public endpoint - no authentication required.
func ListSSOProvidersHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Check if SSO is globally enabled
		ssoEnabled := cfg.SSO != nil && cfg.SSO.Enabled

		response := SSOProvidersResponse{
			Providers: []SSOProviderInfo{},
			Enabled:   ssoEnabled,
		}

		if !ssoEnabled {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		// Get enabled providers from repository
		providers, err := repos.SSO.ListProviders(ctx, true) // enabledOnly=true
		if err != nil {
			slog.Error("failed to list SSO providers", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Convert to public info (hide sensitive fields)
		for _, p := range providers {
			response.Providers = append(response.Providers, SSOProviderInfo{
				Name:            p.Name,
				Slug:            p.Slug,
				IconURL:         p.IconURL,
				ButtonColor:     p.ButtonColor,
				ButtonTextColor: p.ButtonTextColor,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// SSOLoginHandler returns a handler that initiates the SSO login flow.
// GET /api/auth/sso/{provider}/login
// Redirects the user to the identity provider's authorization endpoint.
func SSOLoginHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Check if SSO is globally enabled
		if cfg.SSO == nil || !cfg.SSO.Enabled {
			slog.Warn("SSO login attempt but SSO is disabled", "ip", clientIP)
			http.Error(w, "SSO is not enabled", http.StatusForbidden)
			return
		}

		// Extract provider slug from URL path
		providerSlug := extractProviderSlug(r.URL.Path, "/api/auth/sso/")
		if providerSlug == "" {
			http.Error(w, "Invalid provider", http.StatusBadRequest)
			return
		}

		// Get the enabled provider by slug
		provider, err := repos.SSO.GetEnabledProviderBySlug(ctx, providerSlug)
		if err != nil {
			if errors.Is(err, repository.ErrSSOProviderNotFound) {
				slog.Warn("SSO login attempt for unknown provider",
					"provider", providerSlug,
					"ip", clientIP,
				)
				http.Error(w, "Provider not found", http.StatusNotFound)
				return
			}
			if errors.Is(err, repository.ErrSSOProviderDisabled) {
				slog.Warn("SSO login attempt for disabled provider",
					"provider", providerSlug,
					"ip", clientIP,
				)
				http.Error(w, "Provider is disabled", http.StatusForbidden)
				return
			}
			slog.Error("failed to get SSO provider",
				"provider", providerSlug,
				"error", err,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Create OIDC provider instance
		oidcProvider, err := sso.NewOIDCProvider(ctx, provider, repos.SSO)
		if err != nil {
			slog.Error("failed to create OIDC provider",
				"provider", providerSlug,
				"error", err,
			)
			http.Error(w, "Failed to initialize SSO provider", http.StatusInternalServerError)
			return
		}

		// Generate cryptographically secure state and nonce
		state, err := generateSecureToken(32)
		if err != nil {
			slog.Error("failed to generate state", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		nonce, err := generateSecureToken(32)
		if err != nil {
			slog.Error("failed to generate nonce", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get optional return URL from query parameter
		returnURL := r.URL.Query().Get("return_url")
		if returnURL == "" {
			returnURL = "/dashboard"
		}

		// Generate authorization URL (also stores state in database)
		authURL, err := oidcProvider.GetAuthorizationURL(
			ctx,
			state,
			nonce,
			returnURL,
			clientIP,
			nil, // No user ID - this is a new login
			cfg.SSO.StateExpiryMinutes,
		)
		if err != nil {
			slog.Error("failed to generate authorization URL",
				"provider", providerSlug,
				"error", err,
			)
			http.Error(w, "Failed to initiate SSO login", http.StatusInternalServerError)
			return
		}

		slog.Info("SSO login initiated",
			"provider", providerSlug,
			"ip", clientIP,
		)

		// Redirect to identity provider
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// SSOCallbackHandler returns a handler that processes the SSO callback from the identity provider.
// GET /api/auth/sso/{provider}/callback
// Handles the OAuth2 callback, validates tokens, and creates/links user accounts.
func SSOCallbackHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)
		userAgent := getUserAgent(r)

		// Check if SSO is globally enabled
		if cfg.SSO == nil || !cfg.SSO.Enabled {
			slog.Warn("SSO callback received but SSO is disabled", "ip", clientIP)
			http.Error(w, "SSO is not enabled", http.StatusForbidden)
			return
		}

		// Extract provider slug from URL path
		providerSlug := extractProviderSlug(r.URL.Path, "/api/auth/sso/")
		if providerSlug == "" {
			http.Error(w, "Invalid provider", http.StatusBadRequest)
			return
		}

		// Get authorization code and state from query parameters
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		// Check for error response from IdP - URL encode to prevent XSS
		if errorCode := r.URL.Query().Get("error"); errorCode != "" {
			errorDesc := r.URL.Query().Get("error_description")
			slog.Warn("SSO callback received error from IdP",
				"provider", providerSlug,
				"error", errorCode,
				"description", errorDesc,
				"ip", clientIP,
			)
			// Redirect to login with URL-encoded error message to prevent XSS
			http.Redirect(w, r, "/login?error=sso_failed&message="+url.QueryEscape(errorCode), http.StatusFound)
			return
		}

		if code == "" {
			slog.Warn("SSO callback missing authorization code",
				"provider", providerSlug,
				"ip", clientIP,
			)
			http.Redirect(w, r, "/login?error=missing_code", http.StatusFound)
			return
		}

		if state == "" {
			slog.Warn("SSO callback missing state parameter",
				"provider", providerSlug,
				"ip", clientIP,
			)
			http.Redirect(w, r, "/login?error=missing_state", http.StatusFound)
			return
		}

		// Get the enabled provider by slug
		provider, err := repos.SSO.GetEnabledProviderBySlug(ctx, providerSlug)
		if err != nil {
			slog.Error("SSO callback for invalid provider",
				"provider", providerSlug,
				"error", err,
				"ip", clientIP,
			)
			http.Redirect(w, r, "/login?error=invalid_provider", http.StatusFound)
			return
		}

		// Create OIDC provider instance
		oidcProvider, err := sso.NewOIDCProvider(ctx, provider, repos.SSO)
		if err != nil {
			slog.Error("failed to create OIDC provider for callback",
				"provider", providerSlug,
				"error", err,
			)
			http.Redirect(w, r, "/login?error=provider_error", http.StatusFound)
			return
		}

		// Exchange authorization code for tokens (validates state and nonce internally)
		token, idToken, ssoState, err := oidcProvider.ExchangeCodeForToken(ctx, code, state)
		if err != nil {
			slog.Warn("SSO token exchange failed",
				"provider", providerSlug,
				"error", err,
				"ip", clientIP,
			)
			http.Redirect(w, r, "/login?error=token_exchange_failed", http.StatusFound)
			return
		}

		// Get user info from ID token
		userInfo, err := oidcProvider.GetUserInfoFromIDToken(idToken)
		if err != nil {
			slog.Error("failed to get user info from ID token",
				"provider", providerSlug,
				"error", err,
			)
			http.Redirect(w, r, "/login?error=userinfo_failed", http.StatusFound)
			return
		}

		// Validate email domain if allowlist is configured
		if err := oidcProvider.ValidateEmailDomain(userInfo.Email); err != nil {
			slog.Warn("SSO login rejected - email domain not allowed",
				"provider", providerSlug,
				"ip", clientIP,
			)
			http.Redirect(w, r, "/login?error=domain_not_allowed", http.StatusFound)
			return
		}

		// Process the SSO authentication
		user, isNewUser, err := processSSOAuthentication(ctx, repos, cfg, provider, userInfo, token, ssoState)
		if err != nil {
			slog.Error("SSO authentication processing failed",
				"provider", providerSlug,
				"error", err,
				"ip", clientIP,
			)
			http.Redirect(w, r, "/login?error=auth_failed", http.StatusFound)
			return
		}

		// Check if user is active
		if !user.IsActive {
			slog.Warn("SSO login failed - account disabled",
				"provider", providerSlug,
				"user_id", user.ID,
				"username", user.Username,
				"ip", clientIP,
			)
			http.Redirect(w, r, "/login?error=account_disabled", http.StatusFound)
			return
		}

		// Create SafeShare session
		sessionToken, err := utils.GenerateSessionToken()
		if err != nil {
			slog.Error("failed to generate session token", "error", err)
			http.Redirect(w, r, "/login?error=session_error", http.StatusFound)
			return
		}

		// Calculate session expiry
		sessionExpiryHours := cfg.SessionExpiryHours
		if cfg.SSO.SessionLifetime > 0 {
			// Use SSO-specific session lifetime (in minutes, convert to hours)
			sessionExpiryHours = cfg.SSO.SessionLifetime / 60
			if sessionExpiryHours < 1 {
				sessionExpiryHours = 1
			}
		}
		expiresAt := time.Now().Add(time.Duration(sessionExpiryHours) * time.Hour)

		// Store session in repository
		if err := repos.Users.CreateSession(ctx, user.ID, sessionToken, expiresAt, clientIP, userAgent); err != nil {
			slog.Error("failed to create user session", "error", err)
			http.Redirect(w, r, "/login?error=session_error", http.StatusFound)
			return
		}

		// Update last login timestamp
		if err := repos.Users.UpdateLastLogin(ctx, user.ID); err != nil {
			slog.Error("failed to update last login", "error", err)
			// Don't fail - continue with login
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "user_session",
			Value:    sessionToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   cfg.HTTPSEnabled,
			SameSite: http.SameSiteLaxMode, // Lax mode to allow redirect from IdP
			Expires:  expiresAt,
		})

		// Set user CSRF cookie
		if _, err := middleware.SetUserCSRFCookie(w, cfg); err != nil {
			slog.Error("failed to set user CSRF cookie", "error", err)
			// Continue anyway - not critical for login success
		}

		if isNewUser {
			slog.Info("SSO login successful - new user created",
				"provider", providerSlug,
				"user_id", user.ID,
				"username", user.Username,
				"ip", clientIP,
			)
		} else {
			slog.Info("SSO login successful",
				"provider", providerSlug,
				"user_id", user.ID,
				"username", user.Username,
				"ip", clientIP,
			)
		}

		// Redirect to return URL or dashboard
		returnURL := "/dashboard"
		if ssoState != nil && ssoState.ReturnURL != "" {
			returnURL = ssoState.ReturnURL
		}

		http.Redirect(w, r, returnURL, http.StatusFound)
	}
}

// processSSOAuthentication handles user lookup/creation and SSO link management.
// Returns the user, whether a new user was created, and any error.
func processSSOAuthentication(
	ctx context.Context,
	repos *repository.Repositories,
	cfg *config.Config,
	provider *repository.SSOProvider,
	userInfo *sso.UserInfo,
	token interface{}, // *oauth2.Token - keeping as interface to avoid import cycle
	ssoState *repository.SSOState,
) (*models.User, bool, error) {
	// Check if this SSO identity is already linked to a user
	existingLink, err := repos.SSO.GetLinkByExternalID(ctx, provider.ID, userInfo.Subject)
	if err != nil && !errors.Is(err, repository.ErrSSOLinkNotFound) {
		return nil, false, fmt.Errorf("failed to check existing SSO link: %w", err)
	}

	// Case 1: Existing SSO link found - get the linked user
	if existingLink != nil {
		// Update last login time on the link
		if err := repos.SSO.UpdateLinkLastLogin(ctx, existingLink.ID); err != nil {
			slog.Error("failed to update SSO link last login", "error", err)
			// Continue anyway
		}

		// Get the user by ID
		user, err := repos.Users.GetByID(ctx, existingLink.UserID)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get linked user: %w", err)
		}
		if user == nil {
			return nil, false, fmt.Errorf("linked user not found (ID: %d)", existingLink.UserID)
		}

		return user, false, nil
	}

	// Case 2: Linking existing account (user was already authenticated)
	if ssoState != nil && ssoState.UserID != nil {
		userID := *ssoState.UserID

		// Get the user
		user, err := repos.Users.GetByID(ctx, userID)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get user for linking: %w", err)
		}
		if user == nil {
			return nil, false, fmt.Errorf("user not found for linking (ID: %d)", userID)
		}

		// Check if user already has a link to this provider
		existingUserLink, err := repos.SSO.GetLinkByUserAndProvider(ctx, userID, provider.ID)
		if err != nil && !errors.Is(err, repository.ErrSSOLinkNotFound) {
			return nil, false, fmt.Errorf("failed to check existing user-provider link: %w", err)
		}
		if existingUserLink != nil {
			return nil, false, fmt.Errorf("user already linked to this provider")
		}

		// Create the SSO link
		linkInput := &repository.CreateUserSSOLinkInput{
			UserID:        userID,
			ProviderID:    provider.ID,
			ExternalID:    userInfo.Subject,
			ExternalEmail: userInfo.Email,
			ExternalName:  userInfo.Name,
		}

		if _, err := repos.SSO.CreateLink(ctx, linkInput); err != nil {
			return nil, false, fmt.Errorf("failed to create SSO link: %w", err)
		}

		slog.Info("SSO account linked",
			"user_id", userID,
			"provider_id", provider.ID,
			"external_id", userInfo.Subject,
		)

		return user, false, nil
	}

	// Case 3: JIT (Just-In-Time) user provisioning
	autoProvision := provider.AutoProvision
	if cfg.SSO != nil && cfg.SSO.AutoProvision {
		autoProvision = true // Global override
	}

	if !autoProvision {
		return nil, false, fmt.Errorf("SSO auto-provisioning is disabled and no linked account exists")
	}

	// Security consideration: Email-based linking
	// We require the IdP to have verified the email to prevent account takeover
	// If the IdP hasn't verified the email, we only create new accounts, not link to existing ones
	emailVerified := userInfo.Verified

	// Try to find an existing user by email (only if email is verified by IdP)
	var existingUserIDs []int64
	if emailVerified {
		existingUserIDs, err = repos.SSO.FindUserByExternalEmail(ctx, userInfo.Email)
		if err != nil {
			return nil, false, fmt.Errorf("failed to find user by email: %w", err)
		}
	}

	var user *models.User
	var isNewUser bool

	if len(existingUserIDs) > 0 && emailVerified {
		// Found existing user with matching verified email - link and use that user
		userID := existingUserIDs[0]
		existingUser, err := repos.Users.GetByID(ctx, userID)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get existing user by ID: %w", err)
		}
		if existingUser == nil {
			return nil, false, fmt.Errorf("existing user not found by ID")
		}

		user = existingUser
		isNewUser = false

		slog.Info("SSO linking to existing user by verified email",
			"user_id", user.ID,
		)
	} else {
		// No existing user (or unverified email) - create a new one
		username := generateUsernameFromEmail(userInfo.Email, userInfo.Name)

		// Determine role
		role := "user"
		if provider.DefaultRole != "" {
			role = provider.DefaultRole
		}
		if cfg.SSO != nil && cfg.SSO.DefaultRole != "" {
			role = cfg.SSO.DefaultRole
		}

		// Generate a random password (SSO users don't need to know it)
		randomPassword, err := generateSecureToken(32)
		if err != nil {
			return nil, false, fmt.Errorf("failed to generate random password: %w", err)
		}

		passwordHash, err := utils.HashPassword(randomPassword)
		if err != nil {
			return nil, false, fmt.Errorf("failed to hash password: %w", err)
		}

		// Create the user
		newUser, err := repos.Users.Create(ctx, username, userInfo.Email, passwordHash, role, false)
		if err != nil {
			return nil, false, fmt.Errorf("failed to create user: %w", err)
		}

		user = newUser
		isNewUser = true

		slog.Info("SSO user provisioned",
			"user_id", user.ID,
			"username", user.Username,
			"role", role,
		)
	}

	// Create SSO link for the user
	linkInput := &repository.CreateUserSSOLinkInput{
		UserID:        user.ID,
		ProviderID:    provider.ID,
		ExternalID:    userInfo.Subject,
		ExternalEmail: userInfo.Email,
		ExternalName:  userInfo.Name,
	}

	link, err := repos.SSO.CreateLink(ctx, linkInput)
	if err != nil {
		// If link creation fails but user was created, we still have a problem
		// but the user can try again and it should work
		return nil, false, fmt.Errorf("failed to create SSO link: %w", err)
	}

	// Update link last login
	if err := repos.SSO.UpdateLinkLastLogin(ctx, link.ID); err != nil {
		slog.Error("failed to update SSO link last login", "error", err)
		// Continue anyway
	}

	return user, isNewUser, nil
}

// generateUsernameFromEmail generates a username from email or display name.
func generateUsernameFromEmail(email, displayName string) string {
	// Try display name first (sanitized)
	if displayName != "" {
		// Remove spaces and special characters, lowercase
		username := strings.ToLower(displayName)
		username = strings.ReplaceAll(username, " ", "_")
		// Keep only alphanumeric and underscore
		var sanitized strings.Builder
		for _, r := range username {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
				sanitized.WriteRune(r)
			}
		}
		if sanitized.Len() >= 3 {
			return sanitized.String()
		}
	}

	// Fall back to email prefix
	parts := strings.Split(email, "@")
	if len(parts) > 0 && len(parts[0]) >= 3 {
		return strings.ToLower(parts[0])
	}

	// Last resort: generate random username
	random, _ := generateSecureToken(8)
	return "user_" + random[:8]
}

// SSOLinkAccountHandler returns a handler that initiates SSO account linking for an authenticated user.
// POST /api/auth/sso/link
// Requires user authentication. Links the current user's account to an SSO provider.
func SSOLinkAccountHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Check if SSO is globally enabled
		if cfg.SSO == nil || !cfg.SSO.Enabled {
			slog.Warn("SSO link attempt but SSO is disabled", "ip", clientIP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "SSO is not enabled",
			})
			return
		}

		// Get authenticated user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Limit JSON request body size
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

		// Parse request
		var req SSOLinkRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error("failed to parse SSO link request", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate provider slug
		if req.ProviderSlug == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Provider slug is required",
			})
			return
		}

		// Get the enabled provider
		provider, err := repos.SSO.GetEnabledProviderBySlug(ctx, req.ProviderSlug)
		if err != nil {
			if errors.Is(err, repository.ErrSSOProviderNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Provider not found",
				})
				return
			}
			if errors.Is(err, repository.ErrSSOProviderDisabled) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Provider is disabled",
				})
				return
			}
			slog.Error("failed to get SSO provider",
				"provider", req.ProviderSlug,
				"error", err,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Check if user already has a link to this provider
		existingLink, err := repos.SSO.GetLinkByUserAndProvider(ctx, user.ID, provider.ID)
		if err != nil && !errors.Is(err, repository.ErrSSOLinkNotFound) {
			slog.Error("failed to check existing SSO link",
				"user_id", user.ID,
				"provider_id", provider.ID,
				"error", err,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if existingLink != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Account is already linked to this provider",
			})
			return
		}

		// Create OIDC provider instance
		oidcProvider, err := sso.NewOIDCProvider(ctx, provider, repos.SSO)
		if err != nil {
			slog.Error("failed to create OIDC provider",
				"provider", req.ProviderSlug,
				"error", err,
			)
			http.Error(w, "Failed to initialize SSO provider", http.StatusInternalServerError)
			return
		}

		// Generate cryptographically secure state and nonce
		state, err := generateSecureToken(32)
		if err != nil {
			slog.Error("failed to generate state", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		nonce, err := generateSecureToken(32)
		if err != nil {
			slog.Error("failed to generate nonce", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Set return URL
		returnURL := req.ReturnURL
		if returnURL == "" {
			returnURL = "/dashboard"
		}

		// Store user ID in state for account linking
		userID := user.ID

		// Generate authorization URL (also stores state in database)
		authURL, err := oidcProvider.GetAuthorizationURL(
			ctx,
			state,
			nonce,
			returnURL,
			clientIP,
			&userID, // Include user ID for linking
			cfg.SSO.StateExpiryMinutes,
		)
		if err != nil {
			slog.Error("failed to generate authorization URL for linking",
				"provider", req.ProviderSlug,
				"user_id", user.ID,
				"error", err,
			)
			http.Error(w, "Failed to initiate SSO linking", http.StatusInternalServerError)
			return
		}

		slog.Info("SSO account linking initiated",
			"provider", req.ProviderSlug,
			"user_id", user.ID,
			"username", user.Username,
			"ip", clientIP,
		)

		// Return the authorization URL for the frontend to redirect
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(SSOLinkResponse{
			AuthorizationURL: authURL,
		})
	}
}

// SSOUnlinkAccountHandler returns a handler that unlinks an SSO provider from a user account.
// DELETE /api/auth/sso/link/{provider}
// Requires user authentication. Removes the SSO link for the current user.
func SSOUnlinkAccountHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Check if SSO is globally enabled
		if cfg.SSO == nil || !cfg.SSO.Enabled {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "SSO is not enabled",
			})
			return
		}

		// Get authenticated user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract provider slug from URL path
		// Expected path: /api/auth/sso/link/{provider}
		providerSlug := strings.TrimPrefix(r.URL.Path, "/api/auth/sso/link/")
		if providerSlug == "" || providerSlug == r.URL.Path {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Provider slug is required",
			})
			return
		}

		// Get the provider
		provider, err := repos.SSO.GetProviderBySlug(ctx, providerSlug)
		if err != nil {
			if errors.Is(err, repository.ErrSSOProviderNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Provider not found",
				})
				return
			}
			slog.Error("failed to get SSO provider",
				"provider", providerSlug,
				"error", err,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get the SSO link
		link, err := repos.SSO.GetLinkByUserAndProvider(ctx, user.ID, provider.ID)
		if err != nil {
			if errors.Is(err, repository.ErrSSOLinkNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Account is not linked to this provider",
				})
				return
			}
			slog.Error("failed to get SSO link",
				"user_id", user.ID,
				"provider_id", provider.ID,
				"error", err,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Delete the link
		if err := repos.SSO.DeleteLink(ctx, link.ID); err != nil {
			slog.Error("failed to delete SSO link",
				"link_id", link.ID,
				"error", err,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("SSO account unlinked",
			"provider", providerSlug,
			"user_id", user.ID,
			"username", user.Username,
			"ip", clientIP,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "SSO link removed successfully",
		})
	}
}

// SSOGetLinkedProvidersHandler returns a handler that lists SSO providers linked to the current user.
// GET /api/auth/sso/linked
// Requires user authentication.
func SSOGetLinkedProvidersHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Check if SSO is globally enabled
		if cfg.SSO == nil || !cfg.SSO.Enabled {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "SSO is not enabled",
			})
			return
		}

		// Get authenticated user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get user's SSO links
		links, err := repos.SSO.GetLinksByUserID(ctx, user.ID)
		if err != nil {
			slog.Error("failed to get user SSO links",
				"user_id", user.ID,
				"error", err,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Build response with provider info
		type LinkedProvider struct {
			ProviderSlug  string     `json:"provider_slug"`
			ProviderName  string     `json:"provider_name"`
			ExternalEmail string     `json:"external_email,omitempty"`
			ExternalName  string     `json:"external_name,omitempty"`
			LinkedAt      time.Time  `json:"linked_at"`
			LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
		}

		linkedProviders := []LinkedProvider{}

		for _, link := range links {
			// Get provider info
			provider, err := repos.SSO.GetProvider(ctx, link.ProviderID)
			if err != nil {
				slog.Error("failed to get provider for link",
					"provider_id", link.ProviderID,
					"error", err,
				)
				continue
			}

			linkedProviders = append(linkedProviders, LinkedProvider{
				ProviderSlug:  provider.Slug,
				ProviderName:  provider.Name,
				ExternalEmail: link.ExternalEmail,
				ExternalName:  link.ExternalName,
				LinkedAt:      link.CreatedAt,
				LastLoginAt:   link.LastLoginAt,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"linked_providers": linkedProviders,
		})
	}
}
