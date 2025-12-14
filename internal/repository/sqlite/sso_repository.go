package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
)

// SSORepository implements repository.SSORepository for SQLite.
type SSORepository struct {
	db *sql.DB
}

// NewSSORepository creates a new SQLite SSO repository.
func NewSSORepository(db *sql.DB) *SSORepository {
	return &SSORepository{db: db}
}

// Input validation constants for SSO.
const (
	maxSSONameLen         = 100  // Maximum length for provider name
	maxSSOSlugLen         = 50   // Maximum length for provider slug
	maxSSOClientIDLen     = 256  // Maximum length for client ID
	maxSSOClientSecretLen = 1024 // Maximum length for encrypted client secret
	maxSSOURLLen          = 2048 // Maximum length for URLs
	maxSSOScopesLen       = 500  // Maximum length for scopes
	maxSSOStateLen        = 128  // Maximum length for state token
	maxSSONonceLen        = 128  // Maximum length for nonce
	maxSSOExternalIDLen   = 256  // Maximum length for external ID
	maxSSOIPLen           = 64   // Maximum length for IP address
)

// ValidRoles defines the allowed values for DefaultRole.
var ValidRoles = map[string]bool{
	"user":  true,
	"admin": true,
}

// Validation patterns for SSO fields.
var (
	// slugPattern validates slug format: lowercase alphanumeric with hyphens, must start/end with alphanumeric
	slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

	// hexColorPattern validates hex color format: #RRGGBB
	hexColorPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
)

// ===========================================================================
// SSO Provider Operations
// ===========================================================================

// CreateProvider creates a new SSO provider.
func (r *SSORepository) CreateProvider(ctx context.Context, input *repository.CreateSSOProviderInput) (*repository.SSOProvider, error) {
	if err := r.validateProviderInput(input); err != nil {
		return nil, err
	}

	query := `
		INSERT INTO sso_providers (
			name, slug, type, enabled,
			client_id, client_secret, issuer_url,
			authorization_url, token_url, userinfo_url, jwks_url,
			scopes, redirect_url,
			auto_provision, default_role, domain_allowlist,
			icon_url, button_color, button_text_color, display_order,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`

	result, err := r.db.ExecContext(ctx, query,
		input.Name, input.Slug, string(input.Type), input.Enabled,
		input.ClientID, input.ClientSecret, input.IssuerURL,
		nullIfEmpty(input.AuthorizationURL), nullIfEmpty(input.TokenURL), nullIfEmpty(input.UserinfoURL), nullIfEmpty(input.JWKSURL),
		input.Scopes, nullIfEmpty(input.RedirectURL),
		input.AutoProvision, input.DefaultRole, nullIfEmpty(input.DomainAllowlist),
		nullIfEmpty(input.IconURL), nullIfEmpty(input.ButtonColor), nullIfEmpty(input.ButtonTextColor), input.DisplayOrder,
	)

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: sso_providers.slug") {
			return nil, repository.ErrSSOProviderSlugExists
		}
		if strings.Contains(err.Error(), "UNIQUE constraint failed: sso_providers.name") {
			return nil, fmt.Errorf("provider name already exists")
		}
		return nil, fmt.Errorf("failed to create SSO provider: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get provider ID: %w", err)
	}

	return r.GetProvider(ctx, id)
}

// GetProvider retrieves an SSO provider by ID.
func (r *SSORepository) GetProvider(ctx context.Context, id int64) (*repository.SSOProvider, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid provider ID")
	}

	provider := &repository.SSOProvider{}
	var (
		authURL, tokenURL, userinfoURL, jwksURL sql.NullString
		redirectURL, domainAllowlist            sql.NullString
		iconURL, buttonColor, buttonTextColor   sql.NullString
	)

	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, slug, type, enabled,
			client_id, client_secret, issuer_url,
			authorization_url, token_url, userinfo_url, jwks_url,
			scopes, redirect_url,
			auto_provision, default_role, domain_allowlist,
			icon_url, button_color, button_text_color, display_order,
			created_at, updated_at
		FROM sso_providers WHERE id = ?`, id).Scan(
		&provider.ID, &provider.Name, &provider.Slug, &provider.Type, &provider.Enabled,
		&provider.ClientID, &provider.ClientSecret, &provider.IssuerURL,
		&authURL, &tokenURL, &userinfoURL, &jwksURL,
		&provider.Scopes, &redirectURL,
		&provider.AutoProvision, &provider.DefaultRole, &domainAllowlist,
		&iconURL, &buttonColor, &buttonTextColor, &provider.DisplayOrder,
		&provider.CreatedAt, &provider.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, repository.ErrSSOProviderNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO provider: %w", err)
	}

	provider.AuthorizationURL = authURL.String
	provider.TokenURL = tokenURL.String
	provider.UserinfoURL = userinfoURL.String
	provider.JWKSURL = jwksURL.String
	provider.RedirectURL = redirectURL.String
	provider.DomainAllowlist = domainAllowlist.String
	provider.IconURL = iconURL.String
	provider.ButtonColor = buttonColor.String
	provider.ButtonTextColor = buttonTextColor.String

	return provider, nil
}

// GetProviderBySlug retrieves an SSO provider by slug.
func (r *SSORepository) GetProviderBySlug(ctx context.Context, slug string) (*repository.SSOProvider, error) {
	if slug == "" || len(slug) > maxSSOSlugLen {
		return nil, fmt.Errorf("invalid slug")
	}

	var id int64
	err := r.db.QueryRowContext(ctx, "SELECT id FROM sso_providers WHERE slug = ?", slug).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, repository.ErrSSOProviderNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO provider by slug: %w", err)
	}

	return r.GetProvider(ctx, id)
}

// GetEnabledProviderBySlug retrieves an SSO provider by slug, ensuring it's enabled.
// Returns ErrSSOProviderDisabled if the provider exists but is disabled.
// Use this method for login flows to ensure disabled providers cannot be used.
func (r *SSORepository) GetEnabledProviderBySlug(ctx context.Context, slug string) (*repository.SSOProvider, error) {
	provider, err := r.GetProviderBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if !provider.Enabled {
		return nil, repository.ErrSSOProviderDisabled
	}
	return provider, nil
}

// UpdateProvider updates an SSO provider.
func (r *SSORepository) UpdateProvider(ctx context.Context, id int64, input *repository.UpdateSSOProviderInput) (*repository.SSOProvider, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid provider ID")
	}

	// Validate update input
	if err := r.validateUpdateInput(input); err != nil {
		return nil, err
	}

	// Build dynamic update query
	var updates []string
	var args []interface{}

	if input.Name != nil {
		if len(*input.Name) == 0 || len(*input.Name) > maxSSONameLen {
			return nil, fmt.Errorf("invalid name length")
		}
		updates = append(updates, "name = ?")
		args = append(args, *input.Name)
	}
	if input.Enabled != nil {
		updates = append(updates, "enabled = ?")
		args = append(args, *input.Enabled)
	}
	if input.ClientID != nil {
		if len(*input.ClientID) > maxSSOClientIDLen {
			return nil, fmt.Errorf("invalid client ID length")
		}
		updates = append(updates, "client_id = ?")
		args = append(args, *input.ClientID)
	}
	if input.ClientSecret != nil {
		if len(*input.ClientSecret) > maxSSOClientSecretLen {
			return nil, fmt.Errorf("invalid client secret length")
		}
		updates = append(updates, "client_secret = ?")
		args = append(args, *input.ClientSecret)
	}
	if input.IssuerURL != nil {
		if len(*input.IssuerURL) > maxSSOURLLen {
			return nil, fmt.Errorf("invalid issuer URL length")
		}
		updates = append(updates, "issuer_url = ?")
		args = append(args, *input.IssuerURL)
	}
	if input.AuthorizationURL != nil {
		updates = append(updates, "authorization_url = ?")
		args = append(args, nullIfEmpty(*input.AuthorizationURL))
	}
	if input.TokenURL != nil {
		updates = append(updates, "token_url = ?")
		args = append(args, nullIfEmpty(*input.TokenURL))
	}
	if input.UserinfoURL != nil {
		updates = append(updates, "userinfo_url = ?")
		args = append(args, nullIfEmpty(*input.UserinfoURL))
	}
	if input.JWKSURL != nil {
		updates = append(updates, "jwks_url = ?")
		args = append(args, nullIfEmpty(*input.JWKSURL))
	}
	if input.Scopes != nil {
		if len(*input.Scopes) > maxSSOScopesLen {
			return nil, fmt.Errorf("invalid scopes length")
		}
		updates = append(updates, "scopes = ?")
		args = append(args, *input.Scopes)
	}
	if input.RedirectURL != nil {
		updates = append(updates, "redirect_url = ?")
		args = append(args, nullIfEmpty(*input.RedirectURL))
	}
	if input.AutoProvision != nil {
		updates = append(updates, "auto_provision = ?")
		args = append(args, *input.AutoProvision)
	}
	if input.DefaultRole != nil {
		updates = append(updates, "default_role = ?")
		args = append(args, *input.DefaultRole)
	}
	if input.DomainAllowlist != nil {
		updates = append(updates, "domain_allowlist = ?")
		args = append(args, nullIfEmpty(*input.DomainAllowlist))
	}
	if input.IconURL != nil {
		updates = append(updates, "icon_url = ?")
		args = append(args, nullIfEmpty(*input.IconURL))
	}
	if input.ButtonColor != nil {
		updates = append(updates, "button_color = ?")
		args = append(args, nullIfEmpty(*input.ButtonColor))
	}
	if input.ButtonTextColor != nil {
		updates = append(updates, "button_text_color = ?")
		args = append(args, nullIfEmpty(*input.ButtonTextColor))
	}
	if input.DisplayOrder != nil {
		updates = append(updates, "display_order = ?")
		args = append(args, *input.DisplayOrder)
	}

	if len(updates) == 0 {
		return r.GetProvider(ctx, id)
	}

	updates = append(updates, "updated_at = CURRENT_TIMESTAMP")
	args = append(args, id)

	query := fmt.Sprintf("UPDATE sso_providers SET %s WHERE id = ?", strings.Join(updates, ", "))

	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update SSO provider: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return nil, repository.ErrSSOProviderNotFound
	}

	return r.GetProvider(ctx, id)
}

// DeleteProvider deletes an SSO provider.
func (r *SSORepository) DeleteProvider(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("invalid provider ID")
	}

	// Use transaction to delete provider and related data
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete states
	if _, err := tx.ExecContext(ctx, "DELETE FROM sso_states WHERE provider_id = ?", id); err != nil {
		return fmt.Errorf("failed to delete SSO states: %w", err)
	}

	// Delete links
	if _, err := tx.ExecContext(ctx, "DELETE FROM user_sso_links WHERE provider_id = ?", id); err != nil {
		return fmt.Errorf("failed to delete SSO links: %w", err)
	}

	// Delete provider
	result, err := tx.ExecContext(ctx, "DELETE FROM sso_providers WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete SSO provider: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return repository.ErrSSOProviderNotFound
	}

	return tx.Commit()
}

// ListProviders retrieves all SSO providers.
func (r *SSORepository) ListProviders(ctx context.Context, enabledOnly bool) ([]repository.SSOProvider, error) {
	query := `
		SELECT id, name, slug, type, enabled,
			client_id, client_secret, issuer_url,
			authorization_url, token_url, userinfo_url, jwks_url,
			scopes, redirect_url,
			auto_provision, default_role, domain_allowlist,
			icon_url, button_color, button_text_color, display_order,
			created_at, updated_at
		FROM sso_providers`

	if enabledOnly {
		query += " WHERE enabled = 1"
	}
	query += " ORDER BY display_order ASC, name ASC LIMIT 100"

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list SSO providers: %w", err)
	}
	defer rows.Close()

	var providers []repository.SSOProvider
	for rows.Next() {
		var provider repository.SSOProvider
		var (
			authURL, tokenURL, userinfoURL, jwksURL sql.NullString
			redirectURL, domainAllowlist            sql.NullString
			iconURL, buttonColor, buttonTextColor   sql.NullString
		)

		err := rows.Scan(
			&provider.ID, &provider.Name, &provider.Slug, &provider.Type, &provider.Enabled,
			&provider.ClientID, &provider.ClientSecret, &provider.IssuerURL,
			&authURL, &tokenURL, &userinfoURL, &jwksURL,
			&provider.Scopes, &redirectURL,
			&provider.AutoProvision, &provider.DefaultRole, &domainAllowlist,
			&iconURL, &buttonColor, &buttonTextColor, &provider.DisplayOrder,
			&provider.CreatedAt, &provider.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SSO provider: %w", err)
		}

		provider.AuthorizationURL = authURL.String
		provider.TokenURL = tokenURL.String
		provider.UserinfoURL = userinfoURL.String
		provider.JWKSURL = jwksURL.String
		provider.RedirectURL = redirectURL.String
		provider.DomainAllowlist = domainAllowlist.String
		provider.IconURL = iconURL.String
		provider.ButtonColor = buttonColor.String
		provider.ButtonTextColor = buttonTextColor.String

		providers = append(providers, provider)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating SSO providers: %w", err)
	}

	return providers, nil
}

// ListProvidersWithStats retrieves all SSO providers with usage statistics.
func (r *SSORepository) ListProvidersWithStats(ctx context.Context) ([]repository.SSOProviderWithStats, error) {
	providers, err := r.ListProviders(ctx, false)
	if err != nil {
		return nil, err
	}

	result := make([]repository.SSOProviderWithStats, len(providers))
	for i, provider := range providers {
		result[i].SSOProvider = provider

		// Get linked users count
		count, err := r.CountLinksByProviderID(ctx, provider.ID)
		if err != nil {
			return nil, err
		}
		result[i].LinkedUsersCount = int(count)

		// Get login count in last 24 hours
		var loginCount int
		err = r.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM user_sso_links 
			WHERE provider_id = ? AND last_login_at > datetime('now', '-1 day')`,
			provider.ID,
		).Scan(&loginCount)
		if err != nil {
			return nil, fmt.Errorf("failed to get login count: %w", err)
		}
		result[i].LoginCount24h = loginCount
	}

	return result, nil
}

// GetProviderCount returns the total number of SSO providers.
func (r *SSORepository) GetProviderCount(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sso_providers").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get provider count: %w", err)
	}
	return count, nil
}

// ===========================================================================
// User SSO Link Operations
// ===========================================================================

// CreateLink creates a new user SSO link.
func (r *SSORepository) CreateLink(ctx context.Context, input *repository.CreateUserSSOLinkInput) (*repository.UserSSOLink, error) {
	if err := r.validateLinkInput(input); err != nil {
		return nil, err
	}

	query := `
		INSERT INTO user_sso_links (
			user_id, provider_id, external_id, external_email, external_name,
			access_token, refresh_token, token_expires_at,
			last_login_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`

	result, err := r.db.ExecContext(ctx, query,
		input.UserID, input.ProviderID, input.ExternalID,
		nullIfEmpty(input.ExternalEmail), nullIfEmpty(input.ExternalName),
		nullIfEmpty(input.AccessToken), nullIfEmpty(input.RefreshToken), input.TokenExpiresAt,
	)

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, repository.ErrSSOLinkExists
		}
		return nil, fmt.Errorf("failed to create SSO link: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get link ID: %w", err)
	}

	return r.GetLink(ctx, id)
}

// GetLink retrieves a user SSO link by ID.
func (r *SSORepository) GetLink(ctx context.Context, id int64) (*repository.UserSSOLink, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid link ID")
	}

	link := &repository.UserSSOLink{}
	var (
		externalEmail, externalName sql.NullString
		accessToken, refreshToken   sql.NullString
		tokenExpiresAt, lastLoginAt sql.NullTime
	)

	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, provider_id, external_id, external_email, external_name,
			access_token, refresh_token, token_expires_at,
			last_login_at, created_at, updated_at
		FROM user_sso_links WHERE id = ?`, id).Scan(
		&link.ID, &link.UserID, &link.ProviderID, &link.ExternalID,
		&externalEmail, &externalName,
		&accessToken, &refreshToken, &tokenExpiresAt,
		&lastLoginAt, &link.CreatedAt, &link.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, repository.ErrSSOLinkNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO link: %w", err)
	}

	link.ExternalEmail = externalEmail.String
	link.ExternalName = externalName.String
	link.AccessToken = accessToken.String
	link.RefreshToken = refreshToken.String
	if tokenExpiresAt.Valid {
		link.TokenExpiresAt = &tokenExpiresAt.Time
	}
	if lastLoginAt.Valid {
		link.LastLoginAt = &lastLoginAt.Time
	}

	return link, nil
}

// GetLinkByExternalID retrieves a user SSO link by provider ID and external ID.
func (r *SSORepository) GetLinkByExternalID(ctx context.Context, providerID int64, externalID string) (*repository.UserSSOLink, error) {
	if providerID <= 0 {
		return nil, fmt.Errorf("invalid provider ID")
	}
	if externalID == "" || len(externalID) > maxSSOExternalIDLen {
		return nil, fmt.Errorf("invalid external ID")
	}

	var id int64
	err := r.db.QueryRowContext(ctx,
		"SELECT id FROM user_sso_links WHERE provider_id = ? AND external_id = ?",
		providerID, externalID,
	).Scan(&id)

	if err == sql.ErrNoRows {
		return nil, repository.ErrSSOLinkNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO link by external ID: %w", err)
	}

	return r.GetLink(ctx, id)
}

// GetLinksByUserID retrieves all SSO links for a user.
func (r *SSORepository) GetLinksByUserID(ctx context.Context, userID int64) ([]repository.UserSSOLink, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("invalid user ID")
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, user_id, provider_id, external_id, external_email, external_name,
			access_token, refresh_token, token_expires_at,
			last_login_at, created_at, updated_at
		FROM user_sso_links WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO links: %w", err)
	}
	defer rows.Close()

	return r.scanLinkRows(rows)
}

// GetLinksByProviderID retrieves all SSO links for a provider.
func (r *SSORepository) GetLinksByProviderID(ctx context.Context, providerID int64) ([]repository.UserSSOLink, error) {
	if providerID <= 0 {
		return nil, fmt.Errorf("invalid provider ID")
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, user_id, provider_id, external_id, external_email, external_name,
			access_token, refresh_token, token_expires_at,
			last_login_at, created_at, updated_at
		FROM user_sso_links WHERE provider_id = ? ORDER BY created_at DESC LIMIT 1000`,
		providerID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO links: %w", err)
	}
	defer rows.Close()

	return r.scanLinkRows(rows)
}

// UpdateLinkTokens updates the access/refresh tokens for a user SSO link.
func (r *SSORepository) UpdateLinkTokens(ctx context.Context, id int64, accessToken, refreshToken string, expiresAt *time.Time) error {
	if id <= 0 {
		return fmt.Errorf("invalid link ID")
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE user_sso_links 
		SET access_token = ?, refresh_token = ?, token_expires_at = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`,
		nullIfEmpty(accessToken), nullIfEmpty(refreshToken), expiresAt, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update SSO link tokens: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return repository.ErrSSOLinkNotFound
	}

	return nil
}

// UpdateLinkLastLogin updates the last login time for a user SSO link.
func (r *SSORepository) UpdateLinkLastLogin(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("invalid link ID")
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE user_sso_links 
		SET last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to update SSO link last login: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return repository.ErrSSOLinkNotFound
	}

	return nil
}

// DeleteLink deletes a user SSO link.
func (r *SSORepository) DeleteLink(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("invalid link ID")
	}

	result, err := r.db.ExecContext(ctx, "DELETE FROM user_sso_links WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete SSO link: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return repository.ErrSSOLinkNotFound
	}

	return nil
}

// DeleteLinksByUserID deletes all SSO links for a user.
func (r *SSORepository) DeleteLinksByUserID(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}

	_, err := r.db.ExecContext(ctx, "DELETE FROM user_sso_links WHERE user_id = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to delete SSO links: %w", err)
	}

	return nil
}

// DeleteLinksByProviderID deletes all SSO links for a provider.
func (r *SSORepository) DeleteLinksByProviderID(ctx context.Context, providerID int64) error {
	if providerID <= 0 {
		return fmt.Errorf("invalid provider ID")
	}

	_, err := r.db.ExecContext(ctx, "DELETE FROM user_sso_links WHERE provider_id = ?", providerID)
	if err != nil {
		return fmt.Errorf("failed to delete SSO links: %w", err)
	}

	return nil
}

// CountLinksByProviderID returns the number of users linked to a provider.
func (r *SSORepository) CountLinksByProviderID(ctx context.Context, providerID int64) (int64, error) {
	if providerID <= 0 {
		return 0, fmt.Errorf("invalid provider ID")
	}

	var count int64
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM user_sso_links WHERE provider_id = ?",
		providerID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count SSO links: %w", err)
	}

	return count, nil
}

// ===========================================================================
// SSO State Operations
// ===========================================================================

// CreateState creates a new SSO state token.
func (r *SSORepository) CreateState(ctx context.Context, state, nonce string, providerID int64, returnURL, createdIP string, userID *int64, expiresAt time.Time) (*repository.SSOState, error) {
	if state == "" || len(state) > maxSSOStateLen {
		return nil, fmt.Errorf("invalid state")
	}
	if nonce == "" || len(nonce) > maxSSONonceLen {
		return nil, fmt.Errorf("invalid nonce")
	}
	if providerID <= 0 {
		return nil, fmt.Errorf("invalid provider ID")
	}
	if len(createdIP) > maxSSOIPLen {
		return nil, fmt.Errorf("invalid IP address")
	}

	// Validate returnURL to prevent open redirect (HIGH-3 fix)
	if err := validateReturnURL(returnURL); err != nil {
		return nil, err
	}

	query := `
		INSERT INTO sso_states (state, nonce, provider_id, return_url, user_id, created_ip, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`

	result, err := r.db.ExecContext(ctx, query,
		state, nonce, providerID, nullIfEmpty(returnURL), userID, nullIfEmpty(createdIP), expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSO state: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get state ID: %w", err)
	}

	return &repository.SSOState{
		ID:         id,
		State:      state,
		Nonce:      nonce,
		ProviderID: providerID,
		ReturnURL:  returnURL,
		UserID:     userID,
		CreatedIP:  createdIP,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
	}, nil
}

// GetState retrieves an SSO state by state value.
func (r *SSORepository) GetState(ctx context.Context, state string) (*repository.SSOState, error) {
	if state == "" || len(state) > maxSSOStateLen {
		return nil, fmt.Errorf("invalid state")
	}

	ssoState := &repository.SSOState{}
	var returnURL, createdIP sql.NullString
	var userID sql.NullInt64

	err := r.db.QueryRowContext(ctx, `
		SELECT id, state, nonce, provider_id, return_url, user_id, created_ip, expires_at, created_at
		FROM sso_states WHERE state = ?`, state).Scan(
		&ssoState.ID, &ssoState.State, &ssoState.Nonce, &ssoState.ProviderID,
		&returnURL, &userID, &createdIP, &ssoState.ExpiresAt, &ssoState.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, repository.ErrSSOStateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO state: %w", err)
	}

	ssoState.ReturnURL = returnURL.String
	ssoState.CreatedIP = createdIP.String
	if userID.Valid {
		ssoState.UserID = &userID.Int64
	}

	// Check if state has expired
	if time.Now().After(ssoState.ExpiresAt) {
		return nil, repository.ErrSSOStateExpired
	}

	return ssoState, nil
}

// DeleteState deletes an SSO state.
func (r *SSORepository) DeleteState(ctx context.Context, state string) error {
	if state == "" || len(state) > maxSSOStateLen {
		return fmt.Errorf("invalid state")
	}

	_, err := r.db.ExecContext(ctx, "DELETE FROM sso_states WHERE state = ?", state)
	if err != nil {
		return fmt.Errorf("failed to delete SSO state: %w", err)
	}

	return nil
}

// CleanupExpiredStates removes all expired SSO states.
func (r *SSORepository) CleanupExpiredStates(ctx context.Context) (int64, error) {
	result, err := r.db.ExecContext(ctx,
		"DELETE FROM sso_states WHERE expires_at < CURRENT_TIMESTAMP",
	)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired SSO states: %w", err)
	}

	count, _ := result.RowsAffected()
	return count, nil
}

// ===========================================================================
// Utility Operations
// ===========================================================================

// GetLinkByUserAndProvider retrieves a user SSO link by user ID and provider ID.
func (r *SSORepository) GetLinkByUserAndProvider(ctx context.Context, userID, providerID int64) (*repository.UserSSOLink, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("invalid user ID")
	}
	if providerID <= 0 {
		return nil, fmt.Errorf("invalid provider ID")
	}

	var id int64
	err := r.db.QueryRowContext(ctx,
		"SELECT id FROM user_sso_links WHERE user_id = ? AND provider_id = ?",
		userID, providerID,
	).Scan(&id)

	if err == sql.ErrNoRows {
		return nil, repository.ErrSSOLinkNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO link: %w", err)
	}

	return r.GetLink(ctx, id)
}

// FindUserByExternalEmail finds users with matching email for JIT provisioning.
func (r *SSORepository) FindUserByExternalEmail(ctx context.Context, email string) ([]int64, error) {
	if email == "" {
		return nil, nil
	}

	rows, err := r.db.QueryContext(ctx,
		"SELECT id FROM users WHERE LOWER(email) = LOWER(?) LIMIT 10",
		email,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to find users by email: %w", err)
	}
	defer rows.Close()

	var userIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan user ID: %w", err)
		}
		userIDs = append(userIDs, id)
	}

	return userIDs, nil
}

// ===========================================================================
// Helper Functions
// ===========================================================================

func (r *SSORepository) validateProviderInput(input *repository.CreateSSOProviderInput) error {
	if input == nil {
		return fmt.Errorf("input is required")
	}
	if input.Name == "" || len(input.Name) > maxSSONameLen {
		return fmt.Errorf("invalid name")
	}
	if input.Slug == "" || len(input.Slug) > maxSSOSlugLen {
		return fmt.Errorf("invalid slug length")
	}
	// MEDIUM-1 fix: Validate slug format
	if !slugPattern.MatchString(input.Slug) {
		return fmt.Errorf("invalid slug format: must contain only lowercase letters, numbers, and hyphens, and must start/end with alphanumeric")
	}
	if input.Type != repository.SSOProviderTypeOIDC && input.Type != repository.SSOProviderTypeSAML {
		return fmt.Errorf("invalid provider type")
	}
	if len(input.ClientID) > maxSSOClientIDLen {
		return fmt.Errorf("invalid client ID length")
	}
	if len(input.ClientSecret) > maxSSOClientSecretLen {
		return fmt.Errorf("invalid client secret length")
	}
	if len(input.IssuerURL) > maxSSOURLLen {
		return fmt.Errorf("invalid issuer URL length")
	}
	if len(input.Scopes) > maxSSOScopesLen {
		return fmt.Errorf("invalid scopes length")
	}
	// HIGH-2 fix: Validate DefaultRole
	if input.DefaultRole != "" && !ValidRoles[input.DefaultRole] {
		return fmt.Errorf("invalid default role: must be 'user' or 'admin'")
	}
	// MEDIUM-4 fix: Validate IconURL
	if err := validateIconURL(input.IconURL); err != nil {
		return err
	}
	// MEDIUM-4 fix: Validate ButtonColor
	if err := validateHexColor(input.ButtonColor, "button color"); err != nil {
		return err
	}
	// MEDIUM-4 fix: Validate ButtonTextColor
	if err := validateHexColor(input.ButtonTextColor, "button text color"); err != nil {
		return err
	}
	return nil
}

// validateUpdateInput validates the update input fields.
func (r *SSORepository) validateUpdateInput(input *repository.UpdateSSOProviderInput) error {
	if input == nil {
		return nil
	}
	// HIGH-2 fix: Validate DefaultRole in updates
	if input.DefaultRole != nil && *input.DefaultRole != "" && !ValidRoles[*input.DefaultRole] {
		return fmt.Errorf("invalid default role: must be 'user' or 'admin'")
	}
	// MEDIUM-4 fix: Validate IconURL in updates
	if input.IconURL != nil {
		if err := validateIconURL(*input.IconURL); err != nil {
			return err
		}
	}
	// MEDIUM-4 fix: Validate ButtonColor in updates
	if input.ButtonColor != nil {
		if err := validateHexColor(*input.ButtonColor, "button color"); err != nil {
			return err
		}
	}
	// MEDIUM-4 fix: Validate ButtonTextColor in updates
	if input.ButtonTextColor != nil {
		if err := validateHexColor(*input.ButtonTextColor, "button text color"); err != nil {
			return err
		}
	}
	return nil
}

func (r *SSORepository) validateLinkInput(input *repository.CreateUserSSOLinkInput) error {
	if input == nil {
		return fmt.Errorf("input is required")
	}
	if input.UserID <= 0 {
		return fmt.Errorf("invalid user ID")
	}
	if input.ProviderID <= 0 {
		return fmt.Errorf("invalid provider ID")
	}
	if input.ExternalID == "" || len(input.ExternalID) > maxSSOExternalIDLen {
		return fmt.Errorf("invalid external ID")
	}
	return nil
}

func (r *SSORepository) scanLinkRows(rows *sql.Rows) ([]repository.UserSSOLink, error) {
	var links []repository.UserSSOLink
	for rows.Next() {
		var link repository.UserSSOLink
		var (
			externalEmail, externalName sql.NullString
			accessToken, refreshToken   sql.NullString
			tokenExpiresAt, lastLoginAt sql.NullTime
		)

		err := rows.Scan(
			&link.ID, &link.UserID, &link.ProviderID, &link.ExternalID,
			&externalEmail, &externalName,
			&accessToken, &refreshToken, &tokenExpiresAt,
			&lastLoginAt, &link.CreatedAt, &link.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SSO link: %w", err)
		}

		link.ExternalEmail = externalEmail.String
		link.ExternalName = externalName.String
		link.AccessToken = accessToken.String
		link.RefreshToken = refreshToken.String
		if tokenExpiresAt.Valid {
			link.TokenExpiresAt = &tokenExpiresAt.Time
		}
		if lastLoginAt.Valid {
			link.LastLoginAt = &lastLoginAt.Time
		}

		links = append(links, link)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating SSO links: %w", err)
	}

	return links, nil
}

// validateReturnURL validates that the return URL is safe (HIGH-3 fix).
// Only allows empty, relative URLs, or URLs without a host (path-only).
func validateReturnURL(returnURL string) error {
	if returnURL == "" {
		return nil
	}
	parsed, err := url.Parse(returnURL)
	if err != nil {
		return fmt.Errorf("invalid return URL")
	}
	// Only allow relative URLs (no scheme or host)
	// This prevents open redirect attacks to external sites
	if parsed.Scheme != "" || parsed.Host != "" {
		return fmt.Errorf("return URL must be a relative path (external URLs not allowed)")
	}
	// Prevent path traversal attempts
	if strings.Contains(returnURL, "..") {
		return fmt.Errorf("return URL cannot contain path traversal")
	}
	return nil
}

// validateIconURL validates that the icon URL uses a safe scheme (MEDIUM-4 fix).
func validateIconURL(iconURL string) error {
	if iconURL == "" {
		return nil
	}
	parsed, err := url.Parse(iconURL)
	if err != nil {
		return fmt.Errorf("invalid icon URL")
	}
	// Only allow http or https schemes (prevent javascript: etc.)
	if parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("icon URL must use http or https scheme")
	}
	return nil
}

// validateHexColor validates that a color is a valid hex color (MEDIUM-4 fix).
func validateHexColor(color, fieldName string) error {
	if color == "" {
		return nil
	}
	if !hexColorPattern.MatchString(color) {
		return fmt.Errorf("invalid %s: must be a valid hex color (e.g., #ffffff)", fieldName)
	}
	return nil
}

// nullIfEmpty returns nil if the string is empty, otherwise returns the string.
func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
