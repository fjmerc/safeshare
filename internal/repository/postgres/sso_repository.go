package postgres

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/jackc/pgx/v5"
)

// SSORepository implements repository.SSORepository for PostgreSQL.
type SSORepository struct {
	pool *Pool
}

// NewSSORepository creates a new PostgreSQL SSO repository.
func NewSSORepository(pool *Pool) *SSORepository {
	return &SSORepository{pool: pool}
}

// Input validation constants for SSO.
const (
	maxSSONameLen         = 100
	maxSSOSlugLen         = 50
	maxSSOClientIDLen     = 256
	maxSSOClientSecretLen = 1024
	maxSSOURLLen          = 2048
	maxSSOScopesLen       = 500
	maxSSOStateLen        = 128
	maxSSONonceLen        = 128
	maxSSOExternalIDLen   = 256
	maxSSOIPLen           = 64
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

	var id int64
	err := r.pool.QueryRow(ctx, `
		INSERT INTO sso_providers (
			name, slug, type, enabled,
			client_id, client_secret, issuer_url,
			authorization_url, token_url, userinfo_url, jwks_url,
			scopes, redirect_url,
			auto_provision, default_role, domain_allowlist,
			icon_url, button_color, button_text_color, display_order
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		RETURNING id`,
		input.Name, input.Slug, string(input.Type), input.Enabled,
		input.ClientID, input.ClientSecret, input.IssuerURL,
		nullIfEmpty(input.AuthorizationURL), nullIfEmpty(input.TokenURL), nullIfEmpty(input.UserinfoURL), nullIfEmpty(input.JWKSURL),
		input.Scopes, nullIfEmpty(input.RedirectURL),
		input.AutoProvision, input.DefaultRole, nullIfEmpty(input.DomainAllowlist),
		nullIfEmpty(input.IconURL), nullIfEmpty(input.ButtonColor), nullIfEmpty(input.ButtonTextColor), input.DisplayOrder,
	).Scan(&id)

	if err != nil {
		if strings.Contains(err.Error(), "sso_providers_slug_key") {
			return nil, repository.ErrSSOProviderSlugExists
		}
		if strings.Contains(err.Error(), "sso_providers_name_key") {
			return nil, fmt.Errorf("provider name already exists")
		}
		return nil, fmt.Errorf("failed to create SSO provider: %w", err)
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
		authURL, tokenURL, userinfoURL, jwksURL *string
		redirectURL, domainAllowlist            *string
		iconURL, buttonColor, buttonTextColor   *string
	)

	err := r.pool.QueryRow(ctx, `
		SELECT id, name, slug, type, enabled,
			client_id, client_secret, issuer_url,
			authorization_url, token_url, userinfo_url, jwks_url,
			scopes, redirect_url,
			auto_provision, default_role, domain_allowlist,
			icon_url, button_color, button_text_color, display_order,
			created_at, updated_at
		FROM sso_providers WHERE id = $1`, id).Scan(
		&provider.ID, &provider.Name, &provider.Slug, &provider.Type, &provider.Enabled,
		&provider.ClientID, &provider.ClientSecret, &provider.IssuerURL,
		&authURL, &tokenURL, &userinfoURL, &jwksURL,
		&provider.Scopes, &redirectURL,
		&provider.AutoProvision, &provider.DefaultRole, &domainAllowlist,
		&iconURL, &buttonColor, &buttonTextColor, &provider.DisplayOrder,
		&provider.CreatedAt, &provider.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, repository.ErrSSOProviderNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO provider: %w", err)
	}

	if authURL != nil {
		provider.AuthorizationURL = *authURL
	}
	if tokenURL != nil {
		provider.TokenURL = *tokenURL
	}
	if userinfoURL != nil {
		provider.UserinfoURL = *userinfoURL
	}
	if jwksURL != nil {
		provider.JWKSURL = *jwksURL
	}
	if redirectURL != nil {
		provider.RedirectURL = *redirectURL
	}
	if domainAllowlist != nil {
		provider.DomainAllowlist = *domainAllowlist
	}
	if iconURL != nil {
		provider.IconURL = *iconURL
	}
	if buttonColor != nil {
		provider.ButtonColor = *buttonColor
	}
	if buttonTextColor != nil {
		provider.ButtonTextColor = *buttonTextColor
	}

	return provider, nil
}

// GetProviderBySlug retrieves an SSO provider by slug.
func (r *SSORepository) GetProviderBySlug(ctx context.Context, slug string) (*repository.SSOProvider, error) {
	if slug == "" || len(slug) > maxSSOSlugLen {
		return nil, fmt.Errorf("invalid slug")
	}

	var id int64
	err := r.pool.QueryRow(ctx, "SELECT id FROM sso_providers WHERE slug = $1", slug).Scan(&id)
	if err == pgx.ErrNoRows {
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
	argNum := 1

	if input.Name != nil {
		if len(*input.Name) == 0 || len(*input.Name) > maxSSONameLen {
			return nil, fmt.Errorf("invalid name length")
		}
		updates = append(updates, fmt.Sprintf("name = $%d", argNum))
		args = append(args, *input.Name)
		argNum++
	}
	if input.Enabled != nil {
		updates = append(updates, fmt.Sprintf("enabled = $%d", argNum))
		args = append(args, *input.Enabled)
		argNum++
	}
	if input.ClientID != nil {
		updates = append(updates, fmt.Sprintf("client_id = $%d", argNum))
		args = append(args, *input.ClientID)
		argNum++
	}
	if input.ClientSecret != nil {
		updates = append(updates, fmt.Sprintf("client_secret = $%d", argNum))
		args = append(args, *input.ClientSecret)
		argNum++
	}
	if input.IssuerURL != nil {
		updates = append(updates, fmt.Sprintf("issuer_url = $%d", argNum))
		args = append(args, *input.IssuerURL)
		argNum++
	}
	if input.AuthorizationURL != nil {
		updates = append(updates, fmt.Sprintf("authorization_url = $%d", argNum))
		args = append(args, nullIfEmpty(*input.AuthorizationURL))
		argNum++
	}
	if input.TokenURL != nil {
		updates = append(updates, fmt.Sprintf("token_url = $%d", argNum))
		args = append(args, nullIfEmpty(*input.TokenURL))
		argNum++
	}
	if input.UserinfoURL != nil {
		updates = append(updates, fmt.Sprintf("userinfo_url = $%d", argNum))
		args = append(args, nullIfEmpty(*input.UserinfoURL))
		argNum++
	}
	if input.JWKSURL != nil {
		updates = append(updates, fmt.Sprintf("jwks_url = $%d", argNum))
		args = append(args, nullIfEmpty(*input.JWKSURL))
		argNum++
	}
	if input.Scopes != nil {
		updates = append(updates, fmt.Sprintf("scopes = $%d", argNum))
		args = append(args, *input.Scopes)
		argNum++
	}
	if input.RedirectURL != nil {
		updates = append(updates, fmt.Sprintf("redirect_url = $%d", argNum))
		args = append(args, nullIfEmpty(*input.RedirectURL))
		argNum++
	}
	if input.AutoProvision != nil {
		updates = append(updates, fmt.Sprintf("auto_provision = $%d", argNum))
		args = append(args, *input.AutoProvision)
		argNum++
	}
	if input.DefaultRole != nil {
		updates = append(updates, fmt.Sprintf("default_role = $%d", argNum))
		args = append(args, *input.DefaultRole)
		argNum++
	}
	if input.DomainAllowlist != nil {
		updates = append(updates, fmt.Sprintf("domain_allowlist = $%d", argNum))
		args = append(args, nullIfEmpty(*input.DomainAllowlist))
		argNum++
	}
	if input.IconURL != nil {
		updates = append(updates, fmt.Sprintf("icon_url = $%d", argNum))
		args = append(args, nullIfEmpty(*input.IconURL))
		argNum++
	}
	if input.ButtonColor != nil {
		updates = append(updates, fmt.Sprintf("button_color = $%d", argNum))
		args = append(args, nullIfEmpty(*input.ButtonColor))
		argNum++
	}
	if input.ButtonTextColor != nil {
		updates = append(updates, fmt.Sprintf("button_text_color = $%d", argNum))
		args = append(args, nullIfEmpty(*input.ButtonTextColor))
		argNum++
	}
	if input.DisplayOrder != nil {
		updates = append(updates, fmt.Sprintf("display_order = $%d", argNum))
		args = append(args, *input.DisplayOrder)
		argNum++
	}

	if len(updates) == 0 {
		return r.GetProvider(ctx, id)
	}

	updates = append(updates, "updated_at = CURRENT_TIMESTAMP")
	args = append(args, id)

	query := fmt.Sprintf("UPDATE sso_providers SET %s WHERE id = $%d", strings.Join(updates, ", "), argNum)

	result, err := r.pool.Exec(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update SSO provider: %w", err)
	}

	if result.RowsAffected() == 0 {
		return nil, repository.ErrSSOProviderNotFound
	}

	return r.GetProvider(ctx, id)
}

// DeleteProvider deletes an SSO provider.
func (r *SSORepository) DeleteProvider(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("invalid provider ID")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // Safe to ignore: no-op after commit

	// Delete states
	if _, err := tx.Exec(ctx, "DELETE FROM sso_states WHERE provider_id = $1", id); err != nil {
		return fmt.Errorf("failed to delete SSO states: %w", err)
	}

	// Delete links
	if _, err := tx.Exec(ctx, "DELETE FROM user_sso_links WHERE provider_id = $1", id); err != nil {
		return fmt.Errorf("failed to delete SSO links: %w", err)
	}

	// Delete provider
	result, err := tx.Exec(ctx, "DELETE FROM sso_providers WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete SSO provider: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrSSOProviderNotFound
	}

	return tx.Commit(ctx)
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
		query += " WHERE enabled = TRUE"
	}
	query += " ORDER BY display_order ASC, name ASC LIMIT 100"

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list SSO providers: %w", err)
	}
	defer rows.Close()

	var providers []repository.SSOProvider
	for rows.Next() {
		var provider repository.SSOProvider
		var (
			authURL, tokenURL, userinfoURL, jwksURL *string
			redirectURL, domainAllowlist            *string
			iconURL, buttonColor, buttonTextColor   *string
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

		if authURL != nil {
			provider.AuthorizationURL = *authURL
		}
		if tokenURL != nil {
			provider.TokenURL = *tokenURL
		}
		if userinfoURL != nil {
			provider.UserinfoURL = *userinfoURL
		}
		if jwksURL != nil {
			provider.JWKSURL = *jwksURL
		}
		if redirectURL != nil {
			provider.RedirectURL = *redirectURL
		}
		if domainAllowlist != nil {
			provider.DomainAllowlist = *domainAllowlist
		}
		if iconURL != nil {
			provider.IconURL = *iconURL
		}
		if buttonColor != nil {
			provider.ButtonColor = *buttonColor
		}
		if buttonTextColor != nil {
			provider.ButtonTextColor = *buttonTextColor
		}

		providers = append(providers, provider)
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
		err = r.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM user_sso_links 
			WHERE provider_id = $1 AND last_login_at > NOW() - INTERVAL '1 day'`,
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
	err := r.pool.QueryRow(ctx, "SELECT COUNT(*) FROM sso_providers").Scan(&count)
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

	var id int64
	err := r.pool.QueryRow(ctx, `
		INSERT INTO user_sso_links (
			user_id, provider_id, external_id, external_email, external_name,
			access_token, refresh_token, token_expires_at,
			last_login_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
		RETURNING id`,
		input.UserID, input.ProviderID, input.ExternalID,
		nullIfEmpty(input.ExternalEmail), nullIfEmpty(input.ExternalName),
		nullIfEmpty(input.AccessToken), nullIfEmpty(input.RefreshToken), input.TokenExpiresAt,
	).Scan(&id)

	if err != nil {
		if strings.Contains(err.Error(), "user_sso_links_provider_id_external_id_key") {
			return nil, repository.ErrSSOLinkExists
		}
		return nil, fmt.Errorf("failed to create SSO link: %w", err)
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
		externalEmail, externalName *string
		accessToken, refreshToken   *string
		tokenExpiresAt, lastLoginAt *time.Time
	)

	err := r.pool.QueryRow(ctx, `
		SELECT id, user_id, provider_id, external_id, external_email, external_name,
			access_token, refresh_token, token_expires_at,
			last_login_at, created_at, updated_at
		FROM user_sso_links WHERE id = $1`, id).Scan(
		&link.ID, &link.UserID, &link.ProviderID, &link.ExternalID,
		&externalEmail, &externalName,
		&accessToken, &refreshToken, &tokenExpiresAt,
		&lastLoginAt, &link.CreatedAt, &link.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, repository.ErrSSOLinkNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO link: %w", err)
	}

	if externalEmail != nil {
		link.ExternalEmail = *externalEmail
	}
	if externalName != nil {
		link.ExternalName = *externalName
	}
	if accessToken != nil {
		link.AccessToken = *accessToken
	}
	if refreshToken != nil {
		link.RefreshToken = *refreshToken
	}
	link.TokenExpiresAt = tokenExpiresAt
	link.LastLoginAt = lastLoginAt

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
	err := r.pool.QueryRow(ctx,
		"SELECT id FROM user_sso_links WHERE provider_id = $1 AND external_id = $2",
		providerID, externalID,
	).Scan(&id)

	if err == pgx.ErrNoRows {
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

	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, provider_id, external_id, external_email, external_name,
			access_token, refresh_token, token_expires_at,
			last_login_at, created_at, updated_at
		FROM user_sso_links WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
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

	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, provider_id, external_id, external_email, external_name,
			access_token, refresh_token, token_expires_at,
			last_login_at, created_at, updated_at
		FROM user_sso_links WHERE provider_id = $1 ORDER BY created_at DESC LIMIT 1000`,
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

	result, err := r.pool.Exec(ctx, `
		UPDATE user_sso_links 
		SET access_token = $1, refresh_token = $2, token_expires_at = $3, updated_at = CURRENT_TIMESTAMP
		WHERE id = $4`,
		nullIfEmpty(accessToken), nullIfEmpty(refreshToken), expiresAt, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update SSO link tokens: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrSSOLinkNotFound
	}

	return nil
}

// UpdateLinkLastLogin updates the last login time for a user SSO link.
func (r *SSORepository) UpdateLinkLastLogin(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("invalid link ID")
	}

	result, err := r.pool.Exec(ctx, `
		UPDATE user_sso_links 
		SET last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to update SSO link last login: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrSSOLinkNotFound
	}

	return nil
}

// DeleteLink deletes a user SSO link.
func (r *SSORepository) DeleteLink(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("invalid link ID")
	}

	result, err := r.pool.Exec(ctx, "DELETE FROM user_sso_links WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete SSO link: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrSSOLinkNotFound
	}

	return nil
}

// DeleteLinksByUserID deletes all SSO links for a user.
func (r *SSORepository) DeleteLinksByUserID(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}

	_, err := r.pool.Exec(ctx, "DELETE FROM user_sso_links WHERE user_id = $1", userID)
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

	_, err := r.pool.Exec(ctx, "DELETE FROM user_sso_links WHERE provider_id = $1", providerID)
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
	err := r.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM user_sso_links WHERE provider_id = $1",
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

	// Validate returnURL to prevent open redirect (HIGH-3 fix)
	if err := validateReturnURL(returnURL); err != nil {
		return nil, err
	}

	var id int64
	var createdAt time.Time
	err := r.pool.QueryRow(ctx, `
		INSERT INTO sso_states (state, nonce, provider_id, return_url, user_id, created_ip, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`,
		state, nonce, providerID, nullIfEmpty(returnURL), userID, nullIfEmpty(createdIP), expiresAt,
	).Scan(&id, &createdAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create SSO state: %w", err)
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
		CreatedAt:  createdAt,
	}, nil
}

// GetState retrieves an SSO state by state value.
func (r *SSORepository) GetState(ctx context.Context, state string) (*repository.SSOState, error) {
	if state == "" || len(state) > maxSSOStateLen {
		return nil, fmt.Errorf("invalid state")
	}

	ssoState := &repository.SSOState{}
	var returnURL, createdIP *string
	var userID *int64

	err := r.pool.QueryRow(ctx, `
		SELECT id, state, nonce, provider_id, return_url, user_id, created_ip, expires_at, created_at
		FROM sso_states WHERE state = $1`, state).Scan(
		&ssoState.ID, &ssoState.State, &ssoState.Nonce, &ssoState.ProviderID,
		&returnURL, &userID, &createdIP, &ssoState.ExpiresAt, &ssoState.CreatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, repository.ErrSSOStateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO state: %w", err)
	}

	if returnURL != nil {
		ssoState.ReturnURL = *returnURL
	}
	if createdIP != nil {
		ssoState.CreatedIP = *createdIP
	}
	ssoState.UserID = userID

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

	_, err := r.pool.Exec(ctx, "DELETE FROM sso_states WHERE state = $1", state)
	if err != nil {
		return fmt.Errorf("failed to delete SSO state: %w", err)
	}

	return nil
}

// CleanupExpiredStates removes all expired SSO states.
func (r *SSORepository) CleanupExpiredStates(ctx context.Context) (int64, error) {
	result, err := r.pool.Exec(ctx,
		"DELETE FROM sso_states WHERE expires_at < CURRENT_TIMESTAMP",
	)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired SSO states: %w", err)
	}

	return result.RowsAffected(), nil
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
	err := r.pool.QueryRow(ctx,
		"SELECT id FROM user_sso_links WHERE user_id = $1 AND provider_id = $2",
		userID, providerID,
	).Scan(&id)

	if err == pgx.ErrNoRows {
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

	rows, err := r.pool.Query(ctx,
		"SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 10",
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

func (r *SSORepository) scanLinkRows(rows pgx.Rows) ([]repository.UserSSOLink, error) {
	var links []repository.UserSSOLink
	for rows.Next() {
		var link repository.UserSSOLink
		var (
			externalEmail, externalName *string
			accessToken, refreshToken   *string
			tokenExpiresAt, lastLoginAt *time.Time
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

		if externalEmail != nil {
			link.ExternalEmail = *externalEmail
		}
		if externalName != nil {
			link.ExternalName = *externalName
		}
		if accessToken != nil {
			link.AccessToken = *accessToken
		}
		if refreshToken != nil {
			link.RefreshToken = *refreshToken
		}
		link.TokenExpiresAt = tokenExpiresAt
		link.LastLoginAt = lastLoginAt

		links = append(links, link)
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
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
