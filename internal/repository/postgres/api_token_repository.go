package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/jackc/pgx/v5"
)

// API token limits.
const (
	maxAPITokenNameLen     = 100
	maxAPITokenScopesLen   = 500
	maxAPITokensPerUser    = 50
	maxAPITokensAdmin      = 1000   // Limit for admin list query
	maxIPAddressLen        = 45     // IPv6 addresses can be up to 45 characters
	expectedTokenHashLen   = 64     // SHA-256 as hex
	expectedTokenPrefixLen = 16     // "safeshare_" prefix + random chars
	maxAdminOffset         = 100000 // Maximum offset for pagination
)

// APITokenRepository implements repository.APITokenRepository for PostgreSQL.
type APITokenRepository struct {
	pool *Pool
}

// NewAPITokenRepository creates a new PostgreSQL API token repository.
func NewAPITokenRepository(pool *Pool) *APITokenRepository {
	return &APITokenRepository{pool: pool}
}

// Create inserts a new API token into the database.
// Returns the created token with populated ID and timestamps.
func (r *APITokenRepository) Create(ctx context.Context, userID int64, name, tokenHash, tokenPrefix, scopes, createdIP string, expiresAt *time.Time) (*models.APIToken, error) {
	// Validate inputs
	if userID <= 0 {
		return nil, fmt.Errorf("user_id must be positive")
	}
	if name == "" {
		return nil, fmt.Errorf("name cannot be empty")
	}
	if len(name) > maxAPITokenNameLen {
		return nil, fmt.Errorf("name too long (max %d chars)", maxAPITokenNameLen)
	}
	if tokenHash == "" || len(tokenHash) != expectedTokenHashLen {
		return nil, fmt.Errorf("token_hash must be %d characters", expectedTokenHashLen)
	}
	if tokenPrefix == "" || len(tokenPrefix) > expectedTokenPrefixLen {
		return nil, fmt.Errorf("token_prefix invalid length")
	}
	if len(scopes) > maxAPITokenScopesLen {
		return nil, fmt.Errorf("scopes too long (max %d chars)", maxAPITokenScopesLen)
	}
	if len(createdIP) > maxIPAddressLen {
		return nil, fmt.Errorf("created_ip too long (max %d chars)", maxIPAddressLen)
	}

	var id int64
	var createdAt time.Time
	err := r.pool.Pool.QueryRow(ctx, `
		INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, scopes, expires_at, created_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at
	`, userID, name, tokenHash, tokenPrefix, scopes, expiresAt, createdIP).Scan(&id, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create API token: %w", err)
	}

	token := &models.APIToken{
		ID:          id,
		UserID:      userID,
		Name:        name,
		TokenHash:   tokenHash,
		TokenPrefix: tokenPrefix,
		Scopes:      scopes,
		ExpiresAt:   expiresAt,
		CreatedAt:   createdAt,
		CreatedIP:   createdIP,
		IsActive:    true,
	}

	return token, nil
}

// GetByHash retrieves an API token by its hash (for validation during auth).
// Returns nil, nil if token not found or inactive.
func (r *APITokenRepository) GetByHash(ctx context.Context, tokenHash string) (*models.APIToken, error) {
	if tokenHash == "" {
		return nil, nil
	}

	var token models.APIToken
	var expiresAt, lastUsedAt *time.Time
	var lastUsedIP *string

	err := r.pool.Pool.QueryRow(ctx, `
		SELECT id, user_id, name, token_hash, token_prefix, scopes, expires_at, 
			last_used_at, last_used_ip, created_at, created_ip, is_active
		FROM api_tokens WHERE token_hash = $1 AND is_active = true
	`, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.Name,
		&token.TokenHash,
		&token.TokenPrefix,
		&token.Scopes,
		&expiresAt,
		&lastUsedAt,
		&lastUsedIP,
		&token.CreatedAt,
		&token.CreatedIP,
		&token.IsActive,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get API token: %w", err)
	}

	token.ExpiresAt = expiresAt
	token.LastUsedAt = lastUsedAt
	token.LastUsedIP = lastUsedIP

	return &token, nil
}

// GetByID retrieves a token by ID (for admin operations).
// Returns nil, nil if not found.
func (r *APITokenRepository) GetByID(ctx context.Context, tokenID int64) (*models.APIToken, error) {
	if tokenID <= 0 {
		return nil, nil
	}

	var token models.APIToken
	var expiresAt, lastUsedAt *time.Time
	var lastUsedIP *string

	err := r.pool.Pool.QueryRow(ctx, `
		SELECT id, user_id, name, token_hash, token_prefix, scopes, expires_at, 
			last_used_at, last_used_ip, created_at, created_ip, is_active
		FROM api_tokens WHERE id = $1
	`, tokenID).Scan(
		&token.ID,
		&token.UserID,
		&token.Name,
		&token.TokenHash,
		&token.TokenPrefix,
		&token.Scopes,
		&expiresAt,
		&lastUsedAt,
		&lastUsedIP,
		&token.CreatedAt,
		&token.CreatedIP,
		&token.IsActive,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get API token: %w", err)
	}

	token.ExpiresAt = expiresAt
	token.LastUsedAt = lastUsedAt
	token.LastUsedIP = lastUsedIP

	return &token, nil
}

// UpdateLastUsed updates the last used timestamp and IP for a token.
func (r *APITokenRepository) UpdateLastUsed(ctx context.Context, tokenID int64, ip string) error {
	if tokenID <= 0 {
		return fmt.Errorf("token_id must be positive")
	}
	// Truncate IP if too long (defensive)
	if len(ip) > maxIPAddressLen {
		ip = ip[:maxIPAddressLen]
	}

	_, err := r.pool.Pool.Exec(ctx, `
		UPDATE api_tokens SET last_used_at = NOW(), last_used_ip = $1 WHERE id = $2
	`, ip, tokenID)
	if err != nil {
		return fmt.Errorf("failed to update token last used: %w", err)
	}
	return nil
}

// GetByUserID retrieves all active tokens for a user.
func (r *APITokenRepository) GetByUserID(ctx context.Context, userID int64) ([]models.APITokenListItem, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("user_id must be positive")
	}

	rows, err := r.pool.Pool.Query(ctx, `
		SELECT id, name, token_prefix, scopes, expires_at, last_used_at, created_at, is_active
		FROM api_tokens WHERE user_id = $1 AND is_active = true 
		ORDER BY created_at DESC
		LIMIT $2
	`, userID, maxAPITokensPerUser)
	if err != nil {
		return nil, fmt.Errorf("failed to query API tokens: %w", err)
	}
	defer rows.Close()

	var tokens []models.APITokenListItem
	for rows.Next() {
		var token models.APITokenListItem
		var scopes string
		var expiresAt, lastUsedAt *time.Time

		err := rows.Scan(
			&token.ID,
			&token.Name,
			&token.TokenPrefix,
			&scopes,
			&expiresAt,
			&lastUsedAt,
			&token.CreatedAt,
			&token.IsActive,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}

		token.ExpiresAt = expiresAt
		token.LastUsedAt = lastUsedAt

		// Convert scopes string to slice
		if scopes != "" {
			token.Scopes = strings.Split(scopes, ",")
		} else {
			token.Scopes = []string{}
		}

		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating tokens: %w", err)
	}

	return tokens, nil
}

// CountByUserID returns the count of active tokens for a user.
func (r *APITokenRepository) CountByUserID(ctx context.Context, userID int64) (int, error) {
	if userID <= 0 {
		return 0, fmt.Errorf("user_id must be positive")
	}

	var count int
	err := r.pool.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM api_tokens WHERE user_id = $1 AND is_active = true
	`, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count user tokens: %w", err)
	}
	return count, nil
}

// Revoke soft-deletes a token (sets is_active = false) for a specific user.
// Returns ErrNotFound if token not found or doesn't belong to user.
func (r *APITokenRepository) Revoke(ctx context.Context, tokenID, userID int64) error {
	if tokenID <= 0 {
		return fmt.Errorf("token_id must be positive")
	}
	if userID <= 0 {
		return fmt.Errorf("user_id must be positive")
	}

	tag, err := r.pool.Pool.Exec(ctx, `
		UPDATE api_tokens SET is_active = false WHERE id = $1 AND user_id = $2
	`, tokenID, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// RevokeAdmin revokes any token (admin only, no user check).
// Returns ErrNotFound if token not found.
func (r *APITokenRepository) RevokeAdmin(ctx context.Context, tokenID int64) error {
	if tokenID <= 0 {
		return fmt.Errorf("token_id must be positive")
	}

	tag, err := r.pool.Pool.Exec(ctx, `
		UPDATE api_tokens SET is_active = false WHERE id = $1
	`, tokenID)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// DeleteByUserID removes all tokens for a user (used when user is deleted).
// This is a hard delete since user is being deleted.
func (r *APITokenRepository) DeleteByUserID(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return fmt.Errorf("user_id must be positive")
	}

	_, err := r.pool.Pool.Exec(ctx, `DELETE FROM api_tokens WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user tokens: %w", err)
	}
	return nil
}

// GetAllAdmin retrieves all tokens for admin view with pagination.
// Returns (tokens, totalCount, error).
func (r *APITokenRepository) GetAllAdmin(ctx context.Context, limit, offset int) ([]models.APITokenListItem, int, error) {
	// Validate and apply limits
	if limit <= 0 {
		limit = 50 // Default limit
	}
	if limit > maxAPITokensAdmin {
		limit = maxAPITokensAdmin
	}
	if offset < 0 {
		offset = 0
	}
	if offset > maxAdminOffset {
		offset = maxAdminOffset
	}

	// Get total count
	var total int
	err := r.pool.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM api_tokens`).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count tokens: %w", err)
	}

	rows, err := r.pool.Pool.Query(ctx, `
		SELECT t.id, t.user_id, t.name, t.token_prefix, t.scopes, t.expires_at, 
			t.last_used_at, t.created_at, t.is_active, u.username
		FROM api_tokens t
		LEFT JOIN users u ON t.user_id = u.id
		ORDER BY t.created_at DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query tokens: %w", err)
	}
	defer rows.Close()

	var tokens []models.APITokenListItem
	for rows.Next() {
		var token models.APITokenListItem
		var scopes string
		var expiresAt, lastUsedAt *time.Time
		var username *string

		err := rows.Scan(
			&token.ID,
			&token.UserID,
			&token.Name,
			&token.TokenPrefix,
			&scopes,
			&expiresAt,
			&lastUsedAt,
			&token.CreatedAt,
			&token.IsActive,
			&username,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan token: %w", err)
		}

		token.ExpiresAt = expiresAt
		token.LastUsedAt = lastUsedAt
		if username != nil {
			token.Username = *username
		}

		// Convert scopes string to slice
		if scopes != "" {
			token.Scopes = strings.Split(scopes, ",")
		} else {
			token.Scopes = []string{}
		}

		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating tokens: %w", err)
	}

	return tokens, total, nil
}

// CleanupExpired removes expired tokens.
// Returns the number of tokens deleted.
func (r *APITokenRepository) CleanupExpired(ctx context.Context) (int64, error) {
	tag, err := r.pool.Pool.Exec(ctx, `
		DELETE FROM api_tokens WHERE expires_at IS NOT NULL AND expires_at < NOW()
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Ensure APITokenRepository implements repository.APITokenRepository.
var _ repository.APITokenRepository = (*APITokenRepository)(nil)
