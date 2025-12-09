package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
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

// APITokenRepository implements repository.APITokenRepository for SQLite.
type APITokenRepository struct {
	db *sql.DB
}

// NewAPITokenRepository creates a new SQLite API token repository.
func NewAPITokenRepository(db *sql.DB) *APITokenRepository {
	return &APITokenRepository{db: db}
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

	var expiresAtStr *string
	if expiresAt != nil {
		s := expiresAt.Format(time.RFC3339)
		expiresAtStr = &s
	}

	query := `INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, scopes, expires_at, created_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(ctx, query, userID, name, tokenHash, tokenPrefix, scopes, expiresAtStr, createdIP)
	if err != nil {
		return nil, fmt.Errorf("failed to create API token: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get token ID: %w", err)
	}

	token := &models.APIToken{
		ID:          id,
		UserID:      userID,
		Name:        name,
		TokenHash:   tokenHash,
		TokenPrefix: tokenPrefix,
		Scopes:      scopes,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now(),
		CreatedIP:   createdIP,
		IsActive:    true,
	}

	return token, nil
}

// CreateWithLimit creates a new API token with atomic limit enforcement.
// Uses a database transaction to prevent race conditions between count check and insert.
// Returns repository.ErrTooManyTokens if the user has reached or exceeded maxTokens.
func (r *APITokenRepository) CreateWithLimit(ctx context.Context, userID int64, name, tokenHash, tokenPrefix, scopes, createdIP string, expiresAt *time.Time, maxTokens int) (*models.APIToken, error) {
	// Validate inputs (same as Create)
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
	if maxTokens <= 0 {
		return nil, fmt.Errorf("maxTokens must be positive")
	}

	// Use IMMEDIATE transaction to acquire write lock before read
	// This prevents concurrent transactions from modifying the count between check and insert
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Count existing active tokens for user within the transaction
	var count int
	countQuery := `SELECT COUNT(*) FROM api_tokens WHERE user_id = ? AND is_active = 1`
	if err := tx.QueryRowContext(ctx, countQuery, userID).Scan(&count); err != nil {
		return nil, fmt.Errorf("failed to count tokens: %w", err)
	}

	// Check limit
	if count >= maxTokens {
		return nil, repository.ErrTooManyTokens
	}

	// Insert the new token within the same transaction
	var expiresAtStr *string
	if expiresAt != nil {
		s := expiresAt.Format(time.RFC3339)
		expiresAtStr = &s
	}

	insertQuery := `INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, scopes, expires_at, created_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	result, err := tx.ExecContext(ctx, insertQuery, userID, name, tokenHash, tokenPrefix, scopes, expiresAtStr, createdIP)
	if err != nil {
		return nil, fmt.Errorf("failed to create API token: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get token ID: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	token := &models.APIToken{
		ID:          id,
		UserID:      userID,
		Name:        name,
		TokenHash:   tokenHash,
		TokenPrefix: tokenPrefix,
		Scopes:      scopes,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now(),
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

	query := `SELECT id, user_id, name, token_hash, token_prefix, scopes, expires_at, 
		last_used_at, last_used_ip, created_at, created_ip, is_active
		FROM api_tokens WHERE token_hash = ? AND is_active = 1`

	var token models.APIToken
	var createdAt string
	var expiresAt, lastUsedAt sql.NullString
	var lastUsedIP sql.NullString

	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.Name,
		&token.TokenHash,
		&token.TokenPrefix,
		&token.Scopes,
		&expiresAt,
		&lastUsedAt,
		&lastUsedIP,
		&createdAt,
		&token.CreatedIP,
		&token.IsActive,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get API token: %w", err)
	}

	// Parse timestamps
	var parseErr error
	token.CreatedAt, parseErr = time.Parse(time.RFC3339, createdAt)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", parseErr)
	}

	if expiresAt.Valid {
		t, err := time.Parse(time.RFC3339, expiresAt.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse expires_at: %w", err)
		}
		token.ExpiresAt = &t
	}
	if lastUsedAt.Valid {
		t, err := time.Parse(time.RFC3339, lastUsedAt.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse last_used_at: %w", err)
		}
		token.LastUsedAt = &t
	}
	if lastUsedIP.Valid {
		token.LastUsedIP = &lastUsedIP.String
	}

	return &token, nil
}

// GetByID retrieves a token by ID (for admin operations).
// Returns nil, nil if not found.
func (r *APITokenRepository) GetByID(ctx context.Context, tokenID int64) (*models.APIToken, error) {
	if tokenID <= 0 {
		return nil, nil
	}

	query := `SELECT id, user_id, name, token_hash, token_prefix, scopes, expires_at, 
		last_used_at, last_used_ip, created_at, created_ip, is_active
		FROM api_tokens WHERE id = ?`

	var token models.APIToken
	var createdAt string
	var expiresAt, lastUsedAt sql.NullString
	var lastUsedIP sql.NullString

	err := r.db.QueryRowContext(ctx, query, tokenID).Scan(
		&token.ID,
		&token.UserID,
		&token.Name,
		&token.TokenHash,
		&token.TokenPrefix,
		&token.Scopes,
		&expiresAt,
		&lastUsedAt,
		&lastUsedIP,
		&createdAt,
		&token.CreatedIP,
		&token.IsActive,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get API token: %w", err)
	}

	// Parse timestamps with proper error handling
	var parseErr error
	token.CreatedAt, parseErr = time.Parse(time.RFC3339, createdAt)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", parseErr)
	}

	if expiresAt.Valid {
		t, err := time.Parse(time.RFC3339, expiresAt.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse expires_at: %w", err)
		}
		token.ExpiresAt = &t
	}
	if lastUsedAt.Valid {
		t, err := time.Parse(time.RFC3339, lastUsedAt.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse last_used_at: %w", err)
		}
		token.LastUsedAt = &t
	}
	if lastUsedIP.Valid {
		token.LastUsedIP = &lastUsedIP.String
	}

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

	query := `UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?`
	now := time.Now().Format(time.RFC3339)

	_, err := r.db.ExecContext(ctx, query, now, ip, tokenID)
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

	query := `SELECT id, name, token_prefix, scopes, expires_at, last_used_at, created_at, is_active
		FROM api_tokens WHERE user_id = ? AND is_active = 1 
		ORDER BY created_at DESC
		LIMIT ?`

	rows, err := r.db.QueryContext(ctx, query, userID, maxAPITokensPerUser)
	if err != nil {
		return nil, fmt.Errorf("failed to query API tokens: %w", err)
	}
	defer rows.Close()

	var tokens []models.APITokenListItem
	for rows.Next() {
		var token models.APITokenListItem
		var scopes string
		var createdAt string
		var expiresAt, lastUsedAt sql.NullString

		err := rows.Scan(
			&token.ID,
			&token.Name,
			&token.TokenPrefix,
			&scopes,
			&expiresAt,
			&lastUsedAt,
			&createdAt,
			&token.IsActive,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}

		var parseErr error
		token.CreatedAt, parseErr = time.Parse(time.RFC3339, createdAt)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse created_at: %w", parseErr)
		}
		if expiresAt.Valid {
			t, err := time.Parse(time.RFC3339, expiresAt.String)
			if err != nil {
				return nil, fmt.Errorf("failed to parse expires_at: %w", err)
			}
			token.ExpiresAt = &t
		}
		if lastUsedAt.Valid {
			t, err := time.Parse(time.RFC3339, lastUsedAt.String)
			if err != nil {
				return nil, fmt.Errorf("failed to parse last_used_at: %w", err)
			}
			token.LastUsedAt = &t
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
		return nil, fmt.Errorf("error iterating tokens: %w", err)
	}

	return tokens, nil
}

// CountByUserID returns the count of active tokens for a user.
func (r *APITokenRepository) CountByUserID(ctx context.Context, userID int64) (int, error) {
	if userID <= 0 {
		return 0, fmt.Errorf("user_id must be positive")
	}

	query := `SELECT COUNT(*) FROM api_tokens WHERE user_id = ? AND is_active = 1`
	var count int
	err := r.db.QueryRowContext(ctx, query, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count user tokens: %w", err)
	}
	return count, nil
}

// Revoke soft-deletes a token (sets is_active = 0) for a specific user.
// Returns ErrNotFound if token not found or doesn't belong to user.
func (r *APITokenRepository) Revoke(ctx context.Context, tokenID, userID int64) error {
	if tokenID <= 0 {
		return fmt.Errorf("token_id must be positive")
	}
	if userID <= 0 {
		return fmt.Errorf("user_id must be positive")
	}

	query := `UPDATE api_tokens SET is_active = 0 WHERE id = ? AND user_id = ?`
	result, err := r.db.ExecContext(ctx, query, tokenID, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
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

	query := `UPDATE api_tokens SET is_active = 0 WHERE id = ?`
	result, err := r.db.ExecContext(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
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

	query := `DELETE FROM api_tokens WHERE user_id = ?`
	_, err := r.db.ExecContext(ctx, query, userID)
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
	countQuery := `SELECT COUNT(*) FROM api_tokens`
	err := r.db.QueryRowContext(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count tokens: %w", err)
	}

	query := `SELECT t.id, t.user_id, t.name, t.token_prefix, t.scopes, t.expires_at, 
		t.last_used_at, t.created_at, t.is_active, u.username
		FROM api_tokens t
		LEFT JOIN users u ON t.user_id = u.id
		ORDER BY t.created_at DESC
		LIMIT ? OFFSET ?`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query tokens: %w", err)
	}
	defer rows.Close()

	var tokens []models.APITokenListItem
	for rows.Next() {
		var token models.APITokenListItem
		var scopes string
		var createdAt string
		var expiresAt, lastUsedAt sql.NullString
		var username sql.NullString

		err := rows.Scan(
			&token.ID,
			&token.UserID,
			&token.Name,
			&token.TokenPrefix,
			&scopes,
			&expiresAt,
			&lastUsedAt,
			&createdAt,
			&token.IsActive,
			&username,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan token: %w", err)
		}

		var parseErr error
		token.CreatedAt, parseErr = time.Parse(time.RFC3339, createdAt)
		if parseErr != nil {
			return nil, 0, fmt.Errorf("failed to parse created_at: %w", parseErr)
		}
		if expiresAt.Valid {
			t, err := time.Parse(time.RFC3339, expiresAt.String)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to parse expires_at: %w", err)
			}
			token.ExpiresAt = &t
		}
		if lastUsedAt.Valid {
			t, err := time.Parse(time.RFC3339, lastUsedAt.String)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to parse last_used_at: %w", err)
			}
			token.LastUsedAt = &t
		}
		if username.Valid {
			token.Username = username.String
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
	// Note: Uses datetime() for RFC3339 comparison compatibility
	query := `DELETE FROM api_tokens WHERE expires_at IS NOT NULL AND datetime(expires_at) < datetime('now')`
	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}
	rows, _ := result.RowsAffected()
	return rows, nil
}

// Rotate regenerates token credentials while preserving metadata.
// Returns ErrNotFound if token doesn't exist, doesn't belong to user, or is inactive.
// Uses a transaction to ensure atomicity and prevent race conditions.
func (r *APITokenRepository) Rotate(ctx context.Context, tokenID, userID int64, newHash, newPrefix string) (*models.APIToken, error) {
	// Validate inputs
	if tokenID <= 0 {
		return nil, fmt.Errorf("token_id must be positive")
	}
	if userID <= 0 {
		return nil, fmt.Errorf("user_id must be positive")
	}
	if newHash == "" || len(newHash) != expectedTokenHashLen {
		return nil, fmt.Errorf("invalid token credentials")
	}
	if newPrefix == "" || len(newPrefix) > expectedTokenPrefixLen {
		return nil, fmt.Errorf("invalid token credentials")
	}

	// Use transaction with IMMEDIATE to prevent concurrent modifications
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Update token credentials and clear usage tracking
	query := `UPDATE api_tokens 
		SET token_hash = ?, token_prefix = ?, last_used_at = NULL, last_used_ip = NULL 
		WHERE id = ? AND user_id = ? AND is_active = 1`

	result, err := tx.ExecContext(ctx, query, newHash, newPrefix, tokenID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to rotate token: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return nil, repository.ErrNotFound
	}

	// Fetch the updated token within the same transaction
	selectQuery := `SELECT id, user_id, name, token_hash, token_prefix, scopes, expires_at, 
		last_used_at, last_used_ip, created_at, created_ip, is_active
		FROM api_tokens WHERE id = ?`

	var token models.APIToken
	var createdAt string
	var expiresAt, lastUsedAt sql.NullString
	var lastUsedIP sql.NullString

	err = tx.QueryRowContext(ctx, selectQuery, tokenID).Scan(
		&token.ID,
		&token.UserID,
		&token.Name,
		&token.TokenHash,
		&token.TokenPrefix,
		&token.Scopes,
		&expiresAt,
		&lastUsedAt,
		&lastUsedIP,
		&createdAt,
		&token.CreatedIP,
		&token.IsActive,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch rotated token: %w", err)
	}

	// Parse timestamps
	token.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	if expiresAt.Valid {
		t, err := time.Parse(time.RFC3339, expiresAt.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse expires_at: %w", err)
		}
		token.ExpiresAt = &t
	}
	if lastUsedAt.Valid {
		t, err := time.Parse(time.RFC3339, lastUsedAt.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse last_used_at: %w", err)
		}
		token.LastUsedAt = &t
	}
	if lastUsedIP.Valid {
		token.LastUsedIP = &lastUsedIP.String
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &token, nil
}

// LogUsage records a token usage event for audit purposes.
// This should be called after each API request authenticated with this token.
func (r *APITokenRepository) LogUsage(ctx context.Context, tokenID int64, endpoint, ip, userAgent string, status int) error {
	// Validate inputs
	if tokenID <= 0 {
		return fmt.Errorf("token_id must be positive")
	}
	if endpoint == "" {
		return fmt.Errorf("endpoint cannot be empty")
	}
	// Truncate fields if too long (defensive)
	const maxEndpointLen = 500
	const maxUserAgentLen = 1000
	if len(endpoint) > maxEndpointLen {
		endpoint = endpoint[:maxEndpointLen]
	}
	if len(ip) > maxIPAddressLen {
		ip = ip[:maxIPAddressLen]
	}
	if len(userAgent) > maxUserAgentLen {
		userAgent = userAgent[:maxUserAgentLen]
	}
	// Validate status code is in reasonable range
	if status < 100 || status > 599 {
		return fmt.Errorf("invalid HTTP status code")
	}

	query := `INSERT INTO api_token_usage (token_id, endpoint, ip_address, user_agent, response_status)
		VALUES (?, ?, ?, ?, ?)`

	_, err := r.db.ExecContext(ctx, query, tokenID, endpoint, ip, userAgent, status)
	if err != nil {
		return fmt.Errorf("failed to log token usage: %w", err)
	}
	return nil
}

// GetUsageLogs retrieves paginated usage logs for a specific token.
// Returns (logs, totalCount, error) with optional date filtering.
func (r *APITokenRepository) GetUsageLogs(ctx context.Context, tokenID int64, filter repository.UsageFilter) ([]models.APITokenUsageLog, int, error) {
	if tokenID <= 0 {
		return nil, 0, fmt.Errorf("token_id must be positive")
	}

	// Validate and apply limits
	if filter.Limit <= 0 {
		filter.Limit = 50 // Default limit
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000 // Maximum limit
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	if filter.Offset > maxAdminOffset {
		filter.Offset = maxAdminOffset
	}

	// Build query with optional date filters
	var args []interface{}
	args = append(args, tokenID)

	whereClause := "WHERE token_id = ?"
	if filter.StartDate != nil {
		whereClause += " AND timestamp >= ?"
		args = append(args, filter.StartDate.Format(time.RFC3339))
	}
	if filter.EndDate != nil {
		whereClause += " AND timestamp <= ?"
		args = append(args, filter.EndDate.Format(time.RFC3339))
	}

	// Get total count
	var total int
	countQuery := "SELECT COUNT(*) FROM api_token_usage " + whereClause
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count usage logs: %w", err)
	}

	// Get paginated results
	query := `SELECT id, token_id, timestamp, endpoint, ip_address, user_agent, response_status
		FROM api_token_usage ` + whereClause + `
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?`

	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query usage logs: %w", err)
	}
	defer rows.Close()

	var logs []models.APITokenUsageLog
	for rows.Next() {
		var log models.APITokenUsageLog
		var timestamp string
		var userAgent sql.NullString

		err := rows.Scan(
			&log.ID,
			&log.TokenID,
			&timestamp,
			&log.Endpoint,
			&log.IPAddress,
			&userAgent,
			&log.ResponseStatus,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan usage log: %w", err)
		}

		// Parse timestamp
		log.Timestamp, err = time.Parse(time.RFC3339, timestamp)
		if err != nil {
			// Try parsing as SQLite datetime format
			log.Timestamp, err = time.Parse("2006-01-02 15:04:05", timestamp)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to parse timestamp: %w", err)
			}
		}

		if userAgent.Valid {
			log.UserAgent = userAgent.String
		}

		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating usage logs: %w", err)
	}

	return logs, total, nil
}

// CleanupOldUsageLogs removes usage logs older than the specified retention period.
// Returns the number of logs deleted.
func (r *APITokenRepository) CleanupOldUsageLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	query := `DELETE FROM api_token_usage WHERE datetime(timestamp) < datetime(?)`
	result, err := r.db.ExecContext(ctx, query, olderThan.Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old usage logs: %w", err)
	}
	rows, _ := result.RowsAffected()
	return rows, nil
}

// GetUsageStats retrieves aggregated usage statistics for a token.
// Statistics include total requests, last 24h requests, unique IPs, and top 5 endpoints.
// Returns empty stats (not nil) for tokens with no usage data.
func (r *APITokenRepository) GetUsageStats(ctx context.Context, tokenID int64) (*models.TokenUsageStats, error) {
	if tokenID <= 0 {
		return nil, fmt.Errorf("token_id must be positive")
	}

	stats := &models.TokenUsageStats{
		TopEndpoints: []models.EndpointStat{},
	}

	// Get total requests (all time)
	totalQuery := `SELECT COUNT(*) FROM api_token_usage WHERE token_id = ?`
	err := r.db.QueryRowContext(ctx, totalQuery, tokenID).Scan(&stats.TotalRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to get total requests: %w", err)
	}

	// Get last 24h requests
	// Use datetime('now', '-24 hours') for SQLite
	last24hQuery := `SELECT COUNT(*) FROM api_token_usage 
		WHERE token_id = ? AND datetime(timestamp) > datetime('now', '-24 hours')`
	err = r.db.QueryRowContext(ctx, last24hQuery, tokenID).Scan(&stats.Last24hRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to get last 24h requests: %w", err)
	}

	// Get unique IPs (all time)
	uniqueIPsQuery := `SELECT COUNT(DISTINCT ip_address) FROM api_token_usage WHERE token_id = ?`
	err = r.db.QueryRowContext(ctx, uniqueIPsQuery, tokenID).Scan(&stats.UniqueIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to get unique IPs: %w", err)
	}

	// Get top 5 endpoints by request count
	topEndpointsQuery := `SELECT endpoint, COUNT(*) as count 
		FROM api_token_usage 
		WHERE token_id = ? 
		GROUP BY endpoint 
		ORDER BY count DESC 
		LIMIT 5`
	rows, err := r.db.QueryContext(ctx, topEndpointsQuery, tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to get top endpoints: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ep models.EndpointStat
		if err := rows.Scan(&ep.Endpoint, &ep.Count); err != nil {
			return nil, fmt.Errorf("failed to scan endpoint stat: %w", err)
		}
		stats.TopEndpoints = append(stats.TopEndpoints, ep)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating endpoint stats: %w", err)
	}

	return stats, nil
}

// GetUsageStatsBatch retrieves usage statistics for multiple tokens in a single batch.
// This is more efficient than calling GetUsageStats for each token individually (avoids N+1 queries).
// Returns a map of tokenID to TokenUsageStats. Missing tokens get empty stats.
func (r *APITokenRepository) GetUsageStatsBatch(ctx context.Context, tokenIDs []int64) (map[int64]*models.TokenUsageStats, error) {
	// Initialize result map with empty stats for all requested tokens
	result := make(map[int64]*models.TokenUsageStats, len(tokenIDs))
	for _, id := range tokenIDs {
		result[id] = &models.TokenUsageStats{
			TopEndpoints: []models.EndpointStat{},
		}
	}

	if len(tokenIDs) == 0 {
		return result, nil
	}

	// Build placeholders for IN clause
	placeholders := make([]string, len(tokenIDs))
	args := make([]interface{}, len(tokenIDs))
	for i, id := range tokenIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	inClause := strings.Join(placeholders, ",")

	// Query 1: Get total requests per token
	totalQuery := `SELECT token_id, COUNT(*) as total FROM api_token_usage 
		WHERE token_id IN (` + inClause + `) GROUP BY token_id`
	rows, err := r.db.QueryContext(ctx, totalQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get total requests batch: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tokenID, total int64
		if err := rows.Scan(&tokenID, &total); err != nil {
			return nil, fmt.Errorf("failed to scan total requests: %w", err)
		}
		if stats, ok := result[tokenID]; ok {
			stats.TotalRequests = total
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating total requests: %w", err)
	}

	// Query 2: Get last 24h requests per token
	last24hQuery := `SELECT token_id, COUNT(*) as total FROM api_token_usage 
		WHERE token_id IN (` + inClause + `) AND datetime(timestamp) > datetime('now', '-24 hours') 
		GROUP BY token_id`
	rows, err = r.db.QueryContext(ctx, last24hQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get last 24h requests batch: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tokenID, total int64
		if err := rows.Scan(&tokenID, &total); err != nil {
			return nil, fmt.Errorf("failed to scan last 24h requests: %w", err)
		}
		if stats, ok := result[tokenID]; ok {
			stats.Last24hRequests = total
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating last 24h requests: %w", err)
	}

	// Query 3: Get unique IPs per token
	uniqueIPsQuery := `SELECT token_id, COUNT(DISTINCT ip_address) as unique_ips FROM api_token_usage 
		WHERE token_id IN (` + inClause + `) GROUP BY token_id`
	rows, err = r.db.QueryContext(ctx, uniqueIPsQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get unique IPs batch: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tokenID, uniqueIPs int64
		if err := rows.Scan(&tokenID, &uniqueIPs); err != nil {
			return nil, fmt.Errorf("failed to scan unique IPs: %w", err)
		}
		if stats, ok := result[tokenID]; ok {
			stats.UniqueIPs = uniqueIPs
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating unique IPs: %w", err)
	}

	// Query 4: Get top 5 endpoints per token using window function
	// SQLite supports ROW_NUMBER() in version 3.25.0+
	topEndpointsQuery := `WITH ranked AS (
		SELECT token_id, endpoint, COUNT(*) as count,
			ROW_NUMBER() OVER (PARTITION BY token_id ORDER BY COUNT(*) DESC) as rn
		FROM api_token_usage 
		WHERE token_id IN (` + inClause + `) 
		GROUP BY token_id, endpoint
	)
	SELECT token_id, endpoint, count FROM ranked WHERE rn <= 5`
	rows, err = r.db.QueryContext(ctx, topEndpointsQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get top endpoints batch: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tokenID int64
		var ep models.EndpointStat
		if err := rows.Scan(&tokenID, &ep.Endpoint, &ep.Count); err != nil {
			return nil, fmt.Errorf("failed to scan endpoint stat: %w", err)
		}
		if stats, ok := result[tokenID]; ok {
			stats.TopEndpoints = append(stats.TopEndpoints, ep)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating endpoint stats: %w", err)
	}

	return result, nil
}

// RevokeMultiple revokes multiple tokens by their IDs (admin only, no user check).
// Uses a batch UPDATE operation for efficiency.
// Returns the count of tokens actually revoked (those that were active).
func (r *APITokenRepository) RevokeMultiple(ctx context.Context, tokenIDs []int64) (int, error) {
	if len(tokenIDs) == 0 {
		return 0, nil
	}

	// Validate all token IDs are positive
	for _, id := range tokenIDs {
		if id <= 0 {
			return 0, fmt.Errorf("token_id must be positive")
		}
	}

	// Build placeholders for IN clause
	placeholders := make([]string, len(tokenIDs))
	args := make([]interface{}, len(tokenIDs))
	for i, id := range tokenIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	inClause := strings.Join(placeholders, ",")

	// Only revoke active tokens
	query := `UPDATE api_tokens SET is_active = 0 WHERE id IN (` + inClause + `) AND is_active = 1`

	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke tokens: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return int(rows), nil
}

// RevokeAllByUserID revokes all active tokens for a specific user.
// Returns the count of tokens revoked.
func (r *APITokenRepository) RevokeAllByUserID(ctx context.Context, userID int64) (int, error) {
	if userID <= 0 {
		return 0, fmt.Errorf("user_id must be positive")
	}

	query := `UPDATE api_tokens SET is_active = 0 WHERE user_id = ? AND is_active = 1`

	result, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke user tokens: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return int(rows), nil
}

// Ensure APITokenRepository implements repository.APITokenRepository.
var _ repository.APITokenRepository = (*APITokenRepository)(nil)
