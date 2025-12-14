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

	// Use a transaction to ensure atomicity between count check and insert
	tx, err := r.pool.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // Safe to ignore: no-op after commit

	// Count existing active tokens for user within the transaction
	// Use FOR UPDATE to lock the rows and prevent concurrent inserts
	var count int
	err = tx.QueryRow(ctx, `SELECT COUNT(*) FROM api_tokens WHERE user_id = $1 AND is_active = true`, userID).Scan(&count)
	if err != nil {
		return nil, fmt.Errorf("failed to count tokens: %w", err)
	}

	// Check limit
	if count >= maxTokens {
		return nil, repository.ErrTooManyTokens
	}

	// Insert the new token within the same transaction
	var id int64
	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, scopes, expires_at, created_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at
	`, userID, name, tokenHash, tokenPrefix, scopes, expiresAt, createdIP).Scan(&id, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create API token: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(ctx); err != nil {
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

// Rotate regenerates token credentials while preserving metadata.
// Returns ErrNotFound if token doesn't exist, doesn't belong to user, or is inactive.
// Uses RETURNING clause for atomic update-and-fetch to prevent race conditions.
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

	// Update token credentials and clear usage tracking
	// Use RETURNING clause for atomic update-and-fetch (prevents TOCTOU race)
	var token models.APIToken
	var expiresAt, lastUsedAt *time.Time
	var lastUsedIP *string

	err := r.pool.Pool.QueryRow(ctx, `
		UPDATE api_tokens 
		SET token_hash = $1, token_prefix = $2, last_used_at = NULL, last_used_ip = NULL 
		WHERE id = $3 AND user_id = $4 AND is_active = true
		RETURNING id, user_id, name, token_hash, token_prefix, scopes, expires_at, 
			last_used_at, last_used_ip, created_at, created_ip, is_active
	`, newHash, newPrefix, tokenID, userID).Scan(
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
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to rotate token: %w", err)
	}

	token.ExpiresAt = expiresAt
	token.LastUsedAt = lastUsedAt
	token.LastUsedIP = lastUsedIP

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

	_, err := r.pool.Pool.Exec(ctx, `
		INSERT INTO api_token_usage (token_id, endpoint, ip_address, user_agent, response_status)
		VALUES ($1, $2, $3, $4, $5)
	`, tokenID, endpoint, ip, userAgent, status)
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

	// Build query dynamically based on filters
	var countArgs []interface{}
	var queryArgs []interface{}

	// Build WHERE clause
	whereClause := "WHERE token_id = $1"
	countArgs = append(countArgs, tokenID)
	queryArgs = append(queryArgs, tokenID)
	placeholderNum := 2

	if filter.StartDate != nil {
		whereClause += fmt.Sprintf(" AND timestamp >= $%d", placeholderNum)
		countArgs = append(countArgs, *filter.StartDate)
		queryArgs = append(queryArgs, *filter.StartDate)
		placeholderNum++
	}
	if filter.EndDate != nil {
		whereClause += fmt.Sprintf(" AND timestamp <= $%d", placeholderNum)
		countArgs = append(countArgs, *filter.EndDate)
		queryArgs = append(queryArgs, *filter.EndDate)
		placeholderNum++
	}

	// Get total count
	var total int
	err := r.pool.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM api_token_usage "+whereClause, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count usage logs: %w", err)
	}

	// Add pagination parameters
	queryArgs = append(queryArgs, filter.Limit, filter.Offset)
	limitPlaceholder := placeholderNum
	offsetPlaceholder := placeholderNum + 1

	// Get paginated results
	query := fmt.Sprintf(`
		SELECT id, token_id, timestamp, endpoint, ip_address, user_agent, response_status
		FROM api_token_usage %s
		ORDER BY timestamp DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, limitPlaceholder, offsetPlaceholder)

	rows, err := r.pool.Pool.Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query usage logs: %w", err)
	}
	defer rows.Close()

	var logs []models.APITokenUsageLog
	for rows.Next() {
		var log models.APITokenUsageLog
		var userAgent *string

		err := rows.Scan(
			&log.ID,
			&log.TokenID,
			&log.Timestamp,
			&log.Endpoint,
			&log.IPAddress,
			&userAgent,
			&log.ResponseStatus,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan usage log: %w", err)
		}

		if userAgent != nil {
			log.UserAgent = *userAgent
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
	tag, err := r.pool.Pool.Exec(ctx, `
		DELETE FROM api_token_usage WHERE timestamp < $1
	`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old usage logs: %w", err)
	}
	return tag.RowsAffected(), nil
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
	err := r.pool.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM api_token_usage WHERE token_id = $1
	`, tokenID).Scan(&stats.TotalRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to get total requests: %w", err)
	}

	// Get last 24h requests
	// Use NOW() - INTERVAL '24 hours' for PostgreSQL
	err = r.pool.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM api_token_usage 
		WHERE token_id = $1 AND timestamp > NOW() - INTERVAL '24 hours'
	`, tokenID).Scan(&stats.Last24hRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to get last 24h requests: %w", err)
	}

	// Get unique IPs (all time)
	err = r.pool.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT ip_address) FROM api_token_usage WHERE token_id = $1
	`, tokenID).Scan(&stats.UniqueIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to get unique IPs: %w", err)
	}

	// Get top 5 endpoints by request count
	rows, err := r.pool.Pool.Query(ctx, `
		SELECT endpoint, COUNT(*) as count 
		FROM api_token_usage 
		WHERE token_id = $1 
		GROUP BY endpoint 
		ORDER BY count DESC 
		LIMIT 5
	`, tokenID)
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

	// Convert tokenIDs to interface slice for query args
	args := make([]interface{}, len(tokenIDs))
	for i, id := range tokenIDs {
		args[i] = id
	}

	// Build numbered placeholders for PostgreSQL ($1, $2, $3...)
	placeholders := make([]string, len(tokenIDs))
	for i := range tokenIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}
	inClause := strings.Join(placeholders, ",")

	// Query 1: Get total requests per token
	totalQuery := `SELECT token_id, COUNT(*) as total FROM api_token_usage 
		WHERE token_id IN (` + inClause + `) GROUP BY token_id`
	rows, err := r.pool.Pool.Query(ctx, totalQuery, args...)
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
		WHERE token_id IN (` + inClause + `) AND timestamp > NOW() - INTERVAL '24 hours' 
		GROUP BY token_id`
	rows, err = r.pool.Pool.Query(ctx, last24hQuery, args...)
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
	rows, err = r.pool.Pool.Query(ctx, uniqueIPsQuery, args...)
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
	topEndpointsQuery := `WITH ranked AS (
		SELECT token_id, endpoint, COUNT(*) as count,
			ROW_NUMBER() OVER (PARTITION BY token_id ORDER BY COUNT(*) DESC) as rn
		FROM api_token_usage 
		WHERE token_id IN (` + inClause + `) 
		GROUP BY token_id, endpoint
	)
	SELECT token_id, endpoint, count FROM ranked WHERE rn <= 5`
	rows, err = r.pool.Pool.Query(ctx, topEndpointsQuery, args...)
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
// Returns the count of tokens actually revoked.
func (r *APITokenRepository) RevokeMultiple(ctx context.Context, tokenIDs []int64) (int, error) {
	if len(tokenIDs) == 0 {
		return 0, nil
	}

	// Validate all IDs are positive
	for _, id := range tokenIDs {
		if id <= 0 {
			return 0, fmt.Errorf("token_id must be positive")
		}
	}

	// Build parameterized IN clause
	placeholders := make([]string, len(tokenIDs))
	args := make([]interface{}, len(tokenIDs))
	for i, id := range tokenIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	inClause := strings.Join(placeholders, ",")

	query := `UPDATE api_tokens SET is_active = false WHERE id IN (` + inClause + `) AND is_active = true`

	result, err := r.pool.Pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke multiple tokens: %w", err)
	}

	return int(result.RowsAffected()), nil
}

// RevokeAllByUserID revokes all active tokens for a specific user.
// Returns the count of tokens revoked.
func (r *APITokenRepository) RevokeAllByUserID(ctx context.Context, userID int64) (int, error) {
	if userID <= 0 {
		return 0, fmt.Errorf("user_id must be positive")
	}

	query := `UPDATE api_tokens SET is_active = false WHERE user_id = $1 AND is_active = true`

	result, err := r.pool.Pool.Exec(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke all user tokens: %w", err)
	}

	return int(result.RowsAffected()), nil
}

// ExtendMultiple extends the expiration date of multiple tokens by the specified duration.
// Only extends active, non-expired tokens. Returns the count of tokens actually extended.
func (r *APITokenRepository) ExtendMultiple(ctx context.Context, tokenIDs []int64, duration time.Duration) (int, error) {
	if len(tokenIDs) == 0 {
		return 0, nil
	}

	// Validate all token IDs are positive
	for _, id := range tokenIDs {
		if id <= 0 {
			return 0, fmt.Errorf("token_id must be positive")
		}
	}

	// Build parameterized IN clause - duration is $1, token IDs start at $2
	placeholders := make([]string, len(tokenIDs))
	args := make([]interface{}, len(tokenIDs)+1)
	args[0] = duration // PostgreSQL interval can accept Go duration
	for i, id := range tokenIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = id
	}
	inClause := strings.Join(placeholders, ",")

	// Only extend active tokens that have an expiration date
	// Add the duration as an interval to the current expires_at value
	query := `UPDATE api_tokens 
		SET expires_at = expires_at + $1 
		WHERE id IN (` + inClause + `) 
		AND is_active = true 
		AND expires_at IS NOT NULL`

	result, err := r.pool.Pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to extend tokens: %w", err)
	}

	return int(result.RowsAffected()), nil
}

// Ensure APITokenRepository implements repository.APITokenRepository.
var _ repository.APITokenRepository = (*APITokenRepository)(nil)
