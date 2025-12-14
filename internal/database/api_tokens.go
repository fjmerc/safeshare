package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// CreateAPIToken creates a new API token in the database
func CreateAPIToken(db *sql.DB, userID int64, name, tokenHash, tokenPrefix, scopes, createdIP string, expiresAt *time.Time) (*models.APIToken, error) {
	query := `INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, scopes, expires_at, created_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	var expiresAtStr *string
	if expiresAt != nil {
		s := expiresAt.Format(time.RFC3339)
		expiresAtStr = &s
	}

	result, err := db.Exec(query, userID, name, tokenHash, tokenPrefix, scopes, expiresAtStr, createdIP)
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

// GetAPITokenByHash retrieves an API token by its hash (for validation during auth)
// Returns nil, nil if token not found or inactive
func GetAPITokenByHash(db *sql.DB, tokenHash string) (*models.APIToken, error) {
	query := `SELECT id, user_id, name, token_hash, token_prefix, scopes, expires_at, 
		last_used_at, last_used_ip, created_at, created_ip, is_active
		FROM api_tokens WHERE token_hash = ? AND is_active = 1`

	var token models.APIToken
	var createdAt string
	var expiresAt, lastUsedAt sql.NullString
	var lastUsedIP sql.NullString

	err := db.QueryRow(query, tokenHash).Scan(
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
	token.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)

	if expiresAt.Valid {
		t, _ := time.Parse(time.RFC3339, expiresAt.String)
		token.ExpiresAt = &t
	}
	if lastUsedAt.Valid {
		t, _ := time.Parse(time.RFC3339, lastUsedAt.String)
		token.LastUsedAt = &t
	}
	if lastUsedIP.Valid {
		token.LastUsedIP = &lastUsedIP.String
	}

	return &token, nil
}

// UpdateAPITokenLastUsed updates the last used timestamp and IP for a token
func UpdateAPITokenLastUsed(db *sql.DB, tokenID int64, ip string) error {
	query := `UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?`
	now := time.Now().Format(time.RFC3339)
	_, err := db.Exec(query, now, ip, tokenID)
	if err != nil {
		return fmt.Errorf("failed to update token last used: %w", err)
	}
	return nil
}

// GetAPITokensByUserID retrieves all active tokens for a user
func GetAPITokensByUserID(db *sql.DB, userID int64) ([]models.APITokenListItem, error) {
	query := `SELECT id, name, token_prefix, scopes, expires_at, last_used_at, created_at, is_active
		FROM api_tokens WHERE user_id = ? AND is_active = 1 ORDER BY created_at DESC`

	rows, err := db.Query(query, userID)
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

		token.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		if expiresAt.Valid {
			t, _ := time.Parse(time.RFC3339, expiresAt.String)
			token.ExpiresAt = &t
		}
		if lastUsedAt.Valid {
			t, _ := time.Parse(time.RFC3339, lastUsedAt.String)
			token.LastUsedAt = &t
		}

		// Convert scopes string to slice
		token.Scopes = strings.Split(scopes, ",")

		tokens = append(tokens, token)
	}

	return tokens, rows.Err()
}

// RevokeAPIToken soft-deletes a token (sets is_active = 0) for a specific user
// Returns error if token not found or doesn't belong to user
func RevokeAPIToken(db *sql.DB, tokenID, userID int64) error {
	query := `UPDATE api_tokens SET is_active = 0 WHERE id = ? AND user_id = ?`
	result, err := db.Exec(query, tokenID, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("token not found or does not belong to user")
	}
	return nil
}

// RevokeAPITokenAdmin revokes any token (admin only, no user check)
func RevokeAPITokenAdmin(db *sql.DB, tokenID int64) error {
	query := `UPDATE api_tokens SET is_active = 0 WHERE id = ?`
	result, err := db.Exec(query, tokenID)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}

// DeleteAPITokenAdmin permanently deletes any token (admin only, no user check)
// This performs a hard delete, removing the token from the database entirely
func DeleteAPITokenAdmin(db *sql.DB, tokenID int64) error {
	query := `DELETE FROM api_tokens WHERE id = ?`
	result, err := db.Exec(query, tokenID)
	if err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}

// DeleteAPITokensByUserID removes all tokens for a user (used when user is deleted)
// This is a hard delete since user is being deleted
func DeleteAPITokensByUserID(db *sql.DB, userID int64) error {
	query := `DELETE FROM api_tokens WHERE user_id = ?`
	_, err := db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user tokens: %w", err)
	}
	return nil
}

// GetAllAPITokensAdmin retrieves all tokens for admin view with pagination
func GetAllAPITokensAdmin(db *sql.DB, limit, offset int) ([]models.APITokenListItem, int, error) {
	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM api_tokens`
	err := db.QueryRow(countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count tokens: %w", err)
	}

	query := `SELECT t.id, t.user_id, t.name, t.token_prefix, t.scopes, t.expires_at, 
		t.last_used_at, t.created_at, t.is_active, u.username
		FROM api_tokens t
		LEFT JOIN users u ON t.user_id = u.id
		ORDER BY t.created_at DESC
		LIMIT ? OFFSET ?`

	rows, err := db.Query(query, limit, offset)
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

		token.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		if expiresAt.Valid {
			t, _ := time.Parse(time.RFC3339, expiresAt.String)
			token.ExpiresAt = &t
		}
		if lastUsedAt.Valid {
			t, _ := time.Parse(time.RFC3339, lastUsedAt.String)
			token.LastUsedAt = &t
		}
		if username.Valid {
			token.Username = username.String
		}

		// Convert scopes string to slice
		token.Scopes = strings.Split(scopes, ",")

		tokens = append(tokens, token)
	}

	return tokens, total, rows.Err()
}

// CleanupExpiredAPITokens removes expired tokens
// Note: Uses datetime() for RFC3339 comparison compatibility
func CleanupExpiredAPITokens(db *sql.DB) (int64, error) {
	query := `DELETE FROM api_tokens WHERE expires_at IS NOT NULL AND datetime(expires_at) < datetime('now')`
	result, err := db.Exec(query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}
	rows, _ := result.RowsAffected()
	return rows, nil
}

// CountAPITokensByUserID returns the count of active tokens for a user
func CountAPITokensByUserID(db *sql.DB, userID int64) (int, error) {
	query := `SELECT COUNT(*) FROM api_tokens WHERE user_id = ? AND is_active = 1`
	var count int
	err := db.QueryRow(query, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count user tokens: %w", err)
	}
	return count, nil
}

// GetAPITokenByID retrieves a token by ID (for admin operations)
func GetAPITokenByID(db *sql.DB, tokenID int64) (*models.APIToken, error) {
	query := `SELECT id, user_id, name, token_hash, token_prefix, scopes, expires_at, 
		last_used_at, last_used_ip, created_at, created_ip, is_active
		FROM api_tokens WHERE id = ?`

	var token models.APIToken
	var createdAt string
	var expiresAt, lastUsedAt sql.NullString
	var lastUsedIP sql.NullString

	err := db.QueryRow(query, tokenID).Scan(
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
	token.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)

	if expiresAt.Valid {
		t, _ := time.Parse(time.RFC3339, expiresAt.String)
		token.ExpiresAt = &t
	}
	if lastUsedAt.Valid {
		t, _ := time.Parse(time.RFC3339, lastUsedAt.String)
		token.LastUsedAt = &t
	}
	if lastUsedIP.Valid {
		token.LastUsedIP = &lastUsedIP.String
	}

	return &token, nil
}
