package repository

import (
	"context"
	"errors"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// UsageFilter defines the filter parameters for token usage log queries.
type UsageFilter struct {
	StartDate *time.Time // Filter logs from this date
	EndDate   *time.Time // Filter logs until this date
	Limit     int        // Maximum number of records to return
	Offset    int        // Number of records to skip (for pagination)
}

// ErrTooManyTokens is returned when a user has reached their token limit.
var ErrTooManyTokens = errors.New("maximum number of tokens reached")

// APITokenRepository defines the interface for API token database operations.
// All methods accept a context for cancellation and timeout support.
type APITokenRepository interface {
	// Create inserts a new API token into the database.
	// Returns the created token with populated ID and timestamps.
	Create(ctx context.Context, userID int64, name, tokenHash, tokenPrefix, scopes, createdIP string, expiresAt *time.Time) (*models.APIToken, error)

	// CreateWithLimit creates a new API token with atomic limit enforcement.
	// Uses a database transaction to prevent race conditions between count check and insert.
	// Returns ErrTooManyTokens if the user has reached or exceeded maxTokens.
	CreateWithLimit(ctx context.Context, userID int64, name, tokenHash, tokenPrefix, scopes, createdIP string, expiresAt *time.Time, maxTokens int) (*models.APIToken, error)

	// GetByHash retrieves an API token by its hash (for validation during auth).
	// Returns nil, nil if token not found or inactive.
	GetByHash(ctx context.Context, tokenHash string) (*models.APIToken, error)

	// GetByID retrieves a token by ID (for admin operations).
	// Returns nil, nil if not found.
	GetByID(ctx context.Context, tokenID int64) (*models.APIToken, error)

	// UpdateLastUsed updates the last used timestamp and IP for a token.
	UpdateLastUsed(ctx context.Context, tokenID int64, ip string) error

	// GetByUserID retrieves all active tokens for a user.
	GetByUserID(ctx context.Context, userID int64) ([]models.APITokenListItem, error)

	// CountByUserID returns the count of active tokens for a user.
	CountByUserID(ctx context.Context, userID int64) (int, error)

	// Revoke soft-deletes a token (sets is_active = 0) for a specific user.
	// Returns ErrNotFound if token not found or doesn't belong to user.
	Revoke(ctx context.Context, tokenID, userID int64) error

	// RevokeAdmin revokes any token (admin only, no user check).
	// Returns ErrNotFound if token not found.
	RevokeAdmin(ctx context.Context, tokenID int64) error

	// DeleteByUserID removes all tokens for a user (used when user is deleted).
	// This is a hard delete since user is being deleted.
	DeleteByUserID(ctx context.Context, userID int64) error

	// GetAllAdmin retrieves all tokens for admin view with pagination.
	// Returns (tokens, totalCount, error).
	GetAllAdmin(ctx context.Context, limit, offset int) ([]models.APITokenListItem, int, error)

	// CleanupExpired removes expired tokens.
	// Returns the number of tokens deleted.
	CleanupExpired(ctx context.Context) (int64, error)

	// Rotate regenerates token credentials while preserving metadata (name, scopes, expiration).
	// The old token is immediately invalidated and replaced with the new hash/prefix.
	// Clears last_used_at and last_used_ip since the new token hasn't been used yet.
	// Returns ErrNotFound if token doesn't exist, doesn't belong to user, or is inactive.
	Rotate(ctx context.Context, tokenID, userID int64, newHash, newPrefix string) (*models.APIToken, error)

	// LogUsage records a token usage event for audit purposes.
	// This should be called after each API request authenticated with this token.
	LogUsage(ctx context.Context, tokenID int64, endpoint, ip, userAgent string, status int) error

	// GetUsageLogs retrieves paginated usage logs for a specific token.
	// Returns (logs, totalCount, error) with optional date filtering.
	GetUsageLogs(ctx context.Context, tokenID int64, filter UsageFilter) ([]models.APITokenUsageLog, int, error)

	// CleanupOldUsageLogs removes usage logs older than the specified retention period.
	// Returns the number of logs deleted.
	CleanupOldUsageLogs(ctx context.Context, olderThan time.Time) (int64, error)

	// GetUsageStats retrieves aggregated usage statistics for a token.
	// Statistics include total requests, last 24h requests, unique IPs, and top 5 endpoints.
	// Returns empty stats (not nil) for tokens with no usage data.
	GetUsageStats(ctx context.Context, tokenID int64) (*models.TokenUsageStats, error)

	// GetUsageStatsBatch retrieves usage statistics for multiple tokens in a single batch.
	// This is more efficient than calling GetUsageStats for each token individually.
	// Returns a map of tokenID to TokenUsageStats. Missing tokens get empty stats.
	GetUsageStatsBatch(ctx context.Context, tokenIDs []int64) (map[int64]*models.TokenUsageStats, error)

	// RevokeMultiple revokes multiple tokens by their IDs (admin only, no user check).
	// Returns the count of tokens actually revoked.
	RevokeMultiple(ctx context.Context, tokenIDs []int64) (int, error)

	// RevokeAllByUserID revokes all active tokens for a specific user.
	// Returns the count of tokens revoked.
	RevokeAllByUserID(ctx context.Context, userID int64) (int, error)

	// ExtendMultiple extends the expiration date of multiple tokens by the specified duration.
	// Only extends active, non-expired tokens. Returns the count of tokens actually extended.
	ExtendMultiple(ctx context.Context, tokenIDs []int64, duration time.Duration) (int, error)
}
