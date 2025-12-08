package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/jackc/pgx/v5"
)

// RateLimitRepository implements repository.RateLimitRepository for PostgreSQL.
type RateLimitRepository struct {
	pool *Pool
}

// NewRateLimitRepository creates a new PostgreSQL rate limit repository.
func NewRateLimitRepository(pool *Pool) *RateLimitRepository {
	return &RateLimitRepository{pool: pool}
}

// Maximum request count to prevent integer overflow.
const maxRequestCount = 1000000000 // 1 billion

// Maximum allowed rate limit value to prevent configuration errors.
const maxRateLimit = 10000

// validLimitTypes defines the allowed limit types for defense-in-depth.
var validLimitTypes = map[string]bool{
	"upload":       true,
	"download":     true,
	"chunk":        true,
	"regeneration": true,
	"admin_login":  true,
	"user_login":   true,
}

// validateIPAddressPG checks if the IP address is valid and within length limits.
func validateIPAddressPG(ipAddress string) error {
	if ipAddress == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	if len(ipAddress) > 45 { // Max IPv6 with zone ID
		return fmt.Errorf("IP address too long")
	}
	if net.ParseIP(ipAddress) == nil {
		return fmt.Errorf("invalid IP address format")
	}
	return nil
}

// IncrementAndCheck atomically increments the request count for an IP/type combination
// and returns whether the request should be allowed based on the limit.
//
// Uses PostgreSQL transactions with FOR UPDATE for atomic operation.
// SECURITY: Validates all inputs and protects against integer overflow.
func (r *RateLimitRepository) IncrementAndCheck(ctx context.Context, ipAddress, limitType string, limit int, windowDuration time.Duration) (bool, int, error) {
	// Validate IP address
	if err := validateIPAddressPG(ipAddress); err != nil {
		return false, 0, err
	}

	// Validate limit type
	if limitType == "" {
		return false, 0, fmt.Errorf("limit type cannot be empty")
	}
	if len(limitType) > 32 {
		return false, 0, fmt.Errorf("limit type too long")
	}
	if !validLimitTypes[limitType] {
		return false, 0, fmt.Errorf("invalid limit type: %s", limitType)
	}

	// Validate limit bounds
	if limit <= 0 {
		return false, 0, fmt.Errorf("limit must be positive")
	}
	if limit > maxRateLimit {
		return false, 0, fmt.Errorf("limit exceeds maximum allowed value of %d", maxRateLimit)
	}

	if windowDuration <= 0 {
		return false, 0, fmt.Errorf("window duration must be positive")
	}

	now := time.Now()
	windowEnd := now.Add(windowDuration)

	// Use a transaction for atomicity with retry for serialization failures
	var newCount int
	err := withRetryNoReturn(ctx, 3, func() error {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback(ctx)

		// First, check if entry exists and if window has expired
		var existingCount int
		var existingWindowEnd time.Time
		var exists bool

		query := `SELECT request_count, window_end FROM rate_limits WHERE ip_address = $1 AND limit_type = $2 FOR UPDATE`
		err = tx.QueryRow(ctx, query, ipAddress, limitType).Scan(&existingCount, &existingWindowEnd)
		if err == pgx.ErrNoRows {
			exists = false
		} else if err != nil {
			return fmt.Errorf("failed to query rate limit: %w", err)
		} else {
			exists = true
		}

		if exists {
			// Check if window has expired
			if now.After(existingWindowEnd) {
				// Window expired - reset counter
				newCount = 1
				updateQuery := `UPDATE rate_limits SET request_count = 1, window_end = $1, updated_at = $2 WHERE ip_address = $3 AND limit_type = $4`
				_, err = tx.Exec(ctx, updateQuery, windowEnd, now, ipAddress, limitType)
				if err != nil {
					return fmt.Errorf("failed to reset rate limit: %w", err)
				}
			} else {
				// Window still active - increment counter with overflow protection
				if existingCount >= maxRequestCount {
					// Already at max - deny without incrementing (prevents overflow)
					newCount = existingCount
					return nil // Commit transaction and return
				}
				newCount = existingCount + 1
				updateQuery := `UPDATE rate_limits SET request_count = $1, updated_at = $2 WHERE ip_address = $3 AND limit_type = $4`
				_, err = tx.Exec(ctx, updateQuery, newCount, now, ipAddress, limitType)
				if err != nil {
					return fmt.Errorf("failed to increment rate limit: %w", err)
				}
			}
		} else {
			// No entry exists - create new one
			newCount = 1
			insertQuery := `INSERT INTO rate_limits (ip_address, limit_type, request_count, window_end, created_at, updated_at) VALUES ($1, $2, 1, $3, $4, $5)`
			_, err = tx.Exec(ctx, insertQuery, ipAddress, limitType, windowEnd, now, now)
			if err != nil {
				return fmt.Errorf("failed to create rate limit: %w", err)
			}
		}

		return tx.Commit(ctx)
	})

	if err != nil {
		return false, 0, err
	}

	// Return whether the request is allowed (count before this request was under limit)
	allowed := newCount <= limit
	return allowed, newCount, nil
}

// GetEntry retrieves the rate limit entry for an IP/type combination.
// Returns nil, nil if no entry exists.
func (r *RateLimitRepository) GetEntry(ctx context.Context, ipAddress, limitType string) (*repository.RateLimitEntry, error) {
	query := `SELECT id, ip_address, limit_type, request_count, window_end, created_at, updated_at 
		FROM rate_limits WHERE ip_address = $1 AND limit_type = $2`

	var entry repository.RateLimitEntry
	err := r.pool.QueryRow(ctx, query, ipAddress, limitType).Scan(
		&entry.ID,
		&entry.IPAddress,
		&entry.LimitType,
		&entry.Count,
		&entry.WindowEnd,
		&entry.CreatedAt,
		&entry.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get rate limit entry: %w", err)
	}

	return &entry, nil
}

// ResetEntry resets the rate limit for an IP/type combination.
func (r *RateLimitRepository) ResetEntry(ctx context.Context, ipAddress, limitType string) error {
	query := `DELETE FROM rate_limits WHERE ip_address = $1 AND limit_type = $2`

	_, err := r.pool.Exec(ctx, query, ipAddress, limitType)
	if err != nil {
		return fmt.Errorf("failed to reset rate limit: %w", err)
	}

	return nil
}

// CleanupExpired removes rate limit entries that have expired.
// Returns the number of entries removed.
func (r *RateLimitRepository) CleanupExpired(ctx context.Context) (int64, error) {
	// Delete entries where window has expired (with some grace period of 1 hour)
	query := `DELETE FROM rate_limits WHERE window_end < NOW() - INTERVAL '1 hour'`

	result, err := r.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired rate limits: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected > 0 {
		slog.Debug("cleaned up expired rate limit entries", "count", rowsAffected)
	}

	return rowsAffected, nil
}

// GetAllEntriesForIP retrieves all rate limit entries for a given IP.
func (r *RateLimitRepository) GetAllEntriesForIP(ctx context.Context, ipAddress string) ([]repository.RateLimitEntry, error) {
	query := `SELECT id, ip_address, limit_type, request_count, window_end, created_at, updated_at 
		FROM rate_limits WHERE ip_address = $1 ORDER BY limit_type`

	rows, err := r.pool.Query(ctx, query, ipAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to query rate limits for IP: %w", err)
	}
	defer rows.Close()

	var entries []repository.RateLimitEntry
	for rows.Next() {
		var entry repository.RateLimitEntry
		err := rows.Scan(
			&entry.ID,
			&entry.IPAddress,
			&entry.LimitType,
			&entry.Count,
			&entry.WindowEnd,
			&entry.CreatedAt,
			&entry.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rate limit entry: %w", err)
		}
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rate limits: %w", err)
	}

	return entries, nil
}

// Ensure RateLimitRepository implements repository.RateLimitRepository.
var _ repository.RateLimitRepository = (*RateLimitRepository)(nil)
