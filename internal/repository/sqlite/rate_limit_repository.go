package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
)

// RateLimitRepository implements repository.RateLimitRepository for SQLite.
type RateLimitRepository struct {
	db *sql.DB
}

// NewRateLimitRepository creates a new SQLite rate limit repository.
func NewRateLimitRepository(db *sql.DB) *RateLimitRepository {
	return &RateLimitRepository{db: db}
}

// Maximum request count to prevent integer overflow.
// Any legitimate rate limit should be far below this value.
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

// validateIPAddress checks if the IP address is valid and within length limits.
func validateIPAddress(ipAddress string) error {
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
// Uses SQLite's transaction for atomic operation and handles window expiration.
// SECURITY: Validates all inputs and protects against integer overflow.
func (r *RateLimitRepository) IncrementAndCheck(ctx context.Context, ipAddress, limitType string, limit int, windowDuration time.Duration) (bool, int, error) {
	// Validate IP address
	if err := validateIPAddress(ipAddress); err != nil {
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
	nowRFC3339 := now.Format(time.RFC3339)
	windowEndRFC3339 := windowEnd.Format(time.RFC3339)

	// Use a transaction with BEGIN IMMEDIATE for proper SQLite locking
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return false, 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// First, check if entry exists and if window has expired
	var existingCount int
	var existingWindowEnd string
	var exists bool

	query := `SELECT request_count, window_end FROM rate_limits WHERE ip_address = ? AND limit_type = ?`
	err = tx.QueryRowContext(ctx, query, ipAddress, limitType).Scan(&existingCount, &existingWindowEnd)
	if err == sql.ErrNoRows {
		exists = false
	} else if err != nil {
		return false, 0, fmt.Errorf("failed to query rate limit: %w", err)
	} else {
		exists = true
	}

	var newCount int
	if exists {
		// Parse existing window end
		windowEndTime, err := time.Parse(time.RFC3339, existingWindowEnd)
		if err != nil {
			// Try alternate SQLite format
			windowEndTime, err = time.Parse("2006-01-02 15:04:05", existingWindowEnd)
			if err != nil {
				return false, 0, fmt.Errorf("failed to parse window_end: %w", err)
			}
		}

		// Check if window has expired
		if now.After(windowEndTime) {
			// Window expired - reset counter
			newCount = 1
			updateQuery := `UPDATE rate_limits SET request_count = 1, window_end = ?, updated_at = ? WHERE ip_address = ? AND limit_type = ?`
			_, err = tx.ExecContext(ctx, updateQuery, windowEndRFC3339, nowRFC3339, ipAddress, limitType)
			if err != nil {
				return false, 0, fmt.Errorf("failed to reset rate limit: %w", err)
			}
		} else {
			// Window still active - increment counter with overflow protection
			if existingCount >= maxRequestCount {
				// Already at max - deny and don't increment (prevents overflow)
				return false, existingCount, nil
			}
			newCount = existingCount + 1
			updateQuery := `UPDATE rate_limits SET request_count = ?, updated_at = ? WHERE ip_address = ? AND limit_type = ?`
			_, err = tx.ExecContext(ctx, updateQuery, newCount, nowRFC3339, ipAddress, limitType)
			if err != nil {
				return false, 0, fmt.Errorf("failed to increment rate limit: %w", err)
			}
		}
	} else {
		// No entry exists - create new one
		newCount = 1
		insertQuery := `INSERT INTO rate_limits (ip_address, limit_type, request_count, window_end, created_at, updated_at) VALUES (?, ?, 1, ?, ?, ?)`
		_, err = tx.ExecContext(ctx, insertQuery, ipAddress, limitType, windowEndRFC3339, nowRFC3339, nowRFC3339)
		if err != nil {
			return false, 0, fmt.Errorf("failed to create rate limit: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return false, 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Return whether the request is allowed (count before this request was under limit)
	allowed := newCount <= limit
	return allowed, newCount, nil
}

// GetEntry retrieves the rate limit entry for an IP/type combination.
// Returns nil, nil if no entry exists.
func (r *RateLimitRepository) GetEntry(ctx context.Context, ipAddress, limitType string) (*repository.RateLimitEntry, error) {
	query := `SELECT id, ip_address, limit_type, request_count, window_end, created_at, updated_at 
		FROM rate_limits WHERE ip_address = ? AND limit_type = ?`

	var entry repository.RateLimitEntry
	var windowEnd, createdAt, updatedAt string

	err := r.db.QueryRowContext(ctx, query, ipAddress, limitType).Scan(
		&entry.ID,
		&entry.IPAddress,
		&entry.LimitType,
		&entry.Count,
		&windowEnd,
		&createdAt,
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get rate limit entry: %w", err)
	}

	// Parse timestamps
	entry.WindowEnd, err = parseTimestamp(windowEnd)
	if err != nil {
		return nil, fmt.Errorf("failed to parse window_end: %w", err)
	}

	entry.CreatedAt, err = parseTimestamp(createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	entry.UpdatedAt, err = parseTimestamp(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at: %w", err)
	}

	return &entry, nil
}

// ResetEntry resets the rate limit for an IP/type combination.
func (r *RateLimitRepository) ResetEntry(ctx context.Context, ipAddress, limitType string) error {
	query := `DELETE FROM rate_limits WHERE ip_address = ? AND limit_type = ?`

	_, err := r.db.ExecContext(ctx, query, ipAddress, limitType)
	if err != nil {
		return fmt.Errorf("failed to reset rate limit: %w", err)
	}

	return nil
}

// CleanupExpired removes rate limit entries that have expired.
// Returns the number of entries removed.
func (r *RateLimitRepository) CleanupExpired(ctx context.Context) (int64, error) {
	// Delete entries where window has expired (with some grace period of 1 hour)
	query := `DELETE FROM rate_limits WHERE datetime(window_end) < datetime('now', '-1 hour')`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired rate limits: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected > 0 {
		slog.Debug("cleaned up expired rate limit entries", "count", rowsAffected)
	}

	return rowsAffected, nil
}

// GetAllEntriesForIP retrieves all rate limit entries for a given IP.
func (r *RateLimitRepository) GetAllEntriesForIP(ctx context.Context, ipAddress string) ([]repository.RateLimitEntry, error) {
	query := `SELECT id, ip_address, limit_type, request_count, window_end, created_at, updated_at 
		FROM rate_limits WHERE ip_address = ? ORDER BY limit_type`

	rows, err := r.db.QueryContext(ctx, query, ipAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to query rate limits for IP: %w", err)
	}
	defer rows.Close()

	var entries []repository.RateLimitEntry
	for rows.Next() {
		var entry repository.RateLimitEntry
		var windowEnd, createdAt, updatedAt string

		err := rows.Scan(
			&entry.ID,
			&entry.IPAddress,
			&entry.LimitType,
			&entry.Count,
			&windowEnd,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rate limit entry: %w", err)
		}

		entry.WindowEnd, _ = parseTimestamp(windowEnd)
		entry.CreatedAt, _ = parseTimestamp(createdAt)
		entry.UpdatedAt, _ = parseTimestamp(updatedAt)

		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rate limits: %w", err)
	}

	return entries, nil
}

// parseTimestamp attempts to parse a timestamp string from SQLite
func parseTimestamp(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// Try alternate SQLite format
		t, err = time.Parse("2006-01-02 15:04:05", s)
	}
	return t, err
}

// Ensure RateLimitRepository implements repository.RateLimitRepository.
var _ repository.RateLimitRepository = (*RateLimitRepository)(nil)
