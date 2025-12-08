// Package postgres provides PostgreSQL implementations of repository interfaces.
package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgreSQL error codes
const (
	// UniqueViolation is the PostgreSQL error code for unique constraint violations.
	UniqueViolation = "23505"
	// ForeignKeyViolation is the PostgreSQL error code for foreign key violations.
	ForeignKeyViolation = "23503"
	// SerializationFailure is the PostgreSQL error code for serialization failures.
	SerializationFailure = "40001"
	// DeadlockDetected is the PostgreSQL error code for deadlock detection.
	DeadlockDetected = "40P01"
)

// Pool wraps pgxpool.Pool to provide a consistent interface.
type Pool struct {
	*pgxpool.Pool
}

// NewPool creates a new PostgreSQL connection pool.
func NewPool(ctx context.Context, connString string, maxConns int32) (*Pool, error) {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Configure pool settings
	if maxConns > 0 {
		config.MaxConns = maxConns
	} else {
		config.MaxConns = 25 // Default max connections
	}

	config.MinConns = 5
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 30 * time.Minute
	config.HealthCheckPeriod = 1 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Pool{Pool: pool}, nil
}

// validateStoredFilename validates that a stored filename is safe to use in file paths.
// This is a defense-in-depth measure to prevent path traversal attacks.
func validateStoredFilename(filename string) error {
	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}
	if strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		return fmt.Errorf("filename contains path separator")
	}
	if strings.Contains(filename, "..") {
		return fmt.Errorf("filename contains path traversal sequence")
	}
	if strings.HasPrefix(filename, ".") {
		return fmt.Errorf("filename starts with dot (hidden file)")
	}
	for _, char := range filename {
		isValid := (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' ||
			char == '_' ||
			char == '.'
		if !isValid {
			return fmt.Errorf("filename contains invalid character: %c", char)
		}
	}
	return nil
}

// escapeLikePattern escapes SQL LIKE wildcard characters (% and _) to prevent LIKE injection.
func escapeLikePattern(s string) string {
	// Remove null bytes (defense in depth)
	s = strings.ReplaceAll(s, "\x00", "")
	// Replace \ with \\ first to avoid double-escaping
	s = strings.ReplaceAll(s, "\\", "\\\\")
	// Escape % and _ wildcards
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}

// generateClaimCode generates a cryptographically secure claim code.
// The code is 8 characters using URL-safe base64 alphabet (6 random bytes = ~36 bits of entropy).
func generateClaimCode() (string, error) {
	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// isRetryableError checks if an error is a transient PostgreSQL error worth retrying.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case SerializationFailure, DeadlockDetected:
			return true
		}
	}

	return false
}

// isUniqueViolation checks if an error is a unique constraint violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == UniqueViolation
	}
	return false
}

// withRetry executes a function with exponential backoff retry logic for transient errors.
func withRetry[T any](ctx context.Context, maxRetries int, fn func() (T, error)) (T, error) {
	var zero T
	var lastErr error
	baseDelay := 50 * time.Millisecond

	for attempt := 0; attempt <= maxRetries; attempt++ {
		result, err := fn()
		if err == nil {
			return result, nil
		}

		lastErr = err

		if !isRetryableError(err) {
			return zero, err
		}

		if attempt < maxRetries {
			delay := baseDelay * time.Duration(1<<uint(attempt))
			select {
			case <-ctx.Done():
				return zero, ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	return zero, fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

// withRetryNoReturn executes a function with exponential backoff retry logic for transient errors.
// This variant is for functions that don't return a value.
func withRetryNoReturn(ctx context.Context, maxRetries int, fn func() error) error {
	var lastErr error
	baseDelay := 50 * time.Millisecond

	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		if !isRetryableError(err) {
			return err
		}

		if attempt < maxRetries {
			delay := baseDelay * time.Duration(1<<uint(attempt))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	return fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

// TxOptions returns the default transaction options for PostgreSQL.
func TxOptions() pgx.TxOptions {
	return pgx.TxOptions{
		IsoLevel:   pgx.Serializable,
		AccessMode: pgx.ReadWrite,
	}
}

// scanNullableString scans a nullable string and returns the value if valid.
func scanNullableString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

// scanNullableInt64 scans a nullable int64 and returns a pointer if valid.
func scanNullableInt64(ni sql.NullInt64) *int64 {
	if ni.Valid {
		return &ni.Int64
	}
	return nil
}

// scanNullableInt scans a nullable int64 and returns an int pointer if valid.
func scanNullableInt(ni sql.NullInt64) *int {
	if ni.Valid {
		val := int(ni.Int64)
		return &val
	}
	return nil
}

// scanNullableTime scans a nullable time.Time and returns the value if valid.
func scanNullableTime(nt sql.NullTime) *time.Time {
	if nt.Valid {
		return &nt.Time
	}
	return nil
}

// boolToInt converts a boolean to an integer (0 or 1) for compatibility.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// parseBlockedExtensions converts a comma-separated string to a slice of extensions.
func parseBlockedExtensions(s string) []string {
	if s == "" {
		return []string{}
	}

	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
