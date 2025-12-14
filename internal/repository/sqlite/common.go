// Package sqlite provides SQLite implementations of repository interfaces.
package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

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

// beginImmediateTx starts a transaction with retry logic for robustness.
// The IMMEDIATE locking is ensured by _txlock=immediate in the DSN.
func beginImmediateTx(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	const maxRetries = 5
	baseDelay := 50 * time.Millisecond

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		tx, err := db.BeginTx(ctx, &sql.TxOptions{
			Isolation: sql.LevelSerializable,
		})
		if err == nil {
			return tx, nil
		}

		lastErr = err

		// Check if this is a busy/locked error that's worth retrying
		if !isSQLiteBusyError(err) {
			return nil, err // Non-retryable error
		}

		// Wait with exponential backoff before retrying
		if attempt < maxRetries-1 {
			delay := baseDelay * time.Duration(1<<uint(attempt))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	return nil, fmt.Errorf("failed to begin transaction after %d attempts: %w", maxRetries, lastErr)
}

// isSQLiteBusyError checks if an error is an SQLITE_BUSY or SQLITE_LOCKED error.
func isSQLiteBusyError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "database is locked") ||
		strings.Contains(errStr, "sqlite_busy") ||
		strings.Contains(errStr, "sqlite_locked") ||
		strings.Contains(errStr, "(5)") ||   // SQLITE_BUSY
		strings.Contains(errStr, "(6)") ||   // SQLITE_LOCKED
		strings.Contains(errStr, "(517)") || // SQLITE_BUSY_SNAPSHOT
		strings.Contains(errStr, "(262)")    // SQLITE_BUSY_RECOVERY
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
