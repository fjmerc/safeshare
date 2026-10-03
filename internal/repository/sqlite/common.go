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

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
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

// reservationLapsed is true for an uploading partial upload that hasn't stored
// a chunk within PartialUploadReservationIdle, i.e. whose quota reservation has
// lapsed (T30). It's NULL - and so treated as held - when last_activity is
// missing or unparseable, so bad data fails closed. storageUsageQuery and
// RenewReservation must agree on it, so both use this one expression.
var reservationLapsed = fmt.Sprintf(
	"(COALESCE(status, 'uploading') = 'uploading' AND datetime(last_activity) <= datetime('now', '-%d seconds'))",
	int64(repository.PartialUploadReservationIdle/time.Second))

// storageUsageQuery returns the storage counted against the quota: unexpired
// files plus what incomplete partial uploads hold. A partial upload holds its
// full total_size unless its reservation has lapsed (reservationLapsed), in
// which case it counts only the bytes it has received (T30). Every quota
// check must use this one query so chunked and simple uploads agree.
//
// Defense in depth (bug-hunter finding, ADR-015): infected-audit rows are
// already inserted with file_size=0, but exclude them explicitly too, so a
// future insert bug can't silently reintroduce quota inflation.
var storageUsageQuery = `
	SELECT
		COALESCE(SUM(file_size), 0) +
		COALESCE((
			SELECT SUM(CASE WHEN ` + reservationLapsed + `
				THEN COALESCE(received_bytes, 0)
				ELSE total_size
			END)
			FROM partial_uploads WHERE completed = 0
		), 0)
	FROM files
	WHERE datetime(expires_at) > datetime('now')
	AND (scan_status IS NULL OR scan_status != 'infected')
`

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
		strings.Contains(errStr, "(5)") || // SQLITE_BUSY
		strings.Contains(errStr, "(6)") || // SQLITE_LOCKED
		strings.Contains(errStr, "(517)") || // SQLITE_BUSY_SNAPSHOT
		strings.Contains(errStr, "(262)") // SQLITE_BUSY_RECOVERY
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

// nullableBlob converts a Go byte slice to a value suitable for a nullable
// SQLite BLOB column: nil/empty slice becomes SQL NULL, everything else is
// passed through. The corresponding SELECT path should scan into a
// *[]byte (or use sql.RawBytes) so NULL maps back to a nil slice.
func nullableBlob(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}

// nullableString converts an empty string to SQL NULL; anything else passes
// through unchanged. Used for optional TEXT columns like scan_status/
// scan_result, where "" means "not applicable" rather than a real value.
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// nullableTimeRFC3339 formats a nullable *time.Time for a SQLite DATETIME
// column: nil becomes SQL NULL, matching the RFC3339 string format used
// elsewhere in this package (see e.g. FileRepository.Create's expires_at).
func nullableTimeRFC3339(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.Format(time.RFC3339)
}

// sqlExecer is satisfied by both *sql.DB and *sql.Tx, letting insertFile be
// shared by FileRepository.Create/CreateWithQuotaCheck and
// PartialUploadRepository.PublishAssembly/FailAssembly's audit-row insert
// (ADR-016) — all of which run the identical files INSERT, either against
// the bare connection or an already-open transaction.
type sqlExecer interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// insertFile runs the shared files INSERT against execer (a *sql.DB or an
// open *sql.Tx) and sets file.ID from the result.
func insertFile(ctx context.Context, execer sqlExecer, file *models.File) error {
	query := `
		INSERT INTO files (
			claim_code, original_filename, stored_filename, file_size,
			mime_type, expires_at, max_downloads, uploader_ip, password_hash, user_id, sha256_hash,
			client_encrypted, enc_file_id, scan_status, scan_result, scanned_at, partial_upload_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	expiresAtRFC3339 := file.ExpiresAt.Format(time.RFC3339)

	result, err := execer.ExecContext(
		ctx,
		query,
		file.ClaimCode,
		file.OriginalFilename,
		file.StoredFilename,
		file.FileSize,
		file.MimeType,
		expiresAtRFC3339,
		file.MaxDownloads,
		file.UploaderIP,
		file.PasswordHash,
		file.UserID,
		file.SHA256Hash,
		file.ClientEncrypted,
		nullableBlob(file.EncFileID),
		nullableString(file.ScanStatus),
		nullableString(file.ScanResult),
		nullableTimeRFC3339(file.ScannedAt),
		file.PartialUploadID,
	)
	if err != nil {
		return fmt.Errorf("failed to insert file: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	file.ID = id
	return nil
}
