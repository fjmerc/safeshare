package database

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// validateStoredFilename validates that a stored filename is safe to use in file paths.
// This is a defense-in-depth measure duplicated here to avoid circular imports
// (utils imports database via assembly_recovery.go).
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

// CreateFile inserts a new file record into the database
// Note: ExpiresAt is formatted as RFC3339 to ensure SQLite datetime() can parse it.
// Go's time.Time when passed directly includes monotonic clock that SQLite cannot parse.
func CreateFile(db *sql.DB, file *models.File) error {
	query := `
		INSERT INTO files (
			claim_code, original_filename, stored_filename, file_size,
			mime_type, expires_at, max_downloads, uploader_ip, password_hash, user_id, sha256_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	// Format ExpiresAt as RFC3339 for consistent SQLite datetime() parsing
	expiresAtRFC3339 := file.ExpiresAt.Format(time.RFC3339)

	result, err := db.Exec(
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

// CreateFileWithQuotaCheck atomically checks quota and inserts file record in a transaction.
// This prevents race conditions where multiple uploads could exceed quota limits.
// Returns error if quota would be exceeded.
func CreateFileWithQuotaCheck(db *sql.DB, file *models.File, quotaLimitBytes int64) error {
	// Begin transaction with IMMEDIATE lock to prevent quota bypass races
	// IMMEDIATE acquires RESERVED lock, blocking other writers but allowing readers
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.Warn("failed to rollback transaction", "error", err)
		}
	}()

	// Check quota within transaction (atomic with insert)
	// Note: Uses total_size for partial uploads (not received_bytes) since we reserve full size upfront
	// This prevents quota leakage when uploads fail partway through
	var currentUsage int64
	// Note: datetime(expires_at) normalizes RFC3339 format (from Go) to SQLite datetime format
	// for proper comparison. Without this, string comparison fails due to 'T' vs ' ' difference.
	query := `
		SELECT
			COALESCE(SUM(file_size), 0) +
			COALESCE((SELECT SUM(total_size) FROM partial_uploads WHERE completed = 0), 0)
		FROM files
		WHERE datetime(expires_at) > datetime('now')
	`
	if err := tx.QueryRow(query).Scan(&currentUsage); err != nil {
		return fmt.Errorf("failed to get current usage: %w", err)
	}

	// Check if adding this file would exceed quota
	if currentUsage+file.FileSize > quotaLimitBytes {
		return fmt.Errorf("quota exceeded: current usage %d bytes + file size %d bytes > limit %d bytes",
			currentUsage, file.FileSize, quotaLimitBytes)
	}

	// Insert file record (still within transaction)
	insertQuery := `
		INSERT INTO files (
			claim_code, original_filename, stored_filename, file_size,
			mime_type, expires_at, max_downloads, uploader_ip, password_hash, user_id, sha256_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	// Format ExpiresAt as RFC3339 for consistent SQLite datetime() parsing
	expiresAtRFC3339 := file.ExpiresAt.Format(time.RFC3339)

	result, err := tx.Exec(
		insertQuery,
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
	)
	if err != nil {
		return fmt.Errorf("failed to insert file: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	file.ID = id

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetFileByClaimCode retrieves a file record by its claim code
// Returns nil if not found or expired
func GetFileByClaimCode(db *sql.DB, claimCode string) (*models.File, error) {
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads, download_count, completed_downloads, uploader_ip, password_hash, user_id, sha256_hash
		FROM files
		WHERE claim_code = ?
	`

	file := &models.File{}
	var createdAt, expiresAt string
	var passwordHash sql.NullString
	var userID sql.NullInt64
	var sha256Hash sql.NullString

	err := db.QueryRow(query, claimCode).Scan(
		&file.ID,
		&file.ClaimCode,
		&file.OriginalFilename,
		&file.StoredFilename,
		&file.FileSize,
		&file.MimeType,
		&createdAt,
		&expiresAt,
		&file.MaxDownloads,
		&file.DownloadCount,
		&file.CompletedDownloads,
		&file.UploaderIP,
		&passwordHash,
		&userID,
		&sha256Hash,
	)

	if err == sql.ErrNoRows {
		return nil, nil // File not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query file: %w", err)
	}

	// Parse timestamps (SQLite returns RFC3339 format)
	file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", err)
	}

	// Handle nullable fields
	if passwordHash.Valid {
		file.PasswordHash = passwordHash.String
	}
	if userID.Valid {
		file.UserID = &userID.Int64
	}
	if sha256Hash.Valid {
		file.SHA256Hash = sha256Hash.String
	}

	// Check if expired
	if time.Now().After(file.ExpiresAt) {
		return nil, nil // Expired file treated as not found
	}

	return file, nil
}

// IncrementDownloadCount atomically increments the download counter for a file
func IncrementDownloadCount(db *sql.DB, id int64) error {
	query := `UPDATE files SET download_count = download_count + 1 WHERE id = ?`

	result, err := db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to increment download count: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("no file found with id %d", id)
	}

	return nil
}

// IncrementDownloadCountIfUnchanged increments the download count only if the claim code hasn't changed.
// This prevents download count inconsistencies when claim codes are regenerated mid-download.
func IncrementDownloadCountIfUnchanged(db *sql.DB, id int64, expectedClaimCode string) error {
	query := `
		UPDATE files
		SET download_count = download_count + 1
		WHERE id = ? AND claim_code = ?
	`

	result, err := db.Exec(query, id, expectedClaimCode)
	if err != nil {
		return fmt.Errorf("failed to increment download count: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("claim code changed during download")
	}

	return nil
}

// TryIncrementDownloadWithLimit atomically increments download count only if under the limit.
// This prevents race conditions where multiple downloads could exceed max_downloads.
// Returns true if increment succeeded, false if limit reached.
func TryIncrementDownloadWithLimit(db *sql.DB, id int64, expectedClaimCode string) (bool, error) {
	// Atomic compare-and-increment: only increment if download_count < max_downloads
	// This prevents the TOCTOU race condition in download limit checks
	// Note: max_downloads=0 is treated as unlimited for backward compatibility
	query := `
		UPDATE files
		SET download_count = download_count + 1
		WHERE id = ?
		  AND claim_code = ?
		  AND (max_downloads IS NULL OR max_downloads = 0 OR download_count < max_downloads)
	`

	result, err := db.Exec(query, id, expectedClaimCode)
	if err != nil {
		return false, fmt.Errorf("failed to increment download count: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}

	// rows == 0 means either claim code changed OR limit reached
	if rows == 0 {
		// Check which case it is
		var currentCount, maxDownloads int
		var maxDownloadsNull sql.NullInt64
		checkQuery := `SELECT download_count, max_downloads FROM files WHERE id = ? AND claim_code = ?`
		err := db.QueryRow(checkQuery, id, expectedClaimCode).Scan(&currentCount, &maxDownloadsNull)
		if err == sql.ErrNoRows {
			return false, fmt.Errorf("claim code changed during download")
		}
		if err != nil {
			return false, fmt.Errorf("failed to check download limit: %w", err)
		}

		// If we got here, claim code is valid but limit was reached
		if maxDownloadsNull.Valid {
			maxDownloads = int(maxDownloadsNull.Int64)
			// Only treat as limit reached if maxDownloads > 0 (backward compat: 0 = unlimited)
			if maxDownloads > 0 && currentCount >= maxDownloads {
				return false, nil // Limit reached
			}
		}

		// Shouldn't reach here, but treat as limit reached to be safe
		return false, nil
	}

	return true, nil // Success
}

// IncrementCompletedDownloads atomically increments the completed downloads counter for a file.
// This should only be called when a full file download (HTTP 200 OK) completes successfully.
// Do NOT call this for partial/range downloads (HTTP 206 Partial Content).
func IncrementCompletedDownloads(db *sql.DB, id int64) error {
	query := `UPDATE files SET completed_downloads = completed_downloads + 1 WHERE id = ?`

	result, err := db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to increment completed downloads: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("no file found with id %d", id)
	}

	return nil
}

// ExpiredFileCallback is called for each successfully deleted expired file
// Parameters: claimCode, filename, fileSize, mimeType, expiresAt
type ExpiredFileCallback func(claimCode, filename string, fileSize int64, mimeType string, expiresAt time.Time)

// DeleteExpiredFiles removes expired files from both database and filesystem
// Returns the count of deleted files
// onExpired callback is called for each file after successful deletion (optional, can be nil)
func DeleteExpiredFiles(db *sql.DB, uploadDir string, onExpired ExpiredFileCallback) (int, error) {
	// Find expired files with 1-hour grace period to prevent deletion during active downloads
	// Files must be expired for at least 1 hour before cleanup
	// Query includes webhook-relevant fields for event emission
	// Note: datetime(expires_at) normalizes RFC3339 format (from Go) to SQLite datetime format
	// for proper comparison. Without this, string comparison fails due to 'T' vs ' ' difference.
	query := `
		SELECT id, claim_code, original_filename, stored_filename, file_size, mime_type, expires_at
		FROM files
		WHERE datetime(expires_at) <= datetime('now', '-1 hour')
	`

	rows, err := db.Query(query)
	if err != nil {
		return 0, fmt.Errorf("failed to query expired files: %w", err)
	}
	defer rows.Close()

	type expiredFileData struct {
		ID             int64
		ClaimCode      string
		OriginalFilename string
		StoredFilename string
		FileSize       int64
		MimeType       string
		ExpiresAt      time.Time
	}
	var expiredFiles []expiredFileData

	for rows.Next() {
		var expiresAtStr string
		var id int64
		var claimCode, originalFilename, storedFilename, mimeType string
		var fileSize int64
		
		if err := rows.Scan(&id, &claimCode, &originalFilename, &storedFilename, &fileSize, &mimeType, &expiresAtStr); err != nil {
			slog.Error("failed to scan expired file", "error", err)
			continue
		}
		
		// Parse timestamp from SQLite RFC3339 string format
		expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
		if err != nil {
			slog.Error("failed to parse expires_at timestamp",
				"file_id", id,
				"error", err,
			)
			continue
		}
		
		expiredFiles = append(expiredFiles, expiredFileData{
			ID:             id,
			ClaimCode:      claimCode,
			OriginalFilename: originalFilename,
			StoredFilename: storedFilename,
			FileSize:       fileSize,
			MimeType:       mimeType,
			ExpiresAt:      expiresAt,
		})
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("error iterating expired files: %w", err)
	}

	// Delete files (file first, then database record)
	// Collect successfully deleted file IDs for batch DELETE
	var deletedIDs []int64

	for _, f := range expiredFiles {
		// Step 1: Validate stored filename first (fail fast)
		if err := validateStoredFilename(f.StoredFilename); err != nil {
			slog.Error("stored filename validation failed during cleanup",
				"filename", f.StoredFilename,
				"error", err,
				"file_id", f.ID,
			)
			// Keep DB record intact for investigation
			continue
		}

		// Step 2: Delete physical file FIRST
		filePath := filepath.Join(uploadDir, f.StoredFilename)
		if err := os.Remove(filePath); err != nil {
			if !os.IsNotExist(err) {
				// File exists but couldn't delete - keep DB record for retry
				slog.Error("failed to delete physical file, keeping DB record for retry",
					"path", filePath,
					"file_id", f.ID,
					"error", err,
				)
				continue // IMPORTANT: Skip DB deletion, retry next cleanup
			}
			// File doesn't exist (already deleted) - OK to delete DB record
			slog.Warn("physical file already deleted", "path", filePath, "file_id", f.ID)
		}

		// Step 3: Track ID for batch deletion
		deletedIDs = append(deletedIDs, f.ID)
		slog.Debug("successfully deleted physical file",
			"file_id", f.ID,
			"filename", f.StoredFilename,
		)
	}

	// Step 4: Batch delete database records for successfully deleted files
	deletedCount := 0
	if len(deletedIDs) > 0 {
		deletedCount = batchDeleteFiles(db, deletedIDs)
	}

	// Step 5: Invoke callback for each successfully deleted file (if provided)
	// Callback is invoked AFTER successful database commit
	// Uses a map lookup to correctly match expired files with their deletion status,
	// regardless of any skipped entries during physical file deletion.
	if deletedCount > 0 && onExpired != nil {
		// Create a set of deleted IDs for O(1) lookup
		deletedIDSet := make(map[int64]bool)
		for _, id := range deletedIDs {
			deletedIDSet[id] = true
		}

		// Iterate through ALL expired files and emit webhook only for those that were deleted
		for _, f := range expiredFiles {
			if deletedIDSet[f.ID] {
				onExpired(f.ClaimCode, f.OriginalFilename, f.FileSize, f.MimeType, f.ExpiresAt)
			}
		}
	}

	// Update query planner statistics after bulk deletes
	if deletedCount >= 100 {
		slog.Info("updating query planner statistics after bulk file deletion",
			"deleted_count", deletedCount)

		if _, err := db.Exec("ANALYZE files"); err != nil {
			// Log but don't fail - ANALYZE is optimization, not critical
			slog.Warn("failed to analyze files table", "error", err)
		}
	}

	return deletedCount, nil
}

// batchDeleteFiles deletes multiple file records using batch DELETE operations within a transaction
// Chunks large batches to stay within SQLite parameter limits (max 999 params, using 500 for safety)
// Uses transaction to ensure atomic cleanup (all-or-nothing)
func batchDeleteFiles(db *sql.DB, fileIDs []int64) int {
	const batchSize = 500
	deletedCount := 0

	// Begin transaction for atomic batch delete
	tx, err := db.Begin()
	if err != nil {
		slog.Error("failed to begin transaction for batch delete", "error", err)
		return 0
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.Warn("failed to rollback transaction", "error", err)
		}
	}()

	// Process in chunks to avoid SQLite parameter limit
	for i := 0; i < len(fileIDs); i += batchSize {
		end := i + batchSize
		if end > len(fileIDs) {
			end = len(fileIDs)
		}
		batch := fileIDs[i:end]

		// Build DELETE IN query with placeholders
		placeholders := strings.Repeat("?,", len(batch))
		placeholders = placeholders[:len(placeholders)-1] // Remove trailing comma
		deleteQuery := fmt.Sprintf("DELETE FROM files WHERE id IN (%s)", placeholders)

		// Convert []int64 to []interface{} for db.Exec
		args := make([]interface{}, len(batch))
		for j, id := range batch {
			args[j] = id
		}

		// Execute batch DELETE within transaction
		result, err := tx.Exec(deleteQuery, args...)
		if err != nil {
			slog.Error("failed to batch delete file records",
				"batch_size", len(batch),
				"error", err,
			)
			// Rollback and return on error (atomic operation)
			return 0
		}

		affected, err := result.RowsAffected()
		if err != nil {
			slog.Warn("failed to get rows affected for batch delete", "error", err)
			// Assume all rows were deleted if we can't get count
			affected = int64(len(batch))
		}

		deletedCount += int(affected)
		slog.Debug("batch deleted file records",
			"batch_size", len(batch),
			"deleted", affected,
		)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		slog.Error("failed to commit batch delete transaction", "error", err)
		return 0
	}

	return deletedCount
}

// GetTotalUsage returns the total storage used by all active files AND partial uploads in bytes
// This includes both completed files and incomplete chunked uploads for accurate quota tracking
// Note: Uses total_size for partial uploads (not received_bytes) since quota is reserved upfront
func GetTotalUsage(db *sql.DB) (int64, error) {
	// Note: datetime(expires_at) normalizes RFC3339 format (from Go) to SQLite datetime format
	// for proper comparison. Without this, string comparison fails due to 'T' vs ' ' difference.
	query := `
		SELECT
			COALESCE(SUM(file_size), 0) +
			COALESCE((SELECT SUM(total_size) FROM partial_uploads WHERE completed = 0), 0)
		FROM files
		WHERE datetime(expires_at) > datetime('now')
	`

	var totalUsage int64
	err := db.QueryRow(query).Scan(&totalUsage)
	if err != nil {
		return 0, fmt.Errorf("failed to get total usage: %w", err)
	}

	return totalUsage, nil
}

// GetStats returns statistics about the file storage
func GetStats(db *sql.DB, uploadDir string) (totalFiles int, storageUsed int64, err error) {
	// Count active files (not expired)
	// Note: datetime(expires_at) normalizes RFC3339 format (from Go) to SQLite datetime format
	// for proper comparison. Without this, string comparison fails due to 'T' vs ' ' difference.
	query := `
		SELECT COUNT(*), COALESCE(SUM(file_size), 0)
		FROM files
		WHERE datetime(expires_at) > datetime('now')
	`

	err = db.QueryRow(query).Scan(&totalFiles, &storageUsed)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get stats: %w", err)
	}

	return totalFiles, storageUsed, nil
}

// GetAllFiles returns all files in the database (including expired files)
// This is primarily used for administrative tools like the encryption migration utility
func GetAllFiles(db *sql.DB) ([]*models.File, error) {
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads,
			completed_downloads, uploader_ip, password_hash, user_id, sha256_hash
		FROM files
		ORDER BY created_at DESC
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all files: %w", err)
	}
	defer rows.Close()

	var files []*models.File
	for rows.Next() {
		file := &models.File{}
		var passwordHash sql.NullString
		var userID sql.NullInt64
		var sha256Hash sql.NullString

		err := rows.Scan(
			&file.ID,
			&file.ClaimCode,
			&file.OriginalFilename,
			&file.StoredFilename,
			&file.FileSize,
			&file.MimeType,
			&file.CreatedAt,
			&file.ExpiresAt,
			&file.MaxDownloads,
			&file.CompletedDownloads,
			&file.UploaderIP,
			&passwordHash,
			&userID,
			&sha256Hash,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan file row: %w", err)
		}

		if passwordHash.Valid {
			file.PasswordHash = passwordHash.String
		}
		if userID.Valid {
			uid := userID.Int64
			file.UserID = &uid
		}
		if sha256Hash.Valid {
			file.SHA256Hash = sha256Hash.String
		}

		files = append(files, file)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating file rows: %w", err)
	}

	return files, nil
}
