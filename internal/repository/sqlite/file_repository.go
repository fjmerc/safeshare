// Package sqlite provides SQLite implementations of repository interfaces.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// FileRepository implements repository.FileRepository for SQLite.
type FileRepository struct {
	db *sql.DB
}

// NewFileRepository creates a new SQLite file repository.
func NewFileRepository(db *sql.DB) *FileRepository {
	return &FileRepository{db: db}
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

// beginImmediateTx starts a transaction with retry logic for robustness.
// See database.BeginImmediateTx for the original implementation.
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

// Create inserts a new file record into the database.
func (r *FileRepository) Create(ctx context.Context, file *models.File) error {
	query := `
		INSERT INTO files (
			claim_code, original_filename, stored_filename, file_size,
			mime_type, expires_at, max_downloads, uploader_ip, password_hash, user_id, sha256_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	// Format ExpiresAt as RFC3339 for consistent SQLite datetime() parsing
	expiresAtRFC3339 := file.ExpiresAt.Format(time.RFC3339)

	result, err := r.db.ExecContext(
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

// CreateWithQuotaCheck atomically checks quota and inserts file record in a transaction.
func (r *FileRepository) CreateWithQuotaCheck(ctx context.Context, file *models.File, quotaLimitBytes int64) error {
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.Warn("failed to rollback transaction", "error", err)
		}
	}()

	// Check quota within transaction
	var currentUsage int64
	query := `
		SELECT
			COALESCE(SUM(file_size), 0) +
			COALESCE((SELECT SUM(total_size) FROM partial_uploads WHERE completed = 0), 0)
		FROM files
		WHERE datetime(expires_at) > datetime('now')
	`
	if err := tx.QueryRowContext(ctx, query).Scan(&currentUsage); err != nil {
		return fmt.Errorf("failed to get current usage: %w", err)
	}

	// Check if adding this file would exceed quota
	if currentUsage+file.FileSize > quotaLimitBytes {
		return repository.ErrQuotaExceeded
	}

	// Insert file record
	insertQuery := `
		INSERT INTO files (
			claim_code, original_filename, stored_filename, file_size,
			mime_type, expires_at, max_downloads, uploader_ip, password_hash, user_id, sha256_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	expiresAtRFC3339 := file.ExpiresAt.Format(time.RFC3339)

	result, err := tx.ExecContext(
		ctx,
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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetByID retrieves a file by its database ID.
func (r *FileRepository) GetByID(ctx context.Context, id int64) (*models.File, error) {
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads, download_count, completed_downloads, 
			uploader_ip, password_hash, user_id, sha256_hash
		FROM files
		WHERE id = ?
	`

	file := &models.File{}
	var createdAt, expiresAt string
	var passwordHash sql.NullString
	var userID sql.NullInt64
	var sha256Hash sql.NullString
	var maxDownloads sql.NullInt64

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&file.ID,
		&file.ClaimCode,
		&file.OriginalFilename,
		&file.StoredFilename,
		&file.FileSize,
		&file.MimeType,
		&createdAt,
		&expiresAt,
		&maxDownloads,
		&file.DownloadCount,
		&file.CompletedDownloads,
		&file.UploaderIP,
		&passwordHash,
		&userID,
		&sha256Hash,
	)

	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query file: %w", err)
	}

	// Parse timestamps
	file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", err)
	}

	// Handle nullable fields
	if maxDownloads.Valid {
		val := int(maxDownloads.Int64)
		file.MaxDownloads = &val
	}
	if passwordHash.Valid {
		file.PasswordHash = passwordHash.String
	}
	if userID.Valid {
		file.UserID = &userID.Int64
	}
	if sha256Hash.Valid {
		file.SHA256Hash = sha256Hash.String
	}

	return file, nil
}

// GetByClaimCode retrieves a file by its claim code.
// Returns nil, nil if not found or expired (for backward compatibility).
func (r *FileRepository) GetByClaimCode(ctx context.Context, claimCode string) (*models.File, error) {
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads, download_count, completed_downloads, 
			uploader_ip, password_hash, user_id, sha256_hash
		FROM files
		WHERE claim_code = ?
	`

	file := &models.File{}
	var createdAt, expiresAt string
	var passwordHash sql.NullString
	var userID sql.NullInt64
	var sha256Hash sql.NullString
	var maxDownloads sql.NullInt64

	err := r.db.QueryRowContext(ctx, query, claimCode).Scan(
		&file.ID,
		&file.ClaimCode,
		&file.OriginalFilename,
		&file.StoredFilename,
		&file.FileSize,
		&file.MimeType,
		&createdAt,
		&expiresAt,
		&maxDownloads,
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

	// Parse timestamps
	file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", err)
	}

	// Handle nullable fields
	if maxDownloads.Valid {
		val := int(maxDownloads.Int64)
		file.MaxDownloads = &val
	}
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

// IncrementDownloadCount atomically increments the download counter.
func (r *FileRepository) IncrementDownloadCount(ctx context.Context, id int64) error {
	query := `UPDATE files SET download_count = download_count + 1 WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to increment download count: %w", err)
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

// IncrementDownloadCountIfUnchanged increments download count only if claim code matches.
func (r *FileRepository) IncrementDownloadCountIfUnchanged(ctx context.Context, id int64, expectedClaimCode string) error {
	query := `
		UPDATE files
		SET download_count = download_count + 1
		WHERE id = ? AND claim_code = ?
	`

	result, err := r.db.ExecContext(ctx, query, id, expectedClaimCode)
	if err != nil {
		return fmt.Errorf("failed to increment download count: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return repository.ErrClaimCodeChanged
	}

	return nil
}

// TryIncrementDownloadWithLimit atomically increments download count only if under limit.
func (r *FileRepository) TryIncrementDownloadWithLimit(ctx context.Context, id int64, expectedClaimCode string) (bool, error) {
	// Atomic compare-and-increment
	query := `
		UPDATE files
		SET download_count = download_count + 1
		WHERE id = ?
		  AND claim_code = ?
		  AND (max_downloads IS NULL OR max_downloads = 0 OR download_count < max_downloads)
	`

	result, err := r.db.ExecContext(ctx, query, id, expectedClaimCode)
	if err != nil {
		return false, fmt.Errorf("failed to increment download count: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		// Check which case it is: claim code changed OR limit reached
		var currentCount int
		var maxDownloadsNull sql.NullInt64
		checkQuery := `SELECT download_count, max_downloads FROM files WHERE id = ? AND claim_code = ?`
		err := r.db.QueryRowContext(ctx, checkQuery, id, expectedClaimCode).Scan(&currentCount, &maxDownloadsNull)
		if err == sql.ErrNoRows {
			return false, repository.ErrClaimCodeChanged
		}
		if err != nil {
			return false, fmt.Errorf("failed to check download limit: %w", err)
		}

		// Claim code is valid but limit was reached
		if maxDownloadsNull.Valid {
			maxDownloads := int(maxDownloadsNull.Int64)
			if maxDownloads > 0 && currentCount >= maxDownloads {
				return false, nil // Limit reached
			}
		}

		return false, nil
	}

	return true, nil // Success
}

// IncrementCompletedDownloads increments the completed downloads counter.
func (r *FileRepository) IncrementCompletedDownloads(ctx context.Context, id int64) error {
	query := `UPDATE files SET completed_downloads = completed_downloads + 1 WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to increment completed downloads: %w", err)
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

// Delete removes a file record by ID.
func (r *FileRepository) Delete(ctx context.Context, id int64) error {
	query := `DELETE FROM files WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
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

// DeleteByClaimCode removes a file record by claim code.
// Uses a transaction to prevent TOCTOU race conditions between SELECT and DELETE.
func (r *FileRepository) DeleteByClaimCode(ctx context.Context, claimCode string) (*models.File, error) {
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.Warn("failed to rollback transaction", "error", err)
		}
	}()

	// Get the file info within transaction
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads, download_count, completed_downloads, 
			uploader_ip, password_hash, user_id
		FROM files
		WHERE claim_code = ?
	`

	file := &models.File{}
	var createdAt, expiresAt string
	var passwordHash sql.NullString
	var maxDownloads sql.NullInt64
	var userID sql.NullInt64

	err = tx.QueryRowContext(ctx, query, claimCode).Scan(
		&file.ID,
		&file.ClaimCode,
		&file.OriginalFilename,
		&file.StoredFilename,
		&file.FileSize,
		&file.MimeType,
		&createdAt,
		&expiresAt,
		&maxDownloads,
		&file.DownloadCount,
		&file.CompletedDownloads,
		&file.UploaderIP,
		&passwordHash,
		&userID,
	)

	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query file: %w", err)
	}

	// Parse timestamps
	file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", err)
	}

	// Handle nullable fields
	if maxDownloads.Valid {
		val := int(maxDownloads.Int64)
		file.MaxDownloads = &val
	}
	if passwordHash.Valid {
		file.PasswordHash = passwordHash.String
	}
	if userID.Valid {
		file.UserID = &userID.Int64
	}

	// Delete from database within same transaction
	deleteQuery := `DELETE FROM files WHERE claim_code = ?`
	result, err := tx.ExecContext(ctx, deleteQuery, claimCode)
	if err != nil {
		return nil, fmt.Errorf("failed to delete file from database: %w", err)
	}

	// Verify deletion occurred (defense against concurrent delete)
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return nil, repository.ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return file, nil
}

// DeleteByClaimCodes removes multiple files by claim codes (bulk operation).
func (r *FileRepository) DeleteByClaimCodes(ctx context.Context, claimCodes []string) ([]*models.File, error) {
	if len(claimCodes) == 0 {
		return nil, repository.ErrInvalidInput
	}

	files := make([]*models.File, 0, len(claimCodes))

	for _, claimCode := range claimCodes {
		query := `
			SELECT
				id, claim_code, original_filename, stored_filename, file_size,
				mime_type, created_at, expires_at, max_downloads, download_count, completed_downloads, 
				uploader_ip, password_hash, user_id
			FROM files
			WHERE claim_code = ?
		`

		file := &models.File{}
		var createdAt, expiresAt string
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userID sql.NullInt64

		err := r.db.QueryRowContext(ctx, query, claimCode).Scan(
			&file.ID,
			&file.ClaimCode,
			&file.OriginalFilename,
			&file.StoredFilename,
			&file.FileSize,
			&file.MimeType,
			&createdAt,
			&expiresAt,
			&maxDownloads,
			&file.DownloadCount,
			&file.CompletedDownloads,
			&file.UploaderIP,
			&passwordHash,
			&userID,
		)

		if err == sql.ErrNoRows {
			continue // Skip files that don't exist
		}
		if err != nil {
			return nil, fmt.Errorf("failed to query file %s: %w", claimCode, err)
		}

		// Parse timestamps
		file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse created_at: %w", err)
		}

		file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse expires_at: %w", err)
		}

		// Handle nullable fields
		if maxDownloads.Valid {
			val := int(maxDownloads.Int64)
			file.MaxDownloads = &val
		}
		if passwordHash.Valid {
			file.PasswordHash = passwordHash.String
		}
		if userID.Valid {
			file.UserID = &userID.Int64
		}

		files = append(files, file)
	}

	// Delete all files from database
	if len(files) > 0 {
		placeholders := make([]string, len(files))
		args := make([]interface{}, len(files))
		for i, file := range files {
			placeholders[i] = "?"
			args[i] = file.ClaimCode
		}

		deleteQuery := fmt.Sprintf("DELETE FROM files WHERE claim_code IN (%s)", strings.Join(placeholders, ","))
		_, err := r.db.ExecContext(ctx, deleteQuery, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to delete files from database: %w", err)
		}
	}

	return files, nil
}

// DeleteExpired removes expired files from database and filesystem.
func (r *FileRepository) DeleteExpired(ctx context.Context, uploadDir string, onExpired repository.ExpiredFileCallback) (int, error) {
	// Find expired files with 1-hour grace period
	query := `
		SELECT id, claim_code, original_filename, stored_filename, file_size, mime_type, expires_at
		FROM files
		WHERE datetime(expires_at) <= datetime('now', '-1 hour')
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to query expired files: %w", err)
	}
	defer rows.Close()

	type expiredFileData struct {
		ID               int64
		ClaimCode        string
		OriginalFilename string
		StoredFilename   string
		FileSize         int64
		MimeType         string
		ExpiresAt        time.Time
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

		expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
		if err != nil {
			slog.Error("failed to parse expires_at timestamp",
				"file_id", id,
				"error", err,
			)
			continue
		}

		expiredFiles = append(expiredFiles, expiredFileData{
			ID:               id,
			ClaimCode:        claimCode,
			OriginalFilename: originalFilename,
			StoredFilename:   storedFilename,
			FileSize:         fileSize,
			MimeType:         mimeType,
			ExpiresAt:        expiresAt,
		})
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("error iterating expired files: %w", err)
	}

	// Delete files (file first, then database record)
	var deletedIDs []int64

	for _, f := range expiredFiles {
		// Validate stored filename first
		if err := validateStoredFilename(f.StoredFilename); err != nil {
			slog.Error("stored filename validation failed during cleanup",
				"filename", f.StoredFilename,
				"error", err,
				"file_id", f.ID,
			)
			continue
		}

		// Delete physical file FIRST
		filePath := filepath.Join(uploadDir, f.StoredFilename)
		if err := os.Remove(filePath); err != nil {
			if !os.IsNotExist(err) {
				slog.Error("failed to delete physical file, keeping DB record for retry",
					"path", filePath,
					"file_id", f.ID,
					"error", err,
				)
				continue
			}
			slog.Warn("physical file already deleted", "path", filePath, "file_id", f.ID)
		}

		deletedIDs = append(deletedIDs, f.ID)
		slog.Debug("successfully deleted physical file",
			"file_id", f.ID,
			"filename", f.StoredFilename,
		)
	}

	// Batch delete database records
	deletedCount := 0
	if len(deletedIDs) > 0 {
		deletedCount = r.batchDeleteFiles(ctx, deletedIDs)
	}

	// Invoke callback for each successfully deleted file
	if deletedCount > 0 && onExpired != nil {
		deletedIDSet := make(map[int64]bool)
		for _, id := range deletedIDs {
			deletedIDSet[id] = true
		}

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

		if _, err := r.db.ExecContext(ctx, "ANALYZE files"); err != nil {
			slog.Warn("failed to analyze files table", "error", err)
		}
	}

	return deletedCount, nil
}

// batchDeleteFiles deletes multiple file records using batch DELETE operations.
func (r *FileRepository) batchDeleteFiles(ctx context.Context, fileIDs []int64) int {
	const batchSize = 500
	deletedCount := 0

	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		slog.Error("failed to begin transaction for batch delete", "error", err)
		return 0
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.Warn("failed to rollback transaction", "error", err)
		}
	}()

	// Process in chunks
	for i := 0; i < len(fileIDs); i += batchSize {
		end := i + batchSize
		if end > len(fileIDs) {
			end = len(fileIDs)
		}
		batch := fileIDs[i:end]

		placeholders := strings.Repeat("?,", len(batch))
		placeholders = placeholders[:len(placeholders)-1]
		deleteQuery := fmt.Sprintf("DELETE FROM files WHERE id IN (%s)", placeholders)

		args := make([]interface{}, len(batch))
		for j, id := range batch {
			args[j] = id
		}

		result, err := tx.ExecContext(ctx, deleteQuery, args...)
		if err != nil {
			slog.Error("failed to batch delete file records",
				"batch_size", len(batch),
				"error", err,
			)
			return 0
		}

		affected, err := result.RowsAffected()
		if err != nil {
			slog.Warn("failed to get rows affected for batch delete", "error", err)
			affected = int64(len(batch))
		}

		deletedCount += int(affected)
		slog.Debug("batch deleted file records",
			"batch_size", len(batch),
			"deleted", affected,
		)
	}

	if err := tx.Commit(); err != nil {
		slog.Error("failed to commit batch delete transaction", "error", err)
		return 0
	}

	return deletedCount
}

// GetTotalUsage returns the total storage used by active files and partial uploads.
func (r *FileRepository) GetTotalUsage(ctx context.Context) (int64, error) {
	query := `
		SELECT
			COALESCE(SUM(file_size), 0) +
			COALESCE((SELECT SUM(total_size) FROM partial_uploads WHERE completed = 0), 0)
		FROM files
		WHERE datetime(expires_at) > datetime('now')
	`

	var totalUsage int64
	err := r.db.QueryRowContext(ctx, query).Scan(&totalUsage)
	if err != nil {
		return 0, fmt.Errorf("failed to get total usage: %w", err)
	}

	return totalUsage, nil
}

// GetStats returns statistics about file storage.
func (r *FileRepository) GetStats(ctx context.Context, uploadDir string) (*repository.FileStats, error) {
	query := `
		SELECT COUNT(*), COALESCE(SUM(file_size), 0)
		FROM files
		WHERE datetime(expires_at) > datetime('now')
	`

	var totalFiles int
	var storageUsed int64
	err := r.db.QueryRowContext(ctx, query).Scan(&totalFiles, &storageUsed)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	return &repository.FileStats{
		TotalFiles:  totalFiles,
		StorageUsed: storageUsed,
		ActiveFiles: totalFiles,
		TotalUsage:  storageUsed,
	}, nil
}

// GetAll returns all files in the database (including expired files).
func (r *FileRepository) GetAll(ctx context.Context) ([]*models.File, error) {
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads,
			completed_downloads, uploader_ip, password_hash, user_id, sha256_hash
		FROM files
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
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
		var maxDownloads sql.NullInt64

		err := rows.Scan(
			&file.ID,
			&file.ClaimCode,
			&file.OriginalFilename,
			&file.StoredFilename,
			&file.FileSize,
			&file.MimeType,
			&file.CreatedAt,
			&file.ExpiresAt,
			&maxDownloads,
			&file.CompletedDownloads,
			&file.UploaderIP,
			&passwordHash,
			&userID,
			&sha256Hash,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan file row: %w", err)
		}

		if maxDownloads.Valid {
			val := int(maxDownloads.Int64)
			file.MaxDownloads = &val
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

// GetAllStoredFilenames returns all stored filenames as a set.
func (r *FileRepository) GetAllStoredFilenames(ctx context.Context) (map[string]bool, error) {
	query := `SELECT stored_filename FROM files`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query stored filenames: %w", err)
	}
	defer rows.Close()

	filenames := make(map[string]bool)
	for rows.Next() {
		var filename string
		if err := rows.Scan(&filename); err != nil {
			return nil, fmt.Errorf("failed to scan stored filename: %w", err)
		}
		filenames[filename] = true
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating stored filenames: %w", err)
	}

	return filenames, nil
}

// GetAllForAdmin returns all files with pagination for admin dashboard.
func (r *FileRepository) GetAllForAdmin(ctx context.Context, limit, offset int) ([]models.File, int, error) {
	// Validate pagination bounds (defense in depth)
	if limit < 0 {
		limit = 0
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM files`
	err := r.db.QueryRowContext(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count files: %w", err)
	}

	// Get paginated files with username via LEFT JOIN
	query := `SELECT f.id, f.claim_code, f.original_filename, f.stored_filename, f.file_size, f.mime_type,
		f.created_at, f.expires_at, f.max_downloads, f.download_count, f.completed_downloads, f.uploader_ip, f.password_hash, f.user_id,
		u.username
		FROM files f
		LEFT JOIN users u ON f.user_id = u.id
		ORDER BY f.created_at DESC LIMIT ? OFFSET ?`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query files: %w", err)
	}
	defer rows.Close()

	var files []models.File
	for rows.Next() {
		var file models.File
		var createdAt, expiresAt string
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userID sql.NullInt64
		var username sql.NullString

		err := rows.Scan(
			&file.ID,
			&file.ClaimCode,
			&file.OriginalFilename,
			&file.StoredFilename,
			&file.FileSize,
			&file.MimeType,
			&createdAt,
			&expiresAt,
			&maxDownloads,
			&file.DownloadCount,
			&file.CompletedDownloads,
			&file.UploaderIP,
			&passwordHash,
			&userID,
			&username,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan file: %w", err)
		}

		// Parse timestamps
		file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse created_at: %w", err)
		}

		file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse expires_at: %w", err)
		}

		// Handle nullable fields
		if maxDownloads.Valid {
			val := int(maxDownloads.Int64)
			file.MaxDownloads = &val
		}
		if passwordHash.Valid {
			file.PasswordHash = passwordHash.String
		}
		if userID.Valid {
			file.UserID = &userID.Int64
		}
		if username.Valid {
			file.Username = &username.String
		}

		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating files: %w", err)
	}

	return files, total, nil
}

// SearchForAdmin searches files by claim code, filename, IP, or username.
func (r *FileRepository) SearchForAdmin(ctx context.Context, searchTerm string, limit, offset int) ([]models.File, int, error) {
	// Validate pagination bounds (defense in depth)
	if limit < 0 {
		limit = 0
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	// Escape LIKE wildcards to prevent LIKE injection
	escapedTerm := escapeLikePattern(searchTerm)
	searchPattern := "%" + escapedTerm + "%"

	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM files f
		LEFT JOIN users u ON f.user_id = u.id
		WHERE f.claim_code LIKE ? ESCAPE '\' OR f.original_filename LIKE ? ESCAPE '\' OR f.uploader_ip LIKE ? ESCAPE '\' OR u.username LIKE ? ESCAPE '\'`
	err := r.db.QueryRowContext(ctx, countQuery, searchPattern, searchPattern, searchPattern, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	// Get paginated results with username via LEFT JOIN
	query := `SELECT f.id, f.claim_code, f.original_filename, f.stored_filename, f.file_size, f.mime_type,
		f.created_at, f.expires_at, f.max_downloads, f.download_count, f.completed_downloads, f.uploader_ip, f.password_hash, f.user_id,
		u.username
		FROM files f
		LEFT JOIN users u ON f.user_id = u.id
		WHERE f.claim_code LIKE ? ESCAPE '\' OR f.original_filename LIKE ? ESCAPE '\' OR f.uploader_ip LIKE ? ESCAPE '\' OR u.username LIKE ? ESCAPE '\'
		ORDER BY f.created_at DESC LIMIT ? OFFSET ?`

	rows, err := r.db.QueryContext(ctx, query, searchPattern, searchPattern, searchPattern, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search files: %w", err)
	}
	defer rows.Close()

	var files []models.File
	for rows.Next() {
		var file models.File
		var createdAt, expiresAt string
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userID sql.NullInt64
		var username sql.NullString

		err := rows.Scan(
			&file.ID,
			&file.ClaimCode,
			&file.OriginalFilename,
			&file.StoredFilename,
			&file.FileSize,
			&file.MimeType,
			&createdAt,
			&expiresAt,
			&maxDownloads,
			&file.DownloadCount,
			&file.CompletedDownloads,
			&file.UploaderIP,
			&passwordHash,
			&userID,
			&username,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan file: %w", err)
		}

		// Parse timestamps
		file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse created_at: %w", err)
		}

		file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse expires_at: %w", err)
		}

		// Handle nullable fields
		if maxDownloads.Valid {
			val := int(maxDownloads.Int64)
			file.MaxDownloads = &val
		}
		if passwordHash.Valid {
			file.PasswordHash = passwordHash.String
		}
		if userID.Valid {
			file.UserID = &userID.Int64
		}
		if username.Valid {
			file.Username = &username.String
		}

		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating search results: %w", err)
	}

	return files, total, nil
}

// Ensure FileRepository implements repository.FileRepository.
var _ repository.FileRepository = (*FileRepository)(nil)
