package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// Valid status values for partial uploads.
var validUploadStatuses = map[string]bool{
	"uploading":  true,
	"processing": true,
	"completed":  true,
	"failed":     true,
}

// PartialUploadRepository implements repository.PartialUploadRepository for SQLite.
type PartialUploadRepository struct {
	db *sql.DB
}

// NewPartialUploadRepository creates a new SQLite partial upload repository.
func NewPartialUploadRepository(db *sql.DB) *PartialUploadRepository {
	return &PartialUploadRepository{db: db}
}

// Create inserts a new partial upload record.
func (r *PartialUploadRepository) Create(ctx context.Context, upload *models.PartialUpload) error {
	if upload == nil {
		return fmt.Errorf("upload cannot be nil")
	}
	if upload.UploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}

	query := `
		INSERT INTO partial_uploads (
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code, status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	status := upload.Status
	if status == "" {
		status = "uploading"
	}

	_, err := r.db.ExecContext(ctx, query,
		upload.UploadID,
		upload.UserID,
		upload.Filename,
		upload.TotalSize,
		upload.ChunkSize,
		upload.TotalChunks,
		upload.ChunksReceived,
		upload.ReceivedBytes,
		upload.ExpiresInHours,
		upload.MaxDownloads,
		upload.PasswordHash,
		upload.CreatedAt.Format(time.RFC3339),
		upload.LastActivity.Format(time.RFC3339),
		upload.Completed,
		upload.ClaimCode,
		status,
	)

	if err != nil {
		return fmt.Errorf("failed to create partial upload: %w", err)
	}

	return nil
}

// CreateWithQuotaCheck atomically checks quota and creates a partial upload record.
// Returns ErrQuotaExceeded if adding the upload would exceed the quota limit.
// This prevents race conditions where multiple uploads could exceed quota.
func (r *PartialUploadRepository) CreateWithQuotaCheck(ctx context.Context, upload *models.PartialUpload, quotaLimitBytes int64) error {
	if upload == nil {
		return fmt.Errorf("upload cannot be nil")
	}
	if upload.UploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}
	if quotaLimitBytes < 0 {
		return fmt.Errorf("quota limit cannot be negative")
	}

	const maxRetries = 5
	baseDelay := 50 * time.Millisecond

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		err := r.createWithQuotaCheckOnce(ctx, upload, quotaLimitBytes)
		if err == nil {
			return nil
		}
		lastErr = err

		// Only retry on SQLITE_BUSY errors, not on quota exceeded or other errors
		if !isSQLiteBusyError(err) {
			return err
		}

		// Wait with exponential backoff before retrying
		if attempt < maxRetries-1 {
			delay := baseDelay * time.Duration(1<<uint(attempt))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	return fmt.Errorf("failed to create partial upload after %d attempts: %w", maxRetries, lastErr)
}

// createWithQuotaCheckOnce performs a single attempt at the quota check and insert.
func (r *PartialUploadRepository) createWithQuotaCheckOnce(ctx context.Context, upload *models.PartialUpload, quotaLimitBytes int64) error {
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Check quota within transaction (atomic with insert)
	// Note: Uses total_size for partial uploads (not received_bytes) since we reserve full size upfront
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

	// Check if adding this upload would exceed quota (overflow-safe)
	// Rearrange to avoid potential integer overflow in addition
	if currentUsage > quotaLimitBytes || upload.TotalSize > quotaLimitBytes-currentUsage {
		return repository.ErrQuotaExceeded
	}

	// Insert partial upload record (still within transaction)
	status := upload.Status
	if status == "" {
		status = "uploading"
	}

	insertQuery := `
		INSERT INTO partial_uploads (
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code, status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = tx.ExecContext(ctx, insertQuery,
		upload.UploadID,
		upload.UserID,
		upload.Filename,
		upload.TotalSize,
		upload.ChunkSize,
		upload.TotalChunks,
		upload.ChunksReceived,
		upload.ReceivedBytes,
		upload.ExpiresInHours,
		upload.MaxDownloads,
		upload.PasswordHash,
		upload.CreatedAt.Format(time.RFC3339),
		upload.LastActivity.Format(time.RFC3339),
		upload.Completed,
		upload.ClaimCode,
		status,
	)
	if err != nil {
		return fmt.Errorf("failed to insert partial upload: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetByUploadID retrieves a partial upload by upload_id.
// Returns nil, nil if not found.
func (r *PartialUploadRepository) GetByUploadID(ctx context.Context, uploadID string) (*models.PartialUpload, error) {
	if uploadID == "" {
		return nil, fmt.Errorf("upload_id cannot be empty")
	}

	query := `
		SELECT
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code,
			status, error_message, assembly_started_at, assembly_completed_at
		FROM partial_uploads
		WHERE upload_id = ?
	`

	upload := &models.PartialUpload{}
	var userID sql.NullInt64
	var claimCode sql.NullString
	var status sql.NullString
	var errorMessage sql.NullString
	var assemblyStartedAt sql.NullString
	var assemblyCompletedAt sql.NullString
	var createdAt, lastActivity string

	err := r.db.QueryRowContext(ctx, query, uploadID).Scan(
		&upload.UploadID,
		&userID,
		&upload.Filename,
		&upload.TotalSize,
		&upload.ChunkSize,
		&upload.TotalChunks,
		&upload.ChunksReceived,
		&upload.ReceivedBytes,
		&upload.ExpiresInHours,
		&upload.MaxDownloads,
		&upload.PasswordHash,
		&createdAt,
		&lastActivity,
		&upload.Completed,
		&claimCode,
		&status,
		&errorMessage,
		&assemblyStartedAt,
		&assemblyCompletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get partial upload: %w", err)
	}

	// Parse timestamps
	upload.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}
	upload.LastActivity, err = time.Parse(time.RFC3339, lastActivity)
	if err != nil {
		return nil, fmt.Errorf("failed to parse last_activity: %w", err)
	}

	// Handle nullable fields
	if userID.Valid {
		upload.UserID = &userID.Int64
	}
	if claimCode.Valid {
		upload.ClaimCode = &claimCode.String
	}
	if status.Valid {
		upload.Status = status.String
	} else {
		upload.Status = "uploading" // Default for old records
	}
	if errorMessage.Valid {
		upload.ErrorMessage = &errorMessage.String
	}
	if assemblyStartedAt.Valid {
		t, err := time.Parse(time.RFC3339, assemblyStartedAt.String)
		if err == nil {
			upload.AssemblyStartedAt = &t
		}
	}
	if assemblyCompletedAt.Valid {
		t, err := time.Parse(time.RFC3339, assemblyCompletedAt.String)
		if err == nil {
			upload.AssemblyCompletedAt = &t
		}
	}

	return upload, nil
}

// Exists checks if a partial upload record exists in the database.
func (r *PartialUploadRepository) Exists(ctx context.Context, uploadID string) (bool, error) {
	if uploadID == "" {
		return false, fmt.Errorf("upload_id cannot be empty")
	}

	query := `SELECT COUNT(*) FROM partial_uploads WHERE upload_id = ?`

	var count int
	err := r.db.QueryRowContext(ctx, query, uploadID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check partial upload existence: %w", err)
	}

	return count > 0, nil
}

// UpdateActivity updates the last_activity timestamp.
func (r *PartialUploadRepository) UpdateActivity(ctx context.Context, uploadID string) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}

	query := `UPDATE partial_uploads SET last_activity = ? WHERE upload_id = ?`

	_, err := r.db.ExecContext(ctx, query, time.Now().Format(time.RFC3339), uploadID)
	if err != nil {
		return fmt.Errorf("failed to update partial upload activity: %w", err)
	}

	return nil
}

// IncrementChunksReceived increments chunks_received and received_bytes.
func (r *PartialUploadRepository) IncrementChunksReceived(ctx context.Context, uploadID string, chunkBytes int64) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}
	if chunkBytes < 0 {
		return fmt.Errorf("chunk bytes cannot be negative")
	}

	query := `
		UPDATE partial_uploads
		SET chunks_received = chunks_received + 1,
		    received_bytes = received_bytes + ?,
		    last_activity = ?
		WHERE upload_id = ?
	`

	_, err := r.db.ExecContext(ctx, query, chunkBytes, time.Now().Format(time.RFC3339), uploadID)
	if err != nil {
		return fmt.Errorf("failed to increment chunks received: %w", err)
	}

	return nil
}

// MarkCompleted marks a partial upload as completed and sets the claim code.
func (r *PartialUploadRepository) MarkCompleted(ctx context.Context, uploadID, claimCode string) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}
	if claimCode == "" {
		return fmt.Errorf("claim_code cannot be empty")
	}

	query := `
		UPDATE partial_uploads
		SET completed = 1, claim_code = ?, last_activity = ?
		WHERE upload_id = ?
	`

	_, err := r.db.ExecContext(ctx, query, claimCode, time.Now().Format(time.RFC3339), uploadID)
	if err != nil {
		return fmt.Errorf("failed to mark partial upload as completed: %w", err)
	}

	return nil
}

// Delete removes a partial upload record.
func (r *PartialUploadRepository) Delete(ctx context.Context, uploadID string) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}

	query := `DELETE FROM partial_uploads WHERE upload_id = ?`

	_, err := r.db.ExecContext(ctx, query, uploadID)
	if err != nil {
		return fmt.Errorf("failed to delete partial upload: %w", err)
	}

	return nil
}

// GetAbandoned returns partial uploads that haven't been active for the specified hours
// and are not completed. Includes stuck processing uploads that exceed timeout.
func (r *PartialUploadRepository) GetAbandoned(ctx context.Context, expiryHours int) ([]models.PartialUpload, error) {
	if expiryHours < 0 {
		return nil, fmt.Errorf("expiry hours cannot be negative")
	}

	// For immediate cleanup (expiryHours=0), use <= to catch all incomplete uploads
	// For timed cleanup (expiryHours>0), use < to respect the grace period
	operator := "<"
	if expiryHours == 0 {
		operator = "<="
	}

	// Query includes stuck processing uploads (assembly timeout: 6 hours)
	query := fmt.Sprintf(`
		SELECT
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code,
			status, error_message, assembly_started_at, assembly_completed_at
		FROM partial_uploads
		WHERE completed = 0
		AND (
			-- Stuck processing uploads (assembly timeout: 6 hours)
			(status = 'processing' AND assembly_started_at IS NOT NULL AND datetime(assembly_started_at) < datetime('now', '-6 hours'))
			OR
			-- Regular abandoned uploads (not processing)
			((status IS NULL OR status != 'processing') AND datetime(last_activity) %s datetime('now', '-' || ? || ' hours'))
		)
		ORDER BY last_activity ASC
	`, operator)

	return r.queryPartialUploads(ctx, query, expiryHours)
}

// GetOldCompleted returns completed uploads older than the specified hours.
// These are kept for idempotency and cleaned up after retention period.
func (r *PartialUploadRepository) GetOldCompleted(ctx context.Context, retentionHours int) ([]models.PartialUpload, error) {
	if retentionHours < 0 {
		return nil, fmt.Errorf("retention hours cannot be negative")
	}

	query := `
		SELECT
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code,
			status, error_message, assembly_started_at, assembly_completed_at
		FROM partial_uploads
		WHERE completed = 1
		AND datetime(last_activity) < datetime('now', '-' || ? || ' hours')
		ORDER BY last_activity ASC
	`

	return r.queryPartialUploads(ctx, query, retentionHours)
}

// GetByUserID returns all partial uploads for a specific user.
func (r *PartialUploadRepository) GetByUserID(ctx context.Context, userID int64) ([]models.PartialUpload, error) {
	query := `
		SELECT
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code,
			status, error_message, assembly_started_at, assembly_completed_at
		FROM partial_uploads
		WHERE user_id = ?
		ORDER BY created_at DESC
	`

	return r.queryPartialUploads(ctx, query, userID)
}

// GetTotalUsage returns the total bytes used by active (incomplete) partial uploads.
func (r *PartialUploadRepository) GetTotalUsage(ctx context.Context) (int64, error) {
	query := `SELECT COALESCE(SUM(received_bytes), 0) FROM partial_uploads WHERE completed = 0`

	var total int64
	err := r.db.QueryRowContext(ctx, query).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("failed to get total partial upload usage: %w", err)
	}

	return total, nil
}

// GetIncompleteCount returns the count of incomplete partial upload sessions.
func (r *PartialUploadRepository) GetIncompleteCount(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM partial_uploads WHERE completed = 0`

	var count int
	err := r.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get partial uploads count: %w", err)
	}

	return count, nil
}

// GetAllUploadIDs returns all upload_ids currently in the database as a set.
// This is optimized for orphaned chunk detection to avoid N+1 queries.
func (r *PartialUploadRepository) GetAllUploadIDs(ctx context.Context) (map[string]bool, error) {
	query := `SELECT upload_id FROM partial_uploads`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query partial upload IDs: %w", err)
	}
	defer rows.Close()

	uploadIDs := make(map[string]bool)
	for rows.Next() {
		var uploadID string
		if err := rows.Scan(&uploadID); err != nil {
			return nil, fmt.Errorf("failed to scan upload ID: %w", err)
		}
		uploadIDs[uploadID] = true
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating upload IDs: %w", err)
	}

	return uploadIDs, nil
}

// UpdateStatus updates the status and error_message (if provided).
// Status must be one of: uploading, processing, completed, failed.
func (r *PartialUploadRepository) UpdateStatus(ctx context.Context, uploadID, status string, errorMessage *string) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}
	if status == "" {
		return fmt.Errorf("status cannot be empty")
	}
	if !validUploadStatuses[status] {
		return fmt.Errorf("invalid status: %s (must be one of: uploading, processing, completed, failed)", status)
	}

	query := `UPDATE partial_uploads SET status = ?, error_message = ?, last_activity = ? WHERE upload_id = ?`

	_, err := r.db.ExecContext(ctx, query, status, errorMessage, time.Now().Format(time.RFC3339), uploadID)
	if err != nil {
		return fmt.Errorf("failed to update partial upload status: %w", err)
	}

	return nil
}

// SetAssemblyStarted marks assembly as started.
func (r *PartialUploadRepository) SetAssemblyStarted(ctx context.Context, uploadID string) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}

	now := time.Now().Format(time.RFC3339)
	query := `UPDATE partial_uploads SET status = 'processing', assembly_started_at = ?, last_activity = ? WHERE upload_id = ?`

	_, err := r.db.ExecContext(ctx, query, now, now, uploadID)
	if err != nil {
		return fmt.Errorf("failed to set assembly started: %w", err)
	}

	return nil
}

// SetAssemblyCompleted marks assembly as completed with claim code.
func (r *PartialUploadRepository) SetAssemblyCompleted(ctx context.Context, uploadID, claimCode string) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}
	if claimCode == "" {
		return fmt.Errorf("claim_code cannot be empty")
	}

	now := time.Now().Format(time.RFC3339)
	query := `
		UPDATE partial_uploads
		SET status = 'completed', completed = 1, claim_code = ?,
		    assembly_completed_at = ?, last_activity = ?
		WHERE upload_id = ?
	`

	_, err := r.db.ExecContext(ctx, query, claimCode, now, now, uploadID)
	if err != nil {
		return fmt.Errorf("failed to set assembly completed: %w", err)
	}

	return nil
}

// SetAssemblyFailed marks assembly as failed with error message.
// Retries with exponential backoff to handle SQLITE_BUSY errors.
func (r *PartialUploadRepository) SetAssemblyFailed(ctx context.Context, uploadID, errorMessage string) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}

	now := time.Now().Format(time.RFC3339)
	query := `
		UPDATE partial_uploads
		SET status = 'failed', error_message = ?, last_activity = ?
		WHERE upload_id = ?
	`

	// Retry with exponential backoff to handle SQLITE_BUSY errors
	maxRetries := 5
	baseDelay := 100 * time.Millisecond

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		_, err := r.db.ExecContext(ctx, query, errorMessage, now, uploadID)
		if err == nil {
			return nil
		}

		lastErr = err

		// Only retry on SQLITE_BUSY errors, not permanent failures
		if !isSQLiteBusyError(err) {
			return fmt.Errorf("failed to set assembly failed: %w", err)
		}

		if attempt < maxRetries-1 {
			delay := baseDelay * time.Duration(1<<uint(attempt))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	return fmt.Errorf("failed to set assembly failed after %d attempts: %w", maxRetries, lastErr)
}

// GetProcessing returns all uploads currently in "processing" status.
// Used by startup recovery worker to resume interrupted assemblies.
func (r *PartialUploadRepository) GetProcessing(ctx context.Context) ([]models.PartialUpload, error) {
	query := `
		SELECT
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code,
			status, error_message, assembly_started_at, assembly_completed_at
		FROM partial_uploads
		WHERE status = 'processing'
		ORDER BY assembly_started_at ASC
	`

	return r.queryPartialUploadsNoArgs(ctx, query)
}

// TryLockForProcessing attempts to atomically transition upload from "uploading" to "processing".
// Returns true if successful (lock acquired), false if already locked by another process.
func (r *PartialUploadRepository) TryLockForProcessing(ctx context.Context, uploadID string) (bool, error) {
	if uploadID == "" {
		return false, fmt.Errorf("upload_id cannot be empty")
	}

	now := time.Now().Format(time.RFC3339)
	query := `
		UPDATE partial_uploads
		SET status = 'processing', assembly_started_at = ?, last_activity = ?
		WHERE upload_id = ? AND status = 'uploading'
	`

	result, err := r.db.ExecContext(ctx, query, now, now, uploadID)
	if err != nil {
		return false, fmt.Errorf("failed to lock upload for processing: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}

// queryPartialUploads is a helper that executes a query and returns partial uploads.
func (r *PartialUploadRepository) queryPartialUploads(ctx context.Context, query string, arg interface{}) ([]models.PartialUpload, error) {
	rows, err := r.db.QueryContext(ctx, query, arg)
	if err != nil {
		return nil, fmt.Errorf("failed to query partial uploads: %w", err)
	}
	defer rows.Close()

	return r.scanPartialUploads(rows)
}

// queryPartialUploadsNoArgs is a helper that executes a query without arguments.
func (r *PartialUploadRepository) queryPartialUploadsNoArgs(ctx context.Context, query string) ([]models.PartialUpload, error) {
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query partial uploads: %w", err)
	}
	defer rows.Close()

	return r.scanPartialUploads(rows)
}

// scanPartialUploads scans rows into partial upload structs.
func (r *PartialUploadRepository) scanPartialUploads(rows *sql.Rows) ([]models.PartialUpload, error) {
	var uploads []models.PartialUpload
	for rows.Next() {
		var upload models.PartialUpload
		var userID sql.NullInt64
		var claimCode sql.NullString
		var status sql.NullString
		var errorMessage sql.NullString
		var assemblyStartedAt sql.NullString
		var assemblyCompletedAt sql.NullString
		var createdAt, lastActivity string

		err := rows.Scan(
			&upload.UploadID,
			&userID,
			&upload.Filename,
			&upload.TotalSize,
			&upload.ChunkSize,
			&upload.TotalChunks,
			&upload.ChunksReceived,
			&upload.ReceivedBytes,
			&upload.ExpiresInHours,
			&upload.MaxDownloads,
			&upload.PasswordHash,
			&createdAt,
			&lastActivity,
			&upload.Completed,
			&claimCode,
			&status,
			&errorMessage,
			&assemblyStartedAt,
			&assemblyCompletedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan partial upload: %w", err)
		}

		// Parse timestamps
		upload.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse created_at: %w", err)
		}
		upload.LastActivity, err = time.Parse(time.RFC3339, lastActivity)
		if err != nil {
			return nil, fmt.Errorf("failed to parse last_activity: %w", err)
		}

		// Handle nullable fields
		if userID.Valid {
			upload.UserID = &userID.Int64
		}
		if claimCode.Valid {
			upload.ClaimCode = &claimCode.String
		}
		if status.Valid {
			upload.Status = status.String
		} else {
			upload.Status = "uploading"
		}
		if errorMessage.Valid {
			upload.ErrorMessage = &errorMessage.String
		}
		if assemblyStartedAt.Valid {
			t, err := time.Parse(time.RFC3339, assemblyStartedAt.String)
			if err == nil {
				upload.AssemblyStartedAt = &t
			}
		}
		if assemblyCompletedAt.Valid {
			t, err := time.Parse(time.RFC3339, assemblyCompletedAt.String)
			if err == nil {
				upload.AssemblyCompletedAt = &t
			}
		}

		uploads = append(uploads, upload)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating partial uploads: %w", err)
	}

	return uploads, nil
}

// Ensure PartialUploadRepository implements repository.PartialUploadRepository.
var _ repository.PartialUploadRepository = (*PartialUploadRepository)(nil)
