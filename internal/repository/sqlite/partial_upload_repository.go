package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
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

// partialUploadColumns is the column list shared by every SELECT against
// partial_uploads, in the order scanPartialUploads expects.
const partialUploadColumns = `
	upload_id, user_id, filename, total_size, chunk_size, total_chunks,
	chunks_received, received_bytes, expires_in_hours, max_downloads,
	password_hash, created_at, last_activity, completed, claim_code,
	status, error_message, assembly_started_at, assembly_completed_at, client_encrypted, error_code,
	processing_owner, lease_expires_at, assembly_attempts, error_retryable, uploader_ip
`

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
			password_hash, created_at, last_activity, completed, claim_code, status,
			client_encrypted, uploader_ip
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		upload.ClientEncrypted,
		nullableString(upload.UploaderIP),
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
			password_hash, created_at, last_activity, completed, claim_code, status,
			client_encrypted, uploader_ip
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		upload.ClientEncrypted,
		nullableString(upload.UploaderIP),
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

	query := `SELECT ` + partialUploadColumns + ` FROM partial_uploads WHERE upload_id = ?`

	row := r.db.QueryRowContext(ctx, query, uploadID)
	upload, err := scanPartialUploadRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get partial upload: %w", err)
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
// and are not completed. A "processing" row is only abandoned once its lease (or, for a
// never-leased legacy row, its assembly_started_at/last_activity) has been stale for 6
// hours — a live, unexpired lease is never returned regardless of last_activity, so
// cleanup can never race a genuinely in-progress (or recovering) assembly.
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

	query := fmt.Sprintf(`
		SELECT %s
		FROM partial_uploads
		WHERE completed = 0
		AND (
			-- Stuck processing uploads: lease has been expired for 6+ hours (ADR-016).
			-- A live lease's expiry is in the future, so this never matches a
			-- genuinely in-progress or recently-taken-over assembly.
			(status = 'processing' AND datetime(COALESCE(lease_expires_at, assembly_started_at, last_activity)) < datetime('now', '-6 hours'))
			OR
			-- Regular abandoned uploads (not processing)
			((status IS NULL OR status != 'processing') AND datetime(last_activity) %s datetime('now', '-' || ? || ' hours'))
		)
		ORDER BY last_activity ASC
	`, partialUploadColumns, operator)

	return r.queryPartialUploads(ctx, query, expiryHours)
}

// GetOldCompleted returns completed uploads, and terminally-failed uploads
// (error_retryable = 0), older than the specified hours.
func (r *PartialUploadRepository) GetOldCompleted(ctx context.Context, retentionHours int) ([]models.PartialUpload, error) {
	if retentionHours < 0 {
		return nil, fmt.Errorf("retention hours cannot be negative")
	}

	query := `
		SELECT ` + partialUploadColumns + `
		FROM partial_uploads
		WHERE (completed = 1 OR (status = 'failed' AND error_retryable = 0))
		AND datetime(last_activity) < datetime('now', '-' || ? || ' hours')
		ORDER BY last_activity ASC
	`

	return r.queryPartialUploads(ctx, query, retentionHours)
}

// GetByUserID returns all partial uploads for a specific user.
func (r *PartialUploadRepository) GetByUserID(ctx context.Context, userID int64) ([]models.PartialUpload, error) {
	query := `
		SELECT ` + partialUploadColumns + `
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

// TryLockForProcessing performs the Lock transition (uploading -> processing).
// See repository.PartialUploadRepository for the full transition contract.
func (r *PartialUploadRepository) TryLockForProcessing(ctx context.Context, uploadID string, lease repository.AssemblyLease) (bool, error) {
	if uploadID == "" {
		return false, fmt.Errorf("upload_id cannot be empty")
	}
	if lease.Owner == "" {
		return false, fmt.Errorf("lease owner cannot be empty")
	}

	now := time.Now().Format(time.RFC3339)
	query := `
		UPDATE partial_uploads
		SET status = 'processing',
		    processing_owner = ?,
		    lease_expires_at = datetime('now', '+' || ? || ' seconds'),
		    assembly_attempts = assembly_attempts + 1,
		    assembly_started_at = ?,
		    last_activity = ?,
		    error_message = NULL,
		    error_code = NULL,
		    error_retryable = 0
		WHERE upload_id = ? AND status = 'uploading'
	`
	result, err := r.db.ExecContext(ctx, query, lease.Owner, int64(lease.TTL.Seconds()), now, now, uploadID)
	if err != nil {
		return false, fmt.Errorf("failed to lock upload for processing: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}
	return rows > 0, nil
}

// LockFailedForProcessing performs the Reopen-and-Lock transition in a
// single atomic step (failed -> processing). See
// repository.PartialUploadRepository for the full transition contract and
// why this must not be split into a separate Reopen then Lock.
func (r *PartialUploadRepository) LockFailedForProcessing(ctx context.Context, uploadID string, lease repository.AssemblyLease, maxAttempts int) (bool, error) {
	if uploadID == "" {
		return false, fmt.Errorf("upload_id cannot be empty")
	}
	if lease.Owner == "" {
		return false, fmt.Errorf("lease owner cannot be empty")
	}

	now := time.Now().Format(time.RFC3339)
	query := `
		UPDATE partial_uploads
		SET status = 'processing',
		    processing_owner = ?,
		    lease_expires_at = datetime('now', '+' || ? || ' seconds'),
		    assembly_attempts = assembly_attempts + 1,
		    assembly_started_at = ?,
		    last_activity = ?,
		    error_message = NULL,
		    error_code = NULL,
		    error_retryable = 0
		WHERE upload_id = ? AND status = 'failed' AND error_retryable = 1 AND assembly_attempts < ?
	`
	result, err := r.db.ExecContext(ctx, query, lease.Owner, int64(lease.TTL.Seconds()), now, now, uploadID, maxAttempts)
	if err != nil {
		return false, fmt.Errorf("failed to lock failed upload for processing: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}
	return rows > 0, nil
}

// TakeOverExpiredLease performs the TakeOver transition (processing -> processing).
func (r *PartialUploadRepository) TakeOverExpiredLease(ctx context.Context, uploadID string, lease repository.AssemblyLease, maxAttempts int) (bool, error) {
	if uploadID == "" {
		return false, fmt.Errorf("upload_id cannot be empty")
	}
	if lease.Owner == "" {
		return false, fmt.Errorf("lease owner cannot be empty")
	}

	now := time.Now().Format(time.RFC3339)
	query := `
		UPDATE partial_uploads
		SET processing_owner = ?,
		    lease_expires_at = datetime('now', '+' || ? || ' seconds'),
		    assembly_attempts = assembly_attempts + 1,
		    assembly_started_at = ?,
		    last_activity = ?
		WHERE upload_id = ? AND status = 'processing'
		  AND (lease_expires_at IS NULL OR lease_expires_at < datetime('now'))
		  AND assembly_attempts < ?
	`
	result, err := r.db.ExecContext(ctx, query, lease.Owner, int64(lease.TTL.Seconds()), now, now, uploadID, maxAttempts)
	if err != nil {
		return false, fmt.Errorf("failed to take over expired lease: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}
	return rows > 0, nil
}

// ExhaustExpiredLease performs the Exhaust transition (processing -> failed, terminal).
func (r *PartialUploadRepository) ExhaustExpiredLease(ctx context.Context, uploadID string, maxAttempts int) (bool, error) {
	if uploadID == "" {
		return false, fmt.Errorf("upload_id cannot be empty")
	}

	query := `
		UPDATE partial_uploads
		SET status = 'failed',
		    error_message = 'Assembly failed after maximum retry attempts',
		    error_code = 'ASSEMBLY_RETRIES_EXHAUSTED',
		    error_retryable = 0,
		    processing_owner = NULL,
		    lease_expires_at = NULL,
		    last_activity = ?
		WHERE upload_id = ? AND status = 'processing'
		  AND (lease_expires_at IS NULL OR lease_expires_at < datetime('now'))
		  AND assembly_attempts >= ?
	`
	result, err := r.db.ExecContext(ctx, query, time.Now().Format(time.RFC3339), uploadID, maxAttempts)
	if err != nil {
		return false, fmt.Errorf("failed to exhaust expired lease: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}
	return rows > 0, nil
}

// RenewAssemblyLease performs the Renew (heartbeat) transition.
func (r *PartialUploadRepository) RenewAssemblyLease(ctx context.Context, uploadID string, lease repository.AssemblyLease) (bool, error) {
	if uploadID == "" {
		return false, fmt.Errorf("upload_id cannot be empty")
	}
	if lease.Owner == "" {
		return false, fmt.Errorf("lease owner cannot be empty")
	}

	query := `
		UPDATE partial_uploads
		SET lease_expires_at = datetime('now', '+' || ? || ' seconds'),
		    last_activity = ?
		WHERE upload_id = ? AND status = 'processing' AND processing_owner = ?
	`
	result, err := r.db.ExecContext(ctx, query, int64(lease.TTL.Seconds()), time.Now().Format(time.RFC3339), uploadID, lease.Owner)
	if err != nil {
		return false, fmt.Errorf("failed to renew assembly lease: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}
	return rows > 0, nil
}

// YieldAssemblyLease performs the Yield transition: expires the lease now so
// recovery can take over immediately instead of waiting out the full TTL.
func (r *PartialUploadRepository) YieldAssemblyLease(ctx context.Context, uploadID, owner string) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}
	if owner == "" {
		return fmt.Errorf("owner cannot be empty")
	}

	query := `
		UPDATE partial_uploads
		SET lease_expires_at = datetime('now', '-1 seconds')
		WHERE upload_id = ? AND status = 'processing' AND processing_owner = ?
	`
	if _, err := r.db.ExecContext(ctx, query, uploadID, owner); err != nil {
		return fmt.Errorf("failed to yield assembly lease: %w", err)
	}
	return nil
}

// ReleaseProcessingLock unwinds a speculatively-acquired lock: status stays
// 'processing', but the lease is force-expired (like YieldAssemblyLease) and
// assembly_attempts is decremented to undo the increment made when the
// lock/reopen/takeover was acquired for this (never-run) attempt. See
// repository.PartialUploadRepository for why this must not revert status to
// 'uploading' (ADR-016 bug-hunter findings M2/L2).
func (r *PartialUploadRepository) ReleaseProcessingLock(ctx context.Context, uploadID, owner string) (bool, error) {
	if uploadID == "" {
		return false, fmt.Errorf("upload_id cannot be empty")
	}
	if owner == "" {
		return false, fmt.Errorf("owner cannot be empty")
	}
	query := `
		UPDATE partial_uploads
		SET lease_expires_at = datetime('now', '-1 seconds'),
		    assembly_attempts = CASE WHEN assembly_attempts > 0 THEN assembly_attempts - 1 ELSE 0 END,
		    last_activity = ?
		WHERE upload_id = ? AND status = 'processing' AND processing_owner = ?
	`
	result, err := r.db.ExecContext(ctx, query, time.Now().Format(time.RFC3339), uploadID, owner)
	if err != nil {
		return false, fmt.Errorf("failed to release processing lock: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}
	return rowsAffected > 0, nil
}

// GetExpiredLeases returns up to limit uploads in "processing" status whose
// lease has expired (or was never set), oldest first.
func (r *PartialUploadRepository) GetExpiredLeases(ctx context.Context, limit int) ([]models.PartialUpload, error) {
	query := `
		SELECT ` + partialUploadColumns + `
		FROM partial_uploads
		WHERE status = 'processing'
		  AND (lease_expires_at IS NULL OR lease_expires_at < datetime('now'))
		ORDER BY COALESCE(lease_expires_at, assembly_started_at, last_activity) ASC
	`
	if limit > 0 {
		query += ` LIMIT ?`
		return r.queryPartialUploads(ctx, query, limit)
	}
	return r.queryPartialUploadsNoArgs(ctx, query)
}

// ExpireAllLeases force-expires every "processing" row's lease. Called once
// at SQLite startup before the HTTP server accepts requests.
func (r *PartialUploadRepository) ExpireAllLeases(ctx context.Context) error {
	query := `UPDATE partial_uploads SET lease_expires_at = datetime('now', '-1 seconds') WHERE status = 'processing'`
	if _, err := r.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("failed to expire all assembly leases: %w", err)
	}
	return nil
}

// PublishAssembly performs the Publish transition (processing -> completed)
// and inserts the assembled file record in the same transaction.
func (r *PartialUploadRepository) PublishAssembly(ctx context.Context, uploadID, owner string, file *models.File) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}
	if owner == "" {
		return fmt.Errorf("owner cannot be empty")
	}
	if file == nil {
		return fmt.Errorf("file cannot be nil")
	}

	const maxRetries = 5
	baseDelay := 100 * time.Millisecond
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		err := r.publishAssemblyOnce(ctx, uploadID, owner, file)
		if err == nil {
			return nil
		}
		if !isSQLiteBusyError(err) {
			return err
		}
		lastErr = err
		if attempt < maxRetries-1 {
			delay := baseDelay * time.Duration(1<<uint(attempt))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}
	return fmt.Errorf("failed to publish assembly after %d attempts: %w", maxRetries, lastErr)
}

func (r *PartialUploadRepository) publishAssemblyOnce(ctx context.Context, uploadID, owner string, file *models.File) error {
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Format(time.RFC3339)
	query := `
		UPDATE partial_uploads
		SET status = 'completed',
		    completed = 1,
		    claim_code = ?,
		    assembly_completed_at = ?,
		    last_activity = ?,
		    processing_owner = NULL,
		    lease_expires_at = NULL
		WHERE upload_id = ? AND status = 'processing' AND processing_owner = ?
	`
	result, err := tx.ExecContext(ctx, query, file.ClaimCode, now, now, uploadID, owner)
	if err != nil {
		return fmt.Errorf("failed to mark assembly completed: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return repository.ErrLeaseLost
	}

	uploadIDCopy := uploadID
	file.PartialUploadID = &uploadIDCopy
	if err := insertFile(ctx, tx, file); err != nil {
		if isFilesPartialUploadIDViolation(err) {
			return repository.ErrDuplicateKey
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// FailAssembly performs the Fail transition (processing -> failed), optionally
// inserting an audit file row (e.g. malware-detected) in the same transaction.
func (r *PartialUploadRepository) FailAssembly(ctx context.Context, uploadID, owner, errorMessage, errorCode string, retryable bool, auditFile *models.File) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}
	if owner == "" {
		return fmt.Errorf("owner cannot be empty")
	}

	const maxRetries = 5
	baseDelay := 100 * time.Millisecond
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		err := r.failAssemblyOnce(ctx, uploadID, owner, errorMessage, errorCode, retryable, auditFile)
		if err == nil {
			return nil
		}
		if !isSQLiteBusyError(err) {
			return err
		}
		lastErr = err
		if attempt < maxRetries-1 {
			delay := baseDelay * time.Duration(1<<uint(attempt))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}
	return fmt.Errorf("failed to fail assembly after %d attempts: %w", maxRetries, lastErr)
}

func (r *PartialUploadRepository) failAssemblyOnce(ctx context.Context, uploadID, owner, errorMessage, errorCode string, retryable bool, auditFile *models.File) error {
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var errorCodeArg interface{}
	if errorCode != "" {
		errorCodeArg = errorCode
	}

	now := time.Now().Format(time.RFC3339)
	query := `
		UPDATE partial_uploads
		SET status = 'failed',
		    error_message = ?,
		    error_code = ?,
		    error_retryable = ?,
		    processing_owner = NULL,
		    lease_expires_at = NULL,
		    last_activity = ?
		WHERE upload_id = ? AND status = 'processing' AND processing_owner = ?
	`
	result, err := tx.ExecContext(ctx, query, errorMessage, errorCodeArg, retryable, now, uploadID, owner)
	if err != nil {
		return fmt.Errorf("failed to set assembly failed: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return repository.ErrLeaseLost
	}

	if auditFile != nil {
		uploadIDCopy := uploadID
		auditFile.PartialUploadID = &uploadIDCopy
		if err := insertFile(ctx, tx, auditFile); err != nil {
			if isFilesPartialUploadIDViolation(err) {
				// The whole transaction (including the status='failed'
				// UPDATE above) rolls back via the deferred tx.Rollback, so
				// the row is left "processing" with owner still set to the
				// caller — it did NOT transition to failed. Since owner is
				// the fence, no other attempt can act on it either until
				// this lease expires and recovery takes over. Log distinctly
				// so an operator doesn't mistake this for the caller's
				// FailAssembly having succeeded.
				slog.Error("audit file insert hit a duplicate key during FailAssembly; row left processing for lease-expiry recovery",
					"upload_id", uploadID, "owner", owner, "error", err)
				return repository.ErrDuplicateKey
			}
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// DeleteIfAbandoned atomically deletes the row only if it still matches the
// abandoned criteria at delete time.
func (r *PartialUploadRepository) DeleteIfAbandoned(ctx context.Context, uploadID string, expiryHours int) (bool, error) {
	if uploadID == "" {
		return false, fmt.Errorf("upload_id cannot be empty")
	}
	if expiryHours < 0 {
		return false, fmt.Errorf("expiry hours cannot be negative")
	}

	operator := "<"
	if expiryHours == 0 {
		operator = "<="
	}

	query := fmt.Sprintf(`
		DELETE FROM partial_uploads
		WHERE upload_id = ?
		AND completed = 0
		AND (
			(status = 'processing' AND datetime(COALESCE(lease_expires_at, assembly_started_at, last_activity)) < datetime('now', '-6 hours'))
			OR
			((status IS NULL OR status != 'processing') AND datetime(last_activity) %s datetime('now', '-' || ? || ' hours'))
		)
	`, operator)

	result, err := r.db.ExecContext(ctx, query, uploadID, expiryHours)
	if err != nil {
		return false, fmt.Errorf("failed to delete abandoned upload: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}
	return rows > 0, nil
}

// queryPartialUploads is a helper that executes a query and returns partial uploads.
func (r *PartialUploadRepository) queryPartialUploads(ctx context.Context, query string, arg interface{}) ([]models.PartialUpload, error) {
	rows, err := r.db.QueryContext(ctx, query, arg)
	if err != nil {
		return nil, fmt.Errorf("failed to query partial uploads: %w", err)
	}
	defer rows.Close()

	return scanPartialUploads(rows)
}

// queryPartialUploadsNoArgs is a helper that executes a query without arguments.
func (r *PartialUploadRepository) queryPartialUploadsNoArgs(ctx context.Context, query string) ([]models.PartialUpload, error) {
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query partial uploads: %w", err)
	}
	defer rows.Close()

	return scanPartialUploads(rows)
}

// partialUploadScanner is implemented by both *sql.Row and *sql.Rows.
type partialUploadScanner interface {
	Scan(dest ...interface{}) error
}

// scanPartialUploadRow scans a single row (from QueryRowContext) into a PartialUpload.
func scanPartialUploadRow(row partialUploadScanner) (*models.PartialUpload, error) {
	upload := &models.PartialUpload{}
	if err := scanPartialUploadInto(row, upload); err != nil {
		return nil, err
	}
	return upload, nil
}

// scanPartialUploadInto scans one row's columns (in partialUploadColumns order) into upload.
func scanPartialUploadInto(row partialUploadScanner, upload *models.PartialUpload) error {
	var userID sql.NullInt64
	var claimCode sql.NullString
	var status sql.NullString
	var errorMessage sql.NullString
	var assemblyStartedAt sql.NullString
	var assemblyCompletedAt sql.NullString
	var errorCode sql.NullString
	var processingOwner sql.NullString
	var leaseExpiresAt sql.NullString
	var uploaderIP sql.NullString
	var errorRetryable sql.NullBool
	var createdAt, lastActivity string

	err := row.Scan(
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
		&upload.ClientEncrypted,
		&errorCode,
		&processingOwner,
		&leaseExpiresAt,
		&upload.AssemblyAttempts,
		&errorRetryable,
		&uploaderIP,
	)
	if err != nil {
		return err
	}

	upload.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return fmt.Errorf("failed to parse created_at: %w", err)
	}
	upload.LastActivity, err = time.Parse(time.RFC3339, lastActivity)
	if err != nil {
		return fmt.Errorf("failed to parse last_activity: %w", err)
	}

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
		if t, err := time.Parse(time.RFC3339, assemblyStartedAt.String); err == nil {
			upload.AssemblyStartedAt = &t
		}
	}
	if assemblyCompletedAt.Valid {
		if t, err := time.Parse(time.RFC3339, assemblyCompletedAt.String); err == nil {
			upload.AssemblyCompletedAt = &t
		}
	}
	if errorCode.Valid {
		upload.ErrorCode = &errorCode.String
	}
	if processingOwner.Valid {
		upload.Owner = &processingOwner.String
	}
	if leaseExpiresAt.Valid {
		if t, err := time.Parse(time.RFC3339, normalizeSQLiteTimestamp(leaseExpiresAt.String)); err == nil {
			upload.LeaseExpiresAt = &t
		}
	}
	upload.ErrorRetryable = errorRetryable.Valid && errorRetryable.Bool
	if uploaderIP.Valid {
		upload.UploaderIP = uploaderIP.String
	}

	return nil
}

// normalizeSQLiteTimestamp adapts a SQLite datetime('now', ...) result
// ("2024-01-02 15:04:05") to RFC3339 parsing ("2024-01-02T15:04:05Z") since
// lease_expires_at is written via SQL datetime() rather than Go's
// time.Format(time.RFC3339) like the other timestamp columns.
func normalizeSQLiteTimestamp(s string) string {
	if len(s) == 19 && s[10] == ' ' {
		return s[:10] + "T" + s[10:] + "Z"
	}
	return s
}

// scanPartialUploads scans rows into partial upload structs.
func scanPartialUploads(rows *sql.Rows) ([]models.PartialUpload, error) {
	var uploads []models.PartialUpload
	for rows.Next() {
		var upload models.PartialUpload
		if err := scanPartialUploadInto(rows, &upload); err != nil {
			return nil, fmt.Errorf("failed to scan partial upload: %w", err)
		}
		uploads = append(uploads, upload)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating partial uploads: %w", err)
	}

	return uploads, nil
}

// isFilesPartialUploadIDViolation reports whether err is specifically a
// UNIQUE constraint failure on files.partial_upload_id (idx_files_partial_upload_id
// — the ADR-016 belt-and-suspenders fence on top of the owner-guarded CAS
// that makes a double-publish for one upload_id structurally impossible).
// insertFile's other unique constraint (files.claim_code) is a different
// kind of collision — a rare claim-code-generation race, not "this upload
// was already published/failed by someone else" — and must not be
// misreported as one (code-reviewer / DB-review finding): modernc.org/sqlite
// names the offending column(s) in its error text, so a substring check on
// "files.partial_upload_id" distinguishes the two.
func isFilesPartialUploadIDViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed") &&
		strings.Contains(err.Error(), "files.partial_upload_id")
}

// Ensure PartialUploadRepository implements repository.PartialUploadRepository.
var _ repository.PartialUploadRepository = (*PartialUploadRepository)(nil)
