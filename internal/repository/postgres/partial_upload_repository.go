// Package postgres provides PostgreSQL implementations of repository interfaces.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"

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

// PartialUploadRepository implements repository.PartialUploadRepository for PostgreSQL.
type PartialUploadRepository struct {
	pool *Pool
}

// NewPartialUploadRepository creates a new PostgreSQL partial upload repository.
func NewPartialUploadRepository(pool *Pool) *PartialUploadRepository {
	return &PartialUploadRepository{pool: pool}
}

// Create inserts a new partial upload record.
func (r *PartialUploadRepository) Create(ctx context.Context, upload *models.PartialUpload) error {
	if upload == nil {
		return fmt.Errorf("upload cannot be nil")
	}
	if upload.UploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}

	status := upload.Status
	if status == "" {
		status = "uploading"
	}

	query := `
		INSERT INTO partial_uploads (
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code, status,
			client_encrypted, uploader_ip
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`

	_, err := r.pool.Exec(ctx, query,
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
		upload.CreatedAt,
		upload.LastActivity,
		upload.Completed,
		upload.ClaimCode,
		status,
		upload.ClientEncrypted,
		pgNullableString(upload.UploaderIP),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return repository.ErrDuplicateKey
		}
		return fmt.Errorf("failed to create partial upload: %w", err)
	}

	return nil
}

// CreateWithQuotaCheck atomically checks quota and creates a partial upload record.
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

	return withRetryNoReturn(ctx, 3, func() error {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }() // Safe to ignore: no-op after commit

		// Check quota within transaction
		var currentUsage int64
		if err := tx.QueryRow(ctx, storageUsageQuery).Scan(&currentUsage); err != nil {
			return fmt.Errorf("failed to get current usage: %w", err)
		}

		// Check if adding this upload would exceed quota (overflow-safe)
		if currentUsage > quotaLimitBytes || upload.TotalSize > quotaLimitBytes-currentUsage {
			return repository.ErrQuotaExceeded
		}

		// Insert partial upload record
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
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		`

		_, err = tx.Exec(ctx, insertQuery,
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
			upload.CreatedAt,
			upload.LastActivity,
			upload.Completed,
			upload.ClaimCode,
			status,
			upload.ClientEncrypted,
			pgNullableString(upload.UploaderIP),
		)
		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrDuplicateKey
			}
			return fmt.Errorf("failed to insert partial upload: %w", err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		return nil
	})
}

// GetByUploadID retrieves a partial upload by upload_id.
func (r *PartialUploadRepository) GetByUploadID(ctx context.Context, uploadID string) (*models.PartialUpload, error) {
	if uploadID == "" {
		return nil, fmt.Errorf("upload_id cannot be empty")
	}

	query := `SELECT ` + partialUploadColumns + ` FROM partial_uploads WHERE upload_id = $1`

	upload, err := scanPartialUploadRow(r.pool.QueryRow(ctx, query, uploadID))
	if err == pgx.ErrNoRows {
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

	query := `SELECT EXISTS(SELECT 1 FROM partial_uploads WHERE upload_id = $1)`

	var exists bool
	err := r.pool.QueryRow(ctx, query, uploadID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check partial upload existence: %w", err)
	}

	return exists, nil
}

// UpdateActivity updates the last_activity timestamp.
func (r *PartialUploadRepository) UpdateActivity(ctx context.Context, uploadID string) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}

	query := `UPDATE partial_uploads SET last_activity = NOW() WHERE upload_id = $1`

	_, err := r.pool.Exec(ctx, query, uploadID)
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
		    received_bytes = received_bytes + $1,
		    last_activity = NOW()
		WHERE upload_id = $2
	`

	_, err := r.pool.Exec(ctx, query, chunkBytes, uploadID)
	if err != nil {
		return fmt.Errorf("failed to increment chunks received: %w", err)
	}

	return nil
}

// RecordChunkProgress implements repository.PartialUploadRepository.RecordChunkProgress.
func (r *PartialUploadRepository) RecordChunkProgress(ctx context.Context, uploadID string, receivedBytes int64) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}
	if receivedBytes < 0 {
		return fmt.Errorf("received bytes cannot be negative")
	}

	query := `
		UPDATE partial_uploads
		SET last_activity = NOW(),
		    received_bytes = GREATEST(COALESCE(received_bytes, 0), LEAST($1, total_size))
		WHERE upload_id = $2 AND completed = false AND COALESCE(status, 'uploading') = 'uploading'
	`

	_, err := r.pool.Exec(ctx, query, receivedBytes, uploadID)
	if err != nil {
		return fmt.Errorf("failed to record chunk progress: %w", err)
	}

	return nil
}

// RenewReservation implements repository.PartialUploadRepository.RenewReservation.
func (r *PartialUploadRepository) RenewReservation(ctx context.Context, uploadID string, quotaLimitBytes int64) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}
	if quotaLimitBytes < 0 {
		return fmt.Errorf("quota limit cannot be negative")
	}

	return withRetryNoReturn(ctx, 3, func() error {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }() // Safe to ignore: no-op after commit

		// Re-read with the row locked: a parallel chunk may already have
		// renewed it, in which case it's held again and there's nothing to do.
		var lapsed bool
		var remaining int64
		err = tx.QueryRow(ctx, `
			SELECT
				COALESCE(completed = false AND `+reservationLapsed+`, false),
				total_size - COALESCE(received_bytes, 0)
			FROM partial_uploads
			WHERE upload_id = $1
			FOR UPDATE
		`, uploadID).Scan(&lapsed, &remaining)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !lapsed) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read partial upload: %w", err)
		}

		// The lapsed upload is counted at received_bytes in the usage, so the
		// rest of its size has to fit on top of it (overflow-safe).
		var currentUsage int64
		if err := tx.QueryRow(ctx, storageUsageQuery).Scan(&currentUsage); err != nil {
			return fmt.Errorf("failed to get current usage: %w", err)
		}
		if currentUsage > quotaLimitBytes || remaining > quotaLimitBytes-currentUsage {
			return repository.ErrQuotaExceeded
		}

		if _, err := tx.Exec(ctx, `UPDATE partial_uploads SET last_activity = NOW() WHERE upload_id = $1`, uploadID); err != nil {
			return fmt.Errorf("failed to renew reservation: %w", err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
		return nil
	})
}

// Delete removes a partial upload record.
func (r *PartialUploadRepository) Delete(ctx context.Context, uploadID string) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}

	query := `DELETE FROM partial_uploads WHERE upload_id = $1`

	_, err := r.pool.Exec(ctx, query, uploadID)
	if err != nil {
		return fmt.Errorf("failed to delete partial upload: %w", err)
	}

	return nil
}

// GetAbandoned returns partial uploads that haven't been active for the specified hours.
// A "processing" row is only abandoned once its lease (or, for a never-leased legacy
// row, its assembly_started_at/last_activity) has been stale for 6 hours — a live,
// unexpired lease is never returned regardless of last_activity (ADR-016).
func (r *PartialUploadRepository) GetAbandoned(ctx context.Context, expiryHours int) ([]models.PartialUpload, error) {
	if expiryHours < 0 {
		return nil, fmt.Errorf("expiry hours cannot be negative")
	}

	query := `
		SELECT ` + partialUploadColumns + `
		FROM partial_uploads
		WHERE completed = false
		AND (
			(status = 'processing' AND COALESCE(lease_expires_at, assembly_started_at, last_activity) < NOW() - INTERVAL '6 hours')
			OR
			((status IS NULL OR status != 'processing') AND last_activity < NOW() - $1 * INTERVAL '1 hour')
		)
		ORDER BY last_activity ASC
	`

	return r.queryPartialUploads(ctx, query, expiryHours)
}

// GetOldCompleted returns completed uploads, and terminally-failed uploads
// (error_retryable = false), older than the specified hours.
func (r *PartialUploadRepository) GetOldCompleted(ctx context.Context, retentionHours int) ([]models.PartialUpload, error) {
	if retentionHours < 0 {
		return nil, fmt.Errorf("retention hours cannot be negative")
	}

	query := `
		SELECT ` + partialUploadColumns + `
		FROM partial_uploads
		WHERE (completed = true OR (status = 'failed' AND error_retryable = false))
		AND last_activity < NOW() - $1 * INTERVAL '1 hour'
		ORDER BY last_activity ASC
	`

	return r.queryPartialUploads(ctx, query, retentionHours)
}

// GetByUserID returns all partial uploads for a specific user.
func (r *PartialUploadRepository) GetByUserID(ctx context.Context, userID int64) ([]models.PartialUpload, error) {
	query := `
		SELECT ` + partialUploadColumns + `
		FROM partial_uploads
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	return r.queryPartialUploads(ctx, query, userID)
}

// GetTotalUsage returns the total bytes used by active (incomplete) partial uploads.
func (r *PartialUploadRepository) GetTotalUsage(ctx context.Context) (int64, error) {
	query := `SELECT COALESCE(SUM(received_bytes), 0) FROM partial_uploads WHERE completed = false`

	var total int64
	err := r.pool.QueryRow(ctx, query).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("failed to get total partial upload usage: %w", err)
	}

	return total, nil
}

// GetIncompleteCount returns the count of incomplete partial upload sessions.
func (r *PartialUploadRepository) GetIncompleteCount(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM partial_uploads WHERE completed = false`

	var count int
	err := r.pool.QueryRow(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get partial uploads count: %w", err)
	}

	return count, nil
}

// GetAllUploadIDs returns all upload_ids currently in the database as a set.
func (r *PartialUploadRepository) GetAllUploadIDs(ctx context.Context) (map[string]bool, error) {
	query := `SELECT upload_id FROM partial_uploads`

	rows, err := r.pool.Query(ctx, query)
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

	query := `UPDATE partial_uploads SET status = $1, error_message = $2, last_activity = NOW() WHERE upload_id = $3`

	_, err := r.pool.Exec(ctx, query, status, errorMessage, uploadID)
	if err != nil {
		return fmt.Errorf("failed to update partial upload status: %w", err)
	}

	return nil
}

// TryLockForProcessing performs the Lock transition (uploading -> processing).
func (r *PartialUploadRepository) TryLockForProcessing(ctx context.Context, uploadID string, lease repository.AssemblyLease) (bool, error) {
	if uploadID == "" {
		return false, fmt.Errorf("upload_id cannot be empty")
	}
	if lease.Owner == "" {
		return false, fmt.Errorf("lease owner cannot be empty")
	}

	query := `
		UPDATE partial_uploads
		SET status = 'processing',
		    processing_owner = $1,
		    lease_expires_at = NOW() + make_interval(secs => $2),
		    assembly_attempts = assembly_attempts + 1,
		    assembly_started_at = NOW(),
		    last_activity = NOW(),
		    error_message = NULL,
		    error_code = NULL,
		    error_retryable = false
		WHERE upload_id = $3 AND status = 'uploading'
	`
	result, err := r.pool.Exec(ctx, query, lease.Owner, lease.TTL.Seconds(), uploadID)
	if err != nil {
		return false, fmt.Errorf("failed to lock upload for processing: %w", err)
	}
	return result.RowsAffected() > 0, nil
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

	query := `
		UPDATE partial_uploads
		SET status = 'processing',
		    processing_owner = $1,
		    lease_expires_at = NOW() + make_interval(secs => $2),
		    assembly_attempts = assembly_attempts + 1,
		    assembly_started_at = NOW(),
		    last_activity = NOW(),
		    error_message = NULL,
		    error_code = NULL,
		    error_retryable = false
		WHERE upload_id = $3 AND status = 'failed' AND error_retryable = true AND assembly_attempts < $4
	`
	result, err := r.pool.Exec(ctx, query, lease.Owner, lease.TTL.Seconds(), uploadID, maxAttempts)
	if err != nil {
		return false, fmt.Errorf("failed to lock failed upload for processing: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

// TakeOverExpiredLease performs the TakeOver transition (processing -> processing).
func (r *PartialUploadRepository) TakeOverExpiredLease(ctx context.Context, uploadID string, lease repository.AssemblyLease, maxAttempts int) (bool, error) {
	if uploadID == "" {
		return false, fmt.Errorf("upload_id cannot be empty")
	}
	if lease.Owner == "" {
		return false, fmt.Errorf("lease owner cannot be empty")
	}

	query := `
		UPDATE partial_uploads
		SET processing_owner = $1,
		    lease_expires_at = NOW() + make_interval(secs => $2),
		    assembly_attempts = assembly_attempts + 1,
		    assembly_started_at = NOW(),
		    last_activity = NOW()
		WHERE upload_id = $3 AND status = 'processing'
		  AND (lease_expires_at IS NULL OR lease_expires_at < NOW())
		  AND assembly_attempts < $4
	`
	result, err := r.pool.Exec(ctx, query, lease.Owner, lease.TTL.Seconds(), uploadID, maxAttempts)
	if err != nil {
		return false, fmt.Errorf("failed to take over expired lease: %w", err)
	}
	return result.RowsAffected() > 0, nil
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
		    error_retryable = false,
		    processing_owner = NULL,
		    lease_expires_at = NULL,
		    last_activity = NOW()
		WHERE upload_id = $1 AND status = 'processing'
		  AND (lease_expires_at IS NULL OR lease_expires_at < NOW())
		  AND assembly_attempts >= $2
	`
	result, err := r.pool.Exec(ctx, query, uploadID, maxAttempts)
	if err != nil {
		return false, fmt.Errorf("failed to exhaust expired lease: %w", err)
	}
	return result.RowsAffected() > 0, nil
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
		SET lease_expires_at = NOW() + make_interval(secs => $1),
		    last_activity = NOW()
		WHERE upload_id = $2 AND status = 'processing' AND processing_owner = $3
	`
	result, err := r.pool.Exec(ctx, query, lease.TTL.Seconds(), uploadID, lease.Owner)
	if err != nil {
		return false, fmt.Errorf("failed to renew assembly lease: %w", err)
	}
	return result.RowsAffected() > 0, nil
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
		SET lease_expires_at = NOW() - INTERVAL '1 second'
		WHERE upload_id = $1 AND status = 'processing' AND processing_owner = $2
	`
	if _, err := r.pool.Exec(ctx, query, uploadID, owner); err != nil {
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
		SET lease_expires_at = NOW() - INTERVAL '1 second',
		    assembly_attempts = CASE WHEN assembly_attempts > 0 THEN assembly_attempts - 1 ELSE 0 END,
		    last_activity = NOW()
		WHERE upload_id = $1 AND status = 'processing' AND processing_owner = $2
	`
	result, err := r.pool.Exec(ctx, query, uploadID, owner)
	if err != nil {
		return false, fmt.Errorf("failed to release processing lock: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

// GetExpiredLeases returns up to limit uploads in "processing" status whose
// lease has expired (or was never set), oldest first.
func (r *PartialUploadRepository) GetExpiredLeases(ctx context.Context, limit int) ([]models.PartialUpload, error) {
	query := `
		SELECT ` + partialUploadColumns + `
		FROM partial_uploads
		WHERE status = 'processing'
		  AND (lease_expires_at IS NULL OR lease_expires_at < NOW())
		ORDER BY COALESCE(lease_expires_at, assembly_started_at, last_activity) ASC
	`
	if limit > 0 {
		query += ` LIMIT $1`
		return r.queryPartialUploads(ctx, query, limit)
	}
	return r.queryPartialUploadsNoArgs(ctx, query)
}

// ExpireAllLeases force-expires every "processing" row's lease. Not required
// for PostgreSQL (multi-process HA relies on the TTL alone), but implemented
// for interface parity / operator-triggered recovery.
func (r *PartialUploadRepository) ExpireAllLeases(ctx context.Context) error {
	query := `UPDATE partial_uploads SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE status = 'processing'`
	if _, err := r.pool.Exec(ctx, query); err != nil {
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

	return withRetryNoReturn(ctx, 3, func() error {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		query := `
			UPDATE partial_uploads
			SET status = 'completed',
			    completed = true,
			    claim_code = $1,
			    assembly_completed_at = NOW(),
			    last_activity = NOW(),
			    processing_owner = NULL,
			    lease_expires_at = NULL
			WHERE upload_id = $2 AND status = 'processing' AND processing_owner = $3
		`
		result, err := tx.Exec(ctx, query, file.ClaimCode, uploadID, owner)
		if err != nil {
			return fmt.Errorf("failed to mark assembly completed: %w", err)
		}
		if result.RowsAffected() == 0 {
			return repository.ErrLeaseLost
		}

		uploadIDCopy := uploadID
		file.PartialUploadID = &uploadIDCopy
		if err := insertFile(ctx, tx, file); err != nil {
			// Only a collision on idx_files_partial_upload_id itself means
			// "this upload was already published by someone else" — a
			// files.claim_code collision here is a different (much rarer)
			// problem and must not be misreported as ErrDuplicateKey
			// (DB-review finding).
			if isFilesPartialUploadIDViolation(err) {
				return repository.ErrDuplicateKey
			}
			return err
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
		return nil
	})
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

	return withRetryNoReturn(ctx, 3, func() error {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		var errorCodeArg interface{}
		if errorCode != "" {
			errorCodeArg = errorCode
		}

		query := `
			UPDATE partial_uploads
			SET status = 'failed',
			    error_message = $1,
			    error_code = $2,
			    error_retryable = $3,
			    processing_owner = NULL,
			    lease_expires_at = NULL,
			    last_activity = NOW()
			WHERE upload_id = $4 AND status = 'processing' AND processing_owner = $5
		`
		result, err := tx.Exec(ctx, query, errorMessage, errorCodeArg, retryable, uploadID, owner)
		if err != nil {
			return fmt.Errorf("failed to set assembly failed: %w", err)
		}
		if result.RowsAffected() == 0 {
			return repository.ErrLeaseLost
		}

		if auditFile != nil {
			uploadIDCopy := uploadID
			auditFile.PartialUploadID = &uploadIDCopy
			if err := insertFile(ctx, tx, auditFile); err != nil {
				// Only a collision on idx_files_partial_upload_id itself
				// means "an audit/file row for this upload already exists"
				// — a files.claim_code collision here is a different (much
				// rarer) problem and must not be misreported as
				// ErrDuplicateKey (DB-review finding).
				if isFilesPartialUploadIDViolation(err) {
					// The whole transaction (including the status='failed'
					// UPDATE above) rolls back, so the row is left
					// "processing" with owner still set to the caller — it
					// did NOT transition to failed. Since owner is the
					// fence, no other attempt can act on it either until
					// this lease expires and recovery takes over. Log
					// distinctly so an operator doesn't mistake this for
					// the caller's FailAssembly having succeeded.
					slog.Error("audit file insert hit a duplicate key during FailAssembly; row left processing for lease-expiry recovery",
						"upload_id", uploadID, "owner", owner, "error", err)
					return repository.ErrDuplicateKey
				}
				return err
			}
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
		return nil
	})
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

	query := `
		DELETE FROM partial_uploads
		WHERE upload_id = $1
		AND completed = false
		AND (
			(status = 'processing' AND COALESCE(lease_expires_at, assembly_started_at, last_activity) < NOW() - INTERVAL '6 hours')
			OR
			((status IS NULL OR status != 'processing') AND last_activity < NOW() - $2 * INTERVAL '1 hour')
		)
	`
	result, err := r.pool.Exec(ctx, query, uploadID, expiryHours)
	if err != nil {
		return false, fmt.Errorf("failed to delete abandoned upload: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

// queryPartialUploads is a helper that executes a query and returns partial uploads.
func (r *PartialUploadRepository) queryPartialUploads(ctx context.Context, query string, arg interface{}) ([]models.PartialUpload, error) {
	rows, err := r.pool.Query(ctx, query, arg)
	if err != nil {
		return nil, fmt.Errorf("failed to query partial uploads: %w", err)
	}
	defer rows.Close()

	return scanPartialUploads(rows)
}

// queryPartialUploadsNoArgs is a helper that executes a query without arguments.
func (r *PartialUploadRepository) queryPartialUploadsNoArgs(ctx context.Context, query string) ([]models.PartialUpload, error) {
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query partial uploads: %w", err)
	}
	defer rows.Close()

	return scanPartialUploads(rows)
}

// partialUploadScanner is implemented by both pgx.Row (from QueryRow) and pgx.Rows.
type partialUploadScanner interface {
	Scan(dest ...interface{}) error
}

// scanPartialUploadRow scans a single row (from QueryRow) into a PartialUpload.
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
	var assemblyStartedAt sql.NullTime
	var assemblyCompletedAt sql.NullTime
	var errorCode sql.NullString
	var processingOwner sql.NullString
	var leaseExpiresAt sql.NullTime
	var uploaderIP sql.NullString
	var errorRetryable sql.NullBool

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
		&upload.CreatedAt,
		&upload.LastActivity,
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
		upload.AssemblyStartedAt = &assemblyStartedAt.Time
	}
	if assemblyCompletedAt.Valid {
		upload.AssemblyCompletedAt = &assemblyCompletedAt.Time
	}
	if errorCode.Valid {
		upload.ErrorCode = &errorCode.String
	}
	if processingOwner.Valid {
		upload.Owner = &processingOwner.String
	}
	if leaseExpiresAt.Valid {
		upload.LeaseExpiresAt = &leaseExpiresAt.Time
	}
	upload.ErrorRetryable = errorRetryable.Valid && errorRetryable.Bool
	if uploaderIP.Valid {
		upload.UploaderIP = uploaderIP.String
	}

	return nil
}

// scanPartialUploads scans rows into partial upload structs.
func scanPartialUploads(rows pgx.Rows) ([]models.PartialUpload, error) {
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

// pgNullableString converts an empty string to SQL NULL for a nullable TEXT
// column (mirrors sqlite's nullableString).
func pgNullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// Ensure PartialUploadRepository implements repository.PartialUploadRepository.
var _ repository.PartialUploadRepository = (*PartialUploadRepository)(nil)
