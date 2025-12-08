// Package postgres provides PostgreSQL implementations of repository interfaces.
package postgres

import (
	"context"
	"database/sql"
	"fmt"

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
			password_hash, created_at, last_activity, completed, claim_code, status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
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
		defer tx.Rollback(ctx)

		// Check quota within transaction
		var currentUsage int64
		query := `
			SELECT
				COALESCE(SUM(file_size), 0) +
				COALESCE((SELECT SUM(total_size) FROM partial_uploads WHERE completed = false), 0)
			FROM files
			WHERE expires_at > NOW()
		`
		if err := tx.QueryRow(ctx, query).Scan(&currentUsage); err != nil {
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
				password_hash, created_at, last_activity, completed, claim_code, status
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
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

	query := `
		SELECT
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code,
			status, error_message, assembly_started_at, assembly_completed_at
		FROM partial_uploads
		WHERE upload_id = $1
	`

	upload := &models.PartialUpload{}
	var userID sql.NullInt64
	var claimCode sql.NullString
	var status sql.NullString
	var errorMessage sql.NullString
	var assemblyStartedAt sql.NullTime
	var assemblyCompletedAt sql.NullTime

	err := r.pool.QueryRow(ctx, query, uploadID).Scan(
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
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get partial upload: %w", err)
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
		upload.AssemblyStartedAt = &assemblyStartedAt.Time
	}
	if assemblyCompletedAt.Valid {
		upload.AssemblyCompletedAt = &assemblyCompletedAt.Time
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
		SET completed = true, claim_code = $1, last_activity = NOW()
		WHERE upload_id = $2
	`

	_, err := r.pool.Exec(ctx, query, claimCode, uploadID)
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

	query := `DELETE FROM partial_uploads WHERE upload_id = $1`

	_, err := r.pool.Exec(ctx, query, uploadID)
	if err != nil {
		return fmt.Errorf("failed to delete partial upload: %w", err)
	}

	return nil
}

// GetAbandoned returns partial uploads that haven't been active for the specified hours.
func (r *PartialUploadRepository) GetAbandoned(ctx context.Context, expiryHours int) ([]models.PartialUpload, error) {
	if expiryHours < 0 {
		return nil, fmt.Errorf("expiry hours cannot be negative")
	}

	query := `
		SELECT
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code,
			status, error_message, assembly_started_at, assembly_completed_at
		FROM partial_uploads
		WHERE completed = false
		AND (
			-- Stuck processing uploads (assembly timeout: 6 hours)
			(status = 'processing' AND assembly_started_at IS NOT NULL AND assembly_started_at < NOW() - INTERVAL '6 hours')
			OR
			-- Regular abandoned uploads (not processing)
			((status IS NULL OR status != 'processing') AND last_activity < NOW() - $1 * INTERVAL '1 hour')
		)
		ORDER BY last_activity ASC
	`

	return r.queryPartialUploads(ctx, query, expiryHours)
}

// GetOldCompleted returns completed uploads older than the specified hours.
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
		WHERE completed = true
		AND last_activity < NOW() - $1 * INTERVAL '1 hour'
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

// SetAssemblyStarted marks assembly as started.
func (r *PartialUploadRepository) SetAssemblyStarted(ctx context.Context, uploadID string) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}

	query := `UPDATE partial_uploads SET status = 'processing', assembly_started_at = NOW(), last_activity = NOW() WHERE upload_id = $1`

	_, err := r.pool.Exec(ctx, query, uploadID)
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

	query := `
		UPDATE partial_uploads
		SET status = 'completed', completed = true, claim_code = $1,
		    assembly_completed_at = NOW(), last_activity = NOW()
		WHERE upload_id = $2
	`

	_, err := r.pool.Exec(ctx, query, claimCode, uploadID)
	if err != nil {
		return fmt.Errorf("failed to set assembly completed: %w", err)
	}

	return nil
}

// SetAssemblyFailed marks assembly as failed with error message.
func (r *PartialUploadRepository) SetAssemblyFailed(ctx context.Context, uploadID, errorMessage string) error {
	if uploadID == "" {
		return fmt.Errorf("upload_id cannot be empty")
	}

	query := `
		UPDATE partial_uploads
		SET status = 'failed', error_message = $1, last_activity = NOW()
		WHERE upload_id = $2
	`

	return withRetryNoReturn(ctx, 3, func() error {
		_, err := r.pool.Exec(ctx, query, errorMessage, uploadID)
		if err != nil {
			return fmt.Errorf("failed to set assembly failed: %w", err)
		}
		return nil
	})
}

// GetProcessing returns all uploads currently in "processing" status.
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
func (r *PartialUploadRepository) TryLockForProcessing(ctx context.Context, uploadID string) (bool, error) {
	if uploadID == "" {
		return false, fmt.Errorf("upload_id cannot be empty")
	}

	query := `
		UPDATE partial_uploads
		SET status = 'processing', assembly_started_at = NOW(), last_activity = NOW()
		WHERE upload_id = $1 AND status = 'uploading'
	`

	result, err := r.pool.Exec(ctx, query, uploadID)
	if err != nil {
		return false, fmt.Errorf("failed to lock upload for processing: %w", err)
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

	return r.scanPartialUploads(rows)
}

// queryPartialUploadsNoArgs is a helper that executes a query without arguments.
func (r *PartialUploadRepository) queryPartialUploadsNoArgs(ctx context.Context, query string) ([]models.PartialUpload, error) {
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query partial uploads: %w", err)
	}
	defer rows.Close()

	return r.scanPartialUploads(rows)
}

// scanPartialUploads scans rows into partial upload structs.
func (r *PartialUploadRepository) scanPartialUploads(rows pgx.Rows) ([]models.PartialUpload, error) {
	var uploads []models.PartialUpload
	for rows.Next() {
		var upload models.PartialUpload
		var userID sql.NullInt64
		var claimCode sql.NullString
		var status sql.NullString
		var errorMessage sql.NullString
		var assemblyStartedAt sql.NullTime
		var assemblyCompletedAt sql.NullTime

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
			&upload.CreatedAt,
			&upload.LastActivity,
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
			upload.AssemblyStartedAt = &assemblyStartedAt.Time
		}
		if assemblyCompletedAt.Valid {
			upload.AssemblyCompletedAt = &assemblyCompletedAt.Time
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
