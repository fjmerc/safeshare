package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// CreatePartialUpload creates a new partial upload record
func CreatePartialUpload(db *sql.DB, upload *models.PartialUpload) error {
	query := `
		INSERT INTO partial_uploads (
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := db.Exec(query,
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
	)

	if err != nil {
		return fmt.Errorf("failed to create partial upload: %w", err)
	}

	return nil
}

// GetPartialUpload retrieves a partial upload by upload_id
func GetPartialUpload(db *sql.DB, uploadID string) (*models.PartialUpload, error) {
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
	var assemblyStartedAt sql.NullTime
	var assemblyCompletedAt sql.NullTime

	err := db.QueryRow(query, uploadID).Scan(
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

	if err == sql.ErrNoRows {
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
		upload.Status = "uploading" // Default for old records
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

// UpdatePartialUploadActivity updates the last_activity timestamp
func UpdatePartialUploadActivity(db *sql.DB, uploadID string) error {
	query := `UPDATE partial_uploads SET last_activity = ? WHERE upload_id = ?`

	_, err := db.Exec(query, time.Now(), uploadID)
	if err != nil {
		return fmt.Errorf("failed to update partial upload activity: %w", err)
	}

	return nil
}

// IncrementChunksReceived increments chunks_received and received_bytes
func IncrementChunksReceived(db *sql.DB, uploadID string, chunkBytes int64) error {
	query := `
		UPDATE partial_uploads
		SET chunks_received = chunks_received + 1,
		    received_bytes = received_bytes + ?,
		    last_activity = ?
		WHERE upload_id = ?
	`

	_, err := db.Exec(query, chunkBytes, time.Now(), uploadID)
	if err != nil {
		return fmt.Errorf("failed to increment chunks received: %w", err)
	}

	return nil
}

// MarkPartialUploadCompleted marks a partial upload as completed and sets the claim code
func MarkPartialUploadCompleted(db *sql.DB, uploadID, claimCode string) error {
	query := `
		UPDATE partial_uploads
		SET completed = 1, claim_code = ?, last_activity = ?
		WHERE upload_id = ?
	`

	_, err := db.Exec(query, claimCode, time.Now(), uploadID)
	if err != nil {
		return fmt.Errorf("failed to mark partial upload as completed: %w", err)
	}

	return nil
}

// DeletePartialUpload deletes a partial upload record
func DeletePartialUpload(db *sql.DB, uploadID string) error {
	query := `DELETE FROM partial_uploads WHERE upload_id = ?`

	_, err := db.Exec(query, uploadID)
	if err != nil {
		return fmt.Errorf("failed to delete partial upload: %w", err)
	}

	return nil
}

// GetAbandonedPartialUploads returns partial uploads that haven't been active for the specified hours
// and are not completed or currently processing
func GetAbandonedPartialUploads(db *sql.DB, expiryHours int) ([]models.PartialUpload, error) {
	query := `
		SELECT
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code,
			status, error_message, assembly_started_at, assembly_completed_at
		FROM partial_uploads
		WHERE completed = 0
		AND status != 'processing'
		AND datetime(last_activity) < datetime('now', '-' || ? || ' hours')
		ORDER BY last_activity ASC
	`

	rows, err := db.Query(query, expiryHours)
	if err != nil {
		return nil, fmt.Errorf("failed to get abandoned partial uploads: %w", err)
	}
	defer rows.Close()

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

// GetOldCompletedUploads returns completed uploads older than the specified hours
// These are kept for idempotency (duplicate completion requests) and cleaned up after retention period
func GetOldCompletedUploads(db *sql.DB, retentionHours int) ([]models.PartialUpload, error) {
	query := `
		SELECT
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code
		FROM partial_uploads
		WHERE completed = 1
		AND datetime(last_activity) < datetime('now', '-' || ? || ' hours')
		ORDER BY last_activity ASC
	`

	rows, err := db.Query(query, retentionHours)
	if err != nil {
		return nil, fmt.Errorf("failed to get old completed uploads: %w", err)
	}
	defer rows.Close()

	var uploads []models.PartialUpload
	for rows.Next() {
		var upload models.PartialUpload
		var userID sql.NullInt64
		var claimCode sql.NullString

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
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan completed upload: %w", err)
		}

		// Handle nullable fields
		if userID.Valid {
			upload.UserID = &userID.Int64
		}

		if claimCode.Valid {
			upload.ClaimCode = &claimCode.String
		}

		uploads = append(uploads, upload)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating completed uploads: %w", err)
	}

	return uploads, nil
}

// GetPartialUploadsByUserID returns all partial uploads for a specific user
func GetPartialUploadsByUserID(db *sql.DB, userID int64) ([]models.PartialUpload, error) {
	query := `
		SELECT
			upload_id, user_id, filename, total_size, chunk_size, total_chunks,
			chunks_received, received_bytes, expires_in_hours, max_downloads,
			password_hash, created_at, last_activity, completed, claim_code
		FROM partial_uploads
		WHERE user_id = ?
		ORDER BY created_at DESC
	`

	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get partial uploads by user: %w", err)
	}
	defer rows.Close()

	var uploads []models.PartialUpload
	for rows.Next() {
		var upload models.PartialUpload
		var userIDVal sql.NullInt64
		var claimCode sql.NullString

		err := rows.Scan(
			&upload.UploadID,
			&userIDVal,
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
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan partial upload: %w", err)
		}

		// Handle nullable fields
		if userIDVal.Valid {
			upload.UserID = &userIDVal.Int64
		}

		if claimCode.Valid {
			upload.ClaimCode = &claimCode.String
		}

		uploads = append(uploads, upload)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating partial uploads: %w", err)
	}

	return uploads, nil
}

// GetTotalPartialUploadUsage returns the total bytes used by partial uploads (for quota tracking)
func GetTotalPartialUploadUsage(db *sql.DB) (int64, error) {
	query := `SELECT COALESCE(SUM(received_bytes), 0) FROM partial_uploads WHERE completed = 0`

	var total int64
	err := db.QueryRow(query).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("failed to get total partial upload usage: %w", err)
	}

	return total, nil
}

// GetIncompletePartialUploadsCount returns the count of incomplete partial upload sessions
func GetIncompletePartialUploadsCount(db *sql.DB) (int, error) {
	query := `SELECT COUNT(*) FROM partial_uploads WHERE completed = 0`

	var count int
	err := db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get partial uploads count: %w", err)
	}

	return count, nil
}

// UpdatePartialUploadStatus updates the status and error_message (if provided)
func UpdatePartialUploadStatus(db *sql.DB, uploadID, status string, errorMessage *string) error {
	query := `UPDATE partial_uploads SET status = ?, error_message = ?, last_activity = ? WHERE upload_id = ?`

	_, err := db.Exec(query, status, errorMessage, time.Now(), uploadID)
	if err != nil {
		return fmt.Errorf("failed to update partial upload status: %w", err)
	}

	return nil
}

// SetAssemblyStarted marks assembly as started
func SetAssemblyStarted(db *sql.DB, uploadID string) error {
	now := time.Now()
	query := `UPDATE partial_uploads SET status = 'processing', assembly_started_at = ?, last_activity = ? WHERE upload_id = ?`

	_, err := db.Exec(query, now, now, uploadID)
	if err != nil {
		return fmt.Errorf("failed to set assembly started: %w", err)
	}

	return nil
}

// SetAssemblyCompleted marks assembly as completed with claim code
func SetAssemblyCompleted(db *sql.DB, uploadID, claimCode string) error {
	now := time.Now()
	query := `
		UPDATE partial_uploads
		SET status = 'completed', completed = 1, claim_code = ?,
		    assembly_completed_at = ?, last_activity = ?
		WHERE upload_id = ?
	`

	_, err := db.Exec(query, claimCode, now, now, uploadID)
	if err != nil {
		return fmt.Errorf("failed to set assembly completed: %w", err)
	}

	return nil
}

// SetAssemblyFailed marks assembly as failed with error message
func SetAssemblyFailed(db *sql.DB, uploadID, errorMessage string) error {
	now := time.Now()
	query := `
		UPDATE partial_uploads
		SET status = 'failed', error_message = ?, last_activity = ?
		WHERE upload_id = ?
	`

	_, err := db.Exec(query, errorMessage, now, uploadID)
	if err != nil {
		return fmt.Errorf("failed to set assembly failed: %w", err)
	}

	return nil
}

// GetProcessingUploads returns all uploads currently in "processing" status
// Used by startup recovery worker to resume interrupted assemblies
func GetProcessingUploads(db *sql.DB) ([]models.PartialUpload, error) {
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

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get processing uploads: %w", err)
	}
	defer rows.Close()

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
			return nil, fmt.Errorf("failed to scan processing upload: %w", err)
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
		return nil, fmt.Errorf("error iterating processing uploads: %w", err)
	}

	return uploads, nil
}

// TryLockUploadForProcessing attempts to atomically transition upload from "uploading" to "processing"
// Returns true if successful (lock acquired), false if already locked by another process
func TryLockUploadForProcessing(db *sql.DB, uploadID string) (bool, error) {
	now := time.Now()
	query := `
		UPDATE partial_uploads
		SET status = 'processing', assembly_started_at = ?, last_activity = ?
		WHERE upload_id = ? AND status = 'uploading'
	`

	result, err := db.Exec(query, now, now, uploadID)
	if err != nil {
		return false, fmt.Errorf("failed to lock upload for processing: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}
