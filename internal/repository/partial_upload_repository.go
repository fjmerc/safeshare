package repository

import (
	"context"

	"github.com/fjmerc/safeshare/internal/models"
)

// PartialUploadRepository defines the interface for partial upload (chunked upload) database operations.
// All methods accept a context for cancellation and timeout support.
type PartialUploadRepository interface {
	// Create inserts a new partial upload record.
	Create(ctx context.Context, upload *models.PartialUpload) error

	// CreateWithQuotaCheck atomically checks quota and creates a partial upload record.
	// Returns ErrQuotaExceeded if adding the upload would exceed the quota limit.
	// This prevents race conditions where multiple uploads could exceed quota.
	CreateWithQuotaCheck(ctx context.Context, upload *models.PartialUpload, quotaLimitBytes int64) error

	// GetByUploadID retrieves a partial upload by upload_id.
	// Returns nil, nil if not found.
	GetByUploadID(ctx context.Context, uploadID string) (*models.PartialUpload, error)

	// Exists checks if a partial upload record exists in the database.
	Exists(ctx context.Context, uploadID string) (bool, error)

	// UpdateActivity updates the last_activity timestamp.
	UpdateActivity(ctx context.Context, uploadID string) error

	// IncrementChunksReceived increments chunks_received and received_bytes.
	IncrementChunksReceived(ctx context.Context, uploadID string, chunkBytes int64) error

	// MarkCompleted marks a partial upload as completed and sets the claim code.
	MarkCompleted(ctx context.Context, uploadID, claimCode string) error

	// Delete removes a partial upload record.
	Delete(ctx context.Context, uploadID string) error

	// GetAbandoned returns partial uploads that haven't been active for the specified hours
	// and are not completed. Includes stuck processing uploads that exceed timeout.
	GetAbandoned(ctx context.Context, expiryHours int) ([]models.PartialUpload, error)

	// GetOldCompleted returns completed uploads older than the specified hours.
	// These are kept for idempotency and cleaned up after retention period.
	GetOldCompleted(ctx context.Context, retentionHours int) ([]models.PartialUpload, error)

	// GetByUserID returns all partial uploads for a specific user.
	GetByUserID(ctx context.Context, userID int64) ([]models.PartialUpload, error)

	// GetTotalUsage returns the total bytes used by active (incomplete) partial uploads.
	GetTotalUsage(ctx context.Context) (int64, error)

	// GetIncompleteCount returns the count of incomplete partial upload sessions.
	GetIncompleteCount(ctx context.Context) (int, error)

	// GetAllUploadIDs returns all upload_ids currently in the database as a set.
	// This is optimized for orphaned chunk detection to avoid N+1 queries.
	GetAllUploadIDs(ctx context.Context) (map[string]bool, error)

	// Assembly status operations

	// UpdateStatus updates the status and error_message (if provided).
	UpdateStatus(ctx context.Context, uploadID, status string, errorMessage *string) error

	// SetAssemblyStarted marks assembly as started.
	SetAssemblyStarted(ctx context.Context, uploadID string) error

	// SetAssemblyCompleted marks assembly as completed with claim code.
	SetAssemblyCompleted(ctx context.Context, uploadID, claimCode string) error

	// SetAssemblyFailed marks assembly as failed with error message.
	SetAssemblyFailed(ctx context.Context, uploadID, errorMessage string) error

	// GetProcessing returns all uploads currently in "processing" status.
	// Used by startup recovery worker to resume interrupted assemblies.
	GetProcessing(ctx context.Context) ([]models.PartialUpload, error)

	// TryLockForProcessing attempts to atomically transition upload from "uploading" to "processing".
	// Returns true if successful (lock acquired), false if already locked by another process.
	TryLockForProcessing(ctx context.Context, uploadID string) (bool, error)
}
