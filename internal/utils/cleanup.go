package utils

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
)

// StartCleanupWorker starts a background goroutine that periodically
// deletes expired files from the database and filesystem
func StartCleanupWorker(ctx context.Context, db *sql.DB, uploadDir string, intervalMinutes int) {
	ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
	defer ticker.Stop()

	slog.Info("cleanup worker started", "interval_minutes", intervalMinutes)

	// Run cleanup immediately on start
	runCleanup(db, uploadDir)

	for {
		select {
		case <-ctx.Done():
			slog.Info("cleanup worker shutting down")
			return
		case <-ticker.C:
			runCleanup(db, uploadDir)
		}
	}
}

// runCleanup performs the actual cleanup operation
func runCleanup(db *sql.DB, uploadDir string) {
	start := time.Now()
	deleted, err := database.DeleteExpiredFiles(db, uploadDir)
	duration := time.Since(start)

	if err != nil {
		slog.Error("cleanup failed", "error", err, "duration", duration)
		return
	}

	if deleted > 0 {
		slog.Info("cleanup completed", "deleted_files", deleted, "duration", duration)
	} else {
		slog.Debug("cleanup completed", "deleted_files", deleted, "duration", duration)
	}
}

// StartPartialUploadCleanupWorker starts a background goroutine that periodically
// deletes abandoned partial uploads from the database and filesystem
func StartPartialUploadCleanupWorker(ctx context.Context, db *sql.DB, uploadDir string, expiryHours int, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	slog.Info("partial upload cleanup worker started",
		"expiry_hours", expiryHours,
		"interval", interval,
	)

	// Run cleanup immediately on start
	runPartialUploadCleanup(db, uploadDir, expiryHours)

	for {
		select {
		case <-ctx.Done():
			slog.Info("partial upload cleanup worker shutting down")
			return
		case <-ticker.C:
			runPartialUploadCleanup(db, uploadDir, expiryHours)
		}
	}
}

// CleanupResult contains statistics about a cleanup operation
type CleanupResult struct {
	DeletedCount  int
	BytesReclaimed int64
}

// CleanupAbandonedUploads removes abandoned partial uploads and returns statistics
// This function is reusable by both the background worker and API endpoints
func CleanupAbandonedUploads(db *sql.DB, uploadDir string, expiryHours int) (*CleanupResult, error) {
	result := &CleanupResult{
		DeletedCount:  0,
		BytesReclaimed: 0,
	}

	// Get abandoned partial uploads (incomplete uploads that are old)
	abandoned, err := database.GetAbandonedPartialUploads(db, expiryHours)
	if err != nil {
		return nil, err
	}

	// Calculate bytes that will be reclaimed
	for _, upload := range abandoned {
		result.BytesReclaimed += upload.ReceivedBytes
	}

	// Clean up abandoned (incomplete) uploads
	for _, upload := range abandoned {
		// Delete chunks from filesystem
		if err := DeleteChunks(uploadDir, upload.UploadID); err != nil {
			slog.Error("failed to delete chunks",
				"upload_id", upload.UploadID,
				"error", err,
			)
			continue // Continue with other uploads
		}

		// Delete partial upload record from database
		if err := database.DeletePartialUpload(db, upload.UploadID); err != nil {
			slog.Error("failed to delete partial upload record",
				"upload_id", upload.UploadID,
				"error", err,
			)
			continue
		}

		slog.Info("cleaned up abandoned partial upload",
			"upload_id", upload.UploadID,
			"filename", upload.Filename,
			"chunks_received", upload.ChunksReceived,
			"total_chunks", upload.TotalChunks,
			"last_activity", upload.LastActivity,
		)

		result.DeletedCount++
	}

	// Clean up empty partial upload directories
	if err := CleanupPartialUploadsDir(uploadDir); err != nil {
		slog.Error("failed to cleanup partial uploads directory", "error", err)
	}

	return result, nil
}

// runPartialUploadCleanup performs the actual partial upload cleanup operation
func runPartialUploadCleanup(db *sql.DB, uploadDir string, expiryHours int) {
	start := time.Now()

	// Clean up abandoned uploads using reusable function
	result, err := CleanupAbandonedUploads(db, uploadDir, expiryHours)
	if err != nil {
		slog.Error("failed to cleanup abandoned uploads", "error", err)
		return
	}

	// Get completed uploads older than 1 hour (for idempotency cleanup)
	completed, err := database.GetOldCompletedUploads(db, 1) // 1 hour retention for idempotency
	if err != nil {
		slog.Error("failed to get old completed uploads", "error", err)
		// Continue even if this fails
		completed = []models.PartialUpload{}
	}

	// Clean up completed uploads (older than 1 hour, kept for idempotency)
	completedCount := 0
	for _, upload := range completed {
		// Chunks should already be deleted, but check anyway
		if err := DeleteChunks(uploadDir, upload.UploadID); err != nil {
			// Chunks likely already deleted during completion, ignore error
			slog.Debug("chunks already deleted", "upload_id", upload.UploadID)
		}

		// Delete partial upload record from database
		if err := database.DeletePartialUpload(db, upload.UploadID); err != nil {
			slog.Error("failed to delete completed upload record",
				"upload_id", upload.UploadID,
				"error", err,
			)
			continue
		}

		slog.Debug("cleaned up old completed upload",
			"upload_id", upload.UploadID,
			"filename", upload.Filename,
			"claim_code", upload.ClaimCode,
		)

		completedCount++
	}

	duration := time.Since(start)
	totalDeleted := result.DeletedCount + completedCount

	if totalDeleted > 0 {
		slog.Info("partial upload cleanup completed",
			"deleted", totalDeleted,
			"abandoned", result.DeletedCount,
			"completed", completedCount,
			"bytes_reclaimed", result.BytesReclaimed,
			"duration", duration,
		)
	} else {
		slog.Debug("partial upload cleanup completed",
			"deleted", 0,
			"duration", duration,
		)
	}
}
