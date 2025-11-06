package utils

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
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

// runPartialUploadCleanup performs the actual partial upload cleanup operation
func runPartialUploadCleanup(db *sql.DB, uploadDir string, expiryHours int) {
	start := time.Now()

	// Get abandoned partial uploads
	abandoned, err := database.GetAbandonedPartialUploads(db, expiryHours)
	if err != nil {
		slog.Error("failed to get abandoned partial uploads", "error", err)
		return
	}

	if len(abandoned) == 0 {
		slog.Debug("partial upload cleanup completed", "deleted", 0, "duration", time.Since(start))
		return
	}

	deleted := 0
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

		deleted++
	}

	// Clean up empty partial upload directories
	if err := CleanupPartialUploadsDir(uploadDir); err != nil {
		slog.Error("failed to cleanup partial uploads directory", "error", err)
	}

	duration := time.Since(start)
	if deleted > 0 {
		slog.Info("partial upload cleanup completed",
			"deleted", deleted,
			"duration", duration,
		)
	} else {
		slog.Debug("partial upload cleanup completed",
			"deleted", deleted,
			"duration", duration,
		)
	}
}
