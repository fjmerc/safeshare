package utils

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
)

// AssemblyWorkerFunc is the type signature for the async assembly function
type AssemblyWorkerFunc func(*sql.DB, *config.Config, *models.PartialUpload, string)

// StartAssemblyRecoveryWorker starts a background worker that recovers interrupted assemblies on startup
// and periodically checks for stuck processing uploads
func StartAssemblyRecoveryWorker(ctx context.Context, db *sql.DB, cfg *config.Config, assemblyFunc AssemblyWorkerFunc) {
	// Run recovery immediately on startup
	slog.Info("running assembly recovery on startup")
	recoverInterruptedAssemblies(db, cfg, assemblyFunc)

	// Then run periodically every 10 minutes
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("assembly recovery worker stopped")
			return
		case <-ticker.C:
			slog.Debug("running periodic assembly recovery check")
			recoverInterruptedAssemblies(db, cfg, assemblyFunc)
		}
	}
}

// recoverInterruptedAssemblies finds and resumes any uploads stuck in "processing" status
func recoverInterruptedAssemblies(db *sql.DB, cfg *config.Config, assemblyFunc AssemblyWorkerFunc) {
	// Get all uploads in "processing" status
	processingUploads, err := database.GetProcessingUploads(db)
	if err != nil {
		slog.Error("failed to get processing uploads for recovery", "error", err)
		return
	}

	if len(processingUploads) == 0 {
		slog.Debug("no interrupted assemblies found")
		return
	}

	slog.Info("found interrupted assemblies",
		"count", len(processingUploads),
	)

	// Resume each interrupted assembly
	for _, upload := range processingUploads {
		// Check if upload has been stuck for more than 30 minutes (likely crashed)
		if upload.AssemblyStartedAt != nil {
			timeSinceStart := time.Since(*upload.AssemblyStartedAt)
			if timeSinceStart < 30*time.Minute {
				// Skip - assembly is probably still in progress
				slog.Debug("skipping recent processing upload",
					"upload_id", upload.UploadID,
					"time_since_start", timeSinceStart,
				)
				continue
			}
		}

		slog.Info("resuming interrupted assembly",
			"upload_id", upload.UploadID,
			"filename", upload.Filename,
			"total_chunks", upload.TotalChunks,
		)

		// Reset status back to "uploading" so the assembly worker can re-lock it
		if err := database.UpdatePartialUploadStatus(db, upload.UploadID, "uploading", nil); err != nil {
			slog.Error("failed to reset upload status", "error", err, "upload_id", upload.UploadID)
			continue
		}

		// Try to lock and process
		locked, err := database.TryLockUploadForProcessing(db, upload.UploadID)
		if err != nil {
			slog.Error("failed to lock upload for recovery", "error", err, "upload_id", upload.UploadID)
			continue
		}

		if !locked {
			slog.Warn("failed to acquire lock for recovery", "upload_id", upload.UploadID)
			continue
		}

		// Spawn goroutine to resume assembly
		// Note: Using "recovery-worker" as client_ip since this is a recovery operation
		uploadCopy := upload
		go assemblyFunc(db, cfg, &uploadCopy, "recovery-worker")
	}
}
