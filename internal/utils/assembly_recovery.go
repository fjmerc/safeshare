package utils

import (
	"context"
	"log/slog"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// AssemblyWorkerFunc is the type signature for the async assembly function
type AssemblyWorkerFunc func(*repository.Repositories, *config.Config, *models.PartialUpload, string)

// StartAssemblyRecoveryWorker starts a background worker that recovers interrupted assemblies on startup
// and periodically checks for stuck processing uploads
func StartAssemblyRecoveryWorker(ctx context.Context, repos *repository.Repositories, cfg *config.Config, assemblyFunc AssemblyWorkerFunc) {
	// Run recovery immediately on startup
	slog.Info("running assembly recovery on startup")
	recoverInterruptedAssemblies(repos, cfg, assemblyFunc)

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
			recoverInterruptedAssemblies(repos, cfg, assemblyFunc)
		}
	}
}

// recoverInterruptedAssemblies finds and resumes any uploads stuck in "processing" status
func recoverInterruptedAssemblies(repos *repository.Repositories, cfg *config.Config, assemblyFunc AssemblyWorkerFunc) {
	ctx := context.Background()

	// Get all uploads in "processing" status
	processingUploads, err := repos.PartialUploads.GetProcessing(ctx)
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
		// Check if upload has been stuck for more than 1 hour (likely crashed)
		// Note: Normal assemblies should complete faster; 1 hour threshold is conservative
		if upload.AssemblyStartedAt != nil {
			timeSinceStart := time.Since(*upload.AssemblyStartedAt)
			if timeSinceStart < 1*time.Hour {
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
		if err := repos.PartialUploads.UpdateStatus(ctx, upload.UploadID, "uploading", nil); err != nil {
			slog.Error("failed to reset upload status", "error", err, "upload_id", upload.UploadID)
			continue
		}

		// Try to lock and process
		locked, err := repos.PartialUploads.TryLockForProcessing(ctx, upload.UploadID)
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
		go assemblyFunc(repos, cfg, &uploadCopy, "recovery-worker")
	}
}
