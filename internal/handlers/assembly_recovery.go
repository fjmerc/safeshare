package handlers

import (
	"context"
	"log/slog"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/google/uuid"
)

// NewAssemblyRecoverer returns a utils.AssemblyRecoverer bound to repos/cfg.
// Defined in the handlers package (rather than utils) because recovering an
// assembly means running the same pipeline as a normal /complete-triggered
// assembly (launchAssembly/runAssembly), which live here; utils declares
// only the AssemblyRecoverer func type to avoid an import cycle.
func NewAssemblyRecoverer(repos *repository.Repositories, cfg *config.Config) utils.AssemblyRecoverer {
	return func(ctx context.Context, upload models.PartialUpload) bool {
		return RecoverAssembly(ctx, repos, cfg, upload)
	}
}

// RecoverAssembly attempts to take over one "processing" upload whose lease
// has expired (ADR-016). If the upload has already exhausted its retry
// budget, it's marked terminally failed (ASSEMBLY_RETRIES_EXHAUSTED)
// instead. Returns true if a new assembly attempt was spawned.
//
// Mirrors UploadCompleteHandler's SH-1.4 acquisition order (semaphore slot,
// then tracker registration, releasing both symmetrically on every early
// return) so recovery can never leak a slot or leave the tracker's
// WaitGroup permanently incremented.
func RecoverAssembly(ctx context.Context, repos *repository.Repositories, cfg *config.Config, upload models.PartialUpload) bool {
	tracker := utils.GetUploadTracker()
	if tracker.IsShuttingDown() {
		return false
	}

	maxAttempts := utils.ResolveAssemblyMaxAttempts()

	if upload.AssemblyAttempts >= maxAttempts {
		ok, err := repos.PartialUploads.ExhaustExpiredLease(ctx, upload.UploadID, maxAttempts)
		if err != nil {
			slog.Error("failed to exhaust expired assembly lease", "error", err, "upload_id", upload.UploadID)
		} else if ok {
			slog.Warn("assembly retries exhausted; marking terminally failed",
				"upload_id", upload.UploadID, "attempts", upload.AssemblyAttempts, "max_attempts", maxAttempts)
		}
		return false
	}

	// SH-1.4-style non-blocking acquire: recovery is a background sweep, not
	// a client request, so it simply skips this upload for this tick rather
	// than blocking or erroring — the next tick (or a client's own
	// /complete retry) will pick it up.
	semCh := *currentAssemblySemaphore()
	select {
	case semCh <- struct{}{}:
	default:
		slog.Debug("assembly recovery: worker pool saturated, deferring to next tick", "upload_id", upload.UploadID)
		return false
	}
	slotHandedOff := false
	defer func() {
		if !slotHandedOff {
			<-semCh
		}
	}()

	owner := utils.GetOwnerID() + "/" + uuid.New().String()
	lease := repository.AssemblyLease{Owner: owner, TTL: utils.ResolveAssemblyLeaseTTL()}

	took, err := repos.PartialUploads.TakeOverExpiredLease(ctx, upload.UploadID, lease, maxAttempts)
	if err != nil {
		slog.Error("failed to take over expired assembly lease", "error", err, "upload_id", upload.UploadID)
		return false
	}
	if !took {
		// Someone else won first: a live worker's heartbeat renewed the
		// lease just before we tried, another recovery tick took over, or a
		// concurrent /complete request reopened/relocked it.
		return false
	}

	if !tracker.StartAssembly(upload.UploadID) {
		// ADR-016 bug-hunter finding L2: this must NOT revert status to
		// 'uploading' — the row came from another 'processing' row via
		// TakeOverExpiredLease, so reverting it out of 'processing' would
		// strand it somewhere the recovery sweep never looks again.
		// ReleaseProcessingLock instead keeps status='processing' and just
		// force-expires the lease (decrementing assembly_attempts to undo
		// the increment TakeOverExpiredLease just made), so the very next
		// sweep tick immediately retries the takeover.
		if _, err := repos.PartialUploads.ReleaseProcessingLock(ctx, upload.UploadID, owner); err != nil {
			slog.Warn("failed to release processing lock on recovery shutdown race", "upload_id", upload.UploadID, "error", err)
		}
		return false
	}

	uploadCopy := upload
	uploadCopy.Owner = &owner
	uploadCopy.AssemblyAttempts++ // reflect the increment TakeOverExpiredLease just made

	slog.Info("recovering interrupted/stalled assembly",
		"upload_id", upload.UploadID,
		"filename", logFilename(upload.Filename, cfg),
		"attempt", uploadCopy.AssemblyAttempts,
		"max_attempts", maxAttempts,
	)

	slotHandedOff = true
	launchAssembly(repos, cfg, &uploadCopy, lease, semCh)
	return true
}
