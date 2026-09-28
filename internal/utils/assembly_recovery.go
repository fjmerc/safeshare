package utils

import (
	"context"
	"log/slog"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// AssemblyRecoverer attempts to recover one "processing" upload whose lease
// has expired: either take over the assembly (spawning a new attempt) or,
// if it has exhausted its retry budget, mark it terminally failed. Returns
// true if a new assembly attempt was actually started.
//
// Implemented as handlers.RecoverAssembly; declared here as a func type
// (rather than importing the handlers package directly) to avoid an
// import cycle — handlers already imports utils.
type AssemblyRecoverer func(ctx context.Context, upload models.PartialUpload) bool

// StartAssemblyRecoveryWorker runs recover against every "processing" upload
// whose lease has expired, once immediately on startup and then on a tick of
// max(leaseTTL/2, 15s) — frequent enough that a crashed or stalled worker's
// row is picked back up well within its own lease TTL, replacing the old
// flat 1-hour-since-assembly_started_at threshold (ADR-016 / T21).
func StartAssemblyRecoveryWorker(ctx context.Context, repos *repository.Repositories, leaseTTL time.Duration, limit int, recoverFn AssemblyRecoverer) {
	tick := leaseTTL / 2
	if tick < 15*time.Second {
		tick = 15 * time.Second
	}

	slog.Info("running assembly recovery on startup", "tick", tick)
	runAssemblyRecovery(repos, limit, recoverFn)

	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("assembly recovery worker stopped")
			return
		case <-ticker.C:
			runAssemblyRecovery(repos, limit, recoverFn)
		}
	}
}

// runAssemblyRecovery finds uploads whose assembly lease has expired and
// hands each to recoverFn.
func runAssemblyRecovery(repos *repository.Repositories, limit int, recoverFn AssemblyRecoverer) {
	ctx := context.Background()

	expired, err := repos.PartialUploads.GetExpiredLeases(ctx, limit)
	if err != nil {
		slog.Error("failed to get expired assembly leases for recovery", "error", err)
		return
	}

	if len(expired) == 0 {
		slog.Debug("no expired assembly leases found")
		return
	}

	slog.Info("found expired assembly leases", "count", len(expired))

	for _, upload := range expired {
		recoverOne(ctx, upload, recoverFn)
	}
}

// recoverOne runs recoverFn for a single upload with panic recovery, so one
// bad row can't take down the whole recovery sweep.
func recoverOne(ctx context.Context, upload models.PartialUpload, recoverFn AssemblyRecoverer) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("assembly recovery panic recovered", "upload_id", upload.UploadID, "panic", r)
		}
	}()
	if !recoverFn(ctx, upload) {
		slog.Debug("assembly recovery did not start a new attempt", "upload_id", upload.UploadID)
	}
}
