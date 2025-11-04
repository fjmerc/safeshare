package utils

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/yourusername/safeshare/internal/database"
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
