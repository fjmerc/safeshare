package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/yourusername/safeshare/internal/config"
	"github.com/yourusername/safeshare/internal/database"
	"github.com/yourusername/safeshare/internal/models"
)

// HealthHandler handles health check requests
func HealthHandler(db *sql.DB, cfg *config.Config, startTime time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept GET requests
		if r.Method != http.MethodGet {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Calculate uptime
		uptime := time.Since(startTime)

		// Get storage statistics
		totalFiles, storageUsed, err := database.GetStats(db, cfg.UploadDir)
		if err != nil {
			slog.Error("failed to get stats", "error", err)
			// Don't fail the health check, just use zero values
			totalFiles = 0
			storageUsed = 0
		}

		// Build response
		response := models.HealthResponse{
			Status:           "healthy",
			UptimeSeconds:    int64(uptime.Seconds()),
			TotalFiles:       totalFiles,
			StorageUsedBytes: storageUsed,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}
