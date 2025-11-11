package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
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

		// Include partial uploads in storage calculation
		partialUploadsSize, err := utils.GetPartialUploadsSize(cfg.UploadDir)
		if err != nil {
			slog.Error("failed to get partial uploads size", "error", err)
			partialUploadsSize = 0
		}
		totalStorageUsed := storageUsed + partialUploadsSize

		// Get disk space information
		diskInfo, err := utils.GetDiskSpace(cfg.UploadDir)
		if err != nil {
			slog.Error("failed to get disk space", "error", err)
			// Don't fail the health check, just omit disk info
		}

		// Build response
		response := models.HealthResponse{
			Status:           "healthy",
			UptimeSeconds:    int64(uptime.Seconds()),
			TotalFiles:       totalFiles,
			StorageUsedBytes: totalStorageUsed,
		}

		// Add disk space info if available
		if diskInfo != nil {
			response.DiskTotalBytes = diskInfo.TotalBytes
			response.DiskFreeBytes = diskInfo.FreeBytes
			response.DiskAvailableBytes = diskInfo.AvailableBytes
			response.DiskUsedPercent = diskInfo.UsedPercent
		}

		// Add quota info if configured
		if cfg.GetQuotaLimitGB() > 0 {
			response.QuotaLimitBytes = cfg.GetQuotaLimitGB() * 1024 * 1024 * 1024
			if response.QuotaLimitBytes > 0 {
				response.QuotaUsedPercent = (float64(totalStorageUsed) / float64(response.QuotaLimitBytes)) * 100
			}
		}

		// Add database metrics
		dbMetrics, err := getDatabaseMetrics(db, cfg.DBPath)
		if err != nil {
			slog.Warn("failed to get database metrics", "error", err)
			// Don't fail health check if metrics unavailable
		} else {
			response.DatabaseMetrics = dbMetrics
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// getDatabaseMetrics retrieves database performance metrics
func getDatabaseMetrics(db *sql.DB, dbPath string) (*models.DatabaseMetrics, error) {
	metrics := &models.DatabaseMetrics{}

	// Get page count and page size from SQLite
	if err := db.QueryRow("PRAGMA page_count").Scan(&metrics.PageCount); err != nil {
		return nil, err
	}
	if err := db.QueryRow("PRAGMA page_size").Scan(&metrics.PageSize); err != nil {
		return nil, err
	}

	// Calculate database size
	metrics.SizeBytes = metrics.PageCount * metrics.PageSize
	metrics.SizeMB = float64(metrics.SizeBytes) / 1024 / 1024

	// Count indexes
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index'").Scan(&metrics.IndexCount); err != nil {
		return nil, err
	}

	// Get WAL file size if it exists
	walPath := dbPath + "-wal"
	if info, err := os.Stat(walPath); err == nil {
		metrics.WALSizeBytes = info.Size()
	}

	return metrics, nil
}
