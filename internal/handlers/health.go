package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
)

const (
	// Health status thresholds
	criticalDiskFreeBytes   = 500 * 1024 * 1024      // 500MB
	warningDiskFreeBytes    = 2 * 1024 * 1024 * 1024 // 2GB
	criticalDiskUsedPercent = 98.0
	warningDiskUsedPercent  = 90.0
	warningQuotaUsedPercent = 95.0
	warningWALSizeBytes     = 100 * 1024 * 1024 // 100MB
	warningStatsQueryMs     = 100               // 100ms
)

// HealthHandler handles comprehensive health check requests
// Returns detailed health information with intelligent status detection
func HealthHandler(db *sql.DB, cfg *config.Config, startTime time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			metrics.HealthCheckDuration.WithLabelValues("health").Observe(time.Since(start).Seconds())
		}()

		// Only accept GET requests
		if r.Method != http.MethodGet {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Get comprehensive health status
		response, status, httpCode := getComprehensiveHealth(db, cfg, startTime)

		// Record metrics
		metrics.HealthChecksTotal.WithLabelValues("health", status).Inc()
		updateHealthStatusGauge(status)

		// Send response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpCode)
		json.NewEncoder(w).Encode(response)
	}
}

// HealthLivenessHandler handles liveness probe requests
// Minimal check: is the process alive and can we ping the database?
// Should complete in < 10ms
func HealthLivenessHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			metrics.HealthCheckDuration.WithLabelValues("live").Observe(time.Since(start).Seconds())
		}()

		// Only accept GET requests
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
			return
		}

		// Minimal database ping
		ctx := r.Context()
		if err := db.PingContext(ctx); err != nil {
			slog.Error("liveness check failed: database ping error", "error", err)
			metrics.HealthChecksTotal.WithLabelValues("live", "unhealthy").Inc()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy"})
			return
		}

		// Alive
		metrics.HealthChecksTotal.WithLabelValues("live", "healthy").Inc()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "alive"})
	}
}

// HealthReadinessHandler handles readiness probe requests
// Comprehensive check: is the instance ready to accept traffic?
func HealthReadinessHandler(db *sql.DB, cfg *config.Config, startTime time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			metrics.HealthCheckDuration.WithLabelValues("ready").Observe(time.Since(start).Seconds())
		}()

		// Only accept GET requests
		if r.Method != http.MethodGet {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Get comprehensive health status
		response, status, httpCode := getComprehensiveHealth(db, cfg, startTime)

		// Record metrics
		metrics.HealthChecksTotal.WithLabelValues("ready", status).Inc()

		// Send response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpCode)
		json.NewEncoder(w).Encode(response)
	}
}

// getComprehensiveHealth performs all health checks and returns response, status, and HTTP code
func getComprehensiveHealth(db *sql.DB, cfg *config.Config, startTime time.Time) (*models.HealthResponse, string, int) {
	var details []string

	// Calculate uptime
	uptime := time.Since(startTime)

	// Get storage statistics with timing
	statsStart := time.Now()
	totalFiles, storageUsed, statsErr := database.GetStats(db, cfg.UploadDir)
	statsDuration := time.Since(statsStart)

	if statsErr != nil {
		slog.Error("failed to get stats", "error", statsErr)
		details = append(details, "database query failed")
		// This is a critical failure
		return &models.HealthResponse{
			Status:        "unhealthy",
			StatusDetails: details,
			UptimeSeconds: int64(uptime.Seconds()),
		}, "unhealthy", http.StatusServiceUnavailable
	}

	// Check for slow stats query
	if statsDuration.Milliseconds() > warningStatsQueryMs {
		details = append(details, fmt.Sprintf("slow database query: %dms", statsDuration.Milliseconds()))
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
		details = append(details, "disk space check failed")
		// This is a critical failure
		return &models.HealthResponse{
			Status:           "unhealthy",
			StatusDetails:    details,
			UptimeSeconds:    int64(uptime.Seconds()),
			TotalFiles:       totalFiles,
			StorageUsedBytes: totalStorageUsed,
		}, "unhealthy", http.StatusServiceUnavailable
	}

	// Check upload directory writable
	if !isDirectoryWritable(cfg.UploadDir) {
		details = append(details, "upload directory not writable")
		return &models.HealthResponse{
			Status:           "unhealthy",
			StatusDetails:    details,
			UptimeSeconds:    int64(uptime.Seconds()),
			TotalFiles:       totalFiles,
			StorageUsedBytes: totalStorageUsed,
		}, "unhealthy", http.StatusServiceUnavailable
	}

	// Build response
	response := &models.HealthResponse{
		Status:             "healthy",
		UptimeSeconds:      int64(uptime.Seconds()),
		TotalFiles:         totalFiles,
		StorageUsedBytes:   totalStorageUsed,
		DiskTotalBytes:     diskInfo.TotalBytes,
		DiskFreeBytes:      diskInfo.FreeBytes,
		DiskAvailableBytes: diskInfo.AvailableBytes,
		DiskUsedPercent:    diskInfo.UsedPercent,
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
	} else {
		response.DatabaseMetrics = dbMetrics

		// Check WAL size
		if dbMetrics.WALSizeBytes > warningWALSizeBytes {
			details = append(details, fmt.Sprintf("large WAL file: %s (needs checkpointing)",
				utils.FormatBytes(uint64(dbMetrics.WALSizeBytes))))
		}
	}

	// Determine overall health status based on all checks
	status := determineHealthStatus(diskInfo, response.QuotaUsedPercent, &details)
	response.Status = status

	// Only include status_details if there are issues
	if len(details) > 0 {
		response.StatusDetails = details
	}

	// Determine HTTP status code
	httpCode := http.StatusOK
	if status == "degraded" || status == "unhealthy" {
		httpCode = http.StatusServiceUnavailable
	}

	return response, status, httpCode
}

// determineHealthStatus analyzes all health metrics and returns status with details
// Note: details is passed as a pointer so appended messages are visible to the caller
func determineHealthStatus(diskInfo *utils.DiskSpaceInfo, quotaUsedPercent float64, details *[]string) string {
	// Check for unhealthy conditions (critical failures)
	if diskInfo.AvailableBytes < criticalDiskFreeBytes {
		*details = append(*details, fmt.Sprintf("critical: disk space < 500MB (%s remaining)",
			utils.FormatBytes(diskInfo.AvailableBytes)))
		return "unhealthy"
	}

	if diskInfo.UsedPercent > criticalDiskUsedPercent {
		*details = append(*details, fmt.Sprintf("critical: disk usage > 98%% (%.1f%% used)",
			diskInfo.UsedPercent))
		return "unhealthy"
	}

	// Check for degraded conditions (warnings)
	degraded := false

	if diskInfo.AvailableBytes < warningDiskFreeBytes {
		*details = append(*details, fmt.Sprintf("warning: disk space low (%s remaining)",
			utils.FormatBytes(diskInfo.AvailableBytes)))
		degraded = true
	}

	if diskInfo.UsedPercent > warningDiskUsedPercent {
		*details = append(*details, fmt.Sprintf("warning: disk usage high (%.1f%% used)",
			diskInfo.UsedPercent))
		degraded = true
	}

	if quotaUsedPercent > warningQuotaUsedPercent {
		*details = append(*details, fmt.Sprintf("warning: quota usage high (%.1f%%)",
			quotaUsedPercent))
		degraded = true
	}

	if degraded {
		return "degraded"
	}

	return "healthy"
}

// isDirectoryWritable checks if a directory is writable by creating a temp file
func isDirectoryWritable(path string) bool {
	// Create a temporary file to test write permissions
	testFile := filepath.Join(path, ".write_test_"+time.Now().Format("20060102150405"))

	file, err := os.Create(testFile)
	if err != nil {
		return false
	}

	// Write a small test string
	_, err = file.WriteString("write test")
	if err != nil {
		file.Close()
		os.Remove(testFile)
		return false
	}

	// Close and remove test file
	file.Close()
	if err := os.Remove(testFile); err != nil {
		slog.Warn("failed to remove write test file", "path", testFile, "error", err)
		// Don't fail the check if we can't clean up
	}

	return true
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

// updateHealthStatusGauge updates the Prometheus gauge based on status string
func updateHealthStatusGauge(status string) {
	switch status {
	case "healthy":
		metrics.HealthStatus.Set(2)
	case "degraded":
		metrics.HealthStatus.Set(1)
	case "unhealthy":
		metrics.HealthStatus.Set(0)
	default:
		metrics.HealthStatus.Set(0)
	}
}
