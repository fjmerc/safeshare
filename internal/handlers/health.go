package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/storage"
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

	// Health check timeout for external dependencies
	healthCheckTimeout = 5 * time.Second
)

// setHealthCacheHeaders sets appropriate cache-control headers for health endpoints.
// Health checks should never be cached to ensure accurate probe responses.
func setHealthCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

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
			setHealthCacheHeaders(w)
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Use request context with timeout for health checks
		ctx, cancel := context.WithTimeout(r.Context(), healthCheckTimeout)
		defer cancel()

		// Get comprehensive health status
		response, status, httpCode := getComprehensiveHealth(ctx, db, cfg, startTime, nil, nil)

		// Record metrics
		metrics.HealthChecksTotal.WithLabelValues("health", status).Inc()
		updateHealthStatusGauge(status)

		// Send response
		setHealthCacheHeaders(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpCode)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			slog.Error("failed to encode health response", "error", err)
		}
	}
}

// HealthHandlerWithDeps handles comprehensive health check requests with repository dependencies.
// This version uses HealthRepository and StorageBackend for more comprehensive checks.
func HealthHandlerWithDeps(db *sql.DB, cfg *config.Config, startTime time.Time, healthRepo repository.HealthRepository, storageBackend storage.StorageBackend) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			metrics.HealthCheckDuration.WithLabelValues("health").Observe(time.Since(start).Seconds())
		}()

		// Only accept GET requests
		if r.Method != http.MethodGet {
			setHealthCacheHeaders(w)
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Use request context with timeout for health checks
		ctx, cancel := context.WithTimeout(r.Context(), healthCheckTimeout)
		defer cancel()

		// Get comprehensive health status
		response, status, httpCode := getComprehensiveHealth(ctx, db, cfg, startTime, healthRepo, storageBackend)

		// Record metrics
		metrics.HealthChecksTotal.WithLabelValues("health", status).Inc()
		updateHealthStatusGauge(status)

		// Send response
		setHealthCacheHeaders(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpCode)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			slog.Error("failed to encode health response", "error", err)
		}
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
			setHealthCacheHeaders(w)
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Minimal database ping
		ctx := r.Context()
		if err := db.PingContext(ctx); err != nil {
			slog.Error("liveness check failed: database ping error", "error", err)
			metrics.HealthChecksTotal.WithLabelValues("live", "unhealthy").Inc()

			setHealthCacheHeaders(w)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			if err := json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy"}); err != nil {
				slog.Error("failed to encode liveness response", "error", err)
			}
			return
		}

		// Alive
		metrics.HealthChecksTotal.WithLabelValues("live", "healthy").Inc()

		setHealthCacheHeaders(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "alive"}); err != nil {
			slog.Error("failed to encode liveness response", "error", err)
		}
	}
}

// HealthLivenessHandlerWithRepo handles liveness probe requests using HealthRepository.
// This version uses the HealthRepository.Ping() method for the database check.
func HealthLivenessHandlerWithRepo(healthRepo repository.HealthRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			metrics.HealthCheckDuration.WithLabelValues("live").Observe(time.Since(start).Seconds())
		}()

		// Only accept GET requests
		if r.Method != http.MethodGet {
			setHealthCacheHeaders(w)
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Minimal database ping using repository
		ctx := r.Context()
		if err := healthRepo.Ping(ctx); err != nil {
			slog.Error("liveness check failed: database ping error", "error", err)
			metrics.HealthChecksTotal.WithLabelValues("live", "unhealthy").Inc()

			setHealthCacheHeaders(w)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			if err := json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy"}); err != nil {
				slog.Error("failed to encode liveness response", "error", err)
			}
			return
		}

		// Alive
		metrics.HealthChecksTotal.WithLabelValues("live", "healthy").Inc()

		setHealthCacheHeaders(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "alive"}); err != nil {
			slog.Error("failed to encode liveness response", "error", err)
		}
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
			setHealthCacheHeaders(w)
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Use request context with timeout for health checks
		ctx, cancel := context.WithTimeout(r.Context(), healthCheckTimeout)
		defer cancel()

		// Get comprehensive health status
		response, status, httpCode := getComprehensiveHealth(ctx, db, cfg, startTime, nil, nil)

		// Record metrics
		metrics.HealthChecksTotal.WithLabelValues("ready", status).Inc()

		// Send response
		setHealthCacheHeaders(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpCode)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			slog.Error("failed to encode readiness response", "error", err)
		}
	}
}

// HealthReadinessHandlerWithDeps handles readiness probe requests with repository dependencies.
// This version uses HealthRepository and StorageBackend for comprehensive health checks.
func HealthReadinessHandlerWithDeps(db *sql.DB, cfg *config.Config, startTime time.Time, healthRepo repository.HealthRepository, storageBackend storage.StorageBackend) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			metrics.HealthCheckDuration.WithLabelValues("ready").Observe(time.Since(start).Seconds())
		}()

		// Only accept GET requests
		if r.Method != http.MethodGet {
			setHealthCacheHeaders(w)
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Use request context with timeout for health checks
		ctx, cancel := context.WithTimeout(r.Context(), healthCheckTimeout)
		defer cancel()

		// Get comprehensive health status
		response, status, httpCode := getComprehensiveHealth(ctx, db, cfg, startTime, healthRepo, storageBackend)

		// Record metrics
		metrics.HealthChecksTotal.WithLabelValues("ready", status).Inc()

		// Send response
		setHealthCacheHeaders(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpCode)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			slog.Error("failed to encode readiness response", "error", err)
		}
	}
}

// getComprehensiveHealth performs all health checks and returns response, status, and HTTP code.
// If healthRepo and storageBackend are provided, additional checks are performed.
// The ctx parameter should be derived from the request context with appropriate timeout.
func getComprehensiveHealth(ctx context.Context, db *sql.DB, cfg *config.Config, startTime time.Time, healthRepo repository.HealthRepository, storageBackend storage.StorageBackend) (*models.HealthResponse, string, int) {
	var details []string

	// Calculate uptime
	uptime := time.Since(startTime)

	// Check database health if HealthRepository is available
	if healthRepo != nil {
		dbHealth, err := healthRepo.CheckHealth(ctx)
		if err != nil {
			slog.Error("database health check failed", "error", err)
			details = append(details, "database health check failed")
			return &models.HealthResponse{
				Status:        "unhealthy",
				StatusDetails: details,
				UptimeSeconds: int64(uptime.Seconds()),
			}, "unhealthy", http.StatusServiceUnavailable
		}
		if dbHealth.Status == repository.HealthStatusUnhealthy {
			details = append(details, fmt.Sprintf("database unhealthy: %s", dbHealth.Message))
			return &models.HealthResponse{
				Status:        "unhealthy",
				StatusDetails: details,
				UptimeSeconds: int64(uptime.Seconds()),
			}, "unhealthy", http.StatusServiceUnavailable
		}
		if dbHealth.Status == repository.HealthStatusDegraded {
			details = append(details, fmt.Sprintf("database degraded: %s", dbHealth.Message))
		}
	}

	// Check storage backend health if available
	if storageBackend != nil {
		if err := storageBackend.HealthCheck(ctx); err != nil {
			slog.Error("storage health check failed", "error", err)
			details = append(details, "storage backend unhealthy")
			return &models.HealthResponse{
				Status:        "unhealthy",
				StatusDetails: details,
				UptimeSeconds: int64(uptime.Seconds()),
			}, "unhealthy", http.StatusServiceUnavailable
		}
	}

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

	// Check upload directory writable (only if storageBackend wasn't provided or as fallback)
	if storageBackend == nil && !isDirectoryWritable(cfg.UploadDir) {
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

	// Add database metrics (for SQLite)
	if cfg.DBPath != "" {
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
	}

	// Add database stats from HealthRepository if available
	if healthRepo != nil {
		dbStats, err := healthRepo.GetDatabaseStats(ctx)
		if err == nil && dbStats != nil {
			// Merge stats into response if DatabaseMetrics wasn't set
			if response.DatabaseMetrics == nil {
				response.DatabaseMetrics = &models.DatabaseMetrics{}
			}
			// Add connection pool stats if available (for PostgreSQL)
			if openConns, ok := dbStats["open_connections"].(int); ok {
				response.DatabaseMetrics.OpenConnections = openConns
			}
			if maxConns, ok := dbStats["max_connections"].(int); ok {
				response.DatabaseMetrics.MaxConnections = maxConns
			}
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

// isDirectoryWritable checks if a directory is writable by creating a temp file.
// Uses os.CreateTemp for unique file names to avoid race conditions.
func isDirectoryWritable(path string) bool {
	// Use os.CreateTemp for unique file names
	file, err := os.CreateTemp(path, ".write_test_*")
	if err != nil {
		return false
	}
	testFile := file.Name()

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
