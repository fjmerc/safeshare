package metrics

import (
	"database/sql"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

// DatabaseMetricsCollector collects metrics from the database on each scrape
type DatabaseMetricsCollector struct {
	db           *sql.DB
	quotaLimitGB float64

	// Metric descriptors
	storageUsedBytes        *prometheus.Desc
	activeFilesCount        *prometheus.Desc
	activePartialUploads    *prometheus.Desc
	storageQuotaBytes       *prometheus.Desc
	storageQuotaUsedPercent *prometheus.Desc
}

// NewDatabaseMetricsCollector creates a new collector
func NewDatabaseMetricsCollector(db *sql.DB, quotaLimitGB float64) *DatabaseMetricsCollector {
	return &DatabaseMetricsCollector{
		db:           db,
		quotaLimitGB: quotaLimitGB,
		storageUsedBytes: prometheus.NewDesc(
			"safeshare_storage_used_bytes",
			"Total storage used by uploaded files in bytes",
			nil, nil,
		),
		activeFilesCount: prometheus.NewDesc(
			"safeshare_active_files_count",
			"Number of active files (not expired)",
			nil, nil,
		),
		activePartialUploads: prometheus.NewDesc(
			"safeshare_active_partial_uploads_count",
			"Number of active partial (chunked) uploads in progress",
			nil, nil,
		),
		storageQuotaBytes: prometheus.NewDesc(
			"safeshare_storage_quota_bytes",
			"Storage quota limit in bytes (0 = unlimited)",
			nil, nil,
		),
		storageQuotaUsedPercent: prometheus.NewDesc(
			"safeshare_storage_quota_used_percent",
			"Percentage of storage quota used (0-100)",
			nil, nil,
		),
	}
}

// Describe sends metric descriptors to Prometheus
func (c *DatabaseMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.storageUsedBytes
	ch <- c.activeFilesCount
	ch <- c.activePartialUploads
	ch <- c.storageQuotaBytes
	ch <- c.storageQuotaUsedPercent
}

// Collect fetches current metrics from database and sends to Prometheus
func (c *DatabaseMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	// Query storage usage and file count
	// Note: datetime(expires_at) normalizes RFC3339 format (from Go) to SQLite datetime format
	// for proper comparison. Without this, string comparison fails due to 'T' vs ' ' difference.
	var storageUsed int64
	var fileCount int64
	err := c.db.QueryRow(`
		SELECT COALESCE(SUM(file_size), 0), COUNT(*)
		FROM files
		WHERE datetime(expires_at) > datetime('now')
	`).Scan(&storageUsed, &fileCount)

	if err != nil {
		slog.Error("failed to query storage metrics", "error", err)
		// Send zero values on error to avoid scrape failure
		storageUsed = 0
		fileCount = 0
	}

	// Query partial uploads count
	var partialUploads int64
	err = c.db.QueryRow(`
		SELECT COUNT(*)
		FROM partial_uploads
		WHERE completed = 0
	`).Scan(&partialUploads)

	if err != nil {
		slog.Error("failed to query partial uploads metrics", "error", err)
		partialUploads = 0
	}

	// Calculate quota metrics
	quotaBytes := c.quotaLimitGB * 1024 * 1024 * 1024 // Convert GB to bytes
	var quotaUsedPercent float64
	if quotaBytes > 0 {
		quotaUsedPercent = (float64(storageUsed) / quotaBytes) * 100
	}

	// Send metrics
	ch <- prometheus.MustNewConstMetric(
		c.storageUsedBytes,
		prometheus.GaugeValue,
		float64(storageUsed),
	)

	ch <- prometheus.MustNewConstMetric(
		c.activeFilesCount,
		prometheus.GaugeValue,
		float64(fileCount),
	)

	ch <- prometheus.MustNewConstMetric(
		c.activePartialUploads,
		prometheus.GaugeValue,
		float64(partialUploads),
	)

	ch <- prometheus.MustNewConstMetric(
		c.storageQuotaBytes,
		prometheus.GaugeValue,
		quotaBytes,
	)

	ch <- prometheus.MustNewConstMetric(
		c.storageQuotaUsedPercent,
		prometheus.GaugeValue,
		quotaUsedPercent,
	)
}
