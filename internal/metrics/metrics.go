package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Counter metrics (monotonically increasing)
var (
	// UploadsTotal counts total file uploads by status (success, failure)
	UploadsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "safeshare_uploads_total",
			Help: "Total number of file uploads",
		},
		[]string{"status"},
	)

	// DownloadsTotal counts total file downloads by status (success, failure, password_failed)
	DownloadsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "safeshare_downloads_total",
			Help: "Total number of file downloads",
		},
		[]string{"status"},
	)

	// ChunkedUploadsTotal counts total chunked upload initiations
	ChunkedUploadsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "safeshare_chunked_uploads_total",
			Help: "Total number of chunked upload sessions initiated",
		},
	)

	// ChunkedUploadsCompletedTotal counts successfully completed chunked uploads
	ChunkedUploadsCompletedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "safeshare_chunked_uploads_completed_total",
			Help: "Total number of chunked upload sessions completed",
		},
	)

	// ChunkedUploadChunksTotal counts individual chunks uploaded
	ChunkedUploadChunksTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "safeshare_chunked_upload_chunks_total",
			Help: "Total number of file chunks uploaded",
		},
	)

	// HTTPRequestsTotal counts total HTTP requests by method, path, and status code
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "safeshare_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	// ErrorsTotal counts application errors by type
	ErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "safeshare_errors_total",
			Help: "Total number of application errors",
		},
		[]string{"type"},
	)
)

// Histogram metrics (distributions)
var (
	// HTTPRequestDuration tracks HTTP request latency by method and path
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "safeshare_http_request_duration_seconds",
			Help: "HTTP request latency in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60},
		},
		[]string{"method", "path"},
	)

	// UploadSizeBytes tracks distribution of uploaded file sizes
	UploadSizeBytes = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name: "safeshare_upload_size_bytes",
			Help: "Distribution of uploaded file sizes in bytes",
			Buckets: []float64{
				1024,           // 1 KB
				10240,          // 10 KB
				102400,         // 100 KB
				1048576,        // 1 MB
				10485760,       // 10 MB
				104857600,      // 100 MB
				1073741824,     // 1 GB
				10737418240,    // 10 GB
				107374182400,   // 100 GB
			},
		},
	)

	// DownloadSizeBytes tracks distribution of downloaded file sizes
	DownloadSizeBytes = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name: "safeshare_download_size_bytes",
			Help: "Distribution of downloaded file sizes in bytes",
			Buckets: []float64{
				1024,           // 1 KB
				10240,          // 10 KB
				102400,         // 100 KB
				1048576,        // 1 MB
				10485760,       // 10 MB
				104857600,      // 100 MB
				1073741824,     // 1 GB
				10737418240,    // 10 GB
				107374182400,   // 100 GB
			},
		},
	)
)

// Gauge metrics (current values) are defined in collector.go as they require database queries

// Health check metrics
var (
	// HealthStatus is a gauge representing current health status
	// Values: 0 = unhealthy, 1 = degraded, 2 = healthy
	HealthStatus = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "safeshare_health_status",
			Help: "Current health status (0=unhealthy, 1=degraded, 2=healthy)",
		},
	)

	// HealthCheckDuration tracks health check execution time by endpoint
	HealthCheckDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "safeshare_health_check_duration_seconds",
			Help: "Health check execution time in seconds",
			Buckets: []float64{.001, .002, .005, .01, .025, .05, .1},
		},
		[]string{"endpoint"},
	)

	// HealthChecksTotal counts total health check calls by endpoint and status
	HealthChecksTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "safeshare_health_checks_total",
			Help: "Total number of health checks performed",
		},
		[]string{"endpoint", "status"},
	)
)
