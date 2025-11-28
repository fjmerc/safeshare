package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsRegistration(t *testing.T) {
	// Test that all metrics are properly registered
	metrics := []prometheus.Collector{
		UploadsTotal,
		DownloadsTotal,
		ChunkedUploadsTotal,
		ChunkedUploadsCompletedTotal,
		ChunkedUploadChunksTotal,
		HTTPRequestsTotal,
		ErrorsTotal,
		HTTPRequestDuration,
		UploadSizeBytes,
		DownloadSizeBytes,
	}

	for _, metric := range metrics {
		if metric == nil {
			t.Error("Metric is nil")
		}
	}
}

func TestUploadsTotal(t *testing.T) {
	// Note: Cannot reset counters in tests, they are cumulative
	// Record initial values
	initialSuccess := testutil.ToFloat64(UploadsTotal.WithLabelValues("success"))
	initialFailure := testutil.ToFloat64(UploadsTotal.WithLabelValues("failure"))

	// Increment counters
	UploadsTotal.WithLabelValues("success").Inc()
	UploadsTotal.WithLabelValues("success").Inc()
	UploadsTotal.WithLabelValues("failure").Inc()

	// Verify counts increased
	successCount := testutil.ToFloat64(UploadsTotal.WithLabelValues("success"))
	if successCount < initialSuccess+2.0 {
		t.Errorf("Expected at least %.0f successful uploads, got %f", initialSuccess+2.0, successCount)
	}

	failureCount := testutil.ToFloat64(UploadsTotal.WithLabelValues("failure"))
	if failureCount < initialFailure+1.0 {
		t.Errorf("Expected at least %.0f failed uploads, got %f", initialFailure+1.0, failureCount)
	}
}

func TestDownloadsTotal(t *testing.T) {
	// Record initial values
	initialSuccess := testutil.ToFloat64(DownloadsTotal.WithLabelValues("success"))
	initialPasswordFailed := testutil.ToFloat64(DownloadsTotal.WithLabelValues("password_failed"))

	// Increment counters with different statuses
	DownloadsTotal.WithLabelValues("success").Inc()
	DownloadsTotal.WithLabelValues("success").Inc()
	DownloadsTotal.WithLabelValues("success").Inc()
	DownloadsTotal.WithLabelValues("password_failed").Inc()
	DownloadsTotal.WithLabelValues("failure").Inc()

	// Verify counts increased
	successCount := testutil.ToFloat64(DownloadsTotal.WithLabelValues("success"))
	if successCount < initialSuccess+3.0 {
		t.Errorf("Expected at least %.0f successful downloads, got %f", initialSuccess+3.0, successCount)
	}

	passwordFailedCount := testutil.ToFloat64(DownloadsTotal.WithLabelValues("password_failed"))
	if passwordFailedCount < initialPasswordFailed+1.0 {
		t.Errorf("Expected at least %.0f password failed downloads, got %f", initialPasswordFailed+1.0, passwordFailedCount)
	}
}

func TestChunkedUploadMetrics(t *testing.T) {
	// Record initial values
	initialInits := testutil.ToFloat64(ChunkedUploadsTotal)
	initialCompleted := testutil.ToFloat64(ChunkedUploadsCompletedTotal)
	initialChunks := testutil.ToFloat64(ChunkedUploadChunksTotal)

	// Simulate chunked upload flow
	ChunkedUploadsTotal.Inc()          // Initialize upload
	ChunkedUploadChunksTotal.Inc()     // Upload chunk 1
	ChunkedUploadChunksTotal.Inc()     // Upload chunk 2
	ChunkedUploadChunksTotal.Inc()     // Upload chunk 3
	ChunkedUploadsCompletedTotal.Inc() // Complete upload

	// Verify counts increased
	inits := testutil.ToFloat64(ChunkedUploadsTotal)
	if inits < initialInits+1.0 {
		t.Errorf("Expected at least %.0f chunked upload inits, got %f", initialInits+1.0, inits)
	}

	chunks := testutil.ToFloat64(ChunkedUploadChunksTotal)
	if chunks < initialChunks+3.0 {
		t.Errorf("Expected at least %.0f chunks uploaded, got %f", initialChunks+3.0, chunks)
	}

	completed := testutil.ToFloat64(ChunkedUploadsCompletedTotal)
	if completed < initialCompleted+1.0 {
		t.Errorf("Expected at least %.0f completed chunked uploads, got %f", initialCompleted+1.0, completed)
	}
}

func TestUploadSizeBytes(t *testing.T) {
	// Test that histogram accepts observations without panicking
	// Note: We can't easily verify histogram counts with testutil.ToFloat64 (it only works for counters/gauges)
	UploadSizeBytes.Observe(1024)      // 1 KB
	UploadSizeBytes.Observe(10240)     // 10 KB
	UploadSizeBytes.Observe(1048576)   // 1 MB
	UploadSizeBytes.Observe(104857600) // 100 MB
	// If we got here without panic, test passes
}

func TestDownloadSizeBytes(t *testing.T) {
	// Test that histogram accepts observations without panicking
	DownloadSizeBytes.Observe(1024)     // 1 KB
	DownloadSizeBytes.Observe(10485760) // 10 MB
	// If we got here without panic, test passes
}

func TestHTTPRequestMetrics(t *testing.T) {
	// Record initial values
	initialGetUpload200 := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("GET", "/api/upload", "200"))
	initialPostUpload201 := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("POST", "/api/upload", "201"))

	// Simulate some HTTP requests
	HTTPRequestsTotal.WithLabelValues("GET", "/api/upload", "200").Inc()
	HTTPRequestsTotal.WithLabelValues("GET", "/api/upload", "200").Inc()
	HTTPRequestsTotal.WithLabelValues("POST", "/api/upload", "201").Inc()
	HTTPRequestsTotal.WithLabelValues("GET", "/api/claim/:code", "200").Inc()
	HTTPRequestsTotal.WithLabelValues("GET", "/api/claim/:code", "404").Inc()

	// Verify counts increased
	getUpload200 := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("GET", "/api/upload", "200"))
	if getUpload200 < initialGetUpload200+2.0 {
		t.Errorf("Expected at least %.0f GET /api/upload 200 requests, got %f", initialGetUpload200+2.0, getUpload200)
	}

	postUpload201 := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("POST", "/api/upload", "201"))
	if postUpload201 < initialPostUpload201+1.0 {
		t.Errorf("Expected at least %.0f POST /api/upload 201 requests, got %f", initialPostUpload201+1.0, postUpload201)
	}
}

func TestErrorsTotal(t *testing.T) {
	// Record initial values
	initialDBErrors := testutil.ToFloat64(ErrorsTotal.WithLabelValues("database"))
	initialValidationErrors := testutil.ToFloat64(ErrorsTotal.WithLabelValues("validation"))

	// Simulate errors
	ErrorsTotal.WithLabelValues("database").Inc()
	ErrorsTotal.WithLabelValues("validation").Inc()
	ErrorsTotal.WithLabelValues("validation").Inc()
	ErrorsTotal.WithLabelValues("encryption").Inc()

	// Verify counts increased
	dbErrors := testutil.ToFloat64(ErrorsTotal.WithLabelValues("database"))
	if dbErrors < initialDBErrors+1.0 {
		t.Errorf("Expected at least %.0f database errors, got %f", initialDBErrors+1.0, dbErrors)
	}

	validationErrors := testutil.ToFloat64(ErrorsTotal.WithLabelValues("validation"))
	if validationErrors < initialValidationErrors+2.0 {
		t.Errorf("Expected at least %.0f validation errors, got %f", initialValidationErrors+2.0, validationErrors)
	}
}

func TestHealthMetrics(t *testing.T) {
	// Test HealthStatus gauge
	initialStatus := testutil.ToFloat64(HealthStatus)

	// Set different health statuses
	HealthStatus.Set(2) // Healthy
	healthyStatus := testutil.ToFloat64(HealthStatus)
	if healthyStatus != 2.0 {
		t.Errorf("Expected health status 2.0, got %f", healthyStatus)
	}

	HealthStatus.Set(1) // Degraded
	degradedStatus := testutil.ToFloat64(HealthStatus)
	if degradedStatus != 1.0 {
		t.Errorf("Expected health status 1.0, got %f", degradedStatus)
	}

	HealthStatus.Set(0) // Unhealthy
	unhealthyStatus := testutil.ToFloat64(HealthStatus)
	if unhealthyStatus != 0.0 {
		t.Errorf("Expected health status 0.0, got %f", unhealthyStatus)
	}

	// Restore initial status
	HealthStatus.Set(initialStatus)
}

func TestHealthCheckMetrics(t *testing.T) {
	// Record initial values
	initialHealthChecks := testutil.ToFloat64(HealthChecksTotal.WithLabelValues("/health", "healthy"))

	// Simulate health checks
	HealthChecksTotal.WithLabelValues("/health", "healthy").Inc()
	HealthChecksTotal.WithLabelValues("/health", "healthy").Inc()
	HealthChecksTotal.WithLabelValues("/health", "degraded").Inc()
	HealthChecksTotal.WithLabelValues("/readiness", "healthy").Inc()

	// Verify counts increased
	healthChecks := testutil.ToFloat64(HealthChecksTotal.WithLabelValues("/health", "healthy"))
	if healthChecks < initialHealthChecks+2.0 {
		t.Errorf("Expected at least %.0f health checks, got %f", initialHealthChecks+2.0, healthChecks)
	}
}

func TestHealthCheckDuration(t *testing.T) {
	// Test that histogram accepts observations without panicking
	HealthCheckDuration.WithLabelValues("/health").Observe(0.001)    // 1ms
	HealthCheckDuration.WithLabelValues("/health").Observe(0.005)    // 5ms
	HealthCheckDuration.WithLabelValues("/readiness").Observe(0.010) // 10ms
	// If we got here without panic, test passes
}

func TestHTTPRequestDuration(t *testing.T) {
	// Test that histogram accepts observations without panicking
	HTTPRequestDuration.WithLabelValues("GET", "/api/upload").Observe(0.1)
	HTTPRequestDuration.WithLabelValues("POST", "/api/upload").Observe(0.5)
	HTTPRequestDuration.WithLabelValues("GET", "/api/claim/:code").Observe(0.05)
	// If we got here without panic, test passes
}
