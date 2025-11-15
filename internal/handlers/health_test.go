package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
)

func TestHealthHandler_BasicRequest(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	startTime := time.Now()

	handler := HealthHandler(db, cfg, startTime)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Response should be JSON
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	// Parse response
	var response models.HealthResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify basic fields
	if response.Status != "healthy" {
		t.Errorf("status = %q, want %q", response.Status, "healthy")
	}

	if response.UptimeSeconds < 0 {
		t.Errorf("uptime_seconds = %d, should be >= 0", response.UptimeSeconds)
	}

	if response.TotalFiles < 0 {
		t.Errorf("total_files = %d, should be >= 0", response.TotalFiles)
	}

	if response.StorageUsedBytes < 0 {
		t.Errorf("storage_used_bytes = %d, should be >= 0", response.StorageUsedBytes)
	}
}

func TestHealthHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	startTime := time.Now()

	handler := HealthHandler(db, cfg, startTime)

	methods := []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/health", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("method %s: status = %d, want %d", method, rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func TestHealthHandler_UptimeCalculation(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Set start time to 5 seconds ago
	startTime := time.Now().Add(-5 * time.Second)

	handler := HealthHandler(db, cfg, startTime)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var response models.HealthResponse
	json.NewDecoder(rr.Body).Decode(&response)

	// Uptime should be at least 5 seconds
	if response.UptimeSeconds < 5 {
		t.Errorf("uptime_seconds = %d, want >= 5", response.UptimeSeconds)
	}
}

func TestHealthHandler_WithQuota(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	startTime := time.Now()

	// Set a quota limit
	cfg.SetQuotaLimitGB(10) // 10GB quota

	handler := HealthHandler(db, cfg, startTime)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var response models.HealthResponse
	json.NewDecoder(rr.Body).Decode(&response)

	// Verify quota fields are populated
	expectedQuotaBytes := int64(10 * 1024 * 1024 * 1024)
	if response.QuotaLimitBytes != expectedQuotaBytes {
		t.Errorf("quota_limit_bytes = %d, want %d", response.QuotaLimitBytes, expectedQuotaBytes)
	}

	if response.QuotaUsedPercent < 0 || response.QuotaUsedPercent > 100 {
		t.Errorf("quota_used_percent = %f, should be between 0 and 100", response.QuotaUsedPercent)
	}
}

func TestHealthHandler_WithoutQuota(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	startTime := time.Now()

	// No quota limit (default is 0 = unlimited)
	cfg.SetQuotaLimitGB(0)

	handler := HealthHandler(db, cfg, startTime)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var response models.HealthResponse
	json.NewDecoder(rr.Body).Decode(&response)

	// Quota fields should be zero when no quota is set
	if response.QuotaLimitBytes != 0 {
		t.Errorf("quota_limit_bytes = %d, want 0 when quota is unlimited", response.QuotaLimitBytes)
	}
}

func TestHealthHandler_DiskSpaceInfo(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	startTime := time.Now()

	handler := HealthHandler(db, cfg, startTime)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var response models.HealthResponse
	json.NewDecoder(rr.Body).Decode(&response)

	// Disk space fields might be populated (depends on platform)
	// Just verify they're reasonable if present
	if response.DiskTotalBytes > 0 {
		if response.DiskFreeBytes > response.DiskTotalBytes {
			t.Error("disk_free_bytes should not exceed disk_total_bytes")
		}

		if response.DiskUsedPercent < 0 || response.DiskUsedPercent > 100 {
			t.Errorf("disk_used_percent = %f, should be between 0 and 100", response.DiskUsedPercent)
		}
	}
}

func TestHealthHandler_DatabaseMetrics(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	startTime := time.Now()

	handler := HealthHandler(db, cfg, startTime)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var response models.HealthResponse
	json.NewDecoder(rr.Body).Decode(&response)

	// Database metrics should be populated for in-memory database
	if response.DatabaseMetrics != nil {
		if response.DatabaseMetrics.PageCount <= 0 {
			t.Error("database page_count should be > 0")
		}

		if response.DatabaseMetrics.PageSize <= 0 {
			t.Error("database page_size should be > 0")
		}

		if response.DatabaseMetrics.SizeBytes != response.DatabaseMetrics.PageCount*response.DatabaseMetrics.PageSize {
			t.Error("database size_bytes should equal page_count * page_size")
		}

		expectedSizeMB := float64(response.DatabaseMetrics.SizeBytes) / 1024 / 1024
		if response.DatabaseMetrics.SizeMB != expectedSizeMB {
			t.Errorf("database size_mb = %f, want %f", response.DatabaseMetrics.SizeMB, expectedSizeMB)
		}
	}
}

func TestGetDatabaseMetrics(t *testing.T) {
	db := testutil.SetupTestDB(t)

	metrics, err := getDatabaseMetrics(db, ":memory:")
	if err != nil {
		t.Fatalf("getDatabaseMetrics() failed: %v", err)
	}

	if metrics == nil {
		t.Fatal("metrics should not be nil")
	}

	if metrics.PageCount <= 0 {
		t.Errorf("page_count = %d, want > 0", metrics.PageCount)
	}

	if metrics.PageSize <= 0 {
		t.Errorf("page_size = %d, want > 0", metrics.PageSize)
	}

	if metrics.SizeBytes != metrics.PageCount*metrics.PageSize {
		t.Error("size_bytes should equal page_count * page_size")
	}

	if metrics.IndexCount < 0 {
		t.Errorf("index_count = %d, should be >= 0", metrics.IndexCount)
	}
}

func TestHealthHandler_MultipleRequests(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	startTime := time.Now()

	handler := HealthHandler(db, cfg, startTime)

	// Make multiple requests to ensure consistency
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusOK)
		}

		var response models.HealthResponse
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Errorf("request %d: failed to decode response: %v", i+1, err)
		}

		if response.Status != "healthy" {
			t.Errorf("request %d: status = %q, want %q", i+1, response.Status, "healthy")
		}
	}
}
