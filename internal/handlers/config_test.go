package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/testutil"
)

func TestPublicConfigHandler_BasicRequest(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	handler := PublicConfigHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
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
	var response PublicConfigResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify version field
	if response.Version == "" {
		t.Error("version should not be empty")
	}

	// Version should match the constant
	if response.Version != Version {
		t.Errorf("version = %q, want %q", response.Version, Version)
	}
}

func TestPublicConfigHandler_MethodNotAllowed(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	handler := PublicConfigHandler(cfg)

	methods := []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/config", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("method %s: status = %d, want %d", method, rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func TestPublicConfigHandler_AllFields(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	// Set known values
	cfg.RequireAuthForUpload = true
	cfg.SetMaxFileSize(100 * 1024 * 1024) // 100MB
	cfg.ChunkedUploadEnabled = true
	cfg.ChunkedUploadThreshold = 50 * 1024 * 1024 // 50MB
	cfg.ChunkSize = 10 * 1024 * 1024               // 10MB

	handler := PublicConfigHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var response PublicConfigResponse
	json.NewDecoder(rr.Body).Decode(&response)

	// Verify all fields are populated correctly
	if response.Version != Version {
		t.Errorf("version = %q, want %q", response.Version, Version)
	}

	if response.RequireAuthForUpload != true {
		t.Errorf("require_auth_for_upload = %v, want true", response.RequireAuthForUpload)
	}

	if response.MaxFileSize != 100*1024*1024 {
		t.Errorf("max_file_size = %d, want %d", response.MaxFileSize, 100*1024*1024)
	}

	if response.MaxExpirationHours != 168 {
		t.Errorf("max_expiration_hours = %d, want 168", response.MaxExpirationHours)
	}

	if response.ChunkedUploadEnabled != true {
		t.Errorf("chunked_upload_enabled = %v, want true", response.ChunkedUploadEnabled)
	}

	if response.ChunkedUploadThreshold != 50*1024*1024 {
		t.Errorf("chunked_upload_threshold = %d, want %d", response.ChunkedUploadThreshold, 50*1024*1024)
	}

	if response.ChunkSize != 10*1024*1024 {
		t.Errorf("chunk_size = %d, want %d", response.ChunkSize, 10*1024*1024)
	}
}

func TestPublicConfigHandler_RequireAuthFalse(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	// Set require_auth_for_upload to false
	cfg.RequireAuthForUpload = false

	handler := PublicConfigHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var response PublicConfigResponse
	json.NewDecoder(rr.Body).Decode(&response)

	if response.RequireAuthForUpload != false {
		t.Errorf("require_auth_for_upload = %v, want false", response.RequireAuthForUpload)
	}
}

func TestPublicConfigHandler_ChunkedUploadDisabled(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	// Disable chunked uploads
	cfg.ChunkedUploadEnabled = false

	handler := PublicConfigHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var response PublicConfigResponse
	json.NewDecoder(rr.Body).Decode(&response)

	if response.ChunkedUploadEnabled != false {
		t.Errorf("chunked_upload_enabled = %v, want false", response.ChunkedUploadEnabled)
	}
}

func TestPublicConfigHandler_DifferentFileSizes(t *testing.T) {
	tests := []struct {
		name     string
		fileSize int64
	}{
		{"10MB", 10 * 1024 * 1024},
		{"50MB", 50 * 1024 * 1024},
		{"100MB", 100 * 1024 * 1024},
		{"1GB", 1 * 1024 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testutil.SetupTestConfig(t)
			cfg.SetMaxFileSize(tt.fileSize)

			handler := PublicConfigHandler(cfg)

			req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			var response PublicConfigResponse
			json.NewDecoder(rr.Body).Decode(&response)

			if response.MaxFileSize != tt.fileSize {
				t.Errorf("max_file_size = %d, want %d", response.MaxFileSize, tt.fileSize)
			}
		})
	}
}

func TestPublicConfigHandler_MultipleRequests(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	handler := PublicConfigHandler(cfg)

	// Make multiple requests to ensure consistency
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusOK)
		}

		var response PublicConfigResponse
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Errorf("request %d: failed to decode response: %v", i+1, err)
		}

		if response.Version != Version {
			t.Errorf("request %d: version = %q, want %q", i+1, response.Version, Version)
		}
	}
}

func TestPublicConfigHandler_NoSensitiveData(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	handler := PublicConfigHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Parse response
	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	// Verify sensitive fields are NOT exposed
	sensitiveFields := []string{
		"encryption_key",
		"admin_username",
		"admin_password",
		"db_path",
		"upload_dir",
	}

	for _, field := range sensitiveFields {
		if _, exists := response[field]; exists {
			t.Errorf("response should not contain sensitive field: %s", field)
		}
	}

	// Verify only expected public fields are present
	expectedFields := []string{
		"version",
		"require_auth_for_upload",
		"max_file_size",
		"chunked_upload_enabled",
		"chunked_upload_threshold",
		"chunk_size",
	}

	for _, field := range expectedFields {
		if _, exists := response[field]; !exists {
			t.Errorf("response missing expected field: %s", field)
		}
	}
}

func TestVersion_NotEmpty(t *testing.T) {
	if Version == "" {
		t.Error("Version constant should not be empty")
	}

	// Version should follow semantic versioning (e.g., "2.6.0")
	if len(Version) < 5 {
		t.Errorf("Version = %q, seems too short for semantic versioning", Version)
	}
}
