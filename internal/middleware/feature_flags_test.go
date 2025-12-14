package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/config"
)

func TestFeatureFlagRequired_Enabled(t *testing.T) {
	// Create a checker that always returns true
	checker := func() bool { return true }

	// Create a handler that records if it was called
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with middleware
	middleware := FeatureFlagRequired(checker, "test_feature")
	wrapped := middleware(handler)

	// Make request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	// Handler should be called
	if !handlerCalled {
		t.Error("Handler should be called when feature is enabled")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestFeatureFlagRequired_Disabled(t *testing.T) {
	// Create a checker that always returns false
	checker := func() bool { return false }

	// Create a handler that records if it was called
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	// Wrap with middleware
	middleware := FeatureFlagRequired(checker, "test_feature")
	wrapped := middleware(handler)

	// Make request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	// Handler should NOT be called
	if handlerCalled {
		t.Error("Handler should not be called when feature is disabled")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", rec.Code)
	}

	// Check response body
	var response map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response body: %v", err)
	}

	if response["error"] != "Feature disabled" {
		t.Errorf("Expected error 'Feature disabled', got %v", response["error"])
	}
	if response["feature"] != "test_feature" {
		t.Errorf("Expected feature 'test_feature', got %v", response["feature"])
	}
}

func TestFeatureFlagRequired_LongPath(t *testing.T) {
	// Create a checker that returns false to trigger the warning log
	checker := func() bool { return false }

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	middleware := FeatureFlagRequired(checker, "test_feature")
	wrapped := middleware(handler)

	// Create a request with a very long path (> 200 chars)
	longPath := "/very"
	for i := 0; i < 50; i++ {
		longPath += "/long/path"
	}

	req := httptest.NewRequest(http.MethodGet, longPath, nil)
	rec := httptest.NewRecorder()

	// Should not panic with long path
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", rec.Code)
	}
}

func TestWebhooksEnabled(t *testing.T) {
	cfg := &config.Config{
		Features: config.NewFeatureFlags(),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Test with webhooks disabled
	middleware := WebhooksEnabled(cfg)
	wrapped := middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/webhooks", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 when webhooks disabled, got %d", rec.Code)
	}

	// Enable webhooks
	cfg.Features.SetWebhooksEnabled(true)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 when webhooks enabled, got %d", rec.Code)
	}
}

func TestAPITokensEnabled(t *testing.T) {
	cfg := &config.Config{
		Features: config.NewFeatureFlags(),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := APITokensEnabled(cfg)
	wrapped := middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/tokens", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 when API tokens disabled, got %d", rec.Code)
	}

	cfg.Features.SetAPITokensEnabled(true)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 when API tokens enabled, got %d", rec.Code)
	}
}

func TestBackupsEnabled(t *testing.T) {
	cfg := &config.Config{
		Features: config.NewFeatureFlags(),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := BackupsEnabled(cfg)
	wrapped := middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/backups", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 when backups disabled, got %d", rec.Code)
	}

	cfg.Features.SetBackupsEnabled(true)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 when backups enabled, got %d", rec.Code)
	}
}

func TestMFAEnabled(t *testing.T) {
	cfg := &config.Config{
		Features: config.NewFeatureFlags(),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := MFAEnabled(cfg)
	wrapped := middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/mfa", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 when MFA disabled, got %d", rec.Code)
	}

	cfg.Features.SetMFAEnabled(true)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 when MFA enabled, got %d", rec.Code)
	}
}

func TestSSOEnabled(t *testing.T) {
	cfg := &config.Config{
		Features: config.NewFeatureFlags(),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := SSOEnabled(cfg)
	wrapped := middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/sso", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 when SSO disabled, got %d", rec.Code)
	}

	cfg.Features.SetSSOEnabled(true)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 when SSO enabled, got %d", rec.Code)
	}
}

func TestMalwareScanEnabled(t *testing.T) {
	cfg := &config.Config{
		Features: config.NewFeatureFlags(),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := MalwareScanEnabled(cfg)
	wrapped := middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/scan", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 when malware scan disabled, got %d", rec.Code)
	}

	cfg.Features.SetMalwareScanEnabled(true)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 when malware scan enabled, got %d", rec.Code)
	}
}

func TestFeatureFlagRequired_ResponseHeaders(t *testing.T) {
	checker := func() bool { return false }
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	middleware := FeatureFlagRequired(checker, "test")
	wrapped := middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	// Should have Content-Type header
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}
}
