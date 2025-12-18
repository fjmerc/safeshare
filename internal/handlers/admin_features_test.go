package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
)

func TestAdminGetFeatureFlagsHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	// Set some feature flags
	cfg.Features.SetWebhooksEnabled(true)
	cfg.Features.SetAPITokensEnabled(true)

	handler := AdminGetFeatureFlagsHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/features", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Check Content-Type
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %s, want application/json", contentType)
	}

	// Check Cache-Control header
	cacheControl := rr.Header().Get("Cache-Control")
	if cacheControl != "no-store, no-cache, must-revalidate, private" {
		t.Errorf("Cache-Control = %s, want no-store, no-cache, must-revalidate, private", cacheControl)
	}

	// Parse response
	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	flags, ok := response["feature_flags"].(map[string]interface{})
	if !ok {
		t.Fatal("response should contain feature_flags object")
	}

	// Verify feature flags are returned
	if webhooks, ok := flags["enable_webhooks"].(bool); !ok || !webhooks {
		t.Error("enable_webhooks should be true")
	}
	if apiTokens, ok := flags["enable_api_tokens"].(bool); !ok || !apiTokens {
		t.Error("enable_api_tokens should be true")
	}
}

func TestAdminGetFeatureFlagsHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := AdminGetFeatureFlagsHandler(repos, cfg)

	// Try POST instead of GET
	req := httptest.NewRequest(http.MethodPost, "/api/admin/features", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestAdminUpdateFeatureFlagsHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	// Initially all flags are disabled
	if cfg.Features.IsWebhooksEnabled() {
		t.Error("webhooks should be disabled initially")
	}

	handler := AdminUpdateFeatureFlagsHandler(repos, cfg)

	// Enable webhooks and API tokens
	updateReq := map[string]interface{}{
		"enable_webhooks":   true,
		"enable_api_tokens": true,
	}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/features", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify in-memory flags are updated
	if !cfg.Features.IsWebhooksEnabled() {
		t.Error("webhooks should be enabled after update")
	}
	if !cfg.Features.IsAPITokensEnabled() {
		t.Error("API tokens should be enabled after update")
	}

	// Parse response
	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("response should contain success: true")
	}
}

func TestAdminUpdateFeatureFlagsHandler_PartialUpdate(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := AdminUpdateFeatureFlagsHandler(repos, cfg)

	// First, enable webhooks via the handler (persisted to database)
	initialReq := map[string]interface{}{
		"enable_webhooks": true,
	}
	initialBody, _ := json.Marshal(initialReq)
	req1 := httptest.NewRequest(http.MethodPut, "/api/admin/features", bytes.NewReader(initialBody))
	req1.Header.Set("Content-Type", "application/json")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Fatalf("initial update failed: status = %d, body = %s", rr1.Code, rr1.Body.String())
	}

	// Verify webhooks is enabled
	if !cfg.Features.IsWebhooksEnabled() {
		t.Fatal("webhooks should be enabled after initial update")
	}

	// Now update only API tokens, webhooks should remain enabled
	updateReq := map[string]interface{}{
		"enable_api_tokens": true,
	}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/features", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Both should now be enabled
	if !cfg.Features.IsWebhooksEnabled() {
		t.Error("webhooks should remain enabled")
	}
	if !cfg.Features.IsAPITokensEnabled() {
		t.Error("API tokens should be enabled after update")
	}
}

func TestAdminUpdateFeatureFlagsHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := AdminUpdateFeatureFlagsHandler(repos, cfg)

	// Try GET instead of PUT
	req := httptest.NewRequest(http.MethodGet, "/api/admin/features", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestAdminUpdateFeatureFlagsHandler_InvalidJSON(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := AdminUpdateFeatureFlagsHandler(repos, cfg)

	// Send invalid JSON
	req := httptest.NewRequest(http.MethodPut, "/api/admin/features", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminUpdateFeatureFlagsHandler_UnknownFields(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := AdminUpdateFeatureFlagsHandler(repos, cfg)

	// Send request with unknown field
	updateReq := map[string]interface{}{
		"enable_webhooks":        true,
		"unknown_feature":        true,
	}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/features", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should reject unknown fields with 400
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for unknown fields", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminUpdateFeatureFlagsHandler_AllFlags(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	handler := AdminUpdateFeatureFlagsHandler(repos, cfg)

	// Enable all flags
	updateReq := map[string]interface{}{
		"enable_postgresql":   true,
		"enable_s3_storage":   true,
		"enable_sso":          true,
		"enable_mfa":          true,
		"enable_webhooks":     true,
		"enable_api_tokens":   true,
		"enable_malware_scan": true,
		"enable_backups":      true,
	}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/features", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify all flags
	data := cfg.Features.GetAll()
	if !data.EnablePostgreSQL || !data.EnableS3Storage || !data.EnableSSO ||
		!data.EnableMFA || !data.EnableWebhooks || !data.EnableAPITokens ||
		!data.EnableMalwareScan || !data.EnableBackups {
		t.Error("all flags should be enabled")
	}
}

func TestFeatureFlagsRequest_PointerSemantics(t *testing.T) {
	// Test that nil pointers work for partial updates
	req := featureFlagsRequest{
		EnableWebhooks: boolPtr(true),
	}

	if req.EnablePostgreSQL != nil {
		t.Error("EnablePostgreSQL should be nil")
	}
	if req.EnableWebhooks == nil || *req.EnableWebhooks != true {
		t.Error("EnableWebhooks should be true")
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestAdminUpdateFeatureFlagsHandler_EnableMFA_InitializesWebAuthn(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	// Set PublicURL for WebAuthn
	cfg.PublicURL = "https://test.example.com"

	// Ensure WebAuthn service is nil initially
	SetWebAuthnService(nil)

	handler := AdminUpdateFeatureFlagsHandler(repos, cfg)

	// Enable MFA (which should also initialize WebAuthn)
	updateReq := map[string]interface{}{
		"enable_mfa": true,
	}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/features", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify MFA is enabled in config
	mfaCfg := cfg.GetMFAConfig()
	if mfaCfg == nil || !mfaCfg.Enabled {
		t.Error("MFA should be enabled after update")
	}

	// Verify WebAuthn service was initialized
	if GetWebAuthnService() == nil {
		t.Error("WebAuthn service should be initialized when MFA is enabled")
	}

	// Parse response and check for success
	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("response should contain success: true")
	}

	// Cleanup
	SetWebAuthnService(nil)
}

func TestAdminUpdateFeatureFlagsHandler_DisableMFA_ClearsWebAuthn(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	// Set PublicURL for WebAuthn
	cfg.PublicURL = "https://test.example.com"

	handler := AdminUpdateFeatureFlagsHandler(repos, cfg)

	// First enable MFA
	enableReq := map[string]interface{}{
		"enable_mfa": true,
	}
	body, _ := json.Marshal(enableReq)
	req := httptest.NewRequest(http.MethodPut, "/api/admin/features", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("failed to enable MFA: status = %d", rr.Code)
	}

	// Verify WebAuthn service is initialized
	if GetWebAuthnService() == nil {
		t.Fatal("WebAuthn service should be initialized")
	}

	// Now disable MFA
	disableReq := map[string]interface{}{
		"enable_mfa": false,
	}
	body, _ = json.Marshal(disableReq)
	req = httptest.NewRequest(http.MethodPut, "/api/admin/features", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify MFA is disabled in config
	mfaCfg := cfg.GetMFAConfig()
	if mfaCfg != nil && mfaCfg.Enabled {
		t.Error("MFA should be disabled after update")
	}

	// Verify WebAuthn service was cleared
	if GetWebAuthnService() != nil {
		t.Error("WebAuthn service should be cleared when MFA is disabled")
	}
}

func TestAdminUpdateFeatureFlagsHandler_MFA_ResponseIncludesWarnings(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	// Set valid PublicURL so there's no warning
	cfg.PublicURL = "https://test.example.com"

	// Ensure WebAuthn service is nil initially
	SetWebAuthnService(nil)

	handler := AdminUpdateFeatureFlagsHandler(repos, cfg)

	// Enable MFA
	updateReq := map[string]interface{}{
		"enable_mfa": true,
	}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/features", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Parse response
	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// With valid config, there should be no warnings
	if warnings, exists := response["warnings"]; exists {
		t.Errorf("Expected no warnings with valid config, got: %v", warnings)
	}

	// Cleanup
	SetWebAuthnService(nil)
}

func TestAdminGetFeatureFlagsHandler_DefaultFlags(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	// Use fresh feature flags (all disabled by default)
	cfg.Features = config.NewFeatureFlags()

	handler := AdminGetFeatureFlagsHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/features", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &response)

	flags := response["feature_flags"].(map[string]interface{})

	// All flags should be false by default
	for key, value := range flags {
		if v, ok := value.(bool); ok && v {
			t.Errorf("flag %s should be false by default", key)
		}
	}
}
