package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
)

func setupEnterpriseTestDB(t *testing.T) (*repository.Repositories, *config.Config) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("Failed to create repositories: %v", err)
	}

	return repos, cfg
}

func TestAdminGetEnterpriseConfigHandler_Success(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	// Set up feature flags
	cfg.Features.SetMFAEnabled(true)
	cfg.Features.SetSSOEnabled(false)
	cfg.Features.SetWebhooksEnabled(true)

	handler := AdminGetEnterpriseConfigHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/config/enterprise", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response EnterpriseConfigResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.FeatureFlags == nil {
		t.Error("Expected feature_flags in response")
	}
}

func TestAdminGetEnterpriseConfigHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	handler := AdminGetEnterpriseConfigHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/config/enterprise", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestAdminUpdateMFAConfigHandler_Success(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	handler := AdminUpdateMFAConfigHandler(repos, cfg)

	enabled := true
	required := true
	reqBody := MFAConfigRequest{
		Enabled:  &enabled,
		Required: &required,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/config/mfa", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("Expected success: true in response")
	}
}

func TestAdminUpdateMFAConfigHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	handler := AdminUpdateMFAConfigHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/config/mfa", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestAdminUpdateMFAConfigHandler_InvalidJSON(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	handler := AdminUpdateMFAConfigHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/config/mfa", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestAdminUpdateMFAConfigHandler_PartialUpdate(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	handler := AdminUpdateMFAConfigHandler(repos, cfg)

	// Update only the issuer
	issuer := "TestIssuer"
	reqBody := MFAConfigRequest{
		Issuer: &issuer,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/config/mfa", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	mfaData, ok := response["mfa"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected mfa object in response")
	}

	if mfaData["issuer"] != "TestIssuer" {
		t.Errorf("Expected issuer 'TestIssuer', got '%v'", mfaData["issuer"])
	}
}

func TestAdminUpdateMFAConfigHandler_AllFields(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	handler := AdminUpdateMFAConfigHandler(repos, cfg)

	enabled := true
	required := false
	issuer := "MyCompany"
	totpEnabled := true
	webauthnEnabled := true
	recoveryCodesCount := 10
	challengeExpiryMinutes := 15

	reqBody := MFAConfigRequest{
		Enabled:                &enabled,
		Required:               &required,
		Issuer:                 &issuer,
		TOTPEnabled:            &totpEnabled,
		WebAuthnEnabled:        &webauthnEnabled,
		RecoveryCodesCount:     &recoveryCodesCount,
		ChallengeExpiryMinutes: &challengeExpiryMinutes,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/config/mfa", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	mfaData, ok := response["mfa"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected mfa object in response")
	}

	if mfaData["issuer"] != "MyCompany" {
		t.Errorf("Expected issuer 'MyCompany', got '%v'", mfaData["issuer"])
	}
	if int(mfaData["recovery_codes_count"].(float64)) != 10 {
		t.Errorf("Expected recovery_codes_count 10, got '%v'", mfaData["recovery_codes_count"])
	}
}

func TestAdminUpdateSSOConfigHandler_Success(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	handler := AdminUpdateSSOConfigHandler(repos, cfg)

	enabled := true
	autoProvision := true
	reqBody := SSOConfigRequest{
		Enabled:       &enabled,
		AutoProvision: &autoProvision,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/config/sso", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("Expected success: true in response")
	}
}

func TestAdminUpdateSSOConfigHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	handler := AdminUpdateSSOConfigHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/config/sso", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestAdminUpdateSSOConfigHandler_InvalidJSON(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	handler := AdminUpdateSSOConfigHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/config/sso", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestAdminUpdateSSOConfigHandler_AllFields(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	handler := AdminUpdateSSOConfigHandler(repos, cfg)

	enabled := true
	autoProvision := false
	defaultRole := "admin" // Valid roles are 'user' or 'admin'
	sessionLifetime := 48
	stateExpiryMinutes := 20

	reqBody := SSOConfigRequest{
		Enabled:            &enabled,
		AutoProvision:      &autoProvision,
		DefaultRole:        &defaultRole,
		SessionLifetime:    &sessionLifetime,
		StateExpiryMinutes: &stateExpiryMinutes,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/config/sso", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	ssoData, ok := response["sso"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected sso object in response")
	}

	if ssoData["default_role"] != "admin" {
		t.Errorf("Expected default_role 'admin', got '%v'", ssoData["default_role"])
	}
	if int(ssoData["session_lifetime"].(float64)) != 48 {
		t.Errorf("Expected session_lifetime 48, got '%v'", ssoData["session_lifetime"])
	}
}

func TestAdminUpdateMFAConfigHandler_UnknownFields(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	handler := AdminUpdateMFAConfigHandler(repos, cfg)

	// JSON with unknown fields should be rejected (DisallowUnknownFields)
	body := []byte(`{"enabled": true, "unknown_field": "value"}`)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/config/mfa", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for unknown fields, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestAdminUpdateSSOConfigHandler_UnknownFields(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	handler := AdminUpdateSSOConfigHandler(repos, cfg)

	// JSON with unknown fields should be rejected (DisallowUnknownFields)
	body := []byte(`{"enabled": true, "unknown_field": "value"}`)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/config/sso", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for unknown fields, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test context cancellation during database operation
func TestAdminUpdateMFAConfigHandler_ContextCancellation(t *testing.T) {
	repos, cfg := setupEnterpriseTestDB(t)

	handler := AdminUpdateMFAConfigHandler(repos, cfg)

	enabled := true
	reqBody := MFAConfigRequest{
		Enabled: &enabled,
	}
	body, _ := json.Marshal(reqBody)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := httptest.NewRequest(http.MethodPut, "/api/admin/config/mfa", bytes.NewReader(body))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Expect error due to cancelled context
	if w.Code == http.StatusOK {
		t.Error("Expected error status for cancelled context")
	}
}
