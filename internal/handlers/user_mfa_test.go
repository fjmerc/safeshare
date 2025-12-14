package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/pquerna/otp/totp"
)

// ===========================================================================
// Helper Functions
// ===========================================================================

// setupMFATestEnv sets up test environment with MFA enabled
func setupMFATestEnv(t *testing.T) (*repository.Repositories, *config.Config) {
	t.Helper()
	repos, cfg := testutil.SetupTestRepos(t)

	// Enable MFA features
	cfg.MFA = &config.MFAConfig{
		Enabled:               true,
		TOTPEnabled:           true,
		WebAuthnEnabled:       true,
		RecoveryCodesCount:    10,
		Issuer:                "SafeShare-Test",
		ChallengeExpiryMinutes: 5,
	}

	return repos, cfg
}

// createTestUserWithContext creates a test user and sets up the request context
func createTestUserWithContext(t *testing.T, repos *repository.Repositories, username, email string) (*models.User, context.Context) {
	t.Helper()
	ctx := context.Background()

	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	user, err := repos.Users.Create(ctx, username, email, passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Create context with user
	userCtx := context.WithValue(ctx, middleware.ContextKeyUser, user)
	return user, userCtx
}

// ===========================================================================
// TOTP Setup Tests
// ===========================================================================

func TestMFATOTPSetupHandler_Success(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	user, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")

	handler := MFATOTPSetupHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/user/mfa/totp/setup", nil)
	req = req.WithContext(userCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp TOTPSetupResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Secret == "" {
		t.Error("expected secret to be returned")
	}
	if resp.URL == "" {
		t.Error("expected URL to be returned")
	}
	if resp.Issuer != "SafeShare-Test" {
		t.Errorf("issuer = %q, want SafeShare-Test", resp.Issuer)
	}

	// Verify secret is stored in database
	storedSecret, err := repos.MFA.GetTOTPSecret(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("failed to get stored secret: %v", err)
	}
	if storedSecret == "" {
		t.Error("expected secret to be stored in database")
	}
}

func TestMFATOTPSetupHandler_MFADisabled(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	cfg.MFA.Enabled = false
	_, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")

	handler := MFATOTPSetupHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/user/mfa/totp/setup", nil)
	req = req.WithContext(userCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestMFATOTPSetupHandler_TOTPDisabled(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	cfg.MFA.TOTPEnabled = false
	_, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")

	handler := MFATOTPSetupHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/user/mfa/totp/setup", nil)
	req = req.WithContext(userCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

func TestMFATOTPSetupHandler_AlreadyEnabled(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	user, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")
	ctx := context.Background()

	// Setup and enable TOTP
	if err := repos.MFA.SetupTOTP(ctx, user.ID, "encrypted-secret"); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}

	handler := MFATOTPSetupHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/user/mfa/totp/setup", nil)
	req = req.WithContext(userCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusConflict)
}

func TestMFATOTPSetupHandler_Unauthorized(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)

	handler := MFATOTPSetupHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/user/mfa/totp/setup", nil)
	// No user context

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)
}

func TestMFATOTPSetupHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	_, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")

	handler := MFATOTPSetupHandler(repos, cfg)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/user/mfa/totp/setup", nil)
			req = req.WithContext(userCtx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// ===========================================================================
// TOTP Verify Tests
// ===========================================================================

func TestMFATOTPVerifyHandler_Success(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	user, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")
	ctx := context.Background()

	// Generate a real TOTP key for testing
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SafeShare-Test",
		AccountName: "test@example.com",
	})
	if err != nil {
		t.Fatalf("failed to generate TOTP key: %v", err)
	}

	// Store the secret (plaintext since no encryption in test config)
	err = repos.MFA.SetupTOTP(ctx, user.ID, key.Secret())
	if err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}

	// Generate a valid code
	validCode, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}

	handler := MFATOTPVerifyHandler(repos, cfg)

	verifyReq := TOTPVerifyRequest{Code: validCode}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest(http.MethodPost, "/api/user/mfa/totp/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(userCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp TOTPVerifyResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}
	if len(resp.RecoveryCodes) == 0 {
		t.Error("expected recovery codes to be returned")
	}

	// Verify TOTP is now enabled
	enabled, err := repos.MFA.IsTOTPEnabled(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to check TOTP status: %v", err)
	}
	if !enabled {
		t.Error("expected TOTP to be enabled")
	}
}

func TestMFATOTPVerifyHandler_InvalidCode(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	user, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")
	ctx := context.Background()

	// Generate and store a TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SafeShare-Test",
		AccountName: "test@example.com",
	})
	if err != nil {
		t.Fatalf("failed to generate TOTP key: %v", err)
	}
	if err := repos.MFA.SetupTOTP(ctx, user.ID, key.Secret()); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}

	handler := MFATOTPVerifyHandler(repos, cfg)

	tests := []struct {
		name       string
		code       string
		wantStatus int
	}{
		{"wrong code", "000000", http.StatusUnauthorized},
		{"invalid format - too short", "12345", http.StatusBadRequest},
		{"invalid format - too long", "1234567", http.StatusBadRequest},
		{"invalid format - letters", "abcdef", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifyReq := TOTPVerifyRequest{Code: tt.code}
			body, _ := json.Marshal(verifyReq)

			req := httptest.NewRequest(http.MethodPost, "/api/user/mfa/totp/verify", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(userCtx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, tt.wantStatus)
		})
	}
}

func TestMFATOTPVerifyHandler_NoSetup(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	_, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")

	handler := MFATOTPVerifyHandler(repos, cfg)

	verifyReq := TOTPVerifyRequest{Code: "123456"}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest(http.MethodPost, "/api/user/mfa/totp/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(userCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

func TestMFATOTPVerifyHandler_AlreadyEnabled(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	user, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")
	ctx := context.Background()

	// Setup and enable TOTP
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SafeShare-Test",
		AccountName: "test@example.com",
	})
	if err != nil {
		t.Fatalf("failed to generate TOTP key: %v", err)
	}
	if err := repos.MFA.SetupTOTP(ctx, user.ID, key.Secret()); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}

	handler := MFATOTPVerifyHandler(repos, cfg)

	verifyReq := TOTPVerifyRequest{Code: "123456"}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest(http.MethodPost, "/api/user/mfa/totp/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(userCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusConflict)
}

func TestMFATOTPVerifyHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	_, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")

	handler := MFATOTPVerifyHandler(repos, cfg)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/user/mfa/totp/verify", nil)
			req = req.WithContext(userCtx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// ===========================================================================
// TOTP Disable Tests
// ===========================================================================

func TestMFATOTPDisableHandler_Success(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	user, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")
	ctx := context.Background()

	// Generate and enable TOTP
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SafeShare-Test",
		AccountName: "test@example.com",
	})
	if err != nil {
		t.Fatalf("failed to generate TOTP key: %v", err)
	}
	if err := repos.MFA.SetupTOTP(ctx, user.ID, key.Secret()); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}

	// Generate valid code
	validCode, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}

	handler := MFATOTPDisableHandler(repos, cfg)

	disableReq := TOTPDisableRequest{Code: validCode}
	body, _ := json.Marshal(disableReq)

	req := httptest.NewRequest(http.MethodDelete, "/api/user/mfa/totp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(userCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Verify TOTP is disabled
	enabled, _ := repos.MFA.IsTOTPEnabled(ctx, user.ID)
	if enabled {
		t.Error("expected TOTP to be disabled")
	}
}

func TestMFATOTPDisableHandler_InvalidCode(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	user, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")
	ctx := context.Background()

	// Generate and enable TOTP
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SafeShare-Test",
		AccountName: "test@example.com",
	})
	if err != nil {
		t.Fatalf("failed to generate TOTP key: %v", err)
	}
	if err := repos.MFA.SetupTOTP(ctx, user.ID, key.Secret()); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}

	handler := MFATOTPDisableHandler(repos, cfg)

	disableReq := TOTPDisableRequest{Code: "000000"} // Wrong code
	body, _ := json.Marshal(disableReq)

	req := httptest.NewRequest(http.MethodDelete, "/api/user/mfa/totp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(userCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)

	// Verify TOTP is still enabled
	enabled, _ := repos.MFA.IsTOTPEnabled(ctx, user.ID)
	if !enabled {
		t.Error("expected TOTP to still be enabled")
	}
}

func TestMFATOTPDisableHandler_NotEnabled(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	_, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")

	handler := MFATOTPDisableHandler(repos, cfg)

	disableReq := TOTPDisableRequest{Code: "123456"}
	body, _ := json.Marshal(disableReq)

	req := httptest.NewRequest(http.MethodDelete, "/api/user/mfa/totp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(userCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

// ===========================================================================
// MFA Status Tests
// ===========================================================================

func TestMFAStatusHandler_NoMFA(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	_, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")

	handler := MFAStatusHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/user/mfa/status", nil)
	req = req.WithContext(userCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp MFAStatusResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if !resp.Enabled {
		t.Error("expected MFA to be enabled globally")
	}
	if resp.TOTPEnabled {
		t.Error("expected TOTP to not be enabled for user")
	}
	if resp.WebAuthnEnabled {
		t.Error("expected WebAuthn to not be enabled for user")
	}
	if resp.RecoveryCodesRemaining != 0 {
		t.Errorf("expected 0 recovery codes, got %d", resp.RecoveryCodesRemaining)
	}
}

func TestMFAStatusHandler_WithTOTP(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	user, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")
	ctx := context.Background()

	// Setup and enable TOTP with recovery codes
	if err := repos.MFA.SetupTOTP(ctx, user.ID, "secret"); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}
	if err := repos.MFA.CreateRecoveryCodes(ctx, user.ID, []string{"hash1", "hash2", "hash3"}); err != nil {
		t.Fatalf("failed to create recovery codes: %v", err)
	}

	handler := MFAStatusHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/user/mfa/status", nil)
	req = req.WithContext(userCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp MFAStatusResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if !resp.TOTPEnabled {
		t.Error("expected TOTP to be enabled")
	}
	if resp.TOTPVerifiedAt == "" {
		t.Error("expected TOTP verified at to be set")
	}
	if resp.RecoveryCodesRemaining != 3 {
		t.Errorf("expected 3 recovery codes, got %d", resp.RecoveryCodesRemaining)
	}
}

func TestMFAStatusHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	_, userCtx := createTestUserWithContext(t, repos, "testuser", "test@example.com")

	handler := MFAStatusHandler(repos, cfg)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/user/mfa/status", nil)
			req = req.WithContext(userCtx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// ===========================================================================
// MFA Login Flow Tests
// ===========================================================================

func TestUserLoginWithMFAHandler_NoMFA(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()

	// Create user without MFA
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	if _, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := UserLoginWithMFAHandler(repos, cfg)

	loginReq := models.UserLoginRequest{
		Username: "testuser",
		Password: "password123",
	}
	body, _ := json.Marshal(loginReq)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Should complete login directly without MFA challenge
	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if _, ok := resp["mfa_required"]; ok {
		t.Error("expected direct login without MFA challenge")
	}
	if resp["username"] != "testuser" {
		t.Errorf("expected username 'testuser', got %v", resp["username"])
	}
}

func TestUserLoginWithMFAHandler_WithMFA(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()

	// Create user with MFA
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Enable TOTP
	if err := repos.MFA.SetupTOTP(ctx, user.ID, "secret"); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}

	handler := UserLoginWithMFAHandler(repos, cfg)

	loginReq := models.UserLoginRequest{
		Username: "testuser",
		Password: "password123",
	}
	body, _ := json.Marshal(loginReq)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Should return MFA challenge
	var resp MFALoginResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if !resp.MFARequired {
		t.Error("expected MFA required")
	}
	if resp.ChallengeID == "" {
		t.Error("expected challenge ID")
	}
	if resp.ExpiresIn <= 0 {
		t.Error("expected positive expiry time")
	}
	if len(resp.AvailableMethods) == 0 {
		t.Error("expected available methods")
	}
}

func TestUserLoginWithMFAHandler_InvalidCredentials(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()

	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	if _, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := UserLoginWithMFAHandler(repos, cfg)

	tests := []struct {
		name     string
		username string
		password string
	}{
		{"wrong password", "testuser", "wrongpassword"},
		{"wrong username", "wronguser", "password123"},
		{"empty username", "", "password123"},
		{"empty password", "testuser", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loginReq := models.UserLoginRequest{
				Username: tt.username,
				Password: tt.password,
			}
			body, _ := json.Marshal(loginReq)

			req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)
		})
	}
}

func TestUserLoginWithMFAHandler_DisabledAccount(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()

	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	if err := repos.Users.SetActive(ctx, user.ID, false); err != nil {
		t.Fatalf("failed to set user inactive: %v", err)
	}

	handler := UserLoginWithMFAHandler(repos, cfg)

	loginReq := models.UserLoginRequest{
		Username: "testuser",
		Password: "password123",
	}
	body, _ := json.Marshal(loginReq)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)
}

// ===========================================================================
// MFA Verify Login Tests
// ===========================================================================

func TestMFAVerifyLoginHandler_TOTPSuccess(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()

	// Create user with TOTP enabled
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SafeShare-Test",
		AccountName: "test@example.com",
	})
	if err != nil {
		t.Fatalf("failed to generate TOTP key: %v", err)
	}
	if err := repos.MFA.SetupTOTP(ctx, user.ID, key.Secret()); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}

	// Create MFA challenge
	challengeID, err := mfaLoginStore.Create(user.ID, "127.0.0.1", "TestAgent", 5)
	if err != nil {
		t.Fatalf("failed to create challenge: %v", err)
	}
	t.Cleanup(func() { mfaLoginStore.Delete(challengeID) })

	// Generate valid TOTP code
	validCode, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}

	handler := MFAVerifyLoginHandler(repos, cfg)

	verifyReq := MFAVerifyLoginRequest{
		ChallengeID: challengeID,
		Code:        validCode,
		IsRecovery:  false,
	}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login/verify-mfa", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Set RemoteAddr to trusted proxy IP so X-Forwarded-For is trusted
	req.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Should complete login
	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp["username"] != "testuser" {
		t.Errorf("expected username 'testuser', got %v", resp["username"])
	}
}

func TestMFAVerifyLoginHandler_RecoveryCodeSuccess(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()

	// Create user with TOTP and recovery codes
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	if err := repos.MFA.SetupTOTP(ctx, user.ID, "secret"); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}

	// Create recovery codes using actual generation
	codes, hashes, err := generateRecoveryCodes(10)
	if err != nil {
		t.Fatalf("failed to generate recovery codes: %v", err)
	}
	if err := repos.MFA.CreateRecoveryCodes(ctx, user.ID, hashes); err != nil {
		t.Fatalf("failed to create recovery codes: %v", err)
	}

	// Create MFA challenge
	challengeID, err := mfaLoginStore.Create(user.ID, "127.0.0.1", "TestAgent", 5)
	if err != nil {
		t.Fatalf("failed to create challenge: %v", err)
	}
	t.Cleanup(func() { mfaLoginStore.Delete(challengeID) })

	handler := MFAVerifyLoginHandler(repos, cfg)

	verifyReq := MFAVerifyLoginRequest{
		ChallengeID: challengeID,
		Code:        codes[0], // Use first recovery code
		IsRecovery:  true,
	}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login/verify-mfa", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Set RemoteAddr to trusted proxy IP so X-Forwarded-For is trusted
	req.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Verify recovery code is marked as used
	count, _ := repos.MFA.GetRecoveryCodeCount(ctx, user.ID)
	if count != 9 {
		t.Errorf("expected 9 remaining codes, got %d", count)
	}
}

func TestMFAVerifyLoginHandler_InvalidChallenge(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)

	handler := MFAVerifyLoginHandler(repos, cfg)

	verifyReq := MFAVerifyLoginRequest{
		ChallengeID: "invalid-challenge-id",
		Code:        "123456",
		IsRecovery:  false,
	}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login/verify-mfa", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)
}

func TestMFAVerifyLoginHandler_InvalidTOTPCode(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()

	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SafeShare-Test",
		AccountName: "test@example.com",
	})
	if err != nil {
		t.Fatalf("failed to generate TOTP key: %v", err)
	}
	if err := repos.MFA.SetupTOTP(ctx, user.ID, key.Secret()); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}

	challengeID, err := mfaLoginStore.Create(user.ID, "127.0.0.1", "TestAgent", 5)
	if err != nil {
		t.Fatalf("failed to create challenge: %v", err)
	}
	t.Cleanup(func() { mfaLoginStore.Delete(challengeID) })

	handler := MFAVerifyLoginHandler(repos, cfg)

	verifyReq := MFAVerifyLoginRequest{
		ChallengeID: challengeID,
		Code:        "000000", // Invalid code
		IsRecovery:  false,
	}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login/verify-mfa", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)
}

func TestMFAVerifyLoginHandler_IPMismatch(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()

	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	if err := repos.MFA.SetupTOTP(ctx, user.ID, "secret"); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}

	// Create challenge with one IP
	challengeID, err := mfaLoginStore.Create(user.ID, "127.0.0.1", "TestAgent", 5)
	if err != nil {
		t.Fatalf("failed to create challenge: %v", err)
	}
	t.Cleanup(func() { mfaLoginStore.Delete(challengeID) })

	handler := MFAVerifyLoginHandler(repos, cfg)

	verifyReq := MFAVerifyLoginRequest{
		ChallengeID: challengeID,
		Code:        "123456",
		IsRecovery:  false,
	}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login/verify-mfa", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "192.168.1.1") // Different IP

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)
}

// ===========================================================================
// Admin MFA Tests
// ===========================================================================

func TestAdminGetUserMFAStatusHandler_Success(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()
	_ = cfg // suppress unused warning

	// Create admin user
	adminHash, err := utils.HashPassword("adminpass")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	admin, err := repos.Users.Create(ctx, "admin", "admin@example.com", adminHash, "admin", false)
	if err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}

	// Create target user with MFA
	userHash, err := utils.HashPassword("userpass")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	targetUser, err := repos.Users.Create(ctx, "targetuser", "target@example.com", userHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create target user: %v", err)
	}
	if err := repos.MFA.SetupTOTP(ctx, targetUser.ID, "secret"); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, targetUser.ID); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}

	handler := AdminGetUserMFAStatusHandler(repos)

	adminCtx := context.WithValue(ctx, middleware.ContextKeyUser, admin)
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/api/users/%d/mfa/status", targetUser.ID), nil)
	req = req.WithContext(adminCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp AdminMFAStatusResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if !resp.TOTPEnabled {
		t.Error("expected TOTP to be enabled")
	}
	if resp.Username != "targetuser" {
		t.Errorf("expected username 'targetuser', got %q", resp.Username)
	}
}

func TestAdminGetUserMFAStatusHandler_UserNotFound(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()
	_ = cfg // suppress unused warning

	adminHash, err := utils.HashPassword("adminpass")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	admin, err := repos.Users.Create(ctx, "admin", "admin@example.com", adminHash, "admin", false)
	if err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}

	handler := AdminGetUserMFAStatusHandler(repos)

	adminCtx := context.WithValue(ctx, middleware.ContextKeyUser, admin)
	req := httptest.NewRequest(http.MethodGet, "/admin/api/users/99999/mfa/status", nil)
	req = req.WithContext(adminCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

func TestAdminResetUserMFAHandler_Success(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()

	// Create admin user
	adminHash, err := utils.HashPassword("adminpass")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	admin, err := repos.Users.Create(ctx, "admin", "admin@example.com", adminHash, "admin", false)
	if err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}

	// Create target user (non-admin) with MFA
	userHash, err := utils.HashPassword("userpass")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	targetUser, err := repos.Users.Create(ctx, "targetuser", "target@example.com", userHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create target user: %v", err)
	}
	if err := repos.MFA.SetupTOTP(ctx, targetUser.ID, "secret"); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, targetUser.ID); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}

	handler := AdminResetUserMFAHandler(repos, cfg)

	adminCtx := context.WithValue(ctx, middleware.ContextKeyUser, admin)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/admin/api/users/%d/mfa/reset", targetUser.ID), nil)
	req = req.WithContext(adminCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Verify MFA is disabled
	enabled, _ := repos.MFA.IsTOTPEnabled(ctx, targetUser.ID)
	if enabled {
		t.Error("expected TOTP to be disabled")
	}
}

func TestAdminResetUserMFAHandler_CannotResetAdmin(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()

	// Create two admin users
	adminHash, err := utils.HashPassword("adminpass")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	admin1, err := repos.Users.Create(ctx, "admin1", "admin1@example.com", adminHash, "admin", false)
	if err != nil {
		t.Fatalf("failed to create admin1 user: %v", err)
	}
	admin2, err := repos.Users.Create(ctx, "admin2", "admin2@example.com", adminHash, "admin", false)
	if err != nil {
		t.Fatalf("failed to create admin2 user: %v", err)
	}
	if err := repos.MFA.SetupTOTP(ctx, admin2.ID, "secret"); err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, admin2.ID); err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}

	handler := AdminResetUserMFAHandler(repos, cfg)

	adminCtx := context.WithValue(ctx, middleware.ContextKeyUser, admin1)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/admin/api/users/%d/mfa/reset", admin2.ID), nil)
	req = req.WithContext(adminCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusForbidden)
}

// ===========================================================================
// Helper Function Tests
// ===========================================================================

func TestIsValidTOTPCode(t *testing.T) {
	tests := []struct {
		code  string
		valid bool
	}{
		{"123456", true},
		{"000000", true},
		{"999999", true},
		{"12345", false},  // Too short
		{"1234567", false}, // Too long
		{"abcdef", false},  // Letters
		{"12345a", false},  // Mixed
		{"", false},        // Empty
		{"123 456", false}, // Space
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			got := isValidTOTPCode(tt.code)
			if got != tt.valid {
				t.Errorf("isValidTOTPCode(%q) = %v, want %v", tt.code, got, tt.valid)
			}
		})
	}
}

func TestIsValidRecoveryCodeFormat(t *testing.T) {
	tests := []struct {
		code  string
		valid bool
	}{
		{"abcd-1234-5678-90ab", true},
		{"ABCD-1234-5678-90AB", true},
		{"0000-0000-0000-0000", true},
		{"ffff-ffff-ffff-ffff", true},
		{"abcd12345678-90ab", false},  // Missing dashes
		{"abcd-1234-5678", false},     // Too short
		{"abcd-1234-5678-90ab-ef", false}, // Too long
		{"abcd-1234-5678-90ag", false}, // Invalid hex char
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			got := isValidRecoveryCodeFormat(tt.code)
			if got != tt.valid {
				t.Errorf("isValidRecoveryCodeFormat(%q) = %v, want %v", tt.code, got, tt.valid)
			}
		})
	}
}

func TestFormatRecoveryCode(t *testing.T) {
	tests := []struct {
		hex  string
		want string
	}{
		{"0123456789abcdef", "0123-4567-89ab-cdef"},
		{"ABCDEF0123456789", "ABCD-EF01-2345-6789"},
	}

	for _, tt := range tests {
		t.Run(tt.hex, func(t *testing.T) {
			got := formatRecoveryCode(tt.hex)
			if got != tt.want {
				t.Errorf("formatRecoveryCode(%q) = %q, want %q", tt.hex, got, tt.want)
			}
		})
	}
}

func TestGenerateRecoveryCodes(t *testing.T) {
	codes, hashes, err := generateRecoveryCodes(10)
	if err != nil {
		t.Fatalf("generateRecoveryCodes failed: %v", err)
	}

	if len(codes) != 10 {
		t.Errorf("expected 10 codes, got %d", len(codes))
	}
	if len(hashes) != 10 {
		t.Errorf("expected 10 hashes, got %d", len(hashes))
	}

	// Verify each code is properly formatted
	for _, code := range codes {
		if !isValidRecoveryCodeFormat(code) {
			t.Errorf("invalid recovery code format: %q", code)
		}
	}

	// Verify each code can be verified against its hash
	for i, code := range codes {
		if !VerifyRecoveryCodeHash(code, hashes[i]) {
			t.Errorf("code %q does not verify against hash", code)
		}
	}

	// Verify codes are unique
	seen := make(map[string]bool)
	for _, code := range codes {
		if seen[code] {
			t.Errorf("duplicate code: %q", code)
		}
		seen[code] = true
	}
}

func TestParseUserIDFromMFAPath(t *testing.T) {
	tests := []struct {
		path    string
		wantID  int64
		wantErr bool
	}{
		{"/admin/api/users/1/mfa/status", 1, false},
		{"/admin/api/users/123/mfa/reset", 123, false},
		{"/admin/api/users/999999/mfa/status", 999999, false},
		{"/admin/api/users/0/mfa/status", 0, true},
		{"/admin/api/users/-1/mfa/status", 0, true},
		{"/admin/api/users/abc/mfa/status", 0, true},
		{"/admin/api/users//mfa/status", 0, true},
		{"/invalid/path", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := parseUserIDFromMFAPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseUserIDFromMFAPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if got != tt.wantID {
				t.Errorf("parseUserIDFromMFAPath(%q) = %d, want %d", tt.path, got, tt.wantID)
			}
		})
	}
}

// ===========================================================================
// MFA Login Store Tests
// ===========================================================================

func TestMFALoginStore_Create(t *testing.T) {
	challengeID, err := mfaLoginStore.Create(1, "127.0.0.1", "TestAgent", 5)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	t.Cleanup(func() { mfaLoginStore.Delete(challengeID) })

	if challengeID == "" {
		t.Error("expected challenge ID to be returned")
	}
}

func TestMFALoginStore_Get(t *testing.T) {
	challengeID, err := mfaLoginStore.Create(1, "127.0.0.1", "TestAgent", 5)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	t.Cleanup(func() { mfaLoginStore.Delete(challengeID) })

	challenge, exists := mfaLoginStore.Get(challengeID)
	if !exists {
		t.Error("expected challenge to exist")
	}
	if challenge == nil {
		t.Fatal("expected challenge to be returned")
	}
	if challenge.UserID != 1 {
		t.Errorf("expected user ID 1, got %d", challenge.UserID)
	}
	if challenge.ClientIP != "127.0.0.1" {
		t.Errorf("expected IP '127.0.0.1', got %q", challenge.ClientIP)
	}
}

func TestMFALoginStore_GetAndValidateIP(t *testing.T) {
	challengeID, err := mfaLoginStore.Create(1, "127.0.0.1", "TestAgent", 5)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	t.Cleanup(func() { mfaLoginStore.Delete(challengeID) })

	// Same IP
	challenge, valid, mismatch := mfaLoginStore.GetAndValidateIP(challengeID, "127.0.0.1")
	if !valid {
		t.Error("expected challenge to be valid")
	}
	if mismatch {
		t.Error("expected no IP mismatch")
	}
	if challenge == nil {
		t.Fatal("expected challenge to be returned")
	}

	// Different IP
	_, valid, mismatch = mfaLoginStore.GetAndValidateIP(challengeID, "192.168.1.1")
	if !valid {
		t.Error("expected challenge to be valid")
	}
	if !mismatch {
		t.Error("expected IP mismatch")
	}
}

func TestMFALoginStore_IncrementAttempts(t *testing.T) {
	challengeID, err := mfaLoginStore.Create(1, "127.0.0.1", "TestAgent", 5)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	t.Cleanup(func() { mfaLoginStore.Delete(challengeID) })

	// Should succeed for first several attempts
	for i := 0; i < mfaMaxVerifyAttempts; i++ {
		if !mfaLoginStore.IncrementAttempts(challengeID) {
			t.Errorf("attempt %d should succeed", i+1)
		}
	}

	// Next attempt should fail
	if mfaLoginStore.IncrementAttempts(challengeID) {
		t.Error("expected attempt to fail after max attempts")
	}
}

func TestMFALoginStore_Delete(t *testing.T) {
	challengeID, err := mfaLoginStore.Create(1, "127.0.0.1", "TestAgent", 5)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	mfaLoginStore.Delete(challengeID)

	_, exists := mfaLoginStore.Get(challengeID)
	if exists {
		t.Error("expected challenge to be deleted")
	}
}

// ===========================================================================
// Benchmark Tests
// ===========================================================================

func BenchmarkIsValidTOTPCode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		isValidTOTPCode("123456")
	}
}

func BenchmarkIsValidRecoveryCodeFormat(b *testing.B) {
	for i := 0; i < b.N; i++ {
		isValidRecoveryCodeFormat("abcd-1234-5678-90ab")
	}
}

func BenchmarkGenerateRecoveryCodes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateRecoveryCodes(10)
	}
}
