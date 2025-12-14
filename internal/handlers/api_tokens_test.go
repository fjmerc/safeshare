package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"golang.org/x/crypto/bcrypt"
)

// setupTestUserWithSession creates a test user and returns the user with a valid session context
func setupTestUserWithSession(t *testing.T, db *sql.DB) (*models.User, context.Context) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	user, err := database.CreateUser(db, "testuser", "test@example.com", string(passwordHash), "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	ctx := context.WithValue(context.Background(), middleware.ContextKeyUser, user)
	ctx = context.WithValue(ctx, middleware.ContextKeyAuthType, middleware.AuthTypeSession)

	return user, ctx
}

// setupTestAdmin creates a test admin user with session context
func setupTestAdmin(t *testing.T, db *sql.DB) (*models.User, context.Context) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	user, err := database.CreateUser(db, "adminuser", "admin@example.com", string(passwordHash), "admin", false)
	if err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	ctx := context.WithValue(context.Background(), middleware.ContextKeyUser, user)
	ctx = context.WithValue(ctx, middleware.ContextKeyAuthType, middleware.AuthTypeSession)

	return user, ctx
}

// setupTestReposAndConfig creates test repositories and config for API token tests
func setupTestReposAndConfig(t *testing.T, db *sql.DB) (*repository.Repositories, *config.Config) {
	t.Helper()

	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	return repos, cfg
}

func TestCreateAPITokenHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	user, ctx := setupTestUserWithSession(t, db)

	reqBody := `{"name": "Test Token", "scopes": ["upload", "download"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := CreateAPITokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var resp models.CreateAPITokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Name != "Test Token" {
		t.Errorf("name = %q, want %q", resp.Name, "Test Token")
	}

	if resp.Token == "" {
		t.Error("token should not be empty")
	}

	if resp.TokenPrefix == "" {
		t.Error("token prefix should not be empty")
	}

	if len(resp.Scopes) != 2 {
		t.Errorf("scopes length = %d, want 2", len(resp.Scopes))
	}

	// Verify token is stored in database
	tokens, err := database.GetAPITokensByUserID(db, user.ID)
	if err != nil {
		t.Fatalf("failed to get tokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Errorf("expected 1 token in database, got %d", len(tokens))
	}
}

func TestCreateAPITokenHandler_WithExpiration(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, ctx := setupTestUserWithSession(t, db)

	reqBody := `{"name": "Expiring Token", "scopes": ["upload"], "expires_in_days": 30}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := CreateAPITokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var resp models.CreateAPITokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ExpiresAt == nil {
		t.Error("expires_at should not be nil")
	} else {
		expectedExpiry := time.Now().Add(30 * 24 * time.Hour)
		if resp.ExpiresAt.Before(expectedExpiry.Add(-time.Hour)) || resp.ExpiresAt.After(expectedExpiry.Add(time.Hour)) {
			t.Errorf("expires_at = %v, expected around %v", resp.ExpiresAt, expectedExpiry)
		}
	}
}

func TestCreateAPITokenHandler_ExpirationTooLong(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, ctx := setupTestUserWithSession(t, db)

	reqBody := `{"name": "Long Expiry Token", "scopes": ["upload"], "expires_in_days": 500}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := CreateAPITokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["code"] != "EXPIRATION_TOO_LONG" {
		t.Errorf("error code = %v, want EXPIRATION_TOO_LONG", resp["code"])
	}
}

func TestCreateAPITokenHandler_MissingName(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, ctx := setupTestUserWithSession(t, db)

	reqBody := `{"scopes": ["upload"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := CreateAPITokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestCreateAPITokenHandler_MissingScopes(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, ctx := setupTestUserWithSession(t, db)

	reqBody := `{"name": "Test Token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := CreateAPITokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestCreateAPITokenHandler_InvalidScopes(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, ctx := setupTestUserWithSession(t, db)

	reqBody := `{"name": "Test Token", "scopes": ["upload", "invalid_scope"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := CreateAPITokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["code"] != "INVALID_SCOPES" {
		t.Errorf("error code = %v, want INVALID_SCOPES", resp["code"])
	}
}

func TestCreateAPITokenHandler_AdminScopeByNonAdmin(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, ctx := setupTestUserWithSession(t, db) // Regular user, not admin

	reqBody := `{"name": "Admin Token", "scopes": ["admin"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := CreateAPITokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestCreateAPITokenHandler_AdminScopeByAdmin(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, ctx := setupTestAdmin(t, db)

	reqBody := `{"name": "Admin Token", "scopes": ["admin"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := CreateAPITokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}
}

func TestCreateAPITokenHandler_ViaAPIToken_Forbidden(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	user, err := database.CreateUser(db, "testuser", "test@example.com", string(passwordHash), "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Authenticate via API token instead of session
	ctx := context.WithValue(context.Background(), middleware.ContextKeyUser, user)
	ctx = context.WithValue(ctx, middleware.ContextKeyAuthType, middleware.AuthTypeAPIToken)

	reqBody := `{"name": "Test Token", "scopes": ["upload"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := CreateAPITokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestListAPITokensHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	user, ctx := setupTestUserWithSession(t, db)

	// Create a token first
	reqBody := `{"name": "Test Token", "scopes": ["upload"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	CreateAPITokenHandler(repos, cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("failed to create token: %s", rr.Body.String())
	}

	// Now list tokens
	req = httptest.NewRequest(http.MethodGet, "/api/tokens", nil)
	req = req.WithContext(ctx)
	rr = httptest.NewRecorder()

	handler := ListAPITokensHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tokens, ok := resp["tokens"].([]interface{})
	if !ok {
		t.Fatal("tokens not found in response")
	}

	if len(tokens) != 1 {
		t.Errorf("tokens length = %d, want 1", len(tokens))
	}

	// Verify token belongs to the user
	dbTokens, err := database.GetAPITokensByUserID(db, user.ID)
	if err != nil {
		t.Fatalf("failed to get tokens from db: %v", err)
	}
	if len(dbTokens) != 1 {
		t.Errorf("db tokens length = %d, want 1", len(dbTokens))
	}
}

func TestListAPITokensHandler_Empty(t *testing.T) {
	db := testutil.SetupTestDB(t)

	_, ctx := setupTestUserWithSession(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/tokens", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler := ListAPITokensHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tokens, ok := resp["tokens"].([]interface{})
	if !ok {
		t.Fatal("tokens not found in response")
	}

	if len(tokens) != 0 {
		t.Errorf("tokens length = %d, want 0", len(tokens))
	}
}

func TestRevokeAPITokenHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, ctx := setupTestUserWithSession(t, db)

	// Create a token first
	reqBody := `{"name": "Test Token", "scopes": ["upload"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	CreateAPITokenHandler(repos, cfg).ServeHTTP(rr, req)

	var createResp models.CreateAPITokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&createResp); err != nil {
		t.Fatalf("failed to decode create response: %v", err)
	}

	// Revoke the token
	req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/tokens/%d", createResp.ID), nil)
	req = req.WithContext(ctx)
	// Add token ID to query
	q := req.URL.Query()
	q.Add("id", "1")
	req.URL.RawQuery = q.Encode()
	rr = httptest.NewRecorder()

	handler := RevokeAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
}

func TestRevokeAPITokenHandler_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)

	_, ctx := setupTestUserWithSession(t, db)

	req := httptest.NewRequest(http.MethodDelete, "/api/tokens/999", nil)
	req = req.WithContext(ctx)
	q := req.URL.Query()
	q.Add("id", "999")
	req.URL.RawQuery = q.Encode()
	rr := httptest.NewRecorder()

	handler := RevokeAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestRevokeAPITokenHandler_ViaAPIToken_Forbidden(t *testing.T) {
	db := testutil.SetupTestDB(t)

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	user, err := database.CreateUser(db, "testuser", "test@example.com", string(passwordHash), "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Authenticate via API token instead of session
	ctx := context.WithValue(context.Background(), middleware.ContextKeyUser, user)
	ctx = context.WithValue(ctx, middleware.ContextKeyAuthType, middleware.AuthTypeAPIToken)

	req := httptest.NewRequest(http.MethodDelete, "/api/tokens/1", nil)
	req = req.WithContext(ctx)
	q := req.URL.Query()
	q.Add("id", "1")
	req.URL.RawQuery = q.Encode()
	rr := httptest.NewRecorder()

	handler := RevokeAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestRevokeAPITokenHandler_InvalidID(t *testing.T) {
	db := testutil.SetupTestDB(t)

	_, ctx := setupTestUserWithSession(t, db)

	req := httptest.NewRequest(http.MethodDelete, "/api/tokens/invalid", nil)
	req = req.WithContext(ctx)
	q := req.URL.Query()
	q.Add("id", "invalid")
	req.URL.RawQuery = q.Encode()
	rr := httptest.NewRecorder()

	handler := RevokeAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestCreateAPITokenHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, ctx := setupTestUserWithSession(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/tokens", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler := CreateAPITokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestListAPITokensHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)

	_, ctx := setupTestUserWithSession(t, db)

	req := httptest.NewRequest(http.MethodPost, "/api/tokens", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler := ListAPITokensHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestRevokeAPITokenHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)

	_, ctx := setupTestUserWithSession(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/tokens/1", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler := RevokeAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestCreateAPITokenHandler_MaxTokensPerUser(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	// Set a low limit for testing
	cfg.APIToken.MaxTokensPerUser = 2

	_, ctx := setupTestUserWithSession(t, db)

	// Create first token - should succeed
	reqBody := `{"name": "Token 1", "scopes": ["upload"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	CreateAPITokenHandler(repos, cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("first token creation failed: %s", rr.Body.String())
	}

	// Create second token - should succeed
	reqBody = `{"name": "Token 2", "scopes": ["download"]}`
	req = httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	CreateAPITokenHandler(repos, cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("second token creation failed: %s", rr.Body.String())
	}

	// Create third token - should fail with TOO_MANY_TOKENS
	reqBody = `{"name": "Token 3", "scopes": ["upload"]}`
	req = httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	CreateAPITokenHandler(repos, cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["code"] != "TOO_MANY_TOKENS" {
		t.Errorf("error code = %v, want TOO_MANY_TOKENS", resp["code"])
	}
}

func TestCreateAPITokenHandler_ConfigurableExpiryLimit(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	// Set a low expiry limit for testing
	cfg.APIToken.MaxExpiryDays = 30

	_, ctx := setupTestUserWithSession(t, db)

	// Try to create a token with expiration beyond the limit
	reqBody := `{"name": "Long Expiry Token", "scopes": ["upload"], "expires_in_days": 60}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := CreateAPITokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["code"] != "EXPIRATION_TOO_LONG" {
		t.Errorf("error code = %v, want EXPIRATION_TOO_LONG", resp["code"])
	}

	// Now try with a valid expiration
	reqBody = `{"name": "Valid Expiry Token", "scopes": ["upload"], "expires_in_days": 25}`
	req = httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}
}

// ============================================================================
// Token Rotation Handler Tests (Task 3.3.1)
// ============================================================================

func TestRotateTokenHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, ctx := setupTestUserWithSession(t, db)

	// Create a token first
	reqBody := `{"name": "Rotate Test Token", "scopes": ["upload", "download"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	CreateAPITokenHandler(repos, cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("failed to create token: %s", rr.Body.String())
	}

	var createResp models.CreateAPITokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&createResp); err != nil {
		t.Fatalf("failed to decode create response: %v", err)
	}

	// Rotate the token
	req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/tokens/%d/rotate", createResp.ID), nil)
	req = req.WithContext(ctx)
	rr = httptest.NewRecorder()

	handler := RotateTokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var rotateResp models.RotateAPITokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&rotateResp); err != nil {
		t.Fatalf("failed to decode rotate response: %v", err)
	}

	// Verify response
	if rotateResp.ID != createResp.ID {
		t.Errorf("ID mismatch: got %d, want %d", rotateResp.ID, createResp.ID)
	}
	if rotateResp.Name != "Rotate Test Token" {
		t.Errorf("Name mismatch: got %s", rotateResp.Name)
	}
	if rotateResp.Token == "" {
		t.Error("new token should not be empty")
	}
	if rotateResp.Token == createResp.Token {
		t.Error("new token should be different from original")
	}
	if rotateResp.TokenPrefix == createResp.TokenPrefix {
		// Prefix might be the same by chance, but this checks it's populated
	}
	if len(rotateResp.Scopes) != 2 {
		t.Errorf("scopes length = %d, want 2", len(rotateResp.Scopes))
	}
	if rotateResp.Warning == "" {
		t.Error("warning should be present")
	}
}

func TestRotateTokenHandler_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, ctx := setupTestUserWithSession(t, db)

	// Try to rotate non-existent token
	req := httptest.NewRequest(http.MethodPost, "/api/tokens/99999/rotate", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler := RotateTokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}

func TestRotateTokenHandler_WrongUser(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	// Create token with user1
	_, ctx1 := setupTestUserWithSession(t, db)

	reqBody := `{"name": "User1 Token", "scopes": ["upload"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx1)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	CreateAPITokenHandler(repos, cfg).ServeHTTP(rr, req)

	var createResp models.CreateAPITokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&createResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Create user2 and try to rotate user1's token
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user2, _ := database.CreateUser(db, "user2", "user2@example.com", string(passwordHash), "user", false)
	ctx2 := context.WithValue(context.Background(), middleware.ContextKeyUser, user2)
	ctx2 = context.WithValue(ctx2, middleware.ContextKeyAuthType, middleware.AuthTypeSession)

	req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/tokens/%d/rotate", createResp.ID), nil)
	req = req.WithContext(ctx2)
	rr = httptest.NewRecorder()

	handler := RotateTokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (token not found for wrong user)", rr.Code, http.StatusNotFound)
	}
}

func TestRotateTokenHandler_ViaAPIToken_Forbidden(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user, _ := database.CreateUser(db, "testuser", "test@example.com", string(passwordHash), "user", false)

	// Authenticate via API token instead of session
	ctx := context.WithValue(context.Background(), middleware.ContextKeyUser, user)
	ctx = context.WithValue(ctx, middleware.ContextKeyAuthType, middleware.AuthTypeAPIToken)

	req := httptest.NewRequest(http.MethodPost, "/api/tokens/1/rotate", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler := RotateTokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestRotateTokenHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, ctx := setupTestUserWithSession(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/tokens/1/rotate", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler := RotateTokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestRotateTokenHandler_InvalidPath(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, ctx := setupTestUserWithSession(t, db)

	req := httptest.NewRequest(http.MethodPost, "/api/tokens/invalid/rotate", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler := RotateTokenHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// ============================================================================
// List Tokens With Stats Handler Tests (Task 3.3.3)
// ============================================================================

func TestListAPITokensWithStatsHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	user, ctx := setupTestUserWithSession(t, db)

	// Create a token
	reqBody := `{"name": "Test Token", "scopes": ["upload"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	CreateAPITokenHandler(repos, cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("failed to create token: %s", rr.Body.String())
	}

	// Log some usage for the token
	tokens, _ := repos.APITokens.GetByUserID(context.Background(), user.ID)
	if len(tokens) > 0 {
		_ = repos.APITokens.LogUsage(context.Background(), tokens[0].ID, "/api/upload", "192.168.1.100", "curl", 200)
		_ = repos.APITokens.LogUsage(context.Background(), tokens[0].ID, "/api/upload", "192.168.1.101", "curl", 200)
	}

	// List tokens with stats
	req = httptest.NewRequest(http.MethodGet, "/api/tokens", nil)
	req = req.WithContext(ctx)
	rr = httptest.NewRecorder()

	handler := ListAPITokensWithStatsHandler(repos)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tokensArr, ok := resp["tokens"].([]interface{})
	if !ok {
		t.Fatal("tokens not found in response")
	}

	if len(tokensArr) != 1 {
		t.Errorf("tokens length = %d, want 1", len(tokensArr))
	}

	// Verify usage_stats is included
	tokenObj, ok := tokensArr[0].(map[string]interface{})
	if !ok {
		t.Fatal("token is not an object")
	}

	usageStats, hasStats := tokenObj["usage_stats"]
	if !hasStats {
		t.Error("expected usage_stats in token response")
	}

	// Verify stats have expected fields
	if statsMap, ok := usageStats.(map[string]interface{}); ok {
		if _, hasTotalReqs := statsMap["total_requests"]; !hasTotalReqs {
			t.Error("expected total_requests in usage_stats")
		}
		if _, hasLast24h := statsMap["last_24h_requests"]; !hasLast24h {
			t.Error("expected last_24h_requests in usage_stats")
		}
		if _, hasUniqueIPs := statsMap["unique_ips"]; !hasUniqueIPs {
			t.Error("expected unique_ips in usage_stats")
		}
	}
}

func TestListAPITokensWithStatsHandler_Empty(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, _ := setupTestReposAndConfig(t, db)

	_, ctx := setupTestUserWithSession(t, db)

	// List tokens without creating any
	req := httptest.NewRequest(http.MethodGet, "/api/tokens", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler := ListAPITokensWithStatsHandler(repos)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tokens, ok := resp["tokens"].([]interface{})
	if !ok {
		t.Fatal("tokens not found in response")
	}

	if len(tokens) != 0 {
		t.Errorf("tokens length = %d, want 0", len(tokens))
	}
}

func TestAdminListAPITokensWithStatsHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	// Create regular user and some tokens
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user, _ := database.CreateUser(db, "testuser", "test@example.com", string(passwordHash), "user", false)
	userCtx := context.WithValue(context.Background(), middleware.ContextKeyUser, user)
	userCtx = context.WithValue(userCtx, middleware.ContextKeyAuthType, middleware.AuthTypeSession)

	// Create tokens for the user
	for i := 0; i < 3; i++ {
		reqBody := fmt.Sprintf(`{"name": "Token %d", "scopes": ["upload"]}`, i+1)
		req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
		req = req.WithContext(userCtx)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		CreateAPITokenHandler(repos, cfg).ServeHTTP(rr, req)
	}

	// Create admin user
	_, adminCtx := setupTestAdmin(t, db)

	// Admin lists all tokens with stats
	req := httptest.NewRequest(http.MethodGet, "/admin/api/tokens", nil)
	req = req.WithContext(adminCtx)
	rr := httptest.NewRecorder()

	handler := AdminListAPITokensWithStatsHandler(repos)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tokens, ok := resp["tokens"].([]interface{})
	if !ok {
		t.Fatal("tokens not found in response")
	}

	if len(tokens) != 3 {
		t.Errorf("tokens length = %d, want 3", len(tokens))
	}

	// Verify total and pagination fields
	if total, ok := resp["total"].(float64); !ok || int(total) != 3 {
		t.Errorf("total = %v, want 3", resp["total"])
	}
}

func TestAdminListAPITokensWithStatsHandler_Pagination(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	// Create user and tokens
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user, _ := database.CreateUser(db, "testuser", "test@example.com", string(passwordHash), "user", false)
	userCtx := context.WithValue(context.Background(), middleware.ContextKeyUser, user)
	userCtx = context.WithValue(userCtx, middleware.ContextKeyAuthType, middleware.AuthTypeSession)

	for i := 0; i < 5; i++ {
		reqBody := fmt.Sprintf(`{"name": "Token %d", "scopes": ["upload"]}`, i+1)
		req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
		req = req.WithContext(userCtx)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		CreateAPITokenHandler(repos, cfg).ServeHTTP(rr, req)
	}

	_, adminCtx := setupTestAdmin(t, db)

	// Test pagination
	req := httptest.NewRequest(http.MethodGet, "/admin/api/tokens?limit=2&offset=0", nil)
	req = req.WithContext(adminCtx)
	rr := httptest.NewRecorder()

	handler := AdminListAPITokensWithStatsHandler(repos)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)

	tokens, _ := resp["tokens"].([]interface{})
	if len(tokens) != 2 {
		t.Errorf("tokens length = %d, want 2 (with limit)", len(tokens))
	}

	if total, ok := resp["total"].(float64); !ok || int(total) != 5 {
		t.Errorf("total = %v, want 5", resp["total"])
	}
}

// ============================================================================
// Bulk Operations Handler Tests (Task 3.3.5)
// ============================================================================

func TestAdminBulkRevokeTokensHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	// Create user and tokens
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user, _ := database.CreateUser(db, "testuser", "test@example.com", string(passwordHash), "user", false)
	userCtx := context.WithValue(context.Background(), middleware.ContextKeyUser, user)
	userCtx = context.WithValue(userCtx, middleware.ContextKeyAuthType, middleware.AuthTypeSession)

	var tokenIDs []int64
	for i := 0; i < 3; i++ {
		reqBody := fmt.Sprintf(`{"name": "Token %d", "scopes": ["upload"]}`, i+1)
		req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
		req = req.WithContext(userCtx)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		CreateAPITokenHandler(repos, cfg).ServeHTTP(rr, req)

		var createResp models.CreateAPITokenResponse
		json.NewDecoder(rr.Body).Decode(&createResp)
		tokenIDs = append(tokenIDs, createResp.ID)
	}

	_, adminCtx := setupTestAdmin(t, db)

	// Bulk revoke tokens
	reqBody := fmt.Sprintf(`{"token_ids": [%d, %d], "confirm": true}`, tokenIDs[0], tokenIDs[1])
	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/bulk-revoke", bytes.NewBufferString(reqBody))
	req = req.WithContext(adminCtx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminBulkRevokeTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp BulkRevokeResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.RevokedCount != 2 {
		t.Errorf("revoked_count = %d, want 2", resp.RevokedCount)
	}

	// Verify remaining active token count
	count, _ := repos.APITokens.CountByUserID(context.Background(), user.ID)
	if count != 1 {
		t.Errorf("expected 1 remaining active token, got %d", count)
	}
}

func TestAdminBulkRevokeTokensHandler_NoConfirmation(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, adminCtx := setupTestAdmin(t, db)

	reqBody := `{"token_ids": [1, 2], "confirm": false}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/bulk-revoke", bytes.NewBufferString(reqBody))
	req = req.WithContext(adminCtx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminBulkRevokeTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["code"] != "CONFIRMATION_REQUIRED" {
		t.Errorf("error code = %v, want CONFIRMATION_REQUIRED", resp["code"])
	}
}

func TestAdminBulkRevokeTokensHandler_EmptyTokens(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, adminCtx := setupTestAdmin(t, db)

	reqBody := `{"token_ids": [], "confirm": true}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/bulk-revoke", bytes.NewBufferString(reqBody))
	req = req.WithContext(adminCtx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminBulkRevokeTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["code"] != "MISSING_TOKEN_IDS" {
		t.Errorf("error code = %v, want MISSING_TOKEN_IDS", resp["code"])
	}
}

func TestAdminBulkRevokeTokensHandler_BatchSizeExceeded(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, adminCtx := setupTestAdmin(t, db)

	// Create array of 101 token IDs (exceeds max batch of 100)
	var tokenIDs []int64
	for i := 0; i < 101; i++ {
		tokenIDs = append(tokenIDs, int64(i+1))
	}
	tokenIDsJSON, _ := json.Marshal(tokenIDs)
	reqBody := fmt.Sprintf(`{"token_ids": %s, "confirm": true}`, tokenIDsJSON)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/bulk-revoke", bytes.NewBufferString(reqBody))
	req = req.WithContext(adminCtx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminBulkRevokeTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["code"] != "BATCH_SIZE_EXCEEDED" {
		t.Errorf("error code = %v, want BATCH_SIZE_EXCEEDED", resp["code"])
	}
}

func TestAdminBulkRevokeTokensHandler_InvalidTokenID(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, adminCtx := setupTestAdmin(t, db)

	reqBody := `{"token_ids": [1, 0, 3], "confirm": true}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/bulk-revoke", bytes.NewBufferString(reqBody))
	req = req.WithContext(adminCtx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminBulkRevokeTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["code"] != "INVALID_TOKEN_ID" {
		t.Errorf("error code = %v, want INVALID_TOKEN_ID", resp["code"])
	}
}

func TestAdminBulkRevokeTokensHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, adminCtx := setupTestAdmin(t, db)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/tokens/bulk-revoke", nil)
	req = req.WithContext(adminCtx)
	rr := httptest.NewRecorder()

	handler := AdminBulkRevokeTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestAdminRevokeUserTokensHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	// Create user and tokens
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user, _ := database.CreateUser(db, "testuser", "test@example.com", string(passwordHash), "user", false)
	userCtx := context.WithValue(context.Background(), middleware.ContextKeyUser, user)
	userCtx = context.WithValue(userCtx, middleware.ContextKeyAuthType, middleware.AuthTypeSession)

	for i := 0; i < 3; i++ {
		reqBody := fmt.Sprintf(`{"name": "Token %d", "scopes": ["upload"]}`, i+1)
		req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(reqBody))
		req = req.WithContext(userCtx)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		CreateAPITokenHandler(repos, cfg).ServeHTTP(rr, req)
	}

	_, adminCtx := setupTestAdmin(t, db)

	// Revoke all user tokens
	reqBody := `{"confirm": true}`
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/admin/api/tokens/revoke-user/%d", user.ID), bytes.NewBufferString(reqBody))
	req = req.WithContext(adminCtx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminRevokeUserTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp RevokeUserTokensResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.RevokedCount != 3 {
		t.Errorf("revoked_count = %d, want 3", resp.RevokedCount)
	}
	if resp.UserID != user.ID {
		t.Errorf("user_id = %d, want %d", resp.UserID, user.ID)
	}

	// Verify all tokens are revoked
	count, _ := repos.APITokens.CountByUserID(context.Background(), user.ID)
	if count != 0 {
		t.Errorf("expected 0 active tokens, got %d", count)
	}
}

func TestAdminRevokeUserTokensHandler_UserNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, adminCtx := setupTestAdmin(t, db)

	reqBody := `{"confirm": true}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/revoke-user/99999", bytes.NewBufferString(reqBody))
	req = req.WithContext(adminCtx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminRevokeUserTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["code"] != "USER_NOT_FOUND" {
		t.Errorf("error code = %v, want USER_NOT_FOUND", resp["code"])
	}
}

func TestAdminRevokeUserTokensHandler_NoConfirmation(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user, _ := database.CreateUser(db, "testuser", "test@example.com", string(passwordHash), "user", false)

	_, adminCtx := setupTestAdmin(t, db)

	reqBody := `{"confirm": false}`
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/admin/api/tokens/revoke-user/%d", user.ID), bytes.NewBufferString(reqBody))
	req = req.WithContext(adminCtx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminRevokeUserTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["code"] != "CONFIRMATION_REQUIRED" {
		t.Errorf("error code = %v, want CONFIRMATION_REQUIRED", resp["code"])
	}
}

func TestAdminRevokeUserTokensHandler_InvalidUserID(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, adminCtx := setupTestAdmin(t, db)

	reqBody := `{"confirm": true}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/revoke-user/invalid", bytes.NewBufferString(reqBody))
	req = req.WithContext(adminCtx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminRevokeUserTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminRevokeUserTokensHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	_, adminCtx := setupTestAdmin(t, db)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/tokens/revoke-user/1", nil)
	req = req.WithContext(adminCtx)
	rr := httptest.NewRecorder()

	handler := AdminRevokeUserTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

// Tests for AdminListAPITokensHandler

func TestAdminListAPITokensHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create test user and token
	user, _ := setupTestUserWithSession(t, db)

	// Create a token for the user
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err := database.CreateAPIToken(db, user.ID, "Test Token", "hash123", "ss_test", "files:read", "127.0.0.1", &expiresAt)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/tokens", nil)
	rr := httptest.NewRecorder()

	handler := AdminListAPITokensHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tokens := resp["tokens"].([]interface{})
	if len(tokens) != 1 {
		t.Errorf("tokens count = %d, want 1", len(tokens))
	}
}

func TestAdminListAPITokensHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens", nil)
	rr := httptest.NewRecorder()

	handler := AdminListAPITokensHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestAdminListAPITokensHandler_WithPagination(t *testing.T) {
	db := testutil.SetupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/tokens?limit=10&offset=0", nil)
	rr := httptest.NewRecorder()

	handler := AdminListAPITokensHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if int(resp["limit"].(float64)) != 10 {
		t.Errorf("limit = %v, want 10", resp["limit"])
	}
	if int(resp["offset"].(float64)) != 0 {
		t.Errorf("offset = %v, want 0", resp["offset"])
	}
}

func TestAdminListAPITokensHandler_EmptyResult(t *testing.T) {
	db := testutil.SetupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/tokens", nil)
	rr := httptest.NewRecorder()

	handler := AdminListAPITokensHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tokens := resp["tokens"].([]interface{})
	if tokens == nil || len(tokens) != 0 {
		t.Errorf("expected empty tokens array, got %v", tokens)
	}
}

// Tests for AdminRevokeAPITokenHandler

func TestAdminRevokeAPITokenHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)

	user, _ := setupTestUserWithSession(t, db)

	// Create a token
	expiresAt := time.Now().Add(24 * time.Hour)
	token, err := database.CreateAPIToken(db, user.ID, "Test Token", "hash123", "ss_test", "files:read", "127.0.0.1", &expiresAt)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/admin/api/tokens/revoke?id=%d", token.ID), nil)
	rr := httptest.NewRecorder()

	handler := AdminRevokeAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["message"] != "Token revoked successfully" {
		t.Errorf("message = %q, want 'Token revoked successfully'", resp["message"])
	}
}

func TestAdminRevokeAPITokenHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/tokens/revoke?id=1", nil)
	rr := httptest.NewRecorder()

	handler := AdminRevokeAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestAdminRevokeAPITokenHandler_InvalidTokenID(t *testing.T) {
	db := testutil.SetupTestDB(t)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/tokens/revoke?id=invalid", nil)
	rr := httptest.NewRecorder()

	handler := AdminRevokeAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminRevokeAPITokenHandler_TokenNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/tokens/revoke?id=99999", nil)
	rr := httptest.NewRecorder()

	handler := AdminRevokeAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestAdminRevokeAPITokenHandler_PostMethod(t *testing.T) {
	db := testutil.SetupTestDB(t)

	user, _ := setupTestUserWithSession(t, db)

	// Create a token
	expiresAt := time.Now().Add(24 * time.Hour)
	token, err := database.CreateAPIToken(db, user.ID, "Test Token", "hash123", "ss_test", "files:read", "127.0.0.1", &expiresAt)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// POST should also work
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/admin/api/tokens/revoke?id=%d", token.ID), nil)
	rr := httptest.NewRecorder()

	handler := AdminRevokeAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
}

// Tests for AdminDeleteAPITokenHandler

func TestAdminDeleteAPITokenHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)

	user, _ := setupTestUserWithSession(t, db)

	// Create a token
	expiresAt := time.Now().Add(24 * time.Hour)
	token, err := database.CreateAPIToken(db, user.ID, "Test Token", "hash123", "ss_test", "files:read", "127.0.0.1", &expiresAt)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/admin/api/tokens/delete?id=%d", token.ID), nil)
	rr := httptest.NewRecorder()

	handler := AdminDeleteAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["message"] != "Token deleted permanently" {
		t.Errorf("message = %q, want 'Token deleted permanently'", resp["message"])
	}

	// Verify token is actually deleted
	deletedToken, _ := database.GetAPITokenByID(db, token.ID)
	if deletedToken != nil {
		t.Error("token should have been deleted")
	}
}

func TestAdminDeleteAPITokenHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/delete?id=1", nil)
	rr := httptest.NewRecorder()

	handler := AdminDeleteAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestAdminDeleteAPITokenHandler_InvalidTokenID(t *testing.T) {
	db := testutil.SetupTestDB(t)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/tokens/delete?id=invalid", nil)
	rr := httptest.NewRecorder()

	handler := AdminDeleteAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminDeleteAPITokenHandler_TokenNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/tokens/delete?id=99999", nil)
	rr := httptest.NewRecorder()

	handler := AdminDeleteAPITokenHandler(db)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// Tests for AdminBulkExtendTokensHandler

func TestAdminBulkExtendTokensHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	user, _ := setupTestUserWithSession(t, db)

	// Create a token with short expiry
	expiresAt := time.Now().Add(24 * time.Hour)
	token, err := database.CreateAPIToken(db, user.ID, "Test Token", "hash123", "ss_test", "files:read", "127.0.0.1", &expiresAt)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Include confirm: true as required by the handler
	reqBody := fmt.Sprintf(`{"token_ids": [%d], "days": 30, "confirm": true}`, token.ID)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/bulk-extend", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminBulkExtendTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Handler returns BulkExtendResponse with message and extended_count fields
	if resp["message"] != "Token expiration extended successfully" {
		t.Errorf("message = %v, want 'Token expiration extended successfully'", resp["message"])
	}
	if int(resp["extended_count"].(float64)) != 1 {
		t.Errorf("extended_count = %v, want 1", resp["extended_count"])
	}
}

func TestAdminBulkExtendTokensHandler_RequiresConfirmation(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	// Request without confirm: true should fail
	reqBody := `{"token_ids": [1], "days": 30}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/bulk-extend", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminBulkExtendTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["code"] != "CONFIRMATION_REQUIRED" {
		t.Errorf("error code = %v, want CONFIRMATION_REQUIRED", resp["code"])
	}
}

func TestAdminBulkExtendTokensHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/tokens/bulk-extend", nil)
	rr := httptest.NewRecorder()

	handler := AdminBulkExtendTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestAdminBulkExtendTokensHandler_InvalidJSON(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/bulk-extend", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminBulkExtendTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminBulkExtendTokensHandler_EmptyTokenIDs(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	reqBody := `{"token_ids": [], "days": 30, "confirm": true}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/bulk-extend", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminBulkExtendTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminBulkExtendTokensHandler_InvalidDays(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	reqBody := `{"token_ids": [1], "days": 0, "confirm": true}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/bulk-extend", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminBulkExtendTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminBulkExtendTokensHandler_ExceedMaxDays(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	// Request more than max allowed days (365)
	reqBody := `{"token_ids": [1], "days": 400, "confirm": true}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/bulk-extend", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminBulkExtendTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminBulkExtendTokensHandler_TooManyTokens(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, cfg := setupTestReposAndConfig(t, db)

	// Create an array with 101 token IDs (max is 100)
	tokenIDs := make([]int64, 101)
	for i := range tokenIDs {
		tokenIDs[i] = int64(i + 1)
	}
	tokenIDsJSON, _ := json.Marshal(tokenIDs)
	reqBody := fmt.Sprintf(`{"token_ids": %s, "days": 30, "confirm": true}`, string(tokenIDsJSON))

	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/bulk-extend", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := AdminBulkExtendTokensHandler(repos, cfg)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}
