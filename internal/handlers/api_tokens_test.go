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
