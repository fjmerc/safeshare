package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// =============================================================================
// Token Audit Middleware Tests (Task 3.3.2)
// =============================================================================

// TestAPITokenAuditLog_LogsUsage tests that API token usage is logged
func TestAPITokenAuditLog_LogsUsage(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create user and API token
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create API token using the official utility function
	tokenPlaintext, tokenPrefix, err := utils.GenerateAPIToken()
	if err != nil {
		t.Fatalf("failed to generate API token: %v", err)
	}
	tokenHash := utils.HashAPIToken(tokenPlaintext)
	token, err := repos.APITokens.Create(ctx, user.ID, "test-token", tokenHash, tokenPrefix, "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("failed to create API token: %v", err)
	}

	// Create test handler that returns 200 OK
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	// Wrap with audit middleware
	auditHandler := APITokenAuditLog(repos)(testHandler)

	// Create request with API token ID in context (simulating UserAuth middleware)
	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyTokenID, token.ID))
	req.Header.Set("User-Agent", "TestClient/1.0")
	rr := httptest.NewRecorder()

	// Execute request
	auditHandler.ServeHTTP(rr, req)

	// Verify response
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Wait for async logging to complete
	time.Sleep(100 * time.Millisecond)

	// Verify audit log was created
	filter := repository.UsageFilter{Limit: 10, Offset: 0}
	logs, total, err := repos.APITokens.GetUsageLogs(ctx, token.ID, filter)
	if err != nil {
		t.Fatalf("failed to get usage logs: %v", err)
	}

	if total == 0 {
		t.Error("expected usage log to be created")
	}

	if len(logs) == 0 {
		t.Fatal("no logs returned")
	}

	log := logs[0]
	if log.Endpoint != "/api/user/files" {
		t.Errorf("endpoint = %q, want %q", log.Endpoint, "/api/user/files")
	}
	if log.ResponseStatus != 200 {
		t.Errorf("response_status = %d, want 200", log.ResponseStatus)
	}
	if log.UserAgent != "TestClient/1.0" {
		t.Errorf("user_agent = %q, want %q", log.UserAgent, "TestClient/1.0")
	}
}

// TestAPITokenAuditLog_CapturesErrorStatus tests that error status codes are logged
func TestAPITokenAuditLog_CapturesErrorStatus(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create user and API token
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	tokenPlaintext, tokenPrefix, err := utils.GenerateAPIToken()
	if err != nil {
		t.Fatalf("failed to generate API token: %v", err)
	}
	tokenHash := utils.HashAPIToken(tokenPlaintext)
	token, err := repos.APITokens.Create(ctx, user.ID, "test-token", tokenHash, tokenPrefix, "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("failed to create API token: %v", err)
	}

	// Create test handler that returns 500 error
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	auditHandler := APITokenAuditLog(repos)(testHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyTokenID, token.ID))
	rr := httptest.NewRecorder()

	auditHandler.ServeHTTP(rr, req)

	// Wait for async logging
	time.Sleep(100 * time.Millisecond)

	// Verify error status was logged
	filter := repository.UsageFilter{Limit: 10, Offset: 0}
	logs, _, err := repos.APITokens.GetUsageLogs(ctx, token.ID, filter)
	if err != nil {
		t.Fatalf("failed to get usage logs: %v", err)
	}

	if len(logs) == 0 {
		t.Fatal("expected log entry")
	}

	if logs[0].ResponseStatus != 500 {
		t.Errorf("response_status = %d, want 500", logs[0].ResponseStatus)
	}
}

// TestAPITokenAuditLog_NoLoggingForSessionAuth tests that session auth doesn't create audit logs
func TestAPITokenAuditLog_NoLoggingForSessionAuth(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	auditHandler := APITokenAuditLog(repos)(testHandler)

	// Request without token ID in context (session auth)
	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	rr := httptest.NewRecorder()

	auditHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// No error means it didn't try to log (can't easily verify no logs were created
	// without having a specific token ID to check)
}

// TestAPITokenAuditLog_DefaultStatusOK tests that default status is 200 when WriteHeader isn't called
func TestAPITokenAuditLog_DefaultStatusOK(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create user and API token
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	tokenPlaintext, tokenPrefix, err := utils.GenerateAPIToken()
	if err != nil {
		t.Fatalf("failed to generate API token: %v", err)
	}
	tokenHash := utils.HashAPIToken(tokenPlaintext)
	token, err := repos.APITokens.Create(ctx, user.ID, "test-token", tokenHash, tokenPrefix, "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("failed to create API token: %v", err)
	}

	// Handler that writes without calling WriteHeader (default 200)
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("success"))
	})

	auditHandler := APITokenAuditLog(repos)(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyTokenID, token.ID))
	rr := httptest.NewRecorder()

	auditHandler.ServeHTTP(rr, req)

	// Wait for async logging
	time.Sleep(100 * time.Millisecond)

	filter := repository.UsageFilter{Limit: 10, Offset: 0}
	logs, _, err := repos.APITokens.GetUsageLogs(ctx, token.ID, filter)
	if err != nil {
		t.Fatalf("failed to get usage logs: %v", err)
	}

	if len(logs) == 0 {
		t.Fatal("expected log entry")
	}

	// Should log 200 as default
	if logs[0].ResponseStatus != 200 {
		t.Errorf("response_status = %d, want 200", logs[0].ResponseStatus)
	}
}

// TestStatusCapturingWriter_WriteHeaderOnce tests that WriteHeader is only captured once
func TestStatusCapturingWriter_WriteHeaderOnce(t *testing.T) {
	rr := httptest.NewRecorder()
	captured := &statusCapturingWriter{
		ResponseWriter: rr,
		statusCode:     http.StatusOK,
	}

	// First call should set status
	captured.WriteHeader(http.StatusNotFound)
	if captured.statusCode != http.StatusNotFound {
		t.Errorf("statusCode = %d, want %d", captured.statusCode, http.StatusNotFound)
	}

	// Second call should not change status (handler calls WriteHeader multiple times)
	captured.WriteHeader(http.StatusOK)
	if captured.statusCode != http.StatusNotFound {
		t.Errorf("statusCode = %d, want %d (should not change)", captured.statusCode, http.StatusNotFound)
	}
}

// TestStatusCapturingWriter_WriteSetStatus tests that Write sets status if WriteHeader wasn't called
func TestStatusCapturingWriter_WriteSetStatus(t *testing.T) {
	rr := httptest.NewRecorder()
	captured := &statusCapturingWriter{
		ResponseWriter: rr,
		statusCode:     0, // unset
	}

	// Write without WriteHeader should set 200
	_, err := captured.Write([]byte("test"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if captured.statusCode != http.StatusOK {
		t.Errorf("statusCode = %d, want %d", captured.statusCode, http.StatusOK)
	}
}

// TestGetTokenIDFromContext tests the context helper function
func TestGetTokenIDFromContext(t *testing.T) {
	tests := []struct {
		name     string
		tokenID  interface{}
		setInCtx bool
		want     int64
	}{
		{
			name:     "valid token ID",
			tokenID:  int64(123),
			setInCtx: true,
			want:     123,
		},
		{
			name:     "no token ID in context",
			setInCtx: false,
			want:     0,
		},
		{
			name:     "wrong type in context",
			tokenID:  "not-an-int64",
			setInCtx: true,
			want:     0,
		},
		{
			name:     "zero token ID",
			tokenID:  int64(0),
			setInCtx: true,
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.setInCtx {
				ctx := context.WithValue(req.Context(), ContextKeyTokenID, tt.tokenID)
				req = req.WithContext(ctx)
			}

			result := GetTokenIDFromContext(req)
			if result != tt.want {
				t.Errorf("GetTokenIDFromContext() = %d, want %d", result, tt.want)
			}
		})
	}
}

// TestAPITokenAuditLog_MultipleRequests tests logging multiple requests
func TestAPITokenAuditLog_MultipleRequests(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Create user and API token
	passwordHash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	tokenPlaintext, tokenPrefix, err := utils.GenerateAPIToken()
	if err != nil {
		t.Fatalf("failed to generate API token: %v", err)
	}
	tokenHash := utils.HashAPIToken(tokenPlaintext)
	token, err := repos.APITokens.Create(ctx, user.ID, "test-token", tokenHash, tokenPrefix, "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("failed to create API token: %v", err)
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	auditHandler := APITokenAuditLog(repos)(testHandler)

	// Make multiple requests to different endpoints
	endpoints := []string{"/api/user/files", "/api/upload", "/api/user/tokens"}
	for _, endpoint := range endpoints {
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)
		req = req.WithContext(context.WithValue(req.Context(), ContextKeyTokenID, token.ID))
		rr := httptest.NewRecorder()
		auditHandler.ServeHTTP(rr, req)
	}

	// Wait for async logging
	time.Sleep(200 * time.Millisecond)

	// Verify all requests were logged
	filter := repository.UsageFilter{Limit: 10, Offset: 0}
	logs, total, err := repos.APITokens.GetUsageLogs(ctx, token.ID, filter)
	if err != nil {
		t.Fatalf("failed to get usage logs: %v", err)
	}

	if total != 3 {
		t.Errorf("total logs = %d, want 3", total)
	}

	if len(logs) != 3 {
		t.Errorf("returned logs = %d, want 3", len(logs))
	}

	// Verify each endpoint was logged (logs are in reverse chronological order)
	foundEndpoints := make(map[string]bool)
	for _, log := range logs {
		foundEndpoints[log.Endpoint] = true
	}

	for _, endpoint := range endpoints {
		if !foundEndpoints[endpoint] {
			t.Errorf("endpoint %q not found in logs", endpoint)
		}
	}
}
