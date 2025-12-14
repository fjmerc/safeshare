package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
)

func setupTokenUsageTestDB(t *testing.T) (*sql.DB, *repository.Repositories) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("Failed to create repositories: %v", err)
	}

	return db, repos
}

func createTestUserAndToken(t *testing.T, db *sql.DB) (int64, int64) {
	// Create a test user
	result, err := db.Exec(`
		INSERT INTO users (username, email, password_hash, role, is_active)
		VALUES (?, ?, ?, ?, ?)
	`, "testuser", "test@example.com", "hashedpassword", "user", true)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	userID, _ := result.LastInsertId()

	// Create a test token with valid hash (64 hex chars for SHA-256)
	tokenHash := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	result, err = db.Exec(`
		INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, scopes, created_ip, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, userID, "Test Token", tokenHash, "safeshare_test12", "files:read,files:write", "127.0.0.1", true)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}
	tokenID, _ := result.LastInsertId()

	return userID, tokenID
}

func createTokenUsageLogs(t *testing.T, db *sql.DB, tokenID int64, count int) {
	for i := 0; i < count; i++ {
		_, err := db.Exec(`
			INSERT INTO api_token_usage (token_id, endpoint, ip_address, user_agent, response_status, timestamp)
			VALUES (?, ?, ?, ?, ?, ?)
		`, tokenID, "/api/upload", "127.0.0.1", "TestAgent", 200, time.Now().Add(-time.Duration(i)*time.Hour).Format(time.RFC3339))
		if err != nil {
			t.Fatalf("Failed to create usage log: %v", err)
		}
	}
}

func TestAdminGetTokenUsageHandler_Success(t *testing.T) {
	db, repos := setupTokenUsageTestDB(t)

	_, tokenID := createTestUserAndToken(t, db)
	createTokenUsageLogs(t, db, tokenID, 5)

	handler := AdminGetTokenUsageHandler(repos)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/api/tokens/%d/usage", tokenID), nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response models.APITokenUsageResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.TokenID != tokenID {
		t.Errorf("Expected token_id %d, got %d", tokenID, response.TokenID)
	}
	if response.Total != 5 {
		t.Errorf("Expected total 5, got %d", response.Total)
	}
}

func TestAdminGetTokenUsageHandler_MethodNotAllowed(t *testing.T) {
	_, repos := setupTokenUsageTestDB(t)

	handler := AdminGetTokenUsageHandler(repos)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/tokens/1/usage", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestAdminGetTokenUsageHandler_InvalidPath(t *testing.T) {
	_, repos := setupTokenUsageTestDB(t)

	handler := AdminGetTokenUsageHandler(repos)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/tokens/invalid/usage", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestAdminGetTokenUsageHandler_TokenNotFound(t *testing.T) {
	_, repos := setupTokenUsageTestDB(t)

	handler := AdminGetTokenUsageHandler(repos)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/tokens/99999/usage", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestAdminGetTokenUsageHandler_WithPagination(t *testing.T) {
	db, repos := setupTokenUsageTestDB(t)

	_, tokenID := createTestUserAndToken(t, db)
	createTokenUsageLogs(t, db, tokenID, 20)

	handler := AdminGetTokenUsageHandler(repos)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/api/tokens/%d/usage?limit=5&offset=0", tokenID), nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response models.APITokenUsageResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Limit != 5 {
		t.Errorf("Expected limit 5, got %d", response.Limit)
	}
	if response.Offset != 0 {
		t.Errorf("Expected offset 0, got %d", response.Offset)
	}
	if len(response.Usage) > 5 {
		t.Errorf("Expected max 5 items, got %d", len(response.Usage))
	}
}

func TestAdminGetTokenUsageHandler_WithDateFilters(t *testing.T) {
	db, repos := setupTokenUsageTestDB(t)

	_, tokenID := createTestUserAndToken(t, db)
	createTokenUsageLogs(t, db, tokenID, 5)

	handler := AdminGetTokenUsageHandler(repos)

	startDate := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	endDate := time.Now().Add(time.Hour).Format(time.RFC3339)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/api/tokens/%d/usage?start_date=%s&end_date=%s", tokenID, startDate, endDate), nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestAdminGetTokenUsageHandler_InvalidStartDate(t *testing.T) {
	db, repos := setupTokenUsageTestDB(t)

	_, tokenID := createTestUserAndToken(t, db)

	handler := AdminGetTokenUsageHandler(repos)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/api/tokens/%d/usage?start_date=invalid-date", tokenID), nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestAdminGetTokenUsageHandler_InvalidEndDate(t *testing.T) {
	db, repos := setupTokenUsageTestDB(t)

	_, tokenID := createTestUserAndToken(t, db)

	handler := AdminGetTokenUsageHandler(repos)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/api/tokens/%d/usage?end_date=invalid-date", tokenID), nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestAdminGetTokenUsageHandler_InvalidDateRange(t *testing.T) {
	db, repos := setupTokenUsageTestDB(t)

	_, tokenID := createTestUserAndToken(t, db)

	handler := AdminGetTokenUsageHandler(repos)

	// Start date after end date
	startDate := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	endDate := time.Now().Format(time.RFC3339)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/api/tokens/%d/usage?start_date=%s&end_date=%s", tokenID, startDate, endDate), nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestAdminGetTokenUsageHandler_DateOnlyFormat(t *testing.T) {
	db, repos := setupTokenUsageTestDB(t)

	_, tokenID := createTestUserAndToken(t, db)
	createTokenUsageLogs(t, db, tokenID, 5)

	handler := AdminGetTokenUsageHandler(repos)

	// Use date-only format (YYYY-MM-DD)
	startDate := time.Now().Add(-24 * time.Hour).Format("2006-01-02")
	endDate := time.Now().Format("2006-01-02")

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/api/tokens/%d/usage?start_date=%s&end_date=%s", tokenID, startDate, endDate), nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestAdminGetTokenUsageHandler_MaxLimit(t *testing.T) {
	db, repos := setupTokenUsageTestDB(t)

	_, tokenID := createTestUserAndToken(t, db)

	handler := AdminGetTokenUsageHandler(repos)

	// Request with limit exceeding max - should be capped to maxUsageLimit (1000)
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/api/tokens/%d/usage?limit=5000", tokenID), nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response models.APITokenUsageResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Limit != maxUsageLimit {
		t.Errorf("Expected limit to be capped at %d, got %d", maxUsageLimit, response.Limit)
	}
}

func TestAdminGetTokenUsageHandler_MaxOffset(t *testing.T) {
	db, repos := setupTokenUsageTestDB(t)

	_, tokenID := createTestUserAndToken(t, db)

	handler := AdminGetTokenUsageHandler(repos)

	// Request with offset exceeding max - should be capped to maxUsageOffset (100000)
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/api/tokens/%d/usage?offset=500000", tokenID), nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response models.APITokenUsageResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Offset != maxUsageOffset {
		t.Errorf("Expected offset to be capped at %d, got %d", maxUsageOffset, response.Offset)
	}
}

func TestAdminGetTokenUsageHandler_EmptyUsage(t *testing.T) {
	db, repos := setupTokenUsageTestDB(t)

	_, tokenID := createTestUserAndToken(t, db)
	// Don't create any usage logs

	handler := AdminGetTokenUsageHandler(repos)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/api/tokens/%d/usage", tokenID), nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response models.APITokenUsageResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Should return empty array, not nil
	if response.Usage == nil {
		t.Error("Expected non-nil usage array")
	}
	if len(response.Usage) != 0 {
		t.Errorf("Expected empty usage array, got %d items", len(response.Usage))
	}
}

func TestIsTokenUsagePath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/admin/api/tokens/1/usage", true},
		{"/admin/api/tokens/123/usage", true},
		{"/admin/api/tokens/999999/usage", true},
		{"/admin/api/tokens/1/usage/", true},
		{"/admin/api/tokens/abc/usage", false},
		{"/admin/api/tokens/1/usage/extra", false},
		{"/admin/api/tokens//usage", false},
		{"/admin/api/tokens/usage", false},
		{"/api/tokens/1/usage", false},
	}

	for _, tc := range tests {
		result := IsTokenUsagePath(tc.path)
		if result != tc.expected {
			t.Errorf("IsTokenUsagePath(%q) = %v, expected %v", tc.path, result, tc.expected)
		}
	}
}

func TestAdminGetTokenUsageHandler_InvalidTokenID(t *testing.T) {
	_, repos := setupTokenUsageTestDB(t)

	handler := AdminGetTokenUsageHandler(repos)

	// Token ID of 0 should be invalid
	req := httptest.NewRequest(http.MethodGet, "/admin/api/tokens/0/usage", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for token ID 0, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestAdminGetTokenUsageHandler_NegativeTokenID(t *testing.T) {
	_, repos := setupTokenUsageTestDB(t)

	handler := AdminGetTokenUsageHandler(repos)

	// Negative token ID - path won't match regex
	req := httptest.NewRequest(http.MethodGet, "/admin/api/tokens/-1/usage", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for negative token ID, got %d", http.StatusBadRequest, w.Code)
	}
}
