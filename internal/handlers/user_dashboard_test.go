package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// TestUserDeleteFileHandler_Success tests successful file deletion
func TestUserDeleteFileHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserDeleteFileHandler(db, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", passwordHash, "user", false)

	// Create file owned by user
	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "test-claim-delete"
	if err := database.CreateFile(db, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Get the file back to get its ID
	createdFile, err := database.GetFileByClaimCode(db, file.ClaimCode)
	if err != nil || createdFile == nil {
		t.Fatalf("failed to retrieve created file: %v", err)
	}

	// Create physical file
	os.MkdirAll(cfg.UploadDir, 0755)
	physicalPath := filepath.Join(cfg.UploadDir, createdFile.StoredFilename)
	os.WriteFile(physicalPath, []byte("test content"), 0644)

	// Delete file request
	deleteReq := map[string]int64{
		"file_id": createdFile.ID,
	}

	body, _ := json.Marshal(deleteReq)
	req := httptest.NewRequest(http.MethodDelete, "/api/user/files/delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Add user to context
	ctx := context.WithValue(req.Context(), "user", user)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp["message"] != "File deleted successfully" {
		t.Errorf("message = %q, want File deleted successfully", resp["message"])
	}

	// Verify file no longer exists in database
	deletedFile, _ := database.GetFileByClaimCode(db, createdFile.ClaimCode)
	if deletedFile != nil {
		t.Error("file should be deleted from database")
	}

	// Verify physical file is deleted
	if _, err := os.Stat(physicalPath); !os.IsNotExist(err) {
		t.Error("physical file should be deleted")
	}
}

// TestUserDeleteFileHandler_NotOwner tests that users can't delete files they don't own
func TestUserDeleteFileHandler_NotOwner(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserDeleteFileHandler(db, cfg)

	// Create two users
	passwordHash, _ := utils.HashPassword("password123")
	user1, _ := database.CreateUser(db, "user1", "user1@example.com", passwordHash, "user", false)
	user2, _ := database.CreateUser(db, "user2", "user2@example.com", passwordHash, "user", false)

	// Create file owned by user1
	file := testutil.SampleFile()
	file.UserID = &user1.ID
	file.ClaimCode = "user1-file"
	database.CreateFile(db, file)

	createdFile, _ := database.GetFileByClaimCode(db, file.ClaimCode)

	// Try to delete as user2
	deleteReq := map[string]int64{
		"file_id": createdFile.ID,
	}

	body, _ := json.Marshal(deleteReq)
	req := httptest.NewRequest(http.MethodDelete, "/api/user/files/delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Add user2 to context
	ctx := context.WithValue(req.Context(), "user", user2)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "File not found or does not belong to you" {
		t.Errorf("error = %q, want ownership error", errResp["error"])
	}

	// Verify file still exists
	existingFile, _ := database.GetFileByClaimCode(db, createdFile.ClaimCode)
	if existingFile == nil {
		t.Error("file should not be deleted")
	}
}

// TestUserDeleteFileHandler_FileNotFound tests deleting non-existent file
func TestUserDeleteFileHandler_FileNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserDeleteFileHandler(db, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", passwordHash, "user", false)

	// Try to delete non-existent file
	deleteReq := map[string]int64{
		"file_id": 99999,
	}

	body, _ := json.Marshal(deleteReq)
	req := httptest.NewRequest(http.MethodDelete, "/api/user/files/delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.WithValue(req.Context(), "user", user)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

// TestUserDeleteFileHandler_InvalidFileID tests invalid file ID validation
func TestUserDeleteFileHandler_InvalidFileID(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserDeleteFileHandler(db, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", passwordHash, "user", false)

	tests := []struct {
		name   string
		fileID int64
	}{
		{"zero file ID", 0},
		{"negative file ID", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deleteReq := map[string]int64{
				"file_id": tt.fileID,
			}

			body, _ := json.Marshal(deleteReq)
			req := httptest.NewRequest(http.MethodDelete, "/api/user/files/delete", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			ctx := context.WithValue(req.Context(), "user", user)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

			var errResp map[string]string
			json.Unmarshal(rr.Body.Bytes(), &errResp)

			if errResp["error"] != "Invalid file ID" {
				t.Errorf("error = %q, want Invalid file ID", errResp["error"])
			}
		})
	}
}

// TestUserDeleteFileHandler_InvalidJSON tests malformed request handling
func TestUserDeleteFileHandler_InvalidJSON(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserDeleteFileHandler(db, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", passwordHash, "user", false)

	req := httptest.NewRequest(http.MethodDelete, "/api/user/files/delete", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.WithValue(req.Context(), "user", user)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

// TestUserDeleteFileHandler_MethodNotAllowed tests HTTP method validation
func TestUserDeleteFileHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserDeleteFileHandler(db, cfg)

	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/user/files/delete", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// TestUserDeleteFileHandler_PhysicalFileMissing tests graceful handling when physical file is missing
func TestUserDeleteFileHandler_PhysicalFileMissing(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserDeleteFileHandler(db, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", passwordHash, "user", false)

	// Create file in database but not on disk
	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "orphan-file"
	database.CreateFile(db, file)

	createdFile, _ := database.GetFileByClaimCode(db, file.ClaimCode)

	// Delete file request
	deleteReq := map[string]int64{
		"file_id": createdFile.ID,
	}

	body, _ := json.Marshal(deleteReq)
	req := httptest.NewRequest(http.MethodDelete, "/api/user/files/delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.WithValue(req.Context(), "user", user)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should still succeed even if physical file is missing
	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Database record should be deleted
	deletedFile, _ := database.GetFileByClaimCode(db, createdFile.ClaimCode)
	if deletedFile != nil {
		t.Error("file should be deleted from database")
	}
}

// TestUserDashboardDataHandler_Pagination tests pagination parameters
func TestUserDashboardDataHandler_Pagination(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserDashboardDataHandler(db, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", passwordHash, "user", false)

	// Create 25 test files
	for i := 0; i < 25; i++ {
		file := testutil.SampleFile()
		file.UserID = &user.ID
		file.ClaimCode = fmt.Sprintf("claim-%d", i)
		database.CreateFile(db, file)
	}

	tests := []struct {
		name          string
		limit         string
		offset        string
		expectedLimit int
		expectedCount int
	}{
		{"default", "", "", 50, 25},
		{"limit 10", "10", "0", 10, 10},
		{"limit 10 offset 10", "10", "10", 10, 10},
		{"limit 10 offset 20", "10", "20", 10, 5},
		{"invalid limit", "invalid", "0", 50, 25},
		{"too large limit", "200", "0", 50, 25},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/api/user/files"
			if tt.limit != "" || tt.offset != "" {
				url += "?"
				if tt.limit != "" {
					url += "limit=" + tt.limit
				}
				if tt.offset != "" && tt.limit != "" {
					url += "&"
				}
				if tt.offset != "" {
					url += "offset=" + tt.offset
				}
			}

			req := httptest.NewRequest(http.MethodGet, url, nil)
			ctx := context.WithValue(req.Context(), "user", user)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusOK)

			var resp map[string]interface{}
			json.Unmarshal(rr.Body.Bytes(), &resp)

			if int(resp["limit"].(float64)) != tt.expectedLimit {
				t.Errorf("limit = %v, want %d", resp["limit"], tt.expectedLimit)
			}

			files := resp["files"].([]interface{})
			if len(files) != tt.expectedCount {
				t.Errorf("file count = %d, want %d", len(files), tt.expectedCount)
			}
		})
	}
}

// TestUserDashboardDataHandler_EmptyFileList tests user with no files
func TestUserDashboardDataHandler_EmptyFileList(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserDashboardDataHandler(db, cfg)

	// Create user with no files
	passwordHash, _ := utils.HashPassword("password123")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", passwordHash, "user", false)

	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	ctx := context.WithValue(req.Context(), "user", user)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if int(resp["total"].(float64)) != 0 {
		t.Errorf("total = %v, want 0", resp["total"])
	}

	files := resp["files"].([]interface{})
	if len(files) != 0 {
		t.Errorf("files count = %d, want 0", len(files))
	}
}

// TestUserDashboardDataHandler_MethodNotAllowed tests HTTP method validation
func TestUserDashboardDataHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserDashboardDataHandler(db, cfg)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/user/files", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// TestUserDashboardDataHandler_FileFields tests response includes expected fields
func TestUserDashboardDataHandler_FileFields(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserDashboardDataHandler(db, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", passwordHash, "user", false)

	// Create file with known values
	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "test-claim-123"
	file.OriginalFilename = "test-file.txt"
	maxDownloads := 5
	file.MaxDownloads = &maxDownloads
	database.CreateFile(db, file)

	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	ctx := context.WithValue(req.Context(), "user", user)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)

	files := resp["files"].([]interface{})
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}

	fileData := files[0].(map[string]interface{})

	// Check required fields
	requiredFields := []string{
		"id", "claim_code", "original_filename", "file_size", "mime_type",
		"created_at", "expires_at", "max_downloads", "download_count",
		"download_url", "is_expired", "is_password_protected",
	}

	for _, field := range requiredFields {
		if _, exists := fileData[field]; !exists {
			t.Errorf("missing required field: %s", field)
		}
	}

	// Verify specific values
	if fileData["claim_code"] != "test-claim-123" {
		t.Errorf("claim_code = %v, want test-claim-123", fileData["claim_code"])
	}

	if fileData["original_filename"] != "test-file.txt" {
		t.Errorf("original_filename = %v, want test-file.txt", fileData["original_filename"])
	}

	if int(fileData["max_downloads"].(float64)) != 5 {
		t.Errorf("max_downloads = %v, want 5", fileData["max_downloads"])
	}

	// download_url should contain claim code
	downloadURL := fileData["download_url"].(string)
	if downloadURL == "" {
		t.Error("download_url should not be empty")
	}
}
