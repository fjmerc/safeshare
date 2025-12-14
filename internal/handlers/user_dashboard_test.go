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

	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// TestUserDeleteFileHandler_Success tests successful file deletion
func TestUserDeleteFileHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserDeleteFileHandler(repos, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create file owned by user
	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "test-claim-delete"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Get the file back to get its ID
	createdFile, err := repos.Files.GetByClaimCode(ctx, file.ClaimCode)
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
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp["message"] != "File deleted successfully" {
		t.Errorf("message = %q, want File deleted successfully", resp["message"])
	}

	// Verify file no longer exists in database
	deletedFile, _ := repos.Files.GetByClaimCode(ctx, createdFile.ClaimCode)
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
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserDeleteFileHandler(repos, cfg)

	// Create two users
	passwordHash, _ := utils.HashPassword("password123")
	user1, err := repos.Users.Create(ctx, "user1", "user1@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user1: %v", err)
	}
	user2, err := repos.Users.Create(ctx, "user2", "user2@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user2: %v", err)
	}

	// Create file owned by user1
	file := testutil.SampleFile()
	file.UserID = &user1.ID
	file.ClaimCode = "user1-file"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	createdFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)

	// Try to delete as user2
	deleteReq := map[string]int64{
		"file_id": createdFile.ID,
	}

	body, _ := json.Marshal(deleteReq)
	req := httptest.NewRequest(http.MethodDelete, "/api/user/files/delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Add user2 to context
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user2)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "File not found or does not belong to you" {
		t.Errorf("error = %q, want ownership error", errResp["error"])
	}

	// Verify file still exists
	existingFile, _ := repos.Files.GetByClaimCode(ctx, createdFile.ClaimCode)
	if existingFile == nil {
		t.Error("file should not be deleted")
	}
}

// TestUserDeleteFileHandler_FileNotFound tests deleting non-existent file
func TestUserDeleteFileHandler_FileNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserDeleteFileHandler(repos, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Try to delete non-existent file
	deleteReq := map[string]int64{
		"file_id": 99999,
	}

	body, _ := json.Marshal(deleteReq)
	req := httptest.NewRequest(http.MethodDelete, "/api/user/files/delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

// TestUserDeleteFileHandler_InvalidFileID tests invalid file ID validation
func TestUserDeleteFileHandler_InvalidFileID(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserDeleteFileHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

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

			reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
			req = req.WithContext(reqCtx)

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
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserDeleteFileHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/user/files/delete", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

// TestUserDeleteFileHandler_MethodNotAllowed tests HTTP method validation
func TestUserDeleteFileHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := UserDeleteFileHandler(repos, cfg)

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
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserDeleteFileHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create file in database but not on disk
	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "orphan-file"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	createdFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)

	// Delete file request
	deleteReq := map[string]int64{
		"file_id": createdFile.ID,
	}

	body, _ := json.Marshal(deleteReq)
	req := httptest.NewRequest(http.MethodDelete, "/api/user/files/delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should still succeed even if physical file is missing
	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Database record should be deleted
	deletedFile, _ := repos.Files.GetByClaimCode(ctx, createdFile.ClaimCode)
	if deletedFile != nil {
		t.Error("file should be deleted from database")
	}
}

// TestUserDashboardDataHandler_Pagination tests pagination parameters
func TestUserDashboardDataHandler_Pagination(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserDashboardDataHandler(repos, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create 25 test files
	for i := 0; i < 25; i++ {
		file := testutil.SampleFile()
		file.UserID = &user.ID
		file.ClaimCode = fmt.Sprintf("claim-%d", i)
		if err := repos.Files.Create(ctx, file); err != nil {
			t.Fatalf("failed to create file %d: %v", i, err)
		}
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
			reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
			req = req.WithContext(reqCtx)

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
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserDashboardDataHandler(repos, cfg)

	// Create user with no files
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

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
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := UserDashboardDataHandler(repos, cfg)

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
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserDashboardDataHandler(repos, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create file with known values
	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "test-claim-123"
	file.OriginalFilename = "test-file.txt"
	maxDownloads := 5
	file.MaxDownloads = &maxDownloads
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

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

// TestUserRenameFileHandler_Success tests successful file rename
func TestUserRenameFileHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserRenameFileHandler(repos, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create file owned by user
	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "test-rename-success"
	file.OriginalFilename = "oldname.txt"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	createdFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)

	// Rename file request
	renameReq := map[string]interface{}{
		"file_id":      createdFile.ID,
		"new_filename": "newname.txt",
	}

	body, _ := json.Marshal(renameReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/rename", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp["message"] != "File renamed successfully" {
		t.Errorf("message = %q, want 'File renamed successfully'", resp["message"])
	}

	if resp["new_filename"] != "newname.txt" {
		t.Errorf("new_filename = %q, want 'newname.txt'", resp["new_filename"])
	}

	// Verify file was renamed in database
	updatedFile, _ := repos.Files.GetByClaimCode(ctx, createdFile.ClaimCode)
	if updatedFile.OriginalFilename != "newname.txt" {
		t.Errorf("file not renamed in database, got %q", updatedFile.OriginalFilename)
	}
}

// TestUserRenameFileHandler_NotOwner tests that users can't rename files they don't own
func TestUserRenameFileHandler_NotOwner(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserRenameFileHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user1, err := repos.Users.Create(ctx, "user1", "user1@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user1: %v", err)
	}
	user2, err := repos.Users.Create(ctx, "user2", "user2@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user2: %v", err)
	}

	// Create file owned by user1
	file := testutil.SampleFile()
	file.UserID = &user1.ID
	file.ClaimCode = "user1-file-rename"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	createdFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)

	// Try to rename as user2
	renameReq := map[string]interface{}{
		"file_id":      createdFile.ID,
		"new_filename": "hacked.txt",
	}

	body, _ := json.Marshal(renameReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/rename", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user2)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "File not found or does not belong to you" {
		t.Errorf("error = %q, want ownership error", errResp["error"])
	}

	// Verify file was NOT renamed
	unchangedFile, _ := repos.Files.GetByClaimCode(ctx, createdFile.ClaimCode)
	if unchangedFile.OriginalFilename == "hacked.txt" {
		t.Error("file should not have been renamed")
	}
}

// TestUserRenameFileHandler_FileNotFound tests renaming non-existent file
func TestUserRenameFileHandler_FileNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserRenameFileHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	renameReq := map[string]interface{}{
		"file_id":      int64(99999),
		"new_filename": "newname.txt",
	}

	body, _ := json.Marshal(renameReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/rename", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

// TestUserRenameFileHandler_InvalidFileID tests invalid file ID validation
func TestUserRenameFileHandler_InvalidFileID(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserRenameFileHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	tests := []struct {
		name   string
		fileID int64
	}{
		{"zero file ID", 0},
		{"negative file ID", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			renameReq := map[string]interface{}{
				"file_id":      tt.fileID,
				"new_filename": "newname.txt",
			}

			body, _ := json.Marshal(renameReq)
			req := httptest.NewRequest(http.MethodPut, "/api/user/files/rename", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
			req = req.WithContext(reqCtx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

			var errResp map[string]string
			json.Unmarshal(rr.Body.Bytes(), &errResp)

			if errResp["error"] != "Invalid file ID" {
				t.Errorf("error = %q, want 'Invalid file ID'", errResp["error"])
			}
		})
	}
}

// TestUserRenameFileHandler_EmptyFilename tests empty filename validation
func TestUserRenameFileHandler_EmptyFilename(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserRenameFileHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	renameReq := map[string]interface{}{
		"file_id":      int64(1),
		"new_filename": "",
	}

	body, _ := json.Marshal(renameReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/rename", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "Filename cannot be empty" {
		t.Errorf("error = %q, want 'Filename cannot be empty'", errResp["error"])
	}
}

// TestUserRenameFileHandler_InvalidJSON tests malformed request handling
func TestUserRenameFileHandler_InvalidJSON(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserRenameFileHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/user/files/rename", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

// TestUserRenameFileHandler_MethodNotAllowed tests HTTP method validation
func TestUserRenameFileHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := UserRenameFileHandler(repos, cfg)

	methods := []string{http.MethodGet, http.MethodPost, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/user/files/rename", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// TestUserRenameFileHandler_SanitizationWorks tests filename sanitization
func TestUserRenameFileHandler_SanitizationWorks(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserRenameFileHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "test-sanitize"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	createdFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)

	// Try to rename with dangerous characters
	renameReq := map[string]interface{}{
		"file_id":      createdFile.ID,
		"new_filename": "../../../etc/passwd",
	}

	body, _ := json.Marshal(renameReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/rename", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)

	// Should be sanitized to "passwd" (path components removed)
	if resp["new_filename"] != "passwd" {
		t.Errorf("new_filename = %q, want 'passwd' (sanitized)", resp["new_filename"])
	}

	// Verify in database
	updatedFile, _ := repos.Files.GetByClaimCode(ctx, createdFile.ClaimCode)
	if updatedFile.OriginalFilename != "passwd" {
		t.Errorf("filename in database = %q, want 'passwd'", updatedFile.OriginalFilename)
	}
}

// ========== Edit Expiration Tests ==========

// TestUserEditExpirationHandler_Success tests successful expiration update
func TestUserEditExpirationHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserEditExpirationHandler(repos, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create file owned by user
	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "test-edit-expiration-success"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	createdFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)

	// New expiration: 24 hours from now (well within MAX_EXPIRATION_HOURS)
	newExpiration := testutil.TimeNow().Add(24 * testutil.TimeHour)

	// Edit expiration request
	editReq := map[string]interface{}{
		"file_id":        createdFile.ID,
		"new_expiration": newExpiration.Format(testutil.TimeRFC3339),
	}

	body, _ := json.Marshal(editReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/update-expiration", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp["message"] != "File expiration updated successfully" {
		t.Errorf("message = %q, want 'File expiration updated successfully'", resp["message"])
	}

	// Verify file expiration was updated in database
	updatedFile, _ := repos.Files.GetByClaimCode(ctx, createdFile.ClaimCode)
	if updatedFile.ExpiresAt.Unix() != newExpiration.Unix() {
		t.Errorf("expiration not updated in database, got %v, want %v", updatedFile.ExpiresAt, newExpiration)
	}
}

// TestUserEditExpirationHandler_NotOwner tests that users can't edit files they don't own
func TestUserEditExpirationHandler_NotOwner(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserEditExpirationHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user1, err := repos.Users.Create(ctx, "user1", "user1@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user1: %v", err)
	}
	user2, err := repos.Users.Create(ctx, "user2", "user2@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user2: %v", err)
	}

	// Create file owned by user1
	file := testutil.SampleFile()
	file.UserID = &user1.ID
	file.ClaimCode = "user1-file-edit-expiration"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	createdFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)

	// Try to edit expiration as user2
	newExpiration := testutil.TimeNow().Add(24 * testutil.TimeHour)
	editReq := map[string]interface{}{
		"file_id":        createdFile.ID,
		"new_expiration": newExpiration.Format(testutil.TimeRFC3339),
	}

	body, _ := json.Marshal(editReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/update-expiration", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user2)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "File not found or does not belong to you" {
		t.Errorf("error = %q, want ownership error", errResp["error"])
	}
}

// TestUserEditExpirationHandler_FileNotFound tests invalid file ID
func TestUserEditExpirationHandler_FileNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserEditExpirationHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Try to edit non-existent file
	newExpiration := testutil.TimeNow().Add(24 * testutil.TimeHour)
	editReq := map[string]interface{}{
		"file_id":        99999,
		"new_expiration": newExpiration.Format(testutil.TimeRFC3339),
	}

	body, _ := json.Marshal(editReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/update-expiration", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "File not found or does not belong to you" {
		t.Errorf("error = %q, want not found error", errResp["error"])
	}
}

// TestUserEditExpirationHandler_InvalidDate tests malformed date
func TestUserEditExpirationHandler_InvalidDate(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserEditExpirationHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "test-invalid-date"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	createdFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)

	// Invalid date format
	editReq := map[string]interface{}{
		"file_id":        createdFile.ID,
		"new_expiration": "not-a-date",
	}

	body, _ := json.Marshal(editReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/update-expiration", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "Invalid date format" {
		t.Errorf("error = %q, want 'Invalid date format'", errResp["error"])
	}
}

// TestUserEditExpirationHandler_PastDate tests expiration in the past
func TestUserEditExpirationHandler_PastDate(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserEditExpirationHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "test-past-date"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	createdFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)

	// Past date
	pastDate := testutil.TimeNow().Add(-24 * testutil.TimeHour)
	editReq := map[string]interface{}{
		"file_id":        createdFile.ID,
		"new_expiration": pastDate.Format(testutil.TimeRFC3339),
	}

	body, _ := json.Marshal(editReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/update-expiration", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "Expiration date must be in the future" {
		t.Errorf("error = %q, want 'Expiration date must be in the future'", errResp["error"])
	}
}

// TestUserEditExpirationHandler_ExceedsMax tests expiration beyond max allowed
func TestUserEditExpirationHandler_ExceedsMax(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.SetMaxExpirationHours(168) // 7 days
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserEditExpirationHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "test-exceeds-max"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	createdFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)

	// Date beyond max (8 days from now)
	tooFarDate := testutil.TimeNow().Add(200 * testutil.TimeHour)
	editReq := map[string]interface{}{
		"file_id":        createdFile.ID,
		"new_expiration": tooFarDate.Format(testutil.TimeRFC3339),
	}

	body, _ := json.Marshal(editReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/update-expiration", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	expectedError := fmt.Sprintf("Expiration cannot be more than %d hours from now", cfg.GetMaxExpirationHours())
	if errResp["error"] != expectedError {
		t.Errorf("error = %q, want %q", errResp["error"], expectedError)
	}
}

// TestUserEditExpirationHandler_EmptyExpiration tests empty expiration
func TestUserEditExpirationHandler_EmptyExpiration(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserEditExpirationHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "test-empty-expiration"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	createdFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)

	// Empty expiration
	editReq := map[string]interface{}{
		"file_id":        createdFile.ID,
		"new_expiration": "",
	}

	body, _ := json.Marshal(editReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/update-expiration", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "Expiration date cannot be empty" {
		t.Errorf("error = %q, want 'Expiration date cannot be empty'", errResp["error"])
	}
}

// TestUserRegenerateClaimCodeHandler_Success tests successful claim code regeneration
func TestUserRegenerateClaimCodeHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserRegenerateClaimCodeHandler(repos, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create file owned by user
	file := testutil.SampleFile()
	file.UserID = &user.ID
	file.ClaimCode = "original-claim-code"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	createdFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)
	originalClaimCode := createdFile.ClaimCode

	// Regenerate claim code request
	regenReq := map[string]int64{
		"file_id": createdFile.ID,
	}

	body, _ := json.Marshal(regenReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/regenerate-claim-code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp["message"] != "Claim code regenerated successfully" {
		t.Errorf("message = %q, want 'Claim code regenerated successfully'", resp["message"])
	}

	// Verify new claim code is different from original
	newClaimCode := resp["claim_code"]
	if newClaimCode == "" {
		t.Error("new claim_code should not be empty")
	}
	if newClaimCode == originalClaimCode {
		t.Error("new claim_code should be different from original")
	}

	// Verify download URL is present
	if resp["download_url"] == "" {
		t.Error("download_url should not be empty")
	}

	// Verify claim code was updated in database
	updatedFile, _ := repos.Files.GetByClaimCode(ctx, newClaimCode)
	if updatedFile == nil {
		t.Fatal("should be able to retrieve file with new claim code")
	}
	if updatedFile.ClaimCode != newClaimCode {
		t.Errorf("claim code in database = %q, want %q", updatedFile.ClaimCode, newClaimCode)
	}

	// Verify old claim code no longer works
	oldFile, _ := repos.Files.GetByClaimCode(ctx, originalClaimCode)
	if oldFile != nil {
		t.Error("old claim code should not retrieve file")
	}
}

// TestUserRegenerateClaimCodeHandler_MethodNotAllowed tests non-PUT methods are rejected
func TestUserRegenerateClaimCodeHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserRegenerateClaimCodeHandler(repos, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Try GET method (should fail)
	req := httptest.NewRequest(http.MethodGet, "/api/user/files/regenerate-claim-code", nil)
	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
}

// TestUserRegenerateClaimCodeHandler_InvalidJSON tests malformed JSON is rejected
func TestUserRegenerateClaimCodeHandler_InvalidJSON(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserRegenerateClaimCodeHandler(repos, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Send invalid JSON
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/regenerate-claim-code", bytes.NewReader([]byte("{invalid json")))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "Invalid request format" {
		t.Errorf("error = %q, want 'Invalid request format'", errResp["error"])
	}
}

// TestUserRegenerateClaimCodeHandler_InvalidFileID tests invalid file ID is rejected
func TestUserRegenerateClaimCodeHandler_InvalidFileID(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserRegenerateClaimCodeHandler(repos, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Test with file_id = 0
	regenReq := map[string]int64{
		"file_id": 0,
	}

	body, _ := json.Marshal(regenReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/regenerate-claim-code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "Invalid file ID" {
		t.Errorf("error = %q, want 'Invalid file ID'", errResp["error"])
	}
}

// TestUserRegenerateClaimCodeHandler_FileNotFound tests non-existent file returns 404
func TestUserRegenerateClaimCodeHandler_FileNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserRegenerateClaimCodeHandler(repos, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Try to regenerate claim code for non-existent file
	regenReq := map[string]int64{
		"file_id": 99999,
	}

	body, _ := json.Marshal(regenReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/regenerate-claim-code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "File not found or access denied" {
		t.Errorf("error = %q, want 'File not found or access denied'", errResp["error"])
	}
}

// TestUserRegenerateClaimCodeHandler_NotOwner tests users can't regenerate claim codes for files they don't own
func TestUserRegenerateClaimCodeHandler_NotOwner(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := UserRegenerateClaimCodeHandler(repos, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user1, err := repos.Users.Create(ctx, "user1", "user1@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user1: %v", err)
	}
	user2, err := repos.Users.Create(ctx, "user2", "user2@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user2: %v", err)
	}

	// Create file owned by user1
	file := testutil.SampleFile()
	file.UserID = &user1.ID
	file.ClaimCode = "user1-file-regen"
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	createdFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)

	// Try to regenerate claim code as user2
	regenReq := map[string]int64{
		"file_id": createdFile.ID,
	}

	body, _ := json.Marshal(regenReq)
	req := httptest.NewRequest(http.MethodPut, "/api/user/files/regenerate-claim-code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	reqCtx := context.WithValue(req.Context(), middleware.ContextKeyUser, user2)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "File not found or access denied" {
		t.Errorf("error = %q, want 'File not found or access denied'", errResp["error"])
	}

	// Verify file's claim code was NOT changed
	unchangedFile, _ := repos.Files.GetByClaimCode(ctx, file.ClaimCode)
	if unchangedFile == nil {
		t.Error("file should still exist with original claim code")
	}
}
