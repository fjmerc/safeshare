package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

func TestClaimHandler_ValidDownload(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create a test file
	testContent := []byte("This is test file content for download")
	storedFilename := "test-uuid.txt"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)

	if err := os.WriteFile(filePath, testContent, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Create database record
	file := &models.File{
		ClaimCode:        "test123",
		OriginalFilename: "document.txt",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}

	if err := database.CreateFile(db, file); err != nil {
		t.Fatalf("failed to create file record: %v", err)
	}

	// Test download
	req := httptest.NewRequest(http.MethodGet, "/api/claim/test123", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 200 OK
	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Content should match
	if rr.Body.String() != string(testContent) {
		t.Errorf("downloaded content = %q, want %q", rr.Body.String(), string(testContent))
	}

	// Verify download count incremented
	updatedFile, _ := database.GetFileByClaimCode(db, "test123")
	if updatedFile.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1", updatedFile.DownloadCount)
	}
}

func TestClaimHandler_InvalidClaimCode(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/claim/INVALID_CODE", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)

	var errResp models.ErrorResponse
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp.Code != "NOT_FOUND" {
		t.Errorf("error code = %q, want NOT_FOUND", errResp.Code)
	}
}

func TestClaimHandler_ExpiredFile(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create expired file record
	file := &models.File{
		ClaimCode:        "expired123",
		OriginalFilename: "expired.txt",
		StoredFilename:   "expired-uuid.txt",
		FileSize:         100,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		UploaderIP:       "127.0.0.1",
	}

	database.CreateFile(db, file)

	req := httptest.NewRequest(http.MethodGet, "/api/claim/expired123", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)

	var errResp models.ErrorResponse
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp.Code != "NOT_FOUND" {
		t.Errorf("expired file error code = %q, want NOT_FOUND", errResp.Code)
	}
}

func TestClaimHandler_PasswordProtected(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create test file
	testContent := []byte("secret content")
	storedFilename := "secret-uuid.txt"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	// Hash password
	passwordHash, _ := utils.HashPassword("MySecret123!")

	// Create password-protected file
	file := &models.File{
		ClaimCode:        "secret123",
		OriginalFilename: "secret.txt",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		PasswordHash:     passwordHash,
		UploaderIP:       "127.0.0.1",
	}

	database.CreateFile(db, file)

	tests := []struct {
		name       string
		password   string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "correct password",
			password:   "MySecret123!",
			wantStatus: http.StatusOK,
		},
		{
			name:       "incorrect password",
			password:   "WrongPassword",
			wantStatus: http.StatusUnauthorized,
			wantCode:   "INCORRECT_PASSWORD",
		},
		{
			name:       "missing password",
			password:   "",
			wantStatus: http.StatusUnauthorized,
			wantCode:   "INCORRECT_PASSWORD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/api/claim/secret123"
			if tt.password != "" {
				url += "?password=" + tt.password
			}

			req := httptest.NewRequest(http.MethodGet, url, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, tt.wantStatus)

			if tt.wantStatus != http.StatusOK {
				var errResp models.ErrorResponse
				json.Unmarshal(rr.Body.Bytes(), &errResp)

				if errResp.Code != tt.wantCode {
					t.Errorf("error code = %q, want %q", errResp.Code, tt.wantCode)
				}
			} else {
				// Verify content
				if rr.Body.String() != string(testContent) {
					t.Error("downloaded content doesn't match")
				}
			}
		})
	}
}

func TestClaimHandler_DownloadLimit(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create test file
	testContent := []byte("limited content")
	storedFilename := "limited-uuid.txt"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	maxDownloads := 2
	file := &models.File{
		ClaimCode:        "limited123",
		OriginalFilename: "limited.txt",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     &maxDownloads,
		DownloadCount:    0,
		UploaderIP:       "127.0.0.1",
	}

	database.CreateFile(db, file)

	// Download 1: should succeed
	req1 := httptest.NewRequest(http.MethodGet, "/api/claim/limited123", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	testutil.AssertStatusCode(t, rr1, http.StatusOK)

	// Download 2: should succeed
	req2 := httptest.NewRequest(http.MethodGet, "/api/claim/limited123", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	testutil.AssertStatusCode(t, rr2, http.StatusOK)

	// Download 3: should fail (limit reached)
	req3 := httptest.NewRequest(http.MethodGet, "/api/claim/limited123", nil)
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)
	testutil.AssertStatusCode(t, rr3, http.StatusGone)

	var errResp models.ErrorResponse
	json.Unmarshal(rr3.Body.Bytes(), &errResp)

	if errResp.Code != "DOWNLOAD_LIMIT_REACHED" {
		t.Errorf("error code = %q, want DOWNLOAD_LIMIT_REACHED", errResp.Code)
	}
}

func TestClaimHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	methods := []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/claim/test123", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)

			var errResp models.ErrorResponse
			json.Unmarshal(rr.Body.Bytes(), &errResp)

			if errResp.Code != "METHOD_NOT_ALLOWED" {
				t.Errorf("error code = %q, want METHOD_NOT_ALLOWED", errResp.Code)
			}
		})
	}
}

func TestClaimHandler_MissingClaimCode(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/claim/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

	var errResp models.ErrorResponse
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp.Code != "NO_CLAIM_CODE" {
		t.Errorf("error code = %q, want NO_CLAIM_CODE", errResp.Code)
	}
}

func TestClaimHandler_DownloadCountTracking(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create test file
	testContent := []byte("tracking content")
	storedFilename := "track-uuid.txt"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	file := &models.File{
		ClaimCode:        "track123",
		OriginalFilename: "track.txt",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		DownloadCount:    0,
		UploaderIP:       "127.0.0.1",
	}

	database.CreateFile(db, file)

	// Download 5 times
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/claim/track123", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		testutil.AssertStatusCode(t, rr, http.StatusOK)

		// Verify count incremented
		updatedFile, _ := database.GetFileByClaimCode(db, "track123")
		if updatedFile.DownloadCount != i {
			t.Errorf("after download %d: count = %d, want %d", i, updatedFile.DownloadCount, i)
		}
	}
}

func TestClaimHandler_ContentDisposition(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	tests := []struct {
		name             string
		originalFilename string
		expectedHeader   string
	}{
		{
			name:             "normal filename",
			originalFilename: "document.pdf",
			expectedHeader:   `attachment; filename="document.pdf"`,
		},
		{
			name:             "filename with spaces",
			originalFilename: "my document.pdf",
			expectedHeader:   `attachment; filename="my document.pdf"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testContent := []byte("test")
			storedFilename := "test-uuid.txt"
			filePath := filepath.Join(cfg.UploadDir, storedFilename)
			os.WriteFile(filePath, testContent, 0644)

			// Replace spaces in test name to create valid URL
			claimCode := "test-" + strings.ReplaceAll(tt.name, " ", "-")
			file := &models.File{
				ClaimCode:        claimCode,
				OriginalFilename: tt.originalFilename,
				StoredFilename:   storedFilename,
				FileSize:         int64(len(testContent)),
				MimeType:         "application/pdf",
				ExpiresAt:        time.Now().Add(24 * time.Hour),
				UploaderIP:       "127.0.0.1",
			}

			database.CreateFile(db, file)

			req := httptest.NewRequest(http.MethodGet, "/api/claim/"+claimCode, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusOK)

			contentDisp := rr.Header().Get("Content-Disposition")
			if contentDisp != tt.expectedHeader {
				t.Errorf("Content-Disposition = %q, want %q", contentDisp, tt.expectedHeader)
			}
		})
	}
}

func TestClaimHandler_MimeType(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	tests := []struct {
		filename         string
		mimeType         string
		expectedContentType string
	}{
		{"document.pdf", "application/pdf", "application/pdf"},
		{"image.jpg", "image/jpeg", "image/jpeg"},
		{"text.txt", "text/plain", "text/plain"},
		{"data.json", "application/json", "application/json"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			testContent := []byte("test content")
			storedFilename := "test-uuid-" + tt.filename
			filePath := filepath.Join(cfg.UploadDir, storedFilename)
			os.WriteFile(filePath, testContent, 0644)

			claimCode := "mime-" + tt.filename
			file := &models.File{
				ClaimCode:        claimCode,
				OriginalFilename: tt.filename,
				StoredFilename:   storedFilename,
				FileSize:         int64(len(testContent)),
				MimeType:         tt.mimeType,
				ExpiresAt:        time.Now().Add(24 * time.Hour),
				UploaderIP:       "127.0.0.1",
			}

			database.CreateFile(db, file)

			req := httptest.NewRequest(http.MethodGet, "/api/claim/"+claimCode, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusOK)

			contentType := rr.Header().Get("Content-Type")
			if contentType != tt.expectedContentType {
				t.Errorf("Content-Type = %q, want %q", contentType, tt.expectedContentType)
			}
		})
	}
}

func TestClaimHandler_UnlimitedDownloads(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create test file
	testContent := []byte("unlimited content")
	storedFilename := "unlimited-uuid.txt"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	// File with no max_downloads (unlimited)
	file := &models.File{
		ClaimCode:        "unlimited123",
		OriginalFilename: "unlimited.txt",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     nil, // Unlimited
		DownloadCount:    0,
		UploaderIP:       "127.0.0.1",
	}

	database.CreateFile(db, file)

	// Download 100 times - should all succeed
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/claim/unlimited123", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		testutil.AssertStatusCode(t, rr, http.StatusOK)
	}

	// Verify count
	updatedFile, _ := database.GetFileByClaimCode(db, "unlimited123")
	if updatedFile.DownloadCount != 100 {
		t.Errorf("download_count = %d, want 100", updatedFile.DownloadCount)
	}
}

func TestClaimHandler_ClientIPLogging(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create test file
	testContent := []byte("test")
	storedFilename := "ip-test-uuid.txt"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	file := &models.File{
		ClaimCode:        "iptest123",
		OriginalFilename: "iptest.txt",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}

	database.CreateFile(db, file)

	// Test with X-Forwarded-For
	req := httptest.NewRequest(http.MethodGet, "/api/claim/iptest123", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	req.RemoteAddr = "10.0.0.1:12345"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)
	// IP logging is verified in logs (not tested here)
}

func TestClaimInfoHandler_FileInfo(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimInfoHandler(db, cfg)

	maxDownloads := 5
	file := &models.File{
		ClaimCode:        "info123",
		OriginalFilename: "info.txt",
		StoredFilename:   "info-uuid.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     &maxDownloads,
		DownloadCount:    2,
		UploaderIP:       "127.0.0.1",
	}

	database.CreateFile(db, file)

	// Set download count to 2 (CreateFile doesn't preserve DownloadCount, it defaults to 0)
	db.Exec("UPDATE files SET download_count = 2 WHERE claim_code = ?", "info123")

	req := httptest.NewRequest(http.MethodGet, "/api/claim/info123/info", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Parse response
	var info map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &info)

	if info["original_filename"] != "info.txt" {
		t.Errorf("filename = %v, want info.txt", info["original_filename"])
	}

	if int(info["file_size"].(float64)) != 1024 {
		t.Errorf("file_size = %v, want 1024", info["file_size"])
	}

	// Download count should NOT increment for info endpoint
	updatedFile, _ := database.GetFileByClaimCode(db, "info123")
	if updatedFile.DownloadCount != 2 {
		t.Errorf("download_count changed to %d, should remain 2", updatedFile.DownloadCount)
	}
}

// Benchmark claim handler
func BenchmarkClaimHandler(b *testing.B) {
	db := testutil.SetupTestDB(&testing.T{})
	cfg := testutil.SetupTestConfig(&testing.T{})
	handler := ClaimHandler(db, cfg)

	// Create test file
	testContent := []byte("benchmark content")
	storedFilename := "bench-uuid.txt"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	file := &models.File{
		ClaimCode:        "bench123",
		OriginalFilename: "bench.txt",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}

	database.CreateFile(db, file)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/claim/bench123", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}
