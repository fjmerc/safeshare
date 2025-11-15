package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
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
)

func TestUploadHandler_ValidUpload(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	// Create test file
	fileContent := []byte("This is a test file content")
	body, contentType := testutil.CreateMultipartForm(t, fileContent, "test.txt", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should return 201 Created
	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d\nBody: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	// Parse response
	var resp models.UploadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify response fields
	if resp.ClaimCode == "" {
		t.Error("claim_code is empty")
	}

	if resp.OriginalFilename != "test.txt" {
		t.Errorf("original_filename = %q, want %q", resp.OriginalFilename, "test.txt")
	}

	if resp.FileSize != int64(len(fileContent)) {
		t.Errorf("file_size = %d, want %d", resp.FileSize, len(fileContent))
	}

	if resp.DownloadURL == "" {
		t.Error("download_url is empty")
	}

	if resp.ExpiresAt.IsZero() {
		t.Error("expires_at is zero")
	}

	// Verify file was saved to disk
	files, err := os.ReadDir(cfg.UploadDir)
	if err != nil {
		t.Fatalf("failed to read upload dir: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("expected 1 file in upload dir, got %d", len(files))
	}

	// Verify database record
	file, err := database.GetFileByClaimCode(db, resp.ClaimCode)
	if err != nil {
		t.Fatalf("failed to get file from db: %v", err)
	}

	if file == nil {
		t.Fatal("file not found in database")
	}

	if file.OriginalFilename != "test.txt" {
		t.Errorf("db filename = %q, want %q", file.OriginalFilename, "test.txt")
	}
}

func TestUploadHandler_WithOptions(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	tests := []struct {
		name       string
		formValues map[string]string
		wantStatus int
		checkFunc  func(t *testing.T, resp *models.UploadResponse)
	}{
		{
			name: "with expiration hours",
			formValues: map[string]string{
				"expires_in_hours": "48",
			},
			wantStatus: http.StatusCreated,
			checkFunc: func(t *testing.T, resp *models.UploadResponse) {
				// Should expire in ~48 hours
				expectedExpiry := time.Now().Add(48 * time.Hour)
				diff := resp.ExpiresAt.Sub(expectedExpiry)
				if diff > 5*time.Minute || diff < -5*time.Minute {
					t.Errorf("expiry time diff = %v, expected ~48 hours", diff)
				}
			},
		},
		{
			name: "with max downloads",
			formValues: map[string]string{
				"max_downloads": "5",
			},
			wantStatus: http.StatusCreated,
			checkFunc: func(t *testing.T, resp *models.UploadResponse) {
				if resp.MaxDownloads == nil || *resp.MaxDownloads != 5 {
					t.Errorf("max_downloads = %v, want 5", resp.MaxDownloads)
				}
			},
		},
		{
			name: "with password",
			formValues: map[string]string{
				"password": "MySecret123!",
			},
			wantStatus: http.StatusCreated,
			checkFunc: func(t *testing.T, resp *models.UploadResponse) {
				// Verify password was hashed in database
				// (we can't check the response since password isn't returned)
				// This will be verified in download tests
			},
		},
		{
			name: "with all options",
			formValues: map[string]string{
				"expires_in_hours": "24",
				"max_downloads":    "3",
				"password":         "test123",
			},
			wantStatus: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileContent := []byte("test content")
			body, contentType := testutil.CreateMultipartForm(t, fileContent, "test.txt", tt.formValues)

			req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
			req.Header.Set("Content-Type", contentType)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, tt.wantStatus)

			if tt.wantStatus == http.StatusCreated && tt.checkFunc != nil {
				var resp models.UploadResponse
				json.Unmarshal(rr.Body.Bytes(), &resp)
				tt.checkFunc(t, &resp)
			}
		})
	}
}

func TestUploadHandler_FileTooLarge(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.SetMaxFileSize(1024) // 1KB limit
	handler := UploadHandler(db, cfg)

	// Create file larger than limit
	fileContent := bytes.Repeat([]byte("a"), 2048) // 2KB
	body, contentType := testutil.CreateMultipartForm(t, fileContent, "large.txt", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusRequestEntityTooLarge)

	var errResp models.ErrorResponse
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp.Code != "FILE_TOO_LARGE" {
		t.Errorf("error code = %q, want FILE_TOO_LARGE", errResp.Code)
	}
}

func TestUploadHandler_BlockedExtension(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	blockedFiles := []string{
		"virus.exe",
		"script.bat",
		"malware.sh",
		"trojan.ps1",
		"evil.cmd",
	}

	for _, filename := range blockedFiles {
		t.Run(filename, func(t *testing.T) {
			fileContent := []byte("malicious content")
			body, contentType := testutil.CreateMultipartForm(t, fileContent, filename, nil)

			req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
			req.Header.Set("Content-Type", contentType)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

			var errResp models.ErrorResponse
			json.Unmarshal(rr.Body.Bytes(), &errResp)

			if errResp.Code != "BLOCKED_EXTENSION" {
				t.Errorf("error code = %q, want BLOCKED_EXTENSION", errResp.Code)
			}
		})
	}
}

func TestUploadHandler_InvalidExpiration(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.SetMaxExpirationHours(168) // 7 days max
	handler := UploadHandler(db, cfg)

	tests := []struct {
		name           string
		expirationHours string
		wantStatus     int
		wantErrorCode  string
	}{
		{
			name:           "exceeds maximum",
			expirationHours: "1000",
			wantStatus:     http.StatusBadRequest,
			wantErrorCode:  "EXPIRATION_TOO_LONG",
		},
		{
			name:           "invalid format",
			expirationHours: "abc",
			wantStatus:     http.StatusBadRequest,
			wantErrorCode:  "INVALID_PARAMETER",
		},
		{
			name:           "negative value",
			expirationHours: "-5",
			wantStatus:     http.StatusBadRequest,
			wantErrorCode:  "INVALID_PARAMETER",
		},
		{
			name:           "zero value",
			expirationHours: "0",
			wantStatus:     http.StatusBadRequest,
			wantErrorCode:  "INVALID_PARAMETER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileContent := []byte("test")
			formValues := map[string]string{
				"expires_in_hours": tt.expirationHours,
			}
			body, contentType := testutil.CreateMultipartForm(t, fileContent, "test.txt", formValues)

			req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
			req.Header.Set("Content-Type", contentType)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, tt.wantStatus)

			var errResp models.ErrorResponse
			json.Unmarshal(rr.Body.Bytes(), &errResp)

			if errResp.Code != tt.wantErrorCode {
				t.Errorf("error code = %q, want %q", errResp.Code, tt.wantErrorCode)
			}
		})
	}
}

func TestUploadHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	methods := []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
		http.MethodHead,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/upload", nil)
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

func TestUploadHandler_NoFile(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	// Create multipart form without file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("expires_in_hours", "24")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

	var errResp models.ErrorResponse
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp.Code != "NO_FILE" {
		t.Errorf("error code = %q, want NO_FILE", errResp.Code)
	}
}

func TestUploadHandler_FilenameSanitization(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	tests := []struct {
		name              string
		filename          string
		expectedSanitized string
		shouldFail        bool // true if upload should fail at HTTP level
	}{
		{
			name:              "path traversal",
			filename:          "../../../etc/passwd",
			expectedSanitized: "passwd", // filepath.Base() returns just "passwd"
			shouldFail:        false,
		},
		{
			name:       "header injection",
			filename:   "file\r\nContent-Type: evil",
			shouldFail: true, // \r\n breaks multipart form encoding at HTTP level
		},
		{
			name:              "normal filename",
			filename:          "my-document.pdf",
			expectedSanitized: "my-document.pdf",
			shouldFail:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileContent := []byte("test")
			body, contentType := testutil.CreateMultipartForm(t, fileContent, tt.filename, nil)

			req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
			req.Header.Set("Content-Type", contentType)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if tt.shouldFail {
				// Upload should fail at HTTP level due to malformed multipart form
				if rr.Code == http.StatusCreated {
					t.Errorf("upload should have failed but succeeded")
				}
				return
			}

			if rr.Code != http.StatusCreated {
				t.Fatalf("upload failed: %s", rr.Body.String())
			}

			var resp models.UploadResponse
			json.Unmarshal(rr.Body.Bytes(), &resp)

			if resp.OriginalFilename != tt.expectedSanitized {
				t.Errorf("sanitized filename = %q, want %q", resp.OriginalFilename, tt.expectedSanitized)
			}
		})
	}
}

func TestUploadHandler_ClaimCodeUniqueness(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	// Upload multiple files
	codes := make(map[string]bool)
	numUploads := 10

	for i := 0; i < numUploads; i++ {
		fileContent := []byte("test content " + string(rune(i)))
		body, contentType := testutil.CreateMultipartForm(t, fileContent, "test.txt", nil)

		req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
		req.Header.Set("Content-Type", contentType)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("upload %d failed: %s", i, rr.Body.String())
		}

		var resp models.UploadResponse
		json.Unmarshal(rr.Body.Bytes(), &resp)

		if codes[resp.ClaimCode] {
			t.Errorf("duplicate claim code generated: %s", resp.ClaimCode)
		}

		codes[resp.ClaimCode] = true
	}

	if len(codes) != numUploads {
		t.Errorf("expected %d unique codes, got %d", numUploads, len(codes))
	}
}

func TestUploadHandler_ClientIPTracking(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		wantIP     string
	}{
		{
			name:       "direct connection",
			remoteAddr: "203.0.113.1:12345",
			wantIP:     "203.0.113.1",
		},
		{
			name:       "via proxy with X-Forwarded-For",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.5",
			},
			wantIP: "203.0.113.5",
		},
		{
			name:       "via proxy with X-Real-IP",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.10",
			},
			wantIP: "203.0.113.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileContent := []byte("test")
			body, contentType := testutil.CreateMultipartForm(t, fileContent, "test.txt", nil)

			req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
			req.Header.Set("Content-Type", contentType)
			req.RemoteAddr = tt.remoteAddr

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusCreated {
				t.Fatalf("upload failed: %s", rr.Body.String())
			}

			var resp models.UploadResponse
			json.Unmarshal(rr.Body.Bytes(), &resp)

			// Verify IP was tracked in database
			file, _ := database.GetFileByClaimCode(db, resp.ClaimCode)
			if file.UploaderIP != tt.wantIP {
				t.Errorf("uploader_ip = %q, want %q", file.UploaderIP, tt.wantIP)
			}
		})
	}
}

func TestUploadHandler_FractionalExpiration(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	// Test 0.5 hours (30 minutes)
	fileContent := []byte("test")
	formValues := map[string]string{
		"expires_in_hours": "0.5",
	}
	body, contentType := testutil.CreateMultipartForm(t, fileContent, "test.txt", formValues)

	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusCreated)

	var resp models.UploadResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	// Should expire in ~30 minutes
	expectedExpiry := time.Now().Add(30 * time.Minute)
	diff := resp.ExpiresAt.Sub(expectedExpiry)

	if diff > 2*time.Minute || diff < -2*time.Minute {
		t.Errorf("expiry time diff = %v, expected ~30 minutes", diff)
	}
}

func TestUploadHandler_InvalidMaxDownloads(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	invalidValues := []string{
		"abc",
		"-1",
		"0",
		"1.5",
	}

	for _, val := range invalidValues {
		t.Run("max_downloads="+val, func(t *testing.T) {
			fileContent := []byte("test")
			formValues := map[string]string{
				"max_downloads": val,
			}
			body, contentType := testutil.CreateMultipartForm(t, fileContent, "test.txt", formValues)

			req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
			req.Header.Set("Content-Type", contentType)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

			var errResp models.ErrorResponse
			json.Unmarshal(rr.Body.Bytes(), &errResp)

			if errResp.Code != "INVALID_PARAMETER" {
				t.Errorf("error code = %q, want INVALID_PARAMETER", errResp.Code)
			}
		})
	}
}

func TestUploadHandler_EmptyFile(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	// Upload empty file
	fileContent := []byte{}
	body, contentType := testutil.CreateMultipartForm(t, fileContent, "empty.txt", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Empty files should be allowed
	testutil.AssertStatusCode(t, rr, http.StatusCreated)

	var resp models.UploadResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp.FileSize != 0 {
		t.Errorf("file_size = %d, want 0", resp.FileSize)
	}
}

func TestUploadHandler_FileExtensions(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	safeExtensions := []string{
		"document.pdf",
		"image.jpg",
		"archive.zip",
		"data.csv",
		"presentation.pptx",
		"spreadsheet.xlsx",
		"text.txt",
		"code.py",
		"README", // No extension
	}

	for _, filename := range safeExtensions {
		t.Run(filename, func(t *testing.T) {
			fileContent := []byte("test content")
			body, contentType := testutil.CreateMultipartForm(t, fileContent, filename, nil)

			req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
			req.Header.Set("Content-Type", contentType)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusCreated {
				t.Errorf("safe file %q was rejected: %s", filename, rr.Body.String())
			}
		})
	}
}

func TestUploadHandler_CaseInsensitiveExtensionBlocking(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	variants := []string{
		"virus.exe",
		"virus.EXE",
		"virus.Exe",
		"virus.eXe",
	}

	for _, filename := range variants {
		t.Run(filename, func(t *testing.T) {
			fileContent := []byte("malicious")
			body, contentType := testutil.CreateMultipartForm(t, fileContent, filename, nil)

			req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
			req.Header.Set("Content-Type", contentType)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

			var errResp models.ErrorResponse
			json.Unmarshal(rr.Body.Bytes(), &errResp)

			if errResp.Code != "BLOCKED_EXTENSION" {
				t.Errorf("%q should be blocked", filename)
			}
		})
	}
}

func TestUploadHandler_DoubleExtensionAttack(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	attackFiles := []string{
		"document.pdf.exe",
		"image.jpg.bat",
		"archive.zip.sh",
		"safe.txt.exe",
	}

	for _, filename := range attackFiles {
		t.Run(filename, func(t *testing.T) {
			fileContent := []byte("malicious")
			body, contentType := testutil.CreateMultipartForm(t, fileContent, filename, nil)

			req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
			req.Header.Set("Content-Type", contentType)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusBadRequest)

			var errResp models.ErrorResponse
			json.Unmarshal(rr.Body.Bytes(), &errResp)

			if errResp.Code != "BLOCKED_EXTENSION" {
				t.Errorf("double extension attack %q was not blocked", filename)
			}
		})
	}
}

func TestUploadHandler_UnicodeFilenames(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	unicodeFilenames := []string{
		"文档.pdf",
		"документ.txt",
		"文書📄.jpg",
		"مستند.zip",
	}

	for _, filename := range unicodeFilenames {
		t.Run(filename, func(t *testing.T) {
			fileContent := []byte("test content")
			body, contentType := testutil.CreateMultipartForm(t, fileContent, filename, nil)

			req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
			req.Header.Set("Content-Type", contentType)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusCreated {
				t.Errorf("unicode filename %q failed: %s", filename, rr.Body.String())
			}

			var resp models.UploadResponse
			json.Unmarshal(rr.Body.Bytes(), &resp)

			// Filename should be preserved (possibly sanitized)
			if resp.OriginalFilename == "" {
				t.Error("original_filename is empty for unicode file")
			}
		})
	}
}

func TestUploadHandler_WithEncryption(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Set encryption key (64 hex characters = 32 bytes for AES-256)
	cfg.EncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	handler := UploadHandler(db, cfg)

	fileContent := []byte("Secret content that should be encrypted")
	body, contentType := testutil.CreateMultipartForm(t, fileContent, "secret.txt", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d\nBody: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var resp models.UploadResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	// Verify file exists on disk
	files, _ := os.ReadDir(cfg.UploadDir)
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}

	// Read encrypted file from disk
	storedPath := filepath.Join(cfg.UploadDir, files[0].Name())
	encryptedData, err := os.ReadFile(storedPath)
	if err != nil {
		t.Fatalf("failed to read stored file: %v", err)
	}

	// Verify file is actually encrypted (should NOT contain plaintext)
	if bytes.Contains(encryptedData, []byte("Secret content")) {
		t.Error("file appears to be stored in plaintext, not encrypted")
	}

	// Verify file size is larger than original (encryption overhead)
	if int64(len(encryptedData)) <= int64(len(fileContent)) {
		t.Error("encrypted file should be larger than original due to encryption overhead")
	}
}

func TestUploadHandler_QuotaExceeded(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Set quota to 1GB (SetQuotaLimitGB takes int64, whole GB only)
	cfg.SetQuotaLimitGB(1) // 1 GB

	// Increase max file size to allow 200MB uploads
	cfg.SetMaxFileSize(300 * 1024 * 1024) // 300MB

	// Create actual file in upload directory (900MB)
	existingFileData := bytes.Repeat([]byte("X"), 900*1024*1024)
	existingStoredFilename := "existing-quota-test.dat"
	existingFilePath := filepath.Join(cfg.UploadDir, existingStoredFilename)
	if err := os.WriteFile(existingFilePath, existingFileData, 0644); err != nil {
		t.Fatalf("failed to create existing file: %v", err)
	}

	// Upload a file that uses most of the quota (900MB)
	existingFile := &models.File{
		ClaimCode:        "existingfile1",
		OriginalFilename: "existing.dat",
		StoredFilename:   existingStoredFilename,
		FileSize:         900 * 1024 * 1024, // 900MB
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	database.CreateFile(db, existingFile)

	handler := UploadHandler(db, cfg)

	// Try to upload another 200MB file (total would be 1.1GB, exceeds 1GB quota)
	fileContent := bytes.Repeat([]byte("a"), 200*1024*1024)
	body, contentType := testutil.CreateMultipartForm(t, fileContent, "new.dat", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should return 507 Insufficient Storage
	testutil.AssertStatusCode(t, rr, http.StatusInsufficientStorage)

	var errResp models.ErrorResponse
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp.Code != "QUOTA_EXCEEDED" {
		t.Errorf("error code = %q, want QUOTA_EXCEEDED", errResp.Code)
	}
}

func TestUploadHandler_WithUserAuthentication(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	// Create test user
	testUser := &models.User{
		ID:       123,
		Username: "testuser",
		Email:    "test@example.com",
		Role:     "user",
	}

	fileContent := []byte("User uploaded content")
	body, contentType := testutil.CreateMultipartForm(t, fileContent, "userfile.txt", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)

	// Add user to request context
	ctx := context.WithValue(req.Context(), "user", testUser)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusCreated)
	}

	var resp models.UploadResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	// Verify file record has user_id set
	file, _ := database.GetFileByClaimCode(db, resp.ClaimCode)
	if file.UserID == nil {
		t.Error("user_id should be set for authenticated upload")
	}

	if *file.UserID != testUser.ID {
		t.Errorf("user_id = %d, want %d", *file.UserID, testUser.ID)
	}
}

func TestUploadHandler_AnonymousUser(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	fileContent := []byte("Anonymous upload")
	body, contentType := testutil.CreateMultipartForm(t, fileContent, "anon.txt", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	// No user in context - anonymous upload

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusCreated)
	}

	var resp models.UploadResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	// Verify file record has NULL user_id
	file, _ := database.GetFileByClaimCode(db, resp.ClaimCode)
	if file.UserID != nil {
		t.Error("user_id should be NULL for anonymous upload")
	}
}

func TestUploadHandler_MIMETypeDetection(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	tests := []struct {
		name         string
		fileContent  []byte
		filename     string
		expectedMime string
	}{
		{
			name:         "PDF file",
			fileContent:  []byte("%PDF-1.4\n"),
			filename:     "document.pdf",
			expectedMime: "application/pdf",
		},
		{
			name:         "PNG image",
			fileContent:  []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			filename:     "image.png",
			expectedMime: "image/png",
		},
		{
			name:         "ZIP archive",
			fileContent:  []byte{0x50, 0x4B, 0x03, 0x04},
			filename:     "archive.zip",
			expectedMime: "application/zip",
		},
		{
			name:         "plain text",
			fileContent:  []byte("This is plain text"),
			filename:     "file.txt",
			expectedMime: "text/plain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, contentType := testutil.CreateMultipartForm(t, tt.fileContent, tt.filename, nil)

			req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
			req.Header.Set("Content-Type", contentType)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusCreated {
				t.Fatalf("upload failed: %s", rr.Body.String())
			}

			var resp models.UploadResponse
			json.Unmarshal(rr.Body.Bytes(), &resp)

			// Verify MIME type in database
			file, _ := database.GetFileByClaimCode(db, resp.ClaimCode)
			if !strings.HasPrefix(file.MimeType, tt.expectedMime) {
				t.Errorf("mime_type = %q, want prefix %q", file.MimeType, tt.expectedMime)
			}
		})
	}
}

func TestUploadHandler_InsufficientDiskSpace(t *testing.T) {
	// This test is difficult to implement without mocking disk space checks
	// The actual implementation checks real disk space via syscall
	// Skip for now - would require refactoring CheckDiskSpace to be mockable
	t.Skip("Requires disk space mocking - deferred for Phase 7")
}

func TestUploadHandler_ClaimCodeCollision(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	// Pre-populate database with many claim codes to increase collision probability
	// Note: This test may be flaky due to random code generation
	// In practice, collisions are extremely rare (8 char base62 = 218 trillion combinations)

	for i := 0; i < 100; i++ {
		fileContent := []byte(fmt.Sprintf("File %d", i))
		body, contentType := testutil.CreateMultipartForm(t, fileContent, fmt.Sprintf("file%d.txt", i), nil)

		req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
		req.Header.Set("Content-Type", contentType)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("upload %d failed: %s", i, rr.Body.String())
		}
	}

	// All uploads should succeed with unique codes
	// If collision retry logic is working, this should pass

	// Verify all claim codes are unique
	rows, err := db.Query("SELECT claim_code FROM files")
	if err != nil {
		t.Fatalf("failed to query files: %v", err)
	}
	defer rows.Close()

	codes := make(map[string]bool)
	for rows.Next() {
		var code string
		rows.Scan(&code)
		if codes[code] {
			t.Errorf("duplicate claim code found: %s", code)
		}
		codes[code] = true
	}
}

func TestUploadHandler_SmallFile(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UploadHandler(db, cfg)

	// Test with very small file (less than 512 bytes for MIME detection)
	fileContent := []byte("Small")
	body, contentType := testutil.CreateMultipartForm(t, fileContent, "small.txt", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusCreated)

	var resp models.UploadResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp.FileSize != int64(len(fileContent)) {
		t.Errorf("file_size = %d, want %d", resp.FileSize, len(fileContent))
	}
}

// Benchmark upload handler
func BenchmarkUploadHandler(b *testing.B) {
	db := testutil.SetupTestDB(&testing.T{})
	cfg := testutil.SetupTestConfig(&testing.T{})
	handler := UploadHandler(db, cfg)

	fileContent := bytes.Repeat([]byte("a"), 1024) // 1KB file

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body, contentType := testutil.CreateMultipartForm(&testing.T{}, fileContent, "bench.txt", nil)

		req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
		req.Header.Set("Content-Type", contentType)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}
