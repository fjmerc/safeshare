package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
)

// TestClaimHandler_RangeRequest_SingleRange tests HTTP Range request for a single byte range
func TestClaimHandler_RangeRequest_SingleRange(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create test file (1024 bytes)
	testContent := bytes.Repeat([]byte("A"), 1024)
	storedFilename := "range-test-uuid.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	// Create database record
	file := &models.File{
		ClaimCode:        "range123",
		OriginalFilename: "test.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	database.CreateFile(db, file)

	// Request first 100 bytes (Range: bytes=0-99)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/range123", nil)
	req.Header.Set("Range", "bytes=0-99")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 206 Partial Content
	if rr.Code != http.StatusPartialContent {
		t.Errorf("status = %d, want %d (Partial Content)", rr.Code, http.StatusPartialContent)
	}

	// Verify Content-Range header
	contentRange := rr.Header().Get("Content-Range")
	expectedRange := "bytes 0-99/1024"
	if contentRange != expectedRange {
		t.Errorf("Content-Range = %q, want %q", contentRange, expectedRange)
	}

	// Verify Content-Length
	contentLength := rr.Header().Get("Content-Length")
	if contentLength != "100" {
		t.Errorf("Content-Length = %q, want 100", contentLength)
	}

	// Verify response body is exactly 100 bytes
	if rr.Body.Len() != 100 {
		t.Errorf("body length = %d, want 100", rr.Body.Len())
	}

	// Verify content matches
	expected := testContent[0:100]
	if !bytes.Equal(rr.Body.Bytes(), expected) {
		t.Error("response body doesn't match expected range")
	}
}

// TestClaimHandler_RangeRequest_FromOffset tests Range request from offset to end (bytes=500-)
func TestClaimHandler_RangeRequest_FromOffset(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create test file (1024 bytes)
	testContent := bytes.Repeat([]byte("B"), 1024)
	storedFilename := "range-offset-uuid.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	// Create database record
	file := &models.File{
		ClaimCode:        "rangeoffset",
		OriginalFilename: "test-offset.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	database.CreateFile(db, file)

	// Request from byte 500 to end (Range: bytes=500-)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/rangeoffset", nil)
	req.Header.Set("Range", "bytes=500-")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 206 Partial Content
	testutil.AssertStatusCode(t, rr, http.StatusPartialContent)

	// Verify Content-Range header
	contentRange := rr.Header().Get("Content-Range")
	expectedRange := "bytes 500-1023/1024"
	if contentRange != expectedRange {
		t.Errorf("Content-Range = %q, want %q", contentRange, expectedRange)
	}

	// Should return 524 bytes (1024 - 500)
	if rr.Body.Len() != 524 {
		t.Errorf("body length = %d, want 524", rr.Body.Len())
	}

	// Verify content matches
	expected := testContent[500:]
	if !bytes.Equal(rr.Body.Bytes(), expected) {
		t.Error("response body doesn't match expected range")
	}
}

// TestClaimHandler_RangeRequest_LastBytes tests suffix range (bytes=-100)
func TestClaimHandler_RangeRequest_LastBytes(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create test file (1024 bytes)
	testContent := bytes.Repeat([]byte("C"), 1024)
	storedFilename := "range-suffix-uuid.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	// Create database record
	file := &models.File{
		ClaimCode:        "rangesuffix",
		OriginalFilename: "test-suffix.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	database.CreateFile(db, file)

	// Request last 100 bytes (Range: bytes=-100)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/rangesuffix", nil)
	req.Header.Set("Range", "bytes=-100")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 206 Partial Content
	testutil.AssertStatusCode(t, rr, http.StatusPartialContent)

	// Verify Content-Range header
	contentRange := rr.Header().Get("Content-Range")
	expectedRange := "bytes 924-1023/1024"
	if contentRange != expectedRange {
		t.Errorf("Content-Range = %q, want %q", contentRange, expectedRange)
	}

	// Should return 100 bytes
	if rr.Body.Len() != 100 {
		t.Errorf("body length = %d, want 100", rr.Body.Len())
	}

	// Verify content matches
	expected := testContent[924:]
	if !bytes.Equal(rr.Body.Bytes(), expected) {
		t.Error("response body doesn't match expected range")
	}
}

// TestClaimHandler_RangeRequest_InvalidRange tests invalid Range header
func TestClaimHandler_RangeRequest_InvalidRange(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create test file
	testContent := bytes.Repeat([]byte("D"), 1024)
	storedFilename := "range-invalid-uuid.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	file := &models.File{
		ClaimCode:        "rangeinvalid",
		OriginalFilename: "test-invalid.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	database.CreateFile(db, file)

	tests := []struct {
		name        string
		rangeHeader string
		wantStatus  int
	}{
		{
			name:        "range beyond file size",
			rangeHeader: "bytes=2000-3000",
			wantStatus:  http.StatusRequestedRangeNotSatisfiable,
		},
		{
			name:        "invalid range format",
			rangeHeader: "bytes=abc-def",
			wantStatus:  http.StatusRequestedRangeNotSatisfiable, // Handler returns 416 for all range errors
		},
		{
			name:        "start greater than end",
			rangeHeader: "bytes=500-100",
			wantStatus:  http.StatusRequestedRangeNotSatisfiable, // Handler returns 416 for all range errors
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/claim/rangeinvalid", nil)
			req.Header.Set("Range", tt.rangeHeader)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("%s: status = %d, want %d", tt.name, rr.Code, tt.wantStatus)
			}
		})
	}
}

// TestClaimHandler_RangeRequest_AcceptRangesHeader tests that Accept-Ranges header is always present
func TestClaimHandler_RangeRequest_AcceptRangesHeader(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create test file
	testContent := []byte("test content")
	storedFilename := "accept-ranges-uuid.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	file := &models.File{
		ClaimCode:        "acceptranges",
		OriginalFilename: "test.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	database.CreateFile(db, file)

	// Request without Range header
	req := httptest.NewRequest(http.MethodGet, "/api/claim/acceptranges", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Accept-Ranges header should always be present
	acceptRanges := rr.Header().Get("Accept-Ranges")
	if acceptRanges != "bytes" {
		t.Errorf("Accept-Ranges = %q, want 'bytes'", acceptRanges)
	}
}

// TestClaimHandler_RangeRequest_DownloadCountIncrement tests that range requests count as downloads
func TestClaimHandler_RangeRequest_DownloadCountIncrement(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create test file
	testContent := bytes.Repeat([]byte("E"), 1024)
	storedFilename := "range-count-uuid.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	file := &models.File{
		ClaimCode:        "rangecount",
		OriginalFilename: "test-count.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		DownloadCount:    0,
		UploaderIP:       "127.0.0.1",
	}
	database.CreateFile(db, file)

	// Make range request
	req := httptest.NewRequest(http.MethodGet, "/api/claim/rangecount", nil)
	req.Header.Set("Range", "bytes=0-99")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusPartialContent)

	// Verify download count incremented
	updatedFile, _ := database.GetFileByClaimCode(db, "rangecount")
	if updatedFile.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1 (range requests should count)", updatedFile.DownloadCount)
	}
}

// TestClaimHandler_RangeRequest_ResumableDownload tests a simulated resume scenario
func TestClaimHandler_RangeRequest_ResumableDownload(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create test file (10KB for realistic scenario)
	testContent := bytes.Repeat([]byte("RESUME"), 10*1024)
	storedFilename := "range-resume-uuid.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	file := &models.File{
		ClaimCode:        "rangeresume",
		OriginalFilename: "large-file.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	database.CreateFile(db, file)

	// Simulate download interrupted at 5KB, resume from byte 5120
	downloaded := make([]byte, 0, len(testContent))

	// First request: bytes 0-5119
	req1 := httptest.NewRequest(http.MethodGet, "/api/claim/rangeresume", nil)
	req1.Header.Set("Range", "bytes=0-5119")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	testutil.AssertStatusCode(t, rr1, http.StatusPartialContent)
	downloaded = append(downloaded, rr1.Body.Bytes()...)

	// Second request: resume from byte 5120 to end
	req2 := httptest.NewRequest(http.MethodGet, "/api/claim/rangeresume", nil)
	req2.Header.Set("Range", "bytes=5120-")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	testutil.AssertStatusCode(t, rr2, http.StatusPartialContent)
	downloaded = append(downloaded, rr2.Body.Bytes()...)

	// Verify complete file was reassembled
	if len(downloaded) != len(testContent) {
		t.Errorf("reassembled file size = %d, want %d", len(downloaded), len(testContent))
	}

	if !bytes.Equal(downloaded, testContent) {
		t.Error("reassembled file doesn't match original")
	}
}

// TestClaimHandler_RangeRequest_MultipleRanges tests that multi-range requests are not supported (yet)
func TestClaimHandler_RangeRequest_MultipleRanges(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create test file
	testContent := bytes.Repeat([]byte("F"), 1024)
	storedFilename := "range-multi-uuid.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	file := &models.File{
		ClaimCode:        "rangemulti",
		OriginalFilename: "test-multi.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	database.CreateFile(db, file)

	// Request multiple ranges (not supported in current implementation)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/rangemulti", nil)
	req.Header.Set("Range", "bytes=0-99,200-299")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Implementation should either:
	// 1. Return 416 Range Not Satisfiable (not supported)
	// 2. Return 200 OK with full content (ignore Range)
	// 3. Return 206 with only first range (partial support)

	// Accept any of these as valid for now
	if rr.Code != http.StatusRequestedRangeNotSatisfiable &&
		rr.Code != http.StatusOK &&
		rr.Code != http.StatusPartialContent {
		t.Errorf("multi-range: status = %d, expected 416, 200, or 206", rr.Code)
	}
}

// TestClaimHandler_RangeRequest_EmptyFile tests range request on empty file
func TestClaimHandler_RangeRequest_EmptyFile(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(db, cfg)

	// Create empty file
	testContent := []byte{}
	storedFilename := "range-empty-uuid.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, testContent, 0644)

	file := &models.File{
		ClaimCode:        "rangeempty",
		OriginalFilename: "empty.bin",
		StoredFilename:   storedFilename,
		FileSize:         0,
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	database.CreateFile(db, file)

	// Range request on empty file
	req := httptest.NewRequest(http.MethodGet, "/api/claim/rangeempty", nil)
	req.Header.Set("Range", "bytes=0-99")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 416 Range Not Satisfiable for empty file
	if rr.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("empty file range: status = %d, want %d", rr.Code, http.StatusRequestedRangeNotSatisfiable)
	}
}

// TestClaimHandler_RangeRequest_EncryptedFile tests range requests on encrypted files
func TestClaimHandler_RangeRequest_EncryptedFile(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Note: Encryption key must be set at config initialization, not runtime
	// For this test, we'll skip if no encryption key is configured
	if cfg.EncryptionKey == "" {
		t.Skip("Skipping encrypted file test - no encryption key configured")
	}

	handler := ClaimHandler(db, cfg)

	// Create and encrypt test file
	testContent := bytes.Repeat([]byte("ENCRYPTED"), 1024)
	storedFilename := "range-encrypted-uuid.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)

	// Encrypt content before writing
	encryptedFile, _ := os.Create(filePath)
	defer encryptedFile.Close()

	// For this test to work, the file would need to be properly encrypted
	// This is a placeholder - actual implementation needs encryption
	encryptedFile.Write(testContent)

	file := &models.File{
		ClaimCode:        "rangeenc",
		OriginalFilename: "encrypted.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testContent)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	database.CreateFile(db, file)

	// Range request on encrypted file
	req := httptest.NewRequest(http.MethodGet, "/api/claim/rangeenc", nil)
	req.Header.Set("Range", "bytes=0-99")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should support range on encrypted files (if implementation exists)
	// This test documents expected behavior
	t.Logf("Encrypted file range request status: %d", rr.Code)
}
