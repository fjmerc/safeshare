package edgecases

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/handlers"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// TestUploadZeroByteFile tests uploading an empty file
func TestUploadZeroByteFile(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := handlers.UploadHandler(db, cfg)

	// Empty file
	fileContent := []byte{}

	body, contentType := testutil.CreateMultipartForm(t, fileContent, "empty.txt", nil)

	req := httptest.NewRequest("POST", "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should still accept zero-byte files
	if rr.Code != 200 {
		t.Errorf("zero-byte file upload: status = %d, want 200", rr.Code)
	}
}

// TestUploadExactlyMaxSize tests uploading file at exact max size limit
func TestUploadExactlyMaxSize(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	maxSize := int64(1024 * 1024) // 1MB
	cfg.SetMaxFileSize(maxSize)

	handler := handlers.UploadHandler(db, cfg)

	// Exactly max size
	fileContent := bytes.Repeat([]byte("M"), int(maxSize))

	body, contentType := testutil.CreateMultipartForm(t, fileContent, "max.bin", nil)

	req := httptest.NewRequest("POST", "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should accept file at exact max size
	if rr.Code != 200 {
		t.Errorf("exact max size upload: status = %d, want 200", rr.Code)
	}
}

// TestUploadOneByteTooLarge tests uploading file 1 byte over max size
func TestUploadOneByteTooLarge(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	maxSize := int64(1024 * 1024) // 1MB
	cfg.SetMaxFileSize(maxSize)

	handler := handlers.UploadHandler(db, cfg)

	// 1 byte over max size
	fileContent := bytes.Repeat([]byte("L"), int(maxSize)+1)

	body, contentType := testutil.CreateMultipartForm(t, fileContent, "toolarge.bin", nil)

	req := httptest.NewRequest("POST", "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should reject file over max size
	if rr.Code != 413 {
		t.Errorf("one byte over max: status = %d, want 413", rr.Code)
	}
}

// TestFilenameMaxLength tests extremely long filename
func TestFilenameMaxLength(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := handlers.UploadHandler(db, cfg)

	// 255 character filename (typical filesystem limit)
	longFilename := strings.Repeat("a", 255) + ".txt"
	fileContent := []byte("test")

	body, contentType := testutil.CreateMultipartForm(t, fileContent, longFilename, nil)

	req := httptest.NewRequest("POST", "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should handle long filenames (sanitization may truncate)
	if rr.Code != 200 {
		t.Errorf("long filename: status = %d, want 200", rr.Code)
	}
}

// TestFilenameExtremelyLong tests filename longer than typical limits
func TestFilenameExtremelyLong(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := handlers.UploadHandler(db, cfg)

	// 1000 character filename (well over typical limits)
	extremelyLongFilename := strings.Repeat("x", 1000) + ".txt"
	fileContent := []byte("test")

	body, contentType := testutil.CreateMultipartForm(t, fileContent, extremelyLongFilename, nil)

	req := httptest.NewRequest("POST", "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should still handle (likely truncated by sanitization)
	if rr.Code != 200 {
		t.Errorf("extremely long filename: status = %d, want 200", rr.Code)
	}
}

// TestPasswordMaxLength tests extremely long password
func TestPasswordMaxLength(t *testing.T) {
	// bcrypt has max password length of 72 bytes
	longPassword := strings.Repeat("p", 100) // 100 chars > 72 byte limit

	hash, err := utils.HashPassword(longPassword)
	if err != nil {
		t.Fatalf("password hashing failed: %v", err)
	}

	// Should still hash successfully (bcrypt truncates)
	if hash == "" {
		t.Error("hash should not be empty")
	}

	// Verify the password works
	if !utils.VerifyPassword(hash, longPassword) {
		t.Error("long password verification failed")
	}
}

// TestExpirationBoundaries tests expiration at boundaries
func TestExpirationBoundaries(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	cfg.SetDefaultExpirationHours(24)
	cfg.SetMaxExpirationHours(168)

	handler := handlers.UploadHandler(db, cfg)
	fileContent := []byte("test")

	tests := []struct {
		name           string
		expiresInHours string
		wantCode       int
	}{
		{"zero expiration", "0", 200},      // Should use default
		{"one hour", "1", 200},              // Minimum valid
		{"exactly max", "168", 200},         // At max boundary
		{"one hour over max", "169", 400},   // Just over max
		{"very large", "999999", 400},       // Far over max
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, contentType := testutil.CreateMultipartForm(t, fileContent, "test.txt", map[string]string{
				"expires_in_hours": tt.expiresInHours,
			})

			req := httptest.NewRequest("POST", "/api/upload", body)
			req.Header.Set("Content-Type", contentType)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantCode {
				t.Errorf("%s: status = %d, want %d", tt.name, rr.Code, tt.wantCode)
			}
		})
	}
}

// TestMaxDownloadsBoundaries tests max_downloads at boundaries
func TestMaxDownloadsBoundaries(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := handlers.UploadHandler(db, cfg)
	fileContent := []byte("test")

	tests := []struct {
		name         string
		maxDownloads string
		wantCode     int
	}{
		{"zero (unlimited)", "0", 200},
		{"one", "1", 200},
		{"very large", "999999", 200},
		{"negative", "-1", 200}, // Should be converted to 0 (unlimited)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, contentType := testutil.CreateMultipartForm(t, fileContent, "test.txt", map[string]string{
				"max_downloads": tt.maxDownloads,
			})

			req := httptest.NewRequest("POST", "/api/upload", body)
			req.Header.Set("Content-Type", contentType)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantCode {
				t.Errorf("%s: status = %d, want %d", tt.name, rr.Code, tt.wantCode)
			}
		})
	}
}

// TestClaimCodeEdgeCases tests various claim code edge cases
func TestClaimCodeEdgeCases(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := handlers.ClaimHandler(db, cfg)

	tests := []struct {
		name      string
		claimCode string
		wantCode  int
	}{
		{"empty", "", 404},
		{"too short", "abc", 404},
		{"with spaces", "claim code 123", 404},
		{"with special chars", "claim@code!", 404},
		{"SQL injection attempt", "' OR '1'='1", 404},
		{"path traversal", "../../../etc/passwd", 404},
		{"null byte", "claim\x00code", 404},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/claim/"+tt.claimCode, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantCode {
				t.Errorf("claim code '%s': status = %d, want %d", tt.name, rr.Code, tt.wantCode)
			}
		})
	}
}

// TestUnicodeFilenames tests filenames with unicode characters
func TestUnicodeFilenames(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := handlers.UploadHandler(db, cfg)
	fileContent := []byte("test")

	unicodeFilenames := []string{
		"文件.txt",          // Chinese
		"файл.txt",         // Russian
		"ملف.txt",          // Arabic
		"📄🚀.txt",         // Emoji
		"café.txt",         // Accented characters
		"test\u0000.txt",   // Null byte
	}

	for _, filename := range unicodeFilenames {
		t.Run(filename, func(t *testing.T) {
			body, contentType := testutil.CreateMultipartForm(t, fileContent, filename, nil)

			req := httptest.NewRequest("POST", "/api/upload", body)
			req.Header.Set("Content-Type", contentType)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			// Should handle unicode (may be sanitized)
			if rr.Code != 200 {
				t.Errorf("unicode filename '%s': status = %d, want 200", filename, rr.Code)
			}
		})
	}
}

// TestChunkedUploadBoundaries tests chunked upload boundaries
func TestChunkedUploadBoundaries(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Test with very small total size
	t.Run("1 byte file", func(t *testing.T) {
		initHandler := handlers.UploadInitHandler(db, cfg)

		body, _ := testutil.CreateMultipartForm(t, []byte{}, "init", map[string]string{
			"filename":   "tiny.bin",
			"total_size": "1",
		})

		req := httptest.NewRequest("POST", "/api/upload/init", body)
		rr := httptest.NewRecorder()

		initHandler.ServeHTTP(rr, req)

		// Should handle 1-byte file
		if rr.Code != 201 && rr.Code != 400 {
			t.Errorf("1-byte file init: status = %d", rr.Code)
		}
	})

	// Test with chunk number at maximum
	t.Run("high chunk number", func(t *testing.T) {
		// Would test uploading chunk 9999 if upload has that many chunks
		// Implementation depends on actual max chunks limit
	})
}
