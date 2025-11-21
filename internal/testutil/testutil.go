package testutil

import (
	"bytes"
	"database/sql"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
)

// Time constants for testing
const (
	TimeRFC3339 = time.RFC3339
	TimeHour    = time.Hour
)

// TimeNow returns current time (wrapper for time.Now for testability)
func TimeNow() time.Time {
	return time.Now()
}

// SetupTestDB creates an in-memory SQLite database for testing
// The database is automatically closed when the test completes
func SetupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	// IMPORTANT: Force single connection for in-memory databases
	// Each connection in the pool gets its own separate :memory: database
	// This ensures migrations and queries see the same database
	db.SetMaxOpenConns(1)

	// Run migrations to create schema
	if err := database.RunMigrations(db); err != nil {
		db.Close()
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Cleanup when test completes
	t.Cleanup(func() {
		db.Close()
	})

	return db
}

// SetupTestConfig creates a test configuration with temporary directories
// All temporary directories are automatically cleaned up after the test
func SetupTestConfig(t *testing.T) *config.Config {
	t.Helper()

	tmpDir := t.TempDir() // Auto-cleanup on test completion

	// Load default config first
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Override with test-specific values
	// Note: Some fields are immutable (set at startup only), others are mutable (set via setters)

	// Immutable field overrides (directly accessible)
	cfg.Port = "8080"
	cfg.DBPath = ":memory:"
	cfg.UploadDir = tmpDir
	cfg.PublicURL = ""
	cfg.DownloadURL = ""
	cfg.EncryptionKey = ""
	cfg.HTTPSEnabled = false
	cfg.CleanupIntervalMinutes = 60
	cfg.ChunkedUploadEnabled = true
	cfg.ChunkedUploadThreshold = 100 * 1024 * 1024 // 100MB
	cfg.ChunkSize = 10 * 1024 * 1024                // 10MB
	cfg.PartialUploadExpiryHours = 24
	cfg.ReadTimeoutSeconds = 120
	cfg.WriteTimeoutSeconds = 120
	cfg.RequireAuthForUpload = false
	cfg.AdminUsername = "admin"
	cfg.SessionExpiryHours = 24

	// Mutable field overrides (use setters for thread-safety)
	if err := cfg.SetMaxFileSize(10 * 1024 * 1024); err != nil { // 10MB
		t.Fatalf("failed to set max file size: %v", err)
	}
	if err := cfg.SetDefaultExpirationHours(24); err != nil {
		t.Fatalf("failed to set default expiration: %v", err)
	}
	if err := cfg.SetMaxExpirationHours(168); err != nil { // 7 days
		t.Fatalf("failed to set max expiration: %v", err)
	}
	if err := cfg.SetBlockedExtensions([]string{".exe", ".bat", ".cmd", ".sh", ".ps1"}); err != nil {
		t.Fatalf("failed to set blocked extensions: %v", err)
	}
	if err := cfg.SetRateLimitUpload(10); err != nil {
		t.Fatalf("failed to set upload rate limit: %v", err)
	}
	if err := cfg.SetRateLimitDownload(50); err != nil {
		t.Fatalf("failed to set download rate limit: %v", err)
	}
	if err := cfg.SetQuotaLimitGB(0); err != nil { // Unlimited
		t.Fatalf("failed to set quota limit: %v", err)
	}
	if err := cfg.SetAdminPassword("testpass"); err != nil {
		t.Fatalf("failed to set admin password: %v", err)
	}

	return cfg
}

// CreateTestFile creates a temporary test file with the given content
// The file is automatically cleaned up when the test completes
func CreateTestFile(t *testing.T, content []byte) *os.File {
	t.Helper()

	f, err := os.CreateTemp("", "test-*.dat")
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		t.Fatalf("failed to write test file: %v", err)
	}

	// Reset file pointer to beginning
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		os.Remove(f.Name())
		t.Fatalf("failed to seek: %v", err)
	}

	t.Cleanup(func() {
		f.Close()
		os.Remove(f.Name())
	})

	return f
}

// CreateMultipartForm creates a multipart form with a file upload
// Returns the body buffer and content type for the request
func CreateMultipartForm(t *testing.T, fileContent []byte, filename string, formValues map[string]string) (*bytes.Buffer, string) {
	t.Helper()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add file field
	if fileContent != nil {
		part, err := writer.CreateFormFile("file", filename)
		if err != nil {
			t.Fatalf("failed to create form file: %v", err)
		}

		if _, err := io.Copy(part, bytes.NewReader(fileContent)); err != nil {
			t.Fatalf("failed to write file content: %v", err)
		}
	}

	// Add other form values
	for key, val := range formValues {
		if err := writer.WriteField(key, val); err != nil {
			t.Fatalf("failed to write form field %s: %v", key, err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close multipart writer: %v", err)
	}

	return body, writer.FormDataContentType()
}

// AssertStatusCode checks that the HTTP response status code matches expected
func AssertStatusCode(t *testing.T, rr *httptest.ResponseRecorder, wantStatus int) {
	t.Helper()

	if rr.Code != wantStatus {
		t.Errorf("status code = %d, want %d\nBody: %s", rr.Code, wantStatus, rr.Body.String())
	}
}

// AssertNoError fails the test if err is not nil
func AssertNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// AssertError fails the test if err is nil
func AssertError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

// AssertEqual fails the test if got != want
func AssertEqual(t *testing.T, got, want interface{}) {
	t.Helper()

	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

// AssertContains fails the test if haystack doesn't contain needle
func AssertContains(t *testing.T, haystack, needle string) {
	t.Helper()

	if !bytes.Contains([]byte(haystack), []byte(needle)) {
		t.Errorf("expected %q to contain %q", haystack, needle)
	}
}

// AssertNotContains fails the test if haystack contains needle
func AssertNotContains(t *testing.T, haystack, needle string) {
	t.Helper()

	if bytes.Contains([]byte(haystack), []byte(needle)) {
		t.Errorf("expected %q to not contain %q", haystack, needle)
	}
}
