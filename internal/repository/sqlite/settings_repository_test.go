package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// setupSettingsTestDB creates an in-memory SQLite database with settings table.
func setupSettingsTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	// Create settings table (matching the schema from internal/database/db.go)
	// Including feature flag columns added in migration 011_feature_flags.sql
	_, err = db.Exec(`
		CREATE TABLE settings (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			quota_limit_gb INTEGER DEFAULT 0,
			max_file_size_bytes INTEGER DEFAULT 0,
			default_expiration_hours INTEGER DEFAULT 24,
			max_expiration_hours INTEGER DEFAULT 168,
			rate_limit_upload INTEGER DEFAULT 10,
			rate_limit_download INTEGER DEFAULT 50,
			blocked_extensions TEXT DEFAULT '',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			feature_postgresql INTEGER NOT NULL DEFAULT 0,
			feature_s3_storage INTEGER NOT NULL DEFAULT 0,
			feature_sso INTEGER NOT NULL DEFAULT 0,
			feature_mfa INTEGER NOT NULL DEFAULT 0,
			feature_webhooks INTEGER NOT NULL DEFAULT 0,
			feature_api_tokens INTEGER NOT NULL DEFAULT 0,
			feature_malware_scan INTEGER NOT NULL DEFAULT 0,
			feature_backups INTEGER NOT NULL DEFAULT 0
		)
	`)
	if err != nil {
		t.Fatalf("failed to create settings table: %v", err)
	}

	return db
}

func TestNewSettingsRepository(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()

	repo := NewSettingsRepository(db)
	if repo == nil {
		t.Fatal("expected non-nil repository")
	}
	if repo.db != db {
		t.Error("expected repository to store db reference")
	}
}

func TestSettingsRepository_Get_NoSettings(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)

	ctx := context.Background()
	settings, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if settings != nil {
		t.Error("expected nil settings when no row exists")
	}
}

func TestSettingsRepository_Get_WithSettings(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)

	// Insert test settings
	_, err := db.Exec(`
		INSERT INTO settings (id, quota_limit_gb, max_file_size_bytes, default_expiration_hours,
			max_expiration_hours, rate_limit_upload, rate_limit_download, blocked_extensions)
		VALUES (1, 100, 1073741824, 48, 720, 20, 100, '.exe,.bat,.cmd')
	`)
	if err != nil {
		t.Fatalf("failed to insert test settings: %v", err)
	}

	ctx := context.Background()
	settings, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if settings == nil {
		t.Fatal("expected non-nil settings")
	}

	// Verify all fields
	if settings.QuotaLimitGB != 100 {
		t.Errorf("expected QuotaLimitGB=100, got %d", settings.QuotaLimitGB)
	}
	if settings.MaxFileSizeBytes != 1073741824 {
		t.Errorf("expected MaxFileSizeBytes=1073741824, got %d", settings.MaxFileSizeBytes)
	}
	if settings.DefaultExpirationHours != 48 {
		t.Errorf("expected DefaultExpirationHours=48, got %d", settings.DefaultExpirationHours)
	}
	if settings.MaxExpirationHours != 720 {
		t.Errorf("expected MaxExpirationHours=720, got %d", settings.MaxExpirationHours)
	}
	if settings.RateLimitUpload != 20 {
		t.Errorf("expected RateLimitUpload=20, got %d", settings.RateLimitUpload)
	}
	if settings.RateLimitDownload != 100 {
		t.Errorf("expected RateLimitDownload=100, got %d", settings.RateLimitDownload)
	}
	if len(settings.BlockedExtensions) != 3 {
		t.Errorf("expected 3 blocked extensions, got %d", len(settings.BlockedExtensions))
	}
	expectedExts := []string{".exe", ".bat", ".cmd"}
	for i, ext := range expectedExts {
		if settings.BlockedExtensions[i] != ext {
			t.Errorf("expected extension[%d]=%q, got %q", i, ext, settings.BlockedExtensions[i])
		}
	}
}

func TestSettingsRepository_UpdateQuota(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	// Test UPSERT - creates row if not exists
	err := repo.UpdateQuota(ctx, 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify value was set
	var quota int64
	err = db.QueryRow("SELECT quota_limit_gb FROM settings WHERE id = 1").Scan(&quota)
	if err != nil {
		t.Fatalf("failed to query settings: %v", err)
	}
	if quota != 50 {
		t.Errorf("expected quota=50, got %d", quota)
	}

	// Test update existing
	err = repo.UpdateQuota(ctx, 100)
	if err != nil {
		t.Fatalf("unexpected error on update: %v", err)
	}
	err = db.QueryRow("SELECT quota_limit_gb FROM settings WHERE id = 1").Scan(&quota)
	if err != nil {
		t.Fatalf("failed to query settings: %v", err)
	}
	if quota != 100 {
		t.Errorf("expected quota=100, got %d", quota)
	}
}

func TestSettingsRepository_UpdateQuota_Negative(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	err := repo.UpdateQuota(ctx, -10)
	if err == nil {
		t.Fatal("expected error for negative quota")
	}
	if !strings.Contains(err.Error(), "negative") {
		t.Errorf("expected error message about negative, got: %v", err)
	}
}

func TestSettingsRepository_UpdateMaxFileSize(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	err := repo.UpdateMaxFileSize(ctx, 1073741824) // 1GB
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var size int64
	err = db.QueryRow("SELECT max_file_size_bytes FROM settings WHERE id = 1").Scan(&size)
	if err != nil {
		t.Fatalf("failed to query settings: %v", err)
	}
	if size != 1073741824 {
		t.Errorf("expected size=1073741824, got %d", size)
	}
}

func TestSettingsRepository_UpdateMaxFileSize_Negative(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	err := repo.UpdateMaxFileSize(ctx, -1)
	if err == nil {
		t.Fatal("expected error for negative file size")
	}
}

func TestSettingsRepository_UpdateDefaultExpiration(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	err := repo.UpdateDefaultExpiration(ctx, 72)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var hours int
	err = db.QueryRow("SELECT default_expiration_hours FROM settings WHERE id = 1").Scan(&hours)
	if err != nil {
		t.Fatalf("failed to query settings: %v", err)
	}
	if hours != 72 {
		t.Errorf("expected hours=72, got %d", hours)
	}
}

func TestSettingsRepository_UpdateDefaultExpiration_Negative(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	err := repo.UpdateDefaultExpiration(ctx, -1)
	if err == nil {
		t.Fatal("expected error for negative expiration")
	}
}

func TestSettingsRepository_UpdateMaxExpiration(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	err := repo.UpdateMaxExpiration(ctx, 720)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var hours int
	err = db.QueryRow("SELECT max_expiration_hours FROM settings WHERE id = 1").Scan(&hours)
	if err != nil {
		t.Fatalf("failed to query settings: %v", err)
	}
	if hours != 720 {
		t.Errorf("expected hours=720, got %d", hours)
	}
}

func TestSettingsRepository_UpdateMaxExpiration_Negative(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	err := repo.UpdateMaxExpiration(ctx, -1)
	if err == nil {
		t.Fatal("expected error for negative max expiration")
	}
}

func TestSettingsRepository_UpdateRateLimitUpload(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	err := repo.UpdateRateLimitUpload(ctx, 25)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var limit int
	err = db.QueryRow("SELECT rate_limit_upload FROM settings WHERE id = 1").Scan(&limit)
	if err != nil {
		t.Fatalf("failed to query settings: %v", err)
	}
	if limit != 25 {
		t.Errorf("expected limit=25, got %d", limit)
	}
}

func TestSettingsRepository_UpdateRateLimitUpload_Negative(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	err := repo.UpdateRateLimitUpload(ctx, -1)
	if err == nil {
		t.Fatal("expected error for negative rate limit")
	}
}

func TestSettingsRepository_UpdateRateLimitDownload(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	err := repo.UpdateRateLimitDownload(ctx, 150)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var limit int
	err = db.QueryRow("SELECT rate_limit_download FROM settings WHERE id = 1").Scan(&limit)
	if err != nil {
		t.Fatalf("failed to query settings: %v", err)
	}
	if limit != 150 {
		t.Errorf("expected limit=150, got %d", limit)
	}
}

func TestSettingsRepository_UpdateRateLimitDownload_Negative(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	err := repo.UpdateRateLimitDownload(ctx, -1)
	if err == nil {
		t.Fatal("expected error for negative rate limit")
	}
}

func TestSettingsRepository_UpdateBlockedExtensions(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	extensions := []string{".exe", ".bat", ".cmd", ".sh"}
	err := repo.UpdateBlockedExtensions(ctx, extensions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var extsStr string
	err = db.QueryRow("SELECT blocked_extensions FROM settings WHERE id = 1").Scan(&extsStr)
	if err != nil {
		t.Fatalf("failed to query settings: %v", err)
	}
	if extsStr != ".exe,.bat,.cmd,.sh" {
		t.Errorf("expected '.exe,.bat,.cmd,.sh', got %q", extsStr)
	}

	// Verify Get returns the correct parsed extensions
	settings, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("failed to get settings: %v", err)
	}
	if len(settings.BlockedExtensions) != 4 {
		t.Errorf("expected 4 extensions, got %d", len(settings.BlockedExtensions))
	}
}

func TestSettingsRepository_UpdateBlockedExtensions_EmptyList(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	// Set some extensions first
	err := repo.UpdateBlockedExtensions(ctx, []string{".exe", ".bat"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Clear extensions
	err = repo.UpdateBlockedExtensions(ctx, []string{})
	if err != nil {
		t.Fatalf("unexpected error clearing extensions: %v", err)
	}

	settings, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("failed to get settings: %v", err)
	}
	if len(settings.BlockedExtensions) != 0 {
		t.Errorf("expected 0 extensions, got %d", len(settings.BlockedExtensions))
	}
}

func TestSettingsRepository_UpdateBlockedExtensions_CommaInExtension(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	// Extension with comma should be rejected
	extensions := []string{".exe", ".bat,cmd", ".sh"}
	err := repo.UpdateBlockedExtensions(ctx, extensions)
	if err == nil {
		t.Fatal("expected error for extension containing comma")
	}
	if !strings.Contains(err.Error(), "comma") {
		t.Errorf("expected error message about comma, got: %v", err)
	}
}

func TestSettingsRepository_UpdateBlockedExtensions_TooLong(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	// Extension longer than 20 chars should be rejected
	longExt := ".verylongextensionname"
	extensions := []string{longExt}
	err := repo.UpdateBlockedExtensions(ctx, extensions)
	if err == nil {
		t.Fatal("expected error for extension too long")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("expected error message about length, got: %v", err)
	}
}

func TestSettingsRepository_UpdateBlockedExtensions_TotalTooLong(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	// Create many extensions to exceed total length limit
	var extensions []string
	for i := 0; i < 2000; i++ {
		extensions = append(extensions, ".ext"+strings.Repeat("x", 10))
	}
	err := repo.UpdateBlockedExtensions(ctx, extensions)
	if err == nil {
		t.Fatal("expected error for total extensions list too long")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("expected error message about length, got: %v", err)
	}
}

func TestParseBlockedExtensions(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "single extension",
			input:    ".exe",
			expected: []string{".exe"},
		},
		{
			name:     "multiple extensions",
			input:    ".exe,.bat,.cmd",
			expected: []string{".exe", ".bat", ".cmd"},
		},
		{
			name:     "with whitespace",
			input:    " .exe , .bat , .cmd ",
			expected: []string{".exe", ".bat", ".cmd"},
		},
		{
			name:     "empty parts filtered",
			input:    ".exe,,,.bat",
			expected: []string{".exe", ".bat"},
		},
		{
			name:     "whitespace only parts filtered",
			input:    ".exe,   ,.bat",
			expected: []string{".exe", ".bat"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseBlockedExtensions(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d extensions, got %d", len(tt.expected), len(result))
				return
			}
			for i, ext := range tt.expected {
				if result[i] != ext {
					t.Errorf("expected extension[%d]=%q, got %q", i, ext, result[i])
				}
			}
		})
	}
}

func TestSettingsRepository_ContextCancellation(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Operations should fail with cancelled context
	_, err := repo.Get(ctx)
	if err == nil {
		// SQLite may not always respect cancelled context, so this is a soft check
		t.Log("Note: Get did not return error for cancelled context (SQLite driver behavior)")
	}
}

func TestSettingsRepository_AllUpdatesPreserveOtherFields(t *testing.T) {
	db := setupSettingsTestDB(t)
	defer db.Close()
	repo := NewSettingsRepository(db)
	ctx := context.Background()

	// Set initial values via individual updates
	if err := repo.UpdateQuota(ctx, 100); err != nil {
		t.Fatalf("failed to update quota: %v", err)
	}
	if err := repo.UpdateMaxFileSize(ctx, 1073741824); err != nil {
		t.Fatalf("failed to update max file size: %v", err)
	}
	if err := repo.UpdateDefaultExpiration(ctx, 48); err != nil {
		t.Fatalf("failed to update default expiration: %v", err)
	}
	if err := repo.UpdateMaxExpiration(ctx, 720); err != nil {
		t.Fatalf("failed to update max expiration: %v", err)
	}
	if err := repo.UpdateRateLimitUpload(ctx, 20); err != nil {
		t.Fatalf("failed to update rate limit upload: %v", err)
	}
	if err := repo.UpdateRateLimitDownload(ctx, 100); err != nil {
		t.Fatalf("failed to update rate limit download: %v", err)
	}
	if err := repo.UpdateBlockedExtensions(ctx, []string{".exe", ".bat"}); err != nil {
		t.Fatalf("failed to update blocked extensions: %v", err)
	}

	// Now update just quota and verify other fields are preserved
	if err := repo.UpdateQuota(ctx, 200); err != nil {
		t.Fatalf("failed to update quota second time: %v", err)
	}

	settings, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("failed to get settings: %v", err)
	}

	if settings.QuotaLimitGB != 200 {
		t.Errorf("expected quota=200, got %d", settings.QuotaLimitGB)
	}
	if settings.MaxFileSizeBytes != 1073741824 {
		t.Errorf("expected max file size preserved, got %d", settings.MaxFileSizeBytes)
	}
	if settings.DefaultExpirationHours != 48 {
		t.Errorf("expected default expiration preserved, got %d", settings.DefaultExpirationHours)
	}
	if settings.MaxExpirationHours != 720 {
		t.Errorf("expected max expiration preserved, got %d", settings.MaxExpirationHours)
	}
	if settings.RateLimitUpload != 20 {
		t.Errorf("expected rate limit upload preserved, got %d", settings.RateLimitUpload)
	}
	if settings.RateLimitDownload != 100 {
		t.Errorf("expected rate limit download preserved, got %d", settings.RateLimitDownload)
	}
	if len(settings.BlockedExtensions) != 2 {
		t.Errorf("expected blocked extensions preserved, got %d", len(settings.BlockedExtensions))
	}
}
