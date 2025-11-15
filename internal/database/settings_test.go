package database

import (
	"database/sql"
	"os"
	"testing"
)

// setupSettingsTestDB creates an in-memory SQLite database for testing
// Note: We can't use testutil.SetupTestDB here because it would create an import cycle
func setupSettingsTestDB(t *testing.T) *sql.DB {
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
	if err := RunMigrations(db); err != nil {
		db.Close()
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Cleanup when test completes
	t.Cleanup(func() {
		db.Close()
	})

	return db
}

// setupTestDBWithFile creates a file-based SQLite database for testing persistence
func setupTestDBWithFile(t *testing.T) (*sql.DB, string) {
	t.Helper()

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "test-settings-*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpFile.Close()
	dbPath := tmpFile.Name()

	// Initialize database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		os.Remove(dbPath)
		t.Fatalf("failed to open database: %v", err)
	}

	// Run migrations to create schema
	if err := RunMigrations(db); err != nil {
		db.Close()
		os.Remove(dbPath)
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Cleanup when test completes
	t.Cleanup(func() {
		db.Close()
		os.Remove(dbPath)
	})

	return db, dbPath
}

// TestSettingsPersistence tests that settings persist to database and override environment variables
func TestSettingsPersistence(t *testing.T) {
	db := setupSettingsTestDB(t)

	// Initially, no settings should exist
	settings, err := GetSettings(db)
	if err != nil {
		t.Fatalf("GetSettings() error: %v", err)
	}

	if settings != nil {
		t.Error("Settings should be nil initially")
	}
}

// TestUpdateQuotaSetting tests updating quota_limit_gb setting
func TestUpdateQuotaSetting(t *testing.T) {
	db := setupSettingsTestDB(t)

	// Update quota setting
	err := UpdateQuotaSetting(db, int64(100)) // 100 GB
	if err != nil {
		t.Fatalf("UpdateQuotaSetting() error: %v", err)
	}

	// Retrieve and verify
	settings, err := GetSettings(db)
	if err != nil {
		t.Fatalf("GetSettings() error: %v", err)
	}

	if settings == nil {
		t.Fatal("Settings should not be nil after update")
	}

	if settings.QuotaLimitGB != 100 {
		t.Errorf("QuotaLimitGB = %d, want 100", settings.QuotaLimitGB)
	}
}

// TestUpdateMaxFileSizeSetting tests updating max_file_size_bytes setting
func TestUpdateMaxFileSizeSetting(t *testing.T) {
	db := setupSettingsTestDB(t)

	// Update max file size
	maxSize := int64(50 * 1024 * 1024) // 50 MB
	err := UpdateMaxFileSizeSetting(db, maxSize)
	if err != nil {
		t.Fatalf("UpdateMaxFileSizeSetting() error: %v", err)
	}

	// Retrieve and verify
	settings, err := GetSettings(db)
	if err != nil {
		t.Fatalf("GetSettings() error: %v", err)
	}

	if settings.MaxFileSizeBytes != maxSize {
		t.Errorf("MaxFileSizeBytes = %d, want %d", settings.MaxFileSizeBytes, maxSize)
	}
}

// TestUpdateExpirationSettings tests updating default and max expiration hours
func TestUpdateExpirationSettings(t *testing.T) {
	db := setupSettingsTestDB(t)

	// Update expiration settings
	err := UpdateDefaultExpirationSetting(db, 48) // 48 hours default
	if err != nil {
		t.Fatalf("UpdateDefaultExpirationSetting() error: %v", err)
	}

	err = UpdateMaxExpirationSetting(db, 336) // 2 weeks max
	if err != nil {
		t.Fatalf("UpdateMaxExpirationSetting() error: %v", err)
	}

	// Retrieve and verify
	settings, err := GetSettings(db)
	if err != nil {
		t.Fatalf("GetSettings() error: %v", err)
	}

	if settings.DefaultExpirationHours != 48 {
		t.Errorf("DefaultExpirationHours = %d, want 48", settings.DefaultExpirationHours)
	}

	if settings.MaxExpirationHours != 336 {
		t.Errorf("MaxExpirationHours = %d, want 336", settings.MaxExpirationHours)
	}
}

// TestUpdateRateLimitSettings tests updating rate limit settings
func TestUpdateRateLimitSettings(t *testing.T) {
	db := setupSettingsTestDB(t)

	// Update rate limits
	err := UpdateRateLimitUploadSetting(db, 20)
	if err != nil {
		t.Fatalf("UpdateRateLimitUploadSetting() error: %v", err)
	}

	err = UpdateRateLimitDownloadSetting(db, 200)
	if err != nil {
		t.Fatalf("UpdateRateLimitDownloadSetting() error: %v", err)
	}

	// Retrieve and verify
	settings, err := GetSettings(db)
	if err != nil {
		t.Fatalf("GetSettings() error: %v", err)
	}

	if settings.RateLimitUpload != 20 {
		t.Errorf("RateLimitUpload = %d, want 20", settings.RateLimitUpload)
	}

	if settings.RateLimitDownload != 200 {
		t.Errorf("RateLimitDownload = %d, want 200", settings.RateLimitDownload)
	}
}

// TestUpdateBlockedExtensionsSetting tests updating blocked extensions
func TestUpdateBlockedExtensionsSetting(t *testing.T) {
	db := setupSettingsTestDB(t)

	// Update blocked extensions
	extensions := []string{".exe", ".bat", ".cmd", ".sh", ".ps1", ".dll"}
	err := UpdateBlockedExtensionsSetting(db, extensions)
	if err != nil {
		t.Fatalf("UpdateBlockedExtensionsSetting() error: %v", err)
	}

	// Retrieve and verify
	settings, err := GetSettings(db)
	if err != nil {
		t.Fatalf("GetSettings() error: %v", err)
	}

	// Compare slices
	if len(settings.BlockedExtensions) != len(extensions) {
		t.Errorf("BlockedExtensions length = %d, want %d", len(settings.BlockedExtensions), len(extensions))
	} else {
		for i, ext := range extensions {
			if settings.BlockedExtensions[i] != ext {
				t.Errorf("BlockedExtensions[%d] = %q, want %q", i, settings.BlockedExtensions[i], ext)
			}
		}
	}
}

// TestSettingsConcurrentUpdates tests concurrent settings updates
func TestSettingsConcurrentUpdates(t *testing.T) {
	db := setupSettingsTestDB(t)

	// Ensure settings row exists before concurrent updates to avoid race condition
	if err := ensureSettingsRow(db); err != nil {
		t.Fatalf("Failed to initialize settings: %v", err)
	}

	// Concurrent updates to different settings
	done := make(chan bool, 3)

	go func() {
		UpdateQuotaSetting(db, int64(50))
		done <- true
	}()

	go func() {
		UpdateMaxFileSizeSetting(db, 10*1024*1024)
		done <- true
	}()

	go func() {
		UpdateRateLimitUploadSetting(db, 15)
		done <- true
	}()

	// Wait for all updates
	for i := 0; i < 3; i++ {
		<-done
	}

	// Verify all settings were applied
	settings, err := GetSettings(db)
	if err != nil {
		t.Fatalf("GetSettings() error: %v", err)
	}

	if settings.QuotaLimitGB != 50 {
		t.Errorf("QuotaLimitGB = %d, want 50", settings.QuotaLimitGB)
	}

	if settings.MaxFileSizeBytes != 10*1024*1024 {
		t.Errorf("MaxFileSizeBytes = %d, want %d", settings.MaxFileSizeBytes, 10*1024*1024)
	}

	if settings.RateLimitUpload != 15 {
		t.Errorf("RateLimitUpload = %d, want 15", settings.RateLimitUpload)
	}
}

// TestSettingsPersistAcrossRestarts tests that settings persist after database close/reopen
func TestSettingsPersistAcrossRestarts(t *testing.T) {
	// Create temporary database with file
	db, dbPath := setupTestDBWithFile(t)

	// Set some values
	UpdateQuotaSetting(db, int64(75))
	UpdateRateLimitDownloadSetting(db, 150)

	// Close database
	db.Close()

	// Reopen database
	db2, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open() error: %v", err)
	}
	defer db2.Close()

	// Run migrations (idempotent)
	if err := RunMigrations(db2); err != nil {
		t.Fatalf("RunMigrations() error: %v", err)
	}

	// Retrieve settings from reopened database
	settings, err := GetSettings(db2)
	if err != nil {
		t.Fatalf("GetSettings() error: %v", err)
	}

	// Verify settings persisted
	if settings.QuotaLimitGB != 75 {
		t.Errorf("QuotaLimitGB = %d, want 75 (not persisted)", settings.QuotaLimitGB)
	}

	if settings.RateLimitDownload != 150 {
		t.Errorf("RateLimitDownload = %d, want 150 (not persisted)", settings.RateLimitDownload)
	}
}

// TestUpdateSettingIdempotency tests that repeated updates work correctly
func TestUpdateSettingIdempotency(t *testing.T) {
	db := setupSettingsTestDB(t)

	// Update same setting multiple times
	for i := 1; i <= 5; i++ {
		err := UpdateQuotaSetting(db, int64(i*10))
		if err != nil {
			t.Fatalf("UpdateQuotaSetting(%d) error: %v", i*10, err)
		}
	}

	// Verify final value
	settings, err := GetSettings(db)
	if err != nil {
		t.Fatalf("GetSettings() error: %v", err)
	}

	if settings.QuotaLimitGB != 50 {
		t.Errorf("QuotaLimitGB = %d, want 50 (final value)", settings.QuotaLimitGB)
	}
}

// TestSettingsDefaultValues tests that settings have correct defaults when not set
func TestSettingsDefaultValues(t *testing.T) {
	db := setupSettingsTestDB(t)

	// Don't set any settings, just retrieve
	settings, err := GetSettings(db)
	if err != nil {
		t.Fatalf("GetSettings() error: %v", err)
	}

	// Should be nil when no settings exist
	if settings != nil {
		t.Error("Settings should be nil when not initialized")
	}
}
