package backup

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// createTestDatabase creates a test SQLite database with sample data
func createTestDatabase(t *testing.T, dbPath string) {
	t.Helper()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer db.Close()

	// Create tables
	schema := `
		CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		
		CREATE TABLE IF NOT EXISTS files (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			claim_code TEXT UNIQUE NOT NULL,
			original_filename TEXT NOT NULL,
			stored_filename TEXT NOT NULL,
			file_size INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		
		CREATE TABLE IF NOT EXISTS admin_credentials (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL,
			password_hash TEXT NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS blocked_ips (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address TEXT NOT NULL,
			reason TEXT
		);
		
		CREATE TABLE IF NOT EXISTS webhook_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url TEXT NOT NULL,
			events TEXT NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS api_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS user_sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			token TEXT NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS partial_uploads (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			upload_id TEXT NOT NULL
		);
	`

	_, err = db.Exec(schema)
	if err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	// Insert sample data
	_, err = db.Exec(`INSERT INTO settings (key, value) VALUES ('max_file_size', '104857600')`)
	if err != nil {
		t.Fatalf("Failed to insert settings: %v", err)
	}

	_, err = db.Exec(`INSERT INTO users (username, email) VALUES ('testuser', 'test@example.com')`)
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	_, err = db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size) VALUES ('ABC123', 'test.txt', 'uuid-123', 1024)`)
	if err != nil {
		t.Fatalf("Failed to insert file: %v", err)
	}

	_, err = db.Exec(`INSERT INTO admin_credentials (id, username, password_hash) VALUES (1, 'admin', 'hash123')`)
	if err != nil {
		t.Fatalf("Failed to insert admin credentials: %v", err)
	}

	_, err = db.Exec(`INSERT INTO blocked_ips (ip_address, reason) VALUES ('192.168.1.100', 'spam')`)
	if err != nil {
		t.Fatalf("Failed to insert blocked IP: %v", err)
	}

	_, err = db.Exec(`INSERT INTO webhook_configs (url, events) VALUES ('https://example.com/hook', 'upload,download')`)
	if err != nil {
		t.Fatalf("Failed to insert webhook: %v", err)
	}

	_, err = db.Exec(`INSERT INTO api_tokens (token, name) VALUES ('token123', 'test-token')`)
	if err != nil {
		t.Fatalf("Failed to insert api token: %v", err)
	}

	// Insert data into excluded tables
	_, err = db.Exec(`INSERT INTO user_sessions (user_id, token) VALUES (1, 'session123')`)
	if err != nil {
		t.Fatalf("Failed to insert session: %v", err)
	}

	_, err = db.Exec(`INSERT INTO partial_uploads (upload_id) VALUES ('partial123')`)
	if err != nil {
		t.Fatalf("Failed to insert partial upload: %v", err)
	}
}

// createTestUploads creates test upload files
func createTestUploads(t *testing.T, uploadsDir string) {
	t.Helper()

	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatalf("Failed to create uploads dir: %v", err)
	}

	// Create test files
	testFiles := map[string]string{
		"uuid-123": "test file content 1",
		"uuid-456": "test file content 2",
		"uuid-789": "test file content 3",
	}

	for name, content := range testFiles {
		filePath := filepath.Join(uploadsDir, name)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
	}

	// Create .partial directory (should be excluded)
	partialDir := filepath.Join(uploadsDir, ".partial")
	if err := os.MkdirAll(partialDir, 0755); err != nil {
		t.Fatalf("Failed to create .partial dir: %v", err)
	}

	// Create a file in .partial (should be excluded from backup)
	partialFile := filepath.Join(partialDir, "partial-upload")
	if err := os.WriteFile(partialFile, []byte("partial data"), 0644); err != nil {
		t.Fatalf("Failed to create partial file: %v", err)
	}
}

func TestBackupModeIsValid(t *testing.T) {
	tests := []struct {
		mode  BackupMode
		valid bool
	}{
		{ModeConfig, true},
		{ModeDatabase, true},
		{ModeFull, true},
		{BackupMode("invalid"), false},
		{BackupMode(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := tt.mode.IsValid(); got != tt.valid {
				t.Errorf("BackupMode(%q).IsValid() = %v, want %v", tt.mode, got, tt.valid)
			}
		})
	}
}

func TestOrphanHandlingIsValid(t *testing.T) {
	tests := []struct {
		handling OrphanHandling
		valid    bool
	}{
		{OrphanKeep, true},
		{OrphanRemove, true},
		{OrphanPrompt, true},
		{OrphanHandling("invalid"), false},
		{OrphanHandling(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.handling), func(t *testing.T) {
			if got := tt.handling.IsValid(); got != tt.valid {
				t.Errorf("OrphanHandling(%q).IsValid() = %v, want %v", tt.handling, got, tt.valid)
			}
		})
	}
}

func TestNewManifest(t *testing.T) {
	version := "1.4.1"
	manifest := NewManifest(ModeDatabase, version)

	if manifest.Version != ManifestVersion {
		t.Errorf("Version = %q, want %q", manifest.Version, ManifestVersion)
	}

	if manifest.SafeShareVersion != version {
		t.Errorf("SafeShareVersion = %q, want %q", manifest.SafeShareVersion, version)
	}

	if manifest.Mode != ModeDatabase {
		t.Errorf("Mode = %q, want %q", manifest.Mode, ModeDatabase)
	}

	if manifest.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}

	// Check includes for database mode
	if !manifest.Includes.Settings {
		t.Error("Settings should be included for database mode")
	}
	if !manifest.Includes.Users {
		t.Error("Users should be included for database mode")
	}
	if !manifest.Includes.FileMetadata {
		t.Error("FileMetadata should be included for database mode")
	}
	if manifest.Includes.Files {
		t.Error("Files should NOT be included for database mode")
	}
}

func TestComputeChecksum(t *testing.T) {
	// Create a temp file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	content := "Hello, World!"
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	checksum, err := ComputeChecksum(testFile)
	if err != nil {
		t.Fatalf("ComputeChecksum failed: %v", err)
	}

	// SHA256 of "Hello, World!" is known
	expected := "sha256:dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
	if checksum != expected {
		t.Errorf("Checksum = %q, want %q", checksum, expected)
	}
}

func TestComputeKeyFingerprint(t *testing.T) {
	tests := []struct {
		key      string
		wantLen  int
		wantPre  string
		wantNone bool
	}{
		{"", 0, "", true},
		{"testkey123", 71, "sha256:", false}, // sha256: + 64 hex chars
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			fingerprint := ComputeKeyFingerprint(tt.key)

			if tt.wantNone {
				if fingerprint != "" {
					t.Errorf("Expected empty fingerprint for empty key, got %q", fingerprint)
				}
				return
			}

			if len(fingerprint) != tt.wantLen {
				t.Errorf("Fingerprint length = %d, want %d", len(fingerprint), tt.wantLen)
			}

			if fingerprint[:7] != tt.wantPre {
				t.Errorf("Fingerprint prefix = %q, want %q", fingerprint[:7], tt.wantPre)
			}
		})
	}
}

func TestManifestReadWrite(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a manifest
	manifest := NewManifest(ModeFull, "1.4.1")
	manifest.Stats.UsersCount = 5
	manifest.Stats.FileRecordsCount = 100
	manifest.Checksums["test.db"] = "sha256:abc123"

	// Write manifest
	if err := WriteManifest(manifest, tmpDir); err != nil {
		t.Fatalf("WriteManifest failed: %v", err)
	}

	// Read manifest back
	readManifest, err := ReadManifest(tmpDir)
	if err != nil {
		t.Fatalf("ReadManifest failed: %v", err)
	}

	// Verify fields
	if readManifest.Version != manifest.Version {
		t.Errorf("Version mismatch: got %q, want %q", readManifest.Version, manifest.Version)
	}

	if readManifest.Mode != manifest.Mode {
		t.Errorf("Mode mismatch: got %q, want %q", readManifest.Mode, manifest.Mode)
	}

	if readManifest.Stats.UsersCount != manifest.Stats.UsersCount {
		t.Errorf("UsersCount mismatch: got %d, want %d", readManifest.Stats.UsersCount, manifest.Stats.UsersCount)
	}

	if readManifest.Checksums["test.db"] != manifest.Checksums["test.db"] {
		t.Errorf("Checksum mismatch")
	}
}

func TestValidateManifest(t *testing.T) {
	tests := []struct {
		name     string
		manifest *BackupManifest
		wantErr  bool
	}{
		{
			name:     "nil manifest",
			manifest: nil,
			wantErr:  true,
		},
		{
			name: "empty version",
			manifest: &BackupManifest{
				CreatedAt: time.Now(),
				Mode:      ModeDatabase,
				Checksums: map[string]string{DatabaseFilename: "sha256:abc"},
			},
			wantErr: true,
		},
		{
			name: "zero created_at",
			manifest: &BackupManifest{
				Version:   "1.0",
				Mode:      ModeDatabase,
				Checksums: map[string]string{DatabaseFilename: "sha256:abc"},
			},
			wantErr: true,
		},
		{
			name: "invalid mode",
			manifest: &BackupManifest{
				Version:   "1.0",
				CreatedAt: time.Now(),
				Mode:      BackupMode("invalid"),
				Checksums: map[string]string{},
			},
			wantErr: true,
		},
		{
			name: "missing database checksum for database mode",
			manifest: &BackupManifest{
				Version:   "1.0",
				CreatedAt: time.Now(),
				Mode:      ModeDatabase,
				Checksums: map[string]string{},
			},
			wantErr: true,
		},
		{
			name: "valid database manifest",
			manifest: &BackupManifest{
				Version:   "1.0",
				CreatedAt: time.Now(),
				Mode:      ModeDatabase,
				Checksums: map[string]string{DatabaseFilename: "sha256:abc"},
			},
			wantErr: false,
		},
		{
			name: "valid config manifest (no db checksum required)",
			manifest: &BackupManifest{
				Version:   "1.0",
				CreatedAt: time.Now(),
				Mode:      ModeConfig,
				Checksums: map[string]string{},
			},
			wantErr: true, // Config mode still requires db backup
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateManifest(tt.manifest)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateManifest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBackupDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDB := filepath.Join(tmpDir, "source.db")
	destDB := filepath.Join(tmpDir, "backup.db")

	// Create source database
	createTestDatabase(t, sourceDB)

	// Backup database
	if err := BackupDatabase(sourceDB, destDB); err != nil {
		t.Fatalf("BackupDatabase failed: %v", err)
	}

	// Verify backup exists
	if _, err := os.Stat(destDB); err != nil {
		t.Errorf("Backup file not created: %v", err)
	}

	// Verify backup is valid
	if err := ValidateDatabase(destDB); err != nil {
		t.Errorf("Backup database validation failed: %v", err)
	}
}

func TestGetDatabaseStats(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	createTestDatabase(t, dbPath)

	stats, err := GetDatabaseStats(dbPath)
	if err != nil {
		t.Fatalf("GetDatabaseStats failed: %v", err)
	}

	if stats.UsersCount != 1 {
		t.Errorf("UsersCount = %d, want 1", stats.UsersCount)
	}

	if stats.FileRecordsCount != 1 {
		t.Errorf("FileRecordsCount = %d, want 1", stats.FileRecordsCount)
	}

	if stats.BlockedIPsCount != 1 {
		t.Errorf("BlockedIPsCount = %d, want 1", stats.BlockedIPsCount)
	}

	if stats.WebhooksCount != 1 {
		t.Errorf("WebhooksCount = %d, want 1", stats.WebhooksCount)
	}

	if stats.APITokensCount != 1 {
		t.Errorf("APITokensCount = %d, want 1", stats.APITokensCount)
	}
}

func TestCopyUploadsDir(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "uploads")
	destDir := filepath.Join(tmpDir, "backup_uploads")

	// Create source uploads with test files
	createTestUploads(t, srcDir)

	// Copy uploads
	count, size, err := CopyUploadsDir(srcDir, destDir, nil)
	if err != nil {
		t.Fatalf("CopyUploadsDir failed: %v", err)
	}

	// Should have copied 3 files (excluding .partial)
	if count != 3 {
		t.Errorf("Files copied = %d, want 3", count)
	}

	if size == 0 {
		t.Error("Total size should be > 0")
	}

	// Verify .partial was not copied
	partialDir := filepath.Join(destDir, ".partial")
	if _, err := os.Stat(partialDir); !os.IsNotExist(err) {
		t.Error(".partial directory should not be copied")
	}
}

func TestCreateBackup(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	outputDir := filepath.Join(tmpDir, "backups")

	// Create test data
	createTestDatabase(t, dbPath)
	createTestUploads(t, uploadsDir)
	os.MkdirAll(outputDir, 0755)

	tests := []struct {
		name        string
		mode        BackupMode
		wantFiles   bool
		wantSuccess bool
	}{
		{
			name:        "config backup",
			mode:        ModeConfig,
			wantFiles:   false,
			wantSuccess: true,
		},
		{
			name:        "database backup",
			mode:        ModeDatabase,
			wantFiles:   false,
			wantSuccess: true,
		},
		{
			name:        "full backup",
			mode:        ModeFull,
			wantFiles:   true,
			wantSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := CreateOptions{
				Mode:             tt.mode,
				DBPath:           dbPath,
				UploadsDir:       uploadsDir,
				OutputDir:        outputDir,
				SafeShareVersion: "1.4.1",
			}

			result, err := Create(opts)

			if tt.wantSuccess {
				if err != nil {
					t.Fatalf("Create failed: %v", err)
				}
				if !result.Success {
					t.Errorf("Expected success, got failure: %s", result.Error)
				}
				if result.BackupPath == "" {
					t.Error("BackupPath should not be empty")
				}
				if result.Manifest == nil {
					t.Error("Manifest should not be nil")
				}

				// Verify files included based on mode
				if tt.wantFiles {
					if result.Manifest.Stats.FilesBackedUp == 0 {
						t.Error("Expected files to be backed up")
					}
				} else {
					if result.Manifest.Stats.FilesBackedUp != 0 {
						t.Errorf("Expected 0 files, got %d", result.Manifest.Stats.FilesBackedUp)
					}
				}
			} else {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			}
		})
	}
}

func TestVerifyBackup(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	outputDir := filepath.Join(tmpDir, "backups")

	// Create test data
	createTestDatabase(t, dbPath)
	createTestUploads(t, uploadsDir)
	os.MkdirAll(outputDir, 0755)

	// Create a backup
	opts := CreateOptions{
		Mode:             ModeFull,
		DBPath:           dbPath,
		UploadsDir:       uploadsDir,
		OutputDir:        outputDir,
		SafeShareVersion: "1.4.1",
	}

	result, err := Create(opts)
	if err != nil {
		t.Fatalf("Create backup failed: %v", err)
	}

	// Verify the backup
	verifyResult := Verify(result.BackupPath)

	if !verifyResult.Valid {
		t.Errorf("Backup should be valid, errors: %v", verifyResult.Errors)
	}

	if !verifyResult.ManifestValid {
		t.Error("Manifest should be valid")
	}

	if !verifyResult.DatabaseValid {
		t.Error("Database should be valid")
	}

	if !verifyResult.ChecksumsValid {
		t.Errorf("Checksums should be valid, mismatches: %v", verifyResult.ChecksumMismatches)
	}
}

func TestListBackups(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	outputDir := filepath.Join(tmpDir, "backups")

	// Create test data
	createTestDatabase(t, dbPath)
	createTestUploads(t, uploadsDir)
	os.MkdirAll(outputDir, 0755)

	// Create multiple backups
	for i := 0; i < 3; i++ {
		opts := CreateOptions{
			Mode:             ModeDatabase,
			DBPath:           dbPath,
			UploadsDir:       uploadsDir,
			OutputDir:        outputDir,
			SafeShareVersion: "1.4.1",
		}
		_, err := Create(opts)
		if err != nil {
			t.Fatalf("Create backup %d failed: %v", i, err)
		}
		time.Sleep(time.Second) // Ensure different timestamps
	}

	// List backups
	backups, err := ListBackups(outputDir)
	if err != nil {
		t.Fatalf("ListBackups failed: %v", err)
	}

	if len(backups) != 3 {
		t.Errorf("Expected 3 backups, got %d", len(backups))
	}

	for _, backup := range backups {
		if backup.Name == "" {
			t.Error("Backup name should not be empty")
		}
		if backup.Mode != ModeDatabase {
			t.Errorf("Expected mode %s, got %s", ModeDatabase, backup.Mode)
		}
		if backup.SafeShareVersion != "1.4.1" {
			t.Errorf("Expected version 1.4.1, got %s", backup.SafeShareVersion)
		}
	}
}

func TestRestoreBackup(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	outputDir := filepath.Join(tmpDir, "backups")
	restoreDBPath := filepath.Join(tmpDir, "restored.db")
	restoreUploadsDir := filepath.Join(tmpDir, "restored_uploads")

	// Create test data
	createTestDatabase(t, dbPath)
	createTestUploads(t, uploadsDir)
	os.MkdirAll(outputDir, 0755)

	// Create a backup
	createOpts := CreateOptions{
		Mode:             ModeFull,
		DBPath:           dbPath,
		UploadsDir:       uploadsDir,
		OutputDir:        outputDir,
		SafeShareVersion: "1.4.1",
	}

	backupResult, err := Create(createOpts)
	if err != nil {
		t.Fatalf("Create backup failed: %v", err)
	}

	// Restore the backup
	restoreOpts := RestoreOptions{
		InputDir:      backupResult.BackupPath,
		DBPath:        restoreDBPath,
		UploadsDir:    restoreUploadsDir,
		HandleOrphans: OrphanKeep,
		Force:         true,
	}

	restoreResult, err := Restore(restoreOpts)
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	if !restoreResult.Success {
		t.Errorf("Restore should succeed, error: %s", restoreResult.Error)
	}

	// Verify restored database
	if err := ValidateDatabase(restoreDBPath); err != nil {
		t.Errorf("Restored database validation failed: %v", err)
	}

	// Verify restored files count
	if restoreResult.FilesRestored != 3 {
		t.Errorf("Expected 3 files restored, got %d", restoreResult.FilesRestored)
	}
}

func TestRestoreDryRun(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	outputDir := filepath.Join(tmpDir, "backups")
	restoreDBPath := filepath.Join(tmpDir, "restored.db")

	// Create test data
	createTestDatabase(t, dbPath)
	createTestUploads(t, uploadsDir)
	os.MkdirAll(outputDir, 0755)

	// Create a backup
	createOpts := CreateOptions{
		Mode:             ModeDatabase,
		DBPath:           dbPath,
		UploadsDir:       uploadsDir,
		OutputDir:        outputDir,
		SafeShareVersion: "1.4.1",
	}

	backupResult, err := Create(createOpts)
	if err != nil {
		t.Fatalf("Create backup failed: %v", err)
	}

	// Dry run restore
	restoreOpts := RestoreOptions{
		InputDir:      backupResult.BackupPath,
		DBPath:        restoreDBPath,
		HandleOrphans: OrphanKeep,
		DryRun:        true,
	}

	restoreResult, err := Restore(restoreOpts)
	if err != nil {
		t.Fatalf("Restore dry run failed: %v", err)
	}

	if !restoreResult.DryRun {
		t.Error("DryRun flag should be true")
	}

	// Verify no files were actually created
	if _, err := os.Stat(restoreDBPath); !os.IsNotExist(err) {
		t.Error("Database should not be created in dry run mode")
	}
}

// ============================================================================
// Additional tests for increased coverage
// ============================================================================

// Test validateFilename function
func TestValidateFilename(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{"valid filename", "test-file.txt", false},
		{"valid uuid", "550e8400-e29b-41d4-a716-446655440000", false},
		{"empty filename", "", true},
		{"path separator forward", "dir/file", true},
		{"path separator back", "dir\\file", true},
		{"parent traversal", "..", true},
		{"hidden file", ".hidden", true},
		{"partial dir", ".partial", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFilename(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFilename(%q) error = %v, wantErr %v", tt.filename, err, tt.wantErr)
			}
		})
	}
}

// Test RestoreUploadsDir
func TestRestoreUploadsDir(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "backup_uploads")
	destDir := filepath.Join(tmpDir, "restored_uploads")

	// Create source directory with test files
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}

	testFiles := []string{"file1", "file2", "file3"}
	for _, name := range testFiles {
		if err := os.WriteFile(filepath.Join(srcDir, name), []byte("content"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Test restore
	restored, err := RestoreUploadsDir(srcDir, destDir, nil)
	if err != nil {
		t.Fatalf("RestoreUploadsDir failed: %v", err)
	}

	if restored != 3 {
		t.Errorf("Expected 3 files restored, got %d", restored)
	}

	// Verify files exist in destination
	for _, name := range testFiles {
		if _, err := os.Stat(filepath.Join(destDir, name)); err != nil {
			t.Errorf("Expected file %s to exist in destination", name)
		}
	}
}

// Test RestoreUploadsDir with progress callback
func TestRestoreUploadsDirWithProgress(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "backup_uploads")
	destDir := filepath.Join(tmpDir, "restored_uploads")

	// Create source directory with test files
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(srcDir, filepath.Base(t.TempDir())), []byte("content"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	progressCalls := 0
	restored, err := RestoreUploadsDir(srcDir, destDir, func(current, total int, filename string) {
		progressCalls++
	})
	if err != nil {
		t.Fatalf("RestoreUploadsDir failed: %v", err)
	}

	if progressCalls != restored {
		t.Errorf("Expected %d progress calls, got %d", restored, progressCalls)
	}
}

// Test CountUploadFiles
func TestCountUploadFiles(t *testing.T) {
	tmpDir := t.TempDir()
	uploadsDir := filepath.Join(tmpDir, "uploads")
	createTestUploads(t, uploadsDir)

	count, err := CountUploadFiles(uploadsDir)
	if err != nil {
		t.Fatalf("CountUploadFiles failed: %v", err)
	}

	if count != 3 {
		t.Errorf("Expected 3 files, got %d", count)
	}
}

// Test GetUploadsTotalSize
func TestGetUploadsTotalSize(t *testing.T) {
	tmpDir := t.TempDir()
	uploadsDir := filepath.Join(tmpDir, "uploads")
	createTestUploads(t, uploadsDir)

	size, err := GetUploadsTotalSize(uploadsDir)
	if err != nil {
		t.Fatalf("GetUploadsTotalSize failed: %v", err)
	}

	if size == 0 {
		t.Error("Expected size > 0")
	}
}

// Test FindOrphanedFiles
func TestFindOrphanedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	uploadsDir := filepath.Join(tmpDir, "uploads")
	createTestUploads(t, uploadsDir)

	// Only uuid-123 is in the database
	dbStoredFilenames := map[string]bool{"uuid-123": true}

	orphans, err := FindOrphanedFiles(uploadsDir, dbStoredFilenames)
	if err != nil {
		t.Fatalf("FindOrphanedFiles failed: %v", err)
	}

	// uuid-456 and uuid-789 should be orphans
	if len(orphans) != 2 {
		t.Errorf("Expected 2 orphans, got %d", len(orphans))
	}
}

// Test FindMissingFiles
func TestFindMissingFiles(t *testing.T) {
	tmpDir := t.TempDir()
	uploadsDir := filepath.Join(tmpDir, "uploads")
	createTestUploads(t, uploadsDir)

	// Include a file record that doesn't exist
	records := []FileRecord{
		{ClaimCode: "ABC123", StoredFilename: "uuid-123", FileSize: 1024},
		{ClaimCode: "MISSING", StoredFilename: "uuid-missing", FileSize: 2048},
	}

	missing, err := FindMissingFiles(uploadsDir, records)
	if err != nil {
		t.Fatalf("FindMissingFiles failed: %v", err)
	}

	if len(missing) != 1 {
		t.Errorf("Expected 1 missing, got %d", len(missing))
	}

	if len(missing) > 0 && missing[0].ClaimCode != "MISSING" {
		t.Errorf("Expected claim code MISSING, got %s", missing[0].ClaimCode)
	}
}

// Test VerifyUploadsIntegrity
func TestVerifyUploadsIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	uploadsDir := filepath.Join(tmpDir, "uploads")
	createTestUploads(t, uploadsDir)

	// Check for files that exist and one that doesn't
	expectedFiles := []string{"uuid-123", "uuid-456", "uuid-missing"}

	missing, err := VerifyUploadsIntegrity(uploadsDir, expectedFiles)
	if err != nil {
		t.Fatalf("VerifyUploadsIntegrity failed: %v", err)
	}

	if len(missing) != 1 {
		t.Errorf("Expected 1 missing, got %d", len(missing))
	}

	if len(missing) > 0 && missing[0] != "uuid-missing" {
		t.Errorf("Expected uuid-missing, got %s", missing[0])
	}
}

// Test CleanupUploadsDir
func TestCleanupUploadsDir(t *testing.T) {
	tmpDir := t.TempDir()
	uploadsDir := filepath.Join(tmpDir, "uploads")
	createTestUploads(t, uploadsDir)

	// Only keep uuid-123
	keepFiles := map[string]bool{"uuid-123": true}

	removed, err := CleanupUploadsDir(uploadsDir, keepFiles)
	if err != nil {
		t.Fatalf("CleanupUploadsDir failed: %v", err)
	}

	if removed != 2 {
		t.Errorf("Expected 2 removed, got %d", removed)
	}

	// Verify uuid-123 still exists
	if _, err := os.Stat(filepath.Join(uploadsDir, "uuid-123")); err != nil {
		t.Error("uuid-123 should still exist")
	}

	// Verify uuid-456 was removed
	if _, err := os.Stat(filepath.Join(uploadsDir, "uuid-456")); !os.IsNotExist(err) {
		t.Error("uuid-456 should be removed")
	}
}

// Test QuickVerify
func TestQuickVerify(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	outputDir := filepath.Join(tmpDir, "backups")

	// Create test data
	createTestDatabase(t, dbPath)
	createTestUploads(t, uploadsDir)
	os.MkdirAll(outputDir, 0755)

	// Create a backup
	opts := CreateOptions{
		Mode:             ModeFull,
		DBPath:           dbPath,
		UploadsDir:       uploadsDir,
		OutputDir:        outputDir,
		SafeShareVersion: "1.4.1",
	}

	result, err := Create(opts)
	if err != nil {
		t.Fatalf("Create backup failed: %v", err)
	}

	// Quick verify
	verifyResult := QuickVerify(result.BackupPath)

	if !verifyResult.Valid {
		t.Errorf("QuickVerify should return valid, errors: %v", verifyResult.Errors)
	}

	// Should have warning about skipped checksum verification
	hasWarning := false
	for _, w := range verifyResult.Warnings {
		if w == "Checksum verification skipped (quick mode)" {
			hasWarning = true
			break
		}
	}
	if !hasWarning {
		t.Error("Expected checksum skip warning in quick mode")
	}
}

// Test VerifyWithProgress
func TestVerifyWithProgress(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	outputDir := filepath.Join(tmpDir, "backups")

	// Create test data
	createTestDatabase(t, dbPath)
	createTestUploads(t, uploadsDir)
	os.MkdirAll(outputDir, 0755)

	// Create a backup
	opts := CreateOptions{
		Mode:             ModeFull,
		DBPath:           dbPath,
		UploadsDir:       uploadsDir,
		OutputDir:        outputDir,
		SafeShareVersion: "1.4.1",
	}

	result, err := Create(opts)
	if err != nil {
		t.Fatalf("Create backup failed: %v", err)
	}

	// Verify with progress
	progressCalls := 0
	verifyResult := VerifyWithProgress(result.BackupPath, func(current, total int, description string) {
		progressCalls++
	})

	if !verifyResult.Valid {
		t.Errorf("VerifyWithProgress should return valid, errors: %v", verifyResult.Errors)
	}

	if progressCalls == 0 {
		t.Error("Expected progress callbacks")
	}
}

// Test CreateBackup with invalid options
func TestCreateBackupInvalidOptions(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		opts    CreateOptions
		wantErr bool
	}{
		{
			name: "invalid mode",
			opts: CreateOptions{
				Mode:      BackupMode("invalid"),
				DBPath:    "/tmp/db.db",
				OutputDir: tmpDir,
			},
			wantErr: true,
		},
		{
			name: "empty db path",
			opts: CreateOptions{
				Mode:      ModeDatabase,
				DBPath:    "",
				OutputDir: tmpDir,
			},
			wantErr: true,
		},
		{
			name: "empty output dir",
			opts: CreateOptions{
				Mode:   ModeDatabase,
				DBPath: "/tmp/db.db",
			},
			wantErr: true,
		},
		{
			name: "full mode without uploads dir",
			opts: CreateOptions{
				Mode:      ModeFull,
				DBPath:    "/tmp/db.db",
				OutputDir: tmpDir,
			},
			wantErr: true,
		},
		{
			name: "nonexistent db",
			opts: CreateOptions{
				Mode:      ModeDatabase,
				DBPath:    "/nonexistent/path/db.db",
				OutputDir: tmpDir,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Create(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test RestoreBackup with invalid options
func TestRestoreInvalidOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    RestoreOptions
		wantErr bool
	}{
		{
			name: "empty input dir",
			opts: RestoreOptions{
				InputDir:      "",
				DBPath:        "/tmp/db.db",
				HandleOrphans: OrphanKeep,
			},
			wantErr: true,
		},
		{
			name: "empty db path",
			opts: RestoreOptions{
				InputDir:      "/tmp/backup",
				DBPath:        "",
				HandleOrphans: OrphanKeep,
			},
			wantErr: true,
		},
		{
			name: "invalid orphan handling",
			opts: RestoreOptions{
				InputDir:      "/tmp/backup",
				DBPath:        "/tmp/db.db",
				HandleOrphans: OrphanHandling("invalid"),
			},
			wantErr: true,
		},
		{
			name: "prompt mode without callback",
			opts: RestoreOptions{
				InputDir:      "/tmp/backup",
				DBPath:        "/tmp/db.db",
				HandleOrphans: OrphanPrompt,
			},
			wantErr: true,
		},
		{
			name: "nonexistent input dir",
			opts: RestoreOptions{
				InputDir:      "/nonexistent/backup",
				DBPath:        "/tmp/db.db",
				HandleOrphans: OrphanKeep,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Restore(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Restore() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test Verify with nonexistent directory
func TestVerifyNonexistentDir(t *testing.T) {
	result := Verify("/nonexistent/backup")

	if result.Valid {
		t.Error("Expected invalid result for nonexistent directory")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected errors for nonexistent directory")
	}
}

// Test Verify with missing manifest
func TestVerifyMissingManifest(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an empty directory (no manifest)
	result := Verify(tmpDir)

	if result.Valid {
		t.Error("Expected invalid result for directory without manifest")
	}

	if result.ManifestValid {
		t.Error("ManifestValid should be false")
	}
}

// Test Verify with corrupted checksum
func TestVerifyCorruptedChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	outputDir := filepath.Join(tmpDir, "backups")

	// Create test data
	createTestDatabase(t, dbPath)
	createTestUploads(t, uploadsDir)
	os.MkdirAll(outputDir, 0755)

	// Create a backup
	opts := CreateOptions{
		Mode:             ModeFull,
		DBPath:           dbPath,
		UploadsDir:       uploadsDir,
		OutputDir:        outputDir,
		SafeShareVersion: "1.4.1",
	}

	result, err := Create(opts)
	if err != nil {
		t.Fatalf("Create backup failed: %v", err)
	}

	// Corrupt a file
	dbBackupPath := filepath.Join(result.BackupPath, DatabaseFilename)
	if err := os.WriteFile(dbBackupPath, []byte("corrupted"), 0644); err != nil {
		t.Fatalf("Failed to corrupt file: %v", err)
	}

	// Verify should fail
	verifyResult := Verify(result.BackupPath)

	if verifyResult.ChecksumsValid {
		t.Error("ChecksumsValid should be false for corrupted file")
	}
}

// Test ListBackups with nonexistent directory
func TestListBackupsNonexistentDir(t *testing.T) {
	backups, err := ListBackups("/nonexistent/backups")

	if err != nil {
		t.Fatalf("ListBackups should not error for nonexistent directory: %v", err)
	}

	if len(backups) != 0 {
		t.Errorf("Expected empty list, got %d backups", len(backups))
	}
}

// Test GetFileRecords
func TestGetFileRecords(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	createTestDatabase(t, dbPath)

	records, err := GetFileRecords(dbPath)
	if err != nil {
		t.Fatalf("GetFileRecords failed: %v", err)
	}

	if len(records) != 1 {
		t.Errorf("Expected 1 record, got %d", len(records))
	}

	if len(records) > 0 {
		if records[0].ClaimCode != "ABC123" {
			t.Errorf("Expected claim code ABC123, got %s", records[0].ClaimCode)
		}
		if records[0].StoredFilename != "uuid-123" {
			t.Errorf("Expected stored filename uuid-123, got %s", records[0].StoredFilename)
		}
	}
}

// Test DeleteOrphanedFileRecords
func TestDeleteOrphanedFileRecords(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	createTestDatabase(t, dbPath)

	// Delete the record
	deleted, err := DeleteOrphanedFileRecords(dbPath, []string{"uuid-123"})
	if err != nil {
		t.Fatalf("DeleteOrphanedFileRecords failed: %v", err)
	}

	if deleted != 1 {
		t.Errorf("Expected 1 deleted, got %d", deleted)
	}

	// Verify record is gone
	records, err := GetFileRecords(dbPath)
	if err != nil {
		t.Fatalf("GetFileRecords failed: %v", err)
	}

	if len(records) != 0 {
		t.Errorf("Expected 0 records, got %d", len(records))
	}
}

// Test DeleteOrphanedFileRecords with empty list
func TestDeleteOrphanedFileRecordsEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	createTestDatabase(t, dbPath)

	// Delete with empty list
	deleted, err := DeleteOrphanedFileRecords(dbPath, []string{})
	if err != nil {
		t.Fatalf("DeleteOrphanedFileRecords failed: %v", err)
	}

	if deleted != 0 {
		t.Errorf("Expected 0 deleted, got %d", deleted)
	}
}

// Test GetTableCounts
func TestGetTableCounts(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	createTestDatabase(t, dbPath)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	counts, err := GetTableCounts(db)
	if err != nil {
		t.Fatalf("GetTableCounts failed: %v", err)
	}

	if counts["users"] != 1 {
		t.Errorf("Expected 1 user, got %d", counts["users"])
	}

	if counts["files"] != 1 {
		t.Errorf("Expected 1 file, got %d", counts["files"])
	}
}

// Test GetDirectorySize
func TestGetDirectorySize(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some files
	if err := os.WriteFile(filepath.Join(tmpDir, "file1"), []byte("content1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "file2"), []byte("content2"), 0644); err != nil {
		t.Fatal(err)
	}

	size, err := GetDirectorySize(tmpDir)
	if err != nil {
		t.Fatalf("GetDirectorySize failed: %v", err)
	}

	if size == 0 {
		t.Error("Expected size > 0")
	}
}

// Test GetFileSize
func TestGetFileSize(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	content := []byte("Hello, World!")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	size, err := GetFileSize(testFile)
	if err != nil {
		t.Fatalf("GetFileSize failed: %v", err)
	}

	if size != int64(len(content)) {
		t.Errorf("Expected size %d, got %d", len(content), size)
	}
}

// Test RestoreDatabase
func TestRestoreDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDB := filepath.Join(tmpDir, "source.db")
	backupDB := filepath.Join(tmpDir, "backup.db")
	restoreDB := filepath.Join(tmpDir, "restored.db")

	// Create source database
	createTestDatabase(t, sourceDB)

	// Backup it
	if err := BackupDatabase(sourceDB, backupDB); err != nil {
		t.Fatalf("BackupDatabase failed: %v", err)
	}

	// Restore from backup
	if err := RestoreDatabase(backupDB, restoreDB); err != nil {
		t.Fatalf("RestoreDatabase failed: %v", err)
	}

	// Verify restored database
	if err := ValidateDatabase(restoreDB); err != nil {
		t.Errorf("Restored database validation failed: %v", err)
	}
}

// Test VerifyChecksum
func TestVerifyChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	content := "Hello, World!"
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Correct checksum
	correctChecksum := "sha256:dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"

	err := VerifyChecksum(testFile, correctChecksum)
	if err != nil {
		t.Errorf("VerifyChecksum should pass for correct checksum: %v", err)
	}

	// Incorrect checksum
	wrongChecksum := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	err = VerifyChecksum(testFile, wrongChecksum)
	if err == nil {
		t.Error("VerifyChecksum should fail for incorrect checksum")
	}
}

// Test BackupMode String method
func TestBackupModeString(t *testing.T) {
	tests := []struct {
		mode     BackupMode
		expected string
	}{
		{ModeConfig, "config"},
		{ModeDatabase, "database"},
		{ModeFull, "full"},
	}

	for _, tt := range tests {
		if tt.mode.String() != tt.expected {
			t.Errorf("BackupMode.String() = %s, want %s", tt.mode.String(), tt.expected)
		}
	}
}

// Test OrphanHandling String method
func TestOrphanHandlingString(t *testing.T) {
	tests := []struct {
		handling OrphanHandling
		expected string
	}{
		{OrphanKeep, "keep"},
		{OrphanRemove, "remove"},
		{OrphanPrompt, "prompt"},
	}

	for _, tt := range tests {
		if tt.handling.String() != tt.expected {
			t.Errorf("OrphanHandling.String() = %s, want %s", tt.handling.String(), tt.expected)
		}
	}
}

// Test NewManifest for different modes
func TestNewManifestModes(t *testing.T) {
	tests := []struct {
		name         string
		mode         BackupMode
		wantFiles    bool
		wantUsers    bool
		wantMetadata bool
	}{
		{
			name:         "config mode",
			mode:         ModeConfig,
			wantFiles:    false,
			wantUsers:    false,
			wantMetadata: false,
		},
		{
			name:         "database mode",
			mode:         ModeDatabase,
			wantFiles:    false,
			wantUsers:    true,
			wantMetadata: true,
		},
		{
			name:         "full mode",
			mode:         ModeFull,
			wantFiles:    true,
			wantUsers:    true,
			wantMetadata: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := NewManifest(tt.mode, "1.0.0")

			if manifest.Includes.Files != tt.wantFiles {
				t.Errorf("Files = %v, want %v", manifest.Includes.Files, tt.wantFiles)
			}
			if manifest.Includes.Users != tt.wantUsers {
				t.Errorf("Users = %v, want %v", manifest.Includes.Users, tt.wantUsers)
			}
			if manifest.Includes.FileMetadata != tt.wantMetadata {
				t.Errorf("FileMetadata = %v, want %v", manifest.Includes.FileMetadata, tt.wantMetadata)
			}
		})
	}
}

// Test Create with encryption key
func TestCreateBackupWithEncryptionKey(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	outputDir := filepath.Join(tmpDir, "backups")

	// Create test data
	createTestDatabase(t, dbPath)
	createTestUploads(t, uploadsDir)
	os.MkdirAll(outputDir, 0755)

	// Create backup with encryption key
	opts := CreateOptions{
		Mode:             ModeDatabase,
		DBPath:           dbPath,
		UploadsDir:       uploadsDir,
		OutputDir:        outputDir,
		EncryptionKey:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		SafeShareVersion: "1.4.1",
	}

	result, err := Create(opts)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if !result.Manifest.Encryption.Enabled {
		t.Error("Encryption should be marked as enabled")
	}

	if result.Manifest.Encryption.KeyFingerprint == "" {
		t.Error("KeyFingerprint should be set")
	}
}

// Test Create with progress callback
func TestCreateBackupWithProgress(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	outputDir := filepath.Join(tmpDir, "backups")

	// Create test data
	createTestDatabase(t, dbPath)
	createTestUploads(t, uploadsDir)
	os.MkdirAll(outputDir, 0755)

	progressCalls := 0
	opts := CreateOptions{
		Mode:             ModeFull,
		DBPath:           dbPath,
		UploadsDir:       uploadsDir,
		OutputDir:        outputDir,
		SafeShareVersion: "1.4.1",
		ProgressCallback: func(current, total int, description string) {
			progressCalls++
		},
	}

	_, err := Create(opts)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if progressCalls == 0 {
		t.Error("Expected progress callbacks")
	}
}

// Test Restore with OrphanRemove
func TestRestoreWithOrphanRemove(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	outputDir := filepath.Join(tmpDir, "backups")
	restoreDBPath := filepath.Join(tmpDir, "restored.db")

	// Create test data
	createTestDatabase(t, dbPath)
	createTestUploads(t, uploadsDir)
	os.MkdirAll(outputDir, 0755)

	// Create a database-only backup (will have orphans since no files)
	createOpts := CreateOptions{
		Mode:             ModeDatabase,
		DBPath:           dbPath,
		UploadsDir:       uploadsDir,
		OutputDir:        outputDir,
		SafeShareVersion: "1.4.1",
	}

	backupResult, err := Create(createOpts)
	if err != nil {
		t.Fatalf("Create backup failed: %v", err)
	}

	// Restore with OrphanRemove
	restoreOpts := RestoreOptions{
		InputDir:      backupResult.BackupPath,
		DBPath:        restoreDBPath,
		HandleOrphans: OrphanRemove,
		Force:         true,
	}

	restoreResult, err := Restore(restoreOpts)
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	if !restoreResult.Success {
		t.Errorf("Restore should succeed: %s", restoreResult.Error)
	}

	// Since there's 1 file record and no files were restored, there should be 1 orphan
	if restoreResult.OrphansFound != 1 {
		t.Errorf("Expected 1 orphan found, got %d", restoreResult.OrphansFound)
	}

	if restoreResult.OrphansRemoved != 1 {
		t.Errorf("Expected 1 orphan removed, got %d", restoreResult.OrphansRemoved)
	}
}

// Test Restore with encryption key mismatch warning
func TestRestoreEncryptionKeyMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	outputDir := filepath.Join(tmpDir, "backups")
	restoreDBPath := filepath.Join(tmpDir, "restored.db")

	// Create test data
	createTestDatabase(t, dbPath)
	createTestUploads(t, uploadsDir)
	os.MkdirAll(outputDir, 0755)

	// Create backup with encryption key
	originalKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	createOpts := CreateOptions{
		Mode:             ModeDatabase,
		DBPath:           dbPath,
		UploadsDir:       uploadsDir,
		OutputDir:        outputDir,
		EncryptionKey:    originalKey,
		SafeShareVersion: "1.4.1",
	}

	backupResult, err := Create(createOpts)
	if err != nil {
		t.Fatalf("Create backup failed: %v", err)
	}

	// Restore with different encryption key
	differentKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	restoreOpts := RestoreOptions{
		InputDir:      backupResult.BackupPath,
		DBPath:        restoreDBPath,
		EncryptionKey: differentKey,
		HandleOrphans: OrphanKeep,
		Force:         true,
	}

	restoreResult, err := Restore(restoreOpts)
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// Should have a warning about key mismatch
	hasWarning := false
	for _, w := range restoreResult.Warnings {
		if w == "Encryption key fingerprint does not match backup - files may not be decryptable" {
			hasWarning = true
			break
		}
	}

	if !hasWarning {
		t.Error("Expected encryption key mismatch warning")
	}
}

// Test GetBackupDirName format
func TestGetBackupDirName(t *testing.T) {
	name := GetBackupDirName()

	if name == "" {
		t.Error("GetBackupDirName should return non-empty string")
	}

	// Should start with "backup-"
	if len(name) < 7 || name[:7] != "backup-" {
		t.Errorf("GetBackupDirName should start with 'backup-', got %s", name)
	}
}

// Test ValidateDatabase with invalid database
func TestValidateDatabaseInvalid(t *testing.T) {
	tmpDir := t.TempDir()
	invalidDB := filepath.Join(tmpDir, "invalid.db")

	// Create an invalid database file
	if err := os.WriteFile(invalidDB, []byte("not a database"), 0644); err != nil {
		t.Fatal(err)
	}

	err := ValidateDatabase(invalidDB)
	if err == nil {
		t.Error("ValidateDatabase should fail for invalid database")
	}
}

// Test ComputeChecksum with nonexistent file
func TestComputeChecksumNonexistent(t *testing.T) {
	_, err := ComputeChecksum("/nonexistent/file")
	if err == nil {
		t.Error("ComputeChecksum should fail for nonexistent file")
	}
}

// Test ReadManifest with invalid JSON
func TestReadManifestInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, ManifestFilename)

	// Write invalid JSON
	if err := os.WriteFile(manifestPath, []byte("not valid json"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadManifest(tmpDir)
	if err == nil {
		t.Error("ReadManifest should fail for invalid JSON")
	}
}

// Test contains and containsAt helper functions
func TestContainsHelpers(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   bool
	}{
		{"no such table", "no such table", true},
		{"error: no such table foo", "no such table", true},
		{"table doesn't exist", "doesn't exist", true},
		{"success", "no such table", false},
		{"", "test", false},
		{"test", "", true}, // empty substr always matches
	}

	for _, tt := range tests {
		got := contains(tt.s, tt.substr)
		if got != tt.want {
			t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
		}
	}
}

// Test isTableNotFound
func TestIsTableNotFound(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{sql.ErrNoRows, false},
	}

	for _, tt := range tests {
		got := isTableNotFound(tt.err)
		if got != tt.want {
			t.Errorf("isTableNotFound(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

// Test ValidateManifest with nil checksums
func TestValidateManifestNilChecksums(t *testing.T) {
	manifest := &BackupManifest{
		Version:   "1.0",
		CreatedAt: time.Now(),
		Mode:      ModeDatabase,
		Checksums: nil,
	}

	err := ValidateManifest(manifest)
	if err == nil {
		t.Error("ValidateManifest should fail for nil checksums")
	}
}
