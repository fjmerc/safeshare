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
