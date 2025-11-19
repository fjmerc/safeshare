package main

import (
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	_ "modernc.org/sqlite"
)

// setupTestEnvironment creates a test database, uploads directory, and encryption key
func setupTestEnvironment(t *testing.T) (dbPath, uploadsDir, encKey string, cleanup func()) {
	t.Helper()

	// Create temp directory for test
	tempDir := t.TempDir()

	// Create test database
	dbPath = filepath.Join(tempDir, "test.db")
	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("failed to initialize test database: %v", err)
	}
	db.Close()

	// Create uploads directory
	uploadsDir = filepath.Join(tempDir, "uploads")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatalf("failed to create uploads directory: %v", err)
	}

	// Generate encryption key (64 hex chars = 32 bytes)
	encKey = hex.EncodeToString(make([]byte, 32))
	// Use a fixed key for deterministic tests
	encKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	cleanup = func() {
		// t.TempDir() handles cleanup automatically
	}

	return dbPath, uploadsDir, encKey, cleanup
}

// createTestFile creates a test file with given content
func createTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	return path
}

func TestRun_Version(t *testing.T) {
	args := []string{"-version"}
	err := run(args)
	if err != nil {
		t.Errorf("expected no error for version flag, got: %v", err)
	}
}

func TestRun_NoArguments(t *testing.T) {
	args := []string{}
	err := run(args)
	if err == nil {
		t.Error("expected error when no arguments provided")
	}
	if !strings.Contains(err.Error(), "either -source or -directory must be specified") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRun_MissingRequiredFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  string
	}{
		{
			name:    "missing db flag",
			args:    []string{"-source", "/tmp/test.txt", "-uploads", "/tmp/uploads", "-enckey", "abc"},
			wantErr: "-db flag is required",
		},
		{
			name:    "missing uploads flag",
			args:    []string{"-source", "/tmp/test.txt", "-db", "/tmp/db.db", "-enckey", "abc"},
			wantErr: "-uploads flag is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(tt.args)
			if err == nil {
				t.Error("expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidateOptions_BothSourceAndDirectory(t *testing.T) {
	opts := &ImportOptions{
		SourceFile: "/tmp/file.txt",
		Directory:  "/tmp/dir",
	}

	err := validateOptions(opts)
	if err == nil {
		t.Error("expected error when both source and directory are set")
	}
	if !strings.Contains(err.Error(), "cannot specify both -source and -directory") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateOptions_InvalidEncryptionKey(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	uploadsDir := filepath.Join(tempDir, "uploads")
	os.MkdirAll(uploadsDir, 0755)

	// Create minimal database
	db, _ := sql.Open("sqlite", dbPath)
	db.Close()

	tests := []struct {
		name    string
		key     string
		wantErr string
	}{
		{
			name:    "too short",
			key:     "abc",
			wantErr: "encryption key must be exactly 64 hexadecimal characters",
		},
		{
			name:    "non-hex characters",
			key:     "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			wantErr: "encryption key must be valid hexadecimal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &ImportOptions{
				SourceFile: filepath.Join(tempDir, "test.txt"),
				DBPath:     dbPath,
				UploadsDir: uploadsDir,
				EncryptKey: tt.key,
			}

			// Create test file
			os.WriteFile(opts.SourceFile, []byte("test"), 0644)

			err := validateOptions(opts)
			if err == nil {
				t.Error("expected error for invalid encryption key")
				return
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidateOptions_SourceFileNotFound(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	uploadsDir := filepath.Join(tempDir, "uploads")
	os.MkdirAll(uploadsDir, 0755)

	// Create minimal database
	db, _ := sql.Open("sqlite", dbPath)
	db.Close()

	opts := &ImportOptions{
		SourceFile: "/nonexistent/file.txt",
		DBPath:     dbPath,
		UploadsDir: uploadsDir,
		EncryptKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	err := validateOptions(opts)
	if err == nil {
		t.Error("expected error for nonexistent source file")
		return
	}
	if !strings.Contains(err.Error(), "cannot access source file") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateOptions_DirectoryNotFound(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	uploadsDir := filepath.Join(tempDir, "uploads")
	os.MkdirAll(uploadsDir, 0755)

	// Create minimal database
	db, _ := sql.Open("sqlite", dbPath)
	db.Close()

	opts := &ImportOptions{
		Directory:  "/nonexistent/directory",
		DBPath:     dbPath,
		UploadsDir: uploadsDir,
		EncryptKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	err := validateOptions(opts)
	if err == nil {
		t.Error("expected error for nonexistent directory")
		return
	}
	if !strings.Contains(err.Error(), "cannot access directory") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateFileExtension(t *testing.T) {
	blockedExts := []string{".exe", ".bat", ".cmd"}

	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			name:     "safe extension",
			filename: "document.pdf",
			wantErr:  false,
		},
		{
			name:     "blocked extension",
			filename: "virus.exe",
			wantErr:  true,
		},
		{
			name:     "double extension blocked",
			filename: "archive.tar.exe",
			wantErr:  true,
		},
		{
			name:     "case insensitive",
			filename: "VIRUS.EXE",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFileExtension(tt.filename, blockedExts)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFileExtension() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHashFile(t *testing.T) {
	tempDir := t.TempDir()

	// Create test file with known content
	testFile := filepath.Join(tempDir, "test.txt")
	content := "hello world"
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	hash1, err := hashFile(testFile)
	if err != nil {
		t.Fatalf("hashFile() error = %v", err)
	}

	// Hash should be consistent
	hash2, err := hashFile(testFile)
	if err != nil {
		t.Fatalf("hashFile() error = %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("hash mismatch: %s != %s", hash1, hash2)
	}

	// Hash should be 64 characters (SHA256 hex)
	if len(hash1) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash1))
	}
}

func TestHashFile_NonexistentFile(t *testing.T) {
	_, err := hashFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestCheckQuotaAvailable(t *testing.T) {
	dbPath, _, _, cleanup := setupTestEnvironment(t)
	defer cleanup()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// Add some files to simulate current usage
	// Insert a 5GB file
	file := &models.File{
		ClaimCode:        "test123456",
		OriginalFilename: "test.bin",
		StoredFilename:   "uuid.bin",
		FileSize:         5 * 1024 * 1024 * 1024, // 5GB
		MimeType:         "application/octet-stream",
		UploaderIP:       "127.0.0.1",
	}
	if err := database.CreateFile(db, file); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	tests := []struct {
		name     string
		fileSize int64
		quotaGB  int64
		wantErr  bool
	}{
		{
			name:     "within quota",
			fileSize: 1 * 1024 * 1024 * 1024, // 1GB
			quotaGB:  10,                      // 10GB quota
			wantErr:  false,
		},
		{
			name:     "exceeds quota",
			fileSize: 6 * 1024 * 1024 * 1024, // 6GB
			quotaGB:  10,                      // 10GB quota (5GB used + 6GB = 11GB > 10GB)
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkQuotaAvailable(db, tt.fileSize, tt.quotaGB)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkQuotaAvailable() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestImportSingleFile_DryRun(t *testing.T) {
	dbPath, uploadsDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create test file
	tempDir := t.TempDir()
	testFile := createTestFile(t, tempDir, "test.txt", "test content")

	opts := &ImportOptions{
		SourceFile:        testFile,
		DBPath:            dbPath,
		UploadsDir:        uploadsDir,
		EncryptKey:        encKey,
		DryRun:            true,
		BlockedExtensions: []string{},
	}

	result := importSingleFile(opts)

	if !result.Success {
		t.Errorf("expected success in dry-run mode, got: %s", result.Error)
	}

	// Verify source file still exists
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Error("source file should not be deleted in dry-run mode")
	}

	// Verify no encrypted file was created
	files, _ := os.ReadDir(uploadsDir)
	if len(files) > 0 {
		t.Error("no files should be created in dry-run mode")
	}
}

func TestImportSingleFile_BlockedExtension(t *testing.T) {
	dbPath, uploadsDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create test file with blocked extension
	tempDir := t.TempDir()
	testFile := createTestFile(t, tempDir, "virus.exe", "malware")

	opts := &ImportOptions{
		SourceFile:        testFile,
		DBPath:            dbPath,
		UploadsDir:        uploadsDir,
		EncryptKey:        encKey,
		BlockedExtensions: []string{".exe"},
	}

	result := importSingleFile(opts)

	if !result.Skipped {
		t.Error("expected file to be skipped due to blocked extension")
	}

	if !strings.Contains(result.SkipReason, "blocked extension") {
		t.Errorf("unexpected skip reason: %s", result.SkipReason)
	}
}

func TestImportSingleFile_Success(t *testing.T) {
	dbPath, uploadsDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create test file
	tempDir := t.TempDir()
	testContent := "This is test content for import"
	testFile := createTestFile(t, tempDir, "document.pdf", testContent)

	opts := &ImportOptions{
		SourceFile:        testFile,
		DisplayName:       "test-document.pdf",
		ExpiresHours:      24,
		MaxDownloads:      5,
		DBPath:            dbPath,
		UploadsDir:        uploadsDir,
		EncryptKey:        encKey,
		PublicURL:         "https://test.example.com",
		UploaderIP:        "192.168.1.1",
		BlockedExtensions: []string{},
		NoDelete:          true, // Preserve source for verification
	}

	result := importSingleFile(opts)

	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}

	// Verify result fields
	if result.ClaimCode == "" {
		t.Error("claim code should not be empty")
	}

	if result.DisplayName != "test-document.pdf" {
		t.Errorf("expected display name 'test-document.pdf', got: %s", result.DisplayName)
	}

	if result.OriginalSize != int64(len(testContent)) {
		t.Errorf("expected original size %d, got: %d", len(testContent), result.OriginalSize)
	}

	if result.EncryptedSize == 0 {
		t.Error("encrypted size should not be zero")
	}

	if !strings.Contains(result.DownloadURL, result.ClaimCode) {
		t.Error("download URL should contain claim code")
	}

	// Verify encrypted file exists
	files, err := os.ReadDir(uploadsDir)
	if err != nil {
		t.Fatalf("failed to read uploads directory: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("expected 1 file in uploads directory, got %d", len(files))
	}

	// Verify database record
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	file, err := database.GetFileByClaimCode(db, result.ClaimCode)
	if err != nil {
		t.Fatalf("failed to get file from database: %v", err)
	}

	if file.OriginalFilename != "test-document.pdf" {
		t.Errorf("expected filename 'test-document.pdf', got: %s", file.OriginalFilename)
	}

	if file.UploaderIP != "192.168.1.1" {
		t.Errorf("expected uploader IP '192.168.1.1', got: %s", file.UploaderIP)
	}

	if file.MaxDownloads == nil || *file.MaxDownloads != 5 {
		t.Errorf("expected max downloads 5, got: %v", file.MaxDownloads)
	}
}

func TestImportSingleFile_WithVerification(t *testing.T) {
	// Skip this test if it takes too long
	if testing.Short() {
		t.Skip("skipping verification test in short mode")
	}

	dbPath, uploadsDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create test file
	tempDir := t.TempDir()
	testContent := "Content for verification test"
	testFile := createTestFile(t, tempDir, "verify-test.txt", testContent)

	opts := &ImportOptions{
		SourceFile:        testFile,
		DBPath:            dbPath,
		UploadsDir:        uploadsDir,
		EncryptKey:        encKey,
		PublicURL:         "https://test.example.com",
		UploaderIP:        "test-ip",
		BlockedExtensions: []string{},
		Verify:            true,
		NoDelete:          true,
		Quiet:             true, // Suppress output during tests
	}

	result := importSingleFile(opts)

	if !result.Success {
		t.Fatalf("expected success with verification, got error: %s", result.Error)
	}

	if result.VerificationTime == "" {
		t.Error("verification time should not be empty when verify=true")
	}
}

func TestParseBlockedExtensions(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty string",
			input: "",
			want:  []string{},
		},
		{
			name:  "single extension",
			input: ".exe",
			want:  []string{".exe"},
		},
		{
			name:  "multiple extensions",
			input: ".exe,.bat,.cmd",
			want:  []string{".exe", ".bat", ".cmd"},
		},
		{
			name:  "extensions without dot",
			input: "exe,bat,cmd",
			want:  []string{".exe", ".bat", ".cmd"},
		},
		{
			name:  "mixed case",
			input: ".EXE,.Bat,.CMD",
			want:  []string{".exe", ".bat", ".cmd"},
		},
		{
			name:  "with spaces",
			input: " .exe , .bat , .cmd ",
			want:  []string{".exe", ".bat", ".cmd"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBlockedExtensions(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("parseBlockedExtensions() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseBlockedExtensions()[%d] = %s, want %s", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestImportDirectory_DryRun(t *testing.T) {
	dbPath, uploadsDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create test directory with multiple files
	tempDir := t.TempDir()
	testDir := filepath.Join(tempDir, "import-test")
	os.MkdirAll(testDir, 0755)

	createTestFile(t, testDir, "file1.txt", "content1")
	createTestFile(t, testDir, "file2.pdf", "content2")
	createTestFile(t, testDir, "file3.jpg", "content3")

	opts := &ImportOptions{
		Directory:         testDir,
		DBPath:            dbPath,
		UploadsDir:        uploadsDir,
		EncryptKey:        encKey,
		PublicURL:         "https://test.example.com",
		BlockedExtensions: []string{},
		DryRun:            true,
		Quiet:             true,
	}

	summary := importDirectory(opts)

	// In dry-run, all files should be marked as successful
	if summary.Successful != 3 {
		t.Errorf("expected 3 successful files in dry-run, got %d", summary.Successful)
	}

	// No files should be created
	files, _ := os.ReadDir(uploadsDir)
	if len(files) > 0 {
		t.Error("no files should be created in dry-run mode")
	}
}

func TestImportDirectory_WithBlockedExtension(t *testing.T) {
	dbPath, uploadsDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create test directory with mixed files
	tempDir := t.TempDir()
	testDir := filepath.Join(tempDir, "import-test")
	os.MkdirAll(testDir, 0755)

	createTestFile(t, testDir, "document.pdf", "safe content")
	createTestFile(t, testDir, "virus.exe", "malware")
	createTestFile(t, testDir, "script.sh", "script content")

	opts := &ImportOptions{
		Directory:         testDir,
		DBPath:            dbPath,
		UploadsDir:        uploadsDir,
		EncryptKey:        encKey,
		PublicURL:         "https://test.example.com",
		BlockedExtensions: []string{".exe", ".sh"},
		NoDelete:          true,
		Quiet:             true,
		JSON:              true,
	}

	summary := importDirectory(opts)

	if summary.TotalFiles != 3 {
		t.Errorf("expected 3 total files, got %d", summary.TotalFiles)
	}

	if summary.Successful != 1 {
		t.Errorf("expected 1 successful import, got %d", summary.Successful)
	}

	if summary.Skipped != 2 {
		t.Errorf("expected 2 skipped files, got %d", summary.Skipped)
	}

	if summary.Failed != 0 {
		t.Errorf("expected 0 failed files, got %d", summary.Failed)
	}
}

func TestImportDirectory_Recursive(t *testing.T) {
	dbPath, uploadsDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create nested directory structure
	tempDir := t.TempDir()
	testDir := filepath.Join(tempDir, "import-test")
	subDir := filepath.Join(testDir, "subdir")
	os.MkdirAll(subDir, 0755)

	createTestFile(t, testDir, "root-file.txt", "root content")
	createTestFile(t, subDir, "sub-file.txt", "sub content")

	// Test non-recursive (should only import root file)
	opts := &ImportOptions{
		Directory:         testDir,
		Recursive:         false,
		DBPath:            dbPath,
		UploadsDir:        uploadsDir,
		EncryptKey:        encKey,
		PublicURL:         "https://test.example.com",
		BlockedExtensions: []string{},
		NoDelete:          true,
		Quiet:             true,
		JSON:              true,
	}

	summary := importDirectory(opts)

	if summary.Successful != 1 {
		t.Errorf("non-recursive: expected 1 file, got %d", summary.Successful)
	}

	// Test recursive (should import both files)
	// Need fresh uploads directory
	uploadsDir2 := filepath.Join(tempDir, "uploads2")
	os.MkdirAll(uploadsDir2, 0755)

	opts.Recursive = true
	opts.UploadsDir = uploadsDir2

	summary = importDirectory(opts)

	if summary.Successful != 2 {
		t.Errorf("recursive: expected 2 files, got %d", summary.Successful)
	}
}

// TestRun_EndToEnd tests the complete flow from command-line args to successful import
func TestRun_EndToEnd(t *testing.T) {
	dbPath, uploadsDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create test file
	tempDir := t.TempDir()
	testFile := createTestFile(t, tempDir, "end-to-end-test.txt", "end-to-end content")

	args := []string{
		"-source", testFile,
		"-db", dbPath,
		"-uploads", uploadsDir,
		"-enckey", encKey,
		"-quiet",
		"-no-delete", // Keep source file for verification
	}

	err := run(args)
	if err != nil {
		t.Fatalf("run() failed: %v", err)
	}

	// Verify source file still exists (no-delete flag)
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Error("source file should exist with no-delete flag")
	}

	// Verify encrypted file was created
	files, err := os.ReadDir(uploadsDir)
	if err != nil {
		t.Fatalf("failed to read uploads directory: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("expected 1 encrypted file, got %d", len(files))
	}

	// Verify database record exists
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM files").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query database: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 file in database, got %d", count)
	}
}

// TestRun_EndToEnd_BatchMode tests batch import from directory
func TestRun_EndToEnd_BatchMode(t *testing.T) {
	dbPath, uploadsDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create test directory with multiple files
	tempDir := t.TempDir()
	testDir := filepath.Join(tempDir, "batch-test")
	os.MkdirAll(testDir, 0755)

	createTestFile(t, testDir, "file1.txt", "content1")
	createTestFile(t, testDir, "file2.txt", "content2")
	createTestFile(t, testDir, "file3.txt", "content3")

	args := []string{
		"-directory", testDir,
		"-db", dbPath,
		"-uploads", uploadsDir,
		"-enckey", encKey,
		"-quiet",
		"-no-delete",
	}

	err := run(args)
	if err != nil {
		t.Fatalf("run() failed: %v", err)
	}

	// Verify all files were encrypted
	files, err := os.ReadDir(uploadsDir)
	if err != nil {
		t.Fatalf("failed to read uploads directory: %v", err)
	}

	if len(files) != 3 {
		t.Errorf("expected 3 encrypted files, got %d", len(files))
	}

	// Verify database has 3 records
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM files").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query database: %v", err)
	}

	if count != 3 {
		t.Errorf("expected 3 files in database, got %d", count)
	}
}
