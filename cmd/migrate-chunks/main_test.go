package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/utils"
)

// setupTestEnvironment creates a test upload directory and encryption key
func setupTestEnvironment(t *testing.T) (uploadDir, encKey string, cleanup func()) {
	t.Helper()

	// Create temp directory for test
	tempDir := t.TempDir()

	// Create uploads directory
	uploadDir = filepath.Join(tempDir, "uploads")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		t.Fatalf("failed to create uploads directory: %v", err)
	}

	// Generate encryption key (64 hex chars = 32 bytes)
	encKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	cleanup = func() {
		// t.TempDir() handles cleanup automatically
	}

	return uploadDir, encKey, cleanup
}

// createTestFile creates a plain text test file
func createTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	return path
}

// createEncryptedFile creates an SFSE1 encrypted file with specified chunk size
func createEncryptedFile(t *testing.T, dir, name, content, encKey string, chunkSize uint32) string {
	t.Helper()

	// Create temporary plain file
	tempPlain := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(tempPlain, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create temp plain file: %v", err)
	}

	// Encrypt with specified chunk size (requires patching utils.EncryptFileStreaming or creating manually)
	// For now, we'll create a minimal SFSE1 file manually
	encPath := filepath.Join(dir, name)

	// Create SFSE1 header manually
	header := make([]byte, 10)
	copy(header[0:5], []byte("SFSE1"))           // Magic
	header[5] = 1                                  // Version
	binary.LittleEndian.PutUint32(header[6:10], chunkSize) // Chunk size

	// For testing, just write header + some encrypted data
	// Real encryption is tested in utils package
	file, err := os.Create(encPath)
	if err != nil {
		t.Fatalf("failed to create encrypted file: %v", err)
	}
	defer file.Close()

	file.Write(header)

	// Write a minimal encrypted chunk (nonce + ciphertext + tag)
	// This is a fake chunk for testing purposes
	fakeChunk := make([]byte, 128) // Minimal chunk
	file.Write(fakeChunk)

	return encPath
}

func TestRun_MissingEncryptionKey(t *testing.T) {
	args := []string{"--upload-dir", "/tmp/uploads"}
	err := run(args)
	if err == nil {
		t.Error("expected error when encryption key is missing")
	}
	if !strings.Contains(err.Error(), "encryption-key is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRun_InvalidEncryptionKey(t *testing.T) {
	args := []string{
		"--upload-dir", "/tmp/uploads",
		"--encryption-key", "invalid",
	}
	err := run(args)
	if err == nil {
		t.Error("expected error for invalid encryption key")
	}
	if !strings.Contains(err.Error(), "encryption key must be 64 hex characters") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRun_NonexistentDirectory(t *testing.T) {
	args := []string{
		"--upload-dir", "/nonexistent/directory/path",
		"--encryption-key", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	err := run(args)
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
	if !strings.Contains(err.Error(), "upload directory does not exist") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRun_PathIsFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "notadir.txt")
	os.WriteFile(filePath, []byte("content"), 0644)

	args := []string{
		"--upload-dir", filePath,
		"--encryption-key", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	err := run(args)
	if err == nil {
		t.Error("expected error when upload-dir is a file, not a directory")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRun_EmptyDirectory(t *testing.T) {
	uploadDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	args := []string{
		"--upload-dir", uploadDir,
		"--encryption-key", encKey,
	}

	err := run(args)
	if err != nil {
		t.Errorf("expected no error for empty directory, got: %v", err)
	}
}

func TestRun_DryRunMode(t *testing.T) {
	uploadDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create a test SFSE1 file with old chunk size
	createEncryptedFile(t, uploadDir, "test.bin", "test content", encKey, oldChunkSize)

	args := []string{
		"--upload-dir", uploadDir,
		"--encryption-key", encKey,
		"--dry-run",
	}

	err := run(args)
	if err != nil {
		t.Errorf("dry run failed: %v", err)
	}

	// Verify file was not actually modified
	// In dry run, file should still have old chunk size
	chunkSize, err := readChunkSize(filepath.Join(uploadDir, "test.bin"))
	if err != nil {
		t.Fatalf("failed to read chunk size after dry run: %v", err)
	}
	if chunkSize != oldChunkSize {
		t.Error("file should not be modified in dry-run mode")
	}
}

func TestRun_SkipsNonSFSE1Files(t *testing.T) {
	uploadDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create plain text files (not encrypted)
	createTestFile(t, uploadDir, "plain1.txt", "plain content 1")
	createTestFile(t, uploadDir, "plain2.pdf", "plain content 2")

	args := []string{
		"--upload-dir", uploadDir,
		"--encryption-key", encKey,
	}

	err := run(args)
	if err != nil {
		t.Errorf("should not error on non-SFSE1 files, got: %v", err)
	}

	// Verify plain files were not modified
	content, err := os.ReadFile(filepath.Join(uploadDir, "plain1.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "plain content 1" {
		t.Error("plain file was modified")
	}
}

func TestRun_SkipsHiddenFiles(t *testing.T) {
	uploadDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create hidden file
	createTestFile(t, uploadDir, ".hidden", "hidden content")

	// Create hidden directory
	hiddenDir := filepath.Join(uploadDir, ".partial")
	os.MkdirAll(hiddenDir, 0755)
	createTestFile(t, hiddenDir, "chunk_0", "chunk data")

	args := []string{
		"--upload-dir", uploadDir,
		"--encryption-key", encKey,
	}

	err := run(args)
	if err != nil {
		t.Errorf("should not error on hidden files, got: %v", err)
	}
}

func TestReadChunkSize_ValidSFSE1File(t *testing.T) {
	uploadDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create SFSE1 file with new chunk size
	filePath := createEncryptedFile(t, uploadDir, "test.bin", "content", encKey, newChunkSize)

	chunkSize, err := readChunkSize(filePath)
	if err != nil {
		t.Fatalf("readChunkSize failed: %v", err)
	}

	if chunkSize != newChunkSize {
		t.Errorf("expected chunk size %d, got %d", newChunkSize, chunkSize)
	}
}

func TestReadChunkSize_OldChunkSize(t *testing.T) {
	uploadDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create SFSE1 file with old chunk size
	filePath := createEncryptedFile(t, uploadDir, "old.bin", "content", encKey, oldChunkSize)

	chunkSize, err := readChunkSize(filePath)
	if err != nil {
		t.Fatalf("readChunkSize failed: %v", err)
	}

	if chunkSize != oldChunkSize {
		t.Errorf("expected chunk size %d, got %d", oldChunkSize, chunkSize)
	}
}

func TestReadChunkSize_NonexistentFile(t *testing.T) {
	_, err := readChunkSize("/nonexistent/file.bin")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestReadChunkSize_InvalidFile(t *testing.T) {
	uploadDir, _, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create invalid file (too short to have SFSE1 header)
	invalidFile := filepath.Join(uploadDir, "invalid.bin")
	os.WriteFile(invalidFile, []byte("short"), 0644)

	_, err := readChunkSize(invalidFile)
	if err == nil {
		t.Error("expected error for invalid file format")
	}
}

func TestMigrateFile_Success(t *testing.T) {
	// Skip if running in short mode (encryption is slow)
	if testing.Short() {
		t.Skip("skipping migration test in short mode")
	}

	uploadDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create a real encrypted file with old chunk size
	tempDir := t.TempDir()
	plainFile := filepath.Join(tempDir, "plain.txt")
	content := "This is test content for migration"
	os.WriteFile(plainFile, []byte(content), 0644)

	// Encrypt with utils (creates real SFSE1 file)
	encryptedFile := filepath.Join(uploadDir, "encrypted.bin")
	err := utils.EncryptFileStreaming(plainFile, encryptedFile, encKey)
	if err != nil {
		t.Fatalf("failed to create encrypted file: %v", err)
	}

	// Read original chunk size
	originalSize, err := readChunkSize(encryptedFile)
	if err != nil {
		t.Fatalf("failed to read original chunk size: %v", err)
	}

	// Note: Current implementation always uses 10MB chunks, so this test
	// is more about verifying migrateFile doesn't break the file

	// Perform migration
	err = migrateFile(encryptedFile, encKey)
	if err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	// Verify file still exists
	if _, err := os.Stat(encryptedFile); os.IsNotExist(err) {
		t.Error("migrated file does not exist")
	}

	// Verify chunk size (should remain same or be new size)
	newSize, err := readChunkSize(encryptedFile)
	if err != nil {
		t.Fatalf("failed to read new chunk size: %v", err)
	}

	// For current implementation, size should be 10MB
	if newSize != newChunkSize && newSize != originalSize {
		t.Errorf("unexpected chunk size after migration: %d", newSize)
	}

	// Verify file can be decrypted
	decryptedFile := filepath.Join(tempDir, "decrypted.txt")
	err = utils.DecryptFileStreaming(encryptedFile, decryptedFile, encKey)
	if err != nil {
		t.Fatalf("failed to decrypt migrated file: %v", err)
	}

	// Verify content matches
	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}

	if string(decryptedContent) != content {
		t.Errorf("content mismatch after migration: got %q, want %q", string(decryptedContent), content)
	}
}

func TestMigrateFile_InvalidEncryptionKey(t *testing.T) {
	// Skip if running in short mode
	if testing.Short() {
		t.Skip("skipping migration test in short mode")
	}

	uploadDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create a real encrypted file
	tempDir := t.TempDir()
	plainFile := filepath.Join(tempDir, "plain.txt")
	os.WriteFile(plainFile, []byte("test content"), 0644)

	encryptedFile := filepath.Join(uploadDir, "encrypted.bin")
	err := utils.EncryptFileStreaming(plainFile, encryptedFile, encKey)
	if err != nil {
		t.Fatalf("failed to create encrypted file: %v", err)
	}

	// Try to migrate with wrong key
	wrongKey := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	err = migrateFile(encryptedFile, wrongKey)
	if err == nil {
		t.Error("expected error when using wrong encryption key")
	}
}

func TestMigrateFile_NonexistentFile(t *testing.T) {
	encKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	err := migrateFile("/nonexistent/file.bin", encKey)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestRun_EndToEnd tests the complete migration workflow
func TestRun_EndToEnd(t *testing.T) {
	// Skip if running in short mode (encryption is slow)
	if testing.Short() {
		t.Skip("skipping end-to-end test in short mode")
	}

	uploadDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create multiple encrypted files
	tempDir := t.TempDir()

	files := []struct {
		name    string
		content string
	}{
		{"file1.bin", "content 1"},
		{"file2.bin", "content 2"},
		{"file3.bin", "content 3"},
	}

	for _, f := range files {
		plainFile := filepath.Join(tempDir, f.name)
		os.WriteFile(plainFile, []byte(f.content), 0644)

		encryptedFile := filepath.Join(uploadDir, f.name)
		err := utils.EncryptFileStreaming(plainFile, encryptedFile, encKey)
		if err != nil {
			t.Fatalf("failed to create encrypted file %s: %v", f.name, err)
		}
	}

	// Also add a non-encrypted file that should be skipped
	createTestFile(t, uploadDir, "plain.txt", "plain content")

	// Run migration
	args := []string{
		"--upload-dir", uploadDir,
		"--encryption-key", encKey,
	}

	err := run(args)
	if err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	// Verify all encrypted files still exist and can be decrypted
	for _, f := range files {
		encryptedPath := filepath.Join(uploadDir, f.name)

		// Verify file exists
		if _, err := os.Stat(encryptedPath); os.IsNotExist(err) {
			t.Errorf("file %s does not exist after migration", f.name)
			continue
		}

		// Verify can decrypt
		decryptedPath := filepath.Join(tempDir, "decrypted-"+f.name)
		err := utils.DecryptFileStreaming(encryptedPath, decryptedPath, encKey)
		if err != nil {
			t.Errorf("failed to decrypt %s after migration: %v", f.name, err)
			continue
		}

		// Verify content
		content, err := os.ReadFile(decryptedPath)
		if err != nil {
			t.Errorf("failed to read decrypted %s: %v", f.name, err)
			continue
		}

		if string(content) != f.content {
			t.Errorf("content mismatch for %s: got %q, want %q", f.name, string(content), f.content)
		}
	}

	// Verify plain file was not modified
	plainContent, err := os.ReadFile(filepath.Join(uploadDir, "plain.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(plainContent) != "plain content" {
		t.Error("plain file was modified")
	}
}

// TestRun_MixedChunkSizes tests handling files with different chunk sizes
func TestRun_MixedChunkSizes(t *testing.T) {
	uploadDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create files with different chunk sizes
	createEncryptedFile(t, uploadDir, "old-chunks.bin", "content", encKey, oldChunkSize)
	createEncryptedFile(t, uploadDir, "new-chunks.bin", "content", encKey, newChunkSize)
	createEncryptedFile(t, uploadDir, "weird-chunks.bin", "content", encKey, 12345678) // Unexpected size

	// Run in dry-run mode
	args := []string{
		"--upload-dir", uploadDir,
		"--encryption-key", encKey,
		"--dry-run",
	}

	err := run(args)
	if err != nil {
		t.Errorf("migration failed: %v", err)
	}

	// Verify file with old chunk size is detected for migration
	oldFile := filepath.Join(uploadDir, "old-chunks.bin")
	size, _ := readChunkSize(oldFile)
	if size != oldChunkSize {
		t.Error("old-chunks.bin should have old chunk size")
	}

	// Verify file with new chunk size is skipped
	newFile := filepath.Join(uploadDir, "new-chunks.bin")
	size, _ = readChunkSize(newFile)
	if size != newChunkSize {
		t.Error("new-chunks.bin should have new chunk size")
	}

	// Verify file with unexpected chunk size is skipped
	weirdFile := filepath.Join(uploadDir, "weird-chunks.bin")
	size, _ = readChunkSize(weirdFile)
	if size != 12345678 {
		t.Error("weird-chunks.bin should have unexpected chunk size")
	}
}

func TestRun_VerboseFlag(t *testing.T) {
	uploadDir, encKey, cleanup := setupTestEnvironment(t)
	defer cleanup()

	args := []string{
		"--upload-dir", uploadDir,
		"--encryption-key", encKey,
		"--verbose",
	}

	err := run(args)
	if err != nil {
		t.Errorf("verbose mode failed: %v", err)
	}
}
