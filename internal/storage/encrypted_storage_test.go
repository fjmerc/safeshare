package storage_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/fjmerc/safeshare/internal/storage"
	"github.com/fjmerc/safeshare/internal/storage/filesystem"
)

func generateTestKey() string {
	key := make([]byte, 32)
	rand.Read(key)
	return hex.EncodeToString(key)
}

func TestNewEncryptedStorage(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := filesystem.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	key := generateTestKey()
	es, err := storage.NewEncryptedStorage(fs, key)
	if err != nil {
		t.Fatalf("NewEncryptedStorage failed: %v", err)
	}

	if es == nil {
		t.Fatal("EncryptedStorage should not be nil")
	}
}

func TestNewEncryptedStorage_InvalidKey(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := filesystem.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	tests := []struct {
		name string
		key  string
	}{
		{"empty key", ""},
		{"invalid hex", "not-a-hex-string"},
		{"too short", "0123456789abcdef"}, // 16 bytes, need 32
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := storage.NewEncryptedStorage(fs, tt.key)
			if err == nil {
				t.Error("NewEncryptedStorage should fail with invalid key")
			}
		})
	}
}

func TestEncryptedStorage_StoreAndRetrieve(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := filesystem.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	key := generateTestKey()
	es, err := storage.NewEncryptedStorage(fs, key)
	if err != nil {
		t.Fatalf("NewEncryptedStorage failed: %v", err)
	}

	ctx := context.Background()
	content := []byte("hello encrypted world")
	filename := "test.txt"

	// Store
	path, hash, err := es.Store(ctx, filename, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	if path != filename {
		t.Errorf("path = %q, want %q", path, filename)
	}

	if hash == "" {
		t.Error("hash should not be empty")
	}

	// Verify file on disk is encrypted (starts with SFSE1)
	filePath := filepath.Join(tempDir, filename)
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read stored file: %v", err)
	}

	if !bytes.HasPrefix(fileData, []byte(storage.StreamEncryptionMagic)) {
		t.Error("stored file should start with SFSE1 magic header")
	}

	// Verify encrypted data is different from plaintext
	if bytes.Contains(fileData, content) {
		t.Error("encrypted file should not contain plaintext")
	}

	// Retrieve and verify decryption
	reader, err := es.Retrieve(ctx, filename)
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}
	defer reader.Close()

	decrypted, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(decrypted, content) {
		t.Errorf("decrypted content = %q, want %q", decrypted, content)
	}
}

func TestEncryptedStorage_StoreAndRetrieve_LargeFile(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := filesystem.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	key := generateTestKey()
	es, err := storage.NewEncryptedStorage(fs, key)
	if err != nil {
		t.Fatalf("NewEncryptedStorage failed: %v", err)
	}

	ctx := context.Background()
	// Create content larger than one encryption chunk (10MB)
	content := make([]byte, 11*1024*1024) // 11MB
	rand.Read(content)
	filename := "large.bin"

	// Store
	_, hash, err := es.Store(ctx, filename, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	if hash == "" {
		t.Error("hash should not be empty")
	}

	// Retrieve and verify
	reader, err := es.Retrieve(ctx, filename)
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}
	defer reader.Close()

	decrypted, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(decrypted, content) {
		t.Error("decrypted content does not match original")
	}
}

func TestEncryptedStorage_StreamRange(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := filesystem.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	key := generateTestKey()
	es, err := storage.NewEncryptedStorage(fs, key)
	if err != nil {
		t.Fatalf("NewEncryptedStorage failed: %v", err)
	}

	ctx := context.Background()
	content := []byte("0123456789abcdef")
	filename := "range.txt"

	// Store
	_, _, err = es.Store(ctx, filename, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	tests := []struct {
		name     string
		start    int64
		end      int64
		expected string
	}{
		{"first byte", 0, 0, "0"},
		{"first four bytes", 0, 3, "0123"},
		{"middle bytes", 4, 7, "4567"},
		{"last bytes", 12, 15, "cdef"},
		{"entire file", 0, 15, "0123456789abcdef"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			written, err := es.StreamRange(ctx, filename, tt.start, tt.end, &buf)
			if err != nil {
				t.Fatalf("StreamRange failed: %v", err)
			}

			expectedLen := int64(len(tt.expected))
			if written != expectedLen {
				t.Errorf("written = %d, want %d", written, expectedLen)
			}

			if buf.String() != tt.expected {
				t.Errorf("content = %q, want %q", buf.String(), tt.expected)
			}
		})
	}
}

func TestEncryptedStorage_ChunkOperations(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := filesystem.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	key := generateTestKey()
	es, err := storage.NewEncryptedStorage(fs, key)
	if err != nil {
		t.Fatalf("NewEncryptedStorage failed: %v", err)
	}

	ctx := context.Background()
	uploadID := "encrypted-upload"
	chunk0 := []byte("first chunk")
	chunk1 := []byte("second chunk")

	// SaveChunk (unencrypted)
	err = es.SaveChunk(ctx, uploadID, 0, bytes.NewReader(chunk0), int64(len(chunk0)))
	if err != nil {
		t.Fatalf("SaveChunk(0) failed: %v", err)
	}

	err = es.SaveChunk(ctx, uploadID, 1, bytes.NewReader(chunk1), int64(len(chunk1)))
	if err != nil {
		t.Fatalf("SaveChunk(1) failed: %v", err)
	}

	// ChunkExists
	exists, size, err := es.ChunkExists(ctx, uploadID, 0)
	if err != nil {
		t.Fatalf("ChunkExists failed: %v", err)
	}
	if !exists || size != int64(len(chunk0)) {
		t.Errorf("ChunkExists = (%v, %d), want (true, %d)", exists, size, len(chunk0))
	}

	// GetChunkCount
	count, err := es.GetChunkCount(ctx, uploadID)
	if err != nil {
		t.Fatalf("GetChunkCount failed: %v", err)
	}
	if count != 2 {
		t.Errorf("chunk count = %d, want 2", count)
	}

	// Cleanup
	err = es.DeleteChunks(ctx, uploadID)
	if err != nil {
		t.Fatalf("DeleteChunks failed: %v", err)
	}
}

func TestEncryptedStorage_AssembleChunks(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := filesystem.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	key := generateTestKey()
	es, err := storage.NewEncryptedStorage(fs, key)
	if err != nil {
		t.Fatalf("NewEncryptedStorage failed: %v", err)
	}

	ctx := context.Background()
	uploadID := "assemble-encrypted"
	chunks := [][]byte{
		[]byte("chunk one "),
		[]byte("chunk two "),
		[]byte("chunk three"),
	}

	// Save chunks
	for i, chunk := range chunks {
		err := es.SaveChunk(ctx, uploadID, i, bytes.NewReader(chunk), int64(len(chunk)))
		if err != nil {
			t.Fatalf("SaveChunk(%d) failed: %v", i, err)
		}
	}

	// Assemble (should encrypt the result)
	destFilename := "assembled.txt"
	hash, err := es.AssembleChunks(ctx, uploadID, len(chunks), destFilename)
	if err != nil {
		t.Fatalf("AssembleChunks failed: %v", err)
	}

	if hash == "" {
		t.Error("hash should not be empty")
	}

	// Verify assembled file is encrypted
	filePath := filepath.Join(tempDir, destFilename)
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read assembled file: %v", err)
	}

	if !bytes.HasPrefix(fileData, []byte(storage.StreamEncryptionMagic)) {
		t.Error("assembled file should be encrypted (start with SFSE1)")
	}

	// Retrieve and verify content
	reader, err := es.Retrieve(ctx, destFilename)
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}
	defer reader.Close()

	decrypted, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	expectedContent := "chunk one chunk two chunk three"
	if string(decrypted) != expectedContent {
		t.Errorf("decrypted content = %q, want %q", string(decrypted), expectedContent)
	}
}

func TestEncryptedStorage_Delete(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := filesystem.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	key := generateTestKey()
	es, err := storage.NewEncryptedStorage(fs, key)
	if err != nil {
		t.Fatalf("NewEncryptedStorage failed: %v", err)
	}

	ctx := context.Background()
	filename := "delete.txt"

	// Store
	_, _, err = es.Store(ctx, filename, bytes.NewReader([]byte("test")), 4)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Delete
	err = es.Delete(ctx, filename)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify deleted
	exists, err := es.Exists(ctx, filename)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("file should not exist after delete")
	}
}

func TestEncryptedStorage_Exists(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := filesystem.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	key := generateTestKey()
	es, err := storage.NewEncryptedStorage(fs, key)
	if err != nil {
		t.Fatalf("NewEncryptedStorage failed: %v", err)
	}

	ctx := context.Background()
	filename := "exists.txt"

	// Before store
	exists, err := es.Exists(ctx, filename)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("file should not exist before store")
	}

	// Store
	_, _, err = es.Store(ctx, filename, bytes.NewReader([]byte("test")), 4)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// After store
	exists, err = es.Exists(ctx, filename)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("file should exist after store")
	}
}

func TestEncryptedStorage_SpaceManagement(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := filesystem.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	key := generateTestKey()
	es, err := storage.NewEncryptedStorage(fs, key)
	if err != nil {
		t.Fatalf("NewEncryptedStorage failed: %v", err)
	}

	ctx := context.Background()

	// GetAvailableSpace
	available, err := es.GetAvailableSpace(ctx)
	if err != nil {
		t.Fatalf("GetAvailableSpace failed: %v", err)
	}
	if available <= 0 {
		t.Errorf("available space should be positive, got %d", available)
	}

	// GetUsedSpace
	used, err := es.GetUsedSpace(ctx)
	if err != nil {
		t.Fatalf("GetUsedSpace failed: %v", err)
	}
	if used < 0 {
		t.Errorf("used space should be non-negative, got %d", used)
	}
}

func TestEncryptedStorage_GetFilePath(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := filesystem.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	key := generateTestKey()
	es, err := storage.NewEncryptedStorage(fs, key)
	if err != nil {
		t.Fatalf("NewEncryptedStorage failed: %v", err)
	}

	path := es.GetFilePath("test.txt")
	expected := filepath.Join(tempDir, "test.txt")
	if path != expected {
		t.Errorf("GetFilePath = %q, want %q", path, expected)
	}
}

func TestEncryptedStorage_GetBaseDir(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := filesystem.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	key := generateTestKey()
	es, err := storage.NewEncryptedStorage(fs, key)
	if err != nil {
		t.Fatalf("NewEncryptedStorage failed: %v", err)
	}

	baseDir := es.GetBaseDir()
	if baseDir != tempDir {
		t.Errorf("GetBaseDir = %q, want %q", baseDir, tempDir)
	}
}
