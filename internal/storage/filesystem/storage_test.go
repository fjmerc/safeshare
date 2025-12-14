package filesystem

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewFilesystemStorage(t *testing.T) {
	tempDir := t.TempDir()

	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	if fs.baseDir != tempDir {
		t.Errorf("baseDir = %q, want %q", fs.baseDir, tempDir)
	}

	// Check that partial dir was created
	partialPath := filepath.Join(tempDir, ".partial")
	if _, err := os.Stat(partialPath); os.IsNotExist(err) {
		t.Errorf("partial directory was not created")
	}
}

func TestFilesystemStorage_Store(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()
	content := []byte("hello world")
	filename := "test.txt"

	path, hash, err := fs.Store(ctx, filename, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	if path != filename {
		t.Errorf("path = %q, want %q", path, filename)
	}

	// SHA256 of "hello world"
	expectedHash := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != expectedHash {
		t.Errorf("hash = %q, want %q", hash, expectedHash)
	}

	// Verify file was written
	filePath := filepath.Join(tempDir, filename)
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read stored file: %v", err)
	}

	if !bytes.Equal(data, content) {
		t.Errorf("stored content = %q, want %q", data, content)
	}
}

func TestFilesystemStorage_Store_SizeMismatch(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()
	content := []byte("hello")
	filename := "test.txt"

	// Provide wrong size
	_, _, err = fs.Store(ctx, filename, bytes.NewReader(content), 100)
	if err == nil {
		t.Fatal("Store should have failed with size mismatch")
	}

	if !strings.Contains(err.Error(), "size mismatch") {
		t.Errorf("error should contain 'size mismatch', got: %v", err)
	}
}

func TestFilesystemStorage_Retrieve(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()
	content := []byte("retrieve test")
	filename := "retrieve.txt"

	// Store first
	_, _, err = fs.Store(ctx, filename, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Retrieve
	reader, err := fs.Retrieve(ctx, filename)
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(data, content) {
		t.Errorf("retrieved content = %q, want %q", data, content)
	}
}

func TestFilesystemStorage_Retrieve_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()
	_, err = fs.Retrieve(ctx, "nonexistent.txt")
	if err == nil {
		t.Fatal("Retrieve should have failed for nonexistent file")
	}

	if !strings.Contains(err.Error(), "file not found") {
		t.Errorf("error should contain 'file not found', got: %v", err)
	}
}

func TestFilesystemStorage_Delete(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()
	filename := "delete.txt"

	// Store first
	_, _, err = fs.Store(ctx, filename, bytes.NewReader([]byte("test")), 4)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Delete
	err = fs.Delete(ctx, filename)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify file is gone
	exists, err := fs.Exists(ctx, filename)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("file should not exist after delete")
	}
}

func TestFilesystemStorage_Delete_Nonexistent(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()
	// Delete nonexistent file should not error
	err = fs.Delete(ctx, "nonexistent.txt")
	if err != nil {
		t.Errorf("Delete nonexistent file should not error, got: %v", err)
	}
}

func TestFilesystemStorage_Exists(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()
	filename := "exists.txt"

	// Check before store
	exists, err := fs.Exists(ctx, filename)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("file should not exist before store")
	}

	// Store
	_, _, err = fs.Store(ctx, filename, bytes.NewReader([]byte("test")), 4)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Check after store
	exists, err = fs.Exists(ctx, filename)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("file should exist after store")
	}
}

func TestFilesystemStorage_GetSize(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()
	content := []byte("size test content")
	filename := "size.txt"

	_, _, err = fs.Store(ctx, filename, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	size, err := fs.GetSize(ctx, filename)
	if err != nil {
		t.Fatalf("GetSize failed: %v", err)
	}

	if size != int64(len(content)) {
		t.Errorf("size = %d, want %d", size, len(content))
	}
}

func TestFilesystemStorage_StreamRange(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()
	content := []byte("0123456789")
	filename := "range.txt"

	_, _, err = fs.Store(ctx, filename, bytes.NewReader(content), int64(len(content)))
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
		{"first three bytes", 0, 2, "012"},
		{"middle bytes", 3, 5, "345"},
		{"last bytes", 7, 9, "789"},
		{"entire file", 0, 9, "0123456789"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			written, err := fs.StreamRange(ctx, filename, tt.start, tt.end, &buf)
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

func TestFilesystemStorage_ChunkOperations(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()
	uploadID := "test-upload-id"
	chunk0 := []byte("chunk zero data")
	chunk1 := []byte("chunk one data!")

	// Test SaveChunk
	err = fs.SaveChunk(ctx, uploadID, 0, bytes.NewReader(chunk0), int64(len(chunk0)))
	if err != nil {
		t.Fatalf("SaveChunk(0) failed: %v", err)
	}

	err = fs.SaveChunk(ctx, uploadID, 1, bytes.NewReader(chunk1), int64(len(chunk1)))
	if err != nil {
		t.Fatalf("SaveChunk(1) failed: %v", err)
	}

	// Test ChunkExists
	exists, size, err := fs.ChunkExists(ctx, uploadID, 0)
	if err != nil {
		t.Fatalf("ChunkExists failed: %v", err)
	}
	if !exists {
		t.Error("chunk 0 should exist")
	}
	if size != int64(len(chunk0)) {
		t.Errorf("chunk 0 size = %d, want %d", size, len(chunk0))
	}

	// Test nonexistent chunk
	exists, _, err = fs.ChunkExists(ctx, uploadID, 99)
	if err != nil {
		t.Fatalf("ChunkExists failed: %v", err)
	}
	if exists {
		t.Error("chunk 99 should not exist")
	}

	// Test GetChunkCount
	count, err := fs.GetChunkCount(ctx, uploadID)
	if err != nil {
		t.Fatalf("GetChunkCount failed: %v", err)
	}
	if count != 2 {
		t.Errorf("chunk count = %d, want 2", count)
	}

	// Test GetMissingChunks
	missing, err := fs.GetMissingChunks(ctx, uploadID, 3)
	if err != nil {
		t.Fatalf("GetMissingChunks failed: %v", err)
	}
	if len(missing) != 1 || missing[0] != 2 {
		t.Errorf("missing = %v, want [2]", missing)
	}

	// Test GetChunk
	reader, err := fs.GetChunk(ctx, uploadID, 0)
	if err != nil {
		t.Fatalf("GetChunk failed: %v", err)
	}
	data, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if !bytes.Equal(data, chunk0) {
		t.Errorf("chunk content = %q, want %q", data, chunk0)
	}

	// Test DeleteChunks
	err = fs.DeleteChunks(ctx, uploadID)
	if err != nil {
		t.Fatalf("DeleteChunks failed: %v", err)
	}

	count, err = fs.GetChunkCount(ctx, uploadID)
	if err != nil {
		t.Fatalf("GetChunkCount after delete failed: %v", err)
	}
	if count != 0 {
		t.Errorf("chunk count after delete = %d, want 0", count)
	}
}

func TestFilesystemStorage_AssembleChunks(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()
	uploadID := "assemble-test"
	chunks := [][]byte{
		[]byte("first chunk "),
		[]byte("second chunk "),
		[]byte("third chunk"),
	}

	// Save all chunks
	for i, chunk := range chunks {
		err := fs.SaveChunk(ctx, uploadID, i, bytes.NewReader(chunk), int64(len(chunk)))
		if err != nil {
			t.Fatalf("SaveChunk(%d) failed: %v", i, err)
		}
	}

	// Assemble
	destFilename := "assembled.txt"
	hash, err := fs.AssembleChunks(ctx, uploadID, len(chunks), destFilename)
	if err != nil {
		t.Fatalf("AssembleChunks failed: %v", err)
	}

	if hash == "" {
		t.Error("hash should not be empty")
	}

	// Verify assembled file content
	expectedContent := "first chunk second chunk third chunk"
	data, err := os.ReadFile(filepath.Join(tempDir, destFilename))
	if err != nil {
		t.Fatalf("Failed to read assembled file: %v", err)
	}

	if string(data) != expectedContent {
		t.Errorf("assembled content = %q, want %q", string(data), expectedContent)
	}
}

func TestFilesystemStorage_AssembleChunks_MissingChunk(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()
	uploadID := "missing-chunk-test"

	// Save only chunk 0 and 2, missing chunk 1
	err = fs.SaveChunk(ctx, uploadID, 0, bytes.NewReader([]byte("chunk0")), 6)
	if err != nil {
		t.Fatalf("SaveChunk(0) failed: %v", err)
	}

	err = fs.SaveChunk(ctx, uploadID, 2, bytes.NewReader([]byte("chunk2")), 6)
	if err != nil {
		t.Fatalf("SaveChunk(2) failed: %v", err)
	}

	// Assemble should fail
	_, err = fs.AssembleChunks(ctx, uploadID, 3, "assembled.txt")
	if err == nil {
		t.Fatal("AssembleChunks should fail with missing chunks")
	}

	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error should mention missing chunks, got: %v", err)
	}
}

func TestFilesystemStorage_SpaceManagement(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()

	// Test GetAvailableSpace
	available, err := fs.GetAvailableSpace(ctx)
	if err != nil {
		t.Fatalf("GetAvailableSpace failed: %v", err)
	}
	if available <= 0 {
		t.Errorf("available space should be positive, got %d", available)
	}

	// Test GetUsedSpace (should be minimal for empty dir)
	used, err := fs.GetUsedSpace(ctx)
	if err != nil {
		t.Fatalf("GetUsedSpace failed: %v", err)
	}
	if used < 0 {
		t.Errorf("used space should be non-negative, got %d", used)
	}

	// Store some data and check used space increases
	content := make([]byte, 10000)
	_, _, err = fs.Store(ctx, "big.txt", bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	usedAfter, err := fs.GetUsedSpace(ctx)
	if err != nil {
		t.Fatalf("GetUsedSpace after store failed: %v", err)
	}

	// Used space should have increased
	if usedAfter <= used {
		t.Errorf("used space should have increased: before=%d, after=%d", used, usedAfter)
	}
}

func TestFilesystemStorage_GetFilePath(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	path := fs.GetFilePath("test.txt")
	expected := filepath.Join(tempDir, "test.txt")
	if path != expected {
		t.Errorf("GetFilePath = %q, want %q", path, expected)
	}
}

func TestFilesystemStorage_GetChunkNumbers(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage failed: %v", err)
	}

	ctx := context.Background()
	uploadID := "chunk-numbers-test"

	// Save chunks 0, 2, 5 (not in order)
	for _, i := range []int{5, 0, 2} {
		data := []byte("chunk")
		err := fs.SaveChunk(ctx, uploadID, i, bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("SaveChunk(%d) failed: %v", i, err)
		}
	}

	// Get chunk numbers
	numbers, err := fs.GetChunkNumbers(ctx, uploadID)
	if err != nil {
		t.Fatalf("GetChunkNumbers failed: %v", err)
	}

	// Should be sorted
	expected := []int{0, 2, 5}
	if len(numbers) != len(expected) {
		t.Fatalf("chunk numbers length = %d, want %d", len(numbers), len(expected))
	}

	for i, n := range numbers {
		if n != expected[i] {
			t.Errorf("chunk numbers[%d] = %d, want %d", i, n, expected[i])
		}
	}
}
