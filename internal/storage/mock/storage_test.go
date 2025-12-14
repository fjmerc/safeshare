package mock

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestNewStorageBackend(t *testing.T) {
	s := NewStorageBackend()
	if s == nil {
		t.Fatal("NewStorageBackend returned nil")
	}
	if s.files == nil {
		t.Error("files map should be initialized")
	}
	if s.chunks == nil {
		t.Error("chunks map should be initialized")
	}
}

func TestStorageBackend_Store(t *testing.T) {
	ctx := context.Background()
	s := NewStorageBackend()

	content := []byte("test content")
	reader := bytes.NewReader(content)

	path, hash, err := s.Store(ctx, "test.txt", reader, int64(len(content)))
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	if path != "test.txt" {
		t.Errorf("expected path test.txt, got %s", path)
	}
	if hash == "" {
		t.Error("hash should not be empty")
	}

	// Verify stored content
	stored, ok := s.GetFileContent("test.txt")
	if !ok {
		t.Error("file should exist")
	}
	if !bytes.Equal(stored, content) {
		t.Error("stored content should match")
	}
}

func TestStorageBackend_Retrieve(t *testing.T) {
	ctx := context.Background()
	s := NewStorageBackend()

	content := []byte("retrieve test")
	s.AddFile("retrieve.txt", content)

	reader, err := s.Retrieve(ctx, "retrieve.txt")
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}
	defer reader.Close()

	retrieved, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(retrieved, content) {
		t.Error("retrieved content should match")
	}

	// Non-existent file
	_, err = s.Retrieve(ctx, "nonexistent.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestStorageBackend_Delete(t *testing.T) {
	ctx := context.Background()
	s := NewStorageBackend()

	s.AddFile("delete.txt", []byte("content"))

	err := s.Delete(ctx, "delete.txt")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	exists, _ := s.Exists(ctx, "delete.txt")
	if exists {
		t.Error("file should be deleted")
	}

	// Delete non-existent
	err = s.Delete(ctx, "nonexistent.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestStorageBackend_Exists(t *testing.T) {
	ctx := context.Background()
	s := NewStorageBackend()

	s.AddFile("exists.txt", []byte("content"))

	exists, err := s.Exists(ctx, "exists.txt")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("file should exist")
	}

	exists, err = s.Exists(ctx, "nonexistent.txt")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("file should not exist")
	}
}

func TestStorageBackend_GetSize(t *testing.T) {
	ctx := context.Background()
	s := NewStorageBackend()

	content := []byte("size test content")
	s.AddFile("size.txt", content)

	size, err := s.GetSize(ctx, "size.txt")
	if err != nil {
		t.Fatalf("GetSize failed: %v", err)
	}

	if size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), size)
	}

	// Non-existent file
	_, err = s.GetSize(ctx, "nonexistent.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestStorageBackend_StreamRange(t *testing.T) {
	ctx := context.Background()
	s := NewStorageBackend()

	content := []byte("0123456789")
	s.AddFile("range.txt", content)

	var buf bytes.Buffer
	n, err := s.StreamRange(ctx, "range.txt", 2, 5, &buf)
	if err != nil {
		t.Fatalf("StreamRange failed: %v", err)
	}

	if n != 4 {
		t.Errorf("expected 4 bytes written, got %d", n)
	}

	expected := "2345"
	if buf.String() != expected {
		t.Errorf("expected %s, got %s", expected, buf.String())
	}

	// Invalid range
	buf.Reset()
	_, err = s.StreamRange(ctx, "range.txt", 20, 30, &buf)
	if err == nil {
		t.Error("expected error for invalid range")
	}
}

func TestStorageBackend_Chunks(t *testing.T) {
	ctx := context.Background()
	s := NewStorageBackend()

	// Save chunks
	chunk0 := []byte("chunk0")
	chunk1 := []byte("chunk1")

	err := s.SaveChunk(ctx, "upload1", 0, bytes.NewReader(chunk0), int64(len(chunk0)))
	if err != nil {
		t.Fatalf("SaveChunk 0 failed: %v", err)
	}

	err = s.SaveChunk(ctx, "upload1", 1, bytes.NewReader(chunk1), int64(len(chunk1)))
	if err != nil {
		t.Fatalf("SaveChunk 1 failed: %v", err)
	}

	// Get chunk
	reader, err := s.GetChunk(ctx, "upload1", 0)
	if err != nil {
		t.Fatalf("GetChunk failed: %v", err)
	}
	defer reader.Close()

	data, _ := io.ReadAll(reader)
	if !bytes.Equal(data, chunk0) {
		t.Error("chunk content should match")
	}

	// Chunk exists
	exists, size, err := s.ChunkExists(ctx, "upload1", 0)
	if err != nil {
		t.Fatalf("ChunkExists failed: %v", err)
	}
	if !exists {
		t.Error("chunk should exist")
	}
	if size != int64(len(chunk0)) {
		t.Errorf("expected size %d, got %d", len(chunk0), size)
	}

	// Non-existent chunk
	exists, _, _ = s.ChunkExists(ctx, "upload1", 5)
	if exists {
		t.Error("chunk 5 should not exist")
	}

	// Get chunk count
	count, err := s.GetChunkCount(ctx, "upload1")
	if err != nil {
		t.Fatalf("GetChunkCount failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 chunks, got %d", count)
	}
}

func TestStorageBackend_GetMissingChunks(t *testing.T) {
	ctx := context.Background()
	s := NewStorageBackend()

	// Save some chunks (0, 2)
	s.AddChunk("upload1", 0, []byte("chunk0"))
	s.AddChunk("upload1", 2, []byte("chunk2"))

	missing, err := s.GetMissingChunks(ctx, "upload1", 4)
	if err != nil {
		t.Fatalf("GetMissingChunks failed: %v", err)
	}

	expected := []int{1, 3}
	if len(missing) != 2 {
		t.Fatalf("expected 2 missing, got %d", len(missing))
	}
	if missing[0] != expected[0] || missing[1] != expected[1] {
		t.Errorf("expected %v, got %v", expected, missing)
	}
}

func TestStorageBackend_AssembleChunks(t *testing.T) {
	ctx := context.Background()
	s := NewStorageBackend()

	s.AddChunk("assemble", 0, []byte("chunk0"))
	s.AddChunk("assemble", 1, []byte("chunk1"))
	s.AddChunk("assemble", 2, []byte("chunk2"))

	hash, err := s.AssembleChunks(ctx, "assemble", 3, "assembled.txt")
	if err != nil {
		t.Fatalf("AssembleChunks failed: %v", err)
	}

	if hash == "" {
		t.Error("hash should not be empty")
	}

	// Verify assembled file
	content, ok := s.GetFileContent("assembled.txt")
	if !ok {
		t.Error("assembled file should exist")
	}

	expected := "chunk0chunk1chunk2"
	if string(content) != expected {
		t.Errorf("expected %s, got %s", expected, string(content))
	}

	// Chunks should be cleaned up
	count, _ := s.GetChunkCount(ctx, "assemble")
	if count != 0 {
		t.Error("chunks should be cleaned up after assembly")
	}
}

func TestStorageBackend_DeleteChunks(t *testing.T) {
	ctx := context.Background()
	s := NewStorageBackend()

	s.AddChunk("deleteme", 0, []byte("chunk0"))
	s.AddChunk("deleteme", 1, []byte("chunk1"))

	err := s.DeleteChunks(ctx, "deleteme")
	if err != nil {
		t.Fatalf("DeleteChunks failed: %v", err)
	}

	count, _ := s.GetChunkCount(ctx, "deleteme")
	if count != 0 {
		t.Error("chunks should be deleted")
	}

	// Delete non-existent should not error
	err = s.DeleteChunks(ctx, "nonexistent")
	if err != nil {
		t.Errorf("expected no error for non-existent, got %v", err)
	}
}

func TestStorageBackend_Space(t *testing.T) {
	ctx := context.Background()
	s := NewStorageBackend()

	s.SetAvailableSpace(1000)

	available, err := s.GetAvailableSpace(ctx)
	if err != nil {
		t.Fatalf("GetAvailableSpace failed: %v", err)
	}
	if available != 1000 {
		t.Errorf("expected 1000, got %d", available)
	}

	// Store file - reduces available space
	_, _, err = s.Store(ctx, "space.txt", bytes.NewReader([]byte("content")), 7)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	available, _ = s.GetAvailableSpace(ctx)
	if available != 993 { // 1000 - 7
		t.Errorf("expected 993, got %d", available)
	}

	used, _ := s.GetUsedSpace(ctx)
	if used != 7 {
		t.Errorf("expected 7 used, got %d", used)
	}
}

func TestStorageBackend_ErrorInjection(t *testing.T) {
	ctx := context.Background()
	s := NewStorageBackend()

	testErr := errors.New("test error")

	// Test Store error injection
	s.StoreError = testErr
	_, _, err := s.Store(ctx, "test.txt", bytes.NewReader([]byte("test")), 4)
	if err != testErr {
		t.Errorf("expected injected error, got %v", err)
	}
	s.StoreError = nil

	// Test Retrieve error injection
	s.AddFile("test.txt", []byte("content"))
	s.RetrieveError = testErr
	_, err = s.Retrieve(ctx, "test.txt")
	if err != testErr {
		t.Errorf("expected injected error, got %v", err)
	}
	s.RetrieveError = nil
}

func TestStorageBackend_Reset(t *testing.T) {
	ctx := context.Background()
	s := NewStorageBackend()

	// Add data
	s.AddFile("test.txt", []byte("content"))
	s.AddChunk("upload", 0, []byte("chunk"))
	s.StoreError = errors.New("test")

	// Reset
	s.Reset()

	// Verify cleared
	files := s.GetAllFiles()
	if len(files) != 0 {
		t.Error("files should be cleared after reset")
	}

	count, _ := s.GetChunkCount(ctx, "upload")
	if count != 0 {
		t.Error("chunks should be cleared after reset")
	}

	if s.StoreError != nil {
		t.Error("errors should be cleared after reset")
	}
}

func TestStorageBackend_ContextCancellation(t *testing.T) {
	s := NewStorageBackend()
	s.AddFile("test.txt", []byte("content"))

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Operations should return context error
	_, err := s.Retrieve(ctx, "test.txt")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestStorageBackend_GetChunkContent(t *testing.T) {
	s := NewStorageBackend()

	content := []byte("chunk content")
	s.AddChunk("upload1", 0, content)

	retrieved, ok := s.GetChunkContent("upload1", 0)
	if !ok {
		t.Error("chunk should exist")
	}
	if !bytes.Equal(retrieved, content) {
		t.Error("content should match")
	}

	// Modify original shouldn't affect stored
	content[0] = 'X'
	retrieved2, _ := s.GetChunkContent("upload1", 0)
	if retrieved2[0] == 'X' {
		t.Error("stored chunk should be independent copy")
	}
}
