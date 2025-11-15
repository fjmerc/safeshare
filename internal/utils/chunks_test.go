package utils

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCalculateOptimalChunkSize(t *testing.T) {
	tests := []struct {
		name         string
		fileSize     int64
		expectedSize int64
	}{
		{
			name:         "small file 10MB",
			fileSize:     10 * 1024 * 1024,
			expectedSize: 5 * 1024 * 1024, // 5MB chunks for files < 100MB
		},
		{
			name:         "file just under 100MB",
			fileSize:     99 * 1024 * 1024,
			expectedSize: 5 * 1024 * 1024, // 5MB chunks
		},
		{
			name:         "file exactly 100MB",
			fileSize:     100 * 1024 * 1024,
			expectedSize: 10 * 1024 * 1024, // 10MB chunks for 100MB-1GB
		},
		{
			name:         "file 500MB",
			fileSize:     500 * 1024 * 1024,
			expectedSize: 10 * 1024 * 1024, // 10MB chunks
		},
		{
			name:         "file just under 1GB",
			fileSize:     1023 * 1024 * 1024,
			expectedSize: 10 * 1024 * 1024, // 10MB chunks
		},
		{
			name:         "file exactly 1GB",
			fileSize:     1 * 1024 * 1024 * 1024,
			expectedSize: 20 * 1024 * 1024, // 20MB chunks for > 1GB
		},
		{
			name:         "file 5GB",
			fileSize:     5 * 1024 * 1024 * 1024,
			expectedSize: 20 * 1024 * 1024, // 20MB chunks
		},
		{
			name:         "very large file 100GB",
			fileSize:     100 * 1024 * 1024 * 1024,
			expectedSize: 20 * 1024 * 1024, // 20MB chunks
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunkSize := CalculateOptimalChunkSize(tt.fileSize)
			if chunkSize != tt.expectedSize {
				t.Errorf("CalculateOptimalChunkSize(%d) = %d, want %d",
					tt.fileSize, chunkSize, tt.expectedSize)
			}
		})
	}
}

func TestSaveChunk(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "test-upload-123"
	chunkNumber := 0
	chunkData := []byte("test chunk data")

	err := SaveChunk(tmpDir, uploadID, chunkNumber, chunkData)
	if err != nil {
		t.Fatalf("SaveChunk failed: %v", err)
	}

	// Verify chunk file exists
	chunkPath := GetChunkPath(tmpDir, uploadID, chunkNumber)
	if _, err := os.Stat(chunkPath); os.IsNotExist(err) {
		t.Error("chunk file should exist")
	}

	// Verify chunk data
	savedData, err := os.ReadFile(chunkPath)
	if err != nil {
		t.Fatalf("failed to read chunk: %v", err)
	}

	if !bytes.Equal(savedData, chunkData) {
		t.Errorf("chunk data mismatch: got %q, want %q", savedData, chunkData)
	}
}

func TestChunkExists(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "test-upload-456"
	chunkNumber := 0
	chunkData := []byte("chunk exists test")

	// Chunk doesn't exist yet
	exists, size, err := ChunkExists(tmpDir, uploadID, chunkNumber)
	if err != nil {
		t.Fatalf("ChunkExists failed: %v", err)
	}
	if exists {
		t.Error("chunk should not exist yet")
	}
	if size != 0 {
		t.Errorf("size should be 0 for non-existent chunk, got %d", size)
	}

	// Create chunk
	SaveChunk(tmpDir, uploadID, chunkNumber, chunkData)

	// Chunk should now exist
	exists, size, err = ChunkExists(tmpDir, uploadID, chunkNumber)
	if err != nil {
		t.Fatalf("ChunkExists failed: %v", err)
	}
	if !exists {
		t.Error("chunk should exist")
	}
	if size != int64(len(chunkData)) {
		t.Errorf("size = %d, want %d", size, len(chunkData))
	}
}

func TestGetMissingChunks(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "test-upload-789"
	totalChunks := 5

	// Create chunks 0, 2, 4 (missing 1, 3)
	SaveChunk(tmpDir, uploadID, 0, []byte("chunk 0"))
	SaveChunk(tmpDir, uploadID, 2, []byte("chunk 2"))
	SaveChunk(tmpDir, uploadID, 4, []byte("chunk 4"))

	missing, err := GetMissingChunks(tmpDir, uploadID, totalChunks)
	if err != nil {
		t.Fatalf("GetMissingChunks failed: %v", err)
	}

	expected := []int{1, 3}
	if len(missing) != len(expected) {
		t.Fatalf("missing chunks count = %d, want %d", len(missing), len(expected))
	}

	for i, chunkNum := range expected {
		if missing[i] != chunkNum {
			t.Errorf("missing[%d] = %d, want %d", i, missing[i], chunkNum)
		}
	}
}

func TestGetMissingChunks_AllPresent(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "test-upload-complete"
	totalChunks := 3

	// Create all chunks
	for i := 0; i < totalChunks; i++ {
		SaveChunk(tmpDir, uploadID, i, []byte("data"))
	}

	missing, err := GetMissingChunks(tmpDir, uploadID, totalChunks)
	if err != nil {
		t.Fatalf("GetMissingChunks failed: %v", err)
	}

	if len(missing) != 0 {
		t.Errorf("missing chunks = %v, want empty", missing)
	}
}

func TestAssembleChunks(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "test-assembly-123"
	totalChunks := 3

	// Create test chunks
	chunk0 := bytes.Repeat([]byte("A"), 1024) // 1KB
	chunk1 := bytes.Repeat([]byte("B"), 1024) // 1KB
	chunk2 := bytes.Repeat([]byte("C"), 512)  // 512B (last chunk smaller)

	SaveChunk(tmpDir, uploadID, 0, chunk0)
	SaveChunk(tmpDir, uploadID, 1, chunk1)
	SaveChunk(tmpDir, uploadID, 2, chunk2)

	// Assemble chunks
	outputPath := filepath.Join(tmpDir, "assembled.dat")
	totalBytes, err := AssembleChunks(tmpDir, uploadID, totalChunks, outputPath)
	if err != nil {
		t.Fatalf("AssembleChunks failed: %v", err)
	}

	expectedSize := int64(len(chunk0) + len(chunk1) + len(chunk2))
	if totalBytes != expectedSize {
		t.Errorf("totalBytes = %d, want %d", totalBytes, expectedSize)
	}

	// Verify assembled file
	assembledData, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read assembled file: %v", err)
	}

	if int64(len(assembledData)) != expectedSize {
		t.Errorf("assembled file size = %d, want %d", len(assembledData), expectedSize)
	}

	// Verify data integrity
	expectedData := append(append(chunk0, chunk1...), chunk2...)
	if !bytes.Equal(assembledData, expectedData) {
		t.Error("assembled data does not match expected data")
	}
}

func TestAssembleChunks_MissingChunks(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "test-missing-chunks"
	totalChunks := 3

	// Create only 2 out of 3 chunks
	SaveChunk(tmpDir, uploadID, 0, []byte("chunk 0"))
	SaveChunk(tmpDir, uploadID, 1, []byte("chunk 1"))
	// Chunk 2 is missing

	outputPath := filepath.Join(tmpDir, "assembled.dat")
	_, err := AssembleChunks(tmpDir, uploadID, totalChunks, outputPath)

	// Should fail due to missing chunk
	if err == nil {
		t.Error("AssembleChunks should fail when chunks are missing")
	}
}

func TestDeleteChunks(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "test-delete-123"

	// Create some chunks
	SaveChunk(tmpDir, uploadID, 0, []byte("chunk 0"))
	SaveChunk(tmpDir, uploadID, 1, []byte("chunk 1"))
	SaveChunk(tmpDir, uploadID, 2, []byte("chunk 2"))

	chunksDir := GetUploadChunksDir(tmpDir, uploadID)

	// Verify chunks directory exists
	if _, err := os.Stat(chunksDir); os.IsNotExist(err) {
		t.Fatal("chunks directory should exist")
	}

	// Delete chunks
	err := DeleteChunks(tmpDir, uploadID)
	if err != nil {
		t.Fatalf("DeleteChunks failed: %v", err)
	}

	// Verify chunks directory is deleted
	if _, err := os.Stat(chunksDir); !os.IsNotExist(err) {
		t.Error("chunks directory should be deleted")
	}
}

func TestDeleteChunks_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "non-existent-upload"

	// Delete non-existent chunks (should not error)
	err := DeleteChunks(tmpDir, uploadID)
	if err != nil {
		t.Errorf("DeleteChunks should not error for non-existent upload: %v", err)
	}
}

func TestGetChunkCount(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "test-count-123"

	// Initially no chunks
	count, err := GetChunkCount(tmpDir, uploadID)
	if err != nil {
		t.Fatalf("GetChunkCount failed: %v", err)
	}
	if count != 0 {
		t.Errorf("initial count = %d, want 0", count)
	}

	// Create 3 chunks
	SaveChunk(tmpDir, uploadID, 0, []byte("chunk 0"))
	SaveChunk(tmpDir, uploadID, 1, []byte("chunk 1"))
	SaveChunk(tmpDir, uploadID, 2, []byte("chunk 2"))

	count, err = GetChunkCount(tmpDir, uploadID)
	if err != nil {
		t.Fatalf("GetChunkCount failed: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestGetUploadChunksSize(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "test-size-123"

	// Create chunks of known sizes
	chunk0 := bytes.Repeat([]byte("A"), 1024) // 1KB
	chunk1 := bytes.Repeat([]byte("B"), 2048) // 2KB
	chunk2 := bytes.Repeat([]byte("C"), 512)  // 512B

	SaveChunk(tmpDir, uploadID, 0, chunk0)
	SaveChunk(tmpDir, uploadID, 1, chunk1)
	SaveChunk(tmpDir, uploadID, 2, chunk2)

	totalSize, err := GetUploadChunksSize(tmpDir, uploadID)
	if err != nil {
		t.Fatalf("GetUploadChunksSize failed: %v", err)
	}

	expectedSize := int64(1024 + 2048 + 512)
	if totalSize != expectedSize {
		t.Errorf("totalSize = %d, want %d", totalSize, expectedSize)
	}
}

func TestCleanupPartialUploadsDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some upload directories
	uploadID1 := "upload-1"
	uploadID2 := "upload-2"

	SaveChunk(tmpDir, uploadID1, 0, []byte("chunk"))
	SaveChunk(tmpDir, uploadID2, 0, []byte("chunk"))

	// Delete all chunks from upload-1 (makes directory empty)
	DeleteChunks(tmpDir, uploadID1)

	// Create empty directory manually
	emptyDir := filepath.Join(GetPartialUploadDir(tmpDir), "empty-upload")
	os.MkdirAll(emptyDir, 0755)

	// Cleanup should remove empty directories
	err := CleanupPartialUploadsDir(tmpDir)
	if err != nil {
		t.Fatalf("CleanupPartialUploadsDir failed: %v", err)
	}

	// upload-2 should still exist (has chunks)
	if _, err := os.Stat(GetUploadChunksDir(tmpDir, uploadID2)); os.IsNotExist(err) {
		t.Error("upload-2 directory should still exist")
	}

	// Empty directory should be removed
	if _, err := os.Stat(emptyDir); !os.IsNotExist(err) {
		t.Error("empty directory should be removed")
	}
}

func TestVerifyChunkIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "test-verify-123"
	chunkSize := int64(1024)
	totalChunks := 3
	totalSize := int64(2560) // 1024 + 1024 + 512

	// Create chunks with correct sizes
	chunk0 := bytes.Repeat([]byte("A"), 1024) // 1KB (regular chunk)
	chunk1 := bytes.Repeat([]byte("B"), 1024) // 1KB (regular chunk)
	chunk2 := bytes.Repeat([]byte("C"), 512)  // 512B (last chunk smaller)

	SaveChunk(tmpDir, uploadID, 0, chunk0)
	SaveChunk(tmpDir, uploadID, 1, chunk1)
	SaveChunk(tmpDir, uploadID, 2, chunk2)

	// Verification should pass
	err := VerifyChunkIntegrity(tmpDir, uploadID, totalChunks, chunkSize, totalSize)
	if err != nil {
		t.Errorf("VerifyChunkIntegrity failed: %v", err)
	}
}

func TestVerifyChunkIntegrity_WrongSize(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "test-verify-wrong-size"
	chunkSize := int64(1024)
	totalChunks := 2
	totalSize := int64(2048)

	// Create chunks with WRONG sizes
	chunk0 := bytes.Repeat([]byte("A"), 512)  // 512B instead of 1024B (wrong!)
	chunk1 := bytes.Repeat([]byte("B"), 1024) // 1KB (last chunk correct)

	SaveChunk(tmpDir, uploadID, 0, chunk0)
	SaveChunk(tmpDir, uploadID, 1, chunk1)

	// Verification should fail due to size mismatch
	err := VerifyChunkIntegrity(tmpDir, uploadID, totalChunks, chunkSize, totalSize)
	if err == nil {
		t.Error("VerifyChunkIntegrity should fail for incorrect chunk size")
	}
}

func TestVerifyChunkIntegrity_MissingChunk(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "test-verify-missing"
	chunkSize := int64(1024)
	totalChunks := 3
	totalSize := int64(3072)

	// Create only 2 out of 3 chunks
	SaveChunk(tmpDir, uploadID, 0, bytes.Repeat([]byte("A"), 1024))
	SaveChunk(tmpDir, uploadID, 1, bytes.Repeat([]byte("B"), 1024))
	// Chunk 2 missing

	// Verification should fail
	err := VerifyChunkIntegrity(tmpDir, uploadID, totalChunks, chunkSize, totalSize)
	if err == nil {
		t.Error("VerifyChunkIntegrity should fail for missing chunks")
	}
}

func TestGetChunkNumbers(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "test-numbers-123"

	// Create chunks out of order
	SaveChunk(tmpDir, uploadID, 2, []byte("chunk 2"))
	SaveChunk(tmpDir, uploadID, 0, []byte("chunk 0"))
	SaveChunk(tmpDir, uploadID, 4, []byte("chunk 4"))
	SaveChunk(tmpDir, uploadID, 1, []byte("chunk 1"))

	numbers, err := GetChunkNumbers(tmpDir, uploadID)
	if err != nil {
		t.Fatalf("GetChunkNumbers failed: %v", err)
	}

	// Should be sorted in ascending order
	expected := []int{0, 1, 2, 4}
	if len(numbers) != len(expected) {
		t.Fatalf("numbers length = %d, want %d", len(numbers), len(expected))
	}

	for i, num := range expected {
		if numbers[i] != num {
			t.Errorf("numbers[%d] = %d, want %d", i, numbers[i], num)
		}
	}
}

func TestGetChunkNumbers_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	uploadID := "non-existent"

	numbers, err := GetChunkNumbers(tmpDir, uploadID)
	if err != nil {
		t.Fatalf("GetChunkNumbers failed: %v", err)
	}

	if len(numbers) != 0 {
		t.Errorf("numbers = %v, want empty slice", numbers)
	}
}

func TestGetPartialUploadDir(t *testing.T) {
	uploadDir := "/path/to/uploads"
	partialDir := GetPartialUploadDir(uploadDir)

	expected := filepath.Join(uploadDir, ".partial")
	if partialDir != expected {
		t.Errorf("GetPartialUploadDir = %q, want %q", partialDir, expected)
	}
}

func TestGetUploadChunksDir(t *testing.T) {
	uploadDir := "/path/to/uploads"
	uploadID := "test-upload-123"

	chunksDir := GetUploadChunksDir(uploadDir, uploadID)

	expected := filepath.Join(uploadDir, ".partial", uploadID)
	if chunksDir != expected {
		t.Errorf("GetUploadChunksDir = %q, want %q", chunksDir, expected)
	}
}

func TestGetChunkPath(t *testing.T) {
	uploadDir := "/path/to/uploads"
	uploadID := "test-upload-123"
	chunkNumber := 5

	chunkPath := GetChunkPath(uploadDir, uploadID, chunkNumber)

	expected := filepath.Join(uploadDir, ".partial", uploadID, "chunk_5")
	if chunkPath != expected {
		t.Errorf("GetChunkPath = %q, want %q", chunkPath, expected)
	}
}

func TestDetectMimeType(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		expectedMime string
	}{
		{
			name:         "PDF file",
			data:         []byte("%PDF-1.4\n"),
			expectedMime: "application/pdf",
		},
		{
			name:         "PNG image",
			data:         []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			expectedMime: "image/png",
		},
		{
			name:         "plain text",
			data:         []byte("Hello, world!"),
			expectedMime: "text/plain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mimeType := DetectMimeType(tt.data)
			// Use strings.HasPrefix to handle MIME types with parameters like "text/plain; charset=utf-8"
			if !strings.HasPrefix(mimeType, tt.expectedMime) {
				t.Errorf("DetectMimeType = %q, want prefix %q", mimeType, tt.expectedMime)
			}
		})
	}
}
