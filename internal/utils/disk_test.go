package utils

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGetDiskSpace tests disk space information retrieval
func TestGetDiskSpace(t *testing.T) {
	// Use temp directory which should exist
	tmpDir := os.TempDir()

	info, err := GetDiskSpace(tmpDir)
	if err != nil {
		t.Fatalf("GetDiskSpace failed: %v", err)
	}

	// Verify basic sanity checks
	if info.TotalBytes == 0 {
		t.Error("TotalBytes should not be zero")
	}

	if info.FreeBytes > info.TotalBytes {
		t.Errorf("FreeBytes (%d) should not exceed TotalBytes (%d)", info.FreeBytes, info.TotalBytes)
	}

	if info.AvailableBytes > info.TotalBytes {
		t.Errorf("AvailableBytes (%d) should not exceed TotalBytes (%d)", info.AvailableBytes, info.TotalBytes)
	}

	if info.UsedBytes > info.TotalBytes {
		t.Errorf("UsedBytes (%d) should not exceed TotalBytes (%d)", info.UsedBytes, info.TotalBytes)
	}

	if info.UsedPercent < 0 || info.UsedPercent > 100 {
		t.Errorf("UsedPercent (%.2f) should be between 0 and 100", info.UsedPercent)
	}

	// Verify basic math
	expectedUsed := info.TotalBytes - info.FreeBytes
	if info.UsedBytes != expectedUsed {
		t.Errorf("UsedBytes calculation incorrect: got %d, expected %d", info.UsedBytes, expectedUsed)
	}
}

// TestGetDiskSpace_InvalidPath tests disk space check with invalid path
func TestGetDiskSpace_InvalidPath(t *testing.T) {
	invalidPath := "/this/path/definitely/does/not/exist/anywhere"

	_, err := GetDiskSpace(invalidPath)
	if err == nil {
		t.Fatal("Expected error for invalid path, got nil")
	}
}

// TestCheckDiskSpace_Success tests successful disk space check
func TestCheckDiskSpace_Success(t *testing.T) {
	tmpDir := os.TempDir()

	// Test with small upload size (1KB) - should succeed
	// Skip percentage check since CI runners may have high disk usage
	smallUpload := int64(1024)
	ok, msg, err := CheckDiskSpace(tmpDir, smallUpload, true)
	if err != nil {
		t.Fatalf("CheckDiskSpace failed: %v", err)
	}

	if !ok {
		t.Errorf("Expected space check to pass for 1KB upload, got: %s", msg)
	}

	if msg != "" {
		t.Errorf("Expected empty message for successful check, got: %s", msg)
	}
}

// TestCheckDiskSpace_TooLarge tests upload exceeding disk space
func TestCheckDiskSpace_TooLarge(t *testing.T) {
	tmpDir := os.TempDir()

	// Get current disk info
	info, err := GetDiskSpace(tmpDir)
	if err != nil {
		t.Fatalf("Failed to get disk space: %v", err)
	}

	// Try to upload more than available space
	tooLargeUpload := int64(info.AvailableBytes + 1024*1024*1024) // Available + 1GB

	ok, msg, err := CheckDiskSpace(tmpDir, tooLargeUpload, false)
	if err != nil {
		t.Fatalf("CheckDiskSpace failed: %v", err)
	}

	if ok {
		t.Error("Expected space check to fail for oversized upload")
	}

	if msg == "" {
		t.Error("Expected error message for oversized upload")
	}

	t.Logf("Error message for oversized upload: %s", msg)
}

// TestCheckDiskSpace_SkipPercentCheck tests skipping percentage check
func TestCheckDiskSpace_SkipPercentCheck(t *testing.T) {
	tmpDir := os.TempDir()

	// Small upload with percentage check skipped (quota mode)
	smallUpload := int64(1024)
	ok, msg, err := CheckDiskSpace(tmpDir, smallUpload, true)
	if err != nil {
		t.Fatalf("CheckDiskSpace failed: %v", err)
	}

	if !ok {
		t.Errorf("Expected space check to pass with skip=true, got: %s", msg)
	}
}

// TestGetPartialUploadsSize_Empty tests size calculation with no partial uploads
func TestGetPartialUploadsSize_Empty(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "test-partial-uploads-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Should return 0 when .partial doesn't exist
	size, err := GetPartialUploadsSize(tmpDir)
	if err != nil {
		t.Fatalf("GetPartialUploadsSize failed: %v", err)
	}

	if size != 0 {
		t.Errorf("Expected 0 bytes for non-existent .partial dir, got %d", size)
	}
}

// TestGetPartialUploadsSize_WithFiles tests size calculation with partial uploads
func TestGetPartialUploadsSize_WithFiles(t *testing.T) {
	// Create temp directory structure
	tmpDir, err := os.MkdirTemp("", "test-partial-uploads-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	partialDir := filepath.Join(tmpDir, ".partial")
	if err := os.MkdirAll(partialDir, 0755); err != nil {
		t.Fatalf("Failed to create .partial dir: %v", err)
	}

	// Create test upload directory with chunks
	uploadID := "test-upload-123"
	uploadChunksDir := filepath.Join(partialDir, uploadID)
	if err := os.MkdirAll(uploadChunksDir, 0755); err != nil {
		t.Fatalf("Failed to create upload chunks dir: %v", err)
	}

	// Create test chunk files
	testFiles := []struct {
		name string
		size int
	}{
		{"chunk_0", 1024},
		{"chunk_1", 2048},
		{"chunk_2", 512},
	}

	expectedTotalSize := int64(0)
	for _, tf := range testFiles {
		filePath := filepath.Join(uploadChunksDir, tf.name)
		data := make([]byte, tf.size)
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", tf.name, err)
		}
		expectedTotalSize += int64(tf.size)
	}

	// Calculate partial uploads size
	size, err := GetPartialUploadsSize(tmpDir)
	if err != nil {
		t.Fatalf("GetPartialUploadsSize failed: %v", err)
	}

	if size != expectedTotalSize {
		t.Errorf("Expected total size %d bytes, got %d bytes", expectedTotalSize, size)
	}

	t.Logf("Partial uploads total size: %s", FormatBytes(uint64(size)))
}

// TestGetPartialUploadsSize_MultipleUploads tests size with multiple upload sessions
func TestGetPartialUploadsSize_MultipleUploads(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-partial-uploads-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	partialDir := filepath.Join(tmpDir, ".partial")
	if err := os.MkdirAll(partialDir, 0755); err != nil {
		t.Fatalf("Failed to create .partial dir: %v", err)
	}

	// Create multiple upload sessions
	uploads := []string{"upload-1", "upload-2", "upload-3"}
	chunkSize := 1024
	chunksPerUpload := 3

	expectedTotal := int64(len(uploads) * chunksPerUpload * chunkSize)

	for _, uploadID := range uploads {
		uploadDir := filepath.Join(partialDir, uploadID)
		if err := os.MkdirAll(uploadDir, 0755); err != nil {
			t.Fatalf("Failed to create upload dir: %v", err)
		}

		for i := 0; i < chunksPerUpload; i++ {
			chunkPath := GetChunkPath(tmpDir, uploadID, i)
			data := make([]byte, chunkSize)
			if err := os.WriteFile(chunkPath, data, 0644); err != nil {
				t.Fatalf("Failed to create chunk: %v", err)
			}
		}
	}

	size, err := GetPartialUploadsSize(tmpDir)
	if err != nil {
		t.Fatalf("GetPartialUploadsSize failed: %v", err)
	}

	if size != expectedTotal {
		t.Errorf("Expected total size %d bytes, got %d bytes", expectedTotal, size)
	}
}
