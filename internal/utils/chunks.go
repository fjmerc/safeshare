package utils

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/gabriel-vasile/mimetype"
)

const (
	// chunkBufferSize is the buffer size for chunk assembly (8MB)
	// Optimized for large file performance - reduces syscall overhead
	// Increased from 2MB to 8MB for better alignment with chunk sizes
	chunkBufferSize = 8 * 1024 * 1024
)

// GetPartialUploadDir returns the directory path for partial uploads
func GetPartialUploadDir(uploadDir string) string {
	return filepath.Join(uploadDir, ".partial")
}

// GetUploadChunksDir returns the directory path for a specific upload's chunks
func GetUploadChunksDir(uploadDir, uploadID string) string {
	return filepath.Join(GetPartialUploadDir(uploadDir), uploadID)
}

// GetChunkPath returns the file path for a specific chunk
func GetChunkPath(uploadDir, uploadID string, chunkNumber int) string {
	return filepath.Join(GetUploadChunksDir(uploadDir, uploadID), fmt.Sprintf("chunk_%d", chunkNumber))
}

// SaveChunk saves a chunk to disk
func SaveChunk(uploadDir, uploadID string, chunkNumber int, data []byte) error {
	// Create chunks directory if it doesn't exist
	chunksDir := GetUploadChunksDir(uploadDir, uploadID)
	if err := os.MkdirAll(chunksDir, 0755); err != nil {
		return fmt.Errorf("failed to create chunks directory: %w", err)
	}

	// Open chunk file (avoid os.WriteFile to prevent implicit sync)
	chunkPath := GetChunkPath(uploadDir, uploadID, chunkNumber)
	file, err := os.OpenFile(chunkPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create chunk file: %w", err)
	}
	defer file.Close()

	// Write chunk data
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write chunk data: %w", err)
	}

	// Intentionally NO file.Sync() - let OS flush asynchronously
	// Chunks are resumable if server crashes, so this is safe

	slog.Debug("chunk saved",
		"upload_id", uploadID,
		"chunk_number", chunkNumber,
		"size", len(data),
		"path", chunkPath,
	)

	return nil
}

// ChunkExists checks if a specific chunk exists and returns its size
func ChunkExists(uploadDir, uploadID string, chunkNumber int) (bool, int64, error) {
	chunkPath := GetChunkPath(uploadDir, uploadID, chunkNumber)

	info, err := os.Stat(chunkPath)
	if os.IsNotExist(err) {
		return false, 0, nil
	}

	if err != nil {
		return false, 0, fmt.Errorf("failed to stat chunk file: %w", err)
	}

	return true, info.Size(), nil
}

// GetMissingChunks returns a sorted list of missing chunk numbers
func GetMissingChunks(uploadDir, uploadID string, totalChunks int) ([]int, error) {
	var missing []int

	for i := 0; i < totalChunks; i++ {
		exists, _, err := ChunkExists(uploadDir, uploadID, i)
		if err != nil {
			return nil, fmt.Errorf("failed to check chunk %d: %w", i, err)
		}

		if !exists {
			missing = append(missing, i)
		}
	}

	return missing, nil
}

// AssembleChunks assembles all chunks into a single file
// Returns the total bytes written
func AssembleChunks(uploadDir, uploadID string, totalChunks int, outputPath string) (int64, error) {
	startTime := time.Now()

	slog.Info("assembling chunks",
		"upload_id", uploadID,
		"total_chunks", totalChunks,
		"output_path", outputPath,
	)

	// Verify all chunks exist before starting assembly
	missing, err := GetMissingChunks(uploadDir, uploadID, totalChunks)
	if err != nil {
		return 0, fmt.Errorf("failed to check for missing chunks: %w", err)
	}

	if len(missing) > 0 {
		return 0, fmt.Errorf("cannot assemble: %d chunks missing (first missing: %d)", len(missing), missing[0])
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Use buffered writer for better performance
	writer := bufio.NewWriterSize(outFile, chunkBufferSize)
	defer writer.Flush()

	var totalBytesWritten int64

	// Assemble chunks in order
	for i := 0; i < totalChunks; i++ {
		chunkPath := GetChunkPath(uploadDir, uploadID, i)

		// Open chunk file
		chunkFile, err := os.Open(chunkPath)
		if err != nil {
			return 0, fmt.Errorf("failed to open chunk %d: %w", i, err)
		}

		// Copy chunk to output with buffered I/O
		bytesWritten, err := io.Copy(writer, chunkFile)
		chunkFile.Close()

		if err != nil {
			return 0, fmt.Errorf("failed to copy chunk %d: %w", i, err)
		}

		totalBytesWritten += bytesWritten

		// Log progress every 100 chunks
		if (i+1)%100 == 0 || i == totalChunks-1 {
			slog.Debug("chunk assembly progress",
				"upload_id", uploadID,
				"chunks_processed", i+1,
				"total_chunks", totalChunks,
				"bytes_written", totalBytesWritten,
			)
		}
	}

	// Flush buffered writer
	if err := writer.Flush(); err != nil {
		return 0, fmt.Errorf("failed to flush output file: %w", err)
	}

	// NOTE: Deliberately NOT calling outFile.Sync() here for performance
	// Rationale: Assembly can take 60-70s for large files on HDD with fsync()
	// Trade-off: If server crashes during assembly, chunks are still intact
	//            and user can retry the "complete" operation
	// Modern filesystems (ext4, xfs) have journaling which provides some protection

	duration := time.Since(startTime)
	durationMs := duration.Milliseconds()
	throughputMBps := float64(totalBytesWritten) / duration.Seconds() / (1024 * 1024)

	slog.Info("chunk assembly complete",
		"upload_id", uploadID,
		"total_chunks", totalChunks,
		"total_bytes", totalBytesWritten,
		"duration_ms", durationMs,
		"throughput_mbps", fmt.Sprintf("%.1f", throughputMBps),
	)

	return totalBytesWritten, nil
}

// DeleteChunks deletes all chunks and the chunks directory for an upload
func DeleteChunks(uploadDir, uploadID string) error {
	chunksDir := GetUploadChunksDir(uploadDir, uploadID)

	// Check if directory exists
	if _, err := os.Stat(chunksDir); os.IsNotExist(err) {
		return nil // Already deleted
	}

	// Remove entire chunks directory
	if err := os.RemoveAll(chunksDir); err != nil {
		return fmt.Errorf("failed to delete chunks directory: %w", err)
	}

	slog.Debug("chunks deleted", "upload_id", uploadID, "path", chunksDir)

	return nil
}

// GetChunkCount returns the number of chunks present for an upload
func GetChunkCount(uploadDir, uploadID string) (int, error) {
	chunksDir := GetUploadChunksDir(uploadDir, uploadID)

	// Check if directory exists
	if _, err := os.Stat(chunksDir); os.IsNotExist(err) {
		return 0, nil
	}

	// Read directory entries
	entries, err := os.ReadDir(chunksDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read chunks directory: %w", err)
	}

	// Count only chunk files (not directories)
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			count++
		}
	}

	return count, nil
}

// GetUploadChunksSize returns the total size of all chunks for an upload
func GetUploadChunksSize(uploadDir, uploadID string) (int64, error) {
	chunksDir := GetUploadChunksDir(uploadDir, uploadID)

	// Check if directory exists
	if _, err := os.Stat(chunksDir); os.IsNotExist(err) {
		return 0, nil
	}

	// Read directory entries
	entries, err := os.ReadDir(chunksDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read chunks directory: %w", err)
	}

	var totalSize int64
	for _, entry := range entries {
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return 0, fmt.Errorf("failed to get file info: %w", err)
			}
			totalSize += info.Size()
		}
	}

	return totalSize, nil
}

// CleanupPartialUploadsDir removes empty directories in the partial uploads directory
func CleanupPartialUploadsDir(uploadDir string) error {
	partialDir := GetPartialUploadDir(uploadDir)

	// Check if directory exists
	if _, err := os.Stat(partialDir); os.IsNotExist(err) {
		return nil // Nothing to clean up
	}

	// Read entries in partial uploads directory
	entries, err := os.ReadDir(partialDir)
	if err != nil {
		return fmt.Errorf("failed to read partial uploads directory: %w", err)
	}

	// Try to remove empty directories
	for _, entry := range entries {
		if entry.IsDir() {
			dirPath := filepath.Join(partialDir, entry.Name())

			// Try to remove (will fail if not empty, which is fine)
			if err := os.Remove(dirPath); err == nil {
				slog.Debug("removed empty partial upload directory", "path", dirPath)
			}
		}
	}

	return nil
}

// VerifyChunkIntegrity verifies that all chunks exist and match expected sizes
func VerifyChunkIntegrity(uploadDir, uploadID string, totalChunks int, expectedChunkSize int64, totalSize int64) error {
	for i := 0; i < totalChunks; i++ {
		exists, size, err := ChunkExists(uploadDir, uploadID, i)
		if err != nil {
			return fmt.Errorf("failed to check chunk %d: %w", i, err)
		}

		if !exists {
			return fmt.Errorf("chunk %d is missing", i)
		}

		// Verify size (last chunk can be smaller)
		if i < totalChunks-1 {
			// Not the last chunk - should match expected size
			if size != expectedChunkSize {
				return fmt.Errorf("chunk %d has incorrect size: expected %d, got %d", i, expectedChunkSize, size)
			}
		} else {
			// Last chunk - calculate expected size
			lastChunkSize := totalSize - (int64(totalChunks-1) * expectedChunkSize)
			if size != lastChunkSize {
				return fmt.Errorf("last chunk %d has incorrect size: expected %d, got %d", i, lastChunkSize, size)
			}
		}
	}

	return nil
}

// GetChunkNumbers returns a sorted list of chunk numbers that exist
func GetChunkNumbers(uploadDir, uploadID string) ([]int, error) {
	chunksDir := GetUploadChunksDir(uploadDir, uploadID)

	// Check if directory exists
	if _, err := os.Stat(chunksDir); os.IsNotExist(err) {
		return []int{}, nil
	}

	// Read directory entries
	entries, err := os.ReadDir(chunksDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read chunks directory: %w", err)
	}

	var chunkNumbers []int
	for _, entry := range entries {
		if !entry.IsDir() {
			// Parse chunk number from filename (chunk_N)
			var chunkNum int
			if _, err := fmt.Sscanf(entry.Name(), "chunk_%d", &chunkNum); err == nil {
				chunkNumbers = append(chunkNumbers, chunkNum)
			}
		}
	}

	// Sort in ascending order
	sort.Ints(chunkNumbers)

	return chunkNumbers, nil
}

// DetectMimeType detects the MIME type from file content
func DetectMimeType(data []byte) string {
	mtype := mimetype.Detect(data)
	return mtype.String()
}
