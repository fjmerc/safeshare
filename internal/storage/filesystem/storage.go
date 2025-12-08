// Package filesystem implements the StorageBackend interface for local filesystem storage.
package filesystem

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/fjmerc/safeshare/internal/storage"
)

const (
	// chunkBufferSize is the buffer size for chunk assembly (20MB)
	// Set to match maximum possible chunk size
	chunkBufferSize = 20 * 1024 * 1024

	// partialDir is the subdirectory for partial uploads
	partialDir = ".partial"
)

// FilesystemStorage implements StorageBackend for local filesystem storage.
type FilesystemStorage struct {
	baseDir    string // Base directory for all storage operations
	absBaseDir string // Absolute path of baseDir for path validation
}

// NewFilesystemStorage creates a new FilesystemStorage with the given base directory.
func NewFilesystemStorage(baseDir string) (*FilesystemStorage, error) {
	// Ensure base directory exists
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, storage.NewStorageError("NewFilesystemStorage", baseDir, err)
	}

	// Also ensure partial uploads directory exists
	partialPath := filepath.Join(baseDir, partialDir)
	if err := os.MkdirAll(partialPath, 0755); err != nil {
		return nil, storage.NewStorageError("NewFilesystemStorage", partialPath, err)
	}

	// Get absolute path for security validation
	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, storage.NewStorageError("NewFilesystemStorage", baseDir, err)
	}

	return &FilesystemStorage{
		baseDir:    baseDir,
		absBaseDir: absBaseDir,
	}, nil
}

// validatePath validates that the filename doesn't escape the base directory.
// Returns the safe full path or an error if path traversal is detected.
func (fs *FilesystemStorage) validatePath(filename string) (string, error) {
	// Clean the filename to resolve any ".." or "." components
	cleanFilename := filepath.Clean(filename)

	// Reject absolute paths
	if filepath.IsAbs(cleanFilename) {
		return "", fmt.Errorf("absolute paths not allowed: %s", filename)
	}

	// Reject paths that contain ".." after cleaning
	if strings.HasPrefix(cleanFilename, "..") || strings.Contains(cleanFilename, string(filepath.Separator)+"..") {
		return "", fmt.Errorf("path traversal not allowed: %s", filename)
	}

	// Build full path
	fullPath := filepath.Join(fs.baseDir, cleanFilename)

	// Get absolute path and verify it's within baseDir
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	// Ensure the resolved path is within baseDir
	// Must start with baseDir + separator (or equal baseDir for the root case)
	if !strings.HasPrefix(absPath, fs.absBaseDir+string(filepath.Separator)) && absPath != fs.absBaseDir {
		return "", fmt.Errorf("path escape attempt: %s", filename)
	}

	return fullPath, nil
}

// validateUploadID validates that the uploadID doesn't contain path traversal.
func (fs *FilesystemStorage) validateUploadID(uploadID string) error {
	// Upload IDs should be UUIDs, but we validate defensively
	if strings.Contains(uploadID, "..") || strings.Contains(uploadID, string(filepath.Separator)) {
		return fmt.Errorf("invalid upload ID: %s", uploadID)
	}
	return nil
}

// Store writes data from the reader to storage with the given filename.
// Uses atomic write pattern (temp file then rename) for safety.
func (fs *FilesystemStorage) Store(ctx context.Context, filename string, reader io.Reader, size int64) (string, string, error) {
	filePath, err := fs.validatePath(filename)
	if err != nil {
		return "", "", storage.NewStorageErrorWithMessage("Store", filename, err, "path validation failed")
	}
	tempPath := filePath + ".tmp"

	// Create temp file
	tempFile, err := os.Create(tempPath)
	if err != nil {
		return "", "", storage.NewStorageError("Store", filename, err)
	}

	// Track success for cleanup
	var succeeded bool
	defer func() {
		tempFile.Close()
		if !succeeded {
			os.Remove(tempPath)
		}
	}()

	// Setup SHA256 hashing during streaming
	hasher := sha256.New()
	teeReader := io.TeeReader(reader, hasher)

	// Copy data to temp file
	written, err := io.Copy(tempFile, teeReader)
	if err != nil {
		return "", "", storage.NewStorageError("Store", filename, err)
	}

	// Validate size if provided
	if size > 0 && written != size {
		return "", "", storage.NewStorageErrorWithMessage("Store", filename, nil,
			fmt.Sprintf("size mismatch: expected %d bytes, wrote %d bytes", size, written))
	}

	// Finalize hash
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Close temp file before rename
	if err := tempFile.Close(); err != nil {
		return "", "", storage.NewStorageError("Store", filename, err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, filePath); err != nil {
		return "", "", storage.NewStorageError("Store", filename, err)
	}

	succeeded = true
	slog.Debug("file stored",
		"filename", filename,
		"size", written,
		"hash", hash[:16]+"...",
	)

	return filename, hash, nil
}

// Retrieve returns a reader for the stored file.
func (fs *FilesystemStorage) Retrieve(ctx context.Context, filename string) (io.ReadCloser, error) {
	filePath, err := fs.validatePath(filename)
	if err != nil {
		return nil, storage.NewStorageErrorWithMessage("Retrieve", filename, err, "path validation failed")
	}

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.NewStorageErrorWithMessage("Retrieve", filename, err, "file not found")
		}
		return nil, storage.NewStorageError("Retrieve", filename, err)
	}

	return file, nil
}

// Delete removes a file from storage.
func (fs *FilesystemStorage) Delete(ctx context.Context, filename string) error {
	filePath, err := fs.validatePath(filename)
	if err != nil {
		return storage.NewStorageErrorWithMessage("Delete", filename, err, "path validation failed")
	}

	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			// File already deleted, not an error
			return nil
		}
		return storage.NewStorageError("Delete", filename, err)
	}

	slog.Debug("file deleted", "filename", filename)
	return nil
}

// Exists checks if a file exists in storage.
func (fs *FilesystemStorage) Exists(ctx context.Context, filename string) (bool, error) {
	filePath, err := fs.validatePath(filename)
	if err != nil {
		return false, storage.NewStorageErrorWithMessage("Exists", filename, err, "path validation failed")
	}

	_, err = os.Stat(filePath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, storage.NewStorageError("Exists", filename, err)
}

// GetSize returns the size of a stored file in bytes.
func (fs *FilesystemStorage) GetSize(ctx context.Context, filename string) (int64, error) {
	filePath, err := fs.validatePath(filename)
	if err != nil {
		return 0, storage.NewStorageErrorWithMessage("GetSize", filename, err, "path validation failed")
	}

	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, storage.NewStorageErrorWithMessage("GetSize", filename, err, "file not found")
		}
		return 0, storage.NewStorageError("GetSize", filename, err)
	}

	return info.Size(), nil
}

// StreamRange writes a byte range from a stored file to the writer.
func (fs *FilesystemStorage) StreamRange(ctx context.Context, filename string, start, end int64, w io.Writer) (int64, error) {
	// Validate range parameters
	if start < 0 || end < start {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil,
			fmt.Sprintf("invalid range: start=%d, end=%d", start, end))
	}

	filePath, err := fs.validatePath(filename)
	if err != nil {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, err, "path validation failed")
	}

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, err, "file not found")
		}
		return 0, storage.NewStorageError("StreamRange", filename, err)
	}
	defer file.Close()

	// Seek to start position
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return 0, storage.NewStorageError("StreamRange", filename, err)
	}

	// Calculate content length (end is inclusive)
	contentLength := end - start + 1

	// Create limited reader
	limitedReader := io.LimitReader(file, contentLength)

	// Stream to writer
	written, err := io.Copy(w, limitedReader)
	if err != nil {
		return written, storage.NewStorageError("StreamRange", filename, err)
	}

	return written, nil
}

// getChunkPath returns the file path for a specific chunk.
func (fs *FilesystemStorage) getChunkPath(uploadID string, chunkNum int) string {
	return filepath.Join(fs.baseDir, partialDir, uploadID, fmt.Sprintf("chunk_%d", chunkNum))
}

// getChunksDir returns the directory path for a specific upload's chunks.
func (fs *FilesystemStorage) getChunksDir(uploadID string) string {
	return filepath.Join(fs.baseDir, partialDir, uploadID)
}

// SaveChunk saves a chunk of data for a partial upload.
func (fs *FilesystemStorage) SaveChunk(ctx context.Context, uploadID string, chunkNum int, data io.Reader, size int64) error {
	// Validate uploadID to prevent path traversal
	if err := fs.validateUploadID(uploadID); err != nil {
		return storage.NewStorageErrorWithMessage("SaveChunk", uploadID, err, "invalid upload ID")
	}

	// Create chunks directory if it doesn't exist
	chunksDir := fs.getChunksDir(uploadID)
	if err := os.MkdirAll(chunksDir, 0755); err != nil {
		return storage.NewStorageError("SaveChunk", uploadID, err)
	}

	// Open chunk file
	chunkPath := fs.getChunkPath(uploadID, chunkNum)
	file, err := os.OpenFile(chunkPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return storage.NewStorageError("SaveChunk", chunkPath, err)
	}
	defer file.Close()

	// Write chunk data
	written, err := io.Copy(file, data)
	if err != nil {
		return storage.NewStorageError("SaveChunk", chunkPath, err)
	}

	// Validate size if provided
	if size > 0 && written != size {
		os.Remove(chunkPath)
		return storage.NewStorageErrorWithMessage("SaveChunk", chunkPath, nil,
			fmt.Sprintf("size mismatch: expected %d bytes, wrote %d bytes", size, written))
	}

	// Intentionally NO file.Sync() - let OS flush asynchronously
	// Chunks are resumable if server crashes, so this is safe

	slog.Debug("chunk saved",
		"upload_id", uploadID,
		"chunk_number", chunkNum,
		"size", written,
	)

	return nil
}

// GetChunk returns a reader for a specific chunk.
func (fs *FilesystemStorage) GetChunk(ctx context.Context, uploadID string, chunkNum int) (io.ReadCloser, error) {
	// Validate uploadID to prevent path traversal
	if err := fs.validateUploadID(uploadID); err != nil {
		return nil, storage.NewStorageErrorWithMessage("GetChunk", uploadID, err, "invalid upload ID")
	}

	chunkPath := fs.getChunkPath(uploadID, chunkNum)

	file, err := os.Open(chunkPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.NewStorageErrorWithMessage("GetChunk", chunkPath, err, "chunk not found")
		}
		return nil, storage.NewStorageError("GetChunk", chunkPath, err)
	}

	return file, nil
}

// DeleteChunks removes all chunks for an upload session.
func (fs *FilesystemStorage) DeleteChunks(ctx context.Context, uploadID string) error {
	// Validate uploadID to prevent path traversal
	if err := fs.validateUploadID(uploadID); err != nil {
		return storage.NewStorageErrorWithMessage("DeleteChunks", uploadID, err, "invalid upload ID")
	}

	chunksDir := fs.getChunksDir(uploadID)

	// Check if directory exists
	if _, err := os.Stat(chunksDir); os.IsNotExist(err) {
		return nil // Already deleted
	}

	// Remove entire chunks directory
	if err := os.RemoveAll(chunksDir); err != nil {
		return storage.NewStorageError("DeleteChunks", uploadID, err)
	}

	slog.Debug("chunks deleted", "upload_id", uploadID)
	return nil
}

// ChunkExists checks if a specific chunk exists and returns its size.
func (fs *FilesystemStorage) ChunkExists(ctx context.Context, uploadID string, chunkNum int) (bool, int64, error) {
	// Validate uploadID to prevent path traversal
	if err := fs.validateUploadID(uploadID); err != nil {
		return false, 0, storage.NewStorageErrorWithMessage("ChunkExists", uploadID, err, "invalid upload ID")
	}

	chunkPath := fs.getChunkPath(uploadID, chunkNum)

	info, err := os.Stat(chunkPath)
	if os.IsNotExist(err) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, storage.NewStorageError("ChunkExists", chunkPath, err)
	}

	return true, info.Size(), nil
}

// AssembleChunks combines all chunks into a single file.
func (fs *FilesystemStorage) AssembleChunks(ctx context.Context, uploadID string, totalChunks int, destFilename string) (string, error) {
	// Validate uploadID to prevent path traversal
	if err := fs.validateUploadID(uploadID); err != nil {
		return "", storage.NewStorageErrorWithMessage("AssembleChunks", uploadID, err, "invalid upload ID")
	}

	// Validate destination filename
	outputPath, err := fs.validatePath(destFilename)
	if err != nil {
		return "", storage.NewStorageErrorWithMessage("AssembleChunks", destFilename, err, "path validation failed")
	}

	startTime := time.Now()

	slog.Info("assembling chunks",
		"upload_id", uploadID,
		"total_chunks", totalChunks,
		"dest_filename", destFilename,
	)

	// Verify all chunks exist before starting assembly
	missing, err := fs.GetMissingChunks(ctx, uploadID, totalChunks)
	if err != nil {
		return "", storage.NewStorageError("AssembleChunks", uploadID, err)
	}
	if len(missing) > 0 {
		return "", storage.NewStorageErrorWithMessage("AssembleChunks", uploadID, nil,
			fmt.Sprintf("cannot assemble: %d chunks missing (first missing: %d)", len(missing), missing[0]))
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return "", storage.NewStorageError("AssembleChunks", destFilename, err)
	}
	defer outFile.Close()

	// Use buffered writer for better performance
	bufferedWriter := bufio.NewWriterSize(outFile, chunkBufferSize)
	defer bufferedWriter.Flush()

	// Compute SHA256 hash as we write (zero extra I/O)
	hasher := sha256.New()
	writer := io.MultiWriter(bufferedWriter, hasher)

	var totalBytesWritten int64

	// Assemble chunks in order
	for i := 0; i < totalChunks; i++ {
		chunkPath := fs.getChunkPath(uploadID, i)

		// Open chunk file
		chunkFile, err := os.Open(chunkPath)
		if err != nil {
			return "", storage.NewStorageError("AssembleChunks", chunkPath, err)
		}

		// Copy chunk to output with buffered I/O (also hashes via MultiWriter)
		bytesWritten, err := io.Copy(writer, chunkFile)
		chunkFile.Close()

		if err != nil {
			return "", storage.NewStorageError("AssembleChunks", chunkPath, err)
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
	if err := bufferedWriter.Flush(); err != nil {
		return "", storage.NewStorageError("AssembleChunks", destFilename, err)
	}

	// Finalize SHA256 hash
	hash := hex.EncodeToString(hasher.Sum(nil))

	duration := time.Since(startTime)
	throughputMBps := float64(totalBytesWritten) / duration.Seconds() / (1024 * 1024)

	slog.Info("chunk assembly complete",
		"upload_id", uploadID,
		"total_chunks", totalChunks,
		"total_bytes", totalBytesWritten,
		"duration_ms", duration.Milliseconds(),
		"throughput_mbps", fmt.Sprintf("%.1f", throughputMBps),
		"sha256_hash", hash[:16]+"...",
	)

	return hash, nil
}

// GetMissingChunks returns a sorted list of missing chunk numbers.
func (fs *FilesystemStorage) GetMissingChunks(ctx context.Context, uploadID string, totalChunks int) ([]int, error) {
	var missing []int

	for i := 0; i < totalChunks; i++ {
		exists, _, err := fs.ChunkExists(ctx, uploadID, i)
		if err != nil {
			return nil, err
		}
		if !exists {
			missing = append(missing, i)
		}
	}

	return missing, nil
}

// GetChunkCount returns the number of chunks present for an upload.
func (fs *FilesystemStorage) GetChunkCount(ctx context.Context, uploadID string) (int, error) {
	// Validate uploadID to prevent path traversal
	if err := fs.validateUploadID(uploadID); err != nil {
		return 0, storage.NewStorageErrorWithMessage("GetChunkCount", uploadID, err, "invalid upload ID")
	}

	chunksDir := fs.getChunksDir(uploadID)

	// Check if directory exists
	if _, err := os.Stat(chunksDir); os.IsNotExist(err) {
		return 0, nil
	}

	// Read directory entries
	entries, err := os.ReadDir(chunksDir)
	if err != nil {
		return 0, storage.NewStorageError("GetChunkCount", uploadID, err)
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

// GetAvailableSpace returns the available storage space in bytes.
func (fs *FilesystemStorage) GetAvailableSpace(ctx context.Context) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(fs.baseDir, &stat); err != nil {
		return 0, storage.NewStorageError("GetAvailableSpace", fs.baseDir, err)
	}

	// Available to non-root users
	availableBytes := int64(stat.Bavail) * int64(stat.Bsize)
	return availableBytes, nil
}

// GetUsedSpace returns the storage space currently used in bytes.
func (fs *FilesystemStorage) GetUsedSpace(ctx context.Context) (int64, error) {
	var totalSize int64

	err := filepath.Walk(fs.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip files/directories we can't access
			return nil
		}

		// Only count regular files (not directories)
		if !info.IsDir() {
			totalSize += info.Size()
		}

		return nil
	})

	if err != nil {
		return 0, storage.NewStorageError("GetUsedSpace", fs.baseDir, err)
	}

	return totalSize, nil
}

// GetFilePath returns the full file path for a filename.
// This is useful for handlers that need the full path for legacy operations.
func (fs *FilesystemStorage) GetFilePath(filename string) string {
	return filepath.Join(fs.baseDir, filename)
}

// GetBaseDir returns the base directory.
func (fs *FilesystemStorage) GetBaseDir() string {
	return fs.baseDir
}

// GetChunkNumbers returns a sorted list of chunk numbers that exist for an upload.
func (fs *FilesystemStorage) GetChunkNumbers(ctx context.Context, uploadID string) ([]int, error) {
	// Validate uploadID to prevent path traversal
	if err := fs.validateUploadID(uploadID); err != nil {
		return nil, storage.NewStorageErrorWithMessage("GetChunkNumbers", uploadID, err, "invalid upload ID")
	}

	chunksDir := fs.getChunksDir(uploadID)

	// Check if directory exists
	if _, err := os.Stat(chunksDir); os.IsNotExist(err) {
		return []int{}, nil
	}

	// Read directory entries
	entries, err := os.ReadDir(chunksDir)
	if err != nil {
		return nil, storage.NewStorageError("GetChunkNumbers", uploadID, err)
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
