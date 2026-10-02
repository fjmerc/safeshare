package utils

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gabriel-vasile/mimetype"
)

// ErrChunkMissing is returned (wrapped) by chunkSequenceReader.Read when a
// chunk file cannot be opened — missing, permissions, or otherwise
// unreadable. Distinct from a generic I/O error so callers (in particular
// the ADR-015 malware-scan retry loop) can tell "the source data is gone"
// apart from "the downstream scanner is having trouble," which call for
// different responses: the former is never worth retrying and is never a
// candidate for MALWARE_SCAN_ALLOW_UNVERIFIED.
var ErrChunkMissing = errors.New("chunk missing or unreadable")

const (
	// chunkBufferSize is the buffer size for chunk assembly (20MB)
	// Set to match maximum possible chunk size from CalculateOptimalChunkSize
	// Ensures buffer is always large enough for any chunk
	chunkBufferSize = 20 * 1024 * 1024
)

// CalculateOptimalChunkSize determines the best chunk size based on file size
// Optimizes for both network efficiency and failure recovery
func CalculateOptimalChunkSize(fileSize int64) int64 {
	const minChunk = 5 * 1024 * 1024      // 5MB
	const defaultChunk = 10 * 1024 * 1024 // 10MB
	const maxChunk = 20 * 1024 * 1024     // 20MB

	// Files < 100MB: 5MB chunks (faster retry on failure)
	if fileSize < 100*1024*1024 {
		return minChunk
	}

	// Files 100MB-1GB: 10MB chunks (balanced)
	if fileSize < 1*1024*1024*1024 {
		return defaultChunk
	}

	// Files > 1GB: 20MB chunks (reduce HTTP overhead)
	return maxChunk
}

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
	return filepath.Join(GetUploadChunksDir(uploadDir, uploadID), fmt.Sprintf("%s%d", chunkFilePrefix, chunkNumber))
}

// chunkFilePrefix is the name prefix of a stored chunk ("chunk_<N>").
const chunkFilePrefix = "chunk_"

// parseChunkFileName returns the chunk number for a stored chunk file name.
// Only exact "chunk_<digits>" names match, so in-progress temp files are
// never counted or assembled as chunks.
func parseChunkFileName(name string) (int, bool) {
	digits, ok := strings.CutPrefix(name, chunkFilePrefix)
	if !ok || digits == "" {
		return 0, false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ErrChunkTooLarge is returned by StreamChunkToTemp when its source holds
// more than the allowed number of bytes.
var ErrChunkTooLarge = errors.New("chunk exceeds expected size")

// ChunkReadError wraps a failure reading a chunk's source - typically the
// client's request body (disconnect, MaxBytesReader limit) - as opposed to
// a local write failure, so callers can answer with a client error rather
// than a 500.
type ChunkReadError struct{ Err error }

func (e *ChunkReadError) Error() string { return "failed to read chunk data: " + e.Err.Error() }
func (e *ChunkReadError) Unwrap() error { return e.Err }

// errRecordingReader remembers the last non-EOF error its reader returned,
// so a failed io.Copy can be attributed to the read side or the write side.
type errRecordingReader struct {
	r   io.Reader
	err error
}

func (e *errRecordingReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err != nil && err != io.EOF {
		e.err = err
	}
	return n, err
}

// StreamChunkToTemp copies src into a new temp file in the upload's chunks
// directory, hashing it on the way, so a chunk never has to be held in
// memory. At most maxSize bytes are accepted: a longer source returns
// ErrChunkTooLarge. On success the caller owns tmpPath and must either
// CommitChunk it or remove it; on error no temp file is left behind.
//
// The temp name doesn't match parseChunkFileName, so an uncommitted chunk is
// invisible to chunk counts and integrity checks.
func StreamChunkToTemp(uploadDir, uploadID string, chunkNumber int, src io.Reader, maxSize int64) (tmpPath string, size int64, checksum string, err error) {
	chunksDir := GetUploadChunksDir(uploadDir, uploadID)
	if err := os.MkdirAll(chunksDir, 0700); err != nil {
		return "", 0, "", fmt.Errorf("failed to create chunks directory: %w", err)
	}

	// CreateTemp opens with 0600 (avoid os.WriteFile to prevent implicit sync).
	file, err := os.CreateTemp(chunksDir, fmt.Sprintf(".%s%d.tmp-*", chunkFilePrefix, chunkNumber))
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to create chunk file: %w", err)
	}
	// A local copy: the error returns below zero the named tmpPath before
	// this deferred cleanup runs.
	path := file.Name()
	defer func() {
		if err != nil {
			os.Remove(path)
		}
	}()

	hasher := sha256.New()
	// Read one byte past maxSize so an oversized source is detected rather
	// than silently truncated.
	reader := &errRecordingReader{r: io.LimitReader(src, maxSize+1)}
	size, copyErr := io.Copy(io.MultiWriter(file, hasher), reader)
	closeErr := file.Close()

	switch {
	case reader.err != nil:
		return "", 0, "", &ChunkReadError{Err: reader.err}
	case copyErr != nil:
		return "", 0, "", fmt.Errorf("failed to write chunk data: %w", copyErr)
	case closeErr != nil:
		return "", 0, "", fmt.Errorf("failed to close chunk file: %w", closeErr)
	case size > maxSize:
		return "", 0, "", ErrChunkTooLarge
	}
	return path, size, hex.EncodeToString(hasher.Sum(nil)), nil
}

// CommitChunk atomically moves a temp file from StreamChunkToTemp into place
// as the chunk's final file, replacing any previous one.
func CommitChunk(tmpPath, uploadDir, uploadID string, chunkNumber int) error {
	if err := os.Rename(tmpPath, GetChunkPath(uploadDir, uploadID, chunkNumber)); err != nil {
		return fmt.Errorf("failed to finalize chunk file: %w", err)
	}
	return nil
}

// SaveChunk saves a chunk to disk atomically: the data goes to a temp file in
// the same directory that is renamed over the final path only once fully
// written. A failed or interrupted write (ENOSPC, crash, client retry racing
// the original request) therefore never leaves a truncated chunk_N behind,
// which used to make every retry of that chunk fail with CHUNK_CORRUPTION.
func SaveChunk(uploadDir, uploadID string, chunkNumber int, data []byte) error {
	chunkPath := GetChunkPath(uploadDir, uploadID, chunkNumber)
	tmpPath, _, _, err := StreamChunkToTemp(uploadDir, uploadID, chunkNumber, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	if err := CommitChunk(tmpPath, uploadDir, uploadID, chunkNumber); err != nil {
		os.Remove(tmpPath)
		return err
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

// AssembleChunks assembles all chunks into a single file and computes SHA256 hash
// Returns the total bytes written and SHA256 hash (hex-encoded)
func AssembleChunks(uploadDir, uploadID string, totalChunks int, outputPath string) (int64, string, error) {
	startTime := time.Now()

	slog.Info("assembling chunks",
		"upload_id", uploadID,
		"total_chunks", totalChunks,
		"output_path", outputPath,
	)

	// Verify all chunks exist before starting assembly
	missing, err := GetMissingChunks(uploadDir, uploadID, totalChunks)
	if err != nil {
		return 0, "", fmt.Errorf("failed to check for missing chunks: %w", err)
	}

	if len(missing) > 0 {
		return 0, "", fmt.Errorf("cannot assemble: %d chunks missing (first missing: %d)", len(missing), missing[0])
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return 0, "", fmt.Errorf("failed to create output file: %w", err)
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
		chunkPath := GetChunkPath(uploadDir, uploadID, i)

		// Open chunk file
		chunkFile, err := os.Open(chunkPath)
		if err != nil {
			return 0, "", fmt.Errorf("failed to open chunk %d: %w", i, err)
		}

		// Copy chunk to output with buffered I/O (also hashes via MultiWriter)
		bytesWritten, err := io.Copy(writer, chunkFile)
		chunkFile.Close()

		if err != nil {
			return 0, "", fmt.Errorf("failed to copy chunk %d: %w", i, err)
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
		return 0, "", fmt.Errorf("failed to flush output file: %w", err)
	}

	// Finalize SHA256 hash
	sha256Hash := hex.EncodeToString(hasher.Sum(nil))

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
		"sha256_hash", sha256Hash[:16]+"...", // Log first 16 chars for verification
	)

	return totalBytesWritten, sha256Hash, nil
}

// chunkSequenceReader streams the chunks of a partial upload in ascending
// order as one concatenated plaintext stream, opening one chunk file at a
// time (a MultiReader would need every chunk open at once — thousands of
// fds for large uploads).
type chunkSequenceReader struct {
	uploadDir   string
	uploadID    string
	totalChunks int
	nextChunk   int
	current     *os.File
}

func (r *chunkSequenceReader) Read(p []byte) (int, error) {
	for {
		if r.current == nil {
			if r.nextChunk >= r.totalChunks {
				return 0, io.EOF
			}
			f, err := os.Open(GetChunkPath(r.uploadDir, r.uploadID, r.nextChunk))
			if err != nil {
				return 0, fmt.Errorf("failed to open chunk %d: %w: %w", r.nextChunk, ErrChunkMissing, err)
			}
			r.current = f
			r.nextChunk++
		}

		n, err := r.current.Read(p)
		if err == io.EOF {
			r.current.Close()
			r.current = nil
			if n > 0 {
				return n, nil
			}
			continue // advance to next chunk
		}
		return n, err
	}
}

func (r *chunkSequenceReader) Close() error {
	if r.current != nil {
		err := r.current.Close()
		r.current = nil
		return err
	}
	return nil
}

// OpenChunksReader returns an io.ReadCloser that streams the chunks of a
// partial upload, in ascending order, as one concatenated plaintext stream —
// without assembling them into a file on disk first. Used to scan a chunked
// upload's content synchronously (ADR-015) before assembly/encryption.
//
// Chunks are only read here once the upload is frozen for assembly (status
// != "uploading" — see UploadChunkHandler), so it's safe to open them one at
// a time without racing a concurrent chunk write.
func OpenChunksReader(uploadDir, uploadID string, totalChunks int) io.ReadCloser {
	return &chunkSequenceReader{
		uploadDir:   uploadDir,
		uploadID:    uploadID,
		totalChunks: totalChunks,
	}
}

// countingReader counts bytes read through it.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// AssembleChunksEncrypted streams all chunks in order through SFSE2
// encryption directly into outputPath, computing the plaintext SHA-256 in
// the same pass. Compared to AssembleChunks followed by
// EncryptFileStreamingV2 (read chunks, write plaintext, read plaintext,
// write ciphertext = 4 full-file disk passes), this does a single read of
// the chunks and a single write of the encrypted file.
//
// totalSize must be the exact plaintext size; the SFSE2 writer enforces it
// and fails on any mismatch. Returns plaintext bytes processed and the
// hex-encoded plaintext SHA-256. On error the partially written output file
// is removed; chunks are never modified, so the operation is retryable.
func AssembleChunksEncrypted(uploadDir, uploadID string, totalChunks int, totalSize int64, outputPath, keyHex string, encFileID []byte) (int64, string, error) {
	startTime := time.Now()

	slog.Info("assembling chunks with single-pass encryption",
		"upload_id", uploadID,
		"total_chunks", totalChunks,
		"total_size", totalSize,
		"output_path", outputPath,
	)

	// Verify all chunks exist before starting assembly
	missing, err := GetMissingChunks(uploadDir, uploadID, totalChunks)
	if err != nil {
		return 0, "", fmt.Errorf("failed to check for missing chunks: %w", err)
	}
	if len(missing) > 0 {
		return 0, "", fmt.Errorf("cannot assemble: %d chunks missing (first missing: %d)", len(missing), missing[0])
	}

	chunkReader := &chunkSequenceReader{
		uploadDir:   uploadDir,
		uploadID:    uploadID,
		totalChunks: totalChunks,
	}
	defer func() {
		if err := chunkReader.Close(); err != nil {
			slog.Warn("failed to close chunk reader after assembly", "upload_id", uploadID, "error", err)
		}
	}()

	// Hash and count plaintext as the encryptor pulls it through
	hasher := sha256.New()
	counted := &countingReader{r: io.TeeReader(chunkReader, hasher)}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return 0, "", fmt.Errorf("failed to create output file: %w", err)
	}
	// Deferred cleanup (matching EncryptFileStreamingV2) so even a panic in
	// the encryptor can't leak the fd or leave partial ciphertext behind.
	var succeeded bool
	defer func() {
		outFile.Close()
		if !succeeded {
			os.Remove(outputPath)
		}
	}()

	// Small bufio buffer coalesces the SFSE2 header writes; the ~10MB
	// encrypted chunk writes bypass the buffer entirely.
	bufferedWriter := bufio.NewWriterSize(outFile, 64*1024)

	if err := EncryptFileStreamingV2FromReader(bufferedWriter, counted, keyHex, encFileID, totalSize); err != nil {
		return 0, "", fmt.Errorf("failed to encrypt during assembly: %w", err)
	}

	if err := bufferedWriter.Flush(); err != nil {
		return 0, "", fmt.Errorf("failed to flush output file: %w", err)
	}

	// NOTE: Deliberately NOT calling outFile.Sync(), matching AssembleChunks:
	// chunks stay intact until after the DB record is created, so a crash
	// here is recoverable by retrying the complete operation.
	if err := outFile.Close(); err != nil {
		return 0, "", fmt.Errorf("failed to close output file: %w", err)
	}
	succeeded = true

	sha256Hash := hex.EncodeToString(hasher.Sum(nil))

	duration := time.Since(startTime)
	throughputMBps := float64(counted.n) / duration.Seconds() / (1024 * 1024)

	slog.Info("single-pass encrypted assembly complete",
		"upload_id", uploadID,
		"total_chunks", totalChunks,
		"plaintext_bytes", counted.n,
		"duration_ms", duration.Milliseconds(),
		"throughput_mbps", fmt.Sprintf("%.1f", throughputMBps),
		"sha256_hash", sha256Hash[:16]+"...",
	)

	return counted.n, sha256Hash, nil
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

	// Count only chunk files (not directories or in-progress temp files)
	count := 0
	for _, entry := range entries {
		if _, ok := parseChunkFileName(entry.Name()); ok && !entry.IsDir() {
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
		if _, ok := parseChunkFileName(entry.Name()); ok && !entry.IsDir() {
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
			// Last chunk - calculate expected size (P1 security fix: prevent integer underflow)
			lastChunkSize := totalSize - (int64(totalChunks-1) * expectedChunkSize)
			// Validate that lastChunkSize is positive (detect corruption/manipulation)
			if lastChunkSize <= 0 {
				return fmt.Errorf("invalid last chunk size calculation (expected %d, got %d): totalSize=%d, totalChunks=%d, expectedChunkSize=%d - possible metadata corruption",
					lastChunkSize, size, totalSize, totalChunks, expectedChunkSize)
			}
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
		if chunkNum, ok := parseChunkFileName(entry.Name()); ok && !entry.IsDir() {
			chunkNumbers = append(chunkNumbers, chunkNum)
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

// HashFileSHA256 returns the hex SHA-256 of a file's contents, streaming it
// rather than reading it into memory.
func HashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
