package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"time"
)

// EncryptFile encrypts data using AES-256-GCM
// keyHex must be a 64-character hexadecimal string (32 bytes)
// Returns: [nonce(12 bytes)][ciphertext][tag(16 bytes)]
func EncryptFile(plaintext []byte, keyHex string) ([]byte, error) {
	// Decode hex key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256, got %d", len(key))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode (Galois/Counter Mode provides authentication)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce (12 bytes for GCM)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	// Seal appends the ciphertext and tag to nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// DecryptFile decrypts data encrypted by EncryptFile
// keyHex must be the same 64-character hexadecimal string used for encryption
func DecryptFile(ciphertext []byte, keyHex string) ([]byte, error) {
	// Decode hex key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256, got %d", len(key))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum length (nonce + tag)
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertextWithoutNonce := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, nonce, ciphertextWithoutNonce, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong key or corrupted data): %w", err)
	}

	return plaintext, nil
}

// IsEncrypted checks if data appears to be encrypted
// This is a heuristic check - it verifies minimum length for encrypted data
func IsEncrypted(data []byte) bool {
	// Encrypted data must be at least: nonce(12) + tag(16) = 28 bytes
	// Plus at least 1 byte of actual encrypted content
	return len(data) >= 29
}

// IsEncryptionEnabled checks if encryption key is configured
func IsEncryptionEnabled(keyHex string) bool {
	return keyHex != "" && len(keyHex) == 64
}

const (
	// StreamEncryptionMagic is the file header for streaming encrypted files.
	// Shared across SFSE1 and SFSE2; the version byte at offset 5 is the format
	// discriminator. Kept as "SFSE1" intentionally so IsStreamEncrypted detects
	// every member of the family.
	StreamEncryptionMagic = "SFSE1"
	// StreamEncryptionVersion is the legacy version byte (SFSE1).
	StreamEncryptionVersion = 0x01
	// StreamEncryptionVersionV2 is the version byte for SFSE2 (ADR-011): per-chunk
	// AAD authenticates chunk identity (file id, chunk index, is-last flag) and
	// the header carries a total_plaintext_length trailer for length verification.
	StreamEncryptionVersionV2 byte = 0x02
	// DefaultChunkSize is the default chunk size for streaming encryption (10MB).
	// Reduced from 64MB to improve time-to-first-byte for HTTP Range requests
	// and prevent client timeouts during decryption.
	DefaultChunkSize = 10 * 1024 * 1024

	// sfse2HeaderSize = magic(5) + version(1) + chunk_size(4) + total_plaintext_len(8).
	// (SFSE1's 10-byte header is hardcoded inline at the legacy V1 Range reader.)
	sfse2HeaderSize = 18
	// SFSE2EncFileIDSize is the byte length of the AAD file identifier.
	SFSE2EncFileIDSize = 16
	// sfse2AADSize = enc_file_id(16) + chunk_index(8) + flags(1).
	sfse2AADSize = SFSE2EncFileIDSize + 8 + 1
	// sfse2FlagIsLast is bit 0 of the AAD flags byte.
	sfse2FlagIsLast byte = 0x01
)

// ErrUnsupportedSFSEVersion is returned when the version byte in an SFSE
// header is not a recognized value.
var ErrUnsupportedSFSEVersion = errors.New("unsupported SFSE version")

// ErrSFSE2IntegrityCheckFailed indicates an SFSE2 read produced output that
// fails a structural integrity check (plaintext length mismatch, missing
// is_last flag, SHA-256 mismatch against the DB-recorded checksum). Distinct
// from gcm.Open failures, which surface as wrapping errors with the per-chunk
// context.
var ErrSFSE2IntegrityCheckFailed = errors.New("SFSE2 integrity check failed")

// EncryptFileStreaming encrypts a file using chunked AES-256-GCM without loading entire file into memory.
// This prevents OOM issues for large files (>1GB).
//
// File format: [magic(5)][version(1)][chunk_size(4)][chunks...]
// Each chunk: [nonce(12)][encrypted_data][tag(16)]
//
// srcPath: path to plaintext file
// dstPath: path to write encrypted file
// keyHex: 64-character hex string (32 bytes for AES-256)
func EncryptFileStreaming(srcPath, dstPath, keyHex string) error {
	// Validate and decode key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes for AES-256, got %d", len(key))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Open source file
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// Create destination file
	dstFile, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dstFile.Close()

	// Write header: magic + version + chunk_size
	if _, err := dstFile.Write([]byte(StreamEncryptionMagic)); err != nil {
		return fmt.Errorf("failed to write magic: %w", err)
	}
	if _, err := dstFile.Write([]byte{StreamEncryptionVersion}); err != nil {
		return fmt.Errorf("failed to write version: %w", err)
	}
	chunkSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(chunkSizeBytes, DefaultChunkSize)
	if _, err := dstFile.Write(chunkSizeBytes); err != nil {
		return fmt.Errorf("failed to write chunk size: %w", err)
	}

	// Process file in chunks
	buffer := make([]byte, DefaultChunkSize)
	for {
		// Use io.ReadFull to ensure we read full chunks (or final short chunk)
		// This is consistent with EncryptFileStreamingFromReader behavior
		n, err := io.ReadFull(srcFile, buffer)

		// ReadFull returns ErrUnexpectedEOF if it read some data but hit EOF before filling buffer
		// This is expected and correct for the last chunk
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("failed to read chunk: %w", err)
		}

		// If no data was read, we're done
		if n == 0 {
			break
		}

		// Generate nonce for this chunk
		nonce := make([]byte, gcm.NonceSize())
		if _, nonceErr := io.ReadFull(rand.Reader, nonce); nonceErr != nil {
			return fmt.Errorf("failed to generate nonce: %w", nonceErr)
		}

		// Encrypt chunk (use buffer[:n] to handle partial final chunk)
		encrypted := gcm.Seal(nonce, nonce, buffer[:n], nil)

		// Write encrypted chunk (nonce + ciphertext + tag)
		if _, writeErr := dstFile.Write(encrypted); writeErr != nil {
			return fmt.Errorf("failed to write encrypted chunk: %w", writeErr)
		}

		// If we hit EOF or unexpected EOF, we're done
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}

	return nil
}

// EncryptFileStreamingFromReader encrypts data from an io.Reader using chunked AES-256-GCM without loading entire stream into memory.
// This is used for HTTP file uploads where the source is a request body stream.
//
// File format (SFSE1): [magic(5)][version(1)][chunk_size(4)][chunks...]
// Each chunk: [nonce(12)][encrypted_data][tag(16)]
//
// dst: destination writer (typically a file)
// src: source reader (typically HTTP request body)
// keyHex: 64-character hex string (32 bytes for AES-256)
func EncryptFileStreamingFromReader(dst io.Writer, src io.Reader, keyHex string) error {
	// Validate and decode key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes for AES-256, got %d", len(key))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Write header: magic + version + chunk_size
	if _, err := dst.Write([]byte(StreamEncryptionMagic)); err != nil {
		return fmt.Errorf("failed to write magic: %w", err)
	}
	if _, err := dst.Write([]byte{StreamEncryptionVersion}); err != nil {
		return fmt.Errorf("failed to write version: %w", err)
	}
	chunkSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(chunkSizeBytes, DefaultChunkSize)
	if _, err := dst.Write(chunkSizeBytes); err != nil {
		return fmt.Errorf("failed to write chunk size: %w", err)
	}

	// Process stream in chunks
	buffer := make([]byte, DefaultChunkSize)
	for {
		// Use io.ReadFull to ensure we read full chunks (or final short chunk)
		// This prevents io.MultiReader from creating artificial chunk boundaries
		// when combining multiple readers (e.g., MIME buffer + file upload)
		n, err := io.ReadFull(src, buffer)

		// ReadFull returns ErrUnexpectedEOF if it read some data but hit EOF before filling buffer
		// This is expected and correct for the last chunk
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("failed to read chunk: %w", err)
		}

		// If no data was read, we're done
		if n == 0 {
			break
		}

		// Generate nonce for this chunk
		nonce := make([]byte, gcm.NonceSize())
		if _, nonceErr := io.ReadFull(rand.Reader, nonce); nonceErr != nil {
			return fmt.Errorf("failed to generate nonce: %w", nonceErr)
		}

		// Encrypt chunk (use buffer[:n] to handle partial final chunk)
		encrypted := gcm.Seal(nonce, nonce, buffer[:n], nil)

		// Write encrypted chunk (nonce + ciphertext + tag)
		if _, writeErr := dst.Write(encrypted); writeErr != nil {
			return fmt.Errorf("failed to write encrypted chunk: %w", writeErr)
		}

		// If we hit EOF or unexpected EOF, we're done
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}

	return nil
}

// DecryptFileStreaming decrypts a streaming encrypted file without loading entire file into memory.
//
// srcPath: path to encrypted file (must have SFSE1 header)
// dstPath: path to write decrypted file
// keyHex: 64-character hex string (32 bytes for AES-256)
func DecryptFileStreaming(srcPath, dstPath, keyHex string) error {
	// Validate and decode key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes for AES-256, got %d", len(key))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Open source file
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// Read and validate header
	magic := make([]byte, len(StreamEncryptionMagic))
	if _, err := io.ReadFull(srcFile, magic); err != nil {
		return fmt.Errorf("failed to read magic: %w", err)
	}
	if string(magic) != StreamEncryptionMagic {
		return fmt.Errorf("invalid magic header: expected %s, got %s", StreamEncryptionMagic, string(magic))
	}

	versionByte := make([]byte, 1)
	if _, err := io.ReadFull(srcFile, versionByte); err != nil {
		return fmt.Errorf("failed to read version: %w", err)
	}
	if versionByte[0] != StreamEncryptionVersion {
		return fmt.Errorf("unsupported version: %d", versionByte[0])
	}

	chunkSizeBytes := make([]byte, 4)
	if _, err := io.ReadFull(srcFile, chunkSizeBytes); err != nil {
		return fmt.Errorf("failed to read chunk size: %w", err)
	}
	chunkSize := binary.LittleEndian.Uint32(chunkSizeBytes)

	// Create destination file
	dstFile, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dstFile.Close()

	// Each encrypted chunk has: nonce(12) + ciphertext + tag(16)
	// So encrypted chunk size is: chunkSize + 12 + 16
	encryptedChunkSize := int(chunkSize) + gcm.NonceSize() + gcm.Overhead()

	return decryptChunkStream(srcFile, dstFile, gcm, encryptedChunkSize)
}

// decryptChunkStream reads SFSE1 chunks from r using io.ReadFull (so a backing
// reader that returns short reads — NFS/FUSE/CIFS/wrapped — does not feed
// partial chunks into gcm.Open, which would surface as a spurious "failed to
// decrypt chunk" error on uncorrupted data). Treats io.ErrUnexpectedEOF as the
// legitimate short final chunk; io.EOF as clean termination.
//
// Do NOT regress this to bare r.Read — see SH-1.2 in the Security Hardening
// plan. The parallel range-aware loop in DecryptFileStreamingRange and the
// loops in storage/encrypted_storage.go follow the same invariants; keep them
// in sync.
func decryptChunkStream(r io.Reader, w io.Writer, gcm cipher.AEAD, encryptedChunkSize int) error {
	buffer := make([]byte, encryptedChunkSize)
	for {
		n, err := io.ReadFull(r, buffer)
		if err == io.EOF {
			return nil
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("failed to read encrypted chunk: %w", err)
		}
		// err is either nil (full chunk) or io.ErrUnexpectedEOF (final short chunk).
		if n < gcm.NonceSize() {
			return fmt.Errorf("chunk too small: %d bytes", n)
		}
		nonce := buffer[:gcm.NonceSize()]
		ciphertext := buffer[gcm.NonceSize():n]
		plaintext, decErr := gcm.Open(nil, nonce, ciphertext, nil)
		if decErr != nil {
			return fmt.Errorf("failed to decrypt chunk: %w", decErr)
		}
		if _, writeErr := w.Write(plaintext); writeErr != nil {
			return fmt.Errorf("failed to write decrypted chunk: %w", writeErr)
		}
		if err == io.ErrUnexpectedEOF {
			return nil
		}
	}
}

// IsStreamEncrypted checks if a file is encrypted with streaming encryption format.
// Returns true if file starts with SFSE1 magic header.
func IsStreamEncrypted(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	magic := make([]byte, len(StreamEncryptionMagic))
	n, err := file.Read(magic)
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("failed to read header: %w", err)
	}
	if n < len(StreamEncryptionMagic) {
		return false, nil
	}

	return string(magic) == StreamEncryptionMagic, nil
}

// DecryptFileStreamingRange decrypts a specific byte range from a streaming encrypted file.
// This is optimized for HTTP Range requests - only decrypts the chunks needed for the range.
//
// srcPath: path to encrypted file (must have SFSE1 header)
// writer: destination writer for decrypted data
// keyHex: 64-character hex string (32 bytes for AES-256)
// startByte: starting byte offset in the *decrypted* file (0-indexed)
// endByte: ending byte offset in the *decrypted* file (inclusive)
//
// Returns the number of bytes written to the writer.
func DecryptFileStreamingRange(srcPath string, writer io.Writer, keyHex string, startByte, endByte int64) (int64, error) {
	// Start timing for performance profiling
	funcStart := time.Now()

	// Validate range
	if startByte < 0 || endByte < startByte {
		return 0, fmt.Errorf("invalid range: start=%d, end=%d", startByte, endByte)
	}

	// Validate and decode key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return 0, fmt.Errorf("invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return 0, fmt.Errorf("key must be 32 bytes for AES-256, got %d", len(key))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Open source file
	openStart := time.Now()
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()
	slog.Debug("DecryptFileStreamingRange: file opened", "duration_ms", time.Since(openStart).Milliseconds())

	// Read and validate header
	magic := make([]byte, len(StreamEncryptionMagic))
	if _, err := io.ReadFull(srcFile, magic); err != nil {
		return 0, fmt.Errorf("failed to read magic: %w", err)
	}
	if string(magic) != StreamEncryptionMagic {
		return 0, fmt.Errorf("invalid magic header: expected %s, got %s", StreamEncryptionMagic, string(magic))
	}

	versionByte := make([]byte, 1)
	if _, err := io.ReadFull(srcFile, versionByte); err != nil {
		return 0, fmt.Errorf("failed to read version: %w", err)
	}
	if versionByte[0] != StreamEncryptionVersion {
		return 0, fmt.Errorf("unsupported version: %d", versionByte[0])
	}

	chunkSizeBytes := make([]byte, 4)
	if _, err := io.ReadFull(srcFile, chunkSizeBytes); err != nil {
		return 0, fmt.Errorf("failed to read chunk size: %w", err)
	}
	chunkSize := int64(binary.LittleEndian.Uint32(chunkSizeBytes))

	// Calculate which chunks we need to decrypt
	startChunk := startByte / chunkSize
	endChunk := endByte / chunkSize

	// Calculate offset within the first chunk
	offsetInFirstChunk := startByte % chunkSize

	// Each encrypted chunk has: nonce(12) + ciphertext + tag(16)
	encryptedChunkSize := int(chunkSize) + gcm.NonceSize() + gcm.Overhead()
	buffer := make([]byte, encryptedChunkSize)

	// PERFORMANCE OPTIMIZATION: Seek to the first chunk we need instead of reading from start
	// Header size: magic(5) + version(1) + chunk_size(4) = 10 bytes
	headerSize := int64(10)
	firstChunkOffset := headerSize + (startChunk * int64(encryptedChunkSize))

	seekStart := time.Now()
	if _, err := srcFile.Seek(firstChunkOffset, io.SeekStart); err != nil {
		return 0, fmt.Errorf("failed to seek to chunk %d: %w", startChunk, err)
	}
	slog.Debug("DecryptFileStreamingRange: seeked to first chunk",
		"chunk", startChunk,
		"offset_bytes", firstChunkOffset,
		"duration_ms", time.Since(seekStart).Milliseconds())

	var totalWritten int64
	var totalReadTime, totalDecryptTime, totalWriteTime time.Duration
	currentChunk := startChunk // Start from the first chunk we need, not 0

	// Range-aware decrypt loop: structurally mirrors decryptChunkStream but
	// keeps inline because of seek-pinning, partial-chunk windowing
	// (chunkStart/chunkEnd), and telemetry counters. Keep the io.ReadFull
	// invariant in sync with the helper — see SH-1.2.
	for currentChunk <= endChunk {
		// Read encrypted chunk via io.ReadFull so a short read from the
		// backing storage (NFS/FUSE/CIFS — or any wrapped reader in future
		// non-os.File backends) does not feed a partial chunk into gcm.Open
		// and surface as a spurious "failed to decrypt chunk" on intact
		// data. ErrUnexpectedEOF is the legitimate short final chunk; EOF
		// is clean termination.
		readStart := time.Now()
		n, err := io.ReadFull(srcFile, buffer)
		readDuration := time.Since(readStart)
		totalReadTime += readDuration

		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return totalWritten, fmt.Errorf("failed to read encrypted chunk: %w", err)
		}
		if n == 0 {
			break
		}

		slog.Debug("DecryptFileStreamingRange: chunk read",
			"chunk", currentChunk,
			"bytes_read", n,
			"duration_ms", readDuration.Milliseconds())

		// Extract nonce
		if n < gcm.NonceSize() {
			return totalWritten, fmt.Errorf("chunk too small: %d bytes", n)
		}
		nonce := buffer[:gcm.NonceSize()]
		ciphertext := buffer[gcm.NonceSize():n]

		// Decrypt chunk
		decryptStart := time.Now()
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		decryptDuration := time.Since(decryptStart)
		totalDecryptTime += decryptDuration

		if err != nil {
			return totalWritten, fmt.Errorf("failed to decrypt chunk %d: %w", currentChunk, err)
		}

		slog.Debug("DecryptFileStreamingRange: chunk decrypted",
			"chunk", currentChunk,
			"plaintext_bytes", len(plaintext),
			"duration_ms", decryptDuration.Milliseconds())

		// Determine what portion of this chunk to write
		var chunkStart, chunkEnd int64
		if currentChunk == startChunk {
			chunkStart = offsetInFirstChunk
		} else {
			chunkStart = 0
		}

		if currentChunk == endChunk {
			// Calculate offset within the last chunk
			chunkEnd = (endByte % chunkSize) + 1
			if chunkEnd > int64(len(plaintext)) {
				chunkEnd = int64(len(plaintext))
			}
		} else {
			chunkEnd = int64(len(plaintext))
		}

		// Write the relevant portion
		if chunkStart < chunkEnd {
			writeStart := time.Now()
			written, err := writer.Write(plaintext[chunkStart:chunkEnd])
			writeDuration := time.Since(writeStart)
			totalWriteTime += writeDuration

			if err != nil {
				return totalWritten, fmt.Errorf("failed to write decrypted data: %w", err)
			}
			totalWritten += int64(written)

			slog.Debug("DecryptFileStreamingRange: chunk written",
				"chunk", currentChunk,
				"bytes_written", written,
				"duration_ms", writeDuration.Milliseconds())
		}

		currentChunk++

		if err == io.EOF {
			break
		}
	}

	// Log overall performance summary
	totalDuration := time.Since(funcStart)
	chunksProcessed := (endChunk - startChunk) + 1

	slog.Info("DecryptFileStreamingRange: completed",
		"total_duration_ms", totalDuration.Milliseconds(),
		"read_time_ms", totalReadTime.Milliseconds(),
		"decrypt_time_ms", totalDecryptTime.Milliseconds(),
		"write_time_ms", totalWriteTime.Milliseconds(),
		"chunks_processed", chunksProcessed,
		"bytes_written", totalWritten,
		"chunk_size_mb", chunkSize/(1024*1024),
		"avg_read_ms_per_chunk", totalReadTime.Milliseconds()/chunksProcessed,
		"avg_decrypt_ms_per_chunk", totalDecryptTime.Milliseconds()/chunksProcessed,
		"throughput_mbps", float64(totalWritten)/(1024*1024)/totalDuration.Seconds())

	return totalWritten, nil
}

// ============================================================================
// SFSE2 (ADR-011): Per-chunk AAD-authenticated streaming AES-256-GCM
// ============================================================================
//
// SFSE2 wire format:
//
//   [magic(5)="SFSE1"][version(1)=0x02][chunk_size(4 LE)][total_plaintext_len(8 BE)]
//   then [chunk_0] ... [chunk_N] where each chunk = [nonce(12)][ciphertext][tag(16)]
//
// Header total = 18 bytes (V1 had 10). Encrypted chunk shape unchanged from
// V1 so Range seek math is the same.
//
// Per-chunk AAD = [enc_file_id(16)][chunk_index(8 BE)][flags(1)]
//   flags bit 0 = is_last_chunk; bits 1-7 reserved-must-be-zero.
//
// Threats defeated (vs SFSE1's nil-AAD calls):
//   - truncation: removing trailing chunks means the reader never observes
//     is_last==1 at the expected index; integrity check fails.
//   - reorder: chunk_index in AAD must match storage position; tag fails on
//     a swap.
//   - cross-file splice: enc_file_id binds chunks to a specific file; chunk
//     N of file B cannot be fed when decrypting file A.
//   - length forgery: total_plaintext_len in the header is sanity-checked
//     before decrypt and re-verified after.
//
// See SafeShare-Planning/06-Architecture-Decisions/ADR-011 for the full
// design rationale.

// GenerateEncFileID returns a fresh 16-byte random identifier suitable for
// binding into SFSE2 chunk AAD. Stored in files.enc_file_id (BLOB / BYTEA).
func GenerateEncFileID() ([]byte, error) {
	id := make([]byte, SFSE2EncFileIDSize)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		return nil, fmt.Errorf("failed to generate enc_file_id: %w", err)
	}
	return id, nil
}

// buildSFSE2AAD constructs the Additional Authenticated Data for an SFSE2
// chunk. encFileID must be exactly SFSE2EncFileIDSize bytes.
func buildSFSE2AAD(encFileID []byte, chunkIndex uint64, isLast bool) ([]byte, error) {
	if len(encFileID) != SFSE2EncFileIDSize {
		return nil, fmt.Errorf("enc_file_id must be %d bytes, got %d", SFSE2EncFileIDSize, len(encFileID))
	}
	aad := make([]byte, sfse2AADSize)
	copy(aad[0:SFSE2EncFileIDSize], encFileID)
	binary.BigEndian.PutUint64(aad[SFSE2EncFileIDSize:SFSE2EncFileIDSize+8], chunkIndex)
	if isLast {
		aad[SFSE2EncFileIDSize+8] = sfse2FlagIsLast
	}
	return aad, nil
}

// chunkCountFromPlaintextLen returns the number of SFSE2 chunks needed to
// cover `plaintextLen` bytes at `chunkSize`. Zero-byte files produce 0
// chunks; otherwise ceil(plaintextLen / chunkSize).
func chunkCountFromPlaintextLen(plaintextLen, chunkSize int64) int64 {
	if plaintextLen <= 0 {
		return 0
	}
	return (plaintextLen + chunkSize - 1) / chunkSize
}

// EncryptFileStreamingV2FromReader writes an SFSE2-formatted encrypted stream
// to dst, reading plaintext from src. plaintextLen must be the exact byte
// count of plaintext that will be read; the value is written into the SFSE2
// header and used to set the is_last AAD flag on the final chunk.
//
// encFileID must be exactly SFSE2EncFileIDSize bytes. Persist it in the DB
// alongside the file row — it is required to decrypt later.
func EncryptFileStreamingV2FromReader(dst io.Writer, src io.Reader, keyHex string, encFileID []byte, plaintextLen int64) error {
	if plaintextLen < 0 {
		return fmt.Errorf("plaintextLen must be non-negative, got %d", plaintextLen)
	}
	if len(encFileID) != SFSE2EncFileIDSize {
		return fmt.Errorf("enc_file_id must be %d bytes, got %d", SFSE2EncFileIDSize, len(encFileID))
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes for AES-256, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Write SFSE2 header: magic(5) + version(1) + chunk_size(4 LE) + total_plaintext_len(8 BE).
	if _, err := dst.Write([]byte(StreamEncryptionMagic)); err != nil {
		return fmt.Errorf("failed to write magic: %w", err)
	}
	if _, err := dst.Write([]byte{StreamEncryptionVersionV2}); err != nil {
		return fmt.Errorf("failed to write version: %w", err)
	}
	var chunkSizeBytes [4]byte
	binary.LittleEndian.PutUint32(chunkSizeBytes[:], DefaultChunkSize)
	if _, err := dst.Write(chunkSizeBytes[:]); err != nil {
		return fmt.Errorf("failed to write chunk size: %w", err)
	}
	var plaintextLenBytes [8]byte
	binary.BigEndian.PutUint64(plaintextLenBytes[:], uint64(plaintextLen))
	if _, err := dst.Write(plaintextLenBytes[:]); err != nil {
		return fmt.Errorf("failed to write total_plaintext_len: %w", err)
	}

	totalChunks := chunkCountFromPlaintextLen(plaintextLen, int64(DefaultChunkSize))
	if totalChunks == 0 {
		// Zero-byte file: header only, no chunks. Reader treats this as
		// valid empty plaintext; no AAD to compute.
		return nil
	}

	buffer := make([]byte, DefaultChunkSize)
	var totalRead int64
	for chunkIndex := int64(0); chunkIndex < totalChunks; chunkIndex++ {
		// io.ReadFull returns ErrUnexpectedEOF for a legitimate short final
		// chunk and never returns io.EOF when n > 0; any other error is fatal.
		n, readErr := io.ReadFull(src, buffer)
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return fmt.Errorf("failed to read chunk %d: %w", chunkIndex, readErr)
		}
		if n == 0 {
			return fmt.Errorf("plaintext shorter than declared length: read %d bytes, expected %d", totalRead, plaintextLen)
		}
		totalRead += int64(n)

		isLast := chunkIndex == totalChunks-1
		aad, err := buildSFSE2AAD(encFileID, uint64(chunkIndex), isLast)
		if err != nil {
			return err
		}

		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return fmt.Errorf("failed to generate nonce for chunk %d: %w", chunkIndex, err)
		}

		encrypted := gcm.Seal(nonce, nonce, buffer[:n], aad)
		if _, err := dst.Write(encrypted); err != nil {
			return fmt.Errorf("failed to write encrypted chunk %d: %w", chunkIndex, err)
		}

		if isLast {
			break
		}
	}

	if totalRead != plaintextLen {
		return fmt.Errorf("plaintext length mismatch: read %d bytes, header declared %d", totalRead, plaintextLen)
	}
	return nil
}

// EncryptFileStreamingV2 is a path-based wrapper around
// EncryptFileStreamingV2FromReader. It stats srcPath to obtain the plaintext
// length needed for the SFSE2 header.
func EncryptFileStreamingV2(srcPath, dstPath, keyHex string, encFileID []byte) error {
	info, err := os.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("failed to stat source: %w", err)
	}
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	var succeeded bool
	defer func() {
		dstFile.Close()
		if !succeeded {
			os.Remove(dstPath)
		}
	}()

	if err := EncryptFileStreamingV2FromReader(dstFile, srcFile, keyHex, encFileID, info.Size()); err != nil {
		return err
	}
	if err := dstFile.Close(); err != nil {
		return fmt.Errorf("failed to close destination file: %w", err)
	}
	succeeded = true
	return nil
}

// PeekSFSEVersion reads and returns the version byte from an SFSE-magic file
// at srcPath. Returns ErrUnsupportedSFSEVersion if the magic does not match.
// Used by callers that need to dispatch V1 vs V2 reader paths without
// re-implementing the header parser.
func PeekSFSEVersion(srcPath string) (byte, error) {
	f, err := os.Open(srcPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open source: %w", err)
	}
	defer f.Close()
	var hdr [6]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return 0, fmt.Errorf("failed to read SFSE header: %w", err)
	}
	if string(hdr[:5]) != StreamEncryptionMagic {
		return 0, fmt.Errorf("invalid SFSE magic")
	}
	return hdr[5], nil
}

// readSFSE2Header parses the SFSE2 header from r (assumed positioned at the
// magic byte). Returns chunkSize and totalPlaintextLen on success.
func readSFSE2Header(r io.Reader) (chunkSize int64, totalPlaintextLen int64, err error) {
	var hdr [sfse2HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, fmt.Errorf("failed to read SFSE2 header: %w", err)
	}
	if string(hdr[0:5]) != StreamEncryptionMagic {
		return 0, 0, fmt.Errorf("invalid SFSE magic")
	}
	if hdr[5] != StreamEncryptionVersionV2 {
		return 0, 0, fmt.Errorf("%w: expected v%d, got v%d", ErrUnsupportedSFSEVersion, StreamEncryptionVersionV2, hdr[5])
	}
	chunkSize = int64(binary.LittleEndian.Uint32(hdr[6:10]))
	if chunkSize <= 0 {
		return 0, 0, fmt.Errorf("invalid chunk_size %d", chunkSize)
	}
	totalPlaintextLen = int64(binary.BigEndian.Uint64(hdr[10:18]))
	if totalPlaintextLen < 0 {
		return 0, 0, fmt.Errorf("invalid total_plaintext_len %d", totalPlaintextLen)
	}
	return chunkSize, totalPlaintextLen, nil
}

// DecryptFileStreamingV2 decrypts an SFSE2 file at srcPath to dstPath.
// encFileID must be the 16-byte value bound at encrypt time (typically
// loaded from files.enc_file_id in the DB).
//
// When expectedSHA256Hex is non-empty, the running SHA-256 of decrypted
// plaintext is verified against it after the final chunk; mismatch returns
// ErrSFSE2IntegrityCheckFailed. Pass "" to skip (e.g. legacy files predating
// SHA-256 tracking).
//
// When expectedPlaintextLen >= 0, the SFSE2 header's total_plaintext_len is
// verified to match it before any decryption begins. This kills the
// zero-byte-collapse attack where a storage-write attacker truncates a file
// to header-only + rewrites total_plaintext_len=0 to make a non-empty file
// appear legitimately empty. Pass -1 to skip (e.g. when the caller does not
// know the expected length).
func DecryptFileStreamingV2(srcPath, dstPath, keyHex string, encFileID []byte, expectedSHA256Hex string, expectedPlaintextLen int64) error {
	if len(encFileID) != SFSE2EncFileIDSize {
		return fmt.Errorf("enc_file_id must be %d bytes, got %d", SFSE2EncFileIDSize, len(encFileID))
	}

	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	var succeeded bool
	defer func() {
		dstFile.Close()
		if !succeeded {
			os.Remove(dstPath)
		}
	}()

	// decryptSFSE2Stream already verifies the bytes-written count against
	// the header trailer; the explicit return value is informational here.
	if _, err := decryptSFSE2Stream(srcFile, dstFile, keyHex, encFileID, expectedSHA256Hex, expectedPlaintextLen, 0, -1); err != nil {
		return err
	}
	if err := dstFile.Close(); err != nil {
		return fmt.Errorf("failed to close destination file: %w", err)
	}
	succeeded = true
	return nil
}

// DecryptFileStreamingRangeV2 decrypts a specific plaintext byte range from
// an SFSE2 file. start..end are inclusive plaintext-byte offsets. end == -1
// means "to end of file".
//
// expectedSHA256Hex is verified only when the call covers the entire file
// (start=0 and end==total_plaintext_len-1); partial-range reads cannot
// reasonably verify a whole-file hash and pass through with the SHA check
// disabled. expectedPlaintextLen >= 0 always validates the header's
// total_plaintext_len even on partial reads (defends against header
// forgery / zero-byte collapse).
//
// Per ADR-011 §6: Range reads authenticate every touched chunk via AAD but
// cannot detect trailing-chunk truncation if the requested range does not
// reach the final chunk. SHA-256 verification is skipped for partial reads.
func DecryptFileStreamingRangeV2(srcPath string, w io.Writer, keyHex string, encFileID []byte, expectedSHA256Hex string, expectedPlaintextLen, startByte, endByte int64) (int64, error) {
	if len(encFileID) != SFSE2EncFileIDSize {
		return 0, fmt.Errorf("enc_file_id must be %d bytes, got %d", SFSE2EncFileIDSize, len(encFileID))
	}
	if startByte < 0 || (endByte >= 0 && endByte < startByte) {
		return 0, fmt.Errorf("invalid range: start=%d, end=%d", startByte, endByte)
	}

	srcFile, err := os.Open(srcPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	return decryptSFSE2Stream(srcFile, w, keyHex, encFileID, expectedSHA256Hex, expectedPlaintextLen, startByte, endByte)
}

// decryptSFSE2Stream is the SFSE2 decrypt core. It supports both full-file
// reads (start=0, end=-1, expectedSHA256Hex optional) and Range reads
// (positive start/end, SHA-256 skipped on partial). The function seeks within
// srcFile to the first needed chunk and decrypts only the chunks that overlap
// the requested range.
//
// expectedPlaintextLen >= 0 means the caller knows the plaintext length
// (typically from files.file_size in the DB); the header's total_plaintext_len
// is checked against it before any decryption begins, defeating the
// zero-byte-collapse attack and any other plaintext-length header forgery.
// Pass -1 to skip.
//
// Returns the number of bytes written to w. On any AAD failure, length
// mismatch, or SHA-256 mismatch, returns an error that wraps either
// gcm.Open's error or ErrSFSE2IntegrityCheckFailed.
func decryptSFSE2Stream(srcFile *os.File, w io.Writer, keyHex string, encFileID []byte, expectedSHA256Hex string, expectedPlaintextLen, startByte, endByte int64) (int64, error) {
	funcStart := time.Now()

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return 0, fmt.Errorf("invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return 0, fmt.Errorf("key must be 32 bytes for AES-256, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, fmt.Errorf("failed to create GCM: %w", err)
	}

	chunkSize, totalPlaintextLen, err := readSFSE2Header(srcFile)
	if err != nil {
		return 0, err
	}

	// Caller-supplied plaintext-length check. Defeats zero-byte-collapse and
	// other header-length forgery before the AAD even runs. Skipped when the
	// caller passes -1 (e.g. unit tests, admin tools without a DB reference).
	if expectedPlaintextLen >= 0 && totalPlaintextLen != expectedPlaintextLen {
		return 0, fmt.Errorf("%w: header total_plaintext_len=%d, caller expected=%d", ErrSFSE2IntegrityCheckFailed, totalPlaintextLen, expectedPlaintextLen)
	}

	// Sanity-check the encrypted file size against the header before decrypting.
	// Catches blunt truncation/append tampering before AAD does.
	encChunkSize := int64(chunkSize) + int64(gcm.NonceSize()) + int64(gcm.Overhead())
	totalChunks := chunkCountFromPlaintextLen(totalPlaintextLen, chunkSize)
	finalChunkPlainBytes := totalPlaintextLen
	if totalChunks > 0 {
		finalChunkPlainBytes = totalPlaintextLen - (totalChunks-1)*chunkSize
	}
	expectedFileSize := int64(sfse2HeaderSize)
	if totalChunks > 0 {
		expectedFileSize += (totalChunks - 1) * encChunkSize
		expectedFileSize += finalChunkPlainBytes + int64(gcm.NonceSize()) + int64(gcm.Overhead())
	}
	if fi, err := srcFile.Stat(); err == nil {
		if fi.Size() != expectedFileSize {
			return 0, fmt.Errorf("%w: file size %d, header expects %d", ErrSFSE2IntegrityCheckFailed, fi.Size(), expectedFileSize)
		}
	}

	// Determine effective endByte: full read if endByte < 0.
	fullRead := startByte == 0 && (endByte < 0 || endByte == totalPlaintextLen-1)
	if endByte < 0 {
		if totalPlaintextLen == 0 {
			return 0, nil // empty file, no chunks to read
		}
		endByte = totalPlaintextLen - 1
	}
	if totalPlaintextLen == 0 {
		return 0, nil
	}
	if startByte >= totalPlaintextLen {
		return 0, fmt.Errorf("start byte %d beyond plaintext length %d", startByte, totalPlaintextLen)
	}
	if endByte >= totalPlaintextLen {
		endByte = totalPlaintextLen - 1
	}

	startChunk := startByte / chunkSize
	endChunk := endByte / chunkSize
	offsetInFirstChunk := startByte % chunkSize

	// Seek to first needed chunk.
	firstChunkOffset := int64(sfse2HeaderSize) + startChunk*encChunkSize
	if _, err := srcFile.Seek(firstChunkOffset, io.SeekStart); err != nil {
		return 0, fmt.Errorf("failed to seek to chunk %d: %w", startChunk, err)
	}

	buffer := make([]byte, encChunkSize)
	var totalWritten int64
	var hasher *sha256Verifier
	if fullRead && expectedSHA256Hex != "" {
		hasher = newSHA256Verifier(expectedSHA256Hex)
	}

	for currentChunk := startChunk; currentChunk <= endChunk; currentChunk++ {
		isLast := currentChunk == totalChunks-1
		// For all but the final chunk, expect a full encChunkSize read.
		// For the final chunk, the encrypted size is finalChunkPlainBytes + nonce + tag.
		expectedReadSize := encChunkSize
		if isLast {
			expectedReadSize = finalChunkPlainBytes + int64(gcm.NonceSize()) + int64(gcm.Overhead())
		}
		if int64(len(buffer)) < expectedReadSize {
			buffer = make([]byte, expectedReadSize)
		}
		n, readErr := io.ReadFull(srcFile, buffer[:expectedReadSize])
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return totalWritten, fmt.Errorf("failed to read encrypted chunk %d: %w", currentChunk, readErr)
		}
		if int64(n) != expectedReadSize {
			return totalWritten, fmt.Errorf("%w: chunk %d read %d bytes, expected %d", ErrSFSE2IntegrityCheckFailed, currentChunk, n, expectedReadSize)
		}

		aad, err := buildSFSE2AAD(encFileID, uint64(currentChunk), isLast)
		if err != nil {
			return totalWritten, err
		}
		nonce := buffer[:gcm.NonceSize()]
		ciphertext := buffer[gcm.NonceSize():n]
		plaintext, decErr := gcm.Open(nil, nonce, ciphertext, aad)
		if decErr != nil {
			return totalWritten, fmt.Errorf("failed to decrypt chunk %d: %w", currentChunk, decErr)
		}

		// Slice the plaintext to the requested range.
		var chunkStart, chunkEnd int64
		if currentChunk == startChunk {
			chunkStart = offsetInFirstChunk
		}
		if currentChunk == endChunk {
			chunkEnd = (endByte % chunkSize) + 1
			if chunkEnd > int64(len(plaintext)) {
				chunkEnd = int64(len(plaintext))
			}
		} else {
			chunkEnd = int64(len(plaintext))
		}

		if chunkStart < chunkEnd {
			slice := plaintext[chunkStart:chunkEnd]
			written, err := w.Write(slice)
			if err != nil {
				return totalWritten, fmt.Errorf("failed to write decrypted data: %w", err)
			}
			totalWritten += int64(written)
			if hasher != nil {
				hasher.write(slice)
			}
		}
	}

	// Full-read integrity checks: length and (optional) SHA-256.
	if fullRead {
		if totalWritten != totalPlaintextLen {
			return totalWritten, fmt.Errorf("%w: wrote %d bytes, header declared %d", ErrSFSE2IntegrityCheckFailed, totalWritten, totalPlaintextLen)
		}
		if hasher != nil && !hasher.matches() {
			return totalWritten, fmt.Errorf("%w: SHA-256 mismatch", ErrSFSE2IntegrityCheckFailed)
		}
	}

	slog.Debug("SFSE2 decrypt complete",
		"duration_ms", time.Since(funcStart).Milliseconds(),
		"bytes_written", totalWritten,
		"full_read", fullRead,
		"start", startByte,
		"end", endByte,
	)
	return totalWritten, nil
}

// sha256Verifier hashes running plaintext bytes and compares to an expected
// hex-encoded digest. Used for SFSE2 post-decrypt integrity verification.
type sha256Verifier struct {
	hasher      hash.Hash
	expectedHex string
}

func newSHA256Verifier(expectedHex string) *sha256Verifier {
	return &sha256Verifier{hasher: sha256.New(), expectedHex: expectedHex}
}

func (v *sha256Verifier) write(p []byte) {
	_, _ = v.hasher.Write(p)
}

func (v *sha256Verifier) matches() bool {
	actual := hex.EncodeToString(v.hasher.Sum(nil))
	return actual == v.expectedHex
}

// DecryptFileStreamingAny is a version-aware dispatcher. It peeks the SFSE
// version byte and routes to the V1 or V2 reader. For V2 reads, encFileID
// must be the 16-byte value persisted at encrypt time; for V1 it is ignored
// (legacy files have no AAD). expectedSHA256Hex and expectedPlaintextLen are
// used only by V2 reads (V1 has no header length to validate).
func DecryptFileStreamingAny(srcPath, dstPath, keyHex string, encFileID []byte, expectedSHA256Hex string, expectedPlaintextLen int64) error {
	ver, err := PeekSFSEVersion(srcPath)
	if err != nil {
		return err
	}
	switch ver {
	case StreamEncryptionVersion:
		return DecryptFileStreaming(srcPath, dstPath, keyHex)
	case StreamEncryptionVersionV2:
		return DecryptFileStreamingV2(srcPath, dstPath, keyHex, encFileID, expectedSHA256Hex, expectedPlaintextLen)
	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedSFSEVersion, ver)
	}
}

// DecryptFileStreamingRangeAny is the Range counterpart to
// DecryptFileStreamingAny. Peeks the SFSE version byte and routes to the V1
// or V2 Range reader. expectedSHA256Hex / expectedPlaintextLen are forwarded
// to the V2 path only (V1 has no header length to validate). On the V2 path,
// callers should pass file.SHA256Hash when start=0 and end==fileSize-1 so
// the integrity check that ADR-011 §6 promises actually fires on full-file
// downloads served via the Range API.
func DecryptFileStreamingRangeAny(srcPath string, w io.Writer, keyHex string, encFileID []byte, expectedSHA256Hex string, expectedPlaintextLen, startByte, endByte int64) (int64, error) {
	ver, err := PeekSFSEVersion(srcPath)
	if err != nil {
		return 0, err
	}
	switch ver {
	case StreamEncryptionVersion:
		return DecryptFileStreamingRange(srcPath, w, keyHex, startByte, endByte)
	case StreamEncryptionVersionV2:
		return DecryptFileStreamingRangeV2(srcPath, w, keyHex, encFileID, expectedSHA256Hex, expectedPlaintextLen, startByte, endByte)
	default:
		return 0, fmt.Errorf("%w: %d", ErrUnsupportedSFSEVersion, ver)
	}
}
