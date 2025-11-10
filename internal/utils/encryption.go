package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
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
	// StreamEncryptionMagic is the file header for streaming encrypted files
	StreamEncryptionMagic = "SFSE1"
	// StreamEncryptionVersion is the version byte
	StreamEncryptionVersion = 0x01
	// DefaultChunkSize is the default chunk size for streaming encryption (64MB)
	DefaultChunkSize = 64 * 1024 * 1024
)

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
		// Read chunk
		n, err := srcFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read chunk: %w", err)
		}
		if n == 0 {
			break
		}

		// Generate nonce for this chunk
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return fmt.Errorf("failed to generate nonce: %w", err)
		}

		// Encrypt chunk
		encrypted := gcm.Seal(nonce, nonce, buffer[:n], nil)

		// Write encrypted chunk (nonce + ciphertext + tag)
		if _, err := dstFile.Write(encrypted); err != nil {
			return fmt.Errorf("failed to write encrypted chunk: %w", err)
		}

		if err == io.EOF {
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

	// Process chunks
	// Each encrypted chunk has: nonce(12) + ciphertext + tag(16)
	// So encrypted chunk size is: chunkSize + 12 + 16
	encryptedChunkSize := int(chunkSize) + gcm.NonceSize() + gcm.Overhead()
	buffer := make([]byte, encryptedChunkSize)

	for {
		// Read encrypted chunk (may be partial on last chunk)
		n, err := srcFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read encrypted chunk: %w", err)
		}
		if n == 0 {
			break
		}

		// Extract nonce
		if n < gcm.NonceSize() {
			return fmt.Errorf("chunk too small: %d bytes", n)
		}
		nonce := buffer[:gcm.NonceSize()]
		ciphertext := buffer[gcm.NonceSize():n]

		// Decrypt chunk
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt chunk: %w", err)
		}

		// Write decrypted chunk
		if _, err := dstFile.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write decrypted chunk: %w", err)
		}

		if err == io.EOF {
			break
		}
	}

	return nil
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
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

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

	var totalWritten int64
	currentChunk := int64(0)

	for {
		// Read encrypted chunk (may be partial on last chunk)
		n, err := srcFile.Read(buffer)
		if err != nil && err != io.EOF {
			return totalWritten, fmt.Errorf("failed to read encrypted chunk: %w", err)
		}
		if n == 0 {
			break
		}

		// Only process chunks in our range
		if currentChunk >= startChunk && currentChunk <= endChunk {
			// Extract nonce
			if n < gcm.NonceSize() {
				return totalWritten, fmt.Errorf("chunk too small: %d bytes", n)
			}
			nonce := buffer[:gcm.NonceSize()]
			ciphertext := buffer[gcm.NonceSize():n]

			// Decrypt chunk
			plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				return totalWritten, fmt.Errorf("failed to decrypt chunk %d: %w", currentChunk, err)
			}

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
				written, err := writer.Write(plaintext[chunkStart:chunkEnd])
				if err != nil {
					return totalWritten, fmt.Errorf("failed to write decrypted data: %w", err)
				}
				totalWritten += int64(written)
			}
		} else if currentChunk > endChunk {
			// We've processed all chunks we need
			break
		}
		// If currentChunk < startChunk, skip this chunk (don't decrypt)

		currentChunk++

		if err == io.EOF {
			break
		}
	}

	return totalWritten, nil
}
