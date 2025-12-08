// Package s3 implements encrypted storage for S3 using SFSE1 streaming encryption.
package s3

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"

	"github.com/fjmerc/safeshare/internal/storage"
)

const (
	// StreamEncryptionMagic is the file header for streaming encrypted files
	StreamEncryptionMagic = "SFSE1"
	// StreamEncryptionVersion is the version byte
	StreamEncryptionVersion = 0x01
	// DefaultEncryptionChunkSize is the default chunk size for streaming encryption (10MB)
	DefaultEncryptionChunkSize = 10 * 1024 * 1024
)

// S3EncryptedStorage wraps S3Storage and provides transparent encryption/decryption.
// Unlike the filesystem EncryptedStorage which requires FilePathProvider,
// this implementation handles encryption entirely in memory for S3 compatibility.
type S3EncryptedStorage struct {
	backend *S3Storage
	key     []byte
}

// NewS3EncryptedStorage creates a new S3EncryptedStorage wrapping the given S3 backend.
// keyHex must be a 64-character hexadecimal string (32 bytes for AES-256).
func NewS3EncryptedStorage(backend *S3Storage, keyHex string) (*S3EncryptedStorage, error) {
	if keyHex == "" {
		return nil, fmt.Errorf("encryption key is required")
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256, got %d", len(key))
	}

	return &S3EncryptedStorage{
		backend: backend,
		key:     key,
	}, nil
}

// Store encrypts data from the reader using SFSE1 streaming encryption and stores it in S3.
// The hash returned is the hash of the PLAINTEXT (for client verification).
func (es *S3EncryptedStorage) Store(ctx context.Context, filename string, reader io.Reader, size int64) (string, string, error) {
	// Create AES cipher and GCM mode
	block, err := aes.NewCipher(es.key)
	if err != nil {
		return "", "", storage.NewStorageError("Store", filename, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", storage.NewStorageError("Store", filename, err)
	}

	// Buffer for encrypted output
	var encryptedBuf bytes.Buffer

	// Write SFSE1 header
	encryptedBuf.Write([]byte(StreamEncryptionMagic))
	encryptedBuf.WriteByte(StreamEncryptionVersion)
	chunkSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(chunkSizeBytes, DefaultEncryptionChunkSize)
	encryptedBuf.Write(chunkSizeBytes)

	// Setup SHA256 hashing of plaintext
	hasher := sha256.New()

	// Process stream in chunks
	buffer := make([]byte, DefaultEncryptionChunkSize)
	for {
		n, err := io.ReadFull(reader, buffer)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return "", "", storage.NewStorageError("Store", filename, err)
		}

		if n == 0 {
			break
		}

		// Hash plaintext
		hasher.Write(buffer[:n])

		// Generate nonce for this chunk
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return "", "", storage.NewStorageError("Store", filename, err)
		}

		// Encrypt chunk (nonce is prepended to ciphertext)
		encrypted := gcm.Seal(nonce, nonce, buffer[:n], nil)
		encryptedBuf.Write(encrypted)

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}

	// Finalize hash (of plaintext)
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Upload encrypted data to S3 (using base Store which handles streaming)
	encryptedReader := bytes.NewReader(encryptedBuf.Bytes())
	_, _, err = es.backend.Store(ctx, filename, encryptedReader, int64(encryptedBuf.Len()))
	if err != nil {
		return "", "", err
	}

	slog.Debug("encrypted file stored in S3",
		"filename", filename,
		"original_size", size,
		"encrypted_size", encryptedBuf.Len(),
		"hash", hash[:16]+"...",
	)

	return filename, hash, nil
}

// Retrieve returns a reader for the decrypted file content from S3.
func (es *S3EncryptedStorage) Retrieve(ctx context.Context, filename string) (io.ReadCloser, error) {
	// Get encrypted data from S3
	encryptedReader, err := es.backend.Retrieve(ctx, filename)
	if err != nil {
		return nil, err
	}
	defer encryptedReader.Close()

	// Read encrypted data
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		return nil, storage.NewStorageError("Retrieve", filename, err)
	}

	// Check if file is encrypted (has SFSE1 header)
	if len(encryptedData) < len(StreamEncryptionMagic)+1+4 {
		// Too short to be encrypted, return as-is
		return io.NopCloser(bytes.NewReader(encryptedData)), nil
	}

	if string(encryptedData[:len(StreamEncryptionMagic)]) != StreamEncryptionMagic {
		// Not encrypted, return as-is
		return io.NopCloser(bytes.NewReader(encryptedData)), nil
	}

	// Decrypt the data
	decrypted, err := es.decryptData(encryptedData)
	if err != nil {
		return nil, storage.NewStorageError("Retrieve", filename, err)
	}

	return io.NopCloser(bytes.NewReader(decrypted)), nil
}

// decryptData decrypts SFSE1 encrypted data.
func (es *S3EncryptedStorage) decryptData(data []byte) ([]byte, error) {
	if len(data) < len(StreamEncryptionMagic)+1+4 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Validate header
	if string(data[:len(StreamEncryptionMagic)]) != StreamEncryptionMagic {
		return nil, fmt.Errorf("invalid magic header")
	}

	offset := len(StreamEncryptionMagic)
	if data[offset] != StreamEncryptionVersion {
		return nil, fmt.Errorf("unsupported version: %d", data[offset])
	}
	offset++

	chunkSize := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Create cipher
	block, err := aes.NewCipher(es.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Calculate encrypted chunk size
	encryptedChunkSize := int(chunkSize) + gcm.NonceSize() + gcm.Overhead()

	// Decrypt chunks
	var decrypted bytes.Buffer
	for offset < len(data) {
		end := offset + encryptedChunkSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[offset:end]
		if len(chunk) < gcm.NonceSize() {
			return nil, fmt.Errorf("chunk too small")
		}

		nonce := chunk[:gcm.NonceSize()]
		ciphertext := chunk[gcm.NonceSize():]

		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}

		decrypted.Write(plaintext)
		offset = end
	}

	return decrypted.Bytes(), nil
}

// Delete passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) Delete(ctx context.Context, filename string) error {
	return es.backend.Delete(ctx, filename)
}

// Exists passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) Exists(ctx context.Context, filename string) (bool, error) {
	return es.backend.Exists(ctx, filename)
}

// GetSize returns the encrypted size from S3.
// The handler should use the stored file_size from the database for the decrypted size.
func (es *S3EncryptedStorage) GetSize(ctx context.Context, filename string) (int64, error) {
	return es.backend.GetSize(ctx, filename)
}

// StreamRange decrypts and streams a byte range from an encrypted file.
// For S3 encrypted storage, we need to decrypt the relevant chunks.
func (es *S3EncryptedStorage) StreamRange(ctx context.Context, filename string, start, end int64, w io.Writer) (int64, error) {
	// Get encrypted data from S3
	encryptedReader, err := es.backend.Retrieve(ctx, filename)
	if err != nil {
		return 0, err
	}
	defer encryptedReader.Close()

	// Read encrypted data
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		return 0, storage.NewStorageError("StreamRange", filename, err)
	}

	// Check if file is encrypted
	if len(encryptedData) < len(StreamEncryptionMagic)+1+4 ||
		string(encryptedData[:len(StreamEncryptionMagic)]) != StreamEncryptionMagic {
		// Not encrypted, use backend's range streaming
		return es.backend.StreamRange(ctx, filename, start, end, w)
	}

	// Decrypt the data
	decrypted, err := es.decryptData(encryptedData)
	if err != nil {
		return 0, storage.NewStorageError("StreamRange", filename, err)
	}

	// Validate range
	if start < 0 || end < start || start >= int64(len(decrypted)) {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil,
			fmt.Sprintf("invalid range: start=%d, end=%d, size=%d", start, end, len(decrypted)))
	}

	// Adjust end if beyond file size
	if end >= int64(len(decrypted)) {
		end = int64(len(decrypted)) - 1
	}

	// Write the requested range
	written, err := w.Write(decrypted[start : end+1])
	return int64(written), err
}

// SaveChunk passes through to the underlying S3 backend.
// Chunks are stored unencrypted; encryption happens during assembly.
func (es *S3EncryptedStorage) SaveChunk(ctx context.Context, uploadID string, chunkNum int, data io.Reader, size int64) error {
	return es.backend.SaveChunk(ctx, uploadID, chunkNum, data, size)
}

// GetChunk passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) GetChunk(ctx context.Context, uploadID string, chunkNum int) (io.ReadCloser, error) {
	return es.backend.GetChunk(ctx, uploadID, chunkNum)
}

// DeleteChunks passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) DeleteChunks(ctx context.Context, uploadID string) error {
	return es.backend.DeleteChunks(ctx, uploadID)
}

// ChunkExists passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) ChunkExists(ctx context.Context, uploadID string, chunkNum int) (bool, int64, error) {
	return es.backend.ChunkExists(ctx, uploadID, chunkNum)
}

// AssembleChunks assembles chunks from S3 and encrypts the result.
// Returns the SHA256 hash of the plaintext.
func (es *S3EncryptedStorage) AssembleChunks(ctx context.Context, uploadID string, totalChunks int, destFilename string) (string, error) {
	// First, assemble chunks to a temporary filename (unencrypted)
	tempFilename := destFilename + ".plain.tmp"
	hash, err := es.backend.AssembleChunks(ctx, uploadID, totalChunks, tempFilename)
	if err != nil {
		return "", err
	}

	// Get the assembled plaintext
	plaintextReader, err := es.backend.Retrieve(ctx, tempFilename)
	if err != nil {
		es.backend.Delete(ctx, tempFilename) // Cleanup on error
		return "", err
	}

	// Read plaintext (we need it all for encryption)
	plaintextData, err := io.ReadAll(plaintextReader)
	plaintextReader.Close()
	if err != nil {
		es.backend.Delete(ctx, tempFilename)
		return "", storage.NewStorageError("AssembleChunks", tempFilename, err)
	}

	// Delete the temporary unencrypted file
	es.backend.Delete(ctx, tempFilename)

	// Encrypt and store to final destination
	_, _, err = es.Store(ctx, destFilename, bytes.NewReader(plaintextData), int64(len(plaintextData)))
	if err != nil {
		return "", err
	}

	slog.Debug("assembled file encrypted in S3",
		"dest_filename", destFilename,
		"original_size", len(plaintextData),
		"hash", hash[:16]+"...",
	)

	// Return the hash of the plaintext (computed during assembly)
	return hash, nil
}

// GetMissingChunks passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) GetMissingChunks(ctx context.Context, uploadID string, totalChunks int) ([]int, error) {
	return es.backend.GetMissingChunks(ctx, uploadID, totalChunks)
}

// GetChunkCount passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) GetChunkCount(ctx context.Context, uploadID string) (int, error) {
	return es.backend.GetChunkCount(ctx, uploadID)
}

// GetAvailableSpace passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) GetAvailableSpace(ctx context.Context) (int64, error) {
	return es.backend.GetAvailableSpace(ctx)
}

// GetUsedSpace passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) GetUsedSpace(ctx context.Context) (int64, error) {
	return es.backend.GetUsedSpace(ctx)
}

// HealthCheck passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) HealthCheck(ctx context.Context) error {
	return es.backend.HealthCheck(ctx)
}

// Verify S3EncryptedStorage implements StorageBackend
var _ storage.StorageBackend = (*S3EncryptedStorage)(nil)
