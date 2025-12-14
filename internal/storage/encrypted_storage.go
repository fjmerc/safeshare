package storage

import (
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
	"os"
	"time"
)

const (
	// StreamEncryptionMagic is the file header for streaming encrypted files
	StreamEncryptionMagic = "SFSE1"
	// StreamEncryptionVersion is the version byte
	StreamEncryptionVersion = 0x01
	// DefaultEncryptionChunkSize is the default chunk size for streaming encryption (10MB)
	DefaultEncryptionChunkSize = 10 * 1024 * 1024
)

// FilePathProvider is an optional interface that storage backends can implement
// to provide file paths for operations that need direct file access.
type FilePathProvider interface {
	GetFilePath(filename string) string
	GetBaseDir() string
}

// EncryptedStorage wraps a StorageBackend and provides transparent encryption/decryption.
// It uses SFSE1 format for streaming encryption.
type EncryptedStorage struct {
	backend StorageBackend
	keyHex  string
	key     []byte
}

// NewEncryptedStorage creates a new EncryptedStorage wrapping the given backend.
// keyHex must be a 64-character hexadecimal string (32 bytes for AES-256).
func NewEncryptedStorage(backend StorageBackend, keyHex string) (*EncryptedStorage, error) {
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

	return &EncryptedStorage{
		backend: backend,
		keyHex:  keyHex,
		key:     key,
	}, nil
}

// Store encrypts data from the reader and stores it using SFSE1 streaming encryption.
// The hash returned is the hash of the PLAINTEXT (for client verification).
func (es *EncryptedStorage) Store(ctx context.Context, filename string, reader io.Reader, size int64) (string, string, error) {
	// Get file path from backend
	pathProvider, ok := es.backend.(FilePathProvider)
	if !ok {
		return "", "", fmt.Errorf("encrypted storage requires a backend that implements FilePathProvider")
	}

	filePath := pathProvider.GetFilePath(filename)
	tempPath := filePath + ".tmp"

	// Create temp file
	tempFile, err := os.Create(tempPath)
	if err != nil {
		return "", "", NewStorageError("Store", filename, err)
	}

	var succeeded bool
	defer func() {
		tempFile.Close()
		if !succeeded {
			os.Remove(tempPath)
		}
	}()

	// Create AES cipher and GCM mode
	block, err := aes.NewCipher(es.key)
	if err != nil {
		return "", "", NewStorageError("Store", filename, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", NewStorageError("Store", filename, err)
	}

	// Write SFSE1 header
	if _, err := tempFile.Write([]byte(StreamEncryptionMagic)); err != nil {
		return "", "", NewStorageError("Store", filename, err)
	}
	if _, err := tempFile.Write([]byte{StreamEncryptionVersion}); err != nil {
		return "", "", NewStorageError("Store", filename, err)
	}
	chunkSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(chunkSizeBytes, DefaultEncryptionChunkSize)
	if _, err := tempFile.Write(chunkSizeBytes); err != nil {
		return "", "", NewStorageError("Store", filename, err)
	}

	// Setup SHA256 hashing of plaintext
	hasher := sha256.New()

	// Process stream in chunks
	buffer := make([]byte, DefaultEncryptionChunkSize)
	for {
		n, err := io.ReadFull(reader, buffer)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return "", "", NewStorageError("Store", filename, err)
		}

		if n == 0 {
			break
		}

		// Hash plaintext
		hasher.Write(buffer[:n])

		// Generate nonce for this chunk
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return "", "", NewStorageError("Store", filename, err)
		}

		// Encrypt chunk
		encrypted := gcm.Seal(nonce, nonce, buffer[:n], nil)

		// Write encrypted chunk
		if _, err := tempFile.Write(encrypted); err != nil {
			return "", "", NewStorageError("Store", filename, err)
		}

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}

	// Finalize hash (of plaintext)
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Close and rename
	if err := tempFile.Close(); err != nil {
		return "", "", NewStorageError("Store", filename, err)
	}

	if err := os.Rename(tempPath, filePath); err != nil {
		return "", "", NewStorageError("Store", filename, err)
	}

	succeeded = true
	slog.Debug("encrypted file stored",
		"filename", filename,
		"original_size", size,
		"hash", hash[:16]+"...",
	)

	return filename, hash, nil
}

// Retrieve returns a reader for the decrypted file content.
// For SFSE1 encrypted files, this decrypts the entire file to a temp location.
// For non-encrypted files, returns the raw file.
func (es *EncryptedStorage) Retrieve(ctx context.Context, filename string) (io.ReadCloser, error) {
	// Get file path from backend
	pathProvider, ok := es.backend.(FilePathProvider)
	if !ok {
		return nil, fmt.Errorf("encrypted storage requires a backend that implements FilePathProvider")
	}

	filePath := pathProvider.GetFilePath(filename)

	// Check if file is encrypted
	isEncrypted, err := es.IsStreamEncrypted(filePath)
	if err != nil {
		return nil, NewStorageError("Retrieve", filename, err)
	}

	if !isEncrypted {
		// Not encrypted, delegate to backend
		return es.backend.Retrieve(ctx, filename)
	}

	// For encrypted files, we need to decrypt
	// Create a pipe for streaming decryption
	return newDecryptingReader(filePath, es.key)
}

// Delete passes through to the underlying backend.
func (es *EncryptedStorage) Delete(ctx context.Context, filename string) error {
	return es.backend.Delete(ctx, filename)
}

// Exists passes through to the underlying backend.
func (es *EncryptedStorage) Exists(ctx context.Context, filename string) (bool, error) {
	return es.backend.Exists(ctx, filename)
}

// GetSize returns the decrypted size (original file size) for encrypted files.
// This requires reading the file to count plaintext bytes from chunk structure.
func (es *EncryptedStorage) GetSize(ctx context.Context, filename string) (int64, error) {
	// For now, delegate to backend which returns the encrypted size
	// The handler will use the stored file_size from the database for the decrypted size
	return es.backend.GetSize(ctx, filename)
}

// StreamRange decrypts and streams a byte range from an encrypted file.
func (es *EncryptedStorage) StreamRange(ctx context.Context, filename string, start, end int64, w io.Writer) (int64, error) {
	pathProvider, ok := es.backend.(FilePathProvider)
	if !ok {
		return 0, fmt.Errorf("encrypted storage requires a backend that implements FilePathProvider")
	}

	filePath := pathProvider.GetFilePath(filename)

	// Check if file is encrypted
	isEncrypted, err := es.IsStreamEncrypted(filePath)
	if err != nil {
		return 0, NewStorageError("StreamRange", filename, err)
	}

	if !isEncrypted {
		// Not encrypted, delegate to backend
		return es.backend.StreamRange(ctx, filename, start, end, w)
	}

	// Decrypt the requested range using optimized chunk-based decryption
	return es.decryptRange(filePath, w, start, end)
}

// SaveChunk passes through to the underlying backend (chunks are stored unencrypted).
func (es *EncryptedStorage) SaveChunk(ctx context.Context, uploadID string, chunkNum int, data io.Reader, size int64) error {
	return es.backend.SaveChunk(ctx, uploadID, chunkNum, data, size)
}

// GetChunk passes through to the underlying backend.
func (es *EncryptedStorage) GetChunk(ctx context.Context, uploadID string, chunkNum int) (io.ReadCloser, error) {
	return es.backend.GetChunk(ctx, uploadID, chunkNum)
}

// DeleteChunks passes through to the underlying backend.
func (es *EncryptedStorage) DeleteChunks(ctx context.Context, uploadID string) error {
	return es.backend.DeleteChunks(ctx, uploadID)
}

// ChunkExists passes through to the underlying backend.
func (es *EncryptedStorage) ChunkExists(ctx context.Context, uploadID string, chunkNum int) (bool, int64, error) {
	return es.backend.ChunkExists(ctx, uploadID, chunkNum)
}

// AssembleChunks assembles chunks and then encrypts the result.
// To minimize plaintext exposure, assembly goes to a temp file which is then encrypted
// directly to the final destination.
func (es *EncryptedStorage) AssembleChunks(ctx context.Context, uploadID string, totalChunks int, destFilename string) (string, error) {
	pathProvider, ok := es.backend.(FilePathProvider)
	if !ok {
		return "", fmt.Errorf("encrypted storage requires a backend that implements FilePathProvider")
	}

	// Use a temp filename for plaintext assembly to minimize exposure
	tempPlaintextFilename := destFilename + ".plain.tmp"

	// Assemble chunks to temp plaintext file
	hash, err := es.backend.AssembleChunks(ctx, uploadID, totalChunks, tempPlaintextFilename)
	if err != nil {
		return "", err
	}

	tempPlaintextPath := pathProvider.GetFilePath(tempPlaintextFilename)
	finalPath := pathProvider.GetFilePath(destFilename)

	// Always clean up plaintext file
	defer os.Remove(tempPlaintextPath)

	// Get original size for logging
	originalInfo, _ := os.Stat(tempPlaintextPath)

	// Encrypt directly to final destination
	if err := es.encryptFile(tempPlaintextPath, finalPath); err != nil {
		os.Remove(finalPath)
		return "", NewStorageError("AssembleChunks", destFilename, err)
	}

	// Get encrypted size for logging
	encryptedInfo, _ := os.Stat(finalPath)

	if originalInfo != nil && encryptedInfo != nil {
		slog.Debug("assembled file encrypted",
			"dest_filename", destFilename,
			"original_size", originalInfo.Size(),
			"encrypted_size", encryptedInfo.Size(),
		)
	}

	// Return the hash of the plaintext (computed during assembly)
	return hash, nil
}

// GetMissingChunks passes through to the underlying backend.
func (es *EncryptedStorage) GetMissingChunks(ctx context.Context, uploadID string, totalChunks int) ([]int, error) {
	return es.backend.GetMissingChunks(ctx, uploadID, totalChunks)
}

// GetChunkCount passes through to the underlying backend.
func (es *EncryptedStorage) GetChunkCount(ctx context.Context, uploadID string) (int, error) {
	return es.backend.GetChunkCount(ctx, uploadID)
}

// GetAvailableSpace passes through to the underlying backend.
func (es *EncryptedStorage) GetAvailableSpace(ctx context.Context) (int64, error) {
	return es.backend.GetAvailableSpace(ctx)
}

// GetUsedSpace passes through to the underlying backend.
func (es *EncryptedStorage) GetUsedSpace(ctx context.Context) (int64, error) {
	return es.backend.GetUsedSpace(ctx)
}

// HealthCheck passes through to the underlying backend.
func (es *EncryptedStorage) HealthCheck(ctx context.Context) error {
	return es.backend.HealthCheck(ctx)
}

// IsStreamEncrypted checks if a file is encrypted with SFSE1 format.
func (es *EncryptedStorage) IsStreamEncrypted(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	magic := make([]byte, len(StreamEncryptionMagic))
	n, err := file.Read(magic)
	if err != nil && err != io.EOF {
		return false, err
	}
	if n < len(StreamEncryptionMagic) {
		return false, nil
	}

	return string(magic) == StreamEncryptionMagic, nil
}

// encryptFile encrypts a file using SFSE1 streaming encryption.
func (es *EncryptedStorage) encryptFile(srcPath, dstPath string) error {
	block, err := aes.NewCipher(es.key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Write header
	if _, err := dstFile.Write([]byte(StreamEncryptionMagic)); err != nil {
		return err
	}
	if _, err := dstFile.Write([]byte{StreamEncryptionVersion}); err != nil {
		return err
	}
	chunkSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(chunkSizeBytes, DefaultEncryptionChunkSize)
	if _, err := dstFile.Write(chunkSizeBytes); err != nil {
		return err
	}

	// Process file in chunks
	buffer := make([]byte, DefaultEncryptionChunkSize)
	for {
		n, err := io.ReadFull(srcFile, buffer)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}

		if n == 0 {
			break
		}

		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}

		encrypted := gcm.Seal(nonce, nonce, buffer[:n], nil)
		if _, err := dstFile.Write(encrypted); err != nil {
			return err
		}

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}

	return nil
}

// decryptRange decrypts a specific byte range from an encrypted file.
func (es *EncryptedStorage) decryptRange(filePath string, w io.Writer, startByte, endByte int64) (int64, error) {
	funcStart := time.Now()

	if startByte < 0 || endByte < startByte {
		return 0, fmt.Errorf("invalid range: start=%d, end=%d", startByte, endByte)
	}

	block, err := aes.NewCipher(es.key)
	if err != nil {
		return 0, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, err
	}

	srcFile, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer srcFile.Close()

	// Read and validate header
	magic := make([]byte, len(StreamEncryptionMagic))
	if _, err := io.ReadFull(srcFile, magic); err != nil {
		return 0, err
	}
	if string(magic) != StreamEncryptionMagic {
		return 0, fmt.Errorf("invalid magic header")
	}

	versionByte := make([]byte, 1)
	if _, err := io.ReadFull(srcFile, versionByte); err != nil {
		return 0, err
	}
	if versionByte[0] != StreamEncryptionVersion {
		return 0, fmt.Errorf("unsupported version: %d", versionByte[0])
	}

	chunkSizeBytes := make([]byte, 4)
	if _, err := io.ReadFull(srcFile, chunkSizeBytes); err != nil {
		return 0, err
	}
	chunkSize := int64(binary.LittleEndian.Uint32(chunkSizeBytes))

	// Calculate which chunks we need
	startChunk := startByte / chunkSize
	endChunk := endByte / chunkSize
	offsetInFirstChunk := startByte % chunkSize

	// Each encrypted chunk has: nonce(12) + ciphertext + tag(16)
	encryptedChunkSize := int(chunkSize) + gcm.NonceSize() + gcm.Overhead()
	buffer := make([]byte, encryptedChunkSize)

	// Seek to first needed chunk
	headerSize := int64(10) // magic(5) + version(1) + chunk_size(4)
	firstChunkOffset := headerSize + (startChunk * int64(encryptedChunkSize))
	if _, err := srcFile.Seek(firstChunkOffset, io.SeekStart); err != nil {
		return 0, err
	}

	var totalWritten int64
	currentChunk := startChunk

	for currentChunk <= endChunk {
		n, err := srcFile.Read(buffer)
		if err != nil && err != io.EOF {
			return totalWritten, err
		}
		if n == 0 {
			break
		}

		if n < gcm.NonceSize() {
			return totalWritten, fmt.Errorf("chunk too small: %d bytes", n)
		}

		nonce := buffer[:gcm.NonceSize()]
		ciphertext := buffer[gcm.NonceSize():n]

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
			chunkEnd = (endByte % chunkSize) + 1
			if chunkEnd > int64(len(plaintext)) {
				chunkEnd = int64(len(plaintext))
			}
		} else {
			chunkEnd = int64(len(plaintext))
		}

		if chunkStart < chunkEnd {
			written, err := w.Write(plaintext[chunkStart:chunkEnd])
			if err != nil {
				return totalWritten, err
			}
			totalWritten += int64(written)
		}

		currentChunk++

		if err == io.EOF {
			break
		}
	}

	slog.Debug("encrypted range decryption complete",
		"duration_ms", time.Since(funcStart).Milliseconds(),
		"bytes_written", totalWritten,
	)

	return totalWritten, nil
}

// GetFilePath returns the file path for a filename if the backend supports it.
func (es *EncryptedStorage) GetFilePath(filename string) string {
	if provider, ok := es.backend.(FilePathProvider); ok {
		return provider.GetFilePath(filename)
	}
	return ""
}

// GetBaseDir returns the base directory if the backend supports it.
func (es *EncryptedStorage) GetBaseDir() string {
	if provider, ok := es.backend.(FilePathProvider); ok {
		return provider.GetBaseDir()
	}
	return ""
}

// decryptingReader wraps an encrypted file and provides decrypted data.
type decryptingReader struct {
	file       *os.File
	gcm        cipher.AEAD
	chunkSize  uint32
	buffer     []byte
	plaintext  []byte
	offset     int
	encBufSize int
	eof        bool
	closed     bool
}

func newDecryptingReader(filePath string, key []byte) (*decryptingReader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	// Read and validate header
	magic := make([]byte, len(StreamEncryptionMagic))
	if _, err := io.ReadFull(file, magic); err != nil {
		file.Close()
		return nil, err
	}
	if string(magic) != StreamEncryptionMagic {
		file.Close()
		return nil, fmt.Errorf("invalid magic header")
	}

	versionByte := make([]byte, 1)
	if _, err := io.ReadFull(file, versionByte); err != nil {
		file.Close()
		return nil, err
	}
	if versionByte[0] != StreamEncryptionVersion {
		file.Close()
		return nil, fmt.Errorf("unsupported version: %d", versionByte[0])
	}

	chunkSizeBytes := make([]byte, 4)
	if _, err := io.ReadFull(file, chunkSizeBytes); err != nil {
		file.Close()
		return nil, err
	}
	chunkSize := binary.LittleEndian.Uint32(chunkSizeBytes)

	block, err := aes.NewCipher(key)
	if err != nil {
		file.Close()
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		file.Close()
		return nil, err
	}

	encBufSize := int(chunkSize) + gcm.NonceSize() + gcm.Overhead()

	return &decryptingReader{
		file:       file,
		gcm:        gcm,
		chunkSize:  chunkSize,
		buffer:     make([]byte, encBufSize),
		encBufSize: encBufSize,
	}, nil
}

func (dr *decryptingReader) Read(p []byte) (int, error) {
	// Check if reader has been closed
	if dr.closed {
		return 0, fmt.Errorf("read on closed decryptingReader")
	}

	// If we have buffered plaintext, return from there first
	if dr.offset < len(dr.plaintext) {
		n := copy(p, dr.plaintext[dr.offset:])
		dr.offset += n
		return n, nil
	}

	if dr.eof {
		return 0, io.EOF
	}

	// Read next encrypted chunk
	n, err := dr.file.Read(dr.buffer)
	if err != nil && err != io.EOF {
		return 0, err
	}
	if n == 0 {
		dr.eof = true
		return 0, io.EOF
	}

	if n < dr.gcm.NonceSize() {
		return 0, fmt.Errorf("chunk too small")
	}

	nonce := dr.buffer[:dr.gcm.NonceSize()]
	ciphertext := dr.buffer[dr.gcm.NonceSize():n]

	// Reuse plaintext buffer if it has sufficient capacity to reduce allocations
	var plaintext []byte
	if cap(dr.plaintext) >= int(dr.chunkSize) {
		plaintext, err = dr.gcm.Open(dr.plaintext[:0], nonce, ciphertext, nil)
	} else {
		plaintext, err = dr.gcm.Open(nil, nonce, ciphertext, nil)
	}
	if err != nil {
		return 0, err
	}

	dr.plaintext = plaintext
	dr.offset = 0

	copied := copy(p, dr.plaintext)
	dr.offset = copied

	if err == io.EOF {
		dr.eof = true
	}

	return copied, nil
}

func (dr *decryptingReader) Close() error {
	// Idempotent - safe to call multiple times
	if dr.closed {
		return nil
	}
	dr.closed = true

	// Release buffer memory to help GC
	dr.buffer = nil
	dr.plaintext = nil
	dr.gcm = nil

	if dr.file != nil {
		return dr.file.Close()
	}
	return nil
}
