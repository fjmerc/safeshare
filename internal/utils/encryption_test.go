package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"
)

// TestEncryptionSingleChunk tests that small files produce only one chunk
func TestEncryptionSingleChunk(t *testing.T) {
	// Create a 64-character hex key (32 bytes)
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Test with a small file (1539 bytes - matching production issue)
	testData := bytes.Repeat([]byte("A"), 1539)

	// Encrypt the data
	var encryptedBuf bytes.Buffer
	err := EncryptFileStreamingFromReader(&encryptedBuf, bytes.NewReader(testData), testKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	encryptedBytes := encryptedBuf.Bytes()

	t.Logf("Original size: %d bytes", len(testData))
	t.Logf("Encrypted size: %d bytes", len(encryptedBytes))

	// Expected encrypted size:
	// Header: 10 bytes (magic(5) + version(1) + chunk_size(4))
	// Chunk 1: 12 (nonce) + 1539 (data) + 16 (tag) = 1567 bytes
	// Total: 10 + 1567 = 1577 bytes
	expectedSize := 10 + 12 + 1539 + 16
	t.Logf("Expected size: %d bytes", expectedSize)

	if len(encryptedBytes) != expectedSize {
		t.Errorf("FAIL: Encrypted size is %d bytes, expected %d bytes (difference: %d bytes)",
			len(encryptedBytes), expectedSize, len(encryptedBytes)-expectedSize)

		// Analyze the extra bytes
		if len(encryptedBytes) > expectedSize {
			extraBytes := len(encryptedBytes) - expectedSize
			if extraBytes == 28 {
				t.Logf("Extra 28 bytes suggests empty chunk: 12 (nonce) + 0 (data) + 16 (tag)")
			} else if extraBytes == 31 {
				t.Logf("Extra 31 bytes suggests tiny chunk: 12 (nonce) + 3 (data) + 16 (tag)")
				t.Logf("This indicates io.MultiReader split the data across chunk boundaries")
			}
		}
	} else {
		t.Logf("SUCCESS: Encrypted size is correct - single chunk as expected")
	}

	// Decrypt and verify
	decryptedData, err := decryptStreamingData(encryptedBytes, testKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(testData, decryptedData) {
		t.Errorf("Decrypted data does not match original (got %d bytes, expected %d bytes)",
			len(decryptedData), len(testData))
	} else {
		t.Logf("SUCCESS: Decryption verified correctly")
	}
}

// TestEncryptionWithMultiReader tests the exact scenario from upload.go
func TestEncryptionWithMultiReader(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Simulate the MIME detection buffer scenario from upload.go line 234
	mimeBuffer := bytes.Repeat([]byte("M"), 1536) // 1536 bytes (matches MIME buffer size)
	remainingData := []byte("ABC")                // 3 bytes after MIME buffer

	// Total: 1539 bytes (matching production file size)
	fullReader := io.MultiReader(bytes.NewReader(mimeBuffer), bytes.NewReader(remainingData))

	var encryptedBuf bytes.Buffer
	err := EncryptFileStreamingFromReader(&encryptedBuf, fullReader, testKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	encryptedBytes := encryptedBuf.Bytes()
	t.Logf("Encrypted size with MultiReader: %d bytes", len(encryptedBytes))

	// Expected: 10 (header) + 12 + 1539 + 16 = 1577 bytes (ONE chunk)
	expectedSize := 1577
	if len(encryptedBytes) != expectedSize {
		t.Errorf("FAIL: MultiReader scenario produced %d bytes, expected %d (difference: %d bytes)",
			len(encryptedBytes), expectedSize, len(encryptedBytes)-expectedSize)
		t.Logf("This indicates io.MultiReader caused chunk splitting - the fix did not work")
	} else {
		t.Logf("SUCCESS: MultiReader correctly produced single chunk")
	}

	// Verify decryption works
	expectedData := append(mimeBuffer, remainingData...)
	decryptedData, err := decryptStreamingData(encryptedBytes, testKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(expectedData, decryptedData) {
		t.Errorf("Decrypted data does not match original")
	} else {
		t.Logf("SUCCESS: MultiReader data decrypted correctly")
	}
}

// TestEncryptFile_Success tests basic encryption functionality
func TestEncryptFile_Success(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	plaintext := []byte("Hello, World! This is a test message.")

	encrypted, err := EncryptFile(plaintext, testKey)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	// Verify encrypted data is longer (nonce + ciphertext + tag)
	if len(encrypted) <= len(plaintext) {
		t.Errorf("Encrypted data should be longer than plaintext")
	}

	// Verify it's not the same as plaintext
	if bytes.Equal(encrypted, plaintext) {
		t.Errorf("Encrypted data should not equal plaintext")
	}
}

// TestEncryptFile_InvalidKey tests encryption with invalid keys
func TestEncryptFile_InvalidKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr string
	}{
		{
			name:    "non-hex key",
			key:     "invalid-hex-key-with-dashes-and-letters",
			wantErr: "invalid hex key",
		},
		{
			name:    "wrong length key",
			key:     "0123456789abcdef", // Only 16 chars (8 bytes)
			wantErr: "key must be 32 bytes",
		},
		{
			name:    "empty key",
			key:     "",
			wantErr: "key must be 32 bytes", // Empty string decodes to 0 bytes
		},
	}

	plaintext := []byte("test data")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptFile(plaintext, tt.key)
			if err == nil {
				t.Fatalf("Expected error containing '%s', got nil", tt.wantErr)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tt.wantErr)) {
				t.Errorf("Expected error containing '%s', got: %v", tt.wantErr, err)
			}
		})
	}
}

// TestEncryptFile_EmptyData tests encryption of empty data
func TestEncryptFile_EmptyData(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	plaintext := []byte{}

	encrypted, err := EncryptFile(plaintext, testKey)
	if err != nil {
		t.Fatalf("EncryptFile failed on empty data: %v", err)
	}

	// Should still have nonce + tag even with no data
	if len(encrypted) == 0 {
		t.Errorf("Encrypted empty data should not be empty (needs nonce + tag)")
	}
}

// TestDecryptFile_Success tests basic decryption functionality
func TestDecryptFile_Success(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	originalPlaintext := []byte("Secret message for decryption test")

	// Encrypt first
	encrypted, err := EncryptFile(originalPlaintext, testKey)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	// Decrypt
	decrypted, err := DecryptFile(encrypted, testKey)
	if err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	// Verify decryption matches original
	if !bytes.Equal(decrypted, originalPlaintext) {
		t.Errorf("Decrypted data does not match original.\nExpected: %s\nGot: %s",
			string(originalPlaintext), string(decrypted))
	}
}

// TestDecryptFile_WrongKey tests decryption with wrong key
func TestDecryptFile_WrongKey(t *testing.T) {
	correctKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	wrongKey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	plaintext := []byte("Test data")

	// Encrypt with correct key
	encrypted, err := EncryptFile(plaintext, correctKey)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	// Try to decrypt with wrong key
	_, err = DecryptFile(encrypted, wrongKey)
	if err == nil {
		t.Fatal("Expected decryption to fail with wrong key, but it succeeded")
	}

	if !bytes.Contains([]byte(err.Error()), []byte("decryption failed")) {
		t.Errorf("Expected 'decryption failed' error, got: %v", err)
	}
}

// TestDecryptFile_CorruptedData tests decryption with corrupted ciphertext
func TestDecryptFile_CorruptedData(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	plaintext := []byte("Original data before corruption")

	// Encrypt
	encrypted, err := EncryptFile(plaintext, testKey)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	// Corrupt a byte in the middle
	if len(encrypted) > 20 {
		encrypted[20] ^= 0xFF // Flip all bits
	}

	// Try to decrypt
	_, err = DecryptFile(encrypted, testKey)
	if err == nil {
		t.Fatal("Expected decryption to fail with corrupted data, but it succeeded")
	}
}

// TestDecryptFile_TooShort tests decryption with data too short
func TestDecryptFile_TooShort(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Data shorter than nonce size
	tooShort := []byte{0x01, 0x02, 0x03}

	_, err := DecryptFile(tooShort, testKey)
	if err == nil {
		t.Fatal("Expected error for data too short, got nil")
	}

	if !bytes.Contains([]byte(err.Error()), []byte("too short")) {
		t.Errorf("Expected 'too short' error, got: %v", err)
	}
}

// TestIsEncrypted tests encrypted data detection
func TestIsEncrypted(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "encrypted data",
			data:     nil, // Will be set to actual encrypted data
			expected: true,
		},
		{
			name:     "plaintext data",
			data:     []byte("This is plaintext"),
			expected: false,
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: false,
		},
		{
			name:     "very short data",
			data:     []byte{0x01, 0x02},
			expected: false,
		},
	}

	// Generate actual encrypted data for first test
	encrypted, err := EncryptFile([]byte("test"), testKey)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}
	tests[0].data = encrypted

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsEncrypted(tt.data)
			if result != tt.expected {
				t.Errorf("IsEncrypted() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestEncryptDecryptRoundTrip tests full encryption/decryption cycle
func TestEncryptDecryptRoundTrip(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	testCases := []struct {
		name string
		data []byte
	}{
		{"small text", []byte("Hello")},
		{"medium text", []byte(bytes.Repeat([]byte("A"), 1000))},
		{"binary data", []byte{0x00, 0xFF, 0x01, 0xFE, 0x02, 0xFD}},
		{"empty", []byte{}},
		{"unicode", []byte("Hello 世界 🌍")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := EncryptFile(tc.data, testKey)
			if err != nil {
				t.Fatalf("EncryptFile failed: %v", err)
			}

			// Decrypt
			decrypted, err := DecryptFile(encrypted, testKey)
			if err != nil {
				t.Fatalf("DecryptFile failed: %v", err)
			}

			// Verify
			if !bytes.Equal(decrypted, tc.data) {
				t.Errorf("Round trip failed. Original: %v, Decrypted: %v", tc.data, decrypted)
			}
		})
	}
}

// TestIsEncryptionEnabled tests encryption enabled detection
func TestIsEncryptionEnabled(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "valid key",
			key:      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			expected: true,
		},
		{
			name:     "empty key",
			key:      "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsEncryptionEnabled(tt.key)
			if result != tt.expected {
				t.Errorf("IsEncryptionEnabled() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestIsStreamEncrypted tests detection of streaming encrypted files
func TestIsStreamEncrypted(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name     string
		setup    func(t *testing.T) string // Returns path to test file
		expected bool
		wantErr  bool
	}{
		{
			name: "stream encrypted file",
			setup: func(t *testing.T) string {
				t.Helper()
				tmpDir := t.TempDir()
				srcPath := tmpDir + "/plaintext.txt"
				dstPath := tmpDir + "/encrypted.bin"

				// Create plaintext file
				if err := os.WriteFile(srcPath, []byte("test data"), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}

				// Encrypt it using streaming encryption
				if err := EncryptFileStreaming(srcPath, dstPath, testKey); err != nil {
					t.Fatalf("Failed to encrypt file: %v", err)
				}

				return dstPath
			},
			expected: true,
			wantErr:  false,
		},
		{
			name: "plaintext file",
			setup: func(t *testing.T) string {
				t.Helper()
				tmpDir := t.TempDir()
				filePath := tmpDir + "/plaintext.txt"

				if err := os.WriteFile(filePath, []byte("plain text content"), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}

				return filePath
			},
			expected: false,
			wantErr:  false,
		},
		{
			name: "empty file",
			setup: func(t *testing.T) string {
				t.Helper()
				tmpDir := t.TempDir()
				filePath := tmpDir + "/empty.txt"

				if err := os.WriteFile(filePath, []byte{}, 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}

				return filePath
			},
			expected: false,
			wantErr:  false,
		},
		{
			name: "short file",
			setup: func(t *testing.T) string {
				t.Helper()
				tmpDir := t.TempDir()
				filePath := tmpDir + "/short.txt"

				// Only 3 bytes, shorter than magic header
				if err := os.WriteFile(filePath, []byte("abc"), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}

				return filePath
			},
			expected: false,
			wantErr:  false,
		},
		{
			name: "nonexistent file",
			setup: func(t *testing.T) string {
				t.Helper()
				return "/tmp/this-file-does-not-exist.txt"
			},
			expected: false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setup(t)

			result, err := IsStreamEncrypted(filePath)

			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("IsStreamEncrypted() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestDecryptFileStreamingRange tests range decryption for HTTP range requests
func TestDecryptFileStreamingRange(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Create a test file with known content
	tmpDir := t.TempDir()
	srcPath := tmpDir + "/plaintext.txt"
	encPath := tmpDir + "/encrypted.bin"

	// Create plaintext with easily verifiable content (10KB)
	plaintext := bytes.Repeat([]byte("0123456789"), 1024) // 10KB
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Encrypt the file
	if err := EncryptFileStreaming(srcPath, encPath, testKey); err != nil {
		t.Fatalf("Failed to encrypt file: %v", err)
	}

	tests := []struct {
		name      string
		startByte int64
		endByte   int64
		expected  []byte
		wantErr   bool
	}{
		{
			name:      "first 10 bytes",
			startByte: 0,
			endByte:   9,
			expected:  []byte("0123456789"),
			wantErr:   false,
		},
		{
			name:      "middle range",
			startByte: 100,
			endByte:   109,
			expected:  plaintext[100:110],
			wantErr:   false,
		},
		{
			name:      "last 10 bytes",
			startByte: int64(len(plaintext) - 10),
			endByte:   int64(len(plaintext) - 1),
			expected:  plaintext[len(plaintext)-10:],
			wantErr:   false,
		},
		{
			name:      "single byte",
			startByte: 50,
			endByte:   50,
			expected:  plaintext[50:51],
			wantErr:   false,
		},
		{
			name:      "full file",
			startByte: 0,
			endByte:   int64(len(plaintext) - 1),
			expected:  plaintext,
			wantErr:   false,
		},
		{
			name:      "invalid range - start > end",
			startByte: 100,
			endByte:   50,
			expected:  nil,
			wantErr:   true,
		},
		{
			name:      "invalid range - negative start",
			startByte: -1,
			endByte:   10,
			expected:  nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			n, err := DecryptFileStreamingRange(encPath, &buf, testKey, tt.startByte, tt.endByte)

			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify bytes written
			expectedLen := int64(len(tt.expected))
			if n != expectedLen {
				t.Errorf("Expected %d bytes written, got %d", expectedLen, n)
			}

			// Verify content
			if !bytes.Equal(buf.Bytes(), tt.expected) {
				t.Errorf("Content mismatch.\nExpected: %q\nGot: %q", tt.expected, buf.Bytes())
			}
		})
	}
}

// TestDecryptFileStreamingRange_InvalidKey tests range decryption with wrong key
func TestDecryptFileStreamingRange_InvalidKey(t *testing.T) {
	correctKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	wrongKey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	tmpDir := t.TempDir()
	srcPath := tmpDir + "/plaintext.txt"
	encPath := tmpDir + "/encrypted.bin"

	// Create and encrypt test file
	plaintext := []byte("test data")
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	if err := EncryptFileStreaming(srcPath, encPath, correctKey); err != nil {
		t.Fatalf("Failed to encrypt file: %v", err)
	}

	// Try to decrypt with wrong key
	var buf bytes.Buffer
	_, err := DecryptFileStreamingRange(encPath, &buf, wrongKey, 0, int64(len(plaintext)-1))
	if err == nil {
		t.Fatal("Expected error with wrong key, got nil")
	}
}

// TestDecryptFileStreamingRange_NotEncrypted tests range decryption on plaintext file
func TestDecryptFileStreamingRange_NotEncrypted(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tmpDir := t.TempDir()
	plainPath := tmpDir + "/plaintext.txt"

	// Create plaintext file (not encrypted)
	if err := os.WriteFile(plainPath, []byte("plain text"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Try to decrypt as if it were encrypted
	var buf bytes.Buffer
	_, err := DecryptFileStreamingRange(plainPath, &buf, testKey, 0, 9)
	if err == nil {
		t.Fatal("Expected error for non-encrypted file, got nil")
	}

	if !bytes.Contains([]byte(err.Error()), []byte("invalid magic header")) {
		t.Errorf("Expected 'invalid magic header' error, got: %v", err)
	}
}

// decryptStreamingData decrypts SFSE1 format data for testing
func decryptStreamingData(encryptedData []byte, keyHex string) ([]byte, error) {
	// Decode key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %w", err)
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Read header
	if len(encryptedData) < 10 {
		return nil, fmt.Errorf("data too short for header")
	}

	magic := string(encryptedData[0:5])
	if magic != StreamEncryptionMagic {
		return nil, fmt.Errorf("invalid magic: %s", magic)
	}

	version := encryptedData[5]
	if version != StreamEncryptionVersion {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	chunkSize := binary.LittleEndian.Uint32(encryptedData[6:10])

	// Decrypt chunks
	var result bytes.Buffer
	offset := 10

	for offset < len(encryptedData) {
		// Read chunk (variable size)
		remaining := len(encryptedData) - offset
		if remaining < gcm.NonceSize() {
			return nil, fmt.Errorf("incomplete chunk at offset %d", offset)
		}

		nonce := encryptedData[offset : offset+gcm.NonceSize()]
		offset += gcm.NonceSize()

		// Find ciphertext (rest of data or up to next expected chunk boundary)
		maxCiphertextSize := int(chunkSize) + gcm.Overhead()
		ciphertextEnd := offset + maxCiphertextSize
		if ciphertextEnd > len(encryptedData) {
			ciphertextEnd = len(encryptedData)
		}

		// Try to decrypt progressively larger chunks until we succeed
		// (since we don't know exact chunk boundaries)
		var plaintext []byte
		success := false
		for end := offset + gcm.Overhead(); end <= ciphertextEnd; end++ {
			ciphertext := encryptedData[offset:end]
			pt, err := gcm.Open(nil, nonce, ciphertext, nil)
			if err == nil {
				plaintext = pt
				offset = end
				success = true
				break
			}
		}

		if !success {
			return nil, fmt.Errorf("failed to decrypt chunk at offset %d", offset)
		}

		result.Write(plaintext)
	}

	return result.Bytes(), nil
}

// oneBytePerReadReader wraps an io.Reader and returns at most one byte per
// Read call. This simulates the short-read behaviour seen from network-mounted
// filesystems (NFS/FUSE/CIFS), io.MultiReader-style wrappers, and the future
// S3-backed streaming reader path. A `Read(b)` call returns `(1, nil)` until
// the underlying buffer is exhausted, then `(0, io.EOF)`.
type oneBytePerReadReader struct{ inner *bytes.Reader }

func (s *oneBytePerReadReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return s.inner.Read(p[:1])
}

// TestDecryptChunkStream_ShortReads is the SH-1.2 regression test: confirms
// that the decrypt loop reassembles chunks correctly when the backing reader
// returns short reads, which it would not have done before the io.ReadFull
// migration (bare `Read` would have surfaced ErrUnexpectedEOF-shaped buffers
// into gcm.Open as "failed to decrypt chunk" on intact data).
func TestDecryptChunkStream_ShortReads(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Build plaintext large enough to span multiple chunks. The streaming
	// format uses 1 MB chunks by default (1024 * 1024), so 3.5 MB exercises
	// 3 full chunks + 1 short final chunk.
	const chunkSize = 1 << 20 // 1 MiB
	plaintext := make([]byte, chunkSize*3+chunkSize/2)
	for i := range plaintext {
		plaintext[i] = byte(i % 251) // non-repeating-modulo pattern
	}

	// Encrypt via the production writer.
	var encryptedBuf bytes.Buffer
	if err := EncryptFileStreamingFromReader(&encryptedBuf, bytes.NewReader(plaintext), testKey); err != nil {
		t.Fatalf("EncryptFileStreamingFromReader: %v", err)
	}
	encrypted := encryptedBuf.Bytes()

	// Parse SFSE1 header to recover the chunk size the writer used (the
	// writer may pick a different size than we passed; we trust the on-disk
	// chunk_size field).
	if len(encrypted) < 10 {
		t.Fatalf("encrypted payload too short: %d bytes", len(encrypted))
	}
	if string(encrypted[0:5]) != StreamEncryptionMagic {
		t.Fatalf("bad magic: %q", encrypted[0:5])
	}
	if encrypted[5] != StreamEncryptionVersion {
		t.Fatalf("bad version: %d", encrypted[5])
	}
	encodedChunkSize := binary.LittleEndian.Uint32(encrypted[6:10])

	// Build a GCM exactly as the production decrypt path would.
	key, err := hex.DecodeString(testKey)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	encryptedChunkSize := int(encodedChunkSize) + gcm.NonceSize() + gcm.Overhead()

	// Drive the chunk loop through a one-byte-per-read wrapper, which is
	// the worst-case short-read pattern. Pre-SH-1.2 code would fail on the
	// first chunk because srcFile.Read returns (1, nil) — n=1 is less than
	// the gcm.NonceSize() check and the whole loop bails with
	// "chunk too small: 1 bytes". Post-fix uses io.ReadFull which retries
	// until the buffer is full or hits EOF.
	chunkPortion := encrypted[10:] // skip header
	src := &oneBytePerReadReader{inner: bytes.NewReader(chunkPortion)}
	var out bytes.Buffer
	if err := decryptChunkStream(src, &out, gcm, encryptedChunkSize); err != nil {
		t.Fatalf("decryptChunkStream under short reads: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Fatalf("plaintext mismatch: got %d bytes, want %d bytes", out.Len(), len(plaintext))
	}
}

// TestDecryptChunkStream_HappyPath confirms the helper is also correct under
// normal (full-buffer) reads, so the io.ReadFull change is not papering over a
// regression in the typical local-FS case.
func TestDecryptChunkStream_HappyPath(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	plaintext := bytes.Repeat([]byte("safeshare"), 200_000) // ~1.8 MB

	var encryptedBuf bytes.Buffer
	if err := EncryptFileStreamingFromReader(&encryptedBuf, bytes.NewReader(plaintext), testKey); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	encrypted := encryptedBuf.Bytes()
	encodedChunkSize := binary.LittleEndian.Uint32(encrypted[6:10])

	key, _ := hex.DecodeString(testKey)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	encryptedChunkSize := int(encodedChunkSize) + gcm.NonceSize() + gcm.Overhead()

	var out bytes.Buffer
	if err := decryptChunkStream(bytes.NewReader(encrypted[10:]), &out, gcm, encryptedChunkSize); err != nil {
		t.Fatalf("decryptChunkStream: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// TestSH31_AEADCacheReturnsIdenticalInstance verifies that repeated calls to
// newGCMFromKeyHex with the same key return the *same* cipher.AEAD instance,
// proving the cache is wired. Without the cache, each call would allocate a
// fresh AEAD (visible in BenchmarkAEADCacheHit's allocs/op).
//
// SH-3.1.
func TestSH31_AEADCacheReturnsIdenticalInstance(t *testing.T) {
	keyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	first, err := newGCMFromKeyHex(keyHex)
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	second, err := newGCMFromKeyHex(keyHex)
	if err != nil {
		t.Fatalf("second build: %v", err)
	}
	if first != second {
		t.Errorf("newGCMFromKeyHex returned different AEAD instances on repeated calls; cache not wired")
	}

	// A different key must build a new instance.
	otherKey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	other, err := newGCMFromKeyHex(otherKey)
	if err != nil {
		t.Fatalf("third build (different key): %v", err)
	}
	if first == other {
		t.Errorf("newGCMFromKeyHex returned the same instance for two different keys; cache is keyed wrong")
	}
}

// BenchmarkAEADCacheHit measures the per-call overhead of newGCMFromKeyHex on
// the cache-hit path — i.e. the hot path in production where one key is
// reused for every encrypt/decrypt. Expectation: 0 allocs/op.
//
// SH-3.1.
func BenchmarkAEADCacheHit(b *testing.B) {
	keyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := newGCMFromKeyHex(keyHex); err != nil {
		b.Fatalf("warm-up: %v", err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = newGCMFromKeyHex(keyHex)
	}
}
