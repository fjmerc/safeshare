package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
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
	remainingData := []byte("ABC")                 // 3 bytes after MIME buffer

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
