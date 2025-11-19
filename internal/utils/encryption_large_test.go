package utils

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestEncryptionStreaming_LargeFile tests encryption/decryption of large files using streaming
func TestEncryptionStreaming_LargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file encryption test in short mode")
	}

	// Create temporary directory for test files
	tempDir := t.TempDir()

	// Test with 100MB file
	testSizes := []struct {
		name string
		size int64
	}{
		{"10MB", 10 * 1024 * 1024},
		{"50MB", 50 * 1024 * 1024},
		{"100MB", 100 * 1024 * 1024},
	}

	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	for _, tt := range testSizes {
		t.Run(tt.name, func(t *testing.T) {
			// Create large random file
			inputPath := filepath.Join(tempDir, "large_input_"+tt.name+".bin")
			encryptedPath := filepath.Join(tempDir, "encrypted_"+tt.name+".bin")
			decryptedPath := filepath.Join(tempDir, "decrypted_"+tt.name+".bin")

			t.Logf("Creating %s test file...", tt.name)
			if err := createRandomFile(inputPath, tt.size); err != nil {
				t.Fatalf("createRandomFile() error: %v", err)
			}

			// Verify file was created with correct size
			stat, _ := os.Stat(inputPath)
			if stat.Size() != tt.size {
				t.Fatalf("created file size = %d, want %d", stat.Size(), tt.size)
			}

			// Encrypt file
			t.Logf("Encrypting %s file...", tt.name)
			if err := encryptLargeFile(inputPath, encryptedPath, testKey); err != nil {
				t.Fatalf("encryptLargeFile() error: %v", err)
			}

			// Verify encrypted file exists and is larger (due to headers/nonces/tags)
			encStat, _ := os.Stat(encryptedPath)
			if encStat.Size() <= tt.size {
				t.Errorf("encrypted file size = %d should be > %d (original)", encStat.Size(), tt.size)
			}

			// Decrypt file
			t.Logf("Decrypting %s file...", tt.name)
			if err := decryptLargeFile(encryptedPath, decryptedPath, testKey); err != nil {
				t.Fatalf("decryptLargeFile() error: %v", err)
			}

			// Verify decrypted file matches original
			t.Logf("Verifying %s file integrity...", tt.name)
			if err := compareFiles(inputPath, decryptedPath); err != nil {
				t.Fatalf("file comparison failed: %v", err)
			}

			t.Logf("✓ %s file encryption/decryption successful", tt.name)

			// Cleanup (temp dir will be cleaned by t.TempDir())
		})
	}
}

// TestEncryptionStreaming_MemoryEfficiency tests that large file encryption doesn't load entire file into memory
func TestEncryptionStreaming_MemoryEfficiency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory efficiency test in short mode")
	}

	tempDir := t.TempDir()
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Create 50MB file
	inputPath := filepath.Join(tempDir, "memory_test.bin")
	encryptedPath := filepath.Join(tempDir, "memory_test_enc.bin")

	fileSize := int64(50 * 1024 * 1024) // 50MB
	t.Logf("Creating 50MB test file for memory efficiency test...")

	if err := createRandomFile(inputPath, fileSize); err != nil {
		t.Fatalf("createRandomFile() error: %v", err)
	}

	// Encrypt using streaming (should use minimal memory)
	t.Log("Encrypting with streaming (should use ~64KB buffer, not 50MB)...")

	// Note: To properly test memory usage, run with -memprofile:
	// go test -memprofile=mem.prof -run TestEncryptionStreaming_MemoryEfficiency
	// go tool pprof -alloc_space mem.prof

	if err := encryptLargeFile(inputPath, encryptedPath, testKey); err != nil {
		t.Fatalf("encryptLargeFile() error: %v", err)
	}

	t.Log("✓ Encryption completed - check memory profile to verify streaming")
}

// TestEncryptionStreaming_ChunkBoundaries tests encryption works correctly across chunk boundaries
func TestEncryptionStreaming_ChunkBoundaries(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tempDir := t.TempDir()

	// Test file sizes around chunk boundaries
	// Assuming 5MB chunk size (default CHUNK_SIZE in encryption.go)
	testSizes := []struct {
		name string
		size int64
	}{
		{"exactly 1 chunk", 5 * 1024 * 1024},
		{"1 byte over chunk", 5*1024*1024 + 1},
		{"1 byte under 2 chunks", 10*1024*1024 - 1},
		{"exactly 2 chunks", 10 * 1024 * 1024},
		{"2.5 chunks", 12500 * 1024},
	}

	for _, tt := range testSizes {
		t.Run(tt.name, func(t *testing.T) {
			inputPath := filepath.Join(tempDir, "boundary_input_"+tt.name+".bin")
			encryptedPath := filepath.Join(tempDir, "boundary_enc_"+tt.name+".bin")
			decryptedPath := filepath.Join(tempDir, "boundary_dec_"+tt.name+".bin")

			// Create file with specific size
			if err := createRandomFile(inputPath, tt.size); err != nil {
				t.Fatalf("createRandomFile() error: %v", err)
			}

			// Encrypt
			if err := encryptLargeFile(inputPath, encryptedPath, testKey); err != nil {
				t.Fatalf("encryptLargeFile() error: %v", err)
			}

			// Decrypt
			if err := decryptLargeFile(encryptedPath, decryptedPath, testKey); err != nil {
				t.Fatalf("decryptLargeFile() error: %v", err)
			}

			// Verify
			if err := compareFiles(inputPath, decryptedPath); err != nil {
				t.Fatalf("chunk boundary test failed for %s: %v", tt.name, err)
			}

			t.Logf("✓ Chunk boundary test passed for %s (%d bytes)", tt.name, tt.size)
		})
	}
}

// TestEncryptionStreaming_CorruptedData tests that corrupted encrypted data is detected
func TestEncryptionStreaming_CorruptedData(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tempDir := t.TempDir()

	// Create and encrypt a file
	inputPath := filepath.Join(tempDir, "corrupt_input.bin")
	encryptedPath := filepath.Join(tempDir, "corrupt_enc.bin")
	decryptedPath := filepath.Join(tempDir, "corrupt_dec.bin")

	fileSize := int64(1024 * 1024) // 1MB

	if err := createRandomFile(inputPath, fileSize); err != nil {
		t.Fatalf("createRandomFile() error: %v", err)
	}

	if err := encryptLargeFile(inputPath, encryptedPath, testKey); err != nil {
		t.Fatalf("encryptLargeFile() error: %v", err)
	}

	// Corrupt the encrypted file by flipping a byte in the middle
	encFile, err := os.OpenFile(encryptedPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open encrypted file: %v", err)
	}

	// Skip header and corrupt a byte in the first chunk
	encFile.Seek(100, 0) // Skip to middle of file
	var corruptByte [1]byte
	encFile.Read(corruptByte[:])
	corruptByte[0] ^= 0xFF // Flip all bits
	encFile.Seek(-1, 1)    // Go back one byte
	encFile.Write(corruptByte[:])
	encFile.Close()

	// Attempt to decrypt corrupted file - should fail
	err = decryptLargeFile(encryptedPath, decryptedPath, testKey)
	if err == nil {
		t.Error("decryption should fail for corrupted file, but succeeded")
	}

	t.Logf("✓ Corrupted data correctly detected: %v", err)
}

// TestEncryptionStreaming_WrongKey tests that decryption fails with wrong key
func TestEncryptionStreaming_WrongKey(t *testing.T) {
	correctKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	wrongKey := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	tempDir := t.TempDir()

	// Create and encrypt a file
	inputPath := filepath.Join(tempDir, "wrongkey_input.bin")
	encryptedPath := filepath.Join(tempDir, "wrongkey_enc.bin")
	decryptedPath := filepath.Join(tempDir, "wrongkey_dec.bin")

	fileSize := int64(512 * 1024) // 512KB

	if err := createRandomFile(inputPath, fileSize); err != nil {
		t.Fatalf("createRandomFile() error: %v", err)
	}

	// Encrypt with correct key
	if err := encryptLargeFile(inputPath, encryptedPath, correctKey); err != nil {
		t.Fatalf("encryptLargeFile() error: %v", err)
	}

	// Attempt to decrypt with wrong key - should fail
	err := decryptLargeFile(encryptedPath, decryptedPath, wrongKey)
	if err == nil {
		t.Error("decryption should fail with wrong key, but succeeded")
	}

	t.Logf("✓ Wrong key correctly rejected: %v", err)
}

// Helper function to create a file with random content
func createRandomFile(path string, size int64) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write in 1MB chunks to avoid memory issues
	chunkSize := int64(1024 * 1024) // 1MB
	remaining := size
	buffer := make([]byte, chunkSize)

	for remaining > 0 {
		writeSize := chunkSize
		if remaining < chunkSize {
			writeSize = remaining
			buffer = make([]byte, writeSize)
		}

		if _, err := rand.Read(buffer); err != nil {
			return err
		}

		if _, err := file.Write(buffer); err != nil {
			return err
		}

		remaining -= writeSize
	}

	return nil
}

// Helper function to encrypt a large file using streaming
func encryptLargeFile(inputPath, outputPath, keyHex string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	return EncryptFileStreamingFromReader(outputFile, inputFile, keyHex)
}

// Helper function to decrypt a large file using streaming
func decryptLargeFile(inputPath, outputPath, keyHex string) error {
	return DecryptFileStreaming(inputPath, outputPath, keyHex)
}

// Helper function to compare two files byte-by-byte
func compareFiles(path1, path2 string) error {
	file1, err := os.Open(path1)
	if err != nil {
		return err
	}
	defer file1.Close()

	file2, err := os.Open(path2)
	if err != nil {
		return err
	}
	defer file2.Close()

	// Compare file sizes first
	stat1, _ := file1.Stat()
	stat2, _ := file2.Stat()

	if stat1.Size() != stat2.Size() {
		return io.ErrUnexpectedEOF
	}

	// Compare content in chunks
	buffer1 := make([]byte, 64*1024) // 64KB buffer
	buffer2 := make([]byte, 64*1024)

	for {
		n1, err1 := file1.Read(buffer1)
		n2, err2 := file2.Read(buffer2)

		if n1 != n2 {
			return io.ErrUnexpectedEOF
		}

		if !bytes.Equal(buffer1[:n1], buffer2[:n2]) {
			return io.ErrUnexpectedEOF
		}

		if err1 == io.EOF && err2 == io.EOF {
			return nil
		}

		if err1 != nil || err2 != nil {
			if err1 != err2 {
				return io.ErrUnexpectedEOF
			}
		}
	}
}
