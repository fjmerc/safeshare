package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
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
