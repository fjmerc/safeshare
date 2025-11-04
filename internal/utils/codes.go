package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateClaimCode generates a cryptographically secure random claim code
// The code is URL-safe and 16 characters long
func GenerateClaimCode() (string, error) {
	// Generate 12 random bytes
	// 12 bytes = 96 bits of entropy
	// Base64 encoding: 12 bytes -> 16 characters
	bytes := make([]byte, 12)

	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64 URL-safe format (no +, /, or =)
	encoded := base64.URLEncoding.EncodeToString(bytes)

	// Remove padding and take first 16 characters
	// URL-safe base64 may have padding, we remove it
	if len(encoded) > 16 {
		encoded = encoded[:16]
	}

	return encoded, nil
}
