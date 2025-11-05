package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateSessionToken generates a cryptographically secure session token
func GenerateSessionToken() (string, error) {
	// Generate 32 random bytes
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64 URL-safe string
	return base64.URLEncoding.EncodeToString(b), nil
}

// GenerateCSRFToken generates a cryptographically secure CSRF token
func GenerateCSRFToken() (string, error) {
	// Generate 32 random bytes
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64 URL-safe string
	return base64.URLEncoding.EncodeToString(b), nil
}
