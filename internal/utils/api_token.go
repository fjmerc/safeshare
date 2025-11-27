package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// APITokenPrefix is the prefix for all SafeShare API tokens
	// This enables secret scanning tools (GitHub, GitLab) to detect leaked tokens
	APITokenPrefix = "safeshare_"

	// APITokenRandomBytes is the number of random bytes in a token (256 bits of entropy)
	APITokenRandomBytes = 32

	// APITokenLength is the total length of a token (prefix + hex-encoded random bytes)
	// 10 (prefix "safeshare_") + 64 (32 bytes as hex) = 74 characters
	APITokenLength = 74

	// APITokenPrefixDisplayLength is how many characters of the full token to show for identification
	// Shows "safeshare_" + first 3 hex chars = 12 characters
	APITokenPrefixDisplayLength = 12
)

// ValidAPITokenScopes defines all valid scope values
var ValidAPITokenScopes = []string{"upload", "download", "manage", "admin"}

// GenerateAPIToken creates a new API token with the safeshare_ prefix
// Returns the full token (to show user once) and the display prefix (for identification)
func GenerateAPIToken() (fullToken, displayPrefix string, err error) {
	// Generate cryptographically secure random bytes
	b := make([]byte, APITokenRandomBytes)
	_, err = rand.Read(b)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Create full token: prefix + hex-encoded random bytes
	randomHex := hex.EncodeToString(b)
	fullToken = APITokenPrefix + randomHex

	// Display prefix for identification: first 12 chars (safeshare_ + first 3 hex chars)
	displayPrefix = fullToken[:APITokenPrefixDisplayLength]

	return fullToken, displayPrefix, nil
}

// HashAPIToken creates a SHA-256 hash of the token for secure storage
// This is a one-way function - the original token cannot be recovered from the hash
func HashAPIToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// ValidateAPITokenFormat checks if a token has the correct format
// Returns true if the token is properly formatted (doesn't validate if it's valid/active)
func ValidateAPITokenFormat(token string) bool {
	// Must start with prefix
	if !strings.HasPrefix(token, APITokenPrefix) {
		return false
	}

	// Must be exactly the expected length
	if len(token) != APITokenLength {
		return false
	}

	// Random part (after prefix) must be valid hexadecimal
	randomPart := token[len(APITokenPrefix):]
	_, err := hex.DecodeString(randomPart)
	return err == nil
}

// ValidateScopes checks if all provided scopes are valid
// Returns list of invalid scopes and an error if any are invalid
func ValidateScopes(scopes []string) (invalidScopes []string, err error) {
	validSet := make(map[string]bool)
	for _, s := range ValidAPITokenScopes {
		validSet[s] = true
	}

	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if !validSet[scope] {
			invalidScopes = append(invalidScopes, scope)
		}
	}

	if len(invalidScopes) > 0 {
		return invalidScopes, fmt.Errorf("invalid scopes: %v", invalidScopes)
	}
	return nil, nil
}

// HasScope checks if a comma-separated scope string contains a specific scope
// Admin scope grants all permissions (returns true for any required scope)
func HasScope(scopeString, requiredScope string) bool {
	scopes := strings.Split(scopeString, ",")
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == requiredScope {
			return true
		}
		// Admin scope grants all permissions
		if s == "admin" {
			return true
		}
	}
	return false
}

// NormalizeScopes trims whitespace and removes duplicates from scope list
func NormalizeScopes(scopes []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

// ScopesToString converts a slice of scopes to a comma-separated string
func ScopesToString(scopes []string) string {
	return strings.Join(scopes, ",")
}

// StringToScopes converts a comma-separated string to a slice of scopes
// Filters out empty strings and trims whitespace from each scope
func StringToScopes(scopeStr string) []string {
	if scopeStr == "" {
		return []string{}
	}
	parts := strings.Split(scopeStr, ",")
	var scopes []string
	for _, s := range parts {
		s = strings.TrimSpace(s)
		if s != "" {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

// MaskAPIToken masks an API token for safe logging/display
// Shows the prefix (safeshare_) + first 3 hex chars + *** + last 3 chars
// Example: "safeshare_abc...xyz" -> "safeshare_abc***xyz"
func MaskAPIToken(token string) string {
	if token == "" {
		return ""
	}

	// For tokens that don't match expected format, use generic masking
	if len(token) < APITokenLength {
		return MaskToken(token)
	}

	// Show prefix + first 3 hex chars (12 total) + *** + last 3 chars
	return token[:APITokenPrefixDisplayLength] + "***" + token[len(token)-3:]
}
