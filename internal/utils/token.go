package utils

import "strings"

// MaskToken masks a token for safe logging/display
// Shows first 3 and last 3 characters, masks the middle
// Example: "abc123xyz789" -> "abc***789"
func MaskToken(token string) string {
	if token == "" {
		return ""
	}

	// For very short tokens (6 chars or less), mask completely
	if len(token) <= 6 {
		return "***"
	}

	// Show first 3 and last 3 characters
	return token[:3] + "***" + token[len(token)-3:]
}

// IsMaskedToken checks if a token is masked (contains ***)
// Returns true if the token appears to be masked by MaskToken()
// Validates against exact mask format to prevent false positives
func IsMaskedToken(token string) bool {
	if token == "" {
		return false
	}
	
	// Exact match for fully masked short tokens (≤6 chars)
	if token == "***" {
		return true
	}
	
	// Check for pattern: "ABC***XYZ" (3 chars + *** + 3 chars = 9 chars total)
	// This matches the exact format produced by MaskToken()
	if len(token) == 9 && token[3:6] == "***" {
		// Ensure *** is only in the middle (positions 3-5)
		// No asterisks should appear in first 3 or last 3 characters
		if !strings.Contains(token[:3], "*") && !strings.Contains(token[6:], "*") {
			return true
		}
	}
	
	return false
}
