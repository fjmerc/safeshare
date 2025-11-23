package utils

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
