package utils

import (
	"path/filepath"
	"strings"
	"unicode"
)

// SanitizeFilename removes dangerous characters from filenames
// This prevents:
// - HTTP header injection (quotes, newlines)
// - Path traversal (slashes, backslashes)
// - Control characters that could break logs or displays
func SanitizeFilename(filename string) string {
	if filename == "" {
		return "download"
	}

	// Remove path components - only keep the base filename
	filename = filepath.Base(filename)

	// Build sanitized version character by character
	var sanitized strings.Builder
	sanitized.Grow(len(filename))

	for _, r := range filename {
		// Allow: alphanumeric, spaces, hyphens, underscores, periods
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || r == '-' || r == '_' || r == '.' {
			sanitized.WriteRune(r)
		} else {
			// Replace disallowed characters with underscore
			sanitized.WriteRune('_')
		}
	}

	result := sanitized.String()

	// Trim leading/trailing spaces and dots (can cause issues)
	result = strings.Trim(result, " .")

	// If result is empty or only dots, use fallback
	if result == "" || strings.Trim(result, ".") == "" {
		return "download"
	}

	// Limit length to 255 characters (filesystem limitation)
	if len(result) > 255 {
		// Try to preserve extension
		ext := filepath.Ext(result)
		if len(ext) > 0 && len(ext) < 20 {
			basename := result[:len(result)-len(ext)]
			if len(basename) > 255-len(ext) {
				basename = basename[:255-len(ext)]
			}
			result = basename + ext
		} else {
			result = result[:255]
		}
	}

	return result
}

// SanitizeForContentDisposition prepares a filename for use in Content-Disposition header
// It escapes quotes and ensures the filename is RFC 5987 compliant
func SanitizeForContentDisposition(filename string) string {
	// First sanitize the filename to remove dangerous characters
	sanitized := SanitizeFilename(filename)

	// Escape double quotes for Content-Disposition header
	sanitized = strings.ReplaceAll(sanitized, `"`, `\"`)

	return sanitized
}
