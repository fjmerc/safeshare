package utils

import (
	"fmt"
	"path/filepath"
	"strings"
)

// IsFileAllowed checks if a file is allowed based on its extension
// Returns: (allowed bool, matched extension, error)
func IsFileAllowed(filename string, blockedExtensions []string) (bool, string, error) {
	if filename == "" {
		return false, "", fmt.Errorf("filename cannot be empty")
	}

	// If no blocked extensions configured, allow all files
	if len(blockedExtensions) == 0 {
		return true, "", nil
	}

	// Get file extension (lowercase for case-insensitive comparison)
	ext := strings.ToLower(filepath.Ext(filename))

	// Check if extension is blocked
	for _, blocked := range blockedExtensions {
		if ext == blocked {
			return false, ext, nil
		}
	}

	// Check for double extensions (e.g., .tar.gz, .safe.exe)
	// Some malware uses tricks like "document.pdf.exe"
	fullPath := strings.ToLower(filename)
	for _, blocked := range blockedExtensions {
		// Check if blocked extension appears anywhere in the filename
		// (not just at the end, to catch tricks like "file.exe.txt")
		if strings.Contains(fullPath, blocked) {
			// But make sure it's actually an extension, not part of the base name
			// e.g., "executable-file.txt" should be allowed
			parts := strings.Split(fullPath, ".")
			for i, part := range parts {
				if i > 0 && "."+part == blocked {
					return false, blocked, nil
				}
			}
		}
	}

	return true, "", nil
}

// GetFileExtension returns the file extension in lowercase
func GetFileExtension(filename string) string {
	return strings.ToLower(filepath.Ext(filename))
}

// ValidateStoredFilename validates that a stored filename is safe to use in file paths.
// This is a defense-in-depth measure to prevent path traversal attacks in case the
// database is compromised or corrupted. While stored filenames are generated as UUIDs,
// we validate them when reading from the database to ensure they cannot be used for
// directory traversal or access to files outside the upload directory.
//
// Returns an error if the filename:
// - Is empty
// - Contains path separators (/ or \)
// - Contains path traversal sequences (..)
// - Starts with a dot (hidden files)
// - Contains characters outside the safe set (alphanumeric, dash, underscore, dot)
//
// Valid examples: "abc123-def456.bin", "uuid-1234-5678.txt"
// Invalid examples: "../etc/passwd", "/etc/passwd", ".bashrc", "file/name.txt"
func ValidateStoredFilename(filename string) error {
	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}

	// Reject path separators (both Unix and Windows)
	if strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		return fmt.Errorf("filename contains path separator")
	}

	// Reject path traversal sequences
	if strings.Contains(filename, "..") {
		return fmt.Errorf("filename contains path traversal sequence")
	}

	// Reject hidden files (starting with dot)
	if strings.HasPrefix(filename, ".") {
		return fmt.Errorf("filename starts with dot (hidden file)")
	}

	// Validate character whitelist: only allow alphanumeric, dash, underscore, and dot
	// This matches our UUID-based naming scheme: {uuid}.{extension}
	for _, char := range filename {
		isValid := (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' ||
			char == '_' ||
			char == '.'
		if !isValid {
			return fmt.Errorf("filename contains invalid character: %c", char)
		}
	}

	return nil
}
