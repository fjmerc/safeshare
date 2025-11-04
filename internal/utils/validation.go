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
