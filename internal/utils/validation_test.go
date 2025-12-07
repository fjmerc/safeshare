package utils

import (
	"strings"
	"testing"
)

// TestValidateClaimCode tests claim code validation
func TestValidateClaimCode(t *testing.T) {
	tests := []struct {
		name        string
		claimCode   string
		expectError bool
		errorMsg    string
	}{
		// Valid claim codes
		{
			name:        "valid 8 char alphanumeric",
			claimCode:   "abc12345",
			expectError: false,
		},
		{
			name:        "valid 16 char alphanumeric",
			claimCode:   "abcdef1234567890",
			expectError: false,
		},
		{
			name:        "valid 32 char alphanumeric",
			claimCode:   "abcdefghijklmnopqrstuvwxyz123456",
			expectError: false,
		},
		{
			name:        "valid uppercase",
			claimCode:   "ABCD1234",
			expectError: false,
		},
		{
			name:        "valid mixed case",
			claimCode:   "AbCd1234",
			expectError: false,
		},
		{
			name:        "valid all numbers",
			claimCode:   "12345678",
			expectError: false,
		},
		{
			name:        "valid all letters",
			claimCode:   "abcdefgh",
			expectError: false,
		},
		// Valid: URL-safe base64 characters (hyphen and underscore)
		{
			name:        "valid with hyphen (base64url)",
			claimCode:   "abc-1234",
			expectError: false,
		},
		{
			name:        "valid with underscore (base64url)",
			claimCode:   "abc_1234",
			expectError: false,
		},
		{
			name:        "valid with hyphen and underscore (base64url)",
			claimCode:   "ab_c-123",
			expectError: false,
		},
		{
			name:        "valid base64url encoded (8 char)",
			claimCode:   "Aa_-Bb12",
			expectError: false,
		},

		// Invalid: empty
		{
			name:        "empty string",
			claimCode:   "",
			expectError: true,
			errorMsg:    "cannot be empty",
		},

		// Invalid: too short
		{
			name:        "too short - 7 chars",
			claimCode:   "abc1234",
			expectError: true,
			errorMsg:    "8-32 characters",
		},
		{
			name:        "too short - 1 char",
			claimCode:   "a",
			expectError: true,
			errorMsg:    "8-32 characters",
		},

		// Invalid: too long
		{
			name:        "too long - 33 chars",
			claimCode:   "abcdefghijklmnopqrstuvwxyz1234567",
			expectError: true,
			errorMsg:    "8-32 characters",
		},

		// Invalid: special characters (not in base64url)
		{
			name:        "contains space",
			claimCode:   "abc 1234",
			expectError: true,
			errorMsg:    "8-32 characters",
		},
		{
			name:        "contains dot",
			claimCode:   "abc.1234",
			expectError: true,
			errorMsg:    "8-32 characters",
		},
		{
			name:        "contains slash",
			claimCode:   "abc/1234",
			expectError: true,
			errorMsg:    "8-32 characters",
		},
		{
			name:        "contains plus sign",
			claimCode:   "abc+1234",
			expectError: true,
			errorMsg:    "8-32 characters",
		},
		{
			name:        "contains equals sign",
			claimCode:   "abc=1234",
			expectError: true,
			errorMsg:    "8-32 characters",
		},

		// Security: path traversal attempts
		{
			name:        "path traversal attempt",
			claimCode:   "../etc/passwd",
			expectError: true,
			errorMsg:    "8-32 characters",
		},
		{
			name:        "SQL injection attempt",
			claimCode:   "'; DROP TABLE--",
			expectError: true,
			errorMsg:    "8-32 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClaimCode(tt.claimCode)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errorMsg)
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}

// TestIsFileAllowed_EdgeCases tests edge cases for file validation
func TestIsFileAllowed_EdgeCases(t *testing.T) {
	blockedExts := []string{".exe", ".bat", ".sh", ".ps1"}

	tests := []struct {
		name          string
		filename      string
		blocked       []string
		expectAllowed bool
		expectMatched string
		expectError   bool
	}{
		{
			name:          "empty filename",
			filename:      "",
			blocked:       blockedExts,
			expectAllowed: false,
			expectError:   true,
		},
		{
			name:          "allowed file",
			filename:      "document.txt",
			blocked:       blockedExts,
			expectAllowed: true,
			expectMatched: "",
		},
		{
			name:          "blocked exe",
			filename:      "virus.exe",
			blocked:       blockedExts,
			expectAllowed: false,
			expectMatched: ".exe",
		},
		{
			name:          "uppercase extension",
			filename:      "VIRUS.EXE",
			blocked:       blockedExts,
			expectAllowed: false,
			expectMatched: ".exe",
		},
		{
			name:          "mixed case extension",
			filename:      "Script.BaT",
			blocked:       blockedExts,
			expectAllowed: false,
			expectMatched: ".bat",
		},
		{
			name:          "double extension trick",
			filename:      "document.pdf.exe",
			blocked:       blockedExts,
			expectAllowed: false,
			expectMatched: ".exe",
		},
		{
			name:          "reverse double extension",
			filename:      "malware.exe.txt",
			blocked:       blockedExts,
			expectAllowed: false,
			expectMatched: ".exe",
		},
		{
			name:          "no blocked extensions",
			filename:      "anything.exe",
			blocked:       []string{},
			expectAllowed: true,
			expectMatched: "",
		},
		{
			name:          "extension in basename",
			filename:      "executable-file.txt",
			blocked:       blockedExts,
			expectAllowed: true,
			expectMatched: "",
		},
		{
			name:          "no extension",
			filename:      "README",
			blocked:       blockedExts,
			expectAllowed: true,
			expectMatched: "",
		},
		{
			name:          "hidden file",
			filename:      ".bashrc",
			blocked:       blockedExts,
			expectAllowed: true,
			expectMatched: "",
		},
		{
			name:          "blocked shell script",
			filename:      "install.sh",
			blocked:       blockedExts,
			expectAllowed: false,
			expectMatched: ".sh",
		},
		{
			name:          "powershell script",
			filename:      "deploy.ps1",
			blocked:       blockedExts,
			expectAllowed: false,
			expectMatched: ".ps1",
		},
		{
			name:          "triple extension",
			filename:      "archive.tar.gz.exe",
			blocked:       blockedExts,
			expectAllowed: false,
			expectMatched: ".exe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, matched, err := IsFileAllowed(tt.filename, tt.blocked)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if allowed != tt.expectAllowed {
				t.Errorf("IsFileAllowed() allowed = %v, expected %v", allowed, tt.expectAllowed)
			}

			if matched != tt.expectMatched {
				t.Errorf("IsFileAllowed() matched = %q, expected %q", matched, tt.expectMatched)
			}
		})
	}
}

// TestValidateStoredFilename tests defense-in-depth validation of stored filenames
// to prevent path traversal attacks in case of database compromise or corruption
func TestValidateStoredFilename(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		expectError bool
		errorMsg    string
	}{
		// Valid filenames (UUID-based names)
		{
			name:        "valid UUID with extension",
			filename:    "abc123-def456.txt",
			expectError: false,
		},
		{
			name:        "valid UUID with bin extension",
			filename:    "uuid-1234-5678-90ab-cdef.bin",
			expectError: false,
		},
		{
			name:        "valid UUID with multiple dots in extension",
			filename:    "file-uuid.tar.gz",
			expectError: false,
		},
		{
			name:        "valid UUID with underscore",
			filename:    "file_uuid_123.dat",
			expectError: false,
		},
		{
			name:        "valid UUID no extension",
			filename:    "uuid-1234-5678",
			expectError: false,
		},

		// Path traversal attacks
		{
			name:        "path traversal with ../",
			filename:    "../../etc/passwd",
			expectError: true,
			errorMsg:    "path", // Matches both "path separator" and "path traversal"
		},
		{
			name:        "path traversal with single ../",
			filename:    "../passwd",
			expectError: true,
			errorMsg:    "path", // Matches both "path separator" and "path traversal"
		},
		{
			name:        "path traversal in middle",
			filename:    "uploads/../../../etc/passwd",
			expectError: true,
			errorMsg:    "path separator",
		},
		{
			name:        "Windows path traversal",
			filename:    "..\\..\\windows\\system32",
			expectError: true,
			errorMsg:    "path", // Matches both "path separator" and "path traversal"
		},
		{
			name:        "double dot without separator",
			filename:    "file..txt",
			expectError: true,
			errorMsg:    "path traversal",
		},

		// Absolute paths
		{
			name:        "Unix absolute path",
			filename:    "/etc/passwd",
			expectError: true,
			errorMsg:    "path separator",
		},
		{
			name:        "Windows absolute path",
			filename:    "C:\\windows\\system32",
			expectError: true,
			errorMsg:    "path separator",
		},
		{
			name:        "Unix path with slashes",
			filename:    "etc/passwd",
			expectError: true,
			errorMsg:    "path separator",
		},
		{
			name:        "Windows path with backslashes",
			filename:    "windows\\system32",
			expectError: true,
			errorMsg:    "path separator",
		},

		// Hidden files
		{
			name:        "hidden file .bashrc",
			filename:    ".bashrc",
			expectError: true,
			errorMsg:    "hidden file",
		},
		{
			name:        "hidden file .env",
			filename:    ".env",
			expectError: true,
			errorMsg:    "hidden file",
		},
		{
			name:        "hidden file with path",
			filename:    ".ssh/id_rsa",
			expectError: true,
			errorMsg:    "", // Will be rejected by either "hidden file" or "path separator" - both are valid
		},

		// Special characters
		{
			name:        "space in filename",
			filename:    "file name.txt",
			expectError: true,
			errorMsg:    "invalid character",
		},
		{
			name:        "at symbol",
			filename:    "file@name.txt",
			expectError: true,
			errorMsg:    "invalid character",
		},
		{
			name:        "semicolon",
			filename:    "file;name.txt",
			expectError: true,
			errorMsg:    "invalid character",
		},
		{
			name:        "ampersand",
			filename:    "file&name.txt",
			expectError: true,
			errorMsg:    "invalid character",
		},
		{
			name:        "dollar sign",
			filename:    "file$name.txt",
			expectError: true,
			errorMsg:    "invalid character",
		},
		{
			name:        "pipe symbol",
			filename:    "file|name.txt",
			expectError: true,
			errorMsg:    "invalid character",
		},

		// Edge cases
		{
			name:        "empty filename",
			filename:    "",
			expectError: true,
			errorMsg:    "cannot be empty",
		},
		{
			name:        "only dots",
			filename:    "...",
			expectError: true,
			errorMsg:    "path traversal",
		},
		{
			name:        "single dot",
			filename:    ".",
			expectError: true,
			errorMsg:    "hidden file",
		},
		{
			name:        "two dots",
			filename:    "..",
			expectError: true,
			errorMsg:    "", // Will be rejected by either "hidden file" or "path traversal" - both are valid
		},
		{
			name:        "null byte attempt",
			filename:    "file\x00name.txt",
			expectError: true,
			errorMsg:    "invalid character",
		},
		{
			name:        "newline attempt",
			filename:    "file\nname.txt",
			expectError: true,
			errorMsg:    "invalid character",
		},
		{
			name:        "carriage return attempt",
			filename:    "file\rname.txt",
			expectError: true,
			errorMsg:    "invalid character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStoredFilename(tt.filename)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errorMsg)
					return
				}
				// Only check error message if errorMsg is specified
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}
