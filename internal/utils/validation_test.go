package utils

import (
	"testing"
)

// TestIsFileAllowed_EdgeCases tests edge cases for file validation
func TestIsFileAllowed_EdgeCases(t *testing.T) {
	blockedExts := []string{".exe", ".bat", ".sh", ".ps1"}

	tests := []struct {
		name           string
		filename       string
		blocked        []string
		expectAllowed  bool
		expectMatched  string
		expectError    bool
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

