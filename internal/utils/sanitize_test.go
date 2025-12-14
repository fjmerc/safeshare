package utils

import (
	"strings"
	"testing"
)

// Note: TestSanitizeFilename and TestSanitizeFilename_LongFilename are in utils_test.go
// This file contains additional edge case tests

func TestSanitizeFilename_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     string
	}{
		{
			name:     "only special characters",
			filename: "!@#$%^&*()",
			want:     "__________",
		},
		{
			name:     "unicode letters allowed",
			filename: "документ.pdf",
			want:     "документ.pdf",
		},
		{
			name:     "unicode with special chars",
			filename: "文件<>.txt",
			want:     "文件__.txt",
		},
		{
			name:     "only dots",
			filename: "...",
			want:     "download",
		},
		{
			name:     "only spaces",
			filename: "   ",
			want:     "download",
		},
		{
			name:     "mixed unicode and special",
			filename: "日本語ファイル<test>.pdf",
			want:     "日本語ファイル_test_.pdf",
		},
		{
			name:     "arabic filename",
			filename: "ملف.pdf",
			want:     "ملف.pdf",
		},
		{
			name:     "emoji in filename",
			filename: "file🎉.txt",
			want:     "file_.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeFilename(tt.filename)
			if got != tt.want {
				t.Errorf("SanitizeFilename(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestSanitizeFilename_LongExtension(t *testing.T) {
	// Create a filename with a very long extension (more than 20 chars)
	longExt := "file." + strings.Repeat("x", 30)
	longName := strings.Repeat("a", 250) + longExt

	result := SanitizeFilename(longName)

	if len(result) > 255 {
		t.Errorf("SanitizeFilename should limit to 255 chars, got %d", len(result))
	}
}

func TestSanitizeFilename_PreservesValidCharacters(t *testing.T) {
	// Test that valid characters are preserved
	validFilename := "My-File_2024.test.pdf"
	result := SanitizeFilename(validFilename)

	if result != validFilename {
		t.Errorf("SanitizeFilename should preserve valid filename, got %q", result)
	}
}

func TestSanitizeFilename_HTTPHeaderInjection(t *testing.T) {
	// Test that HTTP header injection is prevented
	malicious := "file.txt\r\nContent-Type: text/html"
	result := SanitizeFilename(malicious)

	if strings.Contains(result, "\r") || strings.Contains(result, "\n") {
		t.Errorf("SanitizeFilename should remove CRLF, got %q", result)
	}

	if strings.Contains(result, "Content-Type") {
		t.Errorf("SanitizeFilename should not contain injected header, got %q", result)
	}
}

func TestSanitizeForContentDisposition_AdditionalCases(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     string
	}{
		{
			name:     "null byte injection",
			filename: "file\x00.txt",
			want:     "file_.txt",
		},
		{
			name:     "tab character",
			filename: "file\twith\ttabs.txt",
			want:     "file_with_tabs.txt",
		},
		{
			name:     "semicolon (could break header)",
			filename: "file;name.txt",
			want:     "file_name.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeForContentDisposition(tt.filename)
			if got != tt.want {
				t.Errorf("SanitizeForContentDisposition(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}
