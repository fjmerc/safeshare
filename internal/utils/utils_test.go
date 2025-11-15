package utils

import (
	"strings"
	"testing"
)

// TestGenerateClaimCode tests claim code generation
func TestGenerateClaimCode(t *testing.T) {
	code, err := GenerateClaimCode()
	if err != nil {
		t.Fatalf("GenerateClaimCode() error: %v", err)
	}

	if len(code) != 16 {
		t.Errorf("GenerateClaimCode() length = %d, want 16", len(code))
	}

	// Verify it's alphanumeric (base64 URL-safe)
	for _, char := range code {
		if !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			t.Errorf("GenerateClaimCode() contains invalid character: %c", char)
		}
	}
}

// TestGenerateClaimCode_Uniqueness tests that codes are unique
func TestGenerateClaimCode_Uniqueness(t *testing.T) {
	codes := make(map[string]bool)

	// Generate 100 codes and verify they're all unique
	for i := 0; i < 100; i++ {
		code, err := GenerateClaimCode()
		if err != nil {
			t.Fatalf("GenerateClaimCode() error: %v", err)
		}

		if codes[code] {
			t.Errorf("GenerateClaimCode() generated duplicate code: %s", code)
		}

		codes[code] = true
	}

	if len(codes) != 100 {
		t.Errorf("Generated %d unique codes, want 100", len(codes))
	}
}

// TestIsFileAllowed tests file extension validation
func TestIsFileAllowed(t *testing.T) {
	blocked := []string{".exe", ".bat", ".sh"}

	tests := []struct {
		name     string
		filename string
		blocked  []string
		want     bool
	}{
		{"allowed txt file", "document.txt", blocked, true},
		{"allowed pdf file", "report.pdf", blocked, true},
		{"blocked exe file", "malware.exe", blocked, false},
		{"blocked bat file", "script.bat", blocked, false},
		{"blocked sh file", "install.sh", blocked, false},
		{"case insensitive exe", "VIRUS.EXE", blocked, false},
		{"double extension exe", "document.pdf.exe", blocked, false},
		{"executable in name allowed", "executable-file.txt", blocked, true},
		{"no extension", "README", blocked, true},
		{"empty blocked list", "anything.exe", []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, _, err := IsFileAllowed(tt.filename, tt.blocked)
			if err != nil {
				t.Fatalf("IsFileAllowed() error: %v", err)
			}

			if allowed != tt.want {
				t.Errorf("IsFileAllowed(%q) = %v, want %v", tt.filename, allowed, tt.want)
			}
		})
	}
}

// TestIsFileAllowed_EmptyFilename tests error handling for empty filename
func TestIsFileAllowed_EmptyFilename(t *testing.T) {
	_, _, err := IsFileAllowed("", []string{".exe"})
	if err == nil {
		t.Error("IsFileAllowed(\"\") should return error for empty filename")
	}
}

// TestGetFileExtension tests extension extraction
func TestGetFileExtension(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"document.txt", ".txt"},
		{"archive.tar.gz", ".gz"},
		{"UPPERCASE.PDF", ".pdf"},
		{"no-extension", ""},
		{".hidden", ".hidden"},
		{"file.TXT", ".txt"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			ext := GetFileExtension(tt.filename)
			if ext != tt.want {
				t.Errorf("GetFileExtension(%q) = %q, want %q", tt.filename, ext, tt.want)
			}
		})
	}
}

// TestSanitizeFilename tests filename sanitization
func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     string
		contains string // substring that should be in output
	}{
		{
			name:  "normal filename",
			input: "document.txt",
			want:  "document.txt",
		},
		{
			name:     "path traversal removed",
			input:    "../../../etc/passwd",
			contains: "passwd",
		},
		{
			name:     "quotes removed",
			input:    `file"with"quotes.txt`,
			contains: "file_with_quotes.txt",
		},
		{
			name:  "newlines removed",
			input: "file\nwith\nnewlines.txt",
			want:  "file_with_newlines.txt",
		},
		{
			name:  "control chars removed",
			input: "file\x00\x01\x02.txt",
			want:  "file___.txt",
		},
		{
			name:  "empty string",
			input: "",
			want:  "download",
		},
		{
			name:  "only dots",
			input: "...",
			want:  "download",
		},
		{
			name:  "spaces preserved",
			input: "my document.txt",
			want:  "my document.txt",
		},
		{
			name:  "hyphens and underscores preserved",
			input: "my-file_name.txt",
			want:  "my-file_name.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeFilename(tt.input)

			if tt.want != "" && result != tt.want {
				t.Errorf("SanitizeFilename(%q) = %q, want %q", tt.input, result, tt.want)
			}

			if tt.contains != "" && !strings.Contains(result, tt.contains) {
				t.Errorf("SanitizeFilename(%q) = %q, should contain %q", tt.input, result, tt.contains)
			}

			// Verify length constraint
			if len(result) > 255 {
				t.Errorf("SanitizeFilename(%q) length = %d, should be <= 255", tt.input, len(result))
			}
		})
	}
}

// TestSanitizeFilename_LongFilename tests that long filenames are truncated
func TestSanitizeFilename_LongFilename(t *testing.T) {
	// Create a filename longer than 255 characters
	longName := strings.Repeat("a", 300) + ".txt"
	result := SanitizeFilename(longName)

	if len(result) > 255 {
		t.Errorf("SanitizeFilename() should truncate to 255 chars, got %d", len(result))
	}

	// Should preserve extension
	if !strings.HasSuffix(result, ".txt") {
		t.Error("SanitizeFilename() should preserve extension when truncating")
	}
}

// TestSanitizeForContentDisposition tests HTTP header sanitization
func TestSanitizeForContentDisposition(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple.txt", "simple.txt"},
		{`file"with"quotes.txt`, `file_with_quotes.txt`},
		{"file\nwith\nnewline.txt", "file_with_newline.txt"},
		{"../../../etc/passwd", "passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := SanitizeForContentDisposition(tt.input)

			// Should not contain quotes (they should be sanitized or escaped)
			if strings.Contains(result, `"`) {
				// If quotes are present, they should be escaped
				if !strings.Contains(result, `\"`) && strings.Contains(result, `"`) {
					t.Errorf("SanitizeForContentDisposition(%q) contains unescaped quotes", tt.input)
				}
			}
		})
	}
}

// TestFormatBytes tests byte formatting
func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes uint64
		want  string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"}, // 1.5 * 1024
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"}, // 1.5 * 1024 * 1024
		{1073741824, "1.0 GB"},
		{1099511627776, "1.0 TB"},
		{1125899906842624, "1.0 PB"},
		{1152921504606846976, "1.0 EB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			result := FormatBytes(tt.bytes)
			if result != tt.want {
				t.Errorf("FormatBytes(%d) = %q, want %q", tt.bytes, result, tt.want)
			}
		})
	}
}

// TestFormatBytes_Precision tests that formatting maintains precision
func TestFormatBytes_Precision(t *testing.T) {
	// Test that we get one decimal place
	result := FormatBytes(1536) // 1.5 KB
	if !strings.Contains(result, ".") {
		t.Error("FormatBytes() should include decimal point for non-whole numbers")
	}

	if !strings.HasPrefix(result, "1.5") {
		t.Errorf("FormatBytes(1536) = %q, want to start with '1.5'", result)
	}
}
