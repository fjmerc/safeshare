package utils

import "testing"

func TestMaskToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:     "empty token",
			token:    "",
			expected: "",
		},
		{
			name:     "very short token (3 chars)",
			token:    "abc",
			expected: "***",
		},
		{
			name:     "short token (6 chars)",
			token:    "abc123",
			expected: "***",
		},
		{
			name:     "normal token (12 chars)",
			token:    "abc123xyz789",
			expected: "abc***789",
		},
		{
			name:     "long token (32 chars)",
			token:    "abcdefghijklmnopqrstuvwxyz123456",
			expected: "abc***456",
		},
		{
			name:     "gotify style token",
			token:    "A1B2C3D4E5F6",
			expected: "A1B***5F6",
		},
		{
			name:     "ntfy style token",
			token:    "tk_abcdefghijklmnop123456",
			expected: "tk_***456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskToken(tt.token)
			if result != tt.expected {
				t.Errorf("MaskToken(%q) = %q, want %q", tt.token, result, tt.expected)
			}
		})
	}
}

func TestIsMaskedToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		// Valid masked tokens
		{name: "valid 9-char mask", token: "abc***xyz", expected: true},
		{name: "valid short mask", token: "***", expected: true},
		{name: "valid mask with numbers", token: "A1B***5F6", expected: true},
		{name: "valid mask tk prefix", token: "tk_***456", expected: true},
		
		// Invalid - wrong length
		{name: "empty string", token: "", expected: false},
		{name: "too short (8 chars)", token: "ab***xyz", expected: false},
		{name: "too long (10 chars)", token: "abc***xyza", expected: false},
		{name: "too long (12 chars)", token: "abc***xyz789", expected: false},
		
		// Invalid - asterisks in wrong position
		{name: "asterisks at start", token: "***abc***", expected: false},
		{name: "asterisks at end", token: "abc******", expected: false},
		{name: "asterisk in first 3 chars", token: "a*c***xyz", expected: false},
		{name: "asterisk in last 3 chars", token: "abc***x*z", expected: false},
		{name: "multiple asterisks first", token: "**c***xyz", expected: false},
		{name: "multiple asterisks last", token: "abc***x**", expected: false},
		
		// Invalid - wrong number of asterisks in middle
		{name: "2 asterisks in middle", token: "abc**xyzz", expected: false},
		{name: "4 asterisks in middle", token: "abc****yz", expected: false},
		{name: "1 asterisk in middle", token: "abcd*xyzz", expected: false},
		
		// Real-world tokens (should reject - false positives test)
		{name: "legitimate token with *** substring", token: "my***secret***token", expected: false},
		{name: "gotify token unmask", token: "A1B2C3D4E5F6G7H8", expected: false},
		{name: "ntfy token unmasked", token: "tk_abcdefghijklmnop", expected: false},
		{name: "long token with *** inside", token: "prefix***middle***suffix", expected: false},
		{name: "uuid style token", token: "550e8400-e29b-41d4-a716-446655440000", expected: false},
		
		// Edge cases
		{name: "all asterisks", token: "*********", expected: false},
		{name: "no asterisks", token: "abcdefxyz", expected: false},
		{name: "special chars with ***", token: "a!@***#$%", expected: true}, // Valid mask format
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMaskedToken(tt.token)
			if result != tt.expected {
				t.Errorf("IsMaskedToken(%q) = %v, want %v", tt.token, result, tt.expected)
			}
		})
	}
}
