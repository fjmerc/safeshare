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
