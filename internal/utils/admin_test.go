package utils

import (
	"encoding/base64"
	"testing"
)

// TestGenerateSessionToken tests session token generation
func TestGenerateSessionToken(t *testing.T) {
	token, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken() error: %v", err)
	}

	if token == "" {
		t.Error("GenerateSessionToken() returned empty token")
	}

	// Decode to verify it's valid base64 URL encoding
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		t.Errorf("GenerateSessionToken() returned invalid base64: %v", err)
	}

	// Should decode to 32 bytes
	if len(decoded) != 32 {
		t.Errorf("GenerateSessionToken() decoded length = %d, want 32", len(decoded))
	}
}

// TestGenerateSessionToken_Uniqueness tests that tokens are unique
func TestGenerateSessionToken_Uniqueness(t *testing.T) {
	tokens := make(map[string]bool)

	// Generate 100 tokens and verify they're all unique
	for i := 0; i < 100; i++ {
		token, err := GenerateSessionToken()
		if err != nil {
			t.Fatalf("GenerateSessionToken() error: %v", err)
		}

		if tokens[token] {
			t.Errorf("GenerateSessionToken() generated duplicate token: %s", token)
		}

		tokens[token] = true
	}

	if len(tokens) != 100 {
		t.Errorf("Generated %d unique tokens, want 100", len(tokens))
	}
}

// TestGenerateCSRFToken tests CSRF token generation
func TestGenerateCSRFToken(t *testing.T) {
	token, err := GenerateCSRFToken()
	if err != nil {
		t.Fatalf("GenerateCSRFToken() error: %v", err)
	}

	if token == "" {
		t.Error("GenerateCSRFToken() returned empty token")
	}

	// Decode to verify it's valid base64 URL encoding
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		t.Errorf("GenerateCSRFToken() returned invalid base64: %v", err)
	}

	// Should decode to 32 bytes
	if len(decoded) != 32 {
		t.Errorf("GenerateCSRFToken() decoded length = %d, want 32", len(decoded))
	}
}

// TestGenerateCSRFToken_Uniqueness tests that CSRF tokens are unique
func TestGenerateCSRFToken_Uniqueness(t *testing.T) {
	tokens := make(map[string]bool)

	// Generate 100 tokens and verify they're all unique
	for i := 0; i < 100; i++ {
		token, err := GenerateCSRFToken()
		if err != nil {
			t.Fatalf("GenerateCSRFToken() error: %v", err)
		}

		if tokens[token] {
			t.Errorf("GenerateCSRFToken() generated duplicate token: %s", token)
		}

		tokens[token] = true
	}

	if len(tokens) != 100 {
		t.Errorf("Generated %d unique tokens, want 100", len(tokens))
	}
}

// TestTokensDifferent tests that session and CSRF tokens are different
func TestTokensDifferent(t *testing.T) {
	sessionToken, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken() error: %v", err)
	}

	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		t.Fatalf("GenerateCSRFToken() error: %v", err)
	}

	if sessionToken == csrfToken {
		t.Error("Session and CSRF tokens should be different")
	}
}
