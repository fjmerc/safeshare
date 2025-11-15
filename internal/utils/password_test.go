package utils

import (
	"strings"
	"testing"
)

// TestHashPassword tests password hashing
func TestHashPassword(t *testing.T) {
	password := "mySecurePassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	if hash == "" {
		t.Error("HashPassword() returned empty hash")
	}

	if hash == password {
		t.Error("HashPassword() returned plaintext password instead of hash")
	}

	// Bcrypt hashes start with $2a$, $2b$, or $2y$
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("HashPassword() hash format invalid: %s", hash)
	}
}

// TestHashPassword_Empty tests hashing empty password
func TestHashPassword_Empty(t *testing.T) {
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword(\"\") error: %v", err)
	}

	if hash != "" {
		t.Error("HashPassword(\"\") should return empty string")
	}
}

// TestHashPassword_Unique tests that same password produces different hashes
func TestHashPassword_Unique(t *testing.T) {
	password := "testPassword"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	// Bcrypt generates different hashes for same password (due to salt)
	if hash1 == hash2 {
		t.Error("HashPassword() should generate different hashes for same password (salted)")
	}
}

// TestVerifyPassword tests password verification
func TestVerifyPassword(t *testing.T) {
	password := "correctPassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	// Test correct password
	if !VerifyPassword(hash, password) {
		t.Error("VerifyPassword() should return true for correct password")
	}

	// Test incorrect password
	if VerifyPassword(hash, "wrongPassword") {
		t.Error("VerifyPassword() should return false for incorrect password")
	}

	// Test empty password with empty hash
	if !VerifyPassword("", "") {
		t.Error("VerifyPassword(\"\", \"\") should return true")
	}

	// Test empty password with hash
	if VerifyPassword(hash, "") {
		t.Error("VerifyPassword() should return false for empty password when hash exists")
	}
}

// TestIsPasswordProtected tests password protection check
func TestIsPasswordProtected(t *testing.T) {
	tests := []struct {
		name         string
		passwordHash string
		want         bool
	}{
		{"empty hash", "", false},
		{"with hash", "$2a$10$abcdef...", true},
		{"non-empty string", "something", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPasswordProtected(tt.passwordHash)
			if result != tt.want {
				t.Errorf("IsPasswordProtected(%q) = %v, want %v", tt.passwordHash, result, tt.want)
			}
		})
	}
}

// TestGenerateTemporaryPassword tests temporary password generation
func TestGenerateTemporaryPassword(t *testing.T) {
	password, err := GenerateTemporaryPassword()
	if err != nil {
		t.Fatalf("GenerateTemporaryPassword() error: %v", err)
	}

	if password == "" {
		t.Error("GenerateTemporaryPassword() returned empty password")
	}

	// Should have format: word-word-word-number
	parts := strings.Split(password, "-")
	if len(parts) != 4 {
		t.Errorf("GenerateTemporaryPassword() = %q, want 4 parts separated by dashes", password)
	}

	// Last part should be a number
	lastPart := parts[3]
	if len(lastPart) < 3 || lastPart[0] < '1' || lastPart[0] > '9' {
		t.Errorf("GenerateTemporaryPassword() last part should be a 3-digit number, got %q", lastPart)
	}

	// First three parts should be words (alphabetic)
	for i := 0; i < 3; i++ {
		for _, char := range parts[i] {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')) {
				t.Errorf("GenerateTemporaryPassword() word %d contains non-alphabetic character: %q", i+1, parts[i])
			}
		}
	}
}

// TestGenerateTemporaryPassword_Uniqueness tests password uniqueness
func TestGenerateTemporaryPassword_Uniqueness(t *testing.T) {
	passwords := make(map[string]bool)

	// Generate 50 passwords and verify they're all unique
	for i := 0; i < 50; i++ {
		password, err := GenerateTemporaryPassword()
		if err != nil {
			t.Fatalf("GenerateTemporaryPassword() error: %v", err)
		}

		if passwords[password] {
			t.Errorf("GenerateTemporaryPassword() generated duplicate: %s", password)
		}

		passwords[password] = true
	}

	if len(passwords) != 50 {
		t.Errorf("Generated %d unique passwords, want 50", len(passwords))
	}
}

// TestPasswordWorkflow tests complete password workflow
func TestPasswordWorkflow(t *testing.T) {
	// Generate temporary password
	tempPassword, err := GenerateTemporaryPassword()
	if err != nil {
		t.Fatalf("GenerateTemporaryPassword() error: %v", err)
	}

	// Hash the password
	hash, err := HashPassword(tempPassword)
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	// Verify it's password protected
	if !IsPasswordProtected(hash) {
		t.Error("IsPasswordProtected() should return true after hashing")
	}

	// Verify the password works
	if !VerifyPassword(hash, tempPassword) {
		t.Error("VerifyPassword() should return true for correct temporary password")
	}

	// Verify wrong password fails
	if VerifyPassword(hash, "wrongPassword") {
		t.Error("VerifyPassword() should return false for wrong password")
	}
}
