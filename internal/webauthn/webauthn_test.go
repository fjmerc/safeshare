// Package webauthn provides WebAuthn/FIDO2 authentication support for SafeShare.
package webauthn

import (
	"encoding/base64"
	"testing"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
)

func TestExtractRPID(t *testing.T) {
	tests := []struct {
		name      string
		publicURL string
		want      string
	}{
		{
			name:      "empty url",
			publicURL: "",
			want:      "",
		},
		{
			name:      "https url",
			publicURL: "https://share.example.com",
			want:      "share.example.com",
		},
		{
			name:      "http url",
			publicURL: "http://localhost",
			want:      "localhost",
		},
		{
			name:      "url with port",
			publicURL: "https://localhost:8080",
			want:      "localhost",
		},
		{
			name:      "url with path",
			publicURL: "https://example.com/safeshare",
			want:      "example.com",
		},
		{
			name:      "url with port and path",
			publicURL: "https://example.com:443/app/safeshare",
			want:      "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRPID(tt.publicURL)
			if got != tt.want {
				t.Errorf("extractRPID(%q) = %q, want %q", tt.publicURL, got, tt.want)
			}
		})
	}
}

func TestExtractOrigins(t *testing.T) {
	tests := []struct {
		name      string
		publicURL string
		wantLen   int
		wantFirst string
	}{
		{
			name:      "empty url",
			publicURL: "",
			wantLen:   0,
			wantFirst: "",
		},
		{
			name:      "simple url",
			publicURL: "https://example.com",
			wantLen:   1,
			wantFirst: "https://example.com",
		},
		{
			name:      "url with trailing slash",
			publicURL: "https://example.com/",
			wantLen:   1,
			wantFirst: "https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractOrigins(tt.publicURL)
			if len(got) != tt.wantLen {
				t.Errorf("extractOrigins(%q) returned %d origins, want %d", tt.publicURL, len(got), tt.wantLen)
			}
			if tt.wantLen > 0 && got[0] != tt.wantFirst {
				t.Errorf("extractOrigins(%q)[0] = %q, want %q", tt.publicURL, got[0], tt.wantFirst)
			}
		})
	}
}

func TestValidateSignCount(t *testing.T) {
	tests := []struct {
		name        string
		storedCount uint32
		newCount    uint32
		want        bool
	}{
		{
			name:        "both zero - valid (no sign count support)",
			storedCount: 0,
			newCount:    0,
			want:        true,
		},
		{
			name:        "new count greater - valid",
			storedCount: 5,
			newCount:    6,
			want:        true,
		},
		{
			name:        "new count equal - potential clone",
			storedCount: 5,
			newCount:    5,
			want:        false,
		},
		{
			name:        "new count less - potential clone",
			storedCount: 10,
			newCount:    5,
			want:        false,
		},
		{
			name:        "first use - stored zero new nonzero",
			storedCount: 0,
			newCount:    1,
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateSignCount(tt.storedCount, tt.newCount)
			if got != tt.want {
				t.Errorf("ValidateSignCount(%d, %d) = %v, want %v", tt.storedCount, tt.newCount, got, tt.want)
			}
		})
	}
}

func TestNewService_Disabled(t *testing.T) {
	// Test with MFA disabled
	cfg := &config.Config{
		MFA: nil,
	}

	_, err := NewService(cfg)
	if err == nil {
		t.Error("NewService should return error when MFA is nil")
	}

	// Test with MFA enabled but WebAuthn disabled
	cfg = &config.Config{
		MFA: &config.MFAConfig{
			Enabled:        true,
			WebAuthnEnabled: false,
		},
	}

	_, err = NewService(cfg)
	if err == nil {
		t.Error("NewService should return error when WebAuthn is disabled")
	}
}

func TestNewService_Enabled(t *testing.T) {
	cfg := &config.Config{
		PublicURL: "https://example.com",
		MFA: &config.MFAConfig{
			Enabled:                true,
			WebAuthnEnabled:        true,
			Issuer:                 "SafeShare Test",
			ChallengeExpiryMinutes: 5,
		},
	}

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	if svc == nil {
		t.Fatal("NewService returned nil service")
	}

	// Verify RPID is extracted correctly
	if rpID := svc.GetRPID(); rpID != "example.com" {
		t.Errorf("GetRPID() = %q, want %q", rpID, "example.com")
	}

	// Verify origins are set correctly
	origins := svc.GetRPOrigins()
	if len(origins) == 0 {
		t.Error("GetRPOrigins() returned empty slice")
	}
}

func TestNewService_DefaultValues(t *testing.T) {
	// Test with empty PublicURL to verify defaults
	cfg := &config.Config{
		PublicURL: "",
		MFA: &config.MFAConfig{
			Enabled:                true,
			WebAuthnEnabled:        true,
			Issuer:                 "SafeShare",
			ChallengeExpiryMinutes: 5,
		},
	}

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed with empty PublicURL: %v", err)
	}

	// Should default to localhost
	if rpID := svc.GetRPID(); rpID != "localhost" {
		t.Errorf("GetRPID() with empty PublicURL = %q, want %q", rpID, "localhost")
	}
}

func TestWebAuthnUser(t *testing.T) {
	user := &WebAuthnUser{
		ID:          123,
		Name:        "testuser",
		DisplayName: "Test User",
		Credentials: []gowebauthn.Credential{},
	}

	// Test WebAuthnID
	id := user.WebAuthnID()
	if string(id) != "123" {
		t.Errorf("WebAuthnID() = %q, want %q", string(id), "123")
	}

	// Test WebAuthnName
	if name := user.WebAuthnName(); name != "testuser" {
		t.Errorf("WebAuthnName() = %q, want %q", name, "testuser")
	}

	// Test WebAuthnDisplayName with display name set
	if displayName := user.WebAuthnDisplayName(); displayName != "Test User" {
		t.Errorf("WebAuthnDisplayName() = %q, want %q", displayName, "Test User")
	}

	// Test WebAuthnDisplayName without display name (should fallback to name)
	user.DisplayName = ""
	if displayName := user.WebAuthnDisplayName(); displayName != "testuser" {
		t.Errorf("WebAuthnDisplayName() without DisplayName = %q, want %q", displayName, "testuser")
	}

	// Test WebAuthnCredentials
	if creds := user.WebAuthnCredentials(); len(creds) != 0 {
		t.Errorf("WebAuthnCredentials() length = %d, want 0", len(creds))
	}

	// Test WebAuthnIcon (deprecated, always empty)
	if icon := user.WebAuthnIcon(); icon != "" {
		t.Errorf("WebAuthnIcon() = %q, want empty string", icon)
	}
}

func TestCredentialToWebAuthn(t *testing.T) {
	// Create a test credential
	credID := base64.StdEncoding.EncodeToString([]byte("test-credential-id"))
	pubKey := base64.StdEncoding.EncodeToString([]byte("test-public-key"))
	aaguid := base64.StdEncoding.EncodeToString([]byte("test-aaguid"))

	repoCred := &repository.WebAuthnCredential{
		UserID:          1,
		Name:            "My Key",
		CredentialID:    credID,
		PublicKey:       pubKey,
		AAGUID:          aaguid,
		SignCount:       5,
		Transports:      []string{"usb", "nfc"},
		UserVerified:    true,
		BackupEligible:  true,
		BackupState:     false,
		AttestationType: "none",
	}

	waCred, err := CredentialToWebAuthn(repoCred)
	if err != nil {
		t.Fatalf("CredentialToWebAuthn failed: %v", err)
	}

	if waCred.AttestationType != "none" {
		t.Errorf("AttestationType = %q, want %q", waCred.AttestationType, "none")
	}

	if waCred.Authenticator.SignCount != 5 {
		t.Errorf("SignCount = %d, want 5", waCred.Authenticator.SignCount)
	}

	if !waCred.Flags.UserVerified {
		t.Error("UserVerified flag should be true")
	}
}

func TestCredentialToWebAuthn_InvalidBase64(t *testing.T) {
	// Test with invalid credential ID
	repoCred := &repository.WebAuthnCredential{
		CredentialID: "not-valid-base64!!",
		PublicKey:    base64.StdEncoding.EncodeToString([]byte("key")),
	}

	_, err := CredentialToWebAuthn(repoCred)
	if err == nil {
		t.Error("CredentialToWebAuthn should fail with invalid credential ID")
	}

	// Test with invalid public key
	repoCred = &repository.WebAuthnCredential{
		CredentialID: base64.StdEncoding.EncodeToString([]byte("id")),
		PublicKey:    "not-valid-base64!!",
	}

	_, err = CredentialToWebAuthn(repoCred)
	if err == nil {
		t.Error("CredentialToWebAuthn should fail with invalid public key")
	}
}

func TestWebAuthnToCredential(t *testing.T) {
	waCred := &gowebauthn.Credential{
		ID:              []byte("test-id"),
		PublicKey:       []byte("test-public-key"),
		AttestationType: "direct",
		Authenticator: gowebauthn.Authenticator{
			AAGUID:    []byte("aaguid-bytes"),
			SignCount: 10,
		},
		Flags: gowebauthn.CredentialFlags{
			UserVerified:   true,
			BackupEligible: true,
			BackupState:    false,
		},
	}

	repoCred := WebAuthnToCredential(123, "My Security Key", waCred)

	if repoCred.UserID != 123 {
		t.Errorf("UserID = %d, want 123", repoCred.UserID)
	}

	if repoCred.Name != "My Security Key" {
		t.Errorf("Name = %q, want %q", repoCred.Name, "My Security Key")
	}

	if repoCred.SignCount != 10 {
		t.Errorf("SignCount = %d, want 10", repoCred.SignCount)
	}

	// Verify base64 encoding
	decodedID, _ := base64.StdEncoding.DecodeString(repoCred.CredentialID)
	if string(decodedID) != "test-id" {
		t.Errorf("Decoded CredentialID = %q, want %q", string(decodedID), "test-id")
	}
}

func TestWebAuthnToCredential_EmptyAAGUID(t *testing.T) {
	waCred := &gowebauthn.Credential{
		ID:        []byte("test-id"),
		PublicKey: []byte("test-public-key"),
		Authenticator: gowebauthn.Authenticator{
			AAGUID:    nil, // Empty AAGUID
			SignCount: 0,
		},
	}

	repoCred := WebAuthnToCredential(1, "Key", waCred)

	if repoCred.AAGUID != "" {
		t.Errorf("AAGUID should be empty for nil authenticator AAGUID, got %q", repoCred.AAGUID)
	}
}
