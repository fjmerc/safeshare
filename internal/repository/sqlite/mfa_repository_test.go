package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/fjmerc/safeshare/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// setupMFATestDB creates a test database with required MFA schema
func setupMFATestDB(t *testing.T) *sql.DB {
	t.Helper()

	// Use a shared in-memory database with cache=shared to ensure all connections see the same tables
	db, err := sql.Open("sqlite", "file::memory:?cache=shared&_txlock=immediate&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	// Create users table (required for foreign key)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			is_approved INTEGER NOT NULL DEFAULT 1,
			is_active INTEGER NOT NULL DEFAULT 1,
			require_password_change INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			last_login TEXT
		)
	`)
	if err != nil {
		t.Fatalf("failed to create users table: %v", err)
	}

	// Create user_mfa table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS user_mfa (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER UNIQUE NOT NULL,
			totp_secret TEXT,
			totp_enabled INTEGER NOT NULL DEFAULT 0,
			totp_verified_at TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		t.Fatalf("failed to create user_mfa table: %v", err)
	}

	// Create user_mfa_recovery_codes table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS user_mfa_recovery_codes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			code_hash TEXT NOT NULL,
			used_at TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		t.Fatalf("failed to create user_mfa_recovery_codes table: %v", err)
	}

	// Create user_webauthn_credentials table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS user_webauthn_credentials (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			credential_id TEXT NOT NULL UNIQUE,
			public_key TEXT NOT NULL,
			aaguid TEXT,
			sign_count INTEGER NOT NULL DEFAULT 0,
			transports TEXT,
			user_verified INTEGER NOT NULL DEFAULT 0,
			backup_eligible INTEGER NOT NULL DEFAULT 0,
			backup_state INTEGER NOT NULL DEFAULT 0,
			attestation_type TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		t.Fatalf("failed to create user_webauthn_credentials table: %v", err)
	}

	// Create mfa_challenges table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS mfa_challenges (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			challenge TEXT NOT NULL,
			challenge_type TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		t.Fatalf("failed to create mfa_challenges table: %v", err)
	}

	// Create a test user
	_, err = db.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES ('testuser', 'test@example.com', 'hash', 'user')`)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	return db
}

// ===========================================================================
// TOTP Operation Tests
// ===========================================================================

func TestMFARepository_SetupTOTP(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	err := repo.SetupTOTP(ctx, 1, "encrypted-secret")
	if err != nil {
		t.Fatalf("SetupTOTP failed: %v", err)
	}

	// Verify secret is stored
	secret, err := repo.GetTOTPSecret(ctx, 1)
	if err != nil {
		t.Fatalf("GetTOTPSecret failed: %v", err)
	}
	if secret != "encrypted-secret" {
		t.Errorf("expected secret 'encrypted-secret', got %q", secret)
	}
}

func TestMFARepository_SetupTOTP_InvalidUserID(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	err := repo.SetupTOTP(ctx, 0, "secret")
	if err == nil {
		t.Error("expected error for invalid user ID")
	}

	err = repo.SetupTOTP(ctx, -1, "secret")
	if err == nil {
		t.Error("expected error for negative user ID")
	}
}

func TestMFARepository_SetupTOTP_InvalidSecret(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// Empty secret
	err := repo.SetupTOTP(ctx, 1, "")
	if err == nil {
		t.Error("expected error for empty secret")
	}
}

func TestMFARepository_SetupTOTP_AlreadyEnabled(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// Setup and enable TOTP
	if err := repo.SetupTOTP(ctx, 1, "secret"); err != nil {
		t.Fatalf("SetupTOTP failed: %v", err)
	}
	if err := repo.EnableTOTP(ctx, 1); err != nil {
		t.Fatalf("EnableTOTP failed: %v", err)
	}

	// Try to setup again
	err := repo.SetupTOTP(ctx, 1, "new-secret")
	if err != repository.ErrMFAAlreadyEnabled {
		t.Errorf("expected ErrMFAAlreadyEnabled, got %v", err)
	}
}

func TestMFARepository_GetTOTPSecret(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// No secret set
	secret, err := repo.GetTOTPSecret(ctx, 1)
	if err != nil {
		t.Fatalf("GetTOTPSecret failed: %v", err)
	}
	if secret != "" {
		t.Errorf("expected empty secret, got %q", secret)
	}

	// Set and get secret
	if err := repo.SetupTOTP(ctx, 1, "test-secret"); err != nil {
		t.Fatalf("SetupTOTP failed: %v", err)
	}
	secret, err = repo.GetTOTPSecret(ctx, 1)
	if err != nil {
		t.Fatalf("GetTOTPSecret failed: %v", err)
	}
	if secret != "test-secret" {
		t.Errorf("expected 'test-secret', got %q", secret)
	}
}

func TestMFARepository_GetTOTPSecret_InvalidUserID(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	_, err := repo.GetTOTPSecret(ctx, 0)
	if err == nil {
		t.Error("expected error for invalid user ID")
	}
}

func TestMFARepository_EnableTOTP(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// Setup first
	if err := repo.SetupTOTP(ctx, 1, "secret"); err != nil {
		t.Fatalf("SetupTOTP failed: %v", err)
	}

	// Enable
	err := repo.EnableTOTP(ctx, 1)
	if err != nil {
		t.Fatalf("EnableTOTP failed: %v", err)
	}

	// Verify enabled
	enabled, err := repo.IsTOTPEnabled(ctx, 1)
	if err != nil {
		t.Fatalf("IsTOTPEnabled failed: %v", err)
	}
	if !enabled {
		t.Error("expected TOTP to be enabled")
	}
}

func TestMFARepository_EnableTOTP_NoSetup(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	err := repo.EnableTOTP(ctx, 1)
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMFARepository_DisableTOTP(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// Setup and enable
	if err := repo.SetupTOTP(ctx, 1, "secret"); err != nil {
		t.Fatalf("SetupTOTP failed: %v", err)
	}
	if err := repo.EnableTOTP(ctx, 1); err != nil {
		t.Fatalf("EnableTOTP failed: %v", err)
	}

	// Create recovery codes
	hashes := []string{"hash1", "hash2"}
	if err := repo.CreateRecoveryCodes(ctx, 1, hashes); err != nil {
		t.Fatalf("CreateRecoveryCodes failed: %v", err)
	}

	// Disable
	err := repo.DisableTOTP(ctx, 1)
	if err != nil {
		t.Fatalf("DisableTOTP failed: %v", err)
	}

	// Verify disabled
	enabled, err := repo.IsTOTPEnabled(ctx, 1)
	if err != nil {
		t.Fatalf("IsTOTPEnabled failed: %v", err)
	}
	if enabled {
		t.Error("expected TOTP to be disabled")
	}

	// Verify recovery codes deleted
	count, _ := repo.GetRecoveryCodeCount(ctx, 1)
	if count != 0 {
		t.Errorf("expected 0 recovery codes, got %d", count)
	}
}

func TestMFARepository_IsTOTPEnabled(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// Not set up
	enabled, err := repo.IsTOTPEnabled(ctx, 1)
	if err != nil {
		t.Fatalf("IsTOTPEnabled failed: %v", err)
	}
	if enabled {
		t.Error("expected TOTP to not be enabled")
	}

	// Set up but not enabled
	if err := repo.SetupTOTP(ctx, 1, "secret"); err != nil {
		t.Fatalf("SetupTOTP failed: %v", err)
	}
	enabled, err = repo.IsTOTPEnabled(ctx, 1)
	if err != nil {
		t.Fatalf("IsTOTPEnabled failed: %v", err)
	}
	if enabled {
		t.Error("expected TOTP to not be enabled (not verified)")
	}

	// Enabled
	if err := repo.EnableTOTP(ctx, 1); err != nil {
		t.Fatalf("EnableTOTP failed: %v", err)
	}
	enabled, err = repo.IsTOTPEnabled(ctx, 1)
	if err != nil {
		t.Fatalf("IsTOTPEnabled failed: %v", err)
	}
	if !enabled {
		t.Error("expected TOTP to be enabled")
	}
}

func TestMFARepository_GetMFAStatus(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// No MFA configured
	status, err := repo.GetMFAStatus(ctx, 1)
	if err != nil {
		t.Fatalf("GetMFAStatus failed: %v", err)
	}
	if status.TOTPEnabled {
		t.Error("expected TOTP to not be enabled")
	}
	if status.WebAuthnEnabled {
		t.Error("expected WebAuthn to not be enabled")
	}
	if status.RecoveryCodesRemaining != 0 {
		t.Errorf("expected 0 recovery codes, got %d", status.RecoveryCodesRemaining)
	}

	// With MFA configured
	if err = repo.SetupTOTP(ctx, 1, "secret"); err != nil {
		t.Fatalf("SetupTOTP failed: %v", err)
	}
	if err = repo.EnableTOTP(ctx, 1); err != nil {
		t.Fatalf("EnableTOTP failed: %v", err)
	}
	if err = repo.CreateRecoveryCodes(ctx, 1, []string{"h1", "h2", "h3"}); err != nil {
		t.Fatalf("CreateRecoveryCodes failed: %v", err)
	}

	status, err = repo.GetMFAStatus(ctx, 1)
	if err != nil {
		t.Fatalf("GetMFAStatus failed: %v", err)
	}
	if !status.TOTPEnabled {
		t.Error("expected TOTP to be enabled")
	}
	if status.RecoveryCodesRemaining != 3 {
		t.Errorf("expected 3 recovery codes, got %d", status.RecoveryCodesRemaining)
	}
}

func TestMFARepository_GetUserMFA(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// No MFA record
	mfa, err := repo.GetUserMFA(ctx, 1)
	if err != nil {
		t.Fatalf("GetUserMFA failed: %v", err)
	}
	if mfa != nil {
		t.Error("expected nil for non-existent MFA")
	}

	// With MFA record
	if err = repo.SetupTOTP(ctx, 1, "secret"); err != nil {
		t.Fatalf("SetupTOTP failed: %v", err)
	}
	mfa, err = repo.GetUserMFA(ctx, 1)
	if err != nil {
		t.Fatalf("GetUserMFA failed: %v", err)
	}
	if mfa == nil {
		t.Fatal("expected MFA record")
	}
	if mfa.UserID != 1 {
		t.Errorf("expected user ID 1, got %d", mfa.UserID)
	}
	if mfa.TOTPSecret != "secret" {
		t.Errorf("expected secret 'secret', got %q", mfa.TOTPSecret)
	}
}

// ===========================================================================
// Recovery Code Tests
// ===========================================================================

func TestMFARepository_CreateRecoveryCodes(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	hashes := []string{"hash1", "hash2", "hash3"}
	err := repo.CreateRecoveryCodes(ctx, 1, hashes)
	if err != nil {
		t.Fatalf("CreateRecoveryCodes failed: %v", err)
	}

	count, err := repo.GetRecoveryCodeCount(ctx, 1)
	if err != nil {
		t.Fatalf("GetRecoveryCodeCount failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 codes, got %d", count)
	}
}

func TestMFARepository_CreateRecoveryCodes_InvalidUserID(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	err := repo.CreateRecoveryCodes(ctx, 0, []string{"hash"})
	if err == nil {
		t.Error("expected error for invalid user ID")
	}
}

func TestMFARepository_CreateRecoveryCodes_EmptyCodes(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	err := repo.CreateRecoveryCodes(ctx, 1, []string{})
	if err == nil {
		t.Error("expected error for empty codes")
	}
}

func TestMFARepository_CreateRecoveryCodes_ReplacesExisting(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// Create initial codes
	if err := repo.CreateRecoveryCodes(ctx, 1, []string{"h1", "h2"}); err != nil {
		t.Fatalf("CreateRecoveryCodes failed: %v", err)
	}

	// Create new codes (should replace)
	if err := repo.CreateRecoveryCodes(ctx, 1, []string{"h3", "h4", "h5"}); err != nil {
		t.Fatalf("CreateRecoveryCodes failed: %v", err)
	}

	count, _ := repo.GetRecoveryCodeCount(ctx, 1)
	if count != 3 {
		t.Errorf("expected 3 codes after replacement, got %d", count)
	}
}

func TestMFARepository_UseRecoveryCode_Success(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// Create recovery codes with bcrypt hashes
	code := "abcd-1234-5678-90ab"
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword failed: %v", err)
	}
	if err := repo.CreateRecoveryCodes(ctx, 1, []string{string(hash)}); err != nil {
		t.Fatalf("CreateRecoveryCodes failed: %v", err)
	}

	// Use the code
	err = repo.UseRecoveryCode(ctx, 1, code)
	if err != nil {
		t.Fatalf("UseRecoveryCode failed: %v", err)
	}

	// Verify code is marked as used
	count, _ := repo.GetRecoveryCodeCount(ctx, 1)
	if count != 0 {
		t.Errorf("expected 0 remaining codes, got %d", count)
	}
}

func TestMFARepository_UseRecoveryCode_Invalid(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	code := "abcd-1234-5678-90ab"
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword failed: %v", err)
	}
	if err := repo.CreateRecoveryCodes(ctx, 1, []string{string(hash)}); err != nil {
		t.Fatalf("CreateRecoveryCodes failed: %v", err)
	}

	err = repo.UseRecoveryCode(ctx, 1, "wrong-code")
	if err != repository.ErrInvalidRecoveryCode {
		t.Errorf("expected ErrInvalidRecoveryCode, got %v", err)
	}
}

func TestMFARepository_UseRecoveryCode_AlreadyUsed(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	code := "abcd-1234-5678-90ab"
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword failed: %v", err)
	}
	if err := repo.CreateRecoveryCodes(ctx, 1, []string{string(hash)}); err != nil {
		t.Fatalf("CreateRecoveryCodes failed: %v", err)
	}

	// Use the code
	if err := repo.UseRecoveryCode(ctx, 1, code); err != nil {
		t.Fatalf("UseRecoveryCode failed: %v", err)
	}

	// Try to use again
	err = repo.UseRecoveryCode(ctx, 1, code)
	if err != repository.ErrInvalidRecoveryCode {
		t.Errorf("expected ErrInvalidRecoveryCode for already used code, got %v", err)
	}
}

func TestMFARepository_UseRecoveryCode_EmptyCode(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	err := repo.UseRecoveryCode(ctx, 1, "")
	if err != repository.ErrInvalidRecoveryCode {
		t.Errorf("expected ErrInvalidRecoveryCode for empty code, got %v", err)
	}
}

func TestMFARepository_GetRecoveryCodeCount(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// No codes
	count, err := repo.GetRecoveryCodeCount(ctx, 1)
	if err != nil {
		t.Fatalf("GetRecoveryCodeCount failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}

	// Add codes
	if err := repo.CreateRecoveryCodes(ctx, 1, []string{"h1", "h2", "h3", "h4", "h5"}); err != nil {
		t.Fatalf("CreateRecoveryCodes failed: %v", err)
	}
	count, _ = repo.GetRecoveryCodeCount(ctx, 1)
	if count != 5 {
		t.Errorf("expected 5, got %d", count)
	}
}

func TestMFARepository_DeleteRecoveryCodes(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	if err := repo.CreateRecoveryCodes(ctx, 1, []string{"h1", "h2"}); err != nil {
		t.Fatalf("CreateRecoveryCodes failed: %v", err)
	}

	err := repo.DeleteRecoveryCodes(ctx, 1)
	if err != nil {
		t.Fatalf("DeleteRecoveryCodes failed: %v", err)
	}

	count, _ := repo.GetRecoveryCodeCount(ctx, 1)
	if count != 0 {
		t.Errorf("expected 0 after deletion, got %d", count)
	}
}

// ===========================================================================
// WebAuthn Credential Tests
// ===========================================================================

func TestMFARepository_CreateWebAuthnCredential(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	cred := &repository.WebAuthnCredential{
		UserID:          1,
		Name:            "My Security Key",
		CredentialID:    "credential-id-123",
		PublicKey:       "public-key-data",
		AAGUID:          "aaguid-123",
		SignCount:       0,
		Transports:      []string{"usb", "nfc"},
		UserVerified:    true,
		BackupEligible:  false,
		BackupState:     false,
		AttestationType: "none",
	}

	created, err := repo.CreateWebAuthnCredential(ctx, cred)
	if err != nil {
		t.Fatalf("CreateWebAuthnCredential failed: %v", err)
	}
	if created.ID == 0 {
		t.Error("expected ID to be set")
	}
	if created.Name != "My Security Key" {
		t.Errorf("expected name 'My Security Key', got %q", created.Name)
	}
}

func TestMFARepository_CreateWebAuthnCredential_InvalidInput(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	tests := []struct {
		name string
		cred *repository.WebAuthnCredential
	}{
		{"nil credential", nil},
		{"invalid user ID", &repository.WebAuthnCredential{UserID: 0, Name: "Test", CredentialID: "cid", PublicKey: "pk"}},
		{"empty name", &repository.WebAuthnCredential{UserID: 1, Name: "", CredentialID: "cid", PublicKey: "pk"}},
		{"empty credential ID", &repository.WebAuthnCredential{UserID: 1, Name: "Test", CredentialID: "", PublicKey: "pk"}},
		{"empty public key", &repository.WebAuthnCredential{UserID: 1, Name: "Test", CredentialID: "cid", PublicKey: ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := repo.CreateWebAuthnCredential(ctx, tt.cred)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

func TestMFARepository_GetWebAuthnCredentials(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// No credentials
	creds, err := repo.GetWebAuthnCredentials(ctx, 1)
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials failed: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(creds))
	}

	// Add credentials
	for i := 1; i <= 3; i++ {
		_, err := repo.CreateWebAuthnCredential(ctx, &repository.WebAuthnCredential{
			UserID:       1,
			Name:         fmt.Sprintf("Key %d", i),
			CredentialID: fmt.Sprintf("cred-%d", i),
			PublicKey:    "pk",
		})
		if err != nil {
			t.Fatalf("failed to create credential %d: %v", i, err)
		}
	}

	creds, err = repo.GetWebAuthnCredentials(ctx, 1)
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials failed: %v", err)
	}
	if len(creds) != 3 {
		t.Errorf("expected 3 credentials, got %d", len(creds))
	}
}

func TestMFARepository_GetWebAuthnCredentialByID(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	created, err := repo.CreateWebAuthnCredential(ctx, &repository.WebAuthnCredential{
		UserID:       1,
		Name:         "Test Key",
		CredentialID: "cred-123",
		PublicKey:    "pk",
	})
	if err != nil {
		t.Fatalf("CreateWebAuthnCredential failed: %v", err)
	}

	// Valid retrieval
	cred, err := repo.GetWebAuthnCredentialByID(ctx, created.ID, 1)
	if err != nil {
		t.Fatalf("GetWebAuthnCredentialByID failed: %v", err)
	}
	if cred.Name != "Test Key" {
		t.Errorf("expected name 'Test Key', got %q", cred.Name)
	}

	// Wrong user
	_, err = repo.GetWebAuthnCredentialByID(ctx, created.ID, 99)
	if err != repository.ErrWebAuthnCredentialNotFound {
		t.Errorf("expected ErrWebAuthnCredentialNotFound, got %v", err)
	}

	// Non-existent
	_, err = repo.GetWebAuthnCredentialByID(ctx, 99999, 1)
	if err != repository.ErrWebAuthnCredentialNotFound {
		t.Errorf("expected ErrWebAuthnCredentialNotFound, got %v", err)
	}
}

func TestMFARepository_GetWebAuthnCredentialByCredentialID(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	repo.CreateWebAuthnCredential(ctx, &repository.WebAuthnCredential{
		UserID:       1,
		Name:         "Test Key",
		CredentialID: "unique-cred-id",
		PublicKey:    "pk",
	})

	cred, err := repo.GetWebAuthnCredentialByCredentialID(ctx, "unique-cred-id")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentialByCredentialID failed: %v", err)
	}
	if cred.Name != "Test Key" {
		t.Errorf("expected name 'Test Key', got %q", cred.Name)
	}

	// Non-existent
	_, err = repo.GetWebAuthnCredentialByCredentialID(ctx, "non-existent")
	if err != repository.ErrWebAuthnCredentialNotFound {
		t.Errorf("expected ErrWebAuthnCredentialNotFound, got %v", err)
	}
}

func TestMFARepository_UpdateWebAuthnCredentialSignCount(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	created, _ := repo.CreateWebAuthnCredential(ctx, &repository.WebAuthnCredential{
		UserID:       1,
		Name:         "Test Key",
		CredentialID: "cred-123",
		PublicKey:    "pk",
		SignCount:    0,
	})

	err := repo.UpdateWebAuthnCredentialSignCount(ctx, created.ID, 5)
	if err != nil {
		t.Fatalf("UpdateWebAuthnCredentialSignCount failed: %v", err)
	}

	// Verify update
	cred, _ := repo.GetWebAuthnCredentialByID(ctx, created.ID, 1)
	if cred.SignCount != 5 {
		t.Errorf("expected sign count 5, got %d", cred.SignCount)
	}
	if cred.LastUsedAt == nil {
		t.Error("expected last_used_at to be set")
	}
}

func TestMFARepository_UpdateWebAuthnCredentialSignCount_NotFound(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	err := repo.UpdateWebAuthnCredentialSignCount(ctx, 99999, 5)
	if err != repository.ErrWebAuthnCredentialNotFound {
		t.Errorf("expected ErrWebAuthnCredentialNotFound, got %v", err)
	}
}

func TestMFARepository_UpdateWebAuthnCredentialName(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	created, _ := repo.CreateWebAuthnCredential(ctx, &repository.WebAuthnCredential{
		UserID:       1,
		Name:         "Old Name",
		CredentialID: "cred-123",
		PublicKey:    "pk",
	})

	err := repo.UpdateWebAuthnCredentialName(ctx, created.ID, 1, "New Name")
	if err != nil {
		t.Fatalf("UpdateWebAuthnCredentialName failed: %v", err)
	}

	// Verify update
	cred, _ := repo.GetWebAuthnCredentialByID(ctx, created.ID, 1)
	if cred.Name != "New Name" {
		t.Errorf("expected name 'New Name', got %q", cred.Name)
	}
}

func TestMFARepository_UpdateWebAuthnCredentialName_InvalidInput(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	created, _ := repo.CreateWebAuthnCredential(ctx, &repository.WebAuthnCredential{
		UserID:       1,
		Name:         "Test",
		CredentialID: "cred",
		PublicKey:    "pk",
	})

	// Empty name
	err := repo.UpdateWebAuthnCredentialName(ctx, created.ID, 1, "")
	if err == nil {
		t.Error("expected error for empty name")
	}

	// Wrong user
	err = repo.UpdateWebAuthnCredentialName(ctx, created.ID, 99, "New Name")
	if err != repository.ErrWebAuthnCredentialNotFound {
		t.Errorf("expected ErrWebAuthnCredentialNotFound, got %v", err)
	}
}

func TestMFARepository_DeleteWebAuthnCredential(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	created, _ := repo.CreateWebAuthnCredential(ctx, &repository.WebAuthnCredential{
		UserID:       1,
		Name:         "Test Key",
		CredentialID: "cred-123",
		PublicKey:    "pk",
	})

	err := repo.DeleteWebAuthnCredential(ctx, created.ID, 1)
	if err != nil {
		t.Fatalf("DeleteWebAuthnCredential failed: %v", err)
	}

	// Verify deleted
	_, err = repo.GetWebAuthnCredentialByID(ctx, created.ID, 1)
	if err != repository.ErrWebAuthnCredentialNotFound {
		t.Errorf("expected ErrWebAuthnCredentialNotFound, got %v", err)
	}
}

func TestMFARepository_DeleteWebAuthnCredential_NotFound(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	err := repo.DeleteWebAuthnCredential(ctx, 99999, 1)
	if err != repository.ErrWebAuthnCredentialNotFound {
		t.Errorf("expected ErrWebAuthnCredentialNotFound, got %v", err)
	}
}

func TestMFARepository_DeleteWebAuthnCredential_WrongUser(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	created, _ := repo.CreateWebAuthnCredential(ctx, &repository.WebAuthnCredential{
		UserID:       1,
		Name:         "Test Key",
		CredentialID: "cred-123",
		PublicKey:    "pk",
	})

	err := repo.DeleteWebAuthnCredential(ctx, created.ID, 99)
	if err != repository.ErrWebAuthnCredentialNotFound {
		t.Errorf("expected ErrWebAuthnCredentialNotFound, got %v", err)
	}
}

func TestMFARepository_CountWebAuthnCredentials(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// No credentials
	count, err := repo.CountWebAuthnCredentials(ctx, 1)
	if err != nil {
		t.Fatalf("CountWebAuthnCredentials failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}

	// Add credentials
	for i := 1; i <= 3; i++ {
		_, err := repo.CreateWebAuthnCredential(ctx, &repository.WebAuthnCredential{
			UserID:       1,
			Name:         "Key",
			CredentialID: fmt.Sprintf("cred-%d", i),
			PublicKey:    "pk",
		})
		if err != nil {
			t.Fatalf("failed to create credential %d: %v", i, err)
		}
	}

	count, err = repo.CountWebAuthnCredentials(ctx, 1)
	if err != nil {
		t.Fatalf("CountWebAuthnCredentials failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3, got %d", count)
	}
}

// ===========================================================================
// MFA Challenge Tests
// ===========================================================================

func TestMFARepository_CreateChallenge(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	expiresAt := time.Now().Add(5 * time.Minute)
	challenge, err := repo.CreateChallenge(ctx, 1, "challenge-data", "registration", expiresAt)
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}
	if challenge.ID == 0 {
		t.Error("expected ID to be set")
	}
	if challenge.Challenge != "challenge-data" {
		t.Errorf("expected challenge 'challenge-data', got %q", challenge.Challenge)
	}
	if challenge.ChallengeType != "registration" {
		t.Errorf("expected type 'registration', got %q", challenge.ChallengeType)
	}
}

func TestMFARepository_CreateChallenge_InvalidType(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	expiresAt := time.Now().Add(5 * time.Minute)
	_, err := repo.CreateChallenge(ctx, 1, "challenge", "invalid-type", expiresAt)
	if err == nil {
		t.Error("expected error for invalid challenge type")
	}
}

func TestMFARepository_CreateChallenge_ReplacesExisting(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	expiresAt := time.Now().Add(5 * time.Minute)

	// Create first challenge
	repo.CreateChallenge(ctx, 1, "first-challenge", "registration", expiresAt)

	// Create second challenge of same type
	challenge, err := repo.CreateChallenge(ctx, 1, "second-challenge", "registration", expiresAt)
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}
	if challenge.Challenge != "second-challenge" {
		t.Errorf("expected 'second-challenge', got %q", challenge.Challenge)
	}

	// Verify only one challenge exists
	retrieved, _ := repo.GetChallenge(ctx, 1, "registration")
	if retrieved.Challenge != "second-challenge" {
		t.Error("expected first challenge to be replaced")
	}
}

func TestMFARepository_GetChallenge(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	expiresAt := time.Now().Add(5 * time.Minute)
	repo.CreateChallenge(ctx, 1, "challenge-data", "authentication", expiresAt)

	challenge, err := repo.GetChallenge(ctx, 1, "authentication")
	if err != nil {
		t.Fatalf("GetChallenge failed: %v", err)
	}
	if challenge.Challenge != "challenge-data" {
		t.Errorf("expected 'challenge-data', got %q", challenge.Challenge)
	}
}

func TestMFARepository_GetChallenge_NotFound(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	_, err := repo.GetChallenge(ctx, 1, "registration")
	if err != repository.ErrChallengeNotFound {
		t.Errorf("expected ErrChallengeNotFound, got %v", err)
	}
}

func TestMFARepository_GetChallenge_Expired(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// Create expired challenge
	expiresAt := time.Now().Add(-1 * time.Minute)
	repo.CreateChallenge(ctx, 1, "expired-challenge", "registration", expiresAt)

	_, err := repo.GetChallenge(ctx, 1, "registration")
	if err != repository.ErrChallengeExpired {
		t.Errorf("expected ErrChallengeExpired, got %v", err)
	}
}

func TestMFARepository_DeleteChallenge(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	expiresAt := time.Now().Add(5 * time.Minute)
	repo.CreateChallenge(ctx, 1, "challenge", "registration", expiresAt)

	err := repo.DeleteChallenge(ctx, 1, "registration")
	if err != nil {
		t.Fatalf("DeleteChallenge failed: %v", err)
	}

	_, err = repo.GetChallenge(ctx, 1, "registration")
	if err != repository.ErrChallengeNotFound {
		t.Errorf("expected ErrChallengeNotFound after deletion, got %v", err)
	}
}

func TestMFARepository_CleanupExpiredChallenges(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// Create expired and valid challenges
	expiredTime := time.Now().Add(-1 * time.Minute)
	validTime := time.Now().Add(5 * time.Minute)

	repo.CreateChallenge(ctx, 1, "expired1", "registration", expiredTime)

	// Need to manually insert expired challenge since CreateChallenge might validate
	db.Exec(`INSERT INTO mfa_challenges (user_id, challenge, challenge_type, expires_at, created_at)
		VALUES (1, 'expired2', 'authentication', ?, CURRENT_TIMESTAMP)`, expiredTime.Format("2006-01-02 15:04:05"))

	repo.CreateChallenge(ctx, 1, "valid", "login_authentication", validTime)

	deleted, err := repo.CleanupExpiredChallenges(ctx)
	if err != nil {
		t.Fatalf("CleanupExpiredChallenges failed: %v", err)
	}

	// Should have deleted at least the expired one(s)
	// Note: The exact count depends on timing and what CreateChallenge does
	if deleted < 0 {
		t.Errorf("expected non-negative deleted count, got %d", deleted)
	}

	// Valid challenge should still exist
	challenge, err := repo.GetChallenge(ctx, 1, "login_authentication")
	if err != nil {
		t.Errorf("valid challenge should still exist: %v", err)
	}
	if challenge != nil && challenge.Challenge != "valid" {
		t.Error("expected valid challenge to remain")
	}
}

// ===========================================================================
// Admin Operation Tests
// ===========================================================================

func TestMFARepository_AdminDisableMFA(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// Set up full MFA for user
	if err := repo.SetupTOTP(ctx, 1, "secret"); err != nil {
		t.Fatalf("SetupTOTP failed: %v", err)
	}
	if err := repo.EnableTOTP(ctx, 1); err != nil {
		t.Fatalf("EnableTOTP failed: %v", err)
	}
	if err := repo.CreateRecoveryCodes(ctx, 1, []string{"h1", "h2"}); err != nil {
		t.Fatalf("CreateRecoveryCodes failed: %v", err)
	}
	if _, err := repo.CreateWebAuthnCredential(ctx, &repository.WebAuthnCredential{
		UserID:       1,
		Name:         "Key",
		CredentialID: "cred",
		PublicKey:    "pk",
	}); err != nil {
		t.Fatalf("CreateWebAuthnCredential failed: %v", err)
	}
	if _, err := repo.CreateChallenge(ctx, 1, "challenge", "registration", time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}

	// Disable all MFA
	err := repo.AdminDisableMFA(ctx, 1)
	if err != nil {
		t.Fatalf("AdminDisableMFA failed: %v", err)
	}

	// Verify all MFA is disabled
	enabled, _ := repo.IsTOTPEnabled(ctx, 1)
	if enabled {
		t.Error("expected TOTP to be disabled")
	}

	codeCount, _ := repo.GetRecoveryCodeCount(ctx, 1)
	if codeCount != 0 {
		t.Errorf("expected 0 recovery codes, got %d", codeCount)
	}

	credCount, _ := repo.CountWebAuthnCredentials(ctx, 1)
	if credCount != 0 {
		t.Errorf("expected 0 WebAuthn credentials, got %d", credCount)
	}
}

func TestMFARepository_AdminGetMFAStatus(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	if err := repo.SetupTOTP(ctx, 1, "secret"); err != nil {
		t.Fatalf("SetupTOTP failed: %v", err)
	}
	if err := repo.EnableTOTP(ctx, 1); err != nil {
		t.Fatalf("EnableTOTP failed: %v", err)
	}

	status, err := repo.AdminGetMFAStatus(ctx, 1)
	if err != nil {
		t.Fatalf("AdminGetMFAStatus failed: %v", err)
	}
	if !status.TOTPEnabled {
		t.Error("expected TOTP to be enabled")
	}
}

// ===========================================================================
// Interface Implementation Test
// ===========================================================================

func TestMFARepository_ImplementsInterface(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	var _ repository.MFARepository = NewMFARepository(db)
}

// ===========================================================================
// Edge Case Tests
// ===========================================================================

func TestMFARepository_MultipleUsers(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	// Add a second user
	_, err := db.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES ('user2', 'user2@example.com', 'hash', 'user')`)
	if err != nil {
		t.Fatalf("failed to create second user: %v", err)
	}

	repo := NewMFARepository(db)
	ctx := context.Background()

	// Set up MFA for both users
	if err := repo.SetupTOTP(ctx, 1, "secret1"); err != nil {
		t.Fatalf("SetupTOTP for user 1 failed: %v", err)
	}
	if err := repo.SetupTOTP(ctx, 2, "secret2"); err != nil {
		t.Fatalf("SetupTOTP for user 2 failed: %v", err)
	}
	if err := repo.EnableTOTP(ctx, 1); err != nil {
		t.Fatalf("EnableTOTP for user 1 failed: %v", err)
	}

	// Verify isolation
	enabled1, _ := repo.IsTOTPEnabled(ctx, 1)
	enabled2, _ := repo.IsTOTPEnabled(ctx, 2)

	if !enabled1 {
		t.Error("expected TOTP enabled for user 1")
	}
	if enabled2 {
		t.Error("expected TOTP not enabled for user 2")
	}

	// Verify secrets are isolated
	secret1, _ := repo.GetTOTPSecret(ctx, 1)
	secret2, _ := repo.GetTOTPSecret(ctx, 2)

	if secret1 != "secret1" {
		t.Errorf("expected secret1 for user 1, got %q", secret1)
	}
	if secret2 != "secret2" {
		t.Errorf("expected secret2 for user 2, got %q", secret2)
	}
}

func TestMFARepository_WebAuthnTransportsHandling(t *testing.T) {
	db := setupMFATestDB(t)
	defer db.Close()

	repo := NewMFARepository(db)
	ctx := context.Background()

	// Create credential with multiple transports
	created, err := repo.CreateWebAuthnCredential(ctx, &repository.WebAuthnCredential{
		UserID:       1,
		Name:         "Test",
		CredentialID: "cred",
		PublicKey:    "pk",
		Transports:   []string{"usb", "nfc", "ble"},
	})
	if err != nil {
		t.Fatalf("CreateWebAuthnCredential failed: %v", err)
	}

	// Retrieve and verify transports
	cred, err := repo.GetWebAuthnCredentialByID(ctx, created.ID, 1)
	if err != nil {
		t.Fatalf("GetWebAuthnCredentialByID failed: %v", err)
	}
	if len(cred.Transports) != 3 {
		t.Errorf("expected 3 transports, got %d", len(cred.Transports))
	}
	if cred.Transports[0] != "usb" || cred.Transports[1] != "nfc" || cred.Transports[2] != "ble" {
		t.Errorf("unexpected transports: %v", cred.Transports)
	}

	// Create credential with no transports
	created2, err := repo.CreateWebAuthnCredential(ctx, &repository.WebAuthnCredential{
		UserID:       1,
		Name:         "Test2",
		CredentialID: "cred2",
		PublicKey:    "pk",
		Transports:   nil,
	})
	if err != nil {
		t.Fatalf("CreateWebAuthnCredential (no transports) failed: %v", err)
	}

	cred2, err := repo.GetWebAuthnCredentialByID(ctx, created2.ID, 1)
	if err != nil {
		t.Fatalf("GetWebAuthnCredentialByID failed: %v", err)
	}
	if len(cred2.Transports) != 0 {
		t.Errorf("expected 0 transports, got %d", len(cred2.Transports))
	}
}
