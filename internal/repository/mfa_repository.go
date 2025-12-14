// Package repository provides interfaces for data access operations.
package repository

import (
	"context"
	"errors"
	"time"
)

// MFA-related errors
var (
	// ErrMFANotEnabled is returned when an operation requires MFA to be enabled.
	ErrMFANotEnabled = errors.New("MFA is not enabled for this user")

	// ErrMFAAlreadyEnabled is returned when trying to set up MFA that's already enabled.
	ErrMFAAlreadyEnabled = errors.New("MFA is already enabled for this user")

	// ErrInvalidRecoveryCode is returned when a recovery code is invalid or already used.
	ErrInvalidRecoveryCode = errors.New("invalid or already used recovery code")

	// ErrWebAuthnCredentialNotFound is returned when a WebAuthn credential is not found.
	ErrWebAuthnCredentialNotFound = errors.New("WebAuthn credential not found")

	// ErrChallengeExpired is returned when an MFA challenge has expired.
	ErrChallengeExpired = errors.New("MFA challenge has expired")

	// ErrChallengeNotFound is returned when an MFA challenge is not found.
	ErrChallengeNotFound = errors.New("MFA challenge not found")
)

// UserMFA represents the MFA configuration for a user.
type UserMFA struct {
	ID             int64      `json:"id"`
	UserID         int64      `json:"user_id"`
	TOTPSecret     string     `json:"-"` // Never expose secret in JSON
	TOTPEnabled    bool       `json:"totp_enabled"`
	TOTPVerifiedAt *time.Time `json:"totp_verified_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// MFAStatus represents the MFA status for a user (used in API responses).
type MFAStatus struct {
	TOTPEnabled           bool   `json:"totp_enabled"`
	TOTPVerifiedAt        string `json:"totp_verified_at,omitempty"` // RFC3339 format
	WebAuthnEnabled       bool   `json:"webauthn_enabled"`
	WebAuthnCredentials   int    `json:"webauthn_credentials"`
	RecoveryCodesRemaining int   `json:"recovery_codes_remaining"`
}

// WebAuthnCredential represents a user's WebAuthn credential.
type WebAuthnCredential struct {
	ID              int64      `json:"id"`
	UserID          int64      `json:"user_id"`
	Name            string     `json:"name"`
	CredentialID    string     `json:"credential_id"` // Base64-encoded
	PublicKey       string     `json:"-"`             // Base64-encoded, don't expose in API
	AAGUID          string     `json:"aaguid,omitempty"`
	SignCount       uint32     `json:"sign_count"`
	Transports      []string   `json:"transports,omitempty"`
	UserVerified    bool       `json:"user_verified"`
	BackupEligible  bool       `json:"backup_eligible"`
	BackupState     bool       `json:"backup_state"`
	AttestationType string     `json:"attestation_type,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
}

// MFAChallenge represents a temporary challenge for WebAuthn operations.
type MFAChallenge struct {
	ID            int64     `json:"id"`
	UserID        int64     `json:"user_id"`
	Challenge     string    `json:"challenge"` // Base64-encoded
	ChallengeType string    `json:"challenge_type"` // "registration" or "authentication"
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
}

// MFARepository defines the interface for MFA database operations.
// All methods accept a context for cancellation and timeout support.
type MFARepository interface {
	// ===========================================================================
	// TOTP Operations
	// ===========================================================================

	// SetupTOTP initializes TOTP for a user with an encrypted secret.
	// Creates a new user_mfa record or updates existing one if TOTP is not yet enabled.
	// The secret should be encrypted before storage.
	// Returns ErrMFAAlreadyEnabled if TOTP is already enabled.
	SetupTOTP(ctx context.Context, userID int64, encryptedSecret string) error

	// GetTOTPSecret retrieves the encrypted TOTP secret for a user.
	// Returns empty string if no TOTP is configured.
	GetTOTPSecret(ctx context.Context, userID int64) (string, error)

	// EnableTOTP marks TOTP as verified and enabled for a user.
	// Should be called after the user successfully verifies their first TOTP code.
	// Sets totp_verified_at to current time.
	// Returns ErrNotFound if no TOTP setup exists for the user.
	EnableTOTP(ctx context.Context, userID int64) error

	// DisableTOTP disables TOTP for a user (clears secret and sets enabled to false).
	// Also deletes all recovery codes for the user.
	// Returns nil if TOTP was not enabled (idempotent).
	DisableTOTP(ctx context.Context, userID int64) error

	// IsTOTPEnabled checks if TOTP is enabled and verified for a user.
	IsTOTPEnabled(ctx context.Context, userID int64) (bool, error)

	// GetMFAStatus retrieves the full MFA status for a user.
	// Includes TOTP status, WebAuthn credential count, and remaining recovery codes.
	GetMFAStatus(ctx context.Context, userID int64) (*MFAStatus, error)

	// GetUserMFA retrieves the full MFA record for a user.
	// Returns nil, nil if no MFA is configured.
	GetUserMFA(ctx context.Context, userID int64) (*UserMFA, error)

	// ===========================================================================
	// Recovery Code Operations
	// ===========================================================================

	// CreateRecoveryCodes stores hashed recovery codes for a user.
	// Each code is stored as a bcrypt hash.
	// Typically called during TOTP setup (generates 10 codes).
	// Deletes any existing unused codes before creating new ones.
	CreateRecoveryCodes(ctx context.Context, userID int64, codeHashes []string) error

	// UseRecoveryCode attempts to use a recovery code.
	// Checks if the provided code matches any unused code hash.
	// If found and unused, marks it as used (sets used_at).
	// Returns ErrInvalidRecoveryCode if not found or already used.
	UseRecoveryCode(ctx context.Context, userID int64, code string) error

	// GetRecoveryCodeCount returns the count of remaining (unused) recovery codes.
	GetRecoveryCodeCount(ctx context.Context, userID int64) (int, error)

	// DeleteRecoveryCodes deletes all recovery codes for a user.
	// Called when disabling MFA or regenerating codes.
	DeleteRecoveryCodes(ctx context.Context, userID int64) error

	// ===========================================================================
	// WebAuthn Credential Operations
	// ===========================================================================

	// CreateWebAuthnCredential stores a new WebAuthn credential for a user.
	// Returns the created credential with populated ID.
	CreateWebAuthnCredential(ctx context.Context, cred *WebAuthnCredential) (*WebAuthnCredential, error)

	// GetWebAuthnCredentials retrieves all WebAuthn credentials for a user.
	GetWebAuthnCredentials(ctx context.Context, userID int64) ([]WebAuthnCredential, error)

	// GetWebAuthnCredentialByID retrieves a specific credential by ID.
	// Returns ErrWebAuthnCredentialNotFound if not found or doesn't belong to user.
	GetWebAuthnCredentialByID(ctx context.Context, credentialID int64, userID int64) (*WebAuthnCredential, error)

	// GetWebAuthnCredentialByCredentialID retrieves a credential by its credential ID.
	// The credentialID parameter is the base64-encoded credential ID from the authenticator.
	// Returns ErrWebAuthnCredentialNotFound if not found.
	GetWebAuthnCredentialByCredentialID(ctx context.Context, credentialID string) (*WebAuthnCredential, error)

	// UpdateWebAuthnCredentialSignCount updates the sign count for a credential.
	// Also updates last_used_at to current time.
	// This should be called after each successful authentication to prevent replay attacks.
	UpdateWebAuthnCredentialSignCount(ctx context.Context, credentialID int64, signCount uint32) error

	// UpdateWebAuthnCredentialName updates the user-friendly name of a credential.
	UpdateWebAuthnCredentialName(ctx context.Context, credentialID int64, userID int64, name string) error

	// DeleteWebAuthnCredential removes a WebAuthn credential.
	// Returns ErrWebAuthnCredentialNotFound if not found or doesn't belong to user.
	DeleteWebAuthnCredential(ctx context.Context, credentialID int64, userID int64) error

	// CountWebAuthnCredentials returns the number of WebAuthn credentials for a user.
	CountWebAuthnCredentials(ctx context.Context, userID int64) (int, error)

	// ===========================================================================
	// MFA Challenge Operations (for WebAuthn)
	// ===========================================================================

	// CreateChallenge creates a new WebAuthn challenge.
	// Deletes any existing challenge for the user of the same type first.
	CreateChallenge(ctx context.Context, userID int64, challenge, challengeType string, expiresAt time.Time) (*MFAChallenge, error)

	// GetChallenge retrieves a valid (non-expired) challenge.
	// Returns ErrChallengeNotFound if not found.
	// Returns ErrChallengeExpired if the challenge has expired.
	GetChallenge(ctx context.Context, userID int64, challengeType string) (*MFAChallenge, error)

	// DeleteChallenge removes a challenge after use.
	DeleteChallenge(ctx context.Context, userID int64, challengeType string) error

	// CleanupExpiredChallenges removes all expired challenges.
	// Returns the number of challenges deleted.
	CleanupExpiredChallenges(ctx context.Context) (int64, error)

	// ===========================================================================
	// Admin Operations
	// ===========================================================================

	// AdminDisableMFA disables all MFA methods for a user (admin operation).
	// Clears TOTP, deletes recovery codes, and removes WebAuthn credentials.
	AdminDisableMFA(ctx context.Context, userID int64) error

	// AdminGetMFAStatus retrieves MFA status for any user (admin operation).
	// Same as GetMFAStatus but without ownership check.
	AdminGetMFAStatus(ctx context.Context, userID int64) (*MFAStatus, error)
}
