-- Migration 017: Multi-Factor Authentication support
--
-- Creates tables for MFA (TOTP and WebAuthn):
-- - user_mfa: TOTP secrets and configuration per user
-- - user_mfa_recovery_codes: Single-use recovery codes
-- - user_webauthn_credentials: WebAuthn/FIDO2 hardware key credentials
--
-- Date: 2025-12-09
-- Version: v1.3.0

-- ============================================================================
-- USER MFA TABLE (TOTP configuration per user)
-- ============================================================================
-- Stores TOTP configuration for each user.
-- The totp_secret is encrypted with the system encryption key.
-- A user can only have one TOTP configuration at a time.
CREATE TABLE IF NOT EXISTS user_mfa (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    totp_secret TEXT,                         -- Encrypted TOTP secret (base32 format before encryption)
    totp_enabled INTEGER NOT NULL DEFAULT 0,  -- Whether TOTP is verified and active
    totp_verified_at DATETIME,                -- When TOTP was verified/enabled
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_mfa_user_id ON user_mfa(user_id);

-- ============================================================================
-- USER MFA RECOVERY CODES TABLE
-- ============================================================================
-- Stores single-use recovery codes for users with MFA enabled.
-- Each user gets 10 codes during MFA setup.
-- Codes are bcrypt hashed for security (like passwords).
-- Once used, the used_at timestamp is set.
CREATE TABLE IF NOT EXISTS user_mfa_recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,                  -- bcrypt hash of the recovery code
    used_at DATETIME,                         -- NULL if not used yet
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_mfa_recovery_codes_user_id ON user_mfa_recovery_codes(user_id);
-- Composite index for efficient lookup of unused codes
CREATE INDEX IF NOT EXISTS idx_user_mfa_recovery_codes_user_unused ON user_mfa_recovery_codes(user_id, used_at);

-- ============================================================================
-- USER WEBAUTHN CREDENTIALS TABLE
-- ============================================================================
-- Stores WebAuthn/FIDO2 credentials (hardware security keys, passkeys, etc.)
-- A user can have multiple WebAuthn credentials (e.g., multiple Yubikeys)
CREATE TABLE IF NOT EXISTS user_webauthn_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,                       -- User-friendly name (e.g., "My YubiKey 5")
    credential_id TEXT NOT NULL UNIQUE,       -- Base64-encoded credential ID from authenticator
    public_key TEXT NOT NULL,                 -- Base64-encoded COSE public key
    aaguid TEXT,                              -- Authenticator Attestation GUID (identifies device type)
    sign_count INTEGER NOT NULL DEFAULT 0,    -- Counter to detect cloned keys
    transports TEXT,                          -- Comma-separated transports (usb, nfc, ble, internal)
    user_verified INTEGER NOT NULL DEFAULT 0, -- Whether user verification was performed at registration
    backup_eligible INTEGER NOT NULL DEFAULT 0,   -- Whether credential is backup eligible
    backup_state INTEGER NOT NULL DEFAULT 0,      -- Whether credential is currently backed up
    attestation_type TEXT,                    -- Attestation type (none, indirect, direct, etc.)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_webauthn_credentials_user_id ON user_webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_user_webauthn_credentials_credential_id ON user_webauthn_credentials(credential_id);

-- ============================================================================
-- MFA CHALLENGES TABLE (for WebAuthn authentication flow)
-- ============================================================================
-- Stores temporary challenges for WebAuthn authentication.
-- Challenges expire after a short time (typically 5 minutes).
CREATE TABLE IF NOT EXISTS mfa_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    challenge TEXT NOT NULL UNIQUE,           -- Base64-encoded random challenge
    challenge_type TEXT NOT NULL,             -- 'registration' or 'authentication'
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_id ON mfa_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires_at ON mfa_challenges(expires_at);
