-- Migration 019: Enterprise Configuration UI Support
--
-- Adds columns to settings table for MFA and SSO configuration.
-- This allows enterprise features to be configured via Admin UI
-- instead of requiring environment variables.
--
-- Date: 2025-12-10
-- Version: v1.5.0

-- ============================================================================
-- MFA CONFIGURATION COLUMNS
-- ============================================================================
-- These settings control MFA behavior when the MFA feature is enabled.
-- Default values match the environment variable defaults.

-- Whether MFA is required for all users (vs optional per-user)
ALTER TABLE settings ADD COLUMN mfa_required INTEGER NOT NULL DEFAULT 0;

-- TOTP issuer name shown in authenticator apps
ALTER TABLE settings ADD COLUMN mfa_issuer TEXT NOT NULL DEFAULT 'SafeShare';

-- Enable TOTP as MFA method (authenticator apps)
ALTER TABLE settings ADD COLUMN mfa_totp_enabled INTEGER NOT NULL DEFAULT 1;

-- Enable WebAuthn as MFA method (hardware keys, passkeys)
ALTER TABLE settings ADD COLUMN mfa_webauthn_enabled INTEGER NOT NULL DEFAULT 1;

-- Number of recovery codes to generate per user (5-20)
ALTER TABLE settings ADD COLUMN mfa_recovery_codes_count INTEGER NOT NULL DEFAULT 10;

-- How long MFA challenges are valid in minutes (1-30)
ALTER TABLE settings ADD COLUMN mfa_challenge_expiry_minutes INTEGER NOT NULL DEFAULT 5;

-- ============================================================================
-- SSO CONFIGURATION COLUMNS
-- ============================================================================
-- These settings control SSO behavior when the SSO feature is enabled.
-- Default values match the environment variable defaults.

-- Create users automatically on first SSO login
ALTER TABLE settings ADD COLUMN sso_auto_provision INTEGER NOT NULL DEFAULT 0;

-- Default role for auto-provisioned users ('user' or 'admin')
ALTER TABLE settings ADD COLUMN sso_default_role TEXT NOT NULL DEFAULT 'user';

-- SSO session lifetime in minutes (5-43200, default 8 hours)
ALTER TABLE settings ADD COLUMN sso_session_lifetime INTEGER NOT NULL DEFAULT 480;

-- OAuth2 state token expiry in minutes (5-60)
ALTER TABLE settings ADD COLUMN sso_state_expiry_minutes INTEGER NOT NULL DEFAULT 10;
