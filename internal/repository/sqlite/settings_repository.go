package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/fjmerc/safeshare/internal/repository"
)

// Maximum allowed values for settings to prevent integer overflow and DoS.
const (
	maxExtensionLen        = 20
	maxBlockedExtsTotalLen = 10000
	maxIssuerLen           = 64
	maxRoleLen             = 20
)

// SettingsRepository implements repository.SettingsRepository for SQLite.
type SettingsRepository struct {
	db *sql.DB
}

// NewSettingsRepository creates a new SQLite settings repository.
func NewSettingsRepository(db *sql.DB) *SettingsRepository {
	return &SettingsRepository{db: db}
}

// Get retrieves all settings from the database.
// Returns nil, nil if no settings exist (indicating to use environment variable defaults).
func (r *SettingsRepository) Get(ctx context.Context) (*repository.Settings, error) {
	query := `
		SELECT quota_limit_gb, max_file_size_bytes, default_expiration_hours,
		       max_expiration_hours, rate_limit_upload, rate_limit_download,
		       blocked_extensions,
		       COALESCE(feature_postgresql, 0), COALESCE(feature_s3_storage, 0),
		       COALESCE(feature_sso, 0), COALESCE(feature_mfa, 0),
		       COALESCE(feature_webhooks, 0), COALESCE(feature_api_tokens, 0),
		       COALESCE(feature_malware_scan, 0), COALESCE(feature_backups, 0),
		       COALESCE(mfa_required, 0), COALESCE(mfa_issuer, 'SafeShare'),
		       COALESCE(mfa_totp_enabled, 1), COALESCE(mfa_webauthn_enabled, 1),
		       COALESCE(mfa_recovery_codes_count, 10), COALESCE(mfa_challenge_expiry_minutes, 5),
		       COALESCE(sso_auto_provision, 0), COALESCE(sso_default_role, 'user'),
		       COALESCE(sso_session_lifetime, 480), COALESCE(sso_state_expiry_minutes, 10)
		FROM settings WHERE id = 1
	`

	var s repository.Settings
	var blockedExtsStr string
	var featurePG, featureS3, featureSSO, featureMFA int
	var featureWebhooks, featureAPITokens, featureMalware, featureBackups int
	var mfaRequired, mfaTOTPEnabled, mfaWebAuthnEnabled int
	var ssoAutoProvision int

	err := r.db.QueryRowContext(ctx, query).Scan(
		&s.QuotaLimitGB,
		&s.MaxFileSizeBytes,
		&s.DefaultExpirationHours,
		&s.MaxExpirationHours,
		&s.RateLimitUpload,
		&s.RateLimitDownload,
		&blockedExtsStr,
		&featurePG, &featureS3, &featureSSO, &featureMFA,
		&featureWebhooks, &featureAPITokens, &featureMalware, &featureBackups,
		&mfaRequired, &s.MFAIssuer,
		&mfaTOTPEnabled, &mfaWebAuthnEnabled,
		&s.MFARecoveryCodesCount, &s.MFAChallengeExpiryMinutes,
		&ssoAutoProvision, &s.SSODefaultRole,
		&s.SSOSessionLifetime, &s.SSOStateExpiryMinutes,
	)

	if err == sql.ErrNoRows {
		// No settings exist yet - return nil to indicate use env var defaults
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}

	// Parse comma-separated blocked extensions
	s.BlockedExtensions = parseBlockedExtensions(blockedExtsStr)

	// Convert int to bool for feature flags
	s.FeaturePostgreSQL = featurePG != 0
	s.FeatureS3Storage = featureS3 != 0
	s.FeatureSSO = featureSSO != 0
	s.FeatureMFA = featureMFA != 0
	s.FeatureWebhooks = featureWebhooks != 0
	s.FeatureAPITokens = featureAPITokens != 0
	s.FeatureMalwareScan = featureMalware != 0
	s.FeatureBackups = featureBackups != 0

	// Convert int to bool for MFA config
	s.MFARequired = mfaRequired != 0
	s.MFATOTPEnabled = mfaTOTPEnabled != 0
	s.MFAWebAuthnEnabled = mfaWebAuthnEnabled != 0

	// Convert int to bool for SSO config
	s.SSOAutoProvision = ssoAutoProvision != 0

	return &s, nil
}

// UpdateQuota saves the quota_limit_gb setting to the database.
// Uses atomic UPSERT pattern to prevent race conditions.
func (r *SettingsRepository) UpdateQuota(ctx context.Context, quotaGB int64) error {
	if quotaGB < 0 {
		return fmt.Errorf("quota cannot be negative")
	}

	// Use UPSERT pattern for atomic operation
	query := `
		INSERT INTO settings (id, quota_limit_gb, updated_at) 
		VALUES (1, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET 
			quota_limit_gb = excluded.quota_limit_gb,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := r.db.ExecContext(ctx, query, quotaGB)
	if err != nil {
		return fmt.Errorf("failed to update quota setting: %w", err)
	}
	return nil
}

// UpdateMaxFileSize saves the max_file_size_bytes setting to the database.
// Uses atomic UPSERT pattern to prevent race conditions.
func (r *SettingsRepository) UpdateMaxFileSize(ctx context.Context, sizeBytes int64) error {
	if sizeBytes < 0 {
		return fmt.Errorf("max file size cannot be negative")
	}

	// Use UPSERT pattern for atomic operation
	query := `
		INSERT INTO settings (id, max_file_size_bytes, updated_at) 
		VALUES (1, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET 
			max_file_size_bytes = excluded.max_file_size_bytes,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := r.db.ExecContext(ctx, query, sizeBytes)
	if err != nil {
		return fmt.Errorf("failed to update max file size setting: %w", err)
	}
	return nil
}

// UpdateDefaultExpiration saves the default_expiration_hours setting to the database.
// Uses atomic UPSERT pattern to prevent race conditions.
func (r *SettingsRepository) UpdateDefaultExpiration(ctx context.Context, hours int) error {
	if hours < 0 {
		return fmt.Errorf("default expiration hours cannot be negative")
	}

	// Use UPSERT pattern for atomic operation
	query := `
		INSERT INTO settings (id, default_expiration_hours, updated_at) 
		VALUES (1, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET 
			default_expiration_hours = excluded.default_expiration_hours,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := r.db.ExecContext(ctx, query, hours)
	if err != nil {
		return fmt.Errorf("failed to update default expiration setting: %w", err)
	}
	return nil
}

// UpdateMaxExpiration saves the max_expiration_hours setting to the database.
// Uses atomic UPSERT pattern to prevent race conditions.
func (r *SettingsRepository) UpdateMaxExpiration(ctx context.Context, hours int) error {
	if hours < 0 {
		return fmt.Errorf("max expiration hours cannot be negative")
	}

	// Use UPSERT pattern for atomic operation
	query := `
		INSERT INTO settings (id, max_expiration_hours, updated_at) 
		VALUES (1, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET 
			max_expiration_hours = excluded.max_expiration_hours,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := r.db.ExecContext(ctx, query, hours)
	if err != nil {
		return fmt.Errorf("failed to update max expiration setting: %w", err)
	}
	return nil
}

// UpdateRateLimitUpload saves the rate_limit_upload setting to the database.
// Uses atomic UPSERT pattern to prevent race conditions.
func (r *SettingsRepository) UpdateRateLimitUpload(ctx context.Context, limit int) error {
	if limit < 0 {
		return fmt.Errorf("rate limit upload cannot be negative")
	}

	// Use UPSERT pattern for atomic operation
	query := `
		INSERT INTO settings (id, rate_limit_upload, updated_at) 
		VALUES (1, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET 
			rate_limit_upload = excluded.rate_limit_upload,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := r.db.ExecContext(ctx, query, limit)
	if err != nil {
		return fmt.Errorf("failed to update rate limit upload setting: %w", err)
	}
	return nil
}

// UpdateRateLimitDownload saves the rate_limit_download setting to the database.
// Uses atomic UPSERT pattern to prevent race conditions.
func (r *SettingsRepository) UpdateRateLimitDownload(ctx context.Context, limit int) error {
	if limit < 0 {
		return fmt.Errorf("rate limit download cannot be negative")
	}

	// Use UPSERT pattern for atomic operation
	query := `
		INSERT INTO settings (id, rate_limit_download, updated_at) 
		VALUES (1, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET 
			rate_limit_download = excluded.rate_limit_download,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := r.db.ExecContext(ctx, query, limit)
	if err != nil {
		return fmt.Errorf("failed to update rate limit download setting: %w", err)
	}
	return nil
}

// UpdateBlockedExtensions saves the blocked_extensions setting to the database.
// Uses atomic UPSERT pattern to prevent race conditions.
//
// Validation:
// - Extensions cannot contain commas (used as separator)
// - Each extension is limited to 20 characters
// - Total string length is limited to 10000 characters
func (r *SettingsRepository) UpdateBlockedExtensions(ctx context.Context, extensions []string) error {
	// Validate extensions
	for _, ext := range extensions {
		if strings.Contains(ext, ",") {
			return fmt.Errorf("extension cannot contain comma: %q", ext)
		}
		if len(ext) > maxExtensionLen {
			return fmt.Errorf("extension too long (max %d chars): %q", maxExtensionLen, ext)
		}
	}

	// Convert slice to comma-separated string
	extsStr := strings.Join(extensions, ",")

	// Guard against extremely long strings
	if len(extsStr) > maxBlockedExtsTotalLen {
		return fmt.Errorf("blocked extensions list too long (max %d chars)", maxBlockedExtsTotalLen)
	}

	// Use UPSERT pattern for atomic operation
	query := `
		INSERT INTO settings (id, blocked_extensions, updated_at) 
		VALUES (1, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET 
			blocked_extensions = excluded.blocked_extensions,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := r.db.ExecContext(ctx, query, extsStr)
	if err != nil {
		return fmt.Errorf("failed to update blocked extensions setting: %w", err)
	}
	return nil
}

// GetFeatureFlags retrieves all feature flags from the database.
// Returns a FeatureFlags struct with all flags set to false if no settings exist.
func (r *SettingsRepository) GetFeatureFlags(ctx context.Context) (*repository.FeatureFlags, error) {
	query := `
		SELECT COALESCE(feature_postgresql, 0), COALESCE(feature_s3_storage, 0),
		       COALESCE(feature_sso, 0), COALESCE(feature_mfa, 0),
		       COALESCE(feature_webhooks, 0), COALESCE(feature_api_tokens, 0),
		       COALESCE(feature_malware_scan, 0), COALESCE(feature_backups, 0)
		FROM settings WHERE id = 1
	`

	var featurePG, featureS3, featureSSO, featureMFA int
	var featureWebhooks, featureAPITokens, featureMalware, featureBackups int

	err := r.db.QueryRowContext(ctx, query).Scan(
		&featurePG, &featureS3, &featureSSO, &featureMFA,
		&featureWebhooks, &featureAPITokens, &featureMalware, &featureBackups,
	)

	if err == sql.ErrNoRows {
		// No settings exist yet - return all flags as false
		return &repository.FeatureFlags{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get feature flags: %w", err)
	}

	return &repository.FeatureFlags{
		EnablePostgreSQL:  featurePG != 0,
		EnableS3Storage:   featureS3 != 0,
		EnableSSO:         featureSSO != 0,
		EnableMFA:         featureMFA != 0,
		EnableWebhooks:    featureWebhooks != 0,
		EnableAPITokens:   featureAPITokens != 0,
		EnableMalwareScan: featureMalware != 0,
		EnableBackups:     featureBackups != 0,
	}, nil
}

// UpdateFeatureFlags saves all feature flags to the database.
// Uses atomic UPSERT pattern to prevent race conditions.
func (r *SettingsRepository) UpdateFeatureFlags(ctx context.Context, flags *repository.FeatureFlags) error {
	if flags == nil {
		return fmt.Errorf("feature flags cannot be nil")
	}

	// Convert bool to int for SQLite storage
	query := `
		INSERT INTO settings (
			id, feature_postgresql, feature_s3_storage, feature_sso, feature_mfa,
			feature_webhooks, feature_api_tokens, feature_malware_scan, feature_backups,
			updated_at
		) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			feature_postgresql = excluded.feature_postgresql,
			feature_s3_storage = excluded.feature_s3_storage,
			feature_sso = excluded.feature_sso,
			feature_mfa = excluded.feature_mfa,
			feature_webhooks = excluded.feature_webhooks,
			feature_api_tokens = excluded.feature_api_tokens,
			feature_malware_scan = excluded.feature_malware_scan,
			feature_backups = excluded.feature_backups,
			updated_at = CURRENT_TIMESTAMP
	`

	_, err := r.db.ExecContext(ctx, query,
		boolToInt(flags.EnablePostgreSQL),
		boolToInt(flags.EnableS3Storage),
		boolToInt(flags.EnableSSO),
		boolToInt(flags.EnableMFA),
		boolToInt(flags.EnableWebhooks),
		boolToInt(flags.EnableAPITokens),
		boolToInt(flags.EnableMalwareScan),
		boolToInt(flags.EnableBackups),
	)
	if err != nil {
		return fmt.Errorf("failed to update feature flags: %w", err)
	}
	return nil
}

// GetMFAConfig retrieves MFA configuration from the database.
// Returns default values if no settings exist.
func (r *SettingsRepository) GetMFAConfig(ctx context.Context) (*repository.MFAConfig, error) {
	query := `
		SELECT COALESCE(feature_mfa, 0),
		       COALESCE(mfa_required, 0), COALESCE(mfa_issuer, 'SafeShare'),
		       COALESCE(mfa_totp_enabled, 1), COALESCE(mfa_webauthn_enabled, 1),
		       COALESCE(mfa_recovery_codes_count, 10), COALESCE(mfa_challenge_expiry_minutes, 5)
		FROM settings WHERE id = 1
	`

	var enabled, required, totpEnabled, webauthnEnabled int
	var issuer string
	var recoveryCodesCount, challengeExpiryMinutes int

	err := r.db.QueryRowContext(ctx, query).Scan(
		&enabled, &required, &issuer,
		&totpEnabled, &webauthnEnabled,
		&recoveryCodesCount, &challengeExpiryMinutes,
	)

	if err == sql.ErrNoRows {
		// No settings exist - return defaults
		return &repository.MFAConfig{
			Enabled:                false,
			Required:               false,
			Issuer:                 "SafeShare",
			TOTPEnabled:            true,
			WebAuthnEnabled:        true,
			RecoveryCodesCount:     10,
			ChallengeExpiryMinutes: 5,
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get MFA config: %w", err)
	}

	return &repository.MFAConfig{
		Enabled:                enabled != 0,
		Required:               required != 0,
		Issuer:                 issuer,
		TOTPEnabled:            totpEnabled != 0,
		WebAuthnEnabled:        webauthnEnabled != 0,
		RecoveryCodesCount:     recoveryCodesCount,
		ChallengeExpiryMinutes: challengeExpiryMinutes,
	}, nil
}

// UpdateMFAConfig saves MFA configuration to the database.
// Uses atomic UPSERT pattern to prevent race conditions.
func (r *SettingsRepository) UpdateMFAConfig(ctx context.Context, cfg *repository.MFAConfig) error {
	if cfg == nil {
		return fmt.Errorf("MFA config cannot be nil")
	}

	// Validate issuer length
	if len(cfg.Issuer) == 0 {
		return fmt.Errorf("MFA issuer cannot be empty")
	}
	if len(cfg.Issuer) > maxIssuerLen {
		return fmt.Errorf("MFA issuer too long (max %d chars)", maxIssuerLen)
	}

	// Validate issuer contains only safe characters for TOTP URIs
	// Only allow alphanumeric, spaces, dashes, underscores, and periods
	issuerRegex := regexp.MustCompile(`^[a-zA-Z0-9 _.-]+$`)
	if !issuerRegex.MatchString(cfg.Issuer) {
		return fmt.Errorf("MFA issuer contains invalid characters; only alphanumeric, space, underscore, dash, and period are allowed")
	}

	// Validate recovery codes count (5-20)
	if cfg.RecoveryCodesCount < 5 || cfg.RecoveryCodesCount > 20 {
		return fmt.Errorf("recovery codes count must be between 5 and 20")
	}

	// Validate challenge expiry (1-30 minutes)
	if cfg.ChallengeExpiryMinutes < 1 || cfg.ChallengeExpiryMinutes > 30 {
		return fmt.Errorf("challenge expiry must be between 1 and 30 minutes")
	}

	// At least one MFA method must be enabled if MFA is enabled
	if cfg.Enabled && !cfg.TOTPEnabled && !cfg.WebAuthnEnabled {
		return fmt.Errorf("at least one MFA method must be enabled")
	}

	query := `
		INSERT INTO settings (
			id, feature_mfa, mfa_required, mfa_issuer,
			mfa_totp_enabled, mfa_webauthn_enabled,
			mfa_recovery_codes_count, mfa_challenge_expiry_minutes,
			updated_at
		) VALUES (1, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			feature_mfa = excluded.feature_mfa,
			mfa_required = excluded.mfa_required,
			mfa_issuer = excluded.mfa_issuer,
			mfa_totp_enabled = excluded.mfa_totp_enabled,
			mfa_webauthn_enabled = excluded.mfa_webauthn_enabled,
			mfa_recovery_codes_count = excluded.mfa_recovery_codes_count,
			mfa_challenge_expiry_minutes = excluded.mfa_challenge_expiry_minutes,
			updated_at = CURRENT_TIMESTAMP
	`

	_, err := r.db.ExecContext(ctx, query,
		boolToInt(cfg.Enabled),
		boolToInt(cfg.Required),
		cfg.Issuer,
		boolToInt(cfg.TOTPEnabled),
		boolToInt(cfg.WebAuthnEnabled),
		cfg.RecoveryCodesCount,
		cfg.ChallengeExpiryMinutes,
	)
	if err != nil {
		return fmt.Errorf("failed to update MFA config: %w", err)
	}
	return nil
}

// GetSSOConfig retrieves SSO configuration from the database.
// Returns default values if no settings exist.
func (r *SettingsRepository) GetSSOConfig(ctx context.Context) (*repository.SSOConfig, error) {
	query := `
		SELECT COALESCE(feature_sso, 0),
		       COALESCE(sso_auto_provision, 0), COALESCE(sso_default_role, 'user'),
		       COALESCE(sso_session_lifetime, 480), COALESCE(sso_state_expiry_minutes, 10)
		FROM settings WHERE id = 1
	`

	var enabled, autoProvision int
	var defaultRole string
	var sessionLifetime, stateExpiryMinutes int

	err := r.db.QueryRowContext(ctx, query).Scan(
		&enabled, &autoProvision, &defaultRole,
		&sessionLifetime, &stateExpiryMinutes,
	)

	if err == sql.ErrNoRows {
		// No settings exist - return defaults
		return &repository.SSOConfig{
			Enabled:            false,
			AutoProvision:      false,
			DefaultRole:        "user",
			SessionLifetime:    480,
			StateExpiryMinutes: 10,
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO config: %w", err)
	}

	return &repository.SSOConfig{
		Enabled:            enabled != 0,
		AutoProvision:      autoProvision != 0,
		DefaultRole:        defaultRole,
		SessionLifetime:    sessionLifetime,
		StateExpiryMinutes: stateExpiryMinutes,
	}, nil
}

// UpdateSSOConfig saves SSO configuration to the database.
// Uses atomic UPSERT pattern to prevent race conditions.
func (r *SettingsRepository) UpdateSSOConfig(ctx context.Context, cfg *repository.SSOConfig) error {
	if cfg == nil {
		return fmt.Errorf("SSO config cannot be nil")
	}

	// Validate default role
	if cfg.DefaultRole != "user" && cfg.DefaultRole != "admin" {
		return fmt.Errorf("default role must be 'user' or 'admin'")
	}

	// Security: Prevent auto-provisioning with admin role to avoid privilege escalation
	// All users from the IdP would automatically become admins, which is a significant security risk
	if cfg.AutoProvision && cfg.DefaultRole == "admin" {
		return fmt.Errorf("auto-provisioning with admin role is not allowed for security reasons; please manually promote users to admin after SSO login")
	}

	// Validate session lifetime (5-43200 minutes = 5 min to 30 days)
	if cfg.SessionLifetime < 5 || cfg.SessionLifetime > 43200 {
		return fmt.Errorf("session lifetime must be between 5 and 43200 minutes")
	}

	// Validate state expiry (5-60 minutes)
	if cfg.StateExpiryMinutes < 5 || cfg.StateExpiryMinutes > 60 {
		return fmt.Errorf("state expiry must be between 5 and 60 minutes")
	}

	query := `
		INSERT INTO settings (
			id, feature_sso, sso_auto_provision, sso_default_role,
			sso_session_lifetime, sso_state_expiry_minutes,
			updated_at
		) VALUES (1, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			feature_sso = excluded.feature_sso,
			sso_auto_provision = excluded.sso_auto_provision,
			sso_default_role = excluded.sso_default_role,
			sso_session_lifetime = excluded.sso_session_lifetime,
			sso_state_expiry_minutes = excluded.sso_state_expiry_minutes,
			updated_at = CURRENT_TIMESTAMP
	`

	_, err := r.db.ExecContext(ctx, query,
		boolToInt(cfg.Enabled),
		boolToInt(cfg.AutoProvision),
		cfg.DefaultRole,
		cfg.SessionLifetime,
		cfg.StateExpiryMinutes,
	)
	if err != nil {
		return fmt.Errorf("failed to update SSO config: %w", err)
	}
	return nil
}

// boolToInt converts a boolean to an integer (0 or 1) for SQLite storage.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// parseBlockedExtensions converts a comma-separated string to a slice of extensions.
func parseBlockedExtensions(s string) []string {
	if s == "" {
		return []string{}
	}

	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// Ensure SettingsRepository implements repository.SettingsRepository.
var _ repository.SettingsRepository = (*SettingsRepository)(nil)
