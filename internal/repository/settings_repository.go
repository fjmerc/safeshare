package repository

import "context"

// Settings represents all admin-configurable settings stored in the database.
type Settings struct {
	QuotaLimitGB           int64
	MaxFileSizeBytes       int64
	DefaultExpirationHours int
	MaxExpirationHours     int
	RateLimitUpload        int
	RateLimitDownload      int
	BlockedExtensions      []string

	// Feature flags
	FeaturePostgreSQL  bool
	FeatureS3Storage   bool
	FeatureSSO         bool
	FeatureMFA         bool
	FeatureWebhooks    bool
	FeatureAPITokens   bool
	FeatureMalwareScan bool
	FeatureBackups     bool

	// MFA configuration
	MFARequired               bool
	MFAIssuer                 string
	MFATOTPEnabled            bool
	MFAWebAuthnEnabled        bool
	MFARecoveryCodesCount     int
	MFAChallengeExpiryMinutes int

	// SSO configuration
	SSOAutoProvision      bool
	SSODefaultRole        string
	SSOSessionLifetime    int
	SSOStateExpiryMinutes int
}

// SettingsRepository defines the interface for settings-related database operations.
// All methods accept a context for cancellation and timeout support.
type SettingsRepository interface {
	// Get retrieves all settings from the database.
	// Returns nil, nil if no settings exist (indicating to use environment variable defaults).
	Get(ctx context.Context) (*Settings, error)

	// UpdateQuota saves the quota_limit_gb setting to the database.
	UpdateQuota(ctx context.Context, quotaGB int64) error

	// UpdateMaxFileSize saves the max_file_size_bytes setting to the database.
	UpdateMaxFileSize(ctx context.Context, sizeBytes int64) error

	// UpdateDefaultExpiration saves the default_expiration_hours setting to the database.
	UpdateDefaultExpiration(ctx context.Context, hours int) error

	// UpdateMaxExpiration saves the max_expiration_hours setting to the database.
	UpdateMaxExpiration(ctx context.Context, hours int) error

	// UpdateRateLimitUpload saves the rate_limit_upload setting to the database.
	UpdateRateLimitUpload(ctx context.Context, limit int) error

	// UpdateRateLimitDownload saves the rate_limit_download setting to the database.
	UpdateRateLimitDownload(ctx context.Context, limit int) error

	// UpdateBlockedExtensions saves the blocked_extensions setting to the database.
	UpdateBlockedExtensions(ctx context.Context, extensions []string) error

	// GetFeatureFlags retrieves all feature flags from the database.
	// Returns a FeatureFlags struct. If no settings exist, all flags are false.
	GetFeatureFlags(ctx context.Context) (*FeatureFlags, error)

	// UpdateFeatureFlags saves all feature flags to the database.
	UpdateFeatureFlags(ctx context.Context, flags *FeatureFlags) error

	// GetMFAConfig retrieves MFA configuration from the database.
	// Returns default values if no settings exist.
	GetMFAConfig(ctx context.Context) (*MFAConfig, error)

	// UpdateMFAConfig saves MFA configuration to the database.
	UpdateMFAConfig(ctx context.Context, cfg *MFAConfig) error

	// GetSSOConfig retrieves SSO configuration from the database.
	// Returns default values if no settings exist.
	GetSSOConfig(ctx context.Context) (*SSOConfig, error)

	// UpdateSSOConfig saves SSO configuration to the database.
	UpdateSSOConfig(ctx context.Context, cfg *SSOConfig) error
}

// FeatureFlags represents the persisted feature flag settings.
type FeatureFlags struct {
	EnablePostgreSQL  bool
	EnableS3Storage   bool
	EnableSSO         bool
	EnableMFA         bool
	EnableWebhooks    bool
	EnableAPITokens   bool
	EnableMalwareScan bool
	EnableBackups     bool
}

// MFAConfig represents persisted MFA configuration settings.
type MFAConfig struct {
	// Enabled indicates whether MFA feature is enabled (synced with feature flag)
	Enabled bool
	// Required indicates whether MFA is required for all users
	Required bool
	// Issuer is the TOTP issuer name shown in authenticator apps
	Issuer string
	// TOTPEnabled indicates whether TOTP is available as MFA method
	TOTPEnabled bool
	// WebAuthnEnabled indicates whether WebAuthn/hardware keys are available
	WebAuthnEnabled bool
	// RecoveryCodesCount is the number of recovery codes to generate (5-20)
	RecoveryCodesCount int
	// ChallengeExpiryMinutes is how long MFA challenges are valid (1-30)
	ChallengeExpiryMinutes int
}

// SSOConfig represents persisted SSO configuration settings.
type SSOConfig struct {
	// Enabled indicates whether SSO feature is enabled (synced with feature flag)
	Enabled bool
	// AutoProvision creates users automatically on first SSO login
	AutoProvision bool
	// DefaultRole is the role assigned to auto-provisioned users ('user' or 'admin')
	DefaultRole string
	// SessionLifetime is the SSO session duration in minutes (5-43200)
	SessionLifetime int
	// StateExpiryMinutes is how long OAuth2 state tokens are valid (5-60)
	StateExpiryMinutes int
}
