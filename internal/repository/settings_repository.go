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
