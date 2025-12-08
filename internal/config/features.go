package config

import (
	"os"
	"strings"
	"sync"
)

// FeatureFlags controls which enterprise features are enabled.
// All flags default to false (disabled) for safety.
// Flags can be set via environment variables at startup and updated
// via the admin API at runtime.
type FeatureFlags struct {
	mu sync.RWMutex // Protects all fields for thread-safe access

	// Database backends
	enablePostgreSQL bool // Enable PostgreSQL database backend (Phase 2)

	// Storage backends
	enableS3Storage bool // Enable S3/MinIO storage backend (Phase 2)

	// Authentication
	enableSSO bool // Enable Single Sign-On via SAML/OIDC (Phase 3)
	enableMFA bool // Enable Multi-Factor Authentication (Phase 3)

	// Integrations
	enableWebhooks  bool // Enable webhook notifications (already implemented)
	enableAPITokens bool // Enable API token authentication (already implemented)

	// Security
	enableMalwareScan bool // Enable malware scanning integration (Phase 4)

	// Operations
	enableBackups bool // Enable automated backup functionality (Phase 4)
}

// NewFeatureFlags creates a new FeatureFlags instance with all flags disabled.
func NewFeatureFlags() *FeatureFlags {
	return &FeatureFlags{}
}

// Getters - thread-safe read access

// IsPostgreSQLEnabled returns whether PostgreSQL backend is enabled.
func (f *FeatureFlags) IsPostgreSQLEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.enablePostgreSQL
}

// IsS3StorageEnabled returns whether S3 storage backend is enabled.
func (f *FeatureFlags) IsS3StorageEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.enableS3Storage
}

// IsSSOEnabled returns whether Single Sign-On is enabled.
func (f *FeatureFlags) IsSSOEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.enableSSO
}

// IsMFAEnabled returns whether Multi-Factor Authentication is enabled.
func (f *FeatureFlags) IsMFAEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.enableMFA
}

// IsWebhooksEnabled returns whether webhook notifications are enabled.
func (f *FeatureFlags) IsWebhooksEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.enableWebhooks
}

// IsAPITokensEnabled returns whether API token authentication is enabled.
func (f *FeatureFlags) IsAPITokensEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.enableAPITokens
}

// IsMalwareScanEnabled returns whether malware scanning is enabled.
func (f *FeatureFlags) IsMalwareScanEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.enableMalwareScan
}

// IsBackupsEnabled returns whether automated backups are enabled.
func (f *FeatureFlags) IsBackupsEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.enableBackups
}

// Setters - thread-safe write access

// SetPostgreSQLEnabled enables or disables PostgreSQL backend.
func (f *FeatureFlags) SetPostgreSQLEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enablePostgreSQL = enabled
}

// SetS3StorageEnabled enables or disables S3 storage backend.
func (f *FeatureFlags) SetS3StorageEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableS3Storage = enabled
}

// SetSSOEnabled enables or disables Single Sign-On.
func (f *FeatureFlags) SetSSOEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableSSO = enabled
}

// SetMFAEnabled enables or disables Multi-Factor Authentication.
func (f *FeatureFlags) SetMFAEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableMFA = enabled
}

// SetWebhooksEnabled enables or disables webhook notifications.
func (f *FeatureFlags) SetWebhooksEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableWebhooks = enabled
}

// SetAPITokensEnabled enables or disables API token authentication.
func (f *FeatureFlags) SetAPITokensEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableAPITokens = enabled
}

// SetMalwareScanEnabled enables or disables malware scanning.
func (f *FeatureFlags) SetMalwareScanEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableMalwareScan = enabled
}

// SetBackupsEnabled enables or disables automated backups.
func (f *FeatureFlags) SetBackupsEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableBackups = enabled
}

// Bulk operations

// FeatureFlagsData represents the serializable form of feature flags
// for persistence and API responses.
type FeatureFlagsData struct {
	EnablePostgreSQL  bool `json:"enable_postgresql"`
	EnableS3Storage   bool `json:"enable_s3_storage"`
	EnableSSO         bool `json:"enable_sso"`
	EnableMFA         bool `json:"enable_mfa"`
	EnableWebhooks    bool `json:"enable_webhooks"`
	EnableAPITokens   bool `json:"enable_api_tokens"`
	EnableMalwareScan bool `json:"enable_malware_scan"`
	EnableBackups     bool `json:"enable_backups"`
}

// GetAll returns a snapshot of all feature flags.
// This is useful for API responses and persistence.
func (f *FeatureFlags) GetAll() FeatureFlagsData {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return FeatureFlagsData{
		EnablePostgreSQL:  f.enablePostgreSQL,
		EnableS3Storage:   f.enableS3Storage,
		EnableSSO:         f.enableSSO,
		EnableMFA:         f.enableMFA,
		EnableWebhooks:    f.enableWebhooks,
		EnableAPITokens:   f.enableAPITokens,
		EnableMalwareScan: f.enableMalwareScan,
		EnableBackups:     f.enableBackups,
	}
}

// SetAll updates all feature flags from a data snapshot.
// This is useful for loading from persistence or bulk API updates.
func (f *FeatureFlags) SetAll(data FeatureFlagsData) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enablePostgreSQL = data.EnablePostgreSQL
	f.enableS3Storage = data.EnableS3Storage
	f.enableSSO = data.EnableSSO
	f.enableMFA = data.EnableMFA
	f.enableWebhooks = data.EnableWebhooks
	f.enableAPITokens = data.EnableAPITokens
	f.enableMalwareScan = data.EnableMalwareScan
	f.enableBackups = data.EnableBackups
}

// loadFeatureFlags creates a FeatureFlags instance initialized from environment variables.
// Environment variables:
//   - FEATURE_POSTGRESQL: Enable PostgreSQL backend (default: false)
//   - FEATURE_S3_STORAGE: Enable S3 storage backend (default: false)
//   - FEATURE_SSO: Enable Single Sign-On (default: false)
//   - FEATURE_MFA: Enable Multi-Factor Authentication (default: false)
//   - FEATURE_WEBHOOKS: Enable webhook notifications (default: false)
//   - FEATURE_API_TOKENS: Enable API token authentication (default: false)
//   - FEATURE_MALWARE_SCAN: Enable malware scanning (default: false)
//   - FEATURE_BACKUPS: Enable automated backups (default: false)
//
// All flags default to false for safety.
func loadFeatureFlags() *FeatureFlags {
	f := NewFeatureFlags()

	// Load each flag from environment variables
	f.enablePostgreSQL = getEnvBoolFeature("FEATURE_POSTGRESQL", false)
	f.enableS3Storage = getEnvBoolFeature("FEATURE_S3_STORAGE", false)
	f.enableSSO = getEnvBoolFeature("FEATURE_SSO", false)
	f.enableMFA = getEnvBoolFeature("FEATURE_MFA", false)
	f.enableWebhooks = getEnvBoolFeature("FEATURE_WEBHOOKS", false)
	f.enableAPITokens = getEnvBoolFeature("FEATURE_API_TOKENS", false)
	f.enableMalwareScan = getEnvBoolFeature("FEATURE_MALWARE_SCAN", false)
	f.enableBackups = getEnvBoolFeature("FEATURE_BACKUPS", false)

	return f
}

// getEnvBoolFeature retrieves a boolean environment variable for feature flags.
// Accepts common boolean representations: true/false, 1/0, yes/no, on/off.
func getEnvBoolFeature(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "true" || value == "1" || value == "yes" || value == "on" {
			return true
		}
		if value == "false" || value == "0" || value == "no" || value == "off" {
			return false
		}
	}
	return defaultValue
}
