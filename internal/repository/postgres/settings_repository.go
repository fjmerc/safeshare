// Package postgres provides PostgreSQL implementations of repository interfaces.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/fjmerc/safeshare/internal/repository"
)

// Maximum allowed values for settings to prevent integer overflow and DoS.
const (
	pgMaxExtensionLen       = 20
	pgMaxBlockedExtsTotalLen = 10000
)

// SettingsRepository implements repository.SettingsRepository for PostgreSQL.
type SettingsRepository struct {
	pool *Pool
}

// NewSettingsRepository creates a new PostgreSQL settings repository.
func NewSettingsRepository(pool *Pool) *SettingsRepository {
	return &SettingsRepository{pool: pool}
}

// Get retrieves all settings from the database.
// Returns nil, nil if no settings exist (indicating to use environment variable defaults).
func (r *SettingsRepository) Get(ctx context.Context) (*repository.Settings, error) {
	query := `
		SELECT quota_limit_gb, max_file_size_bytes, default_expiration_hours,
		       max_expiration_hours, rate_limit_upload, rate_limit_download,
		       blocked_extensions,
		       COALESCE(feature_postgresql, false), COALESCE(feature_s3_storage, false),
		       COALESCE(feature_sso, false), COALESCE(feature_mfa, false),
		       COALESCE(feature_webhooks, false), COALESCE(feature_api_tokens, false),
		       COALESCE(feature_malware_scan, false), COALESCE(feature_backups, false)
		FROM settings WHERE id = 1
	`

	var s repository.Settings
	var blockedExtsStr sql.NullString

	err := r.pool.QueryRow(ctx, query).Scan(
		&s.QuotaLimitGB,
		&s.MaxFileSizeBytes,
		&s.DefaultExpirationHours,
		&s.MaxExpirationHours,
		&s.RateLimitUpload,
		&s.RateLimitDownload,
		&blockedExtsStr,
		&s.FeaturePostgreSQL,
		&s.FeatureS3Storage,
		&s.FeatureSSO,
		&s.FeatureMFA,
		&s.FeatureWebhooks,
		&s.FeatureAPITokens,
		&s.FeatureMalwareScan,
		&s.FeatureBackups,
	)

	if err == pgx.ErrNoRows {
		// No settings exist yet - return nil to indicate use env var defaults
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}

	// Parse comma-separated blocked extensions
	if blockedExtsStr.Valid {
		s.BlockedExtensions = parseBlockedExtensions(blockedExtsStr.String)
	} else {
		s.BlockedExtensions = []string{}
	}

	return &s, nil
}

// UpdateQuota saves the quota_limit_gb setting to the database.
func (r *SettingsRepository) UpdateQuota(ctx context.Context, quotaGB int64) error {
	if quotaGB < 0 {
		return fmt.Errorf("quota cannot be negative")
	}

	query := `
		INSERT INTO settings (id, quota_limit_gb, updated_at) 
		VALUES (1, $1, NOW())
		ON CONFLICT (id) DO UPDATE SET 
			quota_limit_gb = EXCLUDED.quota_limit_gb,
			updated_at = NOW()
	`
	_, err := r.pool.Exec(ctx, query, quotaGB)
	if err != nil {
		return fmt.Errorf("failed to update quota setting: %w", err)
	}
	return nil
}

// UpdateMaxFileSize saves the max_file_size_bytes setting to the database.
func (r *SettingsRepository) UpdateMaxFileSize(ctx context.Context, sizeBytes int64) error {
	if sizeBytes < 0 {
		return fmt.Errorf("max file size cannot be negative")
	}

	query := `
		INSERT INTO settings (id, max_file_size_bytes, updated_at) 
		VALUES (1, $1, NOW())
		ON CONFLICT (id) DO UPDATE SET 
			max_file_size_bytes = EXCLUDED.max_file_size_bytes,
			updated_at = NOW()
	`
	_, err := r.pool.Exec(ctx, query, sizeBytes)
	if err != nil {
		return fmt.Errorf("failed to update max file size setting: %w", err)
	}
	return nil
}

// UpdateDefaultExpiration saves the default_expiration_hours setting to the database.
func (r *SettingsRepository) UpdateDefaultExpiration(ctx context.Context, hours int) error {
	if hours < 0 {
		return fmt.Errorf("default expiration hours cannot be negative")
	}

	query := `
		INSERT INTO settings (id, default_expiration_hours, updated_at) 
		VALUES (1, $1, NOW())
		ON CONFLICT (id) DO UPDATE SET 
			default_expiration_hours = EXCLUDED.default_expiration_hours,
			updated_at = NOW()
	`
	_, err := r.pool.Exec(ctx, query, hours)
	if err != nil {
		return fmt.Errorf("failed to update default expiration setting: %w", err)
	}
	return nil
}

// UpdateMaxExpiration saves the max_expiration_hours setting to the database.
func (r *SettingsRepository) UpdateMaxExpiration(ctx context.Context, hours int) error {
	if hours < 0 {
		return fmt.Errorf("max expiration hours cannot be negative")
	}

	query := `
		INSERT INTO settings (id, max_expiration_hours, updated_at) 
		VALUES (1, $1, NOW())
		ON CONFLICT (id) DO UPDATE SET 
			max_expiration_hours = EXCLUDED.max_expiration_hours,
			updated_at = NOW()
	`
	_, err := r.pool.Exec(ctx, query, hours)
	if err != nil {
		return fmt.Errorf("failed to update max expiration setting: %w", err)
	}
	return nil
}

// UpdateRateLimitUpload saves the rate_limit_upload setting to the database.
func (r *SettingsRepository) UpdateRateLimitUpload(ctx context.Context, limit int) error {
	if limit < 0 {
		return fmt.Errorf("rate limit upload cannot be negative")
	}

	query := `
		INSERT INTO settings (id, rate_limit_upload, updated_at) 
		VALUES (1, $1, NOW())
		ON CONFLICT (id) DO UPDATE SET 
			rate_limit_upload = EXCLUDED.rate_limit_upload,
			updated_at = NOW()
	`
	_, err := r.pool.Exec(ctx, query, limit)
	if err != nil {
		return fmt.Errorf("failed to update rate limit upload setting: %w", err)
	}
	return nil
}

// UpdateRateLimitDownload saves the rate_limit_download setting to the database.
func (r *SettingsRepository) UpdateRateLimitDownload(ctx context.Context, limit int) error {
	if limit < 0 {
		return fmt.Errorf("rate limit download cannot be negative")
	}

	query := `
		INSERT INTO settings (id, rate_limit_download, updated_at) 
		VALUES (1, $1, NOW())
		ON CONFLICT (id) DO UPDATE SET 
			rate_limit_download = EXCLUDED.rate_limit_download,
			updated_at = NOW()
	`
	_, err := r.pool.Exec(ctx, query, limit)
	if err != nil {
		return fmt.Errorf("failed to update rate limit download setting: %w", err)
	}
	return nil
}

// UpdateBlockedExtensions saves the blocked_extensions setting to the database.
func (r *SettingsRepository) UpdateBlockedExtensions(ctx context.Context, extensions []string) error {
	// Validate extensions
	for _, ext := range extensions {
		if strings.Contains(ext, ",") {
			return fmt.Errorf("extension cannot contain comma: %q", ext)
		}
		if len(ext) > pgMaxExtensionLen {
			return fmt.Errorf("extension too long (max %d chars): %q", pgMaxExtensionLen, ext)
		}
	}

	// Convert slice to comma-separated string
	extsStr := strings.Join(extensions, ",")

	// Guard against extremely long strings
	if len(extsStr) > pgMaxBlockedExtsTotalLen {
		return fmt.Errorf("blocked extensions list too long (max %d chars)", pgMaxBlockedExtsTotalLen)
	}

	query := `
		INSERT INTO settings (id, blocked_extensions, updated_at) 
		VALUES (1, $1, NOW())
		ON CONFLICT (id) DO UPDATE SET 
			blocked_extensions = EXCLUDED.blocked_extensions,
			updated_at = NOW()
	`
	_, err := r.pool.Exec(ctx, query, extsStr)
	if err != nil {
		return fmt.Errorf("failed to update blocked extensions setting: %w", err)
	}
	return nil
}

// GetFeatureFlags retrieves all feature flags from the database.
// Returns a FeatureFlags struct with all flags set to false if no settings exist.
func (r *SettingsRepository) GetFeatureFlags(ctx context.Context) (*repository.FeatureFlags, error) {
	query := `
		SELECT COALESCE(feature_postgresql, false), COALESCE(feature_s3_storage, false),
		       COALESCE(feature_sso, false), COALESCE(feature_mfa, false),
		       COALESCE(feature_webhooks, false), COALESCE(feature_api_tokens, false),
		       COALESCE(feature_malware_scan, false), COALESCE(feature_backups, false)
		FROM settings WHERE id = 1
	`

	var flags repository.FeatureFlags

	err := r.pool.QueryRow(ctx, query).Scan(
		&flags.EnablePostgreSQL,
		&flags.EnableS3Storage,
		&flags.EnableSSO,
		&flags.EnableMFA,
		&flags.EnableWebhooks,
		&flags.EnableAPITokens,
		&flags.EnableMalwareScan,
		&flags.EnableBackups,
	)

	if err == pgx.ErrNoRows {
		// No settings exist yet - return all flags as false
		return &repository.FeatureFlags{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get feature flags: %w", err)
	}

	return &flags, nil
}

// UpdateFeatureFlags saves all feature flags to the database.
func (r *SettingsRepository) UpdateFeatureFlags(ctx context.Context, flags *repository.FeatureFlags) error {
	if flags == nil {
		return fmt.Errorf("feature flags cannot be nil")
	}

	query := `
		INSERT INTO settings (
			id, feature_postgresql, feature_s3_storage, feature_sso, feature_mfa,
			feature_webhooks, feature_api_tokens, feature_malware_scan, feature_backups,
			updated_at
		) VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (id) DO UPDATE SET
			feature_postgresql = EXCLUDED.feature_postgresql,
			feature_s3_storage = EXCLUDED.feature_s3_storage,
			feature_sso = EXCLUDED.feature_sso,
			feature_mfa = EXCLUDED.feature_mfa,
			feature_webhooks = EXCLUDED.feature_webhooks,
			feature_api_tokens = EXCLUDED.feature_api_tokens,
			feature_malware_scan = EXCLUDED.feature_malware_scan,
			feature_backups = EXCLUDED.feature_backups,
			updated_at = NOW()
	`

	_, err := r.pool.Exec(ctx, query,
		flags.EnablePostgreSQL,
		flags.EnableS3Storage,
		flags.EnableSSO,
		flags.EnableMFA,
		flags.EnableWebhooks,
		flags.EnableAPITokens,
		flags.EnableMalwareScan,
		flags.EnableBackups,
	)
	if err != nil {
		return fmt.Errorf("failed to update feature flags: %w", err)
	}
	return nil
}

// Ensure SettingsRepository implements repository.SettingsRepository.
var _ repository.SettingsRepository = (*SettingsRepository)(nil)
