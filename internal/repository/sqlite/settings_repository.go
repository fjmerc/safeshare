package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/fjmerc/safeshare/internal/repository"
)

// Maximum allowed values for settings to prevent integer overflow and DoS.
const (
	maxExtensionLen       = 20
	maxBlockedExtsTotalLen = 10000
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
		       blocked_extensions
		FROM settings WHERE id = 1
	`

	var s repository.Settings
	var blockedExtsStr string

	err := r.db.QueryRowContext(ctx, query).Scan(
		&s.QuotaLimitGB,
		&s.MaxFileSizeBytes,
		&s.DefaultExpirationHours,
		&s.MaxExpirationHours,
		&s.RateLimitUpload,
		&s.RateLimitDownload,
		&blockedExtsStr,
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
