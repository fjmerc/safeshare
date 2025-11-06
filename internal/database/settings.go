package database

import (
	"database/sql"
	"fmt"
	"strings"
)

// Settings represents all admin-configurable settings stored in the database
type Settings struct {
	QuotaLimitGB           int64
	MaxFileSizeBytes       int64
	DefaultExpirationHours int
	MaxExpirationHours     int
	RateLimitUpload        int
	RateLimitDownload      int
	BlockedExtensions      []string
}

// GetSettings retrieves all settings from the database
// Returns nil if no settings exist (indicating to use environment variable defaults)
func GetSettings(db *sql.DB) (*Settings, error) {
	var s Settings
	var blockedExtsStr string

	query := `
		SELECT quota_limit_gb, max_file_size_bytes, default_expiration_hours,
		       max_expiration_hours, rate_limit_upload, rate_limit_download,
		       blocked_extensions
		FROM settings WHERE id = 1
	`

	err := db.QueryRow(query).Scan(
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

// ensureSettingsRow ensures a settings row exists (creates it if not)
func ensureSettingsRow(db *sql.DB) error {
	query := `INSERT OR IGNORE INTO settings (id) VALUES (1)`
	_, err := db.Exec(query)
	return err
}

// UpdateQuotaSetting saves the quota_limit_gb setting to the database
func UpdateQuotaSetting(db *sql.DB, quotaGB int64) error {
	if err := ensureSettingsRow(db); err != nil {
		return fmt.Errorf("failed to ensure settings row: %w", err)
	}

	query := `UPDATE settings SET quota_limit_gb = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1`
	_, err := db.Exec(query, quotaGB)
	if err != nil {
		return fmt.Errorf("failed to update quota setting: %w", err)
	}
	return nil
}

// UpdateMaxFileSizeSetting saves the max_file_size_bytes setting to the database
func UpdateMaxFileSizeSetting(db *sql.DB, sizeBytes int64) error {
	if err := ensureSettingsRow(db); err != nil {
		return fmt.Errorf("failed to ensure settings row: %w", err)
	}

	query := `UPDATE settings SET max_file_size_bytes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1`
	_, err := db.Exec(query, sizeBytes)
	if err != nil {
		return fmt.Errorf("failed to update max file size setting: %w", err)
	}
	return nil
}

// UpdateDefaultExpirationSetting saves the default_expiration_hours setting to the database
func UpdateDefaultExpirationSetting(db *sql.DB, hours int) error {
	if err := ensureSettingsRow(db); err != nil {
		return fmt.Errorf("failed to ensure settings row: %w", err)
	}

	query := `UPDATE settings SET default_expiration_hours = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1`
	_, err := db.Exec(query, hours)
	if err != nil {
		return fmt.Errorf("failed to update default expiration setting: %w", err)
	}
	return nil
}

// UpdateMaxExpirationSetting saves the max_expiration_hours setting to the database
func UpdateMaxExpirationSetting(db *sql.DB, hours int) error {
	if err := ensureSettingsRow(db); err != nil {
		return fmt.Errorf("failed to ensure settings row: %w", err)
	}

	query := `UPDATE settings SET max_expiration_hours = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1`
	_, err := db.Exec(query, hours)
	if err != nil {
		return fmt.Errorf("failed to update max expiration setting: %w", err)
	}
	return nil
}

// UpdateRateLimitUploadSetting saves the rate_limit_upload setting to the database
func UpdateRateLimitUploadSetting(db *sql.DB, limit int) error {
	if err := ensureSettingsRow(db); err != nil {
		return fmt.Errorf("failed to ensure settings row: %w", err)
	}

	query := `UPDATE settings SET rate_limit_upload = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1`
	_, err := db.Exec(query, limit)
	if err != nil {
		return fmt.Errorf("failed to update rate limit upload setting: %w", err)
	}
	return nil
}

// UpdateRateLimitDownloadSetting saves the rate_limit_download setting to the database
func UpdateRateLimitDownloadSetting(db *sql.DB, limit int) error {
	if err := ensureSettingsRow(db); err != nil {
		return fmt.Errorf("failed to ensure settings row: %w", err)
	}

	query := `UPDATE settings SET rate_limit_download = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1`
	_, err := db.Exec(query, limit)
	if err != nil {
		return fmt.Errorf("failed to update rate limit download setting: %w", err)
	}
	return nil
}

// UpdateBlockedExtensionsSetting saves the blocked_extensions setting to the database
func UpdateBlockedExtensionsSetting(db *sql.DB, extensions []string) error {
	if err := ensureSettingsRow(db); err != nil {
		return fmt.Errorf("failed to ensure settings row: %w", err)
	}

	// Convert slice to comma-separated string
	extsStr := strings.Join(extensions, ",")

	query := `UPDATE settings SET blocked_extensions = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1`
	_, err := db.Exec(query, extsStr)
	if err != nil {
		return fmt.Errorf("failed to update blocked extensions setting: %w", err)
	}
	return nil
}

// parseBlockedExtensions converts a comma-separated string to a slice of extensions
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
