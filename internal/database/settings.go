package database

import (
	"database/sql"
	"fmt"
)

// Settings table schema is created in db.go InitDB()

// GetQuotaSetting retrieves the quota_limit_gb setting from the database
// Returns -1 if no setting exists (indicating to use environment variable default)
func GetQuotaSetting(db *sql.DB) (int64, error) {
	var quotaGB int64
	query := `SELECT quota_limit_gb FROM settings WHERE id = 1`

	err := db.QueryRow(query).Scan(&quotaGB)
	if err == sql.ErrNoRows {
		// No setting exists yet - return -1 to indicate use env var default
		return -1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to get quota setting: %w", err)
	}

	return quotaGB, nil
}

// UpdateQuotaSetting saves the quota_limit_gb setting to the database
// Creates the row if it doesn't exist (UPSERT)
func UpdateQuotaSetting(db *sql.DB, quotaGB int64) error {
	query := `
		INSERT INTO settings (id, quota_limit_gb)
		VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET quota_limit_gb = excluded.quota_limit_gb
	`

	_, err := db.Exec(query, quotaGB)
	if err != nil {
		return fmt.Errorf("failed to update quota setting: %w", err)
	}

	return nil
}
