package sqlite

import (
	"database/sql"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
)

// NewRepositories creates all SQLite repository implementations.
// Currently only SQLite is supported, but this factory allows for easy extension
// to support other database backends in the future.
//
// The cfg parameter is included for future extensibility (e.g., database type selection).
// The db parameter must be a valid, open database connection.
func NewRepositories(cfg *config.Config, db *sql.DB) (*repository.Repositories, error) {
	if db == nil {
		return nil, repository.ErrNilDatabase
	}

	return &repository.Repositories{
		Files:          NewFileRepository(db),
		Users:          NewUserRepository(db),
		Admin:          NewAdminRepository(db),
		Settings:       NewSettingsRepository(db),
		PartialUploads: NewPartialUploadRepository(db),
		Webhooks:       NewWebhookRepository(db),
		APITokens:      NewAPITokenRepository(db),
		DB:             db, // DEPRECATED: for backward compatibility during migration
	}, nil
}
