package sqlite

import (
	"database/sql"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
)

// NewRepositories creates all SQLite repository implementations.
// The cfg parameter is included for consistency with other database backends.
// The db parameter must be a valid, open database connection.
//
// Returns the repositories struct with DatabaseType set to "sqlite" and
// a Cleanup function that closes the database connection.
func NewRepositories(cfg *config.Config, db *sql.DB) (*repository.Repositories, error) {
	if db == nil {
		return nil, repository.ErrNilDatabase
	}

	// Handle nil config gracefully for testing scenarios
	dbPath := ""
	if cfg != nil {
		dbPath = cfg.DBPath
	}

	return &repository.Repositories{
		Files:           NewFileRepository(db),
		Users:           NewUserRepository(db),
		Admin:           NewAdminRepository(db),
		Settings:        NewSettingsRepository(db),
		PartialUploads:  NewPartialUploadRepository(db),
		Webhooks:        NewWebhookRepository(db),
		APITokens:       NewAPITokenRepository(db),
		RateLimits:      NewRateLimitRepository(db),
		Locks:           NewLockRepository(db),
		Health:          NewHealthRepository(db, dbPath),
		BackupScheduler: NewBackupSchedulerRepository(db),
		MFA:             NewMFARepository(db),
		SSO:             NewSSORepository(db),
		DB:              db, // DEPRECATED: for backward compatibility during migration
		DatabaseType:    repository.DatabaseTypeSQLite,
		Cleanup: func() {
			db.Close()
		},
	}, nil
}
