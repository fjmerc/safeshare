package repository

import "database/sql"

// Database types supported by SafeShare.
const (
	DatabaseTypeSQLite     = "sqlite"
	DatabaseTypePostgreSQL = "postgresql"
)

// Repositories holds all repository implementations.
// This struct provides a single point of access to all data access layers.
type Repositories struct {
	Files          FileRepository
	Users          UserRepository
	Admin          AdminRepository
	Settings       SettingsRepository
	PartialUploads PartialUploadRepository
	Webhooks       WebhookRepository
	APITokens      APITokenRepository
	RateLimits      RateLimitRepository
	Locks           LockRepository
	Health          HealthRepository
	BackupScheduler BackupSchedulerRepository
	MFA             MFARepository
	SSO             SSORepository

	// DB provides direct database access for code that hasn't been migrated to use repositories yet.
	// DEPRECATED: This field will be removed once all database access is migrated to use repositories.
	// Do not use this field in new code - use the appropriate repository interface instead.
	// Note: This is nil when using PostgreSQL.
	DB *sql.DB

	// DatabaseType indicates which database backend is being used.
	// One of: DatabaseTypeSQLite, DatabaseTypePostgreSQL
	DatabaseType string

	// Cleanup is a function to call when shutting down to release database resources.
	// For SQLite, this closes the database connection.
	// For PostgreSQL, this closes the connection pool.
	Cleanup func()
}
