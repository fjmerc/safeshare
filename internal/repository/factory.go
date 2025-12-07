package repository

import "database/sql"

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

	// DB provides direct database access for code that hasn't been migrated to use repositories yet.
	// DEPRECATED: This field will be removed once all database access is migrated to use repositories.
	// Do not use this field in new code - use the appropriate repository interface instead.
	DB *sql.DB
}
