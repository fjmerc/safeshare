package repository

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
}
