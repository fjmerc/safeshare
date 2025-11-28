package database

import (
	"database/sql"

	"github.com/fjmerc/safeshare/internal/webhooks"
)

// WebhookDBAdapter adapts database operations to the webhooks.DatabaseOperations interface
// This breaks the circular dependency between database and webhooks packages
type WebhookDBAdapter struct {
	db *sql.DB
}

// NewWebhookDBAdapter creates a new webhook database adapter
func NewWebhookDBAdapter(db *sql.DB) *WebhookDBAdapter {
	return &WebhookDBAdapter{db: db}
}

// GetEnabledWebhookConfigs retrieves all enabled webhook configurations
func (a *WebhookDBAdapter) GetEnabledWebhookConfigs() ([]*webhooks.Config, error) {
	return GetEnabledWebhookConfigs(a.db)
}

// CreateWebhookDelivery creates a new webhook delivery record
func (a *WebhookDBAdapter) CreateWebhookDelivery(delivery *webhooks.Delivery) error {
	return CreateWebhookDelivery(a.db, delivery)
}

// UpdateWebhookDelivery updates a webhook delivery record
func (a *WebhookDBAdapter) UpdateWebhookDelivery(delivery *webhooks.Delivery) error {
	return UpdateWebhookDelivery(a.db, delivery)
}

// GetWebhookConfig retrieves a webhook configuration by ID
func (a *WebhookDBAdapter) GetWebhookConfig(id int64) (*webhooks.Config, error) {
	return GetWebhookConfig(a.db, id)
}

// GetPendingRetries retrieves webhook deliveries that are due for retry
func (a *WebhookDBAdapter) GetPendingRetries() ([]*webhooks.Delivery, error) {
	return GetPendingRetries(a.db)
}
