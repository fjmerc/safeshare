package repository

import (
	"context"

	"github.com/fjmerc/safeshare/internal/webhooks"
)

// WebhookRepository defines the interface for webhook-related database operations.
// All methods accept a context for cancellation and timeout support.
type WebhookRepository interface {
	// Config operations

	// CreateConfig creates a new webhook configuration.
	// The config.ID field will be populated with the generated ID on success.
	CreateConfig(ctx context.Context, config *webhooks.Config) error

	// GetConfig retrieves a webhook configuration by ID.
	// Returns ErrNotFound if the config doesn't exist.
	GetConfig(ctx context.Context, id int64) (*webhooks.Config, error)

	// GetAllConfigs retrieves all webhook configurations.
	GetAllConfigs(ctx context.Context) ([]*webhooks.Config, error)

	// GetEnabledConfigs retrieves all enabled webhook configurations.
	GetEnabledConfigs(ctx context.Context) ([]*webhooks.Config, error)

	// UpdateConfig updates an existing webhook configuration.
	// Returns ErrNotFound if the config doesn't exist.
	UpdateConfig(ctx context.Context, config *webhooks.Config) error

	// UpdateConfigPreserveMasked atomically updates webhook config while preserving masked fields.
	// This prevents TOCTOU race conditions by using conditional SQL updates.
	// If preserveSecret is true, the existing secret is preserved.
	// If preserveToken is true, the existing service_token is preserved.
	UpdateConfigPreserveMasked(ctx context.Context, config *webhooks.Config, preserveSecret, preserveToken bool) error

	// DeleteConfig deletes a webhook configuration.
	// Returns ErrNotFound if the config doesn't exist.
	DeleteConfig(ctx context.Context, id int64) error

	// Delivery operations

	// CreateDelivery creates a new webhook delivery record.
	// The delivery.ID field will be populated with the generated ID on success.
	CreateDelivery(ctx context.Context, delivery *webhooks.Delivery) error

	// GetDelivery retrieves a webhook delivery by ID.
	// Returns ErrNotFound if the delivery doesn't exist.
	GetDelivery(ctx context.Context, id int64) (*webhooks.Delivery, error)

	// GetDeliveries retrieves webhook deliveries with pagination.
	GetDeliveries(ctx context.Context, limit, offset int) ([]*webhooks.Delivery, error)

	// UpdateDelivery updates a webhook delivery record.
	// Returns ErrNotFound if the delivery doesn't exist.
	UpdateDelivery(ctx context.Context, delivery *webhooks.Delivery) error

	// ClearAllDeliveries deletes all webhook delivery records.
	// Returns the number of records deleted.
	ClearAllDeliveries(ctx context.Context) (int64, error)

	// GetPendingRetries retrieves webhook deliveries that are due for retry.
	GetPendingRetries(ctx context.Context) ([]*webhooks.Delivery, error)
}
