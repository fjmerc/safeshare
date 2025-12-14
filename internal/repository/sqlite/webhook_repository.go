package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/webhooks"
)

// Webhook configuration limits.
const (
	maxWebhookRetries       = 100
	maxWebhookTimeoutSeconds = 300
	minWebhookTimeoutSeconds = 1
	maxWebhookConfigs       = 1000 // Limit for unbounded queries
)

// WebhookRepository implements repository.WebhookRepository for SQLite.
type WebhookRepository struct {
	db *sql.DB
}

// NewWebhookRepository creates a new SQLite webhook repository.
func NewWebhookRepository(db *sql.DB) *WebhookRepository {
	return &WebhookRepository{db: db}
}

// CreateConfig creates a new webhook configuration.
// The config.ID field will be populated with the generated ID on success.
func (r *WebhookRepository) CreateConfig(ctx context.Context, config *webhooks.Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if config.URL == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	// Validate numeric fields to prevent DoS and data corruption
	if config.MaxRetries < 0 || config.MaxRetries > maxWebhookRetries {
		return fmt.Errorf("max_retries must be between 0 and %d", maxWebhookRetries)
	}
	if config.TimeoutSeconds < minWebhookTimeoutSeconds || config.TimeoutSeconds > maxWebhookTimeoutSeconds {
		return fmt.Errorf("timeout_seconds must be between %d and %d", minWebhookTimeoutSeconds, maxWebhookTimeoutSeconds)
	}

	eventsJSON, err := webhooks.EncodeEventsJSON(config.Events)
	if err != nil {
		return fmt.Errorf("failed to encode events: %w", err)
	}

	enabled := 0
	if config.Enabled {
		enabled = 1
	}

	format := string(config.Format)
	if format == "" {
		format = "safeshare" // Default format
	}

	result, err := r.db.ExecContext(ctx, `
		INSERT INTO webhook_configs (url, secret, service_token, enabled, events, format, max_retries, timeout_seconds, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, config.URL, config.Secret, config.ServiceToken, enabled, eventsJSON, format, config.MaxRetries, config.TimeoutSeconds)
	if err != nil {
		return fmt.Errorf("failed to insert webhook config: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	config.ID = id
	config.CreatedAt = time.Now()
	config.UpdatedAt = time.Now()

	return nil
}

// GetConfig retrieves a webhook configuration by ID.
// Returns ErrNotFound if the config doesn't exist.
func (r *WebhookRepository) GetConfig(ctx context.Context, id int64) (*webhooks.Config, error) {
	var config webhooks.Config
	var enabled int
	var eventsJSON string
	var format string
	var serviceToken sql.NullString

	err := r.db.QueryRowContext(ctx, `
		SELECT id, url, secret, service_token, enabled, events, format, max_retries, timeout_seconds, created_at, updated_at
		FROM webhook_configs
		WHERE id = ?
	`, id).Scan(&config.ID, &config.URL, &config.Secret, &serviceToken, &enabled, &eventsJSON, &format,
		&config.MaxRetries, &config.TimeoutSeconds, &config.CreatedAt, &config.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query webhook config: %w", err)
	}

	config.Enabled = enabled == 1
	config.Format = webhooks.WebhookFormat(format)
	if config.Format == "" {
		config.Format = webhooks.FormatSafeShare
	}

	if serviceToken.Valid {
		config.ServiceToken = serviceToken.String
	}

	events, err := webhooks.ParseEventsJSON(eventsJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse events: %w", err)
	}
	config.Events = events

	return &config, nil
}

// GetAllConfigs retrieves all webhook configurations.
// Limited to prevent unbounded result sets (DoS protection).
func (r *WebhookRepository) GetAllConfigs(ctx context.Context) ([]*webhooks.Config, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, url, secret, service_token, enabled, events, format, max_retries, timeout_seconds, created_at, updated_at
		FROM webhook_configs
		ORDER BY created_at DESC
		LIMIT ?
	`, maxWebhookConfigs)
	if err != nil {
		return nil, fmt.Errorf("failed to query webhook configs: %w", err)
	}
	defer rows.Close()

	return r.scanConfigs(rows)
}

// GetEnabledConfigs retrieves all enabled webhook configurations.
// Limited to prevent unbounded result sets (DoS protection).
func (r *WebhookRepository) GetEnabledConfigs(ctx context.Context) ([]*webhooks.Config, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, url, secret, service_token, enabled, events, format, max_retries, timeout_seconds, created_at, updated_at
		FROM webhook_configs
		WHERE enabled = 1
		ORDER BY created_at DESC
		LIMIT ?
	`, maxWebhookConfigs)
	if err != nil {
		return nil, fmt.Errorf("failed to query enabled webhook configs: %w", err)
	}
	defer rows.Close()

	return r.scanConfigs(rows)
}

// scanConfigs scans rows into webhook configs.
func (r *WebhookRepository) scanConfigs(rows *sql.Rows) ([]*webhooks.Config, error) {
	var configs []*webhooks.Config
	for rows.Next() {
		var config webhooks.Config
		var enabled int
		var eventsJSON string
		var format string
		var serviceToken sql.NullString

		err := rows.Scan(&config.ID, &config.URL, &config.Secret, &serviceToken, &enabled, &eventsJSON, &format,
			&config.MaxRetries, &config.TimeoutSeconds, &config.CreatedAt, &config.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan webhook config: %w", err)
		}

		config.Enabled = enabled == 1
		config.Format = webhooks.WebhookFormat(format)
		if config.Format == "" {
			config.Format = webhooks.FormatSafeShare
		}

		if serviceToken.Valid {
			config.ServiceToken = serviceToken.String
		}

		events, err := webhooks.ParseEventsJSON(eventsJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to parse events: %w", err)
		}
		config.Events = events

		configs = append(configs, &config)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating webhook configs: %w", err)
	}

	return configs, nil
}

// UpdateConfig updates an existing webhook configuration.
// Returns ErrNotFound if the config doesn't exist.
func (r *WebhookRepository) UpdateConfig(ctx context.Context, config *webhooks.Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if config.URL == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	// Validate numeric fields to prevent DoS and data corruption
	if config.MaxRetries < 0 || config.MaxRetries > maxWebhookRetries {
		return fmt.Errorf("max_retries must be between 0 and %d", maxWebhookRetries)
	}
	if config.TimeoutSeconds < minWebhookTimeoutSeconds || config.TimeoutSeconds > maxWebhookTimeoutSeconds {
		return fmt.Errorf("timeout_seconds must be between %d and %d", minWebhookTimeoutSeconds, maxWebhookTimeoutSeconds)
	}

	eventsJSON, err := webhooks.EncodeEventsJSON(config.Events)
	if err != nil {
		return fmt.Errorf("failed to encode events: %w", err)
	}

	enabled := 0
	if config.Enabled {
		enabled = 1
	}

	format := string(config.Format)
	if format == "" {
		format = "safeshare"
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE webhook_configs
		SET url = ?, secret = ?, service_token = ?, enabled = ?, events = ?, format = ?, max_retries = ?, timeout_seconds = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, config.URL, config.Secret, config.ServiceToken, enabled, eventsJSON, format, config.MaxRetries, config.TimeoutSeconds, config.ID)
	if err != nil {
		return fmt.Errorf("failed to update webhook config: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return repository.ErrNotFound
	}

	config.UpdatedAt = time.Now()

	return nil
}

// UpdateConfigPreserveMasked atomically updates webhook config while preserving masked fields.
// This prevents TOCTOU race conditions by using conditional SQL updates.
// If preserveSecret is true, the existing secret is preserved.
// If preserveToken is true, the existing service_token is preserved.
func (r *WebhookRepository) UpdateConfigPreserveMasked(ctx context.Context, config *webhooks.Config, preserveSecret, preserveToken bool) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if config.URL == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	// Validate numeric fields to prevent DoS and data corruption
	if config.MaxRetries < 0 || config.MaxRetries > maxWebhookRetries {
		return fmt.Errorf("max_retries must be between 0 and %d", maxWebhookRetries)
	}
	if config.TimeoutSeconds < minWebhookTimeoutSeconds || config.TimeoutSeconds > maxWebhookTimeoutSeconds {
		return fmt.Errorf("timeout_seconds must be between %d and %d", minWebhookTimeoutSeconds, maxWebhookTimeoutSeconds)
	}

	eventsJSON, err := webhooks.EncodeEventsJSON(config.Events)
	if err != nil {
		return fmt.Errorf("failed to encode events: %w", err)
	}

	enabled := 0
	if config.Enabled {
		enabled = 1
	}

	format := string(config.Format)
	if format == "" {
		format = "safeshare"
	}

	// Build conditional UPDATE query that preserves fields when requested
	// Uses CASE WHEN to conditionally preserve secret and service_token
	result, err := r.db.ExecContext(ctx, `
		UPDATE webhook_configs
		SET url = ?, 
		    secret = CASE WHEN ? THEN secret ELSE ? END,
		    service_token = CASE WHEN ? THEN service_token ELSE ? END,
		    enabled = ?, events = ?, format = ?, 
		    max_retries = ?, timeout_seconds = ?, 
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, config.URL,
		preserveSecret, config.Secret, // Conditional: preserve or update secret
		preserveToken, config.ServiceToken, // Conditional: preserve or update token
		enabled, eventsJSON, format,
		config.MaxRetries, config.TimeoutSeconds, config.ID)
	if err != nil {
		return fmt.Errorf("failed to update webhook config: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return repository.ErrNotFound
	}

	config.UpdatedAt = time.Now()

	return nil
}

// DeleteConfig deletes a webhook configuration.
// Returns ErrNotFound if the config doesn't exist.
func (r *WebhookRepository) DeleteConfig(ctx context.Context, id int64) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM webhook_configs WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete webhook config: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// CreateDelivery creates a new webhook delivery record.
// The delivery.ID field will be populated with the generated ID on success.
func (r *WebhookRepository) CreateDelivery(ctx context.Context, delivery *webhooks.Delivery) error {
	if delivery == nil {
		return fmt.Errorf("delivery cannot be nil")
	}
	if delivery.WebhookConfigID == 0 {
		return fmt.Errorf("webhook_config_id cannot be zero")
	}

	result, err := r.db.ExecContext(ctx, `
		INSERT INTO webhook_deliveries (webhook_config_id, event_type, payload, attempt_count, status)
		VALUES (?, ?, ?, ?, ?)
	`, delivery.WebhookConfigID, delivery.EventType, delivery.Payload, delivery.AttemptCount, delivery.Status)
	if err != nil {
		return fmt.Errorf("failed to insert webhook delivery: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	delivery.ID = id
	delivery.CreatedAt = time.Now()

	return nil
}

// GetDelivery retrieves a webhook delivery by ID.
// Returns ErrNotFound if the delivery doesn't exist.
func (r *WebhookRepository) GetDelivery(ctx context.Context, id int64) (*webhooks.Delivery, error) {
	var delivery webhooks.Delivery

	err := r.db.QueryRowContext(ctx, `
		SELECT id, webhook_config_id, event_type, payload, attempt_count, status,
		       response_code, response_body, error_message, created_at, completed_at, next_retry_at
		FROM webhook_deliveries
		WHERE id = ?
	`, id).Scan(&delivery.ID, &delivery.WebhookConfigID, &delivery.EventType, &delivery.Payload,
		&delivery.AttemptCount, &delivery.Status, &delivery.ResponseCode, &delivery.ResponseBody,
		&delivery.ErrorMessage, &delivery.CreatedAt, &delivery.CompletedAt, &delivery.NextRetryAt)

	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query webhook delivery: %w", err)
	}

	return &delivery, nil
}

// GetDeliveries retrieves webhook deliveries with pagination.
func (r *WebhookRepository) GetDeliveries(ctx context.Context, limit, offset int) ([]*webhooks.Delivery, error) {
	if limit <= 0 {
		limit = 100 // Default limit
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, webhook_config_id, event_type, payload, attempt_count, status,
		       response_code, response_body, error_message, created_at, completed_at, next_retry_at
		FROM webhook_deliveries
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query webhook deliveries: %w", err)
	}
	defer rows.Close()

	return r.scanDeliveries(rows)
}

// UpdateDelivery updates a webhook delivery record.
// Returns ErrNotFound if the delivery doesn't exist.
func (r *WebhookRepository) UpdateDelivery(ctx context.Context, delivery *webhooks.Delivery) error {
	if delivery == nil {
		return fmt.Errorf("delivery cannot be nil")
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE webhook_deliveries
		SET attempt_count = ?, status = ?, response_code = ?, response_body = ?, 
		    error_message = ?, completed_at = ?, next_retry_at = ?
		WHERE id = ?
	`, delivery.AttemptCount, delivery.Status, delivery.ResponseCode, delivery.ResponseBody,
		delivery.ErrorMessage, delivery.CompletedAt, delivery.NextRetryAt, delivery.ID)
	if err != nil {
		return fmt.Errorf("failed to update webhook delivery: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// ClearAllDeliveries deletes all webhook delivery records.
// Returns the number of records deleted.
func (r *WebhookRepository) ClearAllDeliveries(ctx context.Context) (int64, error) {
	result, err := r.db.ExecContext(ctx, "DELETE FROM webhook_deliveries")
	if err != nil {
		return 0, fmt.Errorf("failed to clear webhook deliveries: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rows, nil
}

// GetPendingRetries retrieves webhook deliveries that are due for retry.
func (r *WebhookRepository) GetPendingRetries(ctx context.Context) ([]*webhooks.Delivery, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, webhook_config_id, event_type, payload, attempt_count, status,
		       response_code, response_body, error_message, created_at, completed_at, next_retry_at
		FROM webhook_deliveries
		WHERE status = ? AND next_retry_at <= CURRENT_TIMESTAMP
		ORDER BY next_retry_at ASC
	`, webhooks.DeliveryStatusRetrying)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending retries: %w", err)
	}
	defer rows.Close()

	return r.scanDeliveries(rows)
}

// scanDeliveries scans rows into webhook deliveries.
func (r *WebhookRepository) scanDeliveries(rows *sql.Rows) ([]*webhooks.Delivery, error) {
	var deliveries []*webhooks.Delivery
	for rows.Next() {
		var delivery webhooks.Delivery

		err := rows.Scan(&delivery.ID, &delivery.WebhookConfigID, &delivery.EventType, &delivery.Payload,
			&delivery.AttemptCount, &delivery.Status, &delivery.ResponseCode, &delivery.ResponseBody,
			&delivery.ErrorMessage, &delivery.CreatedAt, &delivery.CompletedAt, &delivery.NextRetryAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan webhook delivery: %w", err)
		}

		deliveries = append(deliveries, &delivery)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating webhook deliveries: %w", err)
	}

	return deliveries, nil
}

// Ensure WebhookRepository implements repository.WebhookRepository.
var _ repository.WebhookRepository = (*WebhookRepository)(nil)
