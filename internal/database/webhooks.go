package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/fjmerc/safeshare/internal/webhooks"
)

// CreateWebhookConfig creates a new webhook configuration
func CreateWebhookConfig(db *sql.DB, config *webhooks.Config) error {
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

	result, err := db.Exec(`
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

// GetWebhookConfig retrieves a webhook configuration by ID
func GetWebhookConfig(db *sql.DB, id int64) (*webhooks.Config, error) {
	var config webhooks.Config
	var enabled int
	var eventsJSON string
	var format string

	var serviceToken sql.NullString

	err := db.QueryRow(`
		SELECT id, url, secret, service_token, enabled, events, format, max_retries, timeout_seconds, created_at, updated_at
		FROM webhook_configs
		WHERE id = ?
	`, id).Scan(&config.ID, &config.URL, &config.Secret, &serviceToken, &enabled, &eventsJSON, &format,
		&config.MaxRetries, &config.TimeoutSeconds, &config.CreatedAt, &config.UpdatedAt)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("webhook config not found")
		}
		return nil, fmt.Errorf("failed to query webhook config: %w", err)
	}

	config.Enabled = enabled == 1
	config.Format = webhooks.WebhookFormat(format)
	if config.Format == "" {
		config.Format = webhooks.FormatSafeShare // Default format
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

// GetAllWebhookConfigs retrieves all webhook configurations
func GetAllWebhookConfigs(db *sql.DB) ([]*webhooks.Config, error) {
	rows, err := db.Query(`
		SELECT id, url, secret, service_token, enabled, events, format, max_retries, timeout_seconds, created_at, updated_at
		FROM webhook_configs
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query webhook configs: %w", err)
	}
	defer rows.Close()

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

	return configs, rows.Err()
}

// GetEnabledWebhookConfigs retrieves all enabled webhook configurations
func GetEnabledWebhookConfigs(db *sql.DB) ([]*webhooks.Config, error) {
	rows, err := db.Query(`
		SELECT id, url, secret, service_token, enabled, events, format, max_retries, timeout_seconds, created_at, updated_at
		FROM webhook_configs
		WHERE enabled = 1
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query enabled webhook configs: %w", err)
	}
	defer rows.Close()

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

	return configs, rows.Err()
}

// UpdateWebhookConfig updates an existing webhook configuration
func UpdateWebhookConfig(db *sql.DB, config *webhooks.Config) error {
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

	result, err := db.Exec(`
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
		return fmt.Errorf("webhook config not found")
	}

	config.UpdatedAt = time.Now()

	return nil
}

// UpdateWebhookConfigPreserveMasked atomically updates webhook config while preserving masked fields
// This prevents TOCTOU race conditions by using conditional SQL updates
// Pass sentinel value "***PRESERVE***" to preserve existing secret or service_token
func UpdateWebhookConfigPreserveMasked(db *sql.DB, config *webhooks.Config, preserveSecret, preserveToken bool) error {
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
	result, err := db.Exec(`
		UPDATE webhook_configs
		SET url = ?, 
		    secret = CASE WHEN ? THEN secret ELSE ? END,
		    service_token = CASE WHEN ? THEN service_token ELSE ? END,
		    enabled = ?, events = ?, format = ?, 
		    max_retries = ?, timeout_seconds = ?, 
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, config.URL, 
	   preserveSecret, config.Secret,      // Conditional: preserve or update secret
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
		return fmt.Errorf("webhook config not found")
	}

	config.UpdatedAt = time.Now()

	return nil
}

// DeleteWebhookConfig deletes a webhook configuration
func DeleteWebhookConfig(db *sql.DB, id int64) error {
	result, err := db.Exec("DELETE FROM webhook_configs WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete webhook config: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("webhook config not found")
	}

	return nil
}

// CreateWebhookDelivery creates a new webhook delivery record
func CreateWebhookDelivery(db *sql.DB, delivery *webhooks.Delivery) error {
	result, err := db.Exec(`
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

// UpdateWebhookDelivery updates a webhook delivery record
func UpdateWebhookDelivery(db *sql.DB, delivery *webhooks.Delivery) error {
	result, err := db.Exec(`
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
		return fmt.Errorf("webhook delivery not found")
	}

	return nil
}

// GetWebhookDelivery retrieves a webhook delivery by ID
func GetWebhookDelivery(db *sql.DB, id int64) (*webhooks.Delivery, error) {
	var delivery webhooks.Delivery

	err := db.QueryRow(`
		SELECT id, webhook_config_id, event_type, payload, attempt_count, status,
		       response_code, response_body, error_message, created_at, completed_at, next_retry_at
		FROM webhook_deliveries
		WHERE id = ?
	`, id).Scan(&delivery.ID, &delivery.WebhookConfigID, &delivery.EventType, &delivery.Payload,
		&delivery.AttemptCount, &delivery.Status, &delivery.ResponseCode, &delivery.ResponseBody,
		&delivery.ErrorMessage, &delivery.CreatedAt, &delivery.CompletedAt, &delivery.NextRetryAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("webhook delivery not found")
		}
		return nil, fmt.Errorf("failed to query webhook delivery: %w", err)
	}

	return &delivery, nil
}

// GetWebhookDeliveries retrieves webhook deliveries with pagination
func GetWebhookDeliveries(db *sql.DB, limit, offset int) ([]*webhooks.Delivery, error) {
	rows, err := db.Query(`
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

	return deliveries, rows.Err()
}

// GetPendingRetries retrieves webhook deliveries that are due for retry
func GetPendingRetries(db *sql.DB) ([]*webhooks.Delivery, error) {
	rows, err := db.Query(`
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

	return deliveries, rows.Err()
}
