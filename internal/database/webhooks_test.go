package database

import (
	"database/sql"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/webhooks"

	_ "modernc.org/sqlite"
)

// setupWebhookTestDB creates an in-memory SQLite database for webhook testing
func setupWebhookTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	// Force single connection for in-memory databases
	db.SetMaxOpenConns(1)

	// Run migrations to create schema
	if err := RunMigrations(db); err != nil {
		db.Close()
		t.Fatalf("failed to run migrations: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
	})

	return db
}

// createTestWebhookConfig creates a test webhook configuration
func createTestWebhookConfig(t *testing.T, db *sql.DB) *webhooks.Config {
	t.Helper()

	config := &webhooks.Config{
		URL:            "https://example.com/webhook",
		Secret:         "test-secret-12345",
		Enabled:        true,
		Events:         []string{"file.uploaded", "file.downloaded"},
		Format:         webhooks.FormatSafeShare,
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}

	err := CreateWebhookConfig(db, config)
	if err != nil {
		t.Fatalf("CreateWebhookConfig() error: %v", err)
	}

	return config
}

// createTestWebhookDelivery creates a test webhook delivery record
func createTestWebhookDelivery(t *testing.T, db *sql.DB, configID int64, eventType string, status string) *webhooks.Delivery {
	t.Helper()

	delivery := &webhooks.Delivery{
		WebhookConfigID: configID,
		EventType:       eventType,
		Payload:         `{"test": "payload"}`,
		AttemptCount:    1,
		Status:          status,
	}

	err := CreateWebhookDelivery(db, delivery)
	if err != nil {
		t.Fatalf("CreateWebhookDelivery() error: %v", err)
	}

	return delivery
}

// TestClearAllWebhookDeliveries_Empty tests clearing when no deliveries exist
func TestClearAllWebhookDeliveries_Empty(t *testing.T) {
	db := setupWebhookTestDB(t)

	count, err := ClearAllWebhookDeliveries(db)
	if err != nil {
		t.Fatalf("ClearAllWebhookDeliveries() error: %v", err)
	}

	if count != 0 {
		t.Errorf("ClearAllWebhookDeliveries() count = %d, want 0", count)
	}
}

// TestClearAllWebhookDeliveries_WithDeliveries tests clearing multiple deliveries
func TestClearAllWebhookDeliveries_WithDeliveries(t *testing.T) {
	db := setupWebhookTestDB(t)

	// Create a webhook config first (required for foreign key)
	config := createTestWebhookConfig(t, db)

	// Create multiple deliveries
	createTestWebhookDelivery(t, db, config.ID, "file.uploaded", string(webhooks.DeliveryStatusSuccess))
	createTestWebhookDelivery(t, db, config.ID, "file.downloaded", string(webhooks.DeliveryStatusFailed))
	createTestWebhookDelivery(t, db, config.ID, "file.uploaded", string(webhooks.DeliveryStatusRetrying))

	// Verify deliveries were created
	deliveries, err := GetWebhookDeliveries(db, 100, 0)
	if err != nil {
		t.Fatalf("GetWebhookDeliveries() error: %v", err)
	}
	if len(deliveries) != 3 {
		t.Fatalf("Expected 3 deliveries, got %d", len(deliveries))
	}

	// Clear all deliveries
	count, err := ClearAllWebhookDeliveries(db)
	if err != nil {
		t.Fatalf("ClearAllWebhookDeliveries() error: %v", err)
	}

	if count != 3 {
		t.Errorf("ClearAllWebhookDeliveries() count = %d, want 3", count)
	}

	// Verify all deliveries were deleted
	deliveries, err = GetWebhookDeliveries(db, 100, 0)
	if err != nil {
		t.Fatalf("GetWebhookDeliveries() after clear error: %v", err)
	}
	if len(deliveries) != 0 {
		t.Errorf("Expected 0 deliveries after clear, got %d", len(deliveries))
	}
}

// TestClearAllWebhookDeliveries_PreservesConfigs tests that clearing deliveries doesn't affect configs
func TestClearAllWebhookDeliveries_PreservesConfigs(t *testing.T) {
	db := setupWebhookTestDB(t)

	// Create webhook config
	config := createTestWebhookConfig(t, db)

	// Create some deliveries
	createTestWebhookDelivery(t, db, config.ID, "file.uploaded", string(webhooks.DeliveryStatusSuccess))
	createTestWebhookDelivery(t, db, config.ID, "file.downloaded", string(webhooks.DeliveryStatusSuccess))

	// Clear all deliveries
	_, err := ClearAllWebhookDeliveries(db)
	if err != nil {
		t.Fatalf("ClearAllWebhookDeliveries() error: %v", err)
	}

	// Verify webhook config still exists
	retrievedConfig, err := GetWebhookConfig(db, config.ID)
	if err != nil {
		t.Fatalf("GetWebhookConfig() error: %v", err)
	}

	if retrievedConfig == nil {
		t.Error("Webhook config should not be deleted when clearing deliveries")
	}

	if retrievedConfig.URL != config.URL {
		t.Errorf("Config URL = %q, want %q", retrievedConfig.URL, config.URL)
	}
}

// TestCreateWebhookConfig tests webhook config creation
func TestCreateWebhookConfig(t *testing.T) {
	db := setupWebhookTestDB(t)

	config := &webhooks.Config{
		URL:            "https://example.com/webhook",
		Secret:         "test-secret",
		ServiceToken:   "gotify-token",
		Enabled:        true,
		Events:         []string{"file.uploaded", "file.downloaded"},
		Format:         webhooks.FormatGotify,
		MaxRetries:     5,
		TimeoutSeconds: 30,
	}

	err := CreateWebhookConfig(db, config)
	if err != nil {
		t.Fatalf("CreateWebhookConfig() error: %v", err)
	}

	if config.ID == 0 {
		t.Error("CreateWebhookConfig() did not set config ID")
	}

	// Verify config was inserted
	retrieved, err := GetWebhookConfig(db, config.ID)
	if err != nil {
		t.Fatalf("GetWebhookConfig() error: %v", err)
	}

	if retrieved.URL != config.URL {
		t.Errorf("URL = %q, want %q", retrieved.URL, config.URL)
	}

	if retrieved.Secret != config.Secret {
		t.Errorf("Secret = %q, want %q", retrieved.Secret, config.Secret)
	}

	if retrieved.ServiceToken != config.ServiceToken {
		t.Errorf("ServiceToken = %q, want %q", retrieved.ServiceToken, config.ServiceToken)
	}

	if retrieved.Format != config.Format {
		t.Errorf("Format = %q, want %q", retrieved.Format, config.Format)
	}
}

// TestGetAllWebhookConfigs tests retrieving all configs
func TestGetAllWebhookConfigs(t *testing.T) {
	db := setupWebhookTestDB(t)

	// Create multiple configs
	config1 := &webhooks.Config{
		URL:            "https://example1.com/webhook",
		Secret:         "secret1",
		Enabled:        true,
		Events:         []string{"file.uploaded"},
		Format:         webhooks.FormatSafeShare,
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}
	config2 := &webhooks.Config{
		URL:            "https://example2.com/webhook",
		Secret:         "secret2",
		Enabled:        false,
		Events:         []string{"file.downloaded"},
		Format:         webhooks.FormatDiscord,
		MaxRetries:     5,
		TimeoutSeconds: 60,
	}

	CreateWebhookConfig(db, config1)
	CreateWebhookConfig(db, config2)

	configs, err := GetAllWebhookConfigs(db)
	if err != nil {
		t.Fatalf("GetAllWebhookConfigs() error: %v", err)
	}

	if len(configs) != 2 {
		t.Errorf("GetAllWebhookConfigs() returned %d configs, want 2", len(configs))
	}
}

// TestGetEnabledWebhookConfigs tests retrieving only enabled configs
func TestGetEnabledWebhookConfigs(t *testing.T) {
	db := setupWebhookTestDB(t)

	// Create enabled and disabled configs
	enabledConfig := &webhooks.Config{
		URL:            "https://enabled.com/webhook",
		Secret:         "secret",
		Enabled:        true,
		Events:         []string{"file.uploaded"},
		Format:         webhooks.FormatSafeShare,
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}
	disabledConfig := &webhooks.Config{
		URL:            "https://disabled.com/webhook",
		Secret:         "secret",
		Enabled:        false,
		Events:         []string{"file.uploaded"},
		Format:         webhooks.FormatSafeShare,
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}

	CreateWebhookConfig(db, enabledConfig)
	CreateWebhookConfig(db, disabledConfig)

	configs, err := GetEnabledWebhookConfigs(db)
	if err != nil {
		t.Fatalf("GetEnabledWebhookConfigs() error: %v", err)
	}

	if len(configs) != 1 {
		t.Errorf("GetEnabledWebhookConfigs() returned %d configs, want 1", len(configs))
	}

	if configs[0].URL != enabledConfig.URL {
		t.Errorf("Expected enabled config URL, got %q", configs[0].URL)
	}
}

// TestDeleteWebhookConfig tests config deletion
func TestDeleteWebhookConfig(t *testing.T) {
	db := setupWebhookTestDB(t)

	config := createTestWebhookConfig(t, db)

	err := DeleteWebhookConfig(db, config.ID)
	if err != nil {
		t.Fatalf("DeleteWebhookConfig() error: %v", err)
	}

	// Verify config was deleted
	_, err = GetWebhookConfig(db, config.ID)
	if err == nil {
		t.Error("GetWebhookConfig() should return error for deleted config")
	}
}

// TestDeleteWebhookConfig_NotFound tests deleting non-existent config
func TestDeleteWebhookConfig_NotFound(t *testing.T) {
	db := setupWebhookTestDB(t)

	err := DeleteWebhookConfig(db, 99999)
	if err == nil {
		t.Error("DeleteWebhookConfig() should return error for non-existent config")
	}
}

// TestCreateWebhookDelivery tests delivery creation
func TestCreateWebhookDelivery(t *testing.T) {
	db := setupWebhookTestDB(t)

	config := createTestWebhookConfig(t, db)

	delivery := &webhooks.Delivery{
		WebhookConfigID: config.ID,
		EventType:       "file.uploaded",
		Payload:         `{"claim_code": "TEST123"}`,
		AttemptCount:    0,
		Status:          string(webhooks.DeliveryStatusRetrying),
	}

	err := CreateWebhookDelivery(db, delivery)
	if err != nil {
		t.Fatalf("CreateWebhookDelivery() error: %v", err)
	}

	if delivery.ID == 0 {
		t.Error("CreateWebhookDelivery() did not set delivery ID")
	}

	// Verify delivery was inserted
	retrieved, err := GetWebhookDelivery(db, delivery.ID)
	if err != nil {
		t.Fatalf("GetWebhookDelivery() error: %v", err)
	}

	if retrieved.EventType != delivery.EventType {
		t.Errorf("EventType = %q, want %q", retrieved.EventType, delivery.EventType)
	}

	if retrieved.Status != delivery.Status {
		t.Errorf("Status = %q, want %q", retrieved.Status, delivery.Status)
	}
}

// TestUpdateWebhookDelivery tests delivery update
func TestUpdateWebhookDelivery(t *testing.T) {
	db := setupWebhookTestDB(t)

	config := createTestWebhookConfig(t, db)
	delivery := createTestWebhookDelivery(t, db, config.ID, "file.uploaded", string(webhooks.DeliveryStatusRetrying))

	// Update delivery
	delivery.Status = string(webhooks.DeliveryStatusSuccess)
	delivery.AttemptCount = 2
	responseCode := 200
	delivery.ResponseCode = &responseCode
	responseBody := "OK"
	delivery.ResponseBody = &responseBody
	completedAt := time.Now()
	delivery.CompletedAt = &completedAt

	err := UpdateWebhookDelivery(db, delivery)
	if err != nil {
		t.Fatalf("UpdateWebhookDelivery() error: %v", err)
	}

	// Verify update
	retrieved, err := GetWebhookDelivery(db, delivery.ID)
	if err != nil {
		t.Fatalf("GetWebhookDelivery() error: %v", err)
	}

	if retrieved.Status != string(webhooks.DeliveryStatusSuccess) {
		t.Errorf("Status = %q, want %q", retrieved.Status, string(webhooks.DeliveryStatusSuccess))
	}

	if retrieved.AttemptCount != 2 {
		t.Errorf("AttemptCount = %d, want 2", retrieved.AttemptCount)
	}

	if retrieved.ResponseCode == nil || *retrieved.ResponseCode != 200 {
		t.Errorf("ResponseCode = %v, want 200", retrieved.ResponseCode)
	}
}

// TestGetWebhookDeliveries tests pagination
func TestGetWebhookDeliveries(t *testing.T) {
	db := setupWebhookTestDB(t)

	config := createTestWebhookConfig(t, db)

	// Create 5 deliveries
	for i := 0; i < 5; i++ {
		createTestWebhookDelivery(t, db, config.ID, "file.uploaded", string(webhooks.DeliveryStatusSuccess))
	}

	// Test limit
	deliveries, err := GetWebhookDeliveries(db, 3, 0)
	if err != nil {
		t.Fatalf("GetWebhookDeliveries() error: %v", err)
	}
	if len(deliveries) != 3 {
		t.Errorf("GetWebhookDeliveries(limit=3) returned %d, want 3", len(deliveries))
	}

	// Test offset
	deliveries, err = GetWebhookDeliveries(db, 10, 3)
	if err != nil {
		t.Fatalf("GetWebhookDeliveries() error: %v", err)
	}
	if len(deliveries) != 2 {
		t.Errorf("GetWebhookDeliveries(offset=3) returned %d, want 2", len(deliveries))
	}
}

// TestGetPendingRetries tests retrieving deliveries due for retry
func TestGetPendingRetries(t *testing.T) {
	db := setupWebhookTestDB(t)

	config := createTestWebhookConfig(t, db)

	// Create a delivery due for retry
	delivery := &webhooks.Delivery{
		WebhookConfigID: config.ID,
		EventType:       "file.uploaded",
		Payload:         `{"test": "payload"}`,
		AttemptCount:    1,
		Status:          string(webhooks.DeliveryStatusRetrying),
	}
	CreateWebhookDelivery(db, delivery)

	// Set next_retry_at to past time
	pastTime := time.Now().Add(-1 * time.Hour)
	delivery.NextRetryAt = &pastTime
	UpdateWebhookDelivery(db, delivery)

	// Create a delivery not due for retry (future time)
	delivery2 := &webhooks.Delivery{
		WebhookConfigID: config.ID,
		EventType:       "file.downloaded",
		Payload:         `{"test": "payload2"}`,
		AttemptCount:    1,
		Status:          string(webhooks.DeliveryStatusRetrying),
	}
	CreateWebhookDelivery(db, delivery2)
	futureTime := time.Now().Add(1 * time.Hour)
	delivery2.NextRetryAt = &futureTime
	UpdateWebhookDelivery(db, delivery2)

	// Get pending retries
	pending, err := GetPendingRetries(db)
	if err != nil {
		t.Fatalf("GetPendingRetries() error: %v", err)
	}

	if len(pending) != 1 {
		t.Errorf("GetPendingRetries() returned %d, want 1", len(pending))
	}

	if len(pending) > 0 && pending[0].ID != delivery.ID {
		t.Errorf("GetPendingRetries() returned wrong delivery")
	}
}
