package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/webhooks"
)

func TestWebhookRepository_CreateConfig(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	config := &webhooks.Config{
		URL:            "https://example.com/webhook",
		Secret:         "test-secret",
		ServiceToken:   "test-token",
		Enabled:        true,
		Events:         []string{"file.uploaded", "file.downloaded"},
		Format:         webhooks.FormatSafeShare,
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}

	err := repo.CreateConfig(ctx, config)
	if err != nil {
		t.Fatalf("CreateConfig failed: %v", err)
	}

	if config.ID == 0 {
		t.Error("expected ID to be set after creation")
	}

	// Verify by fetching
	fetched, err := repo.GetConfig(ctx, config.ID)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	if fetched.URL != config.URL {
		t.Errorf("URL mismatch: got %s, want %s", fetched.URL, config.URL)
	}
	if fetched.Secret != config.Secret {
		t.Errorf("Secret mismatch: got %s, want %s", fetched.Secret, config.Secret)
	}
	if fetched.ServiceToken != config.ServiceToken {
		t.Errorf("ServiceToken mismatch: got %s, want %s", fetched.ServiceToken, config.ServiceToken)
	}
	if !fetched.Enabled {
		t.Error("expected Enabled to be true")
	}
	if fetched.MaxRetries != config.MaxRetries {
		t.Errorf("MaxRetries mismatch: got %d, want %d", fetched.MaxRetries, config.MaxRetries)
	}
	if fetched.TimeoutSeconds != config.TimeoutSeconds {
		t.Errorf("TimeoutSeconds mismatch: got %d, want %d", fetched.TimeoutSeconds, config.TimeoutSeconds)
	}
}

func TestWebhookRepository_CreateConfig_Validation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	tests := []struct {
		name    string
		config  *webhooks.Config
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "empty URL",
			config: &webhooks.Config{
				URL:            "",
				MaxRetries:     3,
				TimeoutSeconds: 30,
			},
			wantErr: true,
		},
		{
			name: "max_retries too high",
			config: &webhooks.Config{
				URL:            "https://example.com",
				MaxRetries:     101, // maxWebhookRetries = 100
				TimeoutSeconds: 30,
			},
			wantErr: true,
		},
		{
			name: "max_retries negative",
			config: &webhooks.Config{
				URL:            "https://example.com",
				MaxRetries:     -1,
				TimeoutSeconds: 30,
			},
			wantErr: true,
		},
		{
			name: "timeout_seconds too high",
			config: &webhooks.Config{
				URL:            "https://example.com",
				MaxRetries:     3,
				TimeoutSeconds: 301, // maxWebhookTimeoutSeconds = 300
			},
			wantErr: true,
		},
		{
			name: "timeout_seconds too low",
			config: &webhooks.Config{
				URL:            "https://example.com",
				MaxRetries:     3,
				TimeoutSeconds: 0, // minWebhookTimeoutSeconds = 1
			},
			wantErr: true,
		},
		{
			name: "valid config",
			config: &webhooks.Config{
				URL:            "https://example.com",
				MaxRetries:     3,
				TimeoutSeconds: 30,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.CreateConfig(ctx, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWebhookRepository_GetConfig_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	_, err := repo.GetConfig(ctx, 99999)
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestWebhookRepository_GetAllConfigs(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	// Create multiple configs
	for i := 0; i < 3; i++ {
		config := &webhooks.Config{
			URL:            "https://example.com/webhook",
			MaxRetries:     3,
			TimeoutSeconds: 30,
			Enabled:        i%2 == 0, // Some enabled, some disabled
		}
		if err := repo.CreateConfig(ctx, config); err != nil {
			t.Fatalf("CreateConfig failed: %v", err)
		}
	}

	configs, err := repo.GetAllConfigs(ctx)
	if err != nil {
		t.Fatalf("GetAllConfigs failed: %v", err)
	}

	if len(configs) != 3 {
		t.Errorf("expected 3 configs, got %d", len(configs))
	}
}

func TestWebhookRepository_GetEnabledConfigs(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	// Create 3 configs: 2 enabled, 1 disabled
	for i := 0; i < 3; i++ {
		config := &webhooks.Config{
			URL:            "https://example.com/webhook",
			MaxRetries:     3,
			TimeoutSeconds: 30,
			Enabled:        i != 1, // 0=enabled, 1=disabled, 2=enabled
		}
		if err := repo.CreateConfig(ctx, config); err != nil {
			t.Fatalf("CreateConfig failed: %v", err)
		}
	}

	configs, err := repo.GetEnabledConfigs(ctx)
	if err != nil {
		t.Fatalf("GetEnabledConfigs failed: %v", err)
	}

	if len(configs) != 2 {
		t.Errorf("expected 2 enabled configs, got %d", len(configs))
	}

	for _, c := range configs {
		if !c.Enabled {
			t.Error("returned config is not enabled")
		}
	}
}

func TestWebhookRepository_UpdateConfig(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	// Create initial config
	config := &webhooks.Config{
		URL:            "https://example.com/webhook",
		Secret:         "original-secret",
		Enabled:        true,
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}
	if err := repo.CreateConfig(ctx, config); err != nil {
		t.Fatalf("CreateConfig failed: %v", err)
	}

	// Update config
	config.URL = "https://updated.example.com/webhook"
	config.Secret = "new-secret"
	config.Enabled = false
	config.MaxRetries = 5

	if err := repo.UpdateConfig(ctx, config); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	// Verify update
	fetched, err := repo.GetConfig(ctx, config.ID)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	if fetched.URL != "https://updated.example.com/webhook" {
		t.Errorf("URL not updated: got %s", fetched.URL)
	}
	if fetched.Secret != "new-secret" {
		t.Errorf("Secret not updated: got %s", fetched.Secret)
	}
	if fetched.Enabled {
		t.Error("Enabled not updated to false")
	}
	if fetched.MaxRetries != 5 {
		t.Errorf("MaxRetries not updated: got %d", fetched.MaxRetries)
	}
}

func TestWebhookRepository_UpdateConfig_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	config := &webhooks.Config{
		ID:             99999,
		URL:            "https://example.com",
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}

	err := repo.UpdateConfig(ctx, config)
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestWebhookRepository_UpdateConfig_Validation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	// Create a config first
	config := &webhooks.Config{
		URL:            "https://example.com/webhook",
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}
	if err := repo.CreateConfig(ctx, config); err != nil {
		t.Fatalf("CreateConfig failed: %v", err)
	}

	// Try to update with invalid values
	config.MaxRetries = 101
	err := repo.UpdateConfig(ctx, config)
	if err == nil {
		t.Error("expected error for max_retries too high")
	}

	config.MaxRetries = 3
	config.TimeoutSeconds = 0
	err = repo.UpdateConfig(ctx, config)
	if err == nil {
		t.Error("expected error for timeout_seconds too low")
	}
}

func TestWebhookRepository_UpdateConfigPreserveMasked(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	// Create initial config
	config := &webhooks.Config{
		URL:            "https://example.com/webhook",
		Secret:         "original-secret",
		ServiceToken:   "original-token",
		Enabled:        true,
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}
	if err := repo.CreateConfig(ctx, config); err != nil {
		t.Fatalf("CreateConfig failed: %v", err)
	}

	// Update config with masked fields preserved
	config.URL = "https://updated.example.com/webhook"
	config.Secret = "masked-secret" // Should be ignored
	config.ServiceToken = "masked-token" // Should be ignored

	if err := repo.UpdateConfigPreserveMasked(ctx, config, true, true); err != nil {
		t.Fatalf("UpdateConfigPreserveMasked failed: %v", err)
	}

	// Verify update - masked fields should be preserved
	fetched, err := repo.GetConfig(ctx, config.ID)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	if fetched.URL != "https://updated.example.com/webhook" {
		t.Errorf("URL not updated: got %s", fetched.URL)
	}
	if fetched.Secret != "original-secret" {
		t.Errorf("Secret should be preserved: got %s", fetched.Secret)
	}
	if fetched.ServiceToken != "original-token" {
		t.Errorf("ServiceToken should be preserved: got %s", fetched.ServiceToken)
	}
}

func TestWebhookRepository_UpdateConfigPreserveMasked_NotPreserved(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	// Create initial config
	config := &webhooks.Config{
		URL:            "https://example.com/webhook",
		Secret:         "original-secret",
		ServiceToken:   "original-token",
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}
	if err := repo.CreateConfig(ctx, config); err != nil {
		t.Fatalf("CreateConfig failed: %v", err)
	}

	// Update without preserving masked fields
	config.Secret = "new-secret"
	config.ServiceToken = "new-token"

	if err := repo.UpdateConfigPreserveMasked(ctx, config, false, false); err != nil {
		t.Fatalf("UpdateConfigPreserveMasked failed: %v", err)
	}

	// Verify update - masked fields should be updated
	fetched, err := repo.GetConfig(ctx, config.ID)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	if fetched.Secret != "new-secret" {
		t.Errorf("Secret should be updated: got %s", fetched.Secret)
	}
	if fetched.ServiceToken != "new-token" {
		t.Errorf("ServiceToken should be updated: got %s", fetched.ServiceToken)
	}
}

func TestWebhookRepository_DeleteConfig(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	// Create config
	config := &webhooks.Config{
		URL:            "https://example.com/webhook",
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}
	if err := repo.CreateConfig(ctx, config); err != nil {
		t.Fatalf("CreateConfig failed: %v", err)
	}

	// Delete config
	if err := repo.DeleteConfig(ctx, config.ID); err != nil {
		t.Fatalf("DeleteConfig failed: %v", err)
	}

	// Verify deleted
	_, err := repo.GetConfig(ctx, config.ID)
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestWebhookRepository_DeleteConfig_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	err := repo.DeleteConfig(ctx, 99999)
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestWebhookRepository_CreateDelivery(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	// First create a config
	config := &webhooks.Config{
		URL:            "https://example.com/webhook",
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}
	if err := repo.CreateConfig(ctx, config); err != nil {
		t.Fatalf("CreateConfig failed: %v", err)
	}

	// Create delivery
	delivery := &webhooks.Delivery{
		WebhookConfigID: config.ID,
		EventType:       "file.uploaded",
		Payload:         `{"claim_code": "ABC123"}`,
		AttemptCount:    0,
		Status:          string(webhooks.DeliveryStatusPending),
	}

	if err := repo.CreateDelivery(ctx, delivery); err != nil {
		t.Fatalf("CreateDelivery failed: %v", err)
	}

	if delivery.ID == 0 {
		t.Error("expected ID to be set after creation")
	}

	// Verify by fetching
	fetched, err := repo.GetDelivery(ctx, delivery.ID)
	if err != nil {
		t.Fatalf("GetDelivery failed: %v", err)
	}

	if fetched.WebhookConfigID != config.ID {
		t.Errorf("WebhookConfigID mismatch: got %d, want %d", fetched.WebhookConfigID, config.ID)
	}
	if fetched.EventType != "file.uploaded" {
		t.Errorf("EventType mismatch: got %s", fetched.EventType)
	}
	if fetched.Status != string(webhooks.DeliveryStatusPending) {
		t.Errorf("Status mismatch: got %s", fetched.Status)
	}
}

func TestWebhookRepository_CreateDelivery_Validation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	tests := []struct {
		name     string
		delivery *webhooks.Delivery
		wantErr  bool
	}{
		{
			name:     "nil delivery",
			delivery: nil,
			wantErr:  true,
		},
		{
			name: "zero webhook_config_id",
			delivery: &webhooks.Delivery{
				WebhookConfigID: 0,
				EventType:       "file.uploaded",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.CreateDelivery(ctx, tt.delivery)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateDelivery() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWebhookRepository_GetDelivery_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	_, err := repo.GetDelivery(ctx, 99999)
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestWebhookRepository_GetDeliveries(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	// Create a config first
	config := &webhooks.Config{
		URL:            "https://example.com/webhook",
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}
	if err := repo.CreateConfig(ctx, config); err != nil {
		t.Fatalf("CreateConfig failed: %v", err)
	}

	// Create multiple deliveries
	for i := 0; i < 5; i++ {
		delivery := &webhooks.Delivery{
			WebhookConfigID: config.ID,
			EventType:       "file.uploaded",
			Status:          string(webhooks.DeliveryStatusPending),
		}
		if err := repo.CreateDelivery(ctx, delivery); err != nil {
			t.Fatalf("CreateDelivery failed: %v", err)
		}
	}

	// Test pagination
	deliveries, err := repo.GetDeliveries(ctx, 3, 0)
	if err != nil {
		t.Fatalf("GetDeliveries failed: %v", err)
	}
	if len(deliveries) != 3 {
		t.Errorf("expected 3 deliveries, got %d", len(deliveries))
	}

	// Test offset
	deliveries, err = repo.GetDeliveries(ctx, 10, 2)
	if err != nil {
		t.Fatalf("GetDeliveries with offset failed: %v", err)
	}
	if len(deliveries) != 3 {
		t.Errorf("expected 3 deliveries with offset, got %d", len(deliveries))
	}

	// Test default limit
	deliveries, err = repo.GetDeliveries(ctx, 0, 0)
	if err != nil {
		t.Fatalf("GetDeliveries with default limit failed: %v", err)
	}
	if len(deliveries) != 5 {
		t.Errorf("expected 5 deliveries with default limit, got %d", len(deliveries))
	}
}

func TestWebhookRepository_UpdateDelivery(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	// Create a config first
	config := &webhooks.Config{
		URL:            "https://example.com/webhook",
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}
	if err := repo.CreateConfig(ctx, config); err != nil {
		t.Fatalf("CreateConfig failed: %v", err)
	}

	// Create delivery
	delivery := &webhooks.Delivery{
		WebhookConfigID: config.ID,
		EventType:       "file.uploaded",
		Status:          string(webhooks.DeliveryStatusPending),
	}
	if err := repo.CreateDelivery(ctx, delivery); err != nil {
		t.Fatalf("CreateDelivery failed: %v", err)
	}

	// Update delivery
	now := time.Now()
	responseCode := 200
	responseBody := "OK"
	delivery.AttemptCount = 1
	delivery.Status = string(webhooks.DeliveryStatusSuccess)
	delivery.ResponseCode = &responseCode
	delivery.ResponseBody = &responseBody
	delivery.CompletedAt = &now

	if err := repo.UpdateDelivery(ctx, delivery); err != nil {
		t.Fatalf("UpdateDelivery failed: %v", err)
	}

	// Verify update
	fetched, err := repo.GetDelivery(ctx, delivery.ID)
	if err != nil {
		t.Fatalf("GetDelivery failed: %v", err)
	}

	if fetched.AttemptCount != 1 {
		t.Errorf("AttemptCount not updated: got %d", fetched.AttemptCount)
	}
	if fetched.Status != string(webhooks.DeliveryStatusSuccess) {
		t.Errorf("Status not updated: got %s", fetched.Status)
	}
	if fetched.ResponseCode == nil || *fetched.ResponseCode != 200 {
		t.Errorf("ResponseCode not updated correctly")
	}
}

func TestWebhookRepository_UpdateDelivery_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	delivery := &webhooks.Delivery{
		ID:     99999,
		Status: string(webhooks.DeliveryStatusSuccess),
	}

	err := repo.UpdateDelivery(ctx, delivery)
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestWebhookRepository_ClearAllDeliveries(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	// Create a config first
	config := &webhooks.Config{
		URL:            "https://example.com/webhook",
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}
	if err := repo.CreateConfig(ctx, config); err != nil {
		t.Fatalf("CreateConfig failed: %v", err)
	}

	// Create some deliveries
	for i := 0; i < 5; i++ {
		delivery := &webhooks.Delivery{
			WebhookConfigID: config.ID,
			EventType:       "file.uploaded",
			Status:          string(webhooks.DeliveryStatusPending),
		}
		if err := repo.CreateDelivery(ctx, delivery); err != nil {
			t.Fatalf("CreateDelivery failed: %v", err)
		}
	}

	// Clear all deliveries
	count, err := repo.ClearAllDeliveries(ctx)
	if err != nil {
		t.Fatalf("ClearAllDeliveries failed: %v", err)
	}

	if count != 5 {
		t.Errorf("expected 5 deleted, got %d", count)
	}

	// Verify all deleted
	deliveries, err := repo.GetDeliveries(ctx, 100, 0)
	if err != nil {
		t.Fatalf("GetDeliveries failed: %v", err)
	}
	if len(deliveries) != 0 {
		t.Errorf("expected 0 deliveries after clear, got %d", len(deliveries))
	}
}

func TestWebhookRepository_GetPendingRetries(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewWebhookRepository(db)
	ctx := context.Background()

	// Create a config first
	config := &webhooks.Config{
		URL:            "https://example.com/webhook",
		MaxRetries:     3,
		TimeoutSeconds: 30,
	}
	if err := repo.CreateConfig(ctx, config); err != nil {
		t.Fatalf("CreateConfig failed: %v", err)
	}

	// Create deliveries with different statuses
	pastTime := time.Now().Add(-time.Hour)
	futureTime := time.Now().Add(time.Hour)

	// This should be returned - retrying status and next_retry_at in past
	delivery1 := &webhooks.Delivery{
		WebhookConfigID: config.ID,
		EventType:       "file.uploaded",
		Status:          string(webhooks.DeliveryStatusRetrying),
	}
	if err := repo.CreateDelivery(ctx, delivery1); err != nil {
		t.Fatalf("CreateDelivery failed: %v", err)
	}
	delivery1.NextRetryAt = &pastTime
	if err := repo.UpdateDelivery(ctx, delivery1); err != nil {
		t.Fatalf("UpdateDelivery failed: %v", err)
	}

	// This should NOT be returned - retrying but next_retry_at in future
	delivery2 := &webhooks.Delivery{
		WebhookConfigID: config.ID,
		EventType:       "file.uploaded",
		Status:          string(webhooks.DeliveryStatusRetrying),
	}
	if err := repo.CreateDelivery(ctx, delivery2); err != nil {
		t.Fatalf("CreateDelivery failed: %v", err)
	}
	delivery2.NextRetryAt = &futureTime
	if err := repo.UpdateDelivery(ctx, delivery2); err != nil {
		t.Fatalf("UpdateDelivery failed: %v", err)
	}

	// This should NOT be returned - pending status
	delivery3 := &webhooks.Delivery{
		WebhookConfigID: config.ID,
		EventType:       "file.uploaded",
		Status:          string(webhooks.DeliveryStatusPending),
	}
	if err := repo.CreateDelivery(ctx, delivery3); err != nil {
		t.Fatalf("CreateDelivery failed: %v", err)
	}

	// Get pending retries
	retries, err := repo.GetPendingRetries(ctx)
	if err != nil {
		t.Fatalf("GetPendingRetries failed: %v", err)
	}

	if len(retries) != 1 {
		t.Errorf("expected 1 pending retry, got %d", len(retries))
	}

	if len(retries) > 0 && retries[0].ID != delivery1.ID {
		t.Errorf("expected delivery ID %d, got %d", delivery1.ID, retries[0].ID)
	}
}

func TestWebhookRepository_Interface(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Verify WebhookRepository implements repository.WebhookRepository
	var _ repository.WebhookRepository = (*WebhookRepository)(nil)
}
