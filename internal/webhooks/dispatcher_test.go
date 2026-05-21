package webhooks

import (
	"sync"
	"testing"
	"time"
)

// MockDatabaseOperations implements DatabaseOperations for testing
type MockDatabaseOperations struct {
	configs        []*Config
	deliveries     []*Delivery
	pendingRetries []*Delivery
	// SH-3.2: counts GetEnabledWebhookConfigs invocations so cache-behaviour
	// tests can assert on call count without relying on timing.
	getConfigsCalls int
	mu              sync.Mutex
}

func (m *MockDatabaseOperations) GetEnabledWebhookConfigs() ([]*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getConfigsCalls++
	return m.configs, nil
}

// GetConfigsCalls returns the number of times GetEnabledWebhookConfigs has
// been invoked. Used by SH-3.2 cache-behaviour tests.
func (m *MockDatabaseOperations) GetConfigsCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getConfigsCalls
}

func (m *MockDatabaseOperations) CreateWebhookDelivery(delivery *Delivery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delivery.ID = int64(len(m.deliveries) + 1)
	delivery.CreatedAt = time.Now()
	m.deliveries = append(m.deliveries, delivery)
	return nil
}

func (m *MockDatabaseOperations) UpdateWebhookDelivery(delivery *Delivery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, d := range m.deliveries {
		if d.ID == delivery.ID {
			m.deliveries[i] = delivery
			return nil
		}
	}
	return nil
}

func (m *MockDatabaseOperations) GetWebhookConfig(id int64) (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.configs {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, nil
}

func (m *MockDatabaseOperations) GetPendingRetries() ([]*Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pendingRetries, nil
}

// MockMetricsRecorder implements MetricsRecorder for testing
type MockMetricsRecorder struct {
	events        int
	deliveries    int
	retries       int
	droppedEvents int
	queueSize     int
	mu            sync.Mutex
}

func (m *MockMetricsRecorder) RecordEvent(eventType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events++
}

func (m *MockMetricsRecorder) RecordDelivery(eventType, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deliveries++
}

func (m *MockMetricsRecorder) RecordDeliveryDuration(eventType string, duration time.Duration) {
	// No-op for testing
}

func (m *MockMetricsRecorder) RecordRetry(eventType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retries++
}

func (m *MockMetricsRecorder) RecordDroppedEvent() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.droppedEvents++
}

func (m *MockMetricsRecorder) SetQueueSize(size int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queueSize = size
}

func TestNewDispatcher(t *testing.T) {
	mockDB := &MockDatabaseOperations{}
	mockMetrics := &MockMetricsRecorder{}

	dispatcher := NewDispatcher(mockDB, 5, 1000, mockMetrics)

	if dispatcher == nil {
		t.Fatal("NewDispatcher() returned nil")
	}
	if dispatcher.workerCount != 5 {
		t.Errorf("workerCount = %d, want 5", dispatcher.workerCount)
	}
	if cap(dispatcher.eventChan) != 1000 {
		t.Errorf("eventChan capacity = %d, want 1000", cap(dispatcher.eventChan))
	}
}

func TestDispatcher_StartShutdown(t *testing.T) {
	mockDB := &MockDatabaseOperations{}
	mockMetrics := &MockMetricsRecorder{}

	dispatcher := NewDispatcher(mockDB, 2, 10, mockMetrics)
	dispatcher.Start()

	// Give workers time to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown
	dispatcher.Shutdown()

	// Verify shutdown completed (should not hang)
}

func TestDispatcher_Emit(t *testing.T) {
	mockDB := &MockDatabaseOperations{
		configs: []*Config{},
	}
	mockMetrics := &MockMetricsRecorder{}

	dispatcher := NewDispatcher(mockDB, 2, 10, mockMetrics)
	dispatcher.Start()
	defer dispatcher.Shutdown()

	event := &Event{
		Type:      EventFileUploaded,
		Timestamp: time.Now(),
		File: FileData{
			ClaimCode: "TEST123",
			Filename:  "test.txt",
			Size:      1024,
		},
	}

	dispatcher.Emit(event)

	// Give time for processing
	time.Sleep(200 * time.Millisecond)

	// Verify event was recorded
	mockMetrics.mu.Lock()
	eventsCount := mockMetrics.events
	mockMetrics.mu.Unlock()

	if eventsCount != 1 {
		t.Errorf("events recorded = %d, want 1", eventsCount)
	}
}

func TestDispatcher_Emit_ChannelFull(t *testing.T) {
	mockDB := &MockDatabaseOperations{}
	mockMetrics := &MockMetricsRecorder{}

	// Create dispatcher with very small buffer
	dispatcher := NewDispatcher(mockDB, 1, 2, mockMetrics)

	event := &Event{
		Type:      EventFileUploaded,
		Timestamp: time.Now(),
		File:      FileData{ClaimCode: "TEST123"},
	}

	// Fill the channel (don't start dispatcher so nothing drains)
	for i := 0; i < 3; i++ {
		dispatcher.Emit(event)
	}

	// Give time for dropped event to be recorded
	time.Sleep(50 * time.Millisecond)

	// Verify dropped event was recorded
	mockMetrics.mu.Lock()
	droppedCount := mockMetrics.droppedEvents
	mockMetrics.mu.Unlock()

	if droppedCount == 0 {
		t.Error("Expected dropped event when channel full")
	}
}

func TestDispatcher_Emit_AfterShutdown(t *testing.T) {
	mockDB := &MockDatabaseOperations{}
	mockMetrics := &MockMetricsRecorder{}

	dispatcher := NewDispatcher(mockDB, 2, 10, mockMetrics)
	dispatcher.Start()
	dispatcher.Shutdown()

	event := &Event{
		Type:      EventFileUploaded,
		Timestamp: time.Now(),
		File:      FileData{ClaimCode: "TEST123"},
	}

	// Emit after shutdown
	dispatcher.Emit(event)

	// Give time for processing
	time.Sleep(50 * time.Millisecond)

	// Verify dropped event was recorded (should be dropped due to shutdown)
	mockMetrics.mu.Lock()
	droppedCount := mockMetrics.droppedEvents
	mockMetrics.mu.Unlock()

	if droppedCount == 0 {
		t.Error("Expected dropped event after shutdown")
	}
}

func TestDispatcher_GetQueueSize(t *testing.T) {
	mockDB := &MockDatabaseOperations{}
	mockMetrics := &MockMetricsRecorder{}

	dispatcher := NewDispatcher(mockDB, 2, 100, mockMetrics)

	// Initial queue size should be 0
	if size := dispatcher.GetQueueSize(); size != 0 {
		t.Errorf("initial queue size = %d, want 0", size)
	}

	// Don't start dispatcher so events stay in queue
	event := &Event{
		Type:      EventFileUploaded,
		Timestamp: time.Now(),
		File:      FileData{ClaimCode: "TEST123"},
	}

	dispatcher.Emit(event)

	// Queue size should be 1
	if size := dispatcher.GetQueueSize(); size != 1 {
		t.Errorf("queue size after emit = %d, want 1", size)
	}
}

func TestDispatcher_ProcessEvent_NoConfigs(t *testing.T) {
	mockDB := &MockDatabaseOperations{
		configs: []*Config{}, // No webhook configs
	}
	mockMetrics := &MockMetricsRecorder{}

	dispatcher := NewDispatcher(mockDB, 2, 10, mockMetrics)
	dispatcher.Start()
	defer dispatcher.Shutdown()

	event := &Event{
		Type:      EventFileUploaded,
		Timestamp: time.Now(),
		File:      FileData{ClaimCode: "TEST123"},
	}

	dispatcher.Emit(event)

	// Give time for processing
	time.Sleep(200 * time.Millisecond)

	// Verify no deliveries created
	mockDB.mu.Lock()
	deliveryCount := len(mockDB.deliveries)
	mockDB.mu.Unlock()

	if deliveryCount != 0 {
		t.Errorf("deliveries created = %d, want 0 (no configs)", deliveryCount)
	}
}

func TestDispatcher_ProcessEvent_WithSubscribedConfig(t *testing.T) {
	mockDB := &MockDatabaseOperations{
		configs: []*Config{
			{
				ID:             1,
				URL:            "http://example.com/webhook",
				Secret:         "test-secret",
				Enabled:        true,
				Events:         []string{"file.uploaded"},
				Format:         FormatSafeShare,
				MaxRetries:     3,
				TimeoutSeconds: 10,
			},
		},
	}
	mockMetrics := &MockMetricsRecorder{}

	dispatcher := NewDispatcher(mockDB, 2, 10, mockMetrics)
	dispatcher.Start()
	defer dispatcher.Shutdown()

	event := &Event{
		Type:      EventFileUploaded,
		Timestamp: time.Now(),
		File:      FileData{ClaimCode: "TEST123", Filename: "test.txt", Size: 1024},
	}

	dispatcher.Emit(event)

	// Give time for processing
	time.Sleep(500 * time.Millisecond)

	// Verify delivery was created (though it will fail due to invalid URL)
	mockDB.mu.Lock()
	deliveryCount := len(mockDB.deliveries)
	mockDB.mu.Unlock()

	if deliveryCount != 1 {
		t.Errorf("deliveries created = %d, want 1", deliveryCount)
	}
}

func TestDispatcher_ProcessEvent_NotSubscribed(t *testing.T) {
	mockDB := &MockDatabaseOperations{
		configs: []*Config{
			{
				ID:             1,
				URL:            "http://example.com/webhook",
				Secret:         "test-secret",
				Enabled:        true,
				Events:         []string{"file.downloaded"}, // Not subscribed to uploaded
				Format:         FormatSafeShare,
				MaxRetries:     3,
				TimeoutSeconds: 10,
			},
		},
	}
	mockMetrics := &MockMetricsRecorder{}

	dispatcher := NewDispatcher(mockDB, 2, 10, mockMetrics)
	dispatcher.Start()
	defer dispatcher.Shutdown()

	event := &Event{
		Type:      EventFileUploaded, // Different event type
		Timestamp: time.Now(),
		File:      FileData{ClaimCode: "TEST123"},
	}

	dispatcher.Emit(event)

	// Give time for processing
	time.Sleep(200 * time.Millisecond)

	// Verify no delivery created (not subscribed)
	mockDB.mu.Lock()
	deliveryCount := len(mockDB.deliveries)
	mockDB.mu.Unlock()

	if deliveryCount != 0 {
		t.Errorf("deliveries created = %d, want 0 (not subscribed)", deliveryCount)
	}
}

// TestDispatcher_ConfigCache_HitsCacheWithinTTL — SH-3.2.
// Within the TTL window, repeated processEvent calls must serve enabled-
// configs from the in-process cache; only the first call should hit the DB.
func TestDispatcher_ConfigCache_HitsCacheWithinTTL(t *testing.T) {
	mockDB := &MockDatabaseOperations{
		configs: []*Config{
			{ID: 1, URL: "https://example.invalid/hook", Enabled: true, Events: []string{string(EventFileUploaded)}, Format: "safeshare"},
		},
	}
	mockMetrics := &MockMetricsRecorder{}
	dispatcher := NewDispatcher(mockDB, 1, 16, mockMetrics)

	// processEvent calls go via the cache. Use an event type that isn't subscribed
	// so we skip the delivery side-effects but still exercise getConfigsCached.
	event := &Event{Type: EventFileDeleted, Timestamp: time.Now()}

	for i := 0; i < 50; i++ {
		dispatcher.processEvent(event)
	}

	if got := mockDB.GetConfigsCalls(); got != 1 {
		t.Errorf("GetEnabledWebhookConfigs calls = %d, want 1 (cache must serve repeated reads within TTL)", got)
	}
}

// TestDispatcher_ConfigCache_InvalidateForcesRefresh — SH-3.2.
// InvalidateConfigCache must force the next processEvent to re-query the DB,
// matching what the admin handlers do after a create/update/delete.
func TestDispatcher_ConfigCache_InvalidateForcesRefresh(t *testing.T) {
	mockDB := &MockDatabaseOperations{
		configs: []*Config{
			{ID: 1, URL: "https://example.invalid/hook", Enabled: true, Events: []string{string(EventFileUploaded)}, Format: "safeshare"},
		},
	}
	mockMetrics := &MockMetricsRecorder{}
	dispatcher := NewDispatcher(mockDB, 1, 16, mockMetrics)
	event := &Event{Type: EventFileDeleted, Timestamp: time.Now()}

	// Warm the cache.
	dispatcher.processEvent(event)
	if got := mockDB.GetConfigsCalls(); got != 1 {
		t.Fatalf("after warm-up: GetConfigsCalls = %d, want 1", got)
	}

	// Cached read — counter must not move.
	dispatcher.processEvent(event)
	if got := mockDB.GetConfigsCalls(); got != 1 {
		t.Fatalf("after cached read: GetConfigsCalls = %d, want 1", got)
	}

	// Simulate an admin edit.
	dispatcher.InvalidateConfigCache()

	// Next call re-queries.
	dispatcher.processEvent(event)
	if got := mockDB.GetConfigsCalls(); got != 2 {
		t.Errorf("after invalidate: GetConfigsCalls = %d, want 2 (invalidate must force refresh)", got)
	}
}

// TestDispatcher_ConfigCache_FirstCallPopulatesAndReturnsConfigs — SH-3.2.
// Sanity check the slow-path branch returns the configs (not nil) on first
// call when the cache is empty.
func TestDispatcher_ConfigCache_FirstCallPopulatesAndReturnsConfigs(t *testing.T) {
	expected := []*Config{
		{ID: 1, URL: "https://example.invalid/hook", Enabled: true, Events: []string{string(EventFileUploaded)}, Format: "safeshare"},
		{ID: 2, URL: "https://example.invalid/hook2", Enabled: true, Events: []string{string(EventFileExpired)}, Format: "safeshare"},
	}
	mockDB := &MockDatabaseOperations{configs: expected}
	mockMetrics := &MockMetricsRecorder{}
	dispatcher := NewDispatcher(mockDB, 1, 16, mockMetrics)

	got, err := dispatcher.getConfigsCached()
	if err != nil {
		t.Fatalf("getConfigsCached: %v", err)
	}
	if len(got) != len(expected) {
		t.Errorf("returned configs length = %d, want %d", len(got), len(expected))
	}
}
