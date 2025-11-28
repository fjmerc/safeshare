package webhooks

import (
	"log/slog"
	"sync"
	"time"
)

// DatabaseOperations defines the interface for database operations needed by the dispatcher
type DatabaseOperations interface {
	GetEnabledWebhookConfigs() ([]*Config, error)
	CreateWebhookDelivery(delivery *Delivery) error
	UpdateWebhookDelivery(delivery *Delivery) error
	GetWebhookConfig(id int64) (*Config, error)
	GetPendingRetries() ([]*Delivery, error)
}

// Dispatcher handles asynchronous webhook delivery
type Dispatcher struct {
	db           DatabaseOperations
	eventChan    chan *Event
	workerCount  int
	shutdown     chan struct{}
	wg           sync.WaitGroup
	metrics      MetricsRecorder
	shutdownOnce sync.Once
}

// MetricsRecorder is an interface for recording webhook metrics
type MetricsRecorder interface {
	RecordEvent(eventType string)
	RecordDelivery(eventType, status string)
	RecordDeliveryDuration(eventType string, duration time.Duration)
	RecordRetry(eventType string)
	RecordDroppedEvent()
	SetQueueSize(size int)
}

// NewDispatcher creates a new webhook dispatcher
func NewDispatcher(db DatabaseOperations, workerCount, bufferSize int, metrics MetricsRecorder) *Dispatcher {
	return &Dispatcher{
		db:          db,
		eventChan:   make(chan *Event, bufferSize),
		workerCount: workerCount,
		shutdown:    make(chan struct{}),
		metrics:     metrics,
	}
}

// Start starts the webhook dispatcher workers
func (d *Dispatcher) Start() {
	slog.Info("starting webhook dispatcher", "workers", d.workerCount)

	for i := 0; i < d.workerCount; i++ {
		d.wg.Add(1)
		go d.worker(i)
	}

	// Start retry processor
	d.wg.Add(1)
	go d.retryProcessor()
}

// Shutdown gracefully shuts down the dispatcher
// Uses sync.Once to ensure safe shutdown even if called multiple times
func (d *Dispatcher) Shutdown() {
	d.shutdownOnce.Do(func() {
		slog.Info("shutting down webhook dispatcher")

		// Signal workers to stop first
		close(d.shutdown)

		// Close event channel to prevent new events and unblock workers
		// This is safe because shutdown channel is closed first, preventing
		// any new sends to eventChan via the Emit() method
		close(d.eventChan)
	})

	// Wait for all workers to finish processing (outside Once to allow multiple waiters)
	d.wg.Wait()

	slog.Info("webhook dispatcher shutdown complete")
}

// Emit emits a webhook event for delivery
func (d *Dispatcher) Emit(event *Event) {
	// Check if shutting down
	select {
	case <-d.shutdown:
		slog.Warn("webhook dispatcher shutting down, dropping event", "event_type", event.Type)
		d.metrics.RecordDroppedEvent()
		return
	default:
	}

	select {
	case d.eventChan <- event:
		d.metrics.RecordEvent(string(event.Type))
		// Update queue size metric
		d.metrics.SetQueueSize(len(d.eventChan))
	default:
		// Channel is full, drop event and record metric
		slog.Warn("webhook event channel full, dropping event", "event_type", event.Type)
		d.metrics.RecordDroppedEvent()
	}
}

// worker processes webhook events from the channel
func (d *Dispatcher) worker(id int) {
	defer d.wg.Done()

	slog.Debug("webhook worker started", "worker_id", id)

	for {
		select {
		case <-d.shutdown:
			slog.Debug("webhook worker shutting down", "worker_id", id)
			return
		case event, ok := <-d.eventChan:
			// Check if channel is closed
			if !ok {
				slog.Debug("webhook worker event channel closed", "worker_id", id)
				return
			}
			// Skip nil events (defensive check)
			if event == nil {
				slog.Warn("webhook worker received nil event", "worker_id", id)
				continue
			}
			d.processEvent(event)
			// Update queue size metric after processing
			d.metrics.SetQueueSize(len(d.eventChan))
		}
	}
}

// processEvent processes a single webhook event
func (d *Dispatcher) processEvent(event *Event) {
	// Get all enabled webhook configs
	configs, err := d.db.GetEnabledWebhookConfigs()
	if err != nil {
		slog.Error("failed to get enabled webhook configs", "error", err)
		return
	}

	// Filter configs subscribed to this event type
	for _, config := range configs {
		if !config.SubscribedTo(event.Type) {
			continue
		}

		// Transform event to appropriate format
		payload, err := TransformPayload(event, config.Format)
		if err != nil {
			slog.Error("failed to transform event payload", "error", err, "format", config.Format)
			continue
		}

		// Create delivery record
		delivery := &Delivery{
			WebhookConfigID: config.ID,
			EventType:       string(event.Type),
			Payload:         payload,
			AttemptCount:    0,
			Status:          string(DeliveryStatusPending),
		}

		if err := d.db.CreateWebhookDelivery(delivery); err != nil {
			slog.Error("failed to create webhook delivery record", "error", err)
			continue
		}

		// Attempt delivery
		d.attemptDelivery(config, delivery)
	}
}

// attemptDelivery attempts to deliver a webhook
func (d *Dispatcher) attemptDelivery(config *Config, delivery *Delivery) {
	startTime := time.Now()

	// Increment attempt count
	delivery.AttemptCount++

	// Deliver webhook with full config (supports service tokens)
	result := DeliverWebhookWithConfig(config, config.URL, config.Secret, delivery.Payload, config.TimeoutSeconds)

	duration := time.Since(startTime)
	d.metrics.RecordDeliveryDuration(delivery.EventType, duration)

	// Update delivery record based on result
	if result.Success {
		// Success
		delivery.Status = string(DeliveryStatusSuccess)
		delivery.ResponseCode = &result.ResponseCode
		delivery.ResponseBody = &result.ResponseBody
		now := time.Now()
		delivery.CompletedAt = &now

		d.metrics.RecordDelivery(delivery.EventType, "success")
	} else {
		// Failure - determine if we should retry
		if ShouldRetry(delivery.AttemptCount, config.MaxRetries) {
			// Schedule retry
			delivery.Status = string(DeliveryStatusRetrying)
			retryDelay := CalculateRetryDelay(delivery.AttemptCount - 1)
			nextRetry := time.Now().Add(retryDelay)
			delivery.NextRetryAt = &nextRetry

			d.metrics.RecordRetry(delivery.EventType)

			slog.Info("webhook delivery failed, scheduling retry",
				"url", config.URL,
				"attempt", delivery.AttemptCount,
				"max_retries", config.MaxRetries,
				"next_retry", nextRetry)
		} else {
			// Max retries exceeded
			delivery.Status = string(DeliveryStatusFailed)
			now := time.Now()
			delivery.CompletedAt = &now

			d.metrics.RecordDelivery(delivery.EventType, "failed")

			slog.Error("webhook delivery failed after max retries",
				"url", config.URL,
				"attempts", delivery.AttemptCount)
		}

		delivery.ResponseCode = &result.ResponseCode
		delivery.ResponseBody = &result.ResponseBody
		if result.Error != nil {
			errMsg := result.Error.Error()
			delivery.ErrorMessage = &errMsg
		}
	}

	// Update delivery record in database
	if err := d.db.UpdateWebhookDelivery(delivery); err != nil {
		slog.Error("failed to update webhook delivery record", "error", err)
	}
}

// retryProcessor periodically checks for failed deliveries that need retry
func (d *Dispatcher) retryProcessor() {
	defer d.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	slog.Debug("webhook retry processor started")

	for {
		select {
		case <-d.shutdown:
			slog.Debug("webhook retry processor shutting down")
			return
		case <-ticker.C:
			d.processRetries()
		}
	}
}

// processRetries processes pending retries
func (d *Dispatcher) processRetries() {
	// Get deliveries that need retry
	deliveries, err := d.db.GetPendingRetries()
	if err != nil {
		slog.Error("failed to get pending retries", "error", err)
		return
	}

	if len(deliveries) == 0 {
		return
	}

	slog.Debug("processing pending webhook retries", "count", len(deliveries))

	for _, delivery := range deliveries {
		// Get webhook config
		config, err := d.db.GetWebhookConfig(delivery.WebhookConfigID)
		if err != nil {
			slog.Error("failed to get webhook config for retry", "config_id", delivery.WebhookConfigID, "error", err)
			continue
		}

		// Skip if config is now disabled
		if !config.Enabled {
			slog.Debug("skipping retry for disabled webhook", "config_id", config.ID)
			continue
		}

		// Attempt delivery
		d.attemptDelivery(config, delivery)
	}
}

// GetQueueSize returns the current size of the event queue
func (d *Dispatcher) GetQueueSize() int {
	return len(d.eventChan)
}
