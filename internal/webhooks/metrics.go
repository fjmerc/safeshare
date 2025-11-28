package webhooks

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics for webhooks
var (
	// WebhookEventsTotal counts webhook events emitted by event type
	WebhookEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "safeshare_webhook_events_total",
			Help: "Total number of webhook events emitted",
		},
		[]string{"event_type"},
	)

	// WebhookDeliveriesTotal counts webhook delivery attempts by status and event type
	WebhookDeliveriesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "safeshare_webhook_deliveries_total",
			Help: "Total number of webhook delivery attempts",
		},
		[]string{"event_type", "status"},
	)

	// WebhookDeliveryDuration tracks webhook delivery latency by event type
	WebhookDeliveryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "safeshare_webhook_delivery_duration_seconds",
			Help:    "Webhook delivery latency in seconds",
			Buckets: []float64{.1, .25, .5, 1, 2.5, 5, 10, 30, 60},
		},
		[]string{"event_type"},
	)

	// WebhookRetriesTotal counts webhook retry attempts by event type
	WebhookRetriesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "safeshare_webhook_retries_total",
			Help: "Total number of webhook retry attempts",
		},
		[]string{"event_type"},
	)

	// WebhookQueueSize is a gauge representing current event queue size
	WebhookQueueSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "safeshare_webhook_queue_size",
			Help: "Current size of the webhook event queue",
		},
	)

	// WebhookDroppedEventsTotal counts events dropped due to full queue
	WebhookDroppedEventsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "safeshare_webhook_dropped_events_total",
			Help: "Total number of webhook events dropped due to full queue",
		},
	)
)

// PrometheusMetrics implements MetricsRecorder using Prometheus
type PrometheusMetrics struct{}

// NewPrometheusMetrics creates a new Prometheus metrics recorder
func NewPrometheusMetrics() *PrometheusMetrics {
	return &PrometheusMetrics{}
}

// RecordEvent records a webhook event emission
func (m *PrometheusMetrics) RecordEvent(eventType string) {
	WebhookEventsTotal.WithLabelValues(eventType).Inc()
}

// RecordDelivery records a webhook delivery attempt
func (m *PrometheusMetrics) RecordDelivery(eventType, status string) {
	WebhookDeliveriesTotal.WithLabelValues(eventType, status).Inc()
}

// RecordDeliveryDuration records webhook delivery latency
func (m *PrometheusMetrics) RecordDeliveryDuration(eventType string, duration time.Duration) {
	WebhookDeliveryDuration.WithLabelValues(eventType).Observe(duration.Seconds())
}

// RecordRetry records a webhook retry attempt
func (m *PrometheusMetrics) RecordRetry(eventType string) {
	WebhookRetriesTotal.WithLabelValues(eventType).Inc()
}

// RecordDroppedEvent records a dropped webhook event
func (m *PrometheusMetrics) RecordDroppedEvent() {
	WebhookDroppedEventsTotal.Inc()
}

// SetQueueSize sets the current webhook queue size
func (m *PrometheusMetrics) SetQueueSize(size int) {
	WebhookQueueSize.Set(float64(size))
}
