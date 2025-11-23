package handlers

import (
	"github.com/fjmerc/safeshare/internal/webhooks"
)

// Global webhook dispatcher (set by main.go)
var globalWebhookDispatcher *webhooks.Dispatcher

// SetWebhookDispatcher sets the global webhook dispatcher instance
func SetWebhookDispatcher(dispatcher *webhooks.Dispatcher) {
	globalWebhookDispatcher = dispatcher
}

// EmitWebhookEvent emits a webhook event if dispatcher is initialized
func EmitWebhookEvent(event *webhooks.Event) {
	if globalWebhookDispatcher != nil {
		globalWebhookDispatcher.Emit(event)
	}
}
