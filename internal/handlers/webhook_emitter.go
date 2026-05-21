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

// InvalidateWebhookConfigCache tells the dispatcher to re-query its enabled-
// configs view on the next event. Called by webhook admin handlers after a
// create / update / delete so the config change propagates within one event
// rather than waiting up to the dispatcher's cache TTL. No-op when the
// dispatcher isn't installed (test setups, CLI tools).
//
// SH-3.2.
func InvalidateWebhookConfigCache() {
	if globalWebhookDispatcher != nil {
		globalWebhookDispatcher.InvalidateConfigCache()
	}
}
