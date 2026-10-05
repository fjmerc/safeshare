package handlers

import (
	"sync/atomic"

	"github.com/fjmerc/safeshare/internal/webhooks"
)

// webhookEmitGate decides, per event, whether webhooks may be emitted at all.
// It is consulted on every EmitWebhookEvent call (not cached) so a runtime
// feature-flag change takes effect immediately. Nil gate = always allowed
// (test setups, CLI tools).
var webhookEmitGate atomic.Pointer[func() bool]

// SetWebhookEmitGate installs the per-event gate. main.go passes a function
// that is true only when the Webhooks feature flag is on and anonymous mode
// is off.
func SetWebhookEmitGate(gate func() bool) {
	if gate == nil {
		webhookEmitGate.Store(nil)
		return
	}
	webhookEmitGate.Store(&gate)
}

// Global webhook dispatcher (set by main.go)
var globalWebhookDispatcher *webhooks.Dispatcher

// SetWebhookDispatcher sets the global webhook dispatcher instance
func SetWebhookDispatcher(dispatcher *webhooks.Dispatcher) {
	globalWebhookDispatcher = dispatcher
}

// EmitWebhookEvent emits a webhook event if dispatcher is initialized
func EmitWebhookEvent(event *webhooks.Event) {
	if g := webhookEmitGate.Load(); g != nil && !(*g)() {
		return
	}
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
