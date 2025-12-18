package handlers

import (
	"testing"
)

func TestSetWebhookDispatcher(t *testing.T) {
	// Reset to nil initially
	SetWebhookDispatcher(nil)

	// Test setting to nil (should not panic)
	SetWebhookDispatcher(nil)

	// globalWebhookDispatcher should be nil
	// We can't directly check this, but EmitWebhookEvent should handle nil safely
}

func TestEmitWebhookEvent_NilDispatcher(t *testing.T) {
	// Ensure dispatcher is nil
	SetWebhookDispatcher(nil)

	// This should not panic when dispatcher is nil
	EmitWebhookEvent(nil)
}
