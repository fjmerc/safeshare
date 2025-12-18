package handlers

import (
	"testing"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/testutil"
)

func TestSetAndGetWebAuthnService(t *testing.T) {
	// Ensure service starts as nil
	SetWebAuthnService(nil)

	if svc := GetWebAuthnService(); svc != nil {
		t.Error("WebAuthn service should be nil initially")
	}

	// Setting to nil should work without panic
	SetWebAuthnService(nil)

	if svc := GetWebAuthnService(); svc != nil {
		t.Error("WebAuthn service should still be nil")
	}
}

func TestGetWebAuthnService_ThreadSafety(t *testing.T) {
	// Reset to nil
	SetWebAuthnService(nil)

	// Run multiple concurrent reads - should not panic
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_ = GetWebAuthnService()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestInitializeOrClearWebAuthn_MFADisabled(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	// Ensure MFA is disabled
	cfg.SetMFAEnabled(false)

	// Reset WebAuthn service
	SetWebAuthnService(nil)

	warning := InitializeOrClearWebAuthn(cfg, "127.0.0.1")

	// Should return no warning
	if warning != "" {
		t.Errorf("Expected no warning when MFA disabled, got: %s", warning)
	}

	// Service should still be nil
	if svc := GetWebAuthnService(); svc != nil {
		t.Error("WebAuthn service should remain nil when MFA disabled")
	}
}

func TestInitializeOrClearWebAuthn_WebAuthnDisabled(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	// Enable MFA but disable WebAuthn
	cfg.SetMFAEnabled(true)
	cfg.SetMFAWebAuthnEnabled(false)

	// Reset WebAuthn service
	SetWebAuthnService(nil)

	warning := InitializeOrClearWebAuthn(cfg, "127.0.0.1")

	// Should return no warning
	if warning != "" {
		t.Errorf("Expected no warning when WebAuthn disabled, got: %s", warning)
	}

	// Service should still be nil
	if svc := GetWebAuthnService(); svc != nil {
		t.Error("WebAuthn service should remain nil when WebAuthn disabled")
	}
}

func TestInitializeOrClearWebAuthn_EnabledWithValidConfig(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	// Set PublicURL for WebAuthn (required for valid RPID)
	cfg.PublicURL = "https://example.com"

	// Enable MFA and WebAuthn
	cfg.SetMFAEnabled(true)
	cfg.SetMFAWebAuthnEnabled(true)

	// Reset WebAuthn service
	SetWebAuthnService(nil)

	warning := InitializeOrClearWebAuthn(cfg, "127.0.0.1")

	// Should return no warning with valid config
	if warning != "" {
		t.Errorf("Expected no warning with valid config, got: %s", warning)
	}

	// Service should be initialized
	svc := GetWebAuthnService()
	if svc == nil {
		t.Error("WebAuthn service should be initialized when MFA and WebAuthn enabled")
	}

	// Verify RPID was extracted correctly
	if svc != nil && svc.GetRPID() != "example.com" {
		t.Errorf("Expected RPID 'example.com', got '%s'", svc.GetRPID())
	}

	// Cleanup
	SetWebAuthnService(nil)
}

func TestInitializeOrClearWebAuthn_EnabledWithLocalhost(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	// No PublicURL set - should default to localhost
	cfg.PublicURL = ""

	// Enable MFA and WebAuthn
	cfg.SetMFAEnabled(true)
	cfg.SetMFAWebAuthnEnabled(true)

	// Reset WebAuthn service
	SetWebAuthnService(nil)

	warning := InitializeOrClearWebAuthn(cfg, "127.0.0.1")

	// Should return no warning - defaults to localhost
	if warning != "" {
		t.Errorf("Expected no warning with localhost default, got: %s", warning)
	}

	// Service should be initialized with localhost defaults
	svc := GetWebAuthnService()
	if svc == nil {
		t.Error("WebAuthn service should be initialized with localhost defaults")
	}

	if svc != nil && svc.GetRPID() != "localhost" {
		t.Errorf("Expected RPID 'localhost', got '%s'", svc.GetRPID())
	}

	// Cleanup
	SetWebAuthnService(nil)
}

func TestInitializeOrClearWebAuthn_ClearsExistingService(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	// First, initialize the service
	cfg.PublicURL = "https://example.com"
	cfg.SetMFAEnabled(true)
	cfg.SetMFAWebAuthnEnabled(true)

	warning := InitializeOrClearWebAuthn(cfg, "127.0.0.1")
	if warning != "" {
		t.Fatalf("Failed to initialize: %s", warning)
	}

	if GetWebAuthnService() == nil {
		t.Fatal("Service should be initialized")
	}

	// Now disable MFA - should clear the service
	cfg.SetMFAEnabled(false)

	warning = InitializeOrClearWebAuthn(cfg, "127.0.0.1")
	if warning != "" {
		t.Errorf("Expected no warning when disabling, got: %s", warning)
	}

	if GetWebAuthnService() != nil {
		t.Error("Service should be cleared when MFA disabled")
	}
}

func TestInitializeOrClearWebAuthn_ClearsWhenWebAuthnDisabled(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	// First, initialize the service
	cfg.PublicURL = "https://example.com"
	cfg.SetMFAEnabled(true)
	cfg.SetMFAWebAuthnEnabled(true)

	warning := InitializeOrClearWebAuthn(cfg, "127.0.0.1")
	if warning != "" {
		t.Fatalf("Failed to initialize: %s", warning)
	}

	if GetWebAuthnService() == nil {
		t.Fatal("Service should be initialized")
	}

	// Now disable WebAuthn only (MFA still enabled) - should clear the service
	cfg.SetMFAWebAuthnEnabled(false)

	warning = InitializeOrClearWebAuthn(cfg, "127.0.0.1")
	if warning != "" {
		t.Errorf("Expected no warning when disabling WebAuthn, got: %s", warning)
	}

	if GetWebAuthnService() != nil {
		t.Error("Service should be cleared when WebAuthn disabled")
	}
}

func TestInitializeOrClearWebAuthn_NoopWhenAlreadyCleared(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	// Ensure service is nil
	SetWebAuthnService(nil)

	// Disable MFA
	cfg.SetMFAEnabled(false)

	// Should not log "cleared" message when already nil
	warning := InitializeOrClearWebAuthn(cfg, "127.0.0.1")
	if warning != "" {
		t.Errorf("Expected no warning, got: %s", warning)
	}

	// Service should still be nil
	if GetWebAuthnService() != nil {
		t.Error("Service should remain nil")
	}
}

func TestInitializeOrClearWebAuthn_WithNilMFAConfig(t *testing.T) {
	// Create a minimal config without MFA
	cfg := &config.Config{
		MFA:      nil,
		Features: config.NewFeatureFlags(),
	}

	// Reset WebAuthn service
	SetWebAuthnService(nil)

	warning := InitializeOrClearWebAuthn(cfg, "127.0.0.1")

	// Should return no warning
	if warning != "" {
		t.Errorf("Expected no warning with nil MFA config, got: %s", warning)
	}

	// Service should be nil
	if GetWebAuthnService() != nil {
		t.Error("WebAuthn service should be nil with nil MFA config")
	}
}

func TestInitializeOrClearWebAuthn_ReinitializeWithDifferentConfig(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	// First initialization with example.com
	cfg.PublicURL = "https://example.com"
	cfg.SetMFAEnabled(true)
	cfg.SetMFAWebAuthnEnabled(true)

	warning := InitializeOrClearWebAuthn(cfg, "127.0.0.1")
	if warning != "" {
		t.Fatalf("Failed to initialize: %s", warning)
	}

	svc := GetWebAuthnService()
	if svc == nil || svc.GetRPID() != "example.com" {
		t.Fatal("Service should be initialized with example.com")
	}

	// Reinitialize with different domain
	cfg.PublicURL = "https://test.example.org"

	warning = InitializeOrClearWebAuthn(cfg, "127.0.0.1")
	if warning != "" {
		t.Errorf("Expected no warning on reinit, got: %s", warning)
	}

	svc = GetWebAuthnService()
	if svc == nil {
		t.Fatal("Service should be reinitialized")
	}

	if svc.GetRPID() != "test.example.org" {
		t.Errorf("Expected RPID 'test.example.org', got '%s'", svc.GetRPID())
	}

	// Cleanup
	SetWebAuthnService(nil)
}
