package handlers

import (
	"log/slog"
	"sync"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/webauthn"
)

// webauthnService holds the shared WebAuthn service instance.
// This can be updated at runtime when MFA configuration changes.
var (
	webauthnServiceMu sync.RWMutex
	webauthnService   *webauthn.Service
)

// SetWebAuthnService sets the WebAuthn service to be used by handlers.
// This is called during application initialization and when MFA configuration
// is updated via the admin dashboard.
// Thread-safe: can be called while handlers are processing requests.
func SetWebAuthnService(svc *webauthn.Service) {
	webauthnServiceMu.Lock()
	defer webauthnServiceMu.Unlock()
	webauthnService = svc
}

// GetWebAuthnService returns the configured WebAuthn service.
// Returns nil if WebAuthn has not been initialized (e.g., MFA disabled at startup
// and not yet enabled via admin dashboard).
// Thread-safe: can be called concurrently from multiple handlers.
func GetWebAuthnService() *webauthn.Service {
	webauthnServiceMu.RLock()
	defer webauthnServiceMu.RUnlock()
	return webauthnService
}

// InitializeOrClearWebAuthn initializes or clears the WebAuthn service based on
// the current MFA configuration. This should be called whenever MFA settings change.
//
// The function takes a snapshot of the MFA config to avoid TOCTOU race conditions.
// Returns a warning message if WebAuthn initialization fails (empty string on success).
//
// Thread-safe: can be called while handlers are processing requests.
func InitializeOrClearWebAuthn(cfg *config.Config, clientIP string) string {
	// Take a snapshot of MFA config to avoid TOCTOU race conditions
	mfaCfg := cfg.GetMFAConfig()

	// Check if WebAuthn should be enabled
	if mfaCfg != nil && mfaCfg.Enabled && mfaCfg.WebAuthnEnabled {
		newSvc, err := webauthn.NewService(cfg)
		if err != nil {
			slog.Error("failed to initialize WebAuthn service",
				"error", err,
				"ip", clientIP,
			)
			// Return warning - WebAuthn is optional, TOTP still works
			return "WebAuthn initialization failed - security keys will not work. Check PUBLIC_URL configuration. Error: " + err.Error()
		}
		SetWebAuthnService(newSvc)
		slog.Info("WebAuthn service initialized",
			"rpid", newSvc.GetRPID(),
			"origins", newSvc.GetRPOrigins(),
		)
		return ""
	}

	// MFA or WebAuthn disabled - clear the service if it was previously set
	if GetWebAuthnService() != nil {
		SetWebAuthnService(nil)
		slog.Info("WebAuthn service cleared (MFA or WebAuthn disabled)")
	}
	return ""
}
