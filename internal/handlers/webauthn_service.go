package handlers

import (
	"sync"

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
