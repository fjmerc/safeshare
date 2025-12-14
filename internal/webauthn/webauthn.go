// Package webauthn provides WebAuthn/FIDO2 authentication support for SafeShare.
// It wraps the go-webauthn library to provide hardware key authentication as an MFA method.
package webauthn

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
)

// Service provides WebAuthn authentication functionality.
type Service struct {
	webAuthn *gowebauthn.WebAuthn
	config   *config.Config
}

// NewService creates a new WebAuthn service with the given configuration.
// The config must have MFA enabled and valid WebAuthn settings (RPID, origins).
func NewService(cfg *config.Config) (*Service, error) {
	if cfg.MFA == nil || !cfg.MFA.Enabled || !cfg.MFA.WebAuthnEnabled {
		return nil, fmt.Errorf("WebAuthn is not enabled in configuration")
	}

	// Determine RPID from PublicURL or use default
	rpID := extractRPID(cfg.PublicURL)
	if rpID == "" {
		rpID = "localhost"
	}

	// Determine origins from PublicURL
	origins := extractOrigins(cfg.PublicURL)
	if len(origins) == 0 {
		origins = []string{"http://localhost:8080"}
	}

	webAuthnConfig := &gowebauthn.Config{
		RPDisplayName: cfg.MFA.Issuer, // Use the same issuer as TOTP for consistency
		RPID:          rpID,
		RPOrigins:     origins,
		Timeouts: gowebauthn.TimeoutsConfig{
			Login: gowebauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Duration(cfg.MFA.ChallengeExpiryMinutes) * time.Minute,
				TimeoutUVD: time.Duration(cfg.MFA.ChallengeExpiryMinutes) * time.Minute,
			},
			Registration: gowebauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Duration(cfg.MFA.ChallengeExpiryMinutes) * time.Minute,
				TimeoutUVD: time.Duration(cfg.MFA.ChallengeExpiryMinutes) * time.Minute,
			},
		},
	}

	w, err := gowebauthn.New(webAuthnConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn instance: %w", err)
	}

	return &Service{
		webAuthn: w,
		config:   cfg,
	}, nil
}

// extractRPID extracts the Relying Party ID (domain) from a URL.
// For example, "https://share.example.com" becomes "share.example.com"
func extractRPID(publicURL string) string {
	if publicURL == "" {
		return ""
	}

	// Remove protocol prefix
	url := strings.TrimPrefix(publicURL, "https://")
	url = strings.TrimPrefix(url, "http://")

	// Remove port if present
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	// Remove path if present
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	return url
}

// extractOrigins extracts allowed origins from a public URL.
// Returns the URL with protocol, optionally with and without www.
func extractOrigins(publicURL string) []string {
	if publicURL == "" {
		return nil
	}

	origins := []string{publicURL}

	// Remove trailing slash
	if strings.HasSuffix(publicURL, "/") {
		origins[0] = strings.TrimSuffix(publicURL, "/")
	}

	return origins
}

// WebAuthnUser implements the webauthn.User interface for SafeShare users.
type WebAuthnUser struct {
	ID          int64
	Name        string
	DisplayName string
	Credentials []gowebauthn.Credential
}

// WebAuthnID returns the user's ID as bytes (required by webauthn.User interface).
func (u *WebAuthnUser) WebAuthnID() []byte {
	// Encode user ID as base64 for the WebAuthn protocol
	return []byte(fmt.Sprintf("%d", u.ID))
}

// WebAuthnName returns the user's username (required by webauthn.User interface).
func (u *WebAuthnUser) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the user's display name (required by webauthn.User interface).
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Name
}

// WebAuthnCredentials returns the user's credentials (required by webauthn.User interface).
func (u *WebAuthnUser) WebAuthnCredentials() []gowebauthn.Credential {
	return u.Credentials
}

// WebAuthnIcon is deprecated but required by the interface.
func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

// CredentialToWebAuthn converts a repository WebAuthnCredential to the go-webauthn Credential type.
func CredentialToWebAuthn(cred *repository.WebAuthnCredential) (*gowebauthn.Credential, error) {
	// Decode credential ID from base64
	credentialID, err := base64.StdEncoding.DecodeString(cred.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode credential ID: %w", err)
	}

	// Decode public key from base64
	publicKey, err := base64.StdEncoding.DecodeString(cred.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	// Decode AAGUID from base64 if present
	var aaguid []byte
	if cred.AAGUID != "" {
		aaguid, _ = base64.StdEncoding.DecodeString(cred.AAGUID) // Best effort
	}

	// Convert transports to protocol types
	var transports []protocol.AuthenticatorTransport
	for _, t := range cred.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}

	return &gowebauthn.Credential{
		ID:              credentialID,
		PublicKey:       publicKey,
		AttestationType: cred.AttestationType,
		Transport:       transports,
		Flags: gowebauthn.CredentialFlags{
			UserPresent:    true,
			UserVerified:   cred.UserVerified,
			BackupEligible: cred.BackupEligible,
			BackupState:    cred.BackupState,
		},
		Authenticator: gowebauthn.Authenticator{
			AAGUID:    aaguid,
			SignCount: cred.SignCount,
		},
	}, nil
}

// WebAuthnToCredential converts a go-webauthn Credential to repository format.
func WebAuthnToCredential(userID int64, name string, cred *gowebauthn.Credential) *repository.WebAuthnCredential {
	// Encode credential ID to base64
	credentialID := base64.StdEncoding.EncodeToString(cred.ID)

	// Encode public key to base64
	publicKey := base64.StdEncoding.EncodeToString(cred.PublicKey)

	// Encode AAGUID to base64
	aaguid := ""
	if len(cred.Authenticator.AAGUID) > 0 {
		aaguid = base64.StdEncoding.EncodeToString(cred.Authenticator.AAGUID)
	}

	// Convert transports to strings
	var transports []string
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}

	return &repository.WebAuthnCredential{
		UserID:          userID,
		Name:            name,
		CredentialID:    credentialID,
		PublicKey:       publicKey,
		AAGUID:          aaguid,
		SignCount:       cred.Authenticator.SignCount,
		Transports:      transports,
		UserVerified:    cred.Flags.UserVerified,
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
		AttestationType: cred.AttestationType,
	}
}

// BeginRegistration starts the WebAuthn credential registration ceremony.
// Returns the credential creation options to send to the client and session data to store.
func (s *Service) BeginRegistration(user *WebAuthnUser) (*protocol.CredentialCreation, *gowebauthn.SessionData, error) {
	// Build exclusion list from existing credentials
	exclusions := make([]protocol.CredentialDescriptor, 0, len(user.Credentials))
	for _, cred := range user.Credentials {
		exclusions = append(exclusions, cred.Descriptor())
	}

	// Build registration options
	opts := []gowebauthn.RegistrationOption{
		// Exclude existing credentials to prevent re-registration
		gowebauthn.WithExclusions(exclusions),
		// Request credential properties extension to get transport info
		gowebauthn.WithExtensions(map[string]any{"credProps": true}),
		// Allow all authenticator attachment types (platform + cross-platform)
		gowebauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: "",                                      // Allow any
			ResidentKey:             protocol.ResidentKeyRequirementPreferred, // Prefer discoverable credentials
			UserVerification:        protocol.VerificationPreferred,
		}),
	}

	creation, session, err := s.webAuthn.BeginRegistration(user, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin WebAuthn registration: %w", err)
	}

	return creation, session, nil
}

// FinishRegistration completes the WebAuthn credential registration ceremony.
// Returns the new credential to store.
func (s *Service) FinishRegistration(user *WebAuthnUser, sessionData gowebauthn.SessionData, response *protocol.ParsedCredentialCreationData) (*gowebauthn.Credential, error) {
	credential, err := s.webAuthn.CreateCredential(user, sessionData, response)
	if err != nil {
		return nil, fmt.Errorf("failed to finish WebAuthn registration: %w", err)
	}

	return credential, nil
}

// BeginLogin starts the WebAuthn authentication ceremony.
// Returns the credential assertion options to send to the client and session data to store.
func (s *Service) BeginLogin(user *WebAuthnUser) (*protocol.CredentialAssertion, *gowebauthn.SessionData, error) {
	assertion, session, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin WebAuthn login: %w", err)
	}

	return assertion, session, nil
}

// FinishLogin completes the WebAuthn authentication ceremony.
// Returns the validated credential (with updated sign count).
func (s *Service) FinishLogin(user *WebAuthnUser, sessionData gowebauthn.SessionData, response *protocol.ParsedCredentialAssertionData) (*gowebauthn.Credential, error) {
	credential, err := s.webAuthn.ValidateLogin(user, sessionData, response)
	if err != nil {
		return nil, fmt.Errorf("failed to finish WebAuthn login: %w", err)
	}

	return credential, nil
}

// ValidateSignCount checks if the new sign count is greater than the stored count.
// This detects cloned authenticators - if signCount decreases, the authenticator may be cloned.
// Returns true if the sign count is valid (greater than stored), false if potential clone detected.
func ValidateSignCount(storedCount, newCount uint32) bool {
	// Special case: if storedCount is 0, this might be the first use after registration
	// Some authenticators don't implement sign counts and always return 0
	if storedCount == 0 && newCount == 0 {
		return true // Allow if both are 0 (authenticator doesn't implement sign count)
	}

	// The new count must be strictly greater than the stored count
	return newCount > storedCount
}

// GetRPID returns the Relying Party ID for this WebAuthn instance.
func (s *Service) GetRPID() string {
	return s.webAuthn.Config.RPID
}

// GetRPOrigins returns the allowed origins for this WebAuthn instance.
func (s *Service) GetRPOrigins() []string {
	return s.webAuthn.Config.RPOrigins
}
