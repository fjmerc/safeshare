package config

import "fmt"

// SSOConfig holds Single Sign-On configuration.
type SSOConfig struct {
	Enabled            bool   // Enable SSO feature globally (default: false)
	AutoProvision      bool   // Create users on first SSO login (default: false)
	DefaultRole        string // Default role for auto-provisioned users (default: "user")
	SessionLifetime    int    // SSO session lifetime in minutes (default: 480 = 8 hours)
	StateExpiryMinutes int    // OAuth2 state expiry in minutes (default: 10)
}

// loadSSOConfig loads SSO configuration from environment variables.
// Environment variables:
//   - ENABLE_SSO: Enable SSO feature globally (default: false)
//   - SSO_AUTO_PROVISION: Create users on first SSO login (default: false)
//   - SSO_DEFAULT_ROLE: Default role for auto-provisioned users (default: "user")
//   - SSO_SESSION_LIFETIME: SSO session lifetime in minutes (default: 480 = 8 hours)
//   - SSO_STATE_EXPIRY_MINUTES: OAuth2 state expiry in minutes (default: 10)
func loadSSOConfig() *SSOConfig {
	return &SSOConfig{
		Enabled:            getEnvBool("ENABLE_SSO", false),
		AutoProvision:      getEnvBool("SSO_AUTO_PROVISION", false),
		DefaultRole:        getEnv("SSO_DEFAULT_ROLE", "user"),
		SessionLifetime:    getEnvInt("SSO_SESSION_LIFETIME", 480),    // 8 hours
		StateExpiryMinutes: getEnvInt("SSO_STATE_EXPIRY_MINUTES", 10), // 10 minutes
	}
}

// validateSSOSettings validates SSO configuration.
func (c *Config) validateSSOSettings() error {
	if c.SSO == nil {
		return nil // SSO config is optional (will use defaults)
	}

	// If SSO is not enabled, skip further validation
	if !c.SSO.Enabled {
		return nil
	}

	// Validate DefaultRole (must be "user" or "admin" if not empty)
	if c.SSO.DefaultRole != "" {
		validRoles := map[string]bool{"user": true, "admin": true}
		if !validRoles[c.SSO.DefaultRole] {
			return fmt.Errorf("SSO_DEFAULT_ROLE must be 'user' or 'admin', got '%s'", c.SSO.DefaultRole)
		}
	}

	// Validate SessionLifetime (5 minutes to 30 days = 43200 minutes)
	if c.SSO.SessionLifetime < 5 || c.SSO.SessionLifetime > 43200 {
		return fmt.Errorf("SSO_SESSION_LIFETIME must be between 5 and 43200 minutes, got %d", c.SSO.SessionLifetime)
	}

	// Validate StateExpiryMinutes (5 to 60 minutes)
	if c.SSO.StateExpiryMinutes < 5 || c.SSO.StateExpiryMinutes > 60 {
		return fmt.Errorf("SSO_STATE_EXPIRY_MINUTES must be between 5 and 60 minutes, got %d", c.SSO.StateExpiryMinutes)
	}

	return nil
}
