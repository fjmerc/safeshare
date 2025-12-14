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

// SSO Config Setters - allow runtime updates to SSO configuration

// SetSSOEnabled enables or disables the SSO feature.
func (c *Config) SetSSOEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.SSO == nil {
		c.SSO = &SSOConfig{
			DefaultRole:        "user",
			SessionLifetime:    480,
			StateExpiryMinutes: 10,
		}
	}
	c.SSO.Enabled = enabled
}

// SetSSOAutoProvision sets whether users are auto-provisioned on first SSO login.
func (c *Config) SetSSOAutoProvision(autoProvision bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.SSO != nil {
		c.SSO.AutoProvision = autoProvision
	}
}

// SetSSODefaultRole sets the default role for auto-provisioned users.
func (c *Config) SetSSODefaultRole(role string) error {
	if role != "user" && role != "admin" {
		return fmt.Errorf("SSO default role must be 'user' or 'admin'")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.SSO != nil {
		c.SSO.DefaultRole = role
	}
	return nil
}

// SetSSOSessionLifetime sets the SSO session lifetime in minutes.
func (c *Config) SetSSOSessionLifetime(minutes int) error {
	if minutes < 5 || minutes > 43200 {
		return fmt.Errorf("SSO session lifetime must be between 5 and 43200 minutes")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.SSO != nil {
		c.SSO.SessionLifetime = minutes
	}
	return nil
}

// SetSSOStateExpiryMinutes sets how long OAuth2 state tokens are valid.
func (c *Config) SetSSOStateExpiryMinutes(minutes int) error {
	if minutes < 5 || minutes > 60 {
		return fmt.Errorf("SSO state expiry must be between 5 and 60 minutes")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.SSO != nil {
		c.SSO.StateExpiryMinutes = minutes
	}
	return nil
}

// GetSSOConfig returns a copy of the current SSO configuration.
func (c *Config) GetSSOConfig() *SSOConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.SSO == nil {
		return nil
	}
	// Return a copy
	return &SSOConfig{
		Enabled:            c.SSO.Enabled,
		AutoProvision:      c.SSO.AutoProvision,
		DefaultRole:        c.SSO.DefaultRole,
		SessionLifetime:    c.SSO.SessionLifetime,
		StateExpiryMinutes: c.SSO.StateExpiryMinutes,
	}
}
