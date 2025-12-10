package config

import (
	"os"
	"testing"
)

func TestLoadSSOConfig_Defaults(t *testing.T) {
	// Clear any existing SSO env vars
	os.Unsetenv("ENABLE_SSO")
	os.Unsetenv("SSO_AUTO_PROVISION")
	os.Unsetenv("SSO_DEFAULT_ROLE")
	os.Unsetenv("SSO_SESSION_LIFETIME")
	os.Unsetenv("SSO_STATE_EXPIRY_MINUTES")

	cfg := loadSSOConfig()

	if cfg.Enabled {
		t.Errorf("Expected Enabled=false by default, got %v", cfg.Enabled)
	}
	if cfg.AutoProvision {
		t.Errorf("Expected AutoProvision=false by default, got %v", cfg.AutoProvision)
	}
	if cfg.DefaultRole != "user" {
		t.Errorf("Expected DefaultRole='user', got %v", cfg.DefaultRole)
	}
	if cfg.SessionLifetime != 480 {
		t.Errorf("Expected SessionLifetime=480, got %v", cfg.SessionLifetime)
	}
	if cfg.StateExpiryMinutes != 10 {
		t.Errorf("Expected StateExpiryMinutes=10, got %v", cfg.StateExpiryMinutes)
	}
}

func TestLoadSSOConfig_CustomValues(t *testing.T) {
	// Set custom values
	os.Setenv("ENABLE_SSO", "true")
	os.Setenv("SSO_AUTO_PROVISION", "true")
	os.Setenv("SSO_DEFAULT_ROLE", "admin")
	os.Setenv("SSO_SESSION_LIFETIME", "120")
	os.Setenv("SSO_STATE_EXPIRY_MINUTES", "15")
	defer func() {
		os.Unsetenv("ENABLE_SSO")
		os.Unsetenv("SSO_AUTO_PROVISION")
		os.Unsetenv("SSO_DEFAULT_ROLE")
		os.Unsetenv("SSO_SESSION_LIFETIME")
		os.Unsetenv("SSO_STATE_EXPIRY_MINUTES")
	}()

	cfg := loadSSOConfig()

	if !cfg.Enabled {
		t.Errorf("Expected Enabled=true, got %v", cfg.Enabled)
	}
	if !cfg.AutoProvision {
		t.Errorf("Expected AutoProvision=true, got %v", cfg.AutoProvision)
	}
	if cfg.DefaultRole != "admin" {
		t.Errorf("Expected DefaultRole='admin', got %v", cfg.DefaultRole)
	}
	if cfg.SessionLifetime != 120 {
		t.Errorf("Expected SessionLifetime=120, got %v", cfg.SessionLifetime)
	}
	if cfg.StateExpiryMinutes != 15 {
		t.Errorf("Expected StateExpiryMinutes=15, got %v", cfg.StateExpiryMinutes)
	}
}

func TestValidateSSOSettings_NilConfig(t *testing.T) {
	cfg := &Config{
		SSO: nil,
	}

	err := cfg.validateSSOSettings()
	if err != nil {
		t.Errorf("Expected no error for nil SSO config, got %v", err)
	}
}

func TestValidateSSOSettings_Disabled(t *testing.T) {
	cfg := &Config{
		SSO: &SSOConfig{
			Enabled:            false,
			DefaultRole:        "invalid", // Invalid, but SSO is disabled
			SessionLifetime:    1,         // Invalid, but SSO is disabled
			StateExpiryMinutes: 1,         // Invalid, but SSO is disabled
		},
	}

	err := cfg.validateSSOSettings()
	if err != nil {
		t.Errorf("Expected no error for disabled SSO, got %v", err)
	}
}

func TestValidateSSOSettings_ValidRoles(t *testing.T) {
	tests := []struct {
		role    string
		wantErr bool
	}{
		{"user", false},
		{"admin", false},
		{"", false}, // Empty is valid (will use system default)
		{"superadmin", true},
		{"guest", true},
		{"moderator", true},
	}

	for _, tt := range tests {
		t.Run("role_"+tt.role, func(t *testing.T) {
			cfg := &Config{
				SSO: &SSOConfig{
					Enabled:            true,
					DefaultRole:        tt.role,
					SessionLifetime:    480,
					StateExpiryMinutes: 10,
				},
			}

			err := cfg.validateSSOSettings()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSSOSettings() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSSOSettings_SessionLifetime(t *testing.T) {
	tests := []struct {
		name     string
		lifetime int
		wantErr  bool
	}{
		{"minimum valid", 5, false},
		{"maximum valid", 43200, false},
		{"typical 8 hours", 480, false},
		{"too short", 4, true},
		{"zero", 0, true},
		{"negative", -1, true},
		{"too long", 43201, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				SSO: &SSOConfig{
					Enabled:            true,
					DefaultRole:        "user",
					SessionLifetime:    tt.lifetime,
					StateExpiryMinutes: 10,
				},
			}

			err := cfg.validateSSOSettings()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSSOSettings() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSSOSettings_StateExpiry(t *testing.T) {
	tests := []struct {
		name    string
		expiry  int
		wantErr bool
	}{
		{"minimum valid", 5, false},
		{"maximum valid", 60, false},
		{"typical 10 minutes", 10, false},
		{"too short", 4, true},
		{"zero", 0, true},
		{"negative", -1, true},
		{"too long", 61, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				SSO: &SSOConfig{
					Enabled:            true,
					DefaultRole:        "user",
					SessionLifetime:    480,
					StateExpiryMinutes: tt.expiry,
				},
			}

			err := cfg.validateSSOSettings()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSSOSettings() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
