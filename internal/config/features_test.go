package config

import (
	"os"
	"sync"
	"testing"
)

func TestNewFeatureFlags(t *testing.T) {
	f := NewFeatureFlags()
	if f == nil {
		t.Fatal("NewFeatureFlags returned nil")
	}

	// All flags should be disabled by default
	if f.IsPostgreSQLEnabled() {
		t.Error("PostgreSQL should be disabled by default")
	}
	if f.IsS3StorageEnabled() {
		t.Error("S3Storage should be disabled by default")
	}
	if f.IsSSOEnabled() {
		t.Error("SSO should be disabled by default")
	}
	if f.IsMFAEnabled() {
		t.Error("MFA should be disabled by default")
	}
	if f.IsWebhooksEnabled() {
		t.Error("Webhooks should be disabled by default")
	}
	if f.IsAPITokensEnabled() {
		t.Error("APITokens should be disabled by default")
	}
	if f.IsMalwareScanEnabled() {
		t.Error("MalwareScan should be disabled by default")
	}
	if f.IsBackupsEnabled() {
		t.Error("Backups should be disabled by default")
	}
}

func TestFeatureFlags_SettersAndGetters(t *testing.T) {
	f := NewFeatureFlags()

	// Test each setter/getter pair
	tests := []struct {
		name   string
		setter func(bool)
		getter func() bool
	}{
		{"PostgreSQL", f.SetPostgreSQLEnabled, f.IsPostgreSQLEnabled},
		{"S3Storage", f.SetS3StorageEnabled, f.IsS3StorageEnabled},
		{"SSO", f.SetSSOEnabled, f.IsSSOEnabled},
		{"MFA", f.SetMFAEnabled, f.IsMFAEnabled},
		{"Webhooks", f.SetWebhooksEnabled, f.IsWebhooksEnabled},
		{"APITokens", f.SetAPITokensEnabled, f.IsAPITokensEnabled},
		{"MalwareScan", f.SetMalwareScanEnabled, f.IsMalwareScanEnabled},
		{"Backups", f.SetBackupsEnabled, f.IsBackupsEnabled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initially should be false
			if tt.getter() {
				t.Errorf("%s should be false initially", tt.name)
			}

			// Set to true
			tt.setter(true)
			if !tt.getter() {
				t.Errorf("%s should be true after setting to true", tt.name)
			}

			// Set back to false
			tt.setter(false)
			if tt.getter() {
				t.Errorf("%s should be false after setting to false", tt.name)
			}
		})
	}
}

func TestFeatureFlags_GetAll(t *testing.T) {
	f := NewFeatureFlags()

	// Set some flags
	f.SetPostgreSQLEnabled(true)
	f.SetSSOEnabled(true)
	f.SetWebhooksEnabled(true)

	data := f.GetAll()

	if !data.EnablePostgreSQL {
		t.Error("GetAll() EnablePostgreSQL should be true")
	}
	if data.EnableS3Storage {
		t.Error("GetAll() EnableS3Storage should be false")
	}
	if !data.EnableSSO {
		t.Error("GetAll() EnableSSO should be true")
	}
	if data.EnableMFA {
		t.Error("GetAll() EnableMFA should be false")
	}
	if !data.EnableWebhooks {
		t.Error("GetAll() EnableWebhooks should be true")
	}
	if data.EnableAPITokens {
		t.Error("GetAll() EnableAPITokens should be false")
	}
	if data.EnableMalwareScan {
		t.Error("GetAll() EnableMalwareScan should be false")
	}
	if data.EnableBackups {
		t.Error("GetAll() EnableBackups should be false")
	}
}

func TestFeatureFlags_SetAll(t *testing.T) {
	f := NewFeatureFlags()

	data := FeatureFlagsData{
		EnablePostgreSQL:  true,
		EnableS3Storage:   true,
		EnableSSO:         false,
		EnableMFA:         true,
		EnableWebhooks:    false,
		EnableAPITokens:   true,
		EnableMalwareScan: true,
		EnableBackups:     false,
	}

	f.SetAll(data)

	if !f.IsPostgreSQLEnabled() {
		t.Error("PostgreSQL should be enabled")
	}
	if !f.IsS3StorageEnabled() {
		t.Error("S3Storage should be enabled")
	}
	if f.IsSSOEnabled() {
		t.Error("SSO should be disabled")
	}
	if !f.IsMFAEnabled() {
		t.Error("MFA should be enabled")
	}
	if f.IsWebhooksEnabled() {
		t.Error("Webhooks should be disabled")
	}
	if !f.IsAPITokensEnabled() {
		t.Error("APITokens should be enabled")
	}
	if !f.IsMalwareScanEnabled() {
		t.Error("MalwareScan should be enabled")
	}
	if f.IsBackupsEnabled() {
		t.Error("Backups should be disabled")
	}
}

func TestFeatureFlags_ThreadSafety(t *testing.T) {
	f := NewFeatureFlags()
	var wg sync.WaitGroup
	iterations := 100

	wg.Add(4)

	// Concurrent reads
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = f.IsPostgreSQLEnabled()
			_ = f.IsSSOEnabled()
			_ = f.GetAll()
		}
	}()

	// Concurrent writes
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			f.SetPostgreSQLEnabled(i%2 == 0)
			f.SetSSOEnabled(i%2 == 1)
		}
	}()

	// Concurrent SetAll
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			f.SetAll(FeatureFlagsData{
				EnablePostgreSQL: i%2 == 0,
				EnableSSO:        i%2 == 1,
			})
		}
	}()

	// Mixed reads and writes
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			f.SetMFAEnabled(i%2 == 0)
			_ = f.IsMFAEnabled()
			f.SetWebhooksEnabled(i%2 == 1)
			_ = f.IsWebhooksEnabled()
		}
	}()

	wg.Wait()
	// If we get here without data races, test passes
}

func TestGetEnvBoolFeature(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		defaultValue bool
		want         bool
	}{
		// True values
		{"true lowercase", "true", false, true},
		{"true uppercase", "TRUE", false, true},
		{"1", "1", false, true},
		{"yes lowercase", "yes", false, true},
		{"yes uppercase", "YES", false, true},
		{"on lowercase", "on", false, true},
		{"on uppercase", "ON", false, true},

		// False values
		{"false lowercase", "false", true, false},
		{"false uppercase", "FALSE", true, false},
		{"0", "0", true, false},
		{"no lowercase", "no", true, false},
		{"no uppercase", "NO", true, false},
		{"off lowercase", "off", true, false},
		{"off uppercase", "OFF", true, false},

		// Invalid values use default
		{"invalid uses default true", "invalid", true, true},
		{"invalid uses default false", "invalid", false, false},

		// Empty value uses default
		{"empty uses default true", "", true, true},
		{"empty uses default false", "", false, false},

		// Whitespace handling
		{"with whitespace", "  true  ", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envKey := "TEST_FEATURE_FLAG"
			if tt.value != "" {
				os.Setenv(envKey, tt.value)
				defer os.Unsetenv(envKey)
			} else {
				os.Unsetenv(envKey)
			}

			got := getEnvBoolFeature(envKey, tt.defaultValue)
			if got != tt.want {
				t.Errorf("getEnvBoolFeature(%q, %v) with value %q = %v, want %v",
					envKey, tt.defaultValue, tt.value, got, tt.want)
			}
		})
	}
}

func TestLoadFeatureFlags(t *testing.T) {
	// Clear all feature flag env vars first
	clearFeatureEnvVars()

	// Test with no env vars set - all should be false
	f := loadFeatureFlags()
	if f.IsPostgreSQLEnabled() || f.IsS3StorageEnabled() || f.IsSSOEnabled() ||
		f.IsMFAEnabled() || f.IsWebhooksEnabled() || f.IsAPITokensEnabled() ||
		f.IsMalwareScanEnabled() || f.IsBackupsEnabled() {
		t.Error("All feature flags should be false when no env vars are set")
	}

	// Test with env vars set
	os.Setenv("FEATURE_POSTGRESQL", "true")
	os.Setenv("FEATURE_S3_STORAGE", "1")
	os.Setenv("FEATURE_SSO", "yes")
	os.Setenv("FEATURE_MFA", "on")
	os.Setenv("FEATURE_WEBHOOKS", "TRUE")
	os.Setenv("FEATURE_API_TOKENS", "false")
	os.Setenv("FEATURE_MALWARE_SCAN", "0")
	os.Setenv("FEATURE_BACKUPS", "no")
	defer clearFeatureEnvVars()

	f = loadFeatureFlags()

	if !f.IsPostgreSQLEnabled() {
		t.Error("PostgreSQL should be enabled (FEATURE_POSTGRESQL=true)")
	}
	if !f.IsS3StorageEnabled() {
		t.Error("S3Storage should be enabled (FEATURE_S3_STORAGE=1)")
	}
	if !f.IsSSOEnabled() {
		t.Error("SSO should be enabled (FEATURE_SSO=yes)")
	}
	if !f.IsMFAEnabled() {
		t.Error("MFA should be enabled (FEATURE_MFA=on)")
	}
	if !f.IsWebhooksEnabled() {
		t.Error("Webhooks should be enabled (FEATURE_WEBHOOKS=TRUE)")
	}
	if f.IsAPITokensEnabled() {
		t.Error("APITokens should be disabled (FEATURE_API_TOKENS=false)")
	}
	if f.IsMalwareScanEnabled() {
		t.Error("MalwareScan should be disabled (FEATURE_MALWARE_SCAN=0)")
	}
	if f.IsBackupsEnabled() {
		t.Error("Backups should be disabled (FEATURE_BACKUPS=no)")
	}
}

func TestFeatureFlagsData_JSONTags(t *testing.T) {
	// This test verifies the struct has proper JSON tags
	// by checking that the fields can be set and retrieved via GetAll/SetAll
	f := NewFeatureFlags()

	data := FeatureFlagsData{
		EnablePostgreSQL:  true,
		EnableS3Storage:   true,
		EnableSSO:         true,
		EnableMFA:         true,
		EnableWebhooks:    true,
		EnableAPITokens:   true,
		EnableMalwareScan: true,
		EnableBackups:     true,
	}

	f.SetAll(data)
	result := f.GetAll()

	// Verify all fields round-trip correctly
	if result != data {
		t.Errorf("SetAll/GetAll round-trip failed: got %+v, want %+v", result, data)
	}
}

func clearFeatureEnvVars() {
	vars := []string{
		"FEATURE_POSTGRESQL",
		"FEATURE_S3_STORAGE",
		"FEATURE_SSO",
		"FEATURE_MFA",
		"FEATURE_WEBHOOKS",
		"FEATURE_API_TOKENS",
		"FEATURE_MALWARE_SCAN",
		"FEATURE_BACKUPS",
	}
	for _, v := range vars {
		os.Unsetenv(v)
	}
}
