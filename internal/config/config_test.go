package config

import (
	"os"
	"strings"
	"sync"
	"testing"
)

// TestLoad_DefaultConfiguration tests loading config with no environment variables
func TestLoad_DefaultConfiguration(t *testing.T) {
	// Clear all relevant env vars
	clearEnvVars(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with defaults failed: %v", err)
	}

	// Verify immutable field defaults
	if cfg.Port != "8080" {
		t.Errorf("Port = %s, want 8080", cfg.Port)
	}
	if cfg.DBPath != "./safeshare.db" {
		t.Errorf("DBPath = %s, want ./safeshare.db", cfg.DBPath)
	}
	if cfg.UploadDir != "./uploads" {
		t.Errorf("UploadDir = %s, want ./uploads", cfg.UploadDir)
	}
	if cfg.CleanupIntervalMinutes != 60 {
		t.Errorf("CleanupIntervalMinutes = %d, want 60", cfg.CleanupIntervalMinutes)
	}
	if cfg.PublicURL != "" {
		t.Errorf("PublicURL = %s, want empty", cfg.PublicURL)
	}
	if cfg.DownloadURL != "" {
		t.Errorf("DownloadURL = %s, want empty", cfg.DownloadURL)
	}
	if cfg.EncryptionKey != "" {
		t.Errorf("EncryptionKey = %s, want empty", cfg.EncryptionKey)
	}
	if cfg.AdminUsername != "" {
		t.Errorf("AdminUsername = %s, want empty", cfg.AdminUsername)
	}
	if cfg.SessionExpiryHours != 24 {
		t.Errorf("SessionExpiryHours = %d, want 24", cfg.SessionExpiryHours)
	}
	if cfg.HTTPSEnabled != false {
		t.Errorf("HTTPSEnabled = %v, want false", cfg.HTTPSEnabled)
	}
	if cfg.RequireAuthForUpload != false {
		t.Errorf("RequireAuthForUpload = %v, want false", cfg.RequireAuthForUpload)
	}
	if cfg.ChunkedUploadEnabled != true {
		t.Errorf("ChunkedUploadEnabled = %v, want true", cfg.ChunkedUploadEnabled)
	}
	if cfg.ChunkedUploadThreshold != 104857600 {
		t.Errorf("ChunkedUploadThreshold = %d, want 104857600", cfg.ChunkedUploadThreshold)
	}
	if cfg.ChunkSize != 10485760 {
		t.Errorf("ChunkSize = %d, want 10485760", cfg.ChunkSize)
	}
	if cfg.PartialUploadExpiryHours != 24 {
		t.Errorf("PartialUploadExpiryHours = %d, want 24", cfg.PartialUploadExpiryHours)
	}
	if cfg.ReadTimeoutSeconds != 120 {
		t.Errorf("ReadTimeoutSeconds = %d, want 120", cfg.ReadTimeoutSeconds)
	}
	if cfg.WriteTimeoutSeconds != 120 {
		t.Errorf("WriteTimeoutSeconds = %d, want 120", cfg.WriteTimeoutSeconds)
	}

	// Verify mutable field defaults
	if cfg.GetMaxFileSize() != 104857600 {
		t.Errorf("MaxFileSize = %d, want 104857600", cfg.GetMaxFileSize())
	}
	if cfg.GetDefaultExpirationHours() != 24 {
		t.Errorf("DefaultExpirationHours = %d, want 24", cfg.GetDefaultExpirationHours())
	}
	if cfg.GetMaxExpirationHours() != 168 {
		t.Errorf("MaxExpirationHours = %d, want 168", cfg.GetMaxExpirationHours())
	}
	if cfg.GetRateLimitUpload() != 10 {
		t.Errorf("RateLimitUpload = %d, want 10", cfg.GetRateLimitUpload())
	}
	if cfg.GetRateLimitDownload() != 50 {
		t.Errorf("RateLimitDownload = %d, want 50", cfg.GetRateLimitDownload())
	}
	if cfg.GetQuotaLimitGB() != 0 {
		t.Errorf("QuotaLimitGB = %d, want 0", cfg.GetQuotaLimitGB())
	}
	if cfg.GetAdminPassword() != "" {
		t.Errorf("AdminPassword = %s, want empty", cfg.GetAdminPassword())
	}

	// Verify default blocked extensions
	blockedExts := cfg.GetBlockedExtensions()
	if len(blockedExts) == 0 {
		t.Error("BlockedExtensions should have defaults, got empty")
	}
	// Check some expected defaults
	expectedExts := []string{".exe", ".bat", ".cmd", ".sh", ".dll"}
	for _, expected := range expectedExts {
		found := false
		for _, ext := range blockedExts {
			if ext == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected default extension %s not found in blocked extensions", expected)
		}
	}
}

// TestLoad_CustomConfiguration tests loading config with custom environment variables
func TestLoad_CustomConfiguration(t *testing.T) {
	clearEnvVars(t)

	// Set custom values
	t.Setenv("PORT", "9090")
	t.Setenv("DB_PATH", "/custom/db.sqlite")
	t.Setenv("UPLOAD_DIR", "/custom/uploads")
	t.Setenv("MAX_FILE_SIZE", "524288000") // 500MB
	t.Setenv("DEFAULT_EXPIRATION_HOURS", "48")
	t.Setenv("MAX_EXPIRATION_HOURS", "336") // 14 days
	t.Setenv("CLEANUP_INTERVAL_MINUTES", "30")
	t.Setenv("PUBLIC_URL", "https://share.example.com")
	t.Setenv("DOWNLOAD_URL", "https://downloads.example.com")
	t.Setenv("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("BLOCKED_EXTENSIONS", "exe,bat,cmd")
	t.Setenv("RATE_LIMIT_UPLOAD", "20")
	t.Setenv("RATE_LIMIT_DOWNLOAD", "100")
	t.Setenv("QUOTA_LIMIT_GB", "50")
	t.Setenv("ADMIN_USERNAME", "testadmin")
	t.Setenv("ADMIN_PASSWORD", "testpassword123")
	t.Setenv("SESSION_EXPIRY_HOURS", "48")
	t.Setenv("HTTPS_ENABLED", "true")
	t.Setenv("REQUIRE_AUTH_FOR_UPLOAD", "yes")
	t.Setenv("CHUNKED_UPLOAD_ENABLED", "false")
	t.Setenv("CHUNKED_UPLOAD_THRESHOLD", "209715200") // 200MB
	t.Setenv("CHUNK_SIZE", "20971520")                // 20MB
	t.Setenv("PARTIAL_UPLOAD_EXPIRY_HOURS", "48")
	t.Setenv("READ_TIMEOUT", "300")
	t.Setenv("WRITE_TIMEOUT", "300")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with custom config failed: %v", err)
	}

	// Verify custom values
	if cfg.Port != "9090" {
		t.Errorf("Port = %s, want 9090", cfg.Port)
	}
	if cfg.DBPath != "/custom/db.sqlite" {
		t.Errorf("DBPath = %s, want /custom/db.sqlite", cfg.DBPath)
	}
	if cfg.UploadDir != "/custom/uploads" {
		t.Errorf("UploadDir = %s, want /custom/uploads", cfg.UploadDir)
	}
	if cfg.GetMaxFileSize() != 524288000 {
		t.Errorf("MaxFileSize = %d, want 524288000", cfg.GetMaxFileSize())
	}
	if cfg.GetDefaultExpirationHours() != 48 {
		t.Errorf("DefaultExpirationHours = %d, want 48", cfg.GetDefaultExpirationHours())
	}
	if cfg.GetMaxExpirationHours() != 336 {
		t.Errorf("MaxExpirationHours = %d, want 336", cfg.GetMaxExpirationHours())
	}
	if cfg.CleanupIntervalMinutes != 30 {
		t.Errorf("CleanupIntervalMinutes = %d, want 30", cfg.CleanupIntervalMinutes)
	}
	if cfg.PublicURL != "https://share.example.com" {
		t.Errorf("PublicURL = %s, want https://share.example.com", cfg.PublicURL)
	}
	if cfg.DownloadURL != "https://downloads.example.com" {
		t.Errorf("DownloadURL = %s, want https://downloads.example.com", cfg.DownloadURL)
	}
	if cfg.EncryptionKey != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Errorf("EncryptionKey mismatch")
	}
	if cfg.GetRateLimitUpload() != 20 {
		t.Errorf("RateLimitUpload = %d, want 20", cfg.GetRateLimitUpload())
	}
	if cfg.GetRateLimitDownload() != 100 {
		t.Errorf("RateLimitDownload = %d, want 100", cfg.GetRateLimitDownload())
	}
	if cfg.GetQuotaLimitGB() != 50 {
		t.Errorf("QuotaLimitGB = %d, want 50", cfg.GetQuotaLimitGB())
	}
	if cfg.AdminUsername != "testadmin" {
		t.Errorf("AdminUsername = %s, want testadmin", cfg.AdminUsername)
	}
	if cfg.GetAdminPassword() != "testpassword123" {
		t.Errorf("AdminPassword mismatch")
	}
	if cfg.SessionExpiryHours != 48 {
		t.Errorf("SessionExpiryHours = %d, want 48", cfg.SessionExpiryHours)
	}
	if cfg.HTTPSEnabled != true {
		t.Errorf("HTTPSEnabled = %v, want true", cfg.HTTPSEnabled)
	}
	if cfg.RequireAuthForUpload != true {
		t.Errorf("RequireAuthForUpload = %v, want true", cfg.RequireAuthForUpload)
	}
	if cfg.ChunkedUploadEnabled != false {
		t.Errorf("ChunkedUploadEnabled = %v, want false", cfg.ChunkedUploadEnabled)
	}
	if cfg.ChunkedUploadThreshold != 209715200 {
		t.Errorf("ChunkedUploadThreshold = %d, want 209715200", cfg.ChunkedUploadThreshold)
	}
	if cfg.ChunkSize != 20971520 {
		t.Errorf("ChunkSize = %d, want 20971520", cfg.ChunkSize)
	}
	if cfg.PartialUploadExpiryHours != 48 {
		t.Errorf("PartialUploadExpiryHours = %d, want 48", cfg.PartialUploadExpiryHours)
	}
	if cfg.ReadTimeoutSeconds != 300 {
		t.Errorf("ReadTimeoutSeconds = %d, want 300", cfg.ReadTimeoutSeconds)
	}
	if cfg.WriteTimeoutSeconds != 300 {
		t.Errorf("WriteTimeoutSeconds = %d, want 300", cfg.WriteTimeoutSeconds)
	}

	// Verify blocked extensions normalization
	blockedExts := cfg.GetBlockedExtensions()
	expected := []string{".exe", ".bat", ".cmd"}
	if len(blockedExts) != len(expected) {
		t.Errorf("BlockedExtensions length = %d, want %d", len(blockedExts), len(expected))
	}
	for i, exp := range expected {
		if i >= len(blockedExts) || blockedExts[i] != exp {
			t.Errorf("BlockedExtensions[%d] = %s, want %s", i, blockedExts[i], exp)
		}
	}
}

// TestLoad_InvalidEncryptionKey tests various invalid encryption key formats
func TestLoad_InvalidEncryptionKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{"too short", "0123456789abcdef"},
		{"too long", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00"},
		{"non-hex lowercase", "0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef"},
		{"non-hex uppercase", "0123456789ABCDEFG123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"},
		{"special characters", "0123456789abcdef!123456789abcdef0123456789abcdef0123456789abcdef"},
		{"spaces", "0123456789abcdef 123456789abcdef0123456789abcdef0123456789abcdef"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnvVars(t)
			t.Setenv("ENCRYPTION_KEY", tt.key)

			_, err := Load()
			if err == nil {
				t.Errorf("Load() with invalid encryption key %q succeeded, want error", tt.name)
			}
			if !strings.Contains(err.Error(), "ENCRYPTION_KEY") {
				t.Errorf("Error message = %v, want error mentioning ENCRYPTION_KEY", err)
			}
		})
	}
}

// TestLoad_ValidEncryptionKey tests that valid encryption keys are accepted
func TestLoad_ValidEncryptionKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{"lowercase hex", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{"uppercase hex", "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"},
		{"mixed case hex", "0123456789AbCdEf0123456789aBcDeF0123456789abcdef0123456789ABCDEF"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnvVars(t)
			t.Setenv("ENCRYPTION_KEY", tt.key)

			cfg, err := Load()
			if err != nil {
				t.Errorf("Load() with valid encryption key %q failed: %v", tt.name, err)
			}
			if cfg.EncryptionKey != tt.key {
				t.Errorf("EncryptionKey = %s, want %s", cfg.EncryptionKey, tt.key)
			}
		})
	}
}

// TestLoad_InvalidNumericValues tests invalid numeric configuration values
func TestLoad_InvalidNumericValues(t *testing.T) {
	tests := []struct {
		name   string
		envVar string
		value  string
		errMsg string
	}{
		{"negative max file size", "MAX_FILE_SIZE", "-100", "MAX_FILE_SIZE must be positive"},
		{"zero max file size", "MAX_FILE_SIZE", "0", "MAX_FILE_SIZE must be positive"},
		{"negative default expiration", "DEFAULT_EXPIRATION_HOURS", "-1", "DEFAULT_EXPIRATION_HOURS must be positive"},
		{"zero default expiration", "DEFAULT_EXPIRATION_HOURS", "0", "DEFAULT_EXPIRATION_HOURS must be positive"},
		{"negative max expiration", "MAX_EXPIRATION_HOURS", "-1", "MAX_EXPIRATION_HOURS must be positive"},
		{"zero max expiration", "MAX_EXPIRATION_HOURS", "0", "MAX_EXPIRATION_HOURS must be positive"},
		{"negative cleanup interval", "CLEANUP_INTERVAL_MINUTES", "-1", "CLEANUP_INTERVAL_MINUTES must be positive"},
		{"zero cleanup interval", "CLEANUP_INTERVAL_MINUTES", "0", "CLEANUP_INTERVAL_MINUTES must be positive"},
		{"negative upload rate limit", "RATE_LIMIT_UPLOAD", "-1", "RATE_LIMIT_UPLOAD must be positive"},
		{"zero upload rate limit", "RATE_LIMIT_UPLOAD", "0", "RATE_LIMIT_UPLOAD must be positive"},
		{"negative download rate limit", "RATE_LIMIT_DOWNLOAD", "-1", "RATE_LIMIT_DOWNLOAD must be positive"},
		{"zero download rate limit", "RATE_LIMIT_DOWNLOAD", "0", "RATE_LIMIT_DOWNLOAD must be positive"},
		{"negative quota", "QUOTA_LIMIT_GB", "-1", "QUOTA_LIMIT_GB must be 0"},
		{"negative session expiry", "SESSION_EXPIRY_HOURS", "-1", "SESSION_EXPIRY_HOURS must be positive"},
		{"zero session expiry", "SESSION_EXPIRY_HOURS", "0", "SESSION_EXPIRY_HOURS must be positive"},
		{"negative chunk size", "CHUNK_SIZE", "500000", "CHUNK_SIZE must be between 1MB"},
		{"chunk size too large", "CHUNK_SIZE", "100000000", "CHUNK_SIZE must be between 1MB"},
		{"negative chunked threshold", "CHUNKED_UPLOAD_THRESHOLD", "-1", "CHUNKED_UPLOAD_THRESHOLD must be non-negative"},
		{"negative partial expiry", "PARTIAL_UPLOAD_EXPIRY_HOURS", "-1", "PARTIAL_UPLOAD_EXPIRY_HOURS must be positive"},
		{"zero partial expiry", "PARTIAL_UPLOAD_EXPIRY_HOURS", "0", "PARTIAL_UPLOAD_EXPIRY_HOURS must be positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnvVars(t)
			t.Setenv(tt.envVar, tt.value)

			_, err := Load()
			if err == nil {
				t.Errorf("Load() with %s=%s succeeded, want error", tt.envVar, tt.value)
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Error message = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

// TestLoad_ExpirationValidation tests default vs max expiration validation
func TestLoad_ExpirationValidation(t *testing.T) {
	clearEnvVars(t)
	t.Setenv("DEFAULT_EXPIRATION_HOURS", "200")
	t.Setenv("MAX_EXPIRATION_HOURS", "100")

	_, err := Load()
	if err == nil {
		t.Error("Load() with default > max expiration succeeded, want error")
	}
	if !strings.Contains(err.Error(), "DEFAULT_EXPIRATION_HOURS") || !strings.Contains(err.Error(), "MAX_EXPIRATION_HOURS") {
		t.Errorf("Error message = %v, want error mentioning expiration mismatch", err)
	}
}

// TestLoad_AdminCredentialsValidation tests admin username and password validation
func TestLoad_AdminCredentialsValidation(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
		errMsg   string
	}{
		{"both empty", "", "", false, ""},
		{"both set valid", "admin", "password123", false, ""},
		{"username only", "admin", "", true, "both ADMIN_USERNAME and ADMIN_PASSWORD must be set"},
		{"password only", "", "password123", true, "both ADMIN_USERNAME and ADMIN_PASSWORD must be set"},
		{"username too short", "ab", "password123", true, "ADMIN_USERNAME must be at least 3 characters"},
		{"password too short", "admin", "pass", true, "ADMIN_PASSWORD must be at least 8 characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnvVars(t)
			if tt.username != "" {
				t.Setenv("ADMIN_USERNAME", tt.username)
			}
			if tt.password != "" {
				t.Setenv("ADMIN_PASSWORD", tt.password)
			}

			_, err := Load()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Load() succeeded, want error")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Error message = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Load() failed: %v, want success", err)
				}
			}
		})
	}
}

// TestValidate_EmptyRequiredFields tests validation of required fields
// Note: These fields cannot be empty through Load() because getEnv provides defaults,
// but we can test the validation logic directly
func TestValidate_EmptyRequiredFields(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		errMsg string
	}{
		{
			name: "empty port",
			config: &Config{
				Port:                     "",
				DBPath:                   "./test.db",
				UploadDir:                "./uploads",
				maxFileSize:              100,
				defaultExpirationHours:   24,
				maxExpirationHours:       168,
				CleanupIntervalMinutes:   60,
				rateLimitUpload:          10,
				rateLimitDownload:        50,
				quotaLimitGB:             0,
				SessionExpiryHours:       24,
				ChunkSize:                10485760,
				ChunkedUploadThreshold:   0,
				PartialUploadExpiryHours: 24,
			},
			errMsg: "PORT cannot be empty",
		},
		{
			name: "empty db path",
			config: &Config{
				Port:                     "8080",
				DBPath:                   "",
				UploadDir:                "./uploads",
				maxFileSize:              100,
				defaultExpirationHours:   24,
				maxExpirationHours:       168,
				CleanupIntervalMinutes:   60,
				rateLimitUpload:          10,
				rateLimitDownload:        50,
				quotaLimitGB:             0,
				SessionExpiryHours:       24,
				ChunkSize:                10485760,
				ChunkedUploadThreshold:   0,
				PartialUploadExpiryHours: 24,
			},
			errMsg: "DB_PATH cannot be empty",
		},
		{
			name: "empty upload dir",
			config: &Config{
				Port:                     "8080",
				DBPath:                   "./test.db",
				UploadDir:                "",
				maxFileSize:              100,
				defaultExpirationHours:   24,
				maxExpirationHours:       168,
				CleanupIntervalMinutes:   60,
				rateLimitUpload:          10,
				rateLimitDownload:        50,
				quotaLimitGB:             0,
				SessionExpiryHours:       24,
				ChunkSize:                10485760,
				ChunkedUploadThreshold:   0,
				PartialUploadExpiryHours: 24,
			},
			errMsg: "UPLOAD_DIR cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if err == nil {
				t.Errorf("validate() with %s succeeded, want error", tt.name)
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Error message = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

// TestGetEnvBool tests boolean environment variable parsing
func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		defaultValue bool
		want         bool
	}{
		{"true lowercase", "true", false, true},
		{"true uppercase", "TRUE", false, true},
		{"1", "1", false, true},
		{"yes", "yes", false, true},
		{"yes uppercase", "YES", false, true},
		{"on", "on", false, true},
		{"on uppercase", "ON", false, true},
		{"false lowercase", "false", true, false},
		{"false uppercase", "FALSE", true, false},
		{"0", "0", true, false},
		{"no", "no", true, false},
		{"no uppercase", "NO", true, false},
		{"off", "off", true, false},
		{"off uppercase", "OFF", true, false},
		{"invalid value uses default true", "invalid", true, true},
		{"invalid value uses default false", "invalid", false, false},
		{"empty uses default true", "", true, true},
		{"empty uses default false", "", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != "" {
				os.Setenv("TEST_BOOL", tt.value)
				defer os.Unsetenv("TEST_BOOL")
			}

			got := getEnvBool("TEST_BOOL", tt.defaultValue)
			if got != tt.want {
				t.Errorf("getEnvBool(%q, %v) = %v, want %v", tt.value, tt.defaultValue, got, tt.want)
			}
		})
	}
}

// TestGetEnvInt tests integer environment variable parsing
func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		defaultValue int
		want         int
	}{
		{"valid positive", "42", 10, 42},
		{"valid negative", "-42", 10, -42},
		{"valid zero", "0", 10, 0},
		{"invalid uses default", "not-a-number", 10, 10},
		{"empty uses default", "", 10, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != "" {
				os.Setenv("TEST_INT", tt.value)
				defer os.Unsetenv("TEST_INT")
			}

			got := getEnvInt("TEST_INT", tt.defaultValue)
			if got != tt.want {
				t.Errorf("getEnvInt(%q, %d) = %d, want %d", tt.value, tt.defaultValue, got, tt.want)
			}
		})
	}
}

// TestGetEnvInt64 tests int64 environment variable parsing
func TestGetEnvInt64(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		defaultValue int64
		want         int64
	}{
		{"valid positive", "1234567890", 100, 1234567890},
		{"valid negative", "-1234567890", 100, -1234567890},
		{"valid zero", "0", 100, 0},
		{"invalid uses default", "not-a-number", 100, 100},
		{"empty uses default", "", 100, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != "" {
				os.Setenv("TEST_INT64", tt.value)
				defer os.Unsetenv("TEST_INT64")
			}

			got := getEnvInt64("TEST_INT64", tt.defaultValue)
			if got != tt.want {
				t.Errorf("getEnvInt64(%q, %d) = %d, want %d", tt.value, tt.defaultValue, got, tt.want)
			}
		})
	}
}

// TestGetEnvList tests comma-separated list parsing and normalization
func TestGetEnvList(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		defaultValue string
		want         []string
	}{
		{"simple list", "exe,bat,cmd", "", []string{".exe", ".bat", ".cmd"}},
		{"with dots", ".exe,.bat,.cmd", "", []string{".exe", ".bat", ".cmd"}},
		{"mixed case", "EXE,Bat,cmd", "", []string{".exe", ".bat", ".cmd"}},
		{"with spaces", "exe, bat , cmd", "", []string{".exe", ".bat", ".cmd"}},
		{"with extra commas", "exe,,bat,,,cmd", "", []string{".exe", ".bat", ".cmd"}},
		{"empty uses default", "", "dll,so", []string{".dll", ".so"}},
		{"empty string", "", "", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != "" {
				os.Setenv("TEST_LIST", tt.value)
				defer os.Unsetenv("TEST_LIST")
			}

			got := getEnvList("TEST_LIST", tt.defaultValue)
			if len(got) != len(tt.want) {
				t.Errorf("getEnvList(%q) length = %d, want %d", tt.value, len(got), len(tt.want))
			}
			for i, want := range tt.want {
				if i >= len(got) || got[i] != want {
					t.Errorf("getEnvList(%q)[%d] = %s, want %s", tt.value, i, got[i], want)
				}
			}
		})
	}
}

// TestSetMaxFileSize tests SetMaxFileSize with validation
func TestSetMaxFileSize(t *testing.T) {
	clearEnvVars(t)
	cfg, _ := Load()

	tests := []struct {
		name    string
		size    int64
		wantErr bool
	}{
		{"valid positive", 1000000, false},
		{"valid large", 999999999999, false},
		{"zero", 0, true},
		{"negative", -100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfg.SetMaxFileSize(tt.size)
			if tt.wantErr {
				if err == nil {
					t.Errorf("SetMaxFileSize(%d) succeeded, want error", tt.size)
				}
			} else {
				if err != nil {
					t.Errorf("SetMaxFileSize(%d) failed: %v", tt.size, err)
				}
				if cfg.GetMaxFileSize() != tt.size {
					t.Errorf("GetMaxFileSize() = %d, want %d", cfg.GetMaxFileSize(), tt.size)
				}
			}
		})
	}
}

// TestSetDefaultExpirationHours tests SetDefaultExpirationHours with validation
func TestSetDefaultExpirationHours(t *testing.T) {
	clearEnvVars(t)
	cfg, _ := Load()

	tests := []struct {
		name    string
		hours   int
		wantErr bool
		errMsg  string
	}{
		{"valid below max", 100, false, ""},
		{"valid equal max", 168, false, ""},
		{"zero", 0, true, "must be positive"},
		{"negative", -1, true, "must be positive"},
		{"exceeds max", 200, true, "cannot exceed max expiration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfg.SetDefaultExpirationHours(tt.hours)
			if tt.wantErr {
				if err == nil {
					t.Errorf("SetDefaultExpirationHours(%d) succeeded, want error", tt.hours)
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Error message = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("SetDefaultExpirationHours(%d) failed: %v", tt.hours, err)
				}
				if cfg.GetDefaultExpirationHours() != tt.hours {
					t.Errorf("GetDefaultExpirationHours() = %d, want %d", cfg.GetDefaultExpirationHours(), tt.hours)
				}
			}
		})
	}
}

// TestSetMaxExpirationHours tests SetMaxExpirationHours with validation
func TestSetMaxExpirationHours(t *testing.T) {
	clearEnvVars(t)
	cfg, _ := Load()

	tests := []struct {
		name    string
		hours   int
		wantErr bool
		errMsg  string
	}{
		{"valid above default", 200, false, ""},
		{"valid equal default", 24, false, ""},
		{"zero", 0, true, "must be positive"},
		{"negative", -1, true, "must be positive"},
		{"below default", 10, true, "cannot be less than default expiration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfg.SetMaxExpirationHours(tt.hours)
			if tt.wantErr {
				if err == nil {
					t.Errorf("SetMaxExpirationHours(%d) succeeded, want error", tt.hours)
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Error message = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("SetMaxExpirationHours(%d) failed: %v", tt.hours, err)
				}
				if cfg.GetMaxExpirationHours() != tt.hours {
					t.Errorf("GetMaxExpirationHours() = %d, want %d", cfg.GetMaxExpirationHours(), tt.hours)
				}
			}
		})
	}
}

// TestSetBlockedExtensions tests SetBlockedExtensions with normalization
func TestSetBlockedExtensions(t *testing.T) {
	clearEnvVars(t)
	cfg, _ := Load()

	tests := []struct {
		name    string
		input   []string
		want    []string
		wantErr bool
	}{
		{"with dots", []string{".exe", ".bat"}, []string{".exe", ".bat"}, false},
		{"without dots", []string{"exe", "bat"}, []string{".exe", ".bat"}, false},
		{"mixed", []string{".exe", "bat", ".CMD"}, []string{".exe", ".bat", ".cmd"}, false},
		{"with spaces", []string{" exe ", " .bat "}, []string{".exe", ".bat"}, false},
		{"with empty strings", []string{"exe", "", "bat", "  "}, []string{".exe", ".bat"}, false},
		{"nil input", nil, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfg.SetBlockedExtensions(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("SetBlockedExtensions(%v) succeeded, want error", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("SetBlockedExtensions(%v) failed: %v", tt.input, err)
				}
				got := cfg.GetBlockedExtensions()
				if len(got) != len(tt.want) {
					t.Errorf("GetBlockedExtensions() length = %d, want %d", len(got), len(tt.want))
				}
				for i, want := range tt.want {
					if i >= len(got) || got[i] != want {
						t.Errorf("GetBlockedExtensions()[%d] = %s, want %s", i, got[i], want)
					}
				}
			}
		})
	}
}

// TestSetRateLimits tests SetRateLimitUpload and SetRateLimitDownload
func TestSetRateLimits(t *testing.T) {
	clearEnvVars(t)
	cfg, _ := Load()

	tests := []struct {
		name    string
		limit   int
		wantErr bool
	}{
		{"valid positive", 100, false},
		{"valid one", 1, false},
		{"zero", 0, true},
		{"negative", -1, true},
	}

	for _, tt := range tests {
		t.Run("upload_"+tt.name, func(t *testing.T) {
			err := cfg.SetRateLimitUpload(tt.limit)
			if tt.wantErr {
				if err == nil {
					t.Errorf("SetRateLimitUpload(%d) succeeded, want error", tt.limit)
				}
			} else {
				if err != nil {
					t.Errorf("SetRateLimitUpload(%d) failed: %v", tt.limit, err)
				}
				if cfg.GetRateLimitUpload() != tt.limit {
					t.Errorf("GetRateLimitUpload() = %d, want %d", cfg.GetRateLimitUpload(), tt.limit)
				}
			}
		})

		t.Run("download_"+tt.name, func(t *testing.T) {
			err := cfg.SetRateLimitDownload(tt.limit)
			if tt.wantErr {
				if err == nil {
					t.Errorf("SetRateLimitDownload(%d) succeeded, want error", tt.limit)
				}
			} else {
				if err != nil {
					t.Errorf("SetRateLimitDownload(%d) failed: %v", tt.limit, err)
				}
				if cfg.GetRateLimitDownload() != tt.limit {
					t.Errorf("GetRateLimitDownload() = %d, want %d", cfg.GetRateLimitDownload(), tt.limit)
				}
			}
		})
	}
}

// TestSetQuotaLimitGB tests SetQuotaLimitGB validation
func TestSetQuotaLimitGB(t *testing.T) {
	clearEnvVars(t)
	cfg, _ := Load()

	tests := []struct {
		name    string
		quota   int64
		wantErr bool
	}{
		{"zero (unlimited)", 0, false},
		{"positive", 100, false},
		{"large", 999999, false},
		{"negative", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfg.SetQuotaLimitGB(tt.quota)
			if tt.wantErr {
				if err == nil {
					t.Errorf("SetQuotaLimitGB(%d) succeeded, want error", tt.quota)
				}
			} else {
				if err != nil {
					t.Errorf("SetQuotaLimitGB(%d) failed: %v", tt.quota, err)
				}
				if cfg.GetQuotaLimitGB() != tt.quota {
					t.Errorf("GetQuotaLimitGB() = %d, want %d", cfg.GetQuotaLimitGB(), tt.quota)
				}
			}
		})
	}
}

// TestSetAdminPassword tests SetAdminPassword validation
func TestSetAdminPassword(t *testing.T) {
	clearEnvVars(t)
	cfg, _ := Load()

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid 8 chars", "password", false},
		{"valid long", "verylongpassword123", false},
		{"too short", "pass", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfg.SetAdminPassword(tt.password)
			if tt.wantErr {
				if err == nil {
					t.Errorf("SetAdminPassword(%q) succeeded, want error", tt.password)
				}
			} else {
				if err != nil {
					t.Errorf("SetAdminPassword(%q) failed: %v", tt.password, err)
				}
				if cfg.GetAdminPassword() != tt.password {
					t.Errorf("GetAdminPassword() = %q, want %q", cfg.GetAdminPassword(), tt.password)
				}
			}
		})
	}
}

// TestGetBlockedExtensions_ReturnsCopy tests that GetBlockedExtensions returns a copy
func TestGetBlockedExtensions_ReturnsCopy(t *testing.T) {
	clearEnvVars(t)
	cfg, _ := Load()

	// Set initial extensions
	cfg.SetBlockedExtensions([]string{"exe", "bat"})

	// Get extensions and modify the returned slice
	exts := cfg.GetBlockedExtensions()
	exts[0] = ".modified"

	// Verify original is unchanged
	exts2 := cfg.GetBlockedExtensions()
	if exts2[0] == ".modified" {
		t.Error("GetBlockedExtensions() does not return a copy, external modification affected internal state")
	}
}

// TestThreadSafety tests concurrent access to getters and setters
func TestThreadSafety(t *testing.T) {
	clearEnvVars(t)
	cfg, _ := Load()

	var wg sync.WaitGroup
	iterations := 100

	// Test concurrent reads and writes
	wg.Add(4)

	// Concurrent reads
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = cfg.GetMaxFileSize()
			_ = cfg.GetBlockedExtensions()
			_ = cfg.GetRateLimitUpload()
		}
	}()

	// Concurrent writes to different fields
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			cfg.SetMaxFileSize(int64(1000000 + i))
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			cfg.SetRateLimitUpload(10 + (i % 50))
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			cfg.SetBlockedExtensions([]string{"exe", "bat"})
		}
	}()

	wg.Wait()
	// If we get here without data races, test passes
}

// clearEnvVars clears all SafeShare-related environment variables
func clearEnvVars(t *testing.T) {
	t.Helper()
	envVars := []string{
		"PORT", "DB_PATH", "UPLOAD_DIR", "MAX_FILE_SIZE",
		"DEFAULT_EXPIRATION_HOURS", "MAX_EXPIRATION_HOURS",
		"CLEANUP_INTERVAL_MINUTES", "PUBLIC_URL", "DOWNLOAD_URL",
		"ENCRYPTION_KEY", "BLOCKED_EXTENSIONS",
		"RATE_LIMIT_UPLOAD", "RATE_LIMIT_DOWNLOAD",
		"QUOTA_LIMIT_GB", "ADMIN_USERNAME", "ADMIN_PASSWORD",
		"SESSION_EXPIRY_HOURS", "HTTPS_ENABLED", "REQUIRE_AUTH_FOR_UPLOAD",
		"CHUNKED_UPLOAD_ENABLED", "CHUNKED_UPLOAD_THRESHOLD",
		"CHUNK_SIZE", "PARTIAL_UPLOAD_EXPIRY_HOURS",
		"READ_TIMEOUT", "WRITE_TIMEOUT",
	}
	for _, v := range envVars {
		os.Unsetenv(v)
	}
}
