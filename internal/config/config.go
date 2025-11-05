package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all application configuration
type Config struct {
	Port                   string
	DBPath                 string
	UploadDir              string
	MaxFileSize            int64
	DefaultExpirationHours int
	MaxExpirationHours     int      // Maximum allowed expiration time
	CleanupIntervalMinutes int
	PublicURL              string   // Optional: Override auto-detected URL for reverse proxy setups
	BlockedExtensions      []string // File extensions to block (e.g., .exe, .bat)
	EncryptionKey          string   // Optional: AES-256 encryption key (64 hex chars)
	RateLimitUpload        int      // Upload requests per hour per IP
	RateLimitDownload      int      // Download requests per hour per IP
	QuotaLimitGB           int64    // Maximum total storage in GB (0 = unlimited)
}

// Load reads configuration from environment variables with sensible defaults
func Load() (*Config, error) {
	// Default blocked extensions for security
	defaultBlocked := ".exe,.bat,.cmd,.sh,.ps1,.dll,.so,.msi,.scr,.vbs,.jar,.com,.app,.deb,.rpm"

	cfg := &Config{
		Port:                   getEnv("PORT", "8080"),
		DBPath:                 getEnv("DB_PATH", "./safeshare.db"),
		UploadDir:              getEnv("UPLOAD_DIR", "./uploads"),
		MaxFileSize:            getEnvInt64("MAX_FILE_SIZE", 104857600), // 100MB default
		DefaultExpirationHours: getEnvInt("DEFAULT_EXPIRATION_HOURS", 24),
		MaxExpirationHours:     getEnvInt("MAX_EXPIRATION_HOURS", 168), // 7 days default
		CleanupIntervalMinutes: getEnvInt("CLEANUP_INTERVAL_MINUTES", 60),
		PublicURL:              getEnv("PUBLIC_URL", ""),              // Optional
		BlockedExtensions:      getEnvList("BLOCKED_EXTENSIONS", defaultBlocked),
		EncryptionKey:          getEnv("ENCRYPTION_KEY", ""), // Optional
		RateLimitUpload:        getEnvInt("RATE_LIMIT_UPLOAD", 10),   // 10 uploads per hour per IP
		RateLimitDownload:      getEnvInt("RATE_LIMIT_DOWNLOAD", 100), // 100 downloads per hour per IP
		QuotaLimitGB:           getEnvInt64("QUOTA_LIMIT_GB", 0), // 0 = unlimited (default)
	}

	// Validate configuration
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

// validate ensures configuration values are sensible
func (c *Config) validate() error {
	if c.Port == "" {
		return fmt.Errorf("PORT cannot be empty")
	}

	if c.DBPath == "" {
		return fmt.Errorf("DB_PATH cannot be empty")
	}

	if c.UploadDir == "" {
		return fmt.Errorf("UPLOAD_DIR cannot be empty")
	}

	if c.MaxFileSize <= 0 {
		return fmt.Errorf("MAX_FILE_SIZE must be positive, got %d", c.MaxFileSize)
	}

	if c.DefaultExpirationHours <= 0 {
		return fmt.Errorf("DEFAULT_EXPIRATION_HOURS must be positive, got %d", c.DefaultExpirationHours)
	}

	if c.MaxExpirationHours <= 0 {
		return fmt.Errorf("MAX_EXPIRATION_HOURS must be positive, got %d", c.MaxExpirationHours)
	}

	if c.DefaultExpirationHours > c.MaxExpirationHours {
		return fmt.Errorf("DEFAULT_EXPIRATION_HOURS (%d) cannot exceed MAX_EXPIRATION_HOURS (%d)", c.DefaultExpirationHours, c.MaxExpirationHours)
	}

	if c.CleanupIntervalMinutes <= 0 {
		return fmt.Errorf("CLEANUP_INTERVAL_MINUTES must be positive, got %d", c.CleanupIntervalMinutes)
	}

	if c.RateLimitUpload <= 0 {
		return fmt.Errorf("RATE_LIMIT_UPLOAD must be positive, got %d", c.RateLimitUpload)
	}

	if c.RateLimitDownload <= 0 {
		return fmt.Errorf("RATE_LIMIT_DOWNLOAD must be positive, got %d", c.RateLimitDownload)
	}

	if c.QuotaLimitGB < 0 {
		return fmt.Errorf("QUOTA_LIMIT_GB must be 0 (unlimited) or positive, got %d", c.QuotaLimitGB)
	}

	// Validate encryption key if provided (must be 64 hex characters = 32 bytes for AES-256)
	if c.EncryptionKey != "" {
		if len(c.EncryptionKey) != 64 {
			return fmt.Errorf("ENCRYPTION_KEY must be exactly 64 hexadecimal characters (32 bytes), got %d", len(c.EncryptionKey))
		}
		// Verify it's valid hex
		for _, ch := range c.EncryptionKey {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
				return fmt.Errorf("ENCRYPTION_KEY must contain only hexadecimal characters (0-9, a-f, A-F)")
			}
		}
	}

	return nil
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt retrieves an integer environment variable or returns a default value
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// getEnvInt64 retrieves an int64 environment variable or returns a default value
func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// getEnvList retrieves a comma-separated list from environment variable
func getEnvList(key, defaultValue string) []string {
	value := getEnv(key, defaultValue)
	if value == "" {
		return []string{}
	}

	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			// Ensure extensions start with a dot
			if !strings.HasPrefix(trimmed, ".") {
				trimmed = "." + trimmed
			}
			result = append(result, strings.ToLower(trimmed))
		}
	}

	return result
}
