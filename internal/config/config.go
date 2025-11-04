package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds all application configuration
type Config struct {
	Port                   string
	DBPath                 string
	UploadDir              string
	MaxFileSize            int64
	DefaultExpirationHours int
	CleanupIntervalMinutes int
	PublicURL              string // Optional: Override auto-detected URL for reverse proxy setups
}

// Load reads configuration from environment variables with sensible defaults
func Load() (*Config, error) {
	cfg := &Config{
		Port:                   getEnv("PORT", "8080"),
		DBPath:                 getEnv("DB_PATH", "./safeshare.db"),
		UploadDir:              getEnv("UPLOAD_DIR", "./uploads"),
		MaxFileSize:            getEnvInt64("MAX_FILE_SIZE", 104857600), // 100MB default
		DefaultExpirationHours: getEnvInt("DEFAULT_EXPIRATION_HOURS", 24),
		CleanupIntervalMinutes: getEnvInt("CLEANUP_INTERVAL_MINUTES", 60),
		PublicURL:              getEnv("PUBLIC_URL", ""), // Optional
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

	if c.CleanupIntervalMinutes <= 0 {
		return fmt.Errorf("CLEANUP_INTERVAL_MINUTES must be positive, got %d", c.CleanupIntervalMinutes)
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
