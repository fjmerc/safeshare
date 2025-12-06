package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Config holds all application configuration with thread-safe access
type Config struct {
	mu sync.RWMutex // Protects mutable fields

	// Immutable fields (set at startup only)
	Port                     string
	DBPath                   string
	UploadDir                string
	BackupDir                string // Optional backup directory (defaults to DataDir/backups)
	DataDir                  string // Data directory for database and backups
	Version                  string // Application version
	CleanupIntervalMinutes   int
	PublicURL                string
	DownloadURL              string // Optional: Separate URL for downloads (bypasses CDN timeouts)
	EncryptionKey            string
	AdminUsername            string
	SessionExpiryHours       int
	HTTPSEnabled             bool
	RequireAuthForUpload     bool
	ChunkedUploadEnabled     bool
	ChunkedUploadThreshold   int64
	ChunkSize                int64
	PartialUploadExpiryHours int
	ReadTimeoutSeconds       int
	WriteTimeoutSeconds      int
	TrustProxyHeaders        string // "auto", "true", "false" - controls proxy header trust
	TrustedProxyIPs          string // Comma-separated list of trusted proxy IPs/CIDR ranges

	// Mutable fields (can be updated at runtime via admin dashboard)
	maxFileSize            int64
	defaultExpirationHours int
	maxExpirationHours     int
	blockedExtensions      []string
	rateLimitUpload        int
	rateLimitDownload      int
	quotaLimitGB           int64
	adminPassword          string // bcrypt hash
}

// Load reads configuration from environment variables with sensible defaults
func Load() (*Config, error) {
	// Default blocked extensions for security
	defaultBlocked := ".exe,.bat,.cmd,.sh,.ps1,.dll,.so,.msi,.scr,.vbs,.jar,.com,.app,.deb,.rpm"

	cfg := &Config{
		// Immutable fields
		Port:                     getEnv("PORT", "8080"),
		DBPath:                   getEnv("DB_PATH", "./safeshare.db"),
		UploadDir:                getEnv("UPLOAD_DIR", "./uploads"),
		BackupDir:                getEnv("BACKUP_DIR", ""), // Empty = DataDir/backups
		DataDir:                  getEnv("DATA_DIR", "./data"),
		Version:                  getEnv("APP_VERSION", "1.4.1"),
		CleanupIntervalMinutes:   getEnvInt("CLEANUP_INTERVAL_MINUTES", 60),
		PublicURL:                getEnv("PUBLIC_URL", ""),
		DownloadURL:              getEnv("DOWNLOAD_URL", ""), // Optional: bypasses CDN for large downloads
		EncryptionKey:            getEnv("ENCRYPTION_KEY", ""),
		AdminUsername:            getEnv("ADMIN_USERNAME", ""),
		SessionExpiryHours:       getEnvInt("SESSION_EXPIRY_HOURS", 24),
		HTTPSEnabled:             getEnvBool("HTTPS_ENABLED", false),
		RequireAuthForUpload:     getEnvBool("REQUIRE_AUTH_FOR_UPLOAD", false),
		ChunkedUploadEnabled:     getEnvBool("CHUNKED_UPLOAD_ENABLED", true),
		ChunkedUploadThreshold:   getEnvInt64("CHUNKED_UPLOAD_THRESHOLD", 104857600), // 100MB
		ChunkSize:                getEnvInt64("CHUNK_SIZE", 10485760),                // 10MB (was 5MB)
		PartialUploadExpiryHours: getEnvInt("PARTIAL_UPLOAD_EXPIRY_HOURS", 24),
		ReadTimeoutSeconds:       getEnvInt("READ_TIMEOUT", 120),  // 2 minutes (was 15s)
		WriteTimeoutSeconds:      getEnvInt("WRITE_TIMEOUT", 120), // 2 minutes (was 15s)
		TrustProxyHeaders:        getEnv("TRUST_PROXY_HEADERS", "auto"),
		TrustedProxyIPs:          getEnv("TRUSTED_PROXY_IPS", "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"),

		// Mutable fields (lowercase, accessed via getters/setters)
		maxFileSize:            getEnvInt64("MAX_FILE_SIZE", 104857600), // 100MB default
		defaultExpirationHours: getEnvInt("DEFAULT_EXPIRATION_HOURS", 24),
		maxExpirationHours:     getEnvInt("MAX_EXPIRATION_HOURS", 168), // 7 days default
		blockedExtensions:      getEnvList("BLOCKED_EXTENSIONS", defaultBlocked),
		rateLimitUpload:        getEnvInt("RATE_LIMIT_UPLOAD", 10),   // 10 uploads per hour per IP
		rateLimitDownload:      getEnvInt("RATE_LIMIT_DOWNLOAD", 50), // 50 downloads per hour per IP
		quotaLimitGB:           getEnvInt64("QUOTA_LIMIT_GB", 0),     // 0 = unlimited (default)
		adminPassword:          getEnv("ADMIN_PASSWORD", ""),         // Required for admin access
	}

	// Validate configuration
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

// Getter methods for mutable fields (thread-safe reads)

func (c *Config) GetMaxFileSize() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.maxFileSize
}

func (c *Config) GetDefaultExpirationHours() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.defaultExpirationHours
}

func (c *Config) GetMaxExpirationHours() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.maxExpirationHours
}

func (c *Config) GetBlockedExtensions() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	// Return a copy to prevent external modification
	result := make([]string, len(c.blockedExtensions))
	copy(result, c.blockedExtensions)
	return result
}

func (c *Config) GetRateLimitUpload() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rateLimitUpload
}

func (c *Config) GetRateLimitDownload() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rateLimitDownload
}

func (c *Config) GetQuotaLimitGB() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.quotaLimitGB
}

// QuotaLimitGB returns the quota limit for public access (no lock needed for metrics)
// This is used by the metrics collector which needs direct access
func (c *Config) QuotaLimitGB() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return float64(c.quotaLimitGB)
}

func (c *Config) GetAdminPassword() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.adminPassword
}

// GetTrustProxyHeaders returns the proxy header trust setting
func (c *Config) GetTrustProxyHeaders() string {
	return c.TrustProxyHeaders
}

// GetTrustedProxyIPs returns the trusted proxy IPs configuration
func (c *Config) GetTrustedProxyIPs() string {
	return c.TrustedProxyIPs
}

// Setter methods for mutable fields (thread-safe writes with validation)

func (c *Config) SetMaxFileSize(size int64) error {
	if size <= 0 {
		return fmt.Errorf("max file size must be positive, got %d", size)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxFileSize = size
	return nil
}

func (c *Config) SetDefaultExpirationHours(hours int) error {
	if hours <= 0 {
		return fmt.Errorf("default expiration hours must be positive, got %d", hours)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if hours > c.maxExpirationHours {
		return fmt.Errorf("default expiration (%d) cannot exceed max expiration (%d)", hours, c.maxExpirationHours)
	}
	c.defaultExpirationHours = hours
	return nil
}

func (c *Config) SetMaxExpirationHours(hours int) error {
	if hours <= 0 {
		return fmt.Errorf("max expiration hours must be positive, got %d", hours)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.defaultExpirationHours > hours {
		return fmt.Errorf("max expiration (%d) cannot be less than default expiration (%d)", hours, c.defaultExpirationHours)
	}
	c.maxExpirationHours = hours
	return nil
}

func (c *Config) SetBlockedExtensions(extensions []string) error {
	if extensions == nil {
		return fmt.Errorf("blocked extensions cannot be nil")
	}
	// Normalize extensions (add dot prefix, lowercase)
	normalized := make([]string, 0, len(extensions))
	for _, ext := range extensions {
		trimmed := strings.TrimSpace(ext)
		if trimmed != "" {
			if !strings.HasPrefix(trimmed, ".") {
				trimmed = "." + trimmed
			}
			normalized = append(normalized, strings.ToLower(trimmed))
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockedExtensions = normalized
	return nil
}

func (c *Config) SetRateLimitUpload(limit int) error {
	if limit <= 0 {
		return fmt.Errorf("upload rate limit must be positive, got %d", limit)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rateLimitUpload = limit
	return nil
}

func (c *Config) SetRateLimitDownload(limit int) error {
	if limit <= 0 {
		return fmt.Errorf("download rate limit must be positive, got %d", limit)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rateLimitDownload = limit
	return nil
}

func (c *Config) SetQuotaLimitGB(quota int64) error {
	if quota < 0 {
		return fmt.Errorf("quota limit must be 0 (unlimited) or positive, got %d", quota)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.quotaLimitGB = quota
	return nil
}

func (c *Config) SetAdminPassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("admin password must be at least 8 characters")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.adminPassword = password
	return nil
}

// validate ensures configuration values are sensible
func (c *Config) validate() error {
	if err := c.validatePaths(); err != nil {
		return err
	}

	if err := c.validateStorageSettings(); err != nil {
		return err
	}

	if err := c.validateAuthSettings(); err != nil {
		return err
	}

	if err := c.validateEncryptionKey(); err != nil {
		return err
	}

	if err := c.validateChunkedUploadSettings(); err != nil {
		return err
	}

	if err := c.validateProxySettings(); err != nil {
		return err
	}

	return nil
}

// validatePaths validates required path and port configuration fields
func (c *Config) validatePaths() error {
	if c.Port == "" {
		return fmt.Errorf("PORT cannot be empty")
	}

	if c.DBPath == "" {
		return fmt.Errorf("DB_PATH cannot be empty")
	}

	if c.UploadDir == "" {
		return fmt.Errorf("UPLOAD_DIR cannot be empty")
	}

	return nil
}

// validateStorageSettings validates file size, expiration, rate limits, and quota settings
func (c *Config) validateStorageSettings() error {
	if c.maxFileSize <= 0 {
		return fmt.Errorf("MAX_FILE_SIZE must be positive, got %d", c.maxFileSize)
	}

	if c.defaultExpirationHours <= 0 {
		return fmt.Errorf("DEFAULT_EXPIRATION_HOURS must be positive, got %d", c.defaultExpirationHours)
	}

	if c.maxExpirationHours <= 0 {
		return fmt.Errorf("MAX_EXPIRATION_HOURS must be positive, got %d", c.maxExpirationHours)
	}

	if c.defaultExpirationHours > c.maxExpirationHours {
		return fmt.Errorf("DEFAULT_EXPIRATION_HOURS (%d) cannot exceed MAX_EXPIRATION_HOURS (%d)", c.defaultExpirationHours, c.maxExpirationHours)
	}

	if c.CleanupIntervalMinutes <= 0 {
		return fmt.Errorf("CLEANUP_INTERVAL_MINUTES must be positive, got %d", c.CleanupIntervalMinutes)
	}

	if c.rateLimitUpload <= 0 {
		return fmt.Errorf("RATE_LIMIT_UPLOAD must be positive, got %d", c.rateLimitUpload)
	}

	if c.rateLimitDownload <= 0 {
		return fmt.Errorf("RATE_LIMIT_DOWNLOAD must be positive, got %d", c.rateLimitDownload)
	}

	if c.quotaLimitGB < 0 {
		return fmt.Errorf("QUOTA_LIMIT_GB must be 0 (unlimited) or positive, got %d", c.quotaLimitGB)
	}

	return nil
}

// validateAuthSettings validates session expiry and admin credential configuration
func (c *Config) validateAuthSettings() error {
	if c.SessionExpiryHours <= 0 {
		return fmt.Errorf("SESSION_EXPIRY_HOURS must be positive, got %d", c.SessionExpiryHours)
	}

	// Admin credentials validation - both or neither must be provided
	if (c.AdminUsername == "" && c.adminPassword != "") || (c.AdminUsername != "" && c.adminPassword == "") {
		return fmt.Errorf("both ADMIN_USERNAME and ADMIN_PASSWORD must be set to enable admin dashboard")
	}

	if c.AdminUsername != "" && len(c.AdminUsername) < 3 {
		return fmt.Errorf("ADMIN_USERNAME must be at least 3 characters")
	}

	if c.adminPassword != "" && len(c.adminPassword) < 8 {
		return fmt.Errorf("ADMIN_PASSWORD must be at least 8 characters")
	}

	return nil
}

// validateEncryptionKey validates the encryption key format if provided
func (c *Config) validateEncryptionKey() error {
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

// validateChunkedUploadSettings validates chunked upload configuration parameters
func (c *Config) validateChunkedUploadSettings() error {
	if c.ChunkSize < 1048576 || c.ChunkSize > 52428800 {
		return fmt.Errorf("CHUNK_SIZE must be between 1MB (1048576) and 50MB (52428800), got %d", c.ChunkSize)
	}

	if c.ChunkedUploadThreshold < 0 {
		return fmt.Errorf("CHUNKED_UPLOAD_THRESHOLD must be non-negative, got %d", c.ChunkedUploadThreshold)
	}

	if c.PartialUploadExpiryHours <= 0 {
		return fmt.Errorf("PARTIAL_UPLOAD_EXPIRY_HOURS must be positive, got %d", c.PartialUploadExpiryHours)
	}

	return nil
}

// validateProxySettings validates reverse proxy header trust configuration
func (c *Config) validateProxySettings() error {
	validProxySettings := map[string]bool{"auto": true, "true": true, "false": true}
	if !validProxySettings[c.TrustProxyHeaders] {
		return fmt.Errorf("TRUST_PROXY_HEADERS must be 'auto', 'true', or 'false', got '%s'", c.TrustProxyHeaders)
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

// getEnvBool retrieves a boolean environment variable or returns a default value
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		// Parse common boolean representations
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "true" || value == "1" || value == "yes" || value == "on" {
			return true
		}
		if value == "false" || value == "0" || value == "no" || value == "off" {
			return false
		}
	}
	return defaultValue
}
