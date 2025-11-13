package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/fjmerc/safeshare/internal/config"
)

// ConfigAssistantRequest represents the user's environment input
type ConfigAssistantRequest struct {
	UploadSpeed        float64 `json:"upload_speed"`        // Mbps
	DownloadSpeed      float64 `json:"download_speed"`      // Mbps
	NetworkLatency     string  `json:"network_latency"`     // local, low, medium, high
	TypicalFileSize    string  `json:"typical_file_size"`   // small, medium, large, huge
	DeploymentType     string  `json:"deployment_type"`     // LAN, WAN, Internet
	UserLoad           string  `json:"user_load"`           // light, moderate, heavy, very_heavy
	StorageCapacity    int64   `json:"storage_capacity"`    // GB (0 = unlimited)
	UsingCDN           bool    `json:"using_cdn"`           // Behind a CDN?
	CDNTimeout         int     `json:"cdn_timeout"`         // CDN timeout in seconds (0 = unknown)
	EncryptionEnabled  bool    `json:"encryption_enabled"`  // AES-256-GCM encryption active?
}

// ConfigRecommendations represents the recommended configuration
type ConfigRecommendations struct {
	// Immediate settings (can be applied without restart)
	MaxFileSize             int64    `json:"max_file_size"`              // bytes
	QuotaLimitGB            int64    `json:"quota_limit_gb"`             // GB
	DefaultExpirationHours  int      `json:"default_expiration_hours"`   // hours
	MaxExpirationHours      int      `json:"max_expiration_hours"`       // hours
	RateLimitUpload         int      `json:"rate_limit_upload"`          // per hour
	RateLimitDownload       int      `json:"rate_limit_download"`        // per hour
	BlockedExtensions       []string `json:"blocked_extensions"`         // list of extensions

	// Performance settings (require restart)
	ChunkSize                int64 `json:"chunk_size"`                  // bytes
	ReadTimeout              int   `json:"read_timeout"`                // seconds
	WriteTimeout             int   `json:"write_timeout"`               // seconds
	ChunkedUploadThreshold   int64 `json:"chunked_upload_threshold"`   // bytes
	PartialUploadExpiryHours int   `json:"partial_upload_expiry_hours"` // hours

	// Operational settings (require restart)
	SessionExpiryHours     int  `json:"session_expiry_hours"`      // hours
	CleanupIntervalMinutes int  `json:"cleanup_interval_minutes"`  // minutes
	RequireAuthForUpload   bool `json:"require_auth_for_upload"`   // boolean
	HTTPSEnabled           bool `json:"https_enabled"`             // boolean
	ChunkedUploadEnabled   bool `json:"chunked_upload_enabled"`    // boolean
	PublicURL              string `json:"public_url"`              // URL string
}

// ConfigAssistantResponse represents the full response with analysis
type ConfigAssistantResponse struct {
	Recommendations       ConfigRecommendations     `json:"recommendations"`
	CurrentConfig         ConfigRecommendations     `json:"current_config"`
	Analysis              ConfigAnalysis            `json:"analysis"`
}

// ConfigAnalysis provides context about the recommendations
type ConfigAnalysis struct {
	Summary                   string            `json:"summary"`
	Impacts                   map[string]string `json:"impacts"`
	AdditionalRecommendations []string          `json:"additional_recommendations"`
}

// AdminConfigAssistantHandler analyzes user environment and recommends optimal settings
func AdminConfigAssistantHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request
		var req ConfigAssistantRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error("failed to parse config assistant request", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate inputs
		if req.UploadSpeed <= 0 || req.DownloadSpeed <= 0 {
			http.Error(w, "Invalid speed values", http.StatusBadRequest)
			return
		}

		// Get current configuration
		currentConfig := ConfigRecommendations{
			// Immediate settings
			MaxFileSize:            cfg.GetMaxFileSize(),
			QuotaLimitGB:           cfg.GetQuotaLimitGB(),
			DefaultExpirationHours: cfg.GetDefaultExpirationHours(),
			MaxExpirationHours:     cfg.GetMaxExpirationHours(),
			RateLimitUpload:        cfg.GetRateLimitUpload(),
			RateLimitDownload:      cfg.GetRateLimitDownload(),
			BlockedExtensions:      cfg.GetBlockedExtensions(),

			// Performance settings (immutable - from config)
			ChunkSize:                cfg.ChunkSize,
			ReadTimeout:              cfg.ReadTimeoutSeconds,
			WriteTimeout:             cfg.WriteTimeoutSeconds,
			ChunkedUploadThreshold:   cfg.ChunkedUploadThreshold,
			PartialUploadExpiryHours: cfg.PartialUploadExpiryHours,

			// Operational settings (immutable - from config)
			SessionExpiryHours:     cfg.SessionExpiryHours,
			CleanupIntervalMinutes: cfg.CleanupIntervalMinutes,
			RequireAuthForUpload:   cfg.RequireAuthForUpload,
			HTTPSEnabled:           cfg.HTTPSEnabled,
			ChunkedUploadEnabled:   cfg.ChunkedUploadEnabled,
			PublicURL:              cfg.PublicURL,
		}

		// Calculate recommendations based on user environment
		recommendations := calculateRecommendations(req)

		// Generate analysis
		analysis := generateAnalysis(req, currentConfig, recommendations)

		// Build response
		response := ConfigAssistantResponse{
			Recommendations: recommendations,
			CurrentConfig:   currentConfig,
			Analysis:        analysis,
		}

		slog.Info("configuration assistant analysis completed",
			"admin_ip", getClientIP(r),
			"deployment_type", req.DeploymentType,
			"user_load", req.UserLoad,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// calculateRecommendations generates optimal settings based on environment
func calculateRecommendations(req ConfigAssistantRequest) ConfigRecommendations {
	rec := ConfigRecommendations{
		// Default blocked extensions (security baseline)
		BlockedExtensions: []string{".exe", ".bat", ".cmd", ".sh", ".ps1", ".dll", ".so", ".msi", ".scr", ".vbs", ".jar", ".com", ".app", ".deb", ".rpm"},
		// Default to enabled for most cases
		ChunkedUploadEnabled: true,
	}

	// Convert Mbps to MBps (megabytes per second)
	uploadSpeedMBps := req.UploadSpeed / 8.0
	downloadSpeedMBps := req.DownloadSpeed / 8.0

	// 1. Determine Max File Size based on typical file size and storage
	switch req.TypicalFileSize {
	case "small":
		rec.MaxFileSize = 100 * 1024 * 1024 // 100MB
	case "medium":
		rec.MaxFileSize = 1 * 1024 * 1024 * 1024 // 1GB
	case "large":
		rec.MaxFileSize = 5 * 1024 * 1024 * 1024 // 5GB
	case "huge":
		rec.MaxFileSize = 10 * 1024 * 1024 * 1024 // 10GB
	default:
		rec.MaxFileSize = 100 * 1024 * 1024 // default 100MB
	}

	// 2. Set Storage Quota based on available capacity
	if req.StorageCapacity > 0 {
		// Use 80% of available capacity as quota to leave headroom
		rec.QuotaLimitGB = int64(float64(req.StorageCapacity) * 0.8)
		if rec.QuotaLimitGB < 10 {
			rec.QuotaLimitGB = req.StorageCapacity // use full capacity if < 10GB
		}
	} else {
		rec.QuotaLimitGB = 0 // unlimited
	}

	// 3. Set Expiration times based on deployment type
	switch req.DeploymentType {
	case "LAN":
		// LAN deployments typically have shorter retention needs
		rec.DefaultExpirationHours = 24  // 1 day
		rec.MaxExpirationHours = 168     // 7 days
	case "WAN":
		// WAN deployments need moderate retention
		rec.DefaultExpirationHours = 72  // 3 days
		rec.MaxExpirationHours = 336     // 14 days
	case "Internet":
		// Internet deployments benefit from longer retention
		rec.DefaultExpirationHours = 168 // 7 days
		rec.MaxExpirationHours = 720     // 30 days
	default:
		rec.DefaultExpirationHours = 24
		rec.MaxExpirationHours = 168
	}

	// 4. Calculate Rate Limits based on user load and network capacity
	switch req.UserLoad {
	case "light":
		// 1-10 users: generous limits
		rec.RateLimitUpload = 20
		rec.RateLimitDownload = 200
	case "moderate":
		// 10-50 users: balanced limits
		rec.RateLimitUpload = 15
		rec.RateLimitDownload = 150
	case "heavy":
		// 50-200 users: conservative limits to prevent abuse
		rec.RateLimitUpload = 10
		rec.RateLimitDownload = 100
	case "very_heavy":
		// > 200 users: strict limits
		rec.RateLimitUpload = 5
		rec.RateLimitDownload = 50
	default:
		rec.RateLimitUpload = 10
		rec.RateLimitDownload = 100
	}

	// Adjust rate limits based on bandwidth
	if uploadSpeedMBps < 5 {
		// Low bandwidth: reduce limits further
		rec.RateLimitUpload = rec.RateLimitUpload / 2
		if rec.RateLimitUpload < 3 {
			rec.RateLimitUpload = 3 // minimum
		}
	} else if uploadSpeedMBps > 50 {
		// High bandwidth: can afford higher limits for light/moderate loads
		if req.UserLoad == "light" || req.UserLoad == "moderate" {
			rec.RateLimitUpload = int(float64(rec.RateLimitUpload) * 1.5)
		}
	}

	// Adjust download limits similarly
	if downloadSpeedMBps < 10 {
		rec.RateLimitDownload = rec.RateLimitDownload / 2
		if rec.RateLimitDownload < 20 {
			rec.RateLimitDownload = 20 // minimum
		}
	} else if downloadSpeedMBps > 100 {
		if req.UserLoad == "light" || req.UserLoad == "moderate" {
			rec.RateLimitDownload = int(float64(rec.RateLimitDownload) * 1.5)
		}
	}

	// 5. Calculate CHUNK_SIZE based on bandwidth and latency
	// Formula: Optimize for reliability and progress tracking
	// Smaller chunks (5-10MB) for slow/unreliable connections provide better resume capability
	// Larger chunks (20-30MB) for fast connections reduce overhead
	// Range: 5MB - 30MB (always within documented 1-50MB limit)

	if req.NetworkLatency == "high" || uploadSpeedMBps < 2 {
		// High latency or slow connection: smaller chunks for reliability
		rec.ChunkSize = 5 * 1024 * 1024 // 5MB
	} else if uploadSpeedMBps < 5 {
		// Medium-slow connection
		rec.ChunkSize = 8 * 1024 * 1024 // 8MB
	} else if uploadSpeedMBps < 15 {
		// Medium connection
		rec.ChunkSize = 10 * 1024 * 1024 // 10MB (default)
	} else if uploadSpeedMBps < 30 {
		// Fast connection
		rec.ChunkSize = 20 * 1024 * 1024 // 20MB
	} else {
		// Very fast connection
		rec.ChunkSize = 30 * 1024 * 1024 // 30MB
	}

	// Adjust for large files - may want smaller chunks for better progress reporting
	if req.TypicalFileSize == "huge" {
		if rec.ChunkSize > 10*1024*1024 {
			rec.ChunkSize = 10 * 1024 * 1024 // cap at 10MB for huge files
		}
	}

	// 6. Calculate READ_TIMEOUT and WRITE_TIMEOUT
	// Formula: (ChunkSize in MB / UploadSpeed in MBps) × SafetyFactor
	chunkSizeMB := float64(rec.ChunkSize) / (1024 * 1024)
	baseTimeout := int((chunkSizeMB / uploadSpeedMBps) * 3.0) // 3x safety factor

	// Minimum timeout
	if baseTimeout < 60 {
		baseTimeout = 60
	}

	// Add extra time for high latency or slow connections
	if req.NetworkLatency == "high" {
		rec.ReadTimeout = baseTimeout * 2
		rec.WriteTimeout = baseTimeout * 2
	} else if req.NetworkLatency == "medium" {
		rec.ReadTimeout = int(float64(baseTimeout) * 1.5)
		rec.WriteTimeout = int(float64(baseTimeout) * 1.5)
	} else {
		rec.ReadTimeout = baseTimeout
		rec.WriteTimeout = baseTimeout
	}

	// Cap timeouts at reasonable maximums
	if rec.ReadTimeout > 600 {
		rec.ReadTimeout = 600 // 10 minutes max
	}
	if rec.WriteTimeout > 600 {
		rec.WriteTimeout = 600
	}

	// Ensure minimums
	if rec.ReadTimeout < 60 {
		rec.ReadTimeout = 60
	}
	if rec.WriteTimeout < 60 {
		rec.WriteTimeout = 60
	}

	// Apply CDN timeout constraints if behind a CDN
	if req.UsingCDN && req.CDNTimeout > 0 {
		// Timeouts must be less than CDN timeout (use 80% for safety margin)
		maxAllowedTimeout := int(float64(req.CDNTimeout) * 0.8)
		if rec.ReadTimeout > maxAllowedTimeout {
			rec.ReadTimeout = maxAllowedTimeout
		}
		if rec.WriteTimeout > maxAllowedTimeout {
			rec.WriteTimeout = maxAllowedTimeout
		}

		// Adjust chunk size to fit within CDN timeout
		// Formula: ChunkSize <= (UploadSpeed * CDNTimeout * 0.6) to ensure completion
		maxSafeChunkSize := int64(uploadSpeedMBps * float64(req.CDNTimeout) * 0.6 * 1024 * 1024)
		if maxSafeChunkSize < 5*1024*1024 {
			maxSafeChunkSize = 5 * 1024 * 1024 // minimum 5MB
		}
		if rec.ChunkSize > maxSafeChunkSize {
			rec.ChunkSize = maxSafeChunkSize
		}
	}

	// Apply encryption overhead if encryption is enabled
	if req.EncryptionEnabled {
		// Add 20% overhead for encryption/decryption processing
		rec.ReadTimeout = int(float64(rec.ReadTimeout) * 1.2)
		rec.WriteTimeout = int(float64(rec.WriteTimeout) * 1.2)

		// Re-apply maximum cap after encryption adjustment
		if rec.ReadTimeout > 600 {
			rec.ReadTimeout = 600
		}
		if rec.WriteTimeout > 600 {
			rec.WriteTimeout = 600
		}
	}

	// 7. Set CHUNKED_UPLOAD_THRESHOLD
	// Start chunking earlier for large files or slow connections
	// Lower threshold = more files use chunked upload = better reliability and progress tracking
	// Higher threshold = fewer files use chunking = less overhead for small/medium files
	if req.TypicalFileSize == "huge" || uploadSpeedMBps < 5 {
		rec.ChunkedUploadThreshold = 50 * 1024 * 1024 // 50MB - start chunking early for reliability
	} else if req.TypicalFileSize == "large" {
		rec.ChunkedUploadThreshold = 75 * 1024 * 1024 // 75MB - balanced threshold
	} else {
		rec.ChunkedUploadThreshold = 100 * 1024 * 1024 // 100MB - default, minimal overhead
	}

	// 8. Set PARTIAL_UPLOAD_EXPIRY_HOURS
	// Give more time for slow connections with large files
	if (req.TypicalFileSize == "large" || req.TypicalFileSize == "huge") && uploadSpeedMBps < 2 {
		rec.PartialUploadExpiryHours = 72 // 3 days for very slow large uploads
	} else if uploadSpeedMBps < 5 {
		rec.PartialUploadExpiryHours = 48 // 2 days for slow connections
	} else {
		rec.PartialUploadExpiryHours = 24 // 1 day (default)
	}

	// 9. Set SESSION_EXPIRY_HOURS based on deployment type
	switch req.DeploymentType {
	case "LAN":
		rec.SessionExpiryHours = 12 // shorter for internal networks
	case "WAN":
		rec.SessionExpiryHours = 24 // standard
	case "Internet":
		rec.SessionExpiryHours = 48 // longer for external users
	default:
		rec.SessionExpiryHours = 24
	}

	// 10. Set CLEANUP_INTERVAL_MINUTES based on user load and storage
	if req.StorageCapacity > 0 && req.StorageCapacity < 50 {
		// Limited storage: cleanup more frequently
		rec.CleanupIntervalMinutes = 30
	} else if req.UserLoad == "heavy" || req.UserLoad == "very_heavy" {
		// High traffic: cleanup more frequently
		rec.CleanupIntervalMinutes = 45
	} else {
		rec.CleanupIntervalMinutes = 60 // default
	}

	// 11. Set REQUIRE_AUTH_FOR_UPLOAD based on deployment and user load
	if req.DeploymentType == "Internet" && (req.UserLoad == "heavy" || req.UserLoad == "very_heavy") {
		rec.RequireAuthForUpload = true // prevent abuse on public internet
	} else if req.DeploymentType == "Internet" && req.UserLoad == "moderate" {
		rec.RequireAuthForUpload = true // recommended for public internet
	} else {
		rec.RequireAuthForUpload = false // allow anonymous for internal/light use
	}

	// 12. Set HTTPS_ENABLED recommendation
	if req.DeploymentType == "Internet" {
		rec.HTTPSEnabled = true // always for public internet
	} else if req.DeploymentType == "WAN" {
		rec.HTTPSEnabled = true // recommended for WAN
	} else {
		rec.HTTPSEnabled = false // optional for LAN
	}

	// 13. Set PUBLIC_URL recommendation (empty means detect from request)
	if req.DeploymentType == "Internet" || req.DeploymentType == "WAN" {
		rec.PublicURL = "" // Should be set manually by admin
	} else {
		rec.PublicURL = "" // Auto-detect is fine for LAN
	}

	return rec
}

// generateAnalysis creates human-readable analysis and recommendations
func generateAnalysis(req ConfigAssistantRequest, current, recommended ConfigRecommendations) ConfigAnalysis {
	analysis := ConfigAnalysis{
		Impacts:                   make(map[string]string),
		AdditionalRecommendations: []string{},
	}

	// Generate summary
	latencyDesc := map[string]string{
		"local":  "local network",
		"low":    "low-latency",
		"medium": "medium-latency",
		"high":   "high-latency",
	}[req.NetworkLatency]

	analysis.Summary = fmt.Sprintf(
		"Optimized for %s deployment with %s connectivity, %s file sizes, and %s user load.",
		req.DeploymentType,
		latencyDesc,
		req.TypicalFileSize,
		req.UserLoad,
	)

	// Explain impacts of each setting
	if current.MaxFileSize != recommended.MaxFileSize {
		if recommended.MaxFileSize > current.MaxFileSize {
			analysis.Impacts["max_file_size"] = "Increased to accommodate your typical file sizes"
		} else {
			analysis.Impacts["max_file_size"] = "Optimized for storage efficiency"
		}
	}

	if current.QuotaLimitGB != recommended.QuotaLimitGB {
		if recommended.QuotaLimitGB > 0 {
			analysis.Impacts["quota_limit_gb"] = fmt.Sprintf("Set to 80%% of available capacity (%d GB)", req.StorageCapacity)
		} else {
			analysis.Impacts["quota_limit_gb"] = "Unlimited storage recommended based on your capacity"
		}
	}

	if current.DefaultExpirationHours != recommended.DefaultExpirationHours {
		analysis.Impacts["default_expiration_hours"] = fmt.Sprintf("Adjusted for %s deployment pattern", req.DeploymentType)
	}

	if current.MaxExpirationHours != recommended.MaxExpirationHours {
		analysis.Impacts["max_expiration_hours"] = fmt.Sprintf("Extended for %s use case", req.DeploymentType)
	}

	if current.RateLimitUpload != recommended.RateLimitUpload {
		analysis.Impacts["rate_limit_upload"] = fmt.Sprintf("Balanced for %s user load and %.1f Mbps upload speed", req.UserLoad, req.UploadSpeed)
	}

	if current.RateLimitDownload != recommended.RateLimitDownload {
		analysis.Impacts["rate_limit_download"] = fmt.Sprintf("Optimized for %s user load and %.1f Mbps download speed", req.UserLoad, req.DownloadSpeed)
	}

	// Performance settings impacts
	if current.ChunkSize != recommended.ChunkSize {
		chunkSizeMB := float64(recommended.ChunkSize) / (1024 * 1024)
		analysis.Impacts["chunk_size"] = fmt.Sprintf("Optimized to %.0fMB for %.1f Mbps upload speed and %s latency", chunkSizeMB, req.UploadSpeed, req.NetworkLatency)
	}

	if current.ReadTimeout != recommended.ReadTimeout {
		analysis.Impacts["read_timeout"] = fmt.Sprintf("Calculated based on chunk size and upload speed with safety margin (%d seconds)", recommended.ReadTimeout)
	}

	if current.WriteTimeout != recommended.WriteTimeout {
		analysis.Impacts["write_timeout"] = fmt.Sprintf("Matched to read timeout for consistent behavior (%d seconds)", recommended.WriteTimeout)
	}

	if current.ChunkedUploadThreshold != recommended.ChunkedUploadThreshold {
		thresholdMB := recommended.ChunkedUploadThreshold / (1024 * 1024)
		analysis.Impacts["chunked_upload_threshold"] = fmt.Sprintf("Set to %dMB for optimal reliability with %s files", thresholdMB, req.TypicalFileSize)
	}

	if current.PartialUploadExpiryHours != recommended.PartialUploadExpiryHours {
		analysis.Impacts["partial_upload_expiry_hours"] = fmt.Sprintf("Extended to %d hours for slower connections to complete large uploads", recommended.PartialUploadExpiryHours)
	}

	// Operational settings impacts
	if current.SessionExpiryHours != recommended.SessionExpiryHours {
		analysis.Impacts["session_expiry_hours"] = fmt.Sprintf("Adjusted to %d hours for %s deployment pattern", recommended.SessionExpiryHours, req.DeploymentType)
	}

	if current.CleanupIntervalMinutes != recommended.CleanupIntervalMinutes {
		analysis.Impacts["cleanup_interval_minutes"] = fmt.Sprintf("Set to %d minutes for efficient storage management", recommended.CleanupIntervalMinutes)
	}

	if current.RequireAuthForUpload != recommended.RequireAuthForUpload {
		if recommended.RequireAuthForUpload {
			analysis.Impacts["require_auth_for_upload"] = "Enabled to prevent abuse on public internet deployment"
		} else {
			analysis.Impacts["require_auth_for_upload"] = "Disabled for convenience on internal network"
		}
	}

	if current.HTTPSEnabled != recommended.HTTPSEnabled {
		if recommended.HTTPSEnabled {
			analysis.Impacts["https_enabled"] = "Strongly recommended for security on internet/WAN deployments"
		} else {
			analysis.Impacts["https_enabled"] = "Optional for local network deployments"
		}
	}

	// Add additional recommendations based on environment
	if req.NetworkLatency == "high" || req.NetworkLatency == "medium" {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			"Consider enabling TCP tuning for high-latency connections. See docs/TCP_TUNING.md for system-level optimizations.",
		)
	}

	if req.TypicalFileSize == "large" || req.TypicalFileSize == "huge" {
		chunkSizeMB := float64(recommended.ChunkSize) / (1024 * 1024)
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			fmt.Sprintf("For large files: CHUNK_SIZE=%.0fMB, READ_TIMEOUT=%ds, WRITE_TIMEOUT=%ds are calculated for your connection speed.", chunkSizeMB, recommended.ReadTimeout, recommended.WriteTimeout),
		)
	}

	if req.DeploymentType == "Internet" {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			fmt.Sprintf("For public internet: Configure reverse proxy timeouts to at least %d seconds to match READ_TIMEOUT.", recommended.ReadTimeout),
		)
		if recommended.HTTPSEnabled {
			analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
				"Enable HTTPS_ENABLED=true and set PUBLIC_URL to your public domain for correct link generation.",
			)
		}
	}

	// CDN-specific recommendations
	if req.UsingCDN {
		if req.CDNTimeout > 0 {
			chunkSizeMB := float64(recommended.ChunkSize) / (1024 * 1024)
			analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
				fmt.Sprintf("CDN detected (%ds timeout): Chunk size optimized to %.0fMB to ensure uploads complete within timeout limits.", req.CDNTimeout, chunkSizeMB),
			)
		}
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			"CDN detected: Set DOWNLOAD_URL to a DNS-only subdomain (bypassing CDN) for large file downloads. Example: downloads.yourdomain.com",
		)
		if req.CDNTimeout < 60 {
			analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
				fmt.Sprintf("⚠️ CDN timeout is only %ds. Consider upgrading CDN tier or bypassing CDN for upload endpoints to support larger files.", req.CDNTimeout),
			)
		}
	}

	// Encryption-specific recommendations
	if req.EncryptionEnabled {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			"Encryption enabled: Timeouts increased by 20%% to account for AES-256-GCM encryption/decryption overhead.",
		)
	}

	uploadSpeedMBps := req.UploadSpeed / 8
	if uploadSpeedMBps < 5 {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			fmt.Sprintf("Low upload bandwidth detected (%.1f MB/s). Consider CHUNK_SIZE=5MB for better reliability on slow connections.", uploadSpeedMBps),
		)
	}

	if req.UserLoad == "heavy" || req.UserLoad == "very_heavy" {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			"High user load detected. Monitor storage usage and consider implementing user quotas for fair resource allocation.",
		)
	}

	// If storage is limited, warn about it
	if req.StorageCapacity > 0 && req.StorageCapacity < 50 {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			fmt.Sprintf("Limited storage capacity (%d GB). Consider implementing aggressive file expiration policies or increasing storage.", req.StorageCapacity),
		)
	}

	return analysis
}
