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
	UploadSpeed       float64 `json:"upload_speed"`       // Mbps
	DownloadSpeed     float64 `json:"download_speed"`     // Mbps
	NetworkLatency    string  `json:"network_latency"`    // local, low, medium, high
	TypicalFileSize   string  `json:"typical_file_size"`  // small, medium, large, huge
	DeploymentType    string  `json:"deployment_type"`    // LAN, WAN, Internet
	UserLoad          string  `json:"user_load"`          // light, moderate, heavy, very_heavy
	StorageCapacity   int64   `json:"storage_capacity"`   // GB (0 = unlimited)
	UsingCDN          bool    `json:"using_cdn"`          // Behind a CDN?
	CDNTimeout        int     `json:"cdn_timeout"`        // CDN timeout in seconds (0 = unknown)
	EncryptionEnabled bool    `json:"encryption_enabled"` // AES-256-GCM encryption active?
}

// ConfigRecommendations represents the recommended configuration
type ConfigRecommendations struct {
	// Immediate settings (can be applied without restart)
	MaxFileSize            int64    `json:"max_file_size"`            // bytes
	QuotaLimitGB           int64    `json:"quota_limit_gb"`           // GB
	DefaultExpirationHours int      `json:"default_expiration_hours"` // hours
	MaxExpirationHours     int      `json:"max_expiration_hours"`     // hours
	RateLimitUpload        int      `json:"rate_limit_upload"`        // per hour
	RateLimitDownload      int      `json:"rate_limit_download"`      // per hour
	BlockedExtensions      []string `json:"blocked_extensions"`       // list of extensions

	// Performance settings (require restart)
	ChunkSize                int64 `json:"chunk_size"`                  // bytes
	ReadTimeout              int   `json:"read_timeout"`                // seconds
	WriteTimeout             int   `json:"write_timeout"`               // seconds
	ChunkedUploadThreshold   int64 `json:"chunked_upload_threshold"`    // bytes
	PartialUploadExpiryHours int   `json:"partial_upload_expiry_hours"` // hours

	// Operational settings (require restart)
	SessionExpiryHours     int    `json:"session_expiry_hours"`     // hours
	CleanupIntervalMinutes int    `json:"cleanup_interval_minutes"` // minutes
	RequireAuthForUpload   bool   `json:"require_auth_for_upload"`  // boolean
	HTTPSEnabled           bool   `json:"https_enabled"`            // boolean
	ChunkedUploadEnabled   bool   `json:"chunked_upload_enabled"`   // boolean
	PublicURL              string `json:"public_url"`               // URL string
}

// ConfigAssistantResponse represents the full response with analysis
type ConfigAssistantResponse struct {
	Recommendations ConfigRecommendations `json:"recommendations"`
	CurrentConfig   ConfigRecommendations `json:"current_config"`
	Analysis        ConfigAnalysis        `json:"analysis"`
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
		// Limit JSON request body size to prevent memory exhaustion
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

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

	// Convert Mbps to MBps (megabytes per second) for calculations
	uploadSpeedMBps := req.UploadSpeed / 8.0
	downloadSpeedMBps := req.DownloadSpeed / 8.0

	// Calculate each configuration category using helper functions
	rec.MaxFileSize = calculateMaxFileSize(req)
	rec.QuotaLimitGB = calculateStorageQuota(req)
	rec.DefaultExpirationHours, rec.MaxExpirationHours = calculateExpirationTimes(req)
	rec.RateLimitUpload, rec.RateLimitDownload = calculateRateLimits(req, uploadSpeedMBps, downloadSpeedMBps)
	rec.ChunkSize = calculateChunkSize(req, uploadSpeedMBps)

	// Apply CDN constraints to chunk size if needed (must be done before timeout calculation)
	rec.ChunkSize = applyCDNConstraints(req, uploadSpeedMBps, rec.ChunkSize)

	rec.ReadTimeout, rec.WriteTimeout = calculateTimeouts(req, uploadSpeedMBps, rec.ChunkSize)
	rec.ChunkedUploadThreshold, rec.PartialUploadExpiryHours = calculateChunkedUploadSettings(req, uploadSpeedMBps)
	rec.SessionExpiryHours, rec.CleanupIntervalMinutes = calculateOperationalSettings(req)
	rec.RequireAuthForUpload, rec.HTTPSEnabled, rec.PublicURL = calculateSecuritySettings(req)

	return rec
}

// calculateMaxFileSize determines the maximum file size based on typical usage patterns
func calculateMaxFileSize(req ConfigAssistantRequest) int64 {
	switch req.TypicalFileSize {
	case "small":
		return 100 * 1024 * 1024 // 100MB
	case "medium":
		return 1 * 1024 * 1024 * 1024 // 1GB
	case "large":
		return 5 * 1024 * 1024 * 1024 // 5GB
	case "huge":
		return 10 * 1024 * 1024 * 1024 // 10GB
	default:
		return 100 * 1024 * 1024 // default 100MB
	}
}

// calculateStorageQuota determines the storage quota based on available capacity
func calculateStorageQuota(req ConfigAssistantRequest) int64 {
	if req.StorageCapacity <= 0 {
		return 0 // unlimited
	}

	// Use 80% of available capacity as quota to leave headroom
	quota := int64(float64(req.StorageCapacity) * 0.8)
	if quota < 10 {
		return req.StorageCapacity // use full capacity if < 10GB
	}
	return quota
}

// calculateExpirationTimes determines default and maximum expiration hours based on deployment type
func calculateExpirationTimes(req ConfigAssistantRequest) (defaultHours int, maxHours int) {
	switch req.DeploymentType {
	case "LAN":
		// LAN deployments typically have shorter retention needs
		return 24, 168 // 1 day, 7 days
	case "WAN":
		// WAN deployments need moderate retention
		return 72, 336 // 3 days, 14 days
	case "Internet":
		// Internet deployments benefit from longer retention
		return 168, 720 // 7 days, 30 days
	default:
		return 24, 168
	}
}

// calculateRateLimits determines upload and download rate limits based on load and bandwidth
func calculateRateLimits(req ConfigAssistantRequest, uploadSpeedMBps, downloadSpeedMBps float64) (uploadLimit int, downloadLimit int) {
	// Base limits on user load
	switch req.UserLoad {
	case "light":
		uploadLimit, downloadLimit = 20, 200 // 1-10 users: generous limits
	case "moderate":
		uploadLimit, downloadLimit = 15, 150 // 10-50 users: balanced limits
	case "heavy":
		uploadLimit, downloadLimit = 10, 100 // 50-200 users: conservative limits
	case "very_heavy":
		uploadLimit, downloadLimit = 5, 50 // > 200 users: strict limits
	default:
		uploadLimit, downloadLimit = 10, 100
	}

	// Adjust upload limits based on bandwidth
	if uploadSpeedMBps < 5 {
		// Low bandwidth: reduce limits further
		uploadLimit = uploadLimit / 2
		if uploadLimit < 3 {
			uploadLimit = 3 // minimum
		}
	} else if uploadSpeedMBps > 50 {
		// High bandwidth: can afford higher limits for light/moderate loads
		if req.UserLoad == "light" || req.UserLoad == "moderate" {
			uploadLimit = int(float64(uploadLimit) * 1.5)
		}
	}

	// Adjust download limits based on bandwidth
	if downloadSpeedMBps < 10 {
		downloadLimit = downloadLimit / 2
		if downloadLimit < 20 {
			downloadLimit = 20 // minimum
		}
	} else if downloadSpeedMBps > 100 {
		if req.UserLoad == "light" || req.UserLoad == "moderate" {
			downloadLimit = int(float64(downloadLimit) * 1.5)
		}
	}

	return uploadLimit, downloadLimit
}

// calculateChunkSize determines optimal chunk size based on bandwidth and latency
// Range: 5MB - 30MB (within documented 1-50MB limit)
func calculateChunkSize(req ConfigAssistantRequest, uploadSpeedMBps float64) int64 {
	var chunkSize int64

	// Smaller chunks for slow/unreliable connections provide better resume capability
	// Larger chunks for fast connections reduce overhead
	if req.NetworkLatency == "high" || uploadSpeedMBps < 2 {
		chunkSize = 5 * 1024 * 1024 // 5MB - high latency or slow connection
	} else if uploadSpeedMBps < 5 {
		chunkSize = 8 * 1024 * 1024 // 8MB - medium-slow connection
	} else if uploadSpeedMBps < 15 {
		chunkSize = 10 * 1024 * 1024 // 10MB - medium connection (default)
	} else if uploadSpeedMBps < 30 {
		chunkSize = 20 * 1024 * 1024 // 20MB - fast connection
	} else {
		chunkSize = 30 * 1024 * 1024 // 30MB - very fast connection
	}

	// Adjust for large files - smaller chunks for better progress reporting
	if req.TypicalFileSize == "huge" && chunkSize > 10*1024*1024 {
		chunkSize = 10 * 1024 * 1024 // cap at 10MB for huge files
	}

	return chunkSize
}

// applyCDNConstraints adjusts chunk size to fit within CDN timeout limits
func applyCDNConstraints(req ConfigAssistantRequest, uploadSpeedMBps float64, chunkSize int64) int64 {
	if !req.UsingCDN || req.CDNTimeout <= 0 {
		return chunkSize // no CDN or no timeout constraint
	}

	// Formula: ChunkSize <= (UploadSpeed * CDNTimeout * 0.6) to ensure completion
	maxSafeChunkSize := int64(uploadSpeedMBps * float64(req.CDNTimeout) * 0.6 * 1024 * 1024)
	if maxSafeChunkSize < 5*1024*1024 {
		maxSafeChunkSize = 5 * 1024 * 1024 // minimum 5MB
	}

	if chunkSize > maxSafeChunkSize {
		return maxSafeChunkSize
	}
	return chunkSize
}

// calculateTimeouts determines read and write timeouts with CDN and encryption considerations
func calculateTimeouts(req ConfigAssistantRequest, uploadSpeedMBps float64, chunkSize int64) (readTimeout int, writeTimeout int) {
	// Formula: (ChunkSize in MB / UploadSpeed in MBps) × SafetyFactor
	chunkSizeMB := float64(chunkSize) / (1024 * 1024)
	baseTimeout := int((chunkSizeMB / uploadSpeedMBps) * 3.0) // 3x safety factor

	// Ensure minimum timeout
	if baseTimeout < 60 {
		baseTimeout = 60
	}

	// Add extra time for high latency or slow connections
	switch req.NetworkLatency {
	case "high":
		readTimeout = baseTimeout * 2
		writeTimeout = baseTimeout * 2
	case "medium":
		readTimeout = int(float64(baseTimeout) * 1.5)
		writeTimeout = int(float64(baseTimeout) * 1.5)
	default:
		readTimeout = baseTimeout
		writeTimeout = baseTimeout
	}

	// Apply timeout caps and minimums
	readTimeout = applyTimeoutBounds(readTimeout, 60, 600)
	writeTimeout = applyTimeoutBounds(writeTimeout, 60, 600)

	// Apply CDN timeout constraints if behind a CDN
	if req.UsingCDN && req.CDNTimeout > 0 {
		maxAllowedTimeout := int(float64(req.CDNTimeout) * 0.8) // 80% for safety margin
		readTimeout = min(readTimeout, maxAllowedTimeout)
		writeTimeout = min(writeTimeout, maxAllowedTimeout)
	}

	// Apply encryption overhead if encryption is enabled
	if req.EncryptionEnabled {
		// Add 20% overhead for encryption/decryption processing
		readTimeout = applyTimeoutBounds(int(float64(readTimeout)*1.2), 60, 600)
		writeTimeout = applyTimeoutBounds(int(float64(writeTimeout)*1.2), 60, 600)
	}

	return readTimeout, writeTimeout
}

// applyTimeoutBounds ensures timeout is within specified min/max range
func applyTimeoutBounds(timeout, minTimeout, maxTimeout int) int {
	if timeout < minTimeout {
		return minTimeout
	}
	if timeout > maxTimeout {
		return maxTimeout
	}
	return timeout
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// calculateChunkedUploadSettings determines chunked upload threshold and partial expiry hours
func calculateChunkedUploadSettings(req ConfigAssistantRequest, uploadSpeedMBps float64) (threshold int64, expiryHours int) {
	// Lower threshold = more files use chunked upload = better reliability
	// Higher threshold = fewer files use chunking = less overhead
	if req.TypicalFileSize == "huge" || uploadSpeedMBps < 5 {
		threshold = 50 * 1024 * 1024 // 50MB - start chunking early for reliability
	} else if req.TypicalFileSize == "large" {
		threshold = 75 * 1024 * 1024 // 75MB - balanced threshold
	} else {
		threshold = 100 * 1024 * 1024 // 100MB - default, minimal overhead
	}

	// Give more time for slow connections with large files
	if (req.TypicalFileSize == "large" || req.TypicalFileSize == "huge") && uploadSpeedMBps < 2 {
		expiryHours = 72 // 3 days for very slow large uploads
	} else if uploadSpeedMBps < 5 {
		expiryHours = 48 // 2 days for slow connections
	} else {
		expiryHours = 24 // 1 day (default)
	}

	return threshold, expiryHours
}

// calculateOperationalSettings determines session expiry and cleanup interval
func calculateOperationalSettings(req ConfigAssistantRequest) (sessionExpiryHours int, cleanupIntervalMinutes int) {
	// Session expiry based on deployment type
	switch req.DeploymentType {
	case "LAN":
		sessionExpiryHours = 12 // shorter for internal networks
	case "WAN":
		sessionExpiryHours = 24 // standard
	case "Internet":
		sessionExpiryHours = 48 // longer for external users
	default:
		sessionExpiryHours = 24
	}

	// Cleanup interval based on storage and load
	if req.StorageCapacity > 0 && req.StorageCapacity < 50 {
		cleanupIntervalMinutes = 30 // limited storage: cleanup more frequently
	} else if req.UserLoad == "heavy" || req.UserLoad == "very_heavy" {
		cleanupIntervalMinutes = 45 // high traffic: cleanup more frequently
	} else {
		cleanupIntervalMinutes = 60 // default
	}

	return sessionExpiryHours, cleanupIntervalMinutes
}

// calculateSecuritySettings determines authentication, HTTPS, and public URL requirements
func calculateSecuritySettings(req ConfigAssistantRequest) (requireAuth bool, httpsEnabled bool, publicURL string) {
	// Require authentication for public internet deployments with significant load
	if req.DeploymentType == "Internet" && (req.UserLoad == "heavy" || req.UserLoad == "very_heavy") {
		requireAuth = true // prevent abuse on public internet
	} else if req.DeploymentType == "Internet" && req.UserLoad == "moderate" {
		requireAuth = true // recommended for public internet
	} else {
		requireAuth = false // allow anonymous for internal/light use
	}

	// HTTPS recommendation based on deployment type
	if req.DeploymentType == "Internet" || req.DeploymentType == "WAN" {
		httpsEnabled = true // always for public internet, recommended for WAN
	} else {
		httpsEnabled = false // optional for LAN
	}

	// Public URL should be set manually by admin for Internet/WAN
	publicURL = "" // Empty means auto-detect from request

	return requireAuth, httpsEnabled, publicURL
}

// generateAnalysis creates human-readable analysis and recommendations
func generateAnalysis(req ConfigAssistantRequest, current, recommended ConfigRecommendations) ConfigAnalysis {
	analysis := ConfigAnalysis{
		Impacts:                   make(map[string]string),
		AdditionalRecommendations: []string{},
	}

	// Generate summary
	analysis.Summary = generateAnalysisSummary(req)

	// Generate impact descriptions for configuration changes
	generateImpactDescriptions(req, current, recommended, &analysis)

	// Generate additional recommendations based on environment
	generateNetworkRecommendations(req, recommended, &analysis)
	generateFileRecommendations(req, recommended, &analysis)
	generateDeploymentRecommendations(req, recommended, &analysis)
	generateCDNRecommendations(req, recommended, &analysis)
	generateResourceRecommendations(req, &analysis)

	return analysis
}

// generateAnalysisSummary creates a summary description of the optimization
func generateAnalysisSummary(req ConfigAssistantRequest) string {
	latencyDesc := map[string]string{
		"local":  "local network",
		"low":    "low-latency",
		"medium": "medium-latency",
		"high":   "high-latency",
	}[req.NetworkLatency]

	return fmt.Sprintf(
		"Optimized for %s deployment with %s connectivity, %s file sizes, and %s user load.",
		req.DeploymentType,
		latencyDesc,
		req.TypicalFileSize,
		req.UserLoad,
	)
}

// generateImpactDescriptions explains the impacts of each configuration change
func generateImpactDescriptions(req ConfigAssistantRequest, current, recommended ConfigRecommendations, analysis *ConfigAnalysis) {
	// File size and storage impacts
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

	// Expiration impacts
	if current.DefaultExpirationHours != recommended.DefaultExpirationHours {
		analysis.Impacts["default_expiration_hours"] = fmt.Sprintf("Adjusted for %s deployment pattern", req.DeploymentType)
	}

	if current.MaxExpirationHours != recommended.MaxExpirationHours {
		analysis.Impacts["max_expiration_hours"] = fmt.Sprintf("Extended for %s use case", req.DeploymentType)
	}

	// Rate limit impacts
	if current.RateLimitUpload != recommended.RateLimitUpload {
		analysis.Impacts["rate_limit_upload"] = fmt.Sprintf("Balanced for %s user load and %.1f Mbps upload speed", req.UserLoad, req.UploadSpeed)
	}

	if current.RateLimitDownload != recommended.RateLimitDownload {
		analysis.Impacts["rate_limit_download"] = fmt.Sprintf("Optimized for %s user load and %.1f Mbps download speed", req.UserLoad, req.DownloadSpeed)
	}

	// Performance settings impacts
	generatePerformanceImpacts(req, current, recommended, analysis)

	// Operational settings impacts
	generateOperationalImpacts(req, current, recommended, analysis)
}

// generatePerformanceImpacts explains changes to performance-related settings
func generatePerformanceImpacts(req ConfigAssistantRequest, current, recommended ConfigRecommendations, analysis *ConfigAnalysis) {
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
}

// generateOperationalImpacts explains changes to operational settings
func generateOperationalImpacts(req ConfigAssistantRequest, current, recommended ConfigRecommendations, analysis *ConfigAnalysis) {
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
}

// generateNetworkRecommendations adds recommendations based on network conditions
func generateNetworkRecommendations(req ConfigAssistantRequest, recommended ConfigRecommendations, analysis *ConfigAnalysis) {
	if req.NetworkLatency == "high" || req.NetworkLatency == "medium" {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			"Consider enabling TCP tuning for high-latency connections. See docs/TCP_TUNING.md for system-level optimizations.",
		)
	}

	uploadSpeedMBps := req.UploadSpeed / 8
	if uploadSpeedMBps < 5 {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			fmt.Sprintf("Low upload bandwidth detected (%.1f MB/s). Consider CHUNK_SIZE=5MB for better reliability on slow connections.", uploadSpeedMBps),
		)
	}
}

// generateFileRecommendations adds recommendations for file size handling
func generateFileRecommendations(req ConfigAssistantRequest, recommended ConfigRecommendations, analysis *ConfigAnalysis) {
	if req.TypicalFileSize == "large" || req.TypicalFileSize == "huge" {
		chunkSizeMB := float64(recommended.ChunkSize) / (1024 * 1024)
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			fmt.Sprintf("For large files: CHUNK_SIZE=%.0fMB, READ_TIMEOUT=%ds, WRITE_TIMEOUT=%ds are calculated for your connection speed.", chunkSizeMB, recommended.ReadTimeout, recommended.WriteTimeout),
		)
	}
}

// generateDeploymentRecommendations adds recommendations based on deployment type
func generateDeploymentRecommendations(req ConfigAssistantRequest, recommended ConfigRecommendations, analysis *ConfigAnalysis) {
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
}

// generateCDNRecommendations adds CDN-specific recommendations
func generateCDNRecommendations(req ConfigAssistantRequest, recommended ConfigRecommendations, analysis *ConfigAnalysis) {
	if !req.UsingCDN {
		return
	}

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

// generateResourceRecommendations adds recommendations for storage, load, and encryption
func generateResourceRecommendations(req ConfigAssistantRequest, analysis *ConfigAnalysis) {
	if req.EncryptionEnabled {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			"Encryption enabled: Timeouts increased by 20%% to account for AES-256-GCM encryption/decryption overhead.",
		)
	}

	if req.UserLoad == "heavy" || req.UserLoad == "very_heavy" {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			"High user load detected. Monitor storage usage and consider implementing user quotas for fair resource allocation.",
		)
	}

	if req.StorageCapacity > 0 && req.StorageCapacity < 50 {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			fmt.Sprintf("Limited storage capacity (%d GB). Consider implementing aggressive file expiration policies or increasing storage.", req.StorageCapacity),
		)
	}
}
