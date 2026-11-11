package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/fjmerc/safeshare/internal/config"
)

// ConfigAssistantRequest represents the admin's description of their
// environment. Facts the server already knows (anonymous mode, client-side
// encryption, malware scanning) are read from the configuration instead of
// being asked.
type ConfigAssistantRequest struct {
	UploadSpeed     float64 `json:"upload_speed"`      // Mbps
	DownloadSpeed   float64 `json:"download_speed"`    // Mbps
	NetworkLatency  string  `json:"network_latency"`   // local, low, medium, high
	TypicalFileSize string  `json:"typical_file_size"` // small, medium, large, huge
	DeploymentType  string  `json:"deployment_type"`   // LAN, WAN, Internet
	UserLoad        string  `json:"user_load"`         // light, moderate, heavy, very_heavy
	StorageCapacity int64   `json:"storage_capacity"`  // GB (0 = unlimited)
	UsingCDN        bool    `json:"using_cdn"`         // Behind a CDN?
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

// assistantServerFacts is what the server already knows about itself that
// shapes the recommendations.
type assistantServerFacts struct {
	anonymous         bool  // ANONYMOUS_MODE (Ghost)
	clientEncryption  bool  // REQUIRE_CLIENT_ENCRYPTION: every upload is encrypted in the browser
	malwareScan       bool  // malware scanning enabled
	rejectUnscannable bool  // MALWARE_SCAN_REJECT_UNSCANNABLE
	scanMaxFileSize   int64 // CLAMAV_MAX_FILE_SIZE (0 = no limit)
}

// Service-wide rate limits suggested for anonymous mode behind Tor, where
// every visitor shares one address and so one budget (docs/TOR_DEPLOYMENT.md).
const (
	anonymousModeMinRateLimitUpload   = 100
	anonymousModeMinRateLimitDownload = 500
)

// browserEncryptionWarnBytes is where the upload page warns that encrypting
// a file in the browser may exhaust the tab's memory.
const browserEncryptionWarnBytes = 500 * 1024 * 1024

func serverFactsFromConfig(cfg *config.Config) assistantServerFacts {
	facts := assistantServerFacts{
		anonymous:        cfg.IsAnonymousMode(),
		clientEncryption: cfg.IsClientEncryptionRequired(),
	}
	if cfg.Features != nil {
		facts.malwareScan = cfg.Features.IsMalwareScanEnabled()
	}
	if cfg.ClamAV != nil {
		facts.rejectUnscannable = cfg.ClamAV.RejectUnscannable
		facts.scanMaxFileSize = cfg.ClamAV.MaxFileSize
	}
	return facts
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
		// Beyond the largest quota the server accepts, the GB arithmetic
		// below would overflow.
		if req.StorageCapacity < 0 || req.StorageCapacity > config.MaxQuotaLimitGB {
			http.Error(w, "Invalid storage capacity", http.StatusBadRequest)
			return
		}

		currentConfig := ConfigRecommendations{
			// Immediate settings
			MaxFileSize:            cfg.GetMaxFileSize(),
			QuotaLimitGB:           cfg.GetQuotaLimitGB(),
			DefaultExpirationHours: cfg.GetDefaultExpirationHours(),
			MaxExpirationHours:     cfg.GetMaxExpirationHours(),
			RateLimitUpload:        cfg.GetRateLimitUpload(),
			RateLimitDownload:      cfg.GetRateLimitDownload(),
			BlockedExtensions:      cfg.GetBlockedExtensions(),

			// Performance settings (from environment, need a restart)
			ChunkedUploadThreshold:   cfg.ChunkedUploadThreshold,
			PartialUploadExpiryHours: cfg.PartialUploadExpiryHours,

			// Operational settings (from environment, need a restart)
			SessionExpiryHours:     cfg.SessionExpiryHours,
			CleanupIntervalMinutes: cfg.CleanupIntervalMinutes,
			RequireAuthForUpload:   cfg.RequireAuthForUpload,
			HTTPSEnabled:           cfg.HTTPSEnabled,
			ChunkedUploadEnabled:   cfg.ChunkedUploadEnabled,
			PublicURL:              cfg.PublicURL,
		}
		facts := serverFactsFromConfig(cfg)

		recommendations := calculateRecommendations(req)
		notes, impacts := applyServerConstraints(&recommendations, currentConfig, facts)

		analysis := generateAnalysis(req, currentConfig, recommendations)
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations, notes...)
		// A value set by one of this server's rules gets that rule as its
		// explanation, not the generic one for the environment.
		for key, impact := range impacts {
			analysis.Impacts[key] = impact
		}

		response := ConfigAssistantResponse{
			Recommendations: recommendations,
			CurrentConfig:   currentConfig,
			Analysis:        analysis,
		}

		slog.Info("configuration assistant analysis completed",
			"admin_ip", logIP(getClientIP(r), cfg),
			"deployment_type", req.DeploymentType,
			"user_load", req.UserLoad,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// applyServerConstraints adjusts environment-based recommendations to what
// this server's own configuration requires. It returns notes explaining the
// adjustments, and an explanation for each recommendation it changed (keyed
// like ConfigAnalysis.Impacts) to use instead of the generic one.
func applyServerConstraints(rec *ConfigRecommendations, current ConfigRecommendations, facts assistantServerFacts) (notes []string, impacts map[string]string) {
	impacts = make(map[string]string)

	// Never drop extensions the admin already blocks: applying the
	// recommendations replaces the whole list.
	rec.BlockedExtensions = mergeBlockedExtensions(current.BlockedExtensions, rec.BlockedExtensions)

	if facts.anonymous {
		// Short retention is part of what protects uploaders.
		if current.DefaultExpirationHours > 0 && current.MaxExpirationHours > 0 {
			capped := capExpirationsForAnonymousMode(rec, current)
			notes = append(notes, anonymousModeExpirationNote(current, capped))
			if capped {
				impacts["default_expiration_hours"] = "Kept at or below your current value: anonymous mode relies on short retention"
				impacts["max_expiration_hours"] = "Kept at or below your current value: anonymous mode relies on short retention"
			}
		}

		// Behind Tor every visitor shares one address, so the per-address
		// limits are the whole service's budget. Never recommend lowering
		// them, and never below the documented service-wide starting point.
		upload := max(rec.RateLimitUpload, current.RateLimitUpload, anonymousModeMinRateLimitUpload)
		download := max(rec.RateLimitDownload, current.RateLimitDownload, anonymousModeMinRateLimitDownload)
		if upload != rec.RateLimitUpload || download != rec.RateLimitDownload {
			rec.RateLimitUpload, rec.RateLimitDownload = upload, download
			impacts["rate_limit_upload"] = "One budget for the whole service: every Tor visitor shares one address"
			impacts["rate_limit_download"] = "One budget for the whole service: every Tor visitor shares one address"
			notes = append(notes, fmt.Sprintf(
				"Anonymous (Ghost) mode: every Tor visitor shares one address, so rate limits are one budget for the whole service. Recommended %d uploads and %d downloads an hour (never lower than your current limits).",
				upload, download))
		}

		// Requiring accounts contradicts anonymous mode.
		if rec.RequireAuthForUpload {
			rec.RequireAuthForUpload = false
			impacts["require_auth_for_upload"] = "Off in anonymous mode: accounts would identify uploaders"
			notes = append(notes, "Anonymous (Ghost) mode: uploads are not set to require login, because accounts would identify uploaders.")
		}

		// Onion services are reached over http:// (Tor encrypts the
		// connection), so secure-only cookies would break admin login.
		if rec.HTTPSEnabled != current.HTTPSEnabled {
			rec.HTTPSEnabled = current.HTTPSEnabled
			impacts["https_enabled"] = "Left as it is: onion addresses use http:// (Tor encrypts the connection)"
			notes = append(notes, "Anonymous (Ghost) mode: HTTPS_ENABLED is left as it is. Onion addresses use http:// because Tor already encrypts the connection, and HTTPS_ENABLED=true would make login cookies secure-only.")
		}
	}

	// A file the malware scanner can't scan is refused outright when
	// MALWARE_SCAN_REJECT_UNSCANNABLE is on; same test as the upload handlers.
	switch {
	case facts.malwareScan && facts.rejectUnscannable && facts.clientEncryption:
		notes = append(notes, "Malware scanning rejects files it can't scan, and this server requires browser encryption, which makes every upload unscannable. Uploads will be refused until one of the two is turned off.")
	case facts.malwareScan && facts.rejectUnscannable:
		if facts.scanMaxFileSize > 0 && rec.MaxFileSize > facts.scanMaxFileSize {
			rec.MaxFileSize = facts.scanMaxFileSize
			impacts["max_file_size"] = "Limited to the largest file the malware scanner accepts (CLAMAV_MAX_FILE_SIZE)"
			notes = append(notes, fmt.Sprintf(
				"Max file size limited to %s: malware scanning rejects files larger than the scanner accepts (CLAMAV_MAX_FILE_SIZE).",
				formatSizeForNote(facts.scanMaxFileSize)))
		}
	case facts.malwareScan && facts.clientEncryption:
		notes = append(notes, "Uploads are encrypted in the browser, so the malware scanner can't read them: they are stored unscanned.")
	case facts.malwareScan && facts.scanMaxFileSize > 0 && rec.MaxFileSize > facts.scanMaxFileSize:
		notes = append(notes, fmt.Sprintf(
			"Files larger than %s (CLAMAV_MAX_FILE_SIZE) are stored without a malware scan.",
			formatSizeForNote(facts.scanMaxFileSize)))
	}

	// A single file can't be bigger than all the storage allowed.
	if rec.QuotaLimitGB > 0 {
		quotaBytes := rec.QuotaLimitGB * 1024 * 1024 * 1024
		if rec.MaxFileSize > quotaBytes {
			rec.MaxFileSize = quotaBytes
			impacts["max_file_size"] = "Limited to the recommended storage quota: one file can't be bigger than all the storage"
			notes = append(notes, fmt.Sprintf("Max file size limited to the recommended storage quota (%d GB).", rec.QuotaLimitGB))
		}
	}

	if facts.clientEncryption && rec.MaxFileSize > browserEncryptionWarnBytes {
		notes = append(notes, "Uploads are encrypted in the visitor's browser, which holds the file in memory: the upload page warns above 500 MB, and very large files can exhaust a browser tab. Padding also adds up to about 12% to the stored size.")
	}

	return notes, impacts
}

// formatSizeForNote renders a byte count for an analysis note.
func formatSizeForNote(b int64) string {
	const (
		mib = 1024 * 1024
		gib = 1024 * mib
	)
	if b >= gib && b%gib == 0 {
		return fmt.Sprintf("%d GB", b/gib)
	}
	return fmt.Sprintf("%d MB", b/mib)
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

	rec.MaxFileSize = calculateMaxFileSize(req)
	rec.QuotaLimitGB = calculateStorageQuota(req)
	rec.DefaultExpirationHours, rec.MaxExpirationHours = calculateExpirationTimes(req)
	rec.RateLimitUpload, rec.RateLimitDownload = calculateRateLimits(req, uploadSpeedMBps, downloadSpeedMBps)
	rec.ChunkedUploadThreshold, rec.PartialUploadExpiryHours = calculateChunkedUploadSettings(req, uploadSpeedMBps)
	rec.SessionExpiryHours, rec.CleanupIntervalMinutes = calculateOperationalSettings(req)
	rec.RequireAuthForUpload, rec.HTTPSEnabled, rec.PublicURL = calculateSecuritySettings(req)

	return rec
}

// mergeBlockedExtensions returns the current blocked extensions followed by any
// recommended ones that aren't already blocked (case-insensitive, dot optional).
func mergeBlockedExtensions(current, recommended []string) []string {
	merged := make([]string, 0, len(current)+len(recommended))
	seen := make(map[string]bool, len(current)+len(recommended))
	for _, list := range [][]string{current, recommended} {
		for _, ext := range list {
			key := strings.ToLower(strings.TrimSpace(ext))
			if key == "" {
				continue
			}
			if !strings.HasPrefix(key, ".") {
				key = "." + key
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			merged = append(merged, key)
		}
	}
	return merged
}

// capExpirationsForAnonymousMode keeps the recommended expirations at or below
// the current ones. It reports whether it lowered either value. The result
// still satisfies default <= max because both inputs do.
func capExpirationsForAnonymousMode(rec *ConfigRecommendations, current ConfigRecommendations) bool {
	if current.DefaultExpirationHours <= 0 || current.MaxExpirationHours <= 0 {
		return false
	}
	capped := false
	if rec.DefaultExpirationHours > current.DefaultExpirationHours {
		rec.DefaultExpirationHours = current.DefaultExpirationHours
		capped = true
	}
	if rec.MaxExpirationHours > current.MaxExpirationHours {
		rec.MaxExpirationHours = current.MaxExpirationHours
		capped = true
	}
	return capped
}

// anonymousModeExpirationNote explains how anonymous mode shaped the
// expiration recommendations.
func anonymousModeExpirationNote(current ConfigRecommendations, capped bool) string {
	if capped {
		return fmt.Sprintf("⚠️ Anonymous (Ghost) mode is on: expiration recommendations were kept at your current limits (default %dh, max %dh) instead of being raised. Short retention is part of what protects uploaders; raise them only if you mean to.",
			current.DefaultExpirationHours, current.MaxExpirationHours)
	}
	return "Anonymous (Ghost) mode is on: these expiration recommendations don't raise your current limits."
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

// storageQuotaPercent is the share of the available storage recommended as
// the quota, leaving headroom for partial uploads and the database.
const storageQuotaPercent = 75

// calculateStorageQuota determines the storage quota based on available capacity
func calculateStorageQuota(req ConfigAssistantRequest) int64 {
	if req.StorageCapacity <= 0 {
		return 0 // unlimited
	}

	quota := req.StorageCapacity * storageQuotaPercent / 100
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

// calculateRateLimits determines upload and download rate limits based on load and bandwidth.
// Each permitted upload may be MAX_FILE_SIZE: the server sizes the chunk
// allowance from both settings, so large files don't need a higher upload limit.
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
	// Login sessions: shorter the more exposed the server is. A stolen
	// session cookie is worth less when it expires sooner. (The Hardened and
	// Fortress profiles in docs/DEPLOYMENT_MODES.md use 8 and 4 hours.)
	switch req.DeploymentType {
	case "LAN":
		sessionExpiryHours = 24
	case "WAN":
		sessionExpiryHours = 12
	case "Internet":
		sessionExpiryHours = 8
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

	analysis.Summary = generateAnalysisSummary(req)
	generateImpactDescriptions(req, current, recommended, &analysis)
	generateNetworkRecommendations(req, &analysis)
	generateDeploymentRecommendations(req, recommended, &analysis)
	generateCDNRecommendations(req, &analysis)
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
			analysis.Impacts["quota_limit_gb"] = fmt.Sprintf("Set to %d%% of available capacity (%d GB)", storageQuotaPercent, req.StorageCapacity)
		} else {
			analysis.Impacts["quota_limit_gb"] = "Unlimited storage recommended based on your capacity"
		}
	}

	// Expiration impacts
	if current.DefaultExpirationHours != recommended.DefaultExpirationHours {
		analysis.Impacts["default_expiration_hours"] = fmt.Sprintf("Adjusted for %s deployment pattern", req.DeploymentType)
	}

	if current.MaxExpirationHours != recommended.MaxExpirationHours {
		analysis.Impacts["max_expiration_hours"] = fmt.Sprintf("Adjusted for %s use case", req.DeploymentType)
	}

	// Rate limit impacts
	if current.RateLimitUpload != recommended.RateLimitUpload {
		analysis.Impacts["rate_limit_upload"] = fmt.Sprintf("Balanced for %s user load and %.1f Mbps upload speed", req.UserLoad, req.UploadSpeed)
	}

	if current.RateLimitDownload != recommended.RateLimitDownload {
		analysis.Impacts["rate_limit_download"] = fmt.Sprintf("Optimized for %s user load and %.1f Mbps download speed", req.UserLoad, req.DownloadSpeed)
	}

	generatePerformanceImpacts(req, current, recommended, analysis)
	generateOperationalImpacts(req, current, recommended, analysis)
}

// generatePerformanceImpacts explains changes to performance-related settings
func generatePerformanceImpacts(req ConfigAssistantRequest, current, recommended ConfigRecommendations, analysis *ConfigAnalysis) {
	if current.ChunkedUploadThreshold != recommended.ChunkedUploadThreshold {
		thresholdMB := recommended.ChunkedUploadThreshold / (1024 * 1024)
		analysis.Impacts["chunked_upload_threshold"] = fmt.Sprintf("Set to %dMB for optimal reliability with %s files", thresholdMB, req.TypicalFileSize)
	}

	if current.PartialUploadExpiryHours != recommended.PartialUploadExpiryHours {
		analysis.Impacts["partial_upload_expiry_hours"] = fmt.Sprintf("Set to %d hours so slower connections can finish large uploads", recommended.PartialUploadExpiryHours)
	}
}

// generateOperationalImpacts explains changes to operational settings
func generateOperationalImpacts(req ConfigAssistantRequest, current, recommended ConfigRecommendations, analysis *ConfigAnalysis) {
	if current.SessionExpiryHours != recommended.SessionExpiryHours {
		analysis.Impacts["session_expiry_hours"] = fmt.Sprintf("%d hours: shorter sessions limit the damage of a stolen login on a %s deployment", recommended.SessionExpiryHours, req.DeploymentType)
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
func generateNetworkRecommendations(req ConfigAssistantRequest, analysis *ConfigAnalysis) {
	if req.NetworkLatency == "high" || req.NetworkLatency == "medium" {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			"Consider enabling TCP tuning for high-latency connections. See docs/TCP_TUNING.md for system-level optimizations.",
		)
	}
}

// generateDeploymentRecommendations adds recommendations based on deployment type
func generateDeploymentRecommendations(req ConfigAssistantRequest, recommended ConfigRecommendations, analysis *ConfigAnalysis) {
	if req.DeploymentType == "Internet" {
		// The server extends each transfer's deadline with its size (up to 6
		// hours), so the proxy in front must not cut long transfers short.
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			"Reverse proxy: allow long-running requests. SafeShare gives each upload and download time in proportion to its size, up to 6 hours for a single-request transfer, so a proxy timeout shorter than a large transfer cuts it off. See docs/REVERSE_PROXY.md.",
		)
		if recommended.HTTPSEnabled {
			analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
				"Enable HTTPS_ENABLED=true and set PUBLIC_URL to your public domain for correct link generation.",
			)
		}
	}
}

// generateCDNRecommendations adds CDN-specific recommendations
func generateCDNRecommendations(req ConfigAssistantRequest, analysis *ConfigAnalysis) {
	if !req.UsingCDN {
		return
	}
	analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
		"CDN detected: CDNs can cut off long-running requests (Cloudflare's free plan gives the server 100 seconds to respond). Set DOWNLOAD_URL to a DNS-only subdomain that bypasses the CDN for large downloads. Example: downloads.yourdomain.com",
	)
}

// generateResourceRecommendations adds recommendations for storage and load
func generateResourceRecommendations(req ConfigAssistantRequest, analysis *ConfigAnalysis) {
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
