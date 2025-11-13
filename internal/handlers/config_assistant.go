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
	UploadSpeed     float64 `json:"upload_speed"`      // Mbps
	DownloadSpeed   float64 `json:"download_speed"`    // Mbps
	NetworkLatency  string  `json:"network_latency"`   // local, low, medium, high
	TypicalFileSize string  `json:"typical_file_size"` // small, medium, large, huge
	DeploymentType  string  `json:"deployment_type"`   // lan, wan, internet
	UserLoad        string  `json:"user_load"`         // light, moderate, heavy, very_heavy
	StorageCapacity int64   `json:"storage_capacity"`  // GB (0 = unlimited)
}

// ConfigRecommendations represents the recommended configuration
type ConfigRecommendations struct {
	MaxFileSize             int64    `json:"max_file_size"`              // bytes
	QuotaLimitGB            int64    `json:"quota_limit_gb"`             // GB
	DefaultExpirationHours  int      `json:"default_expiration_hours"`   // hours
	MaxExpirationHours      int      `json:"max_expiration_hours"`       // hours
	RateLimitUpload         int      `json:"rate_limit_upload"`          // per hour
	RateLimitDownload       int      `json:"rate_limit_download"`        // per hour
	BlockedExtensions       []string `json:"blocked_extensions"`         // list of extensions
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
			MaxFileSize:            cfg.GetMaxFileSize(),
			QuotaLimitGB:           cfg.GetQuotaLimitGB(),
			DefaultExpirationHours: cfg.GetDefaultExpirationHours(),
			MaxExpirationHours:     cfg.GetMaxExpirationHours(),
			RateLimitUpload:        cfg.GetRateLimitUpload(),
			RateLimitDownload:      cfg.GetRateLimitDownload(),
			BlockedExtensions:      cfg.GetBlockedExtensions(),
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
	}

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
	case "lan":
		// LAN deployments typically have shorter retention needs
		rec.DefaultExpirationHours = 24  // 1 day
		rec.MaxExpirationHours = 168     // 7 days
	case "wan":
		// WAN deployments need moderate retention
		rec.DefaultExpirationHours = 72  // 3 days
		rec.MaxExpirationHours = 336     // 14 days
	case "internet":
		// Internet deployments benefit from longer retention
		rec.DefaultExpirationHours = 168 // 7 days
		rec.MaxExpirationHours = 720     // 30 days
	default:
		rec.DefaultExpirationHours = 24
		rec.MaxExpirationHours = 168
	}

	// 4. Calculate Rate Limits based on user load and network capacity
	uploadCapacityMBps := req.UploadSpeed / 8 // Convert Mbps to MBps

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
	if uploadCapacityMBps < 5 {
		// Low bandwidth: reduce limits further
		rec.RateLimitUpload = rec.RateLimitUpload / 2
		if rec.RateLimitUpload < 3 {
			rec.RateLimitUpload = 3 // minimum
		}
	} else if uploadCapacityMBps > 50 {
		// High bandwidth: can afford higher limits for light/moderate loads
		if req.UserLoad == "light" || req.UserLoad == "moderate" {
			rec.RateLimitUpload = int(float64(rec.RateLimitUpload) * 1.5)
		}
	}

	// Adjust download limits similarly
	downloadCapacityMBps := req.DownloadSpeed / 8
	if downloadCapacityMBps < 10 {
		rec.RateLimitDownload = rec.RateLimitDownload / 2
		if rec.RateLimitDownload < 20 {
			rec.RateLimitDownload = 20 // minimum
		}
	} else if downloadCapacityMBps > 100 {
		if req.UserLoad == "light" || req.UserLoad == "moderate" {
			rec.RateLimitDownload = int(float64(rec.RateLimitDownload) * 1.5)
		}
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

	// Add additional recommendations based on environment
	if req.NetworkLatency == "high" || req.NetworkLatency == "medium" {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			"Consider enabling TCP tuning for high-latency connections. See docs/TCP_TUNING.md for system-level optimizations.",
		)
	}

	if req.TypicalFileSize == "large" || req.TypicalFileSize == "huge" {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			"For large file transfers, ensure CHUNKED_UPLOAD_ENABLED=true (default) and consider READ_TIMEOUT=180 for slow connections.",
		)
	}

	if req.DeploymentType == "internet" {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			"For public internet deployment, ensure HTTPS_ENABLED=true and use a reverse proxy (nginx/Traefik) with appropriate timeouts.",
		)
	}

	uploadCapacityMBps := req.UploadSpeed / 8
	if uploadCapacityMBps < 5 {
		analysis.AdditionalRecommendations = append(analysis.AdditionalRecommendations,
			fmt.Sprintf("Low upload bandwidth detected (%.1f MB/s). Consider CHUNK_SIZE=5MB for better reliability on slow connections.", uploadCapacityMBps),
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
