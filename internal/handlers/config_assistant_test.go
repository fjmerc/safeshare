package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/config"
)

func TestAdminConfigAssistantHandler(t *testing.T) {
	cfg := &config.Config{
		ChunkedUploadThreshold:   100 * 1024 * 1024,
		PartialUploadExpiryHours: 24,
		SessionExpiryHours:       24,
		CleanupIntervalMinutes:   60,
		RequireAuthForUpload:     false,
		HTTPSEnabled:             false,
		ChunkedUploadEnabled:     true,
		PublicURL:                "",
	}

	t.Run("valid request", func(t *testing.T) {
		reqBody := ConfigAssistantRequest{
			UploadSpeed:     100,
			DownloadSpeed:   200,
			NetworkLatency:  "low",
			TypicalFileSize: "medium",
			DeploymentType:  "Internet",
			UserLoad:        "moderate",
			StorageCapacity: 500,
			UsingCDN:        false,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/admin/config-assistant", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler := AdminConfigAssistantHandler(cfg)
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
		}

		var response ConfigAssistantResponse
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if response.Recommendations.MaxFileSize == 0 {
			t.Error("expected non-zero max file size recommendation")
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/config-assistant", nil)
		rr := httptest.NewRecorder()

		handler := AdminConfigAssistantHandler(cfg)
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/config-assistant", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler := AdminConfigAssistantHandler(cfg)
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("invalid speed values", func(t *testing.T) {
		reqBody := ConfigAssistantRequest{
			UploadSpeed:   0, // Invalid
			DownloadSpeed: 100,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/admin/config-assistant", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler := AdminConfigAssistantHandler(cfg)
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("with CDN settings", func(t *testing.T) {
		reqBody := ConfigAssistantRequest{
			UploadSpeed:     50,
			DownloadSpeed:   100,
			NetworkLatency:  "medium",
			TypicalFileSize: "large",
			DeploymentType:  "Internet",
			UserLoad:        "heavy",
			StorageCapacity: 1000,
			UsingCDN:        true,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/admin/config-assistant", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler := AdminConfigAssistantHandler(cfg)
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
		}

		var response ConfigAssistantResponse
		json.NewDecoder(rr.Body).Decode(&response)

		if len(response.Analysis.AdditionalRecommendations) == 0 {
			t.Error("expected CDN recommendations")
		}
	})
}

func TestCalculateMaxFileSize(t *testing.T) {
	tests := []struct {
		name     string
		fileSize string
		want     int64
	}{
		{"small", "small", 100 * 1024 * 1024},
		{"medium", "medium", 1 * 1024 * 1024 * 1024},
		{"large", "large", 5 * 1024 * 1024 * 1024},
		{"huge", "huge", 10 * 1024 * 1024 * 1024},
		{"default", "unknown", 100 * 1024 * 1024},
		{"empty", "", 100 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ConfigAssistantRequest{TypicalFileSize: tt.fileSize}
			got := calculateMaxFileSize(req)
			if got != tt.want {
				t.Errorf("calculateMaxFileSize(%q) = %d, want %d", tt.fileSize, got, tt.want)
			}
		})
	}
}

func TestCalculateStorageQuota(t *testing.T) {
	tests := []struct {
		name     string
		capacity int64
		want     int64
	}{
		{"unlimited", 0, 0},
		{"negative", -10, 0},
		{"small capacity", 5, 5},      // < 10GB uses full capacity
		{"normal capacity", 100, 75},  // 75% of 100
		{"large capacity", 1000, 750}, // 75% of 1000
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ConfigAssistantRequest{StorageCapacity: tt.capacity}
			got := calculateStorageQuota(req)
			if got != tt.want {
				t.Errorf("calculateStorageQuota(%d) = %d, want %d", tt.capacity, got, tt.want)
			}
		})
	}
}

func TestCalculateExpirationTimes(t *testing.T) {
	tests := []struct {
		name           string
		deploymentType string
		wantDefault    int
		wantMax        int
	}{
		{"LAN", "LAN", 24, 168},
		{"WAN", "WAN", 72, 336},
		{"Internet", "Internet", 168, 720},
		{"default", "Unknown", 24, 168},
		{"empty", "", 24, 168},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ConfigAssistantRequest{DeploymentType: tt.deploymentType}
			gotDefault, gotMax := calculateExpirationTimes(req)
			if gotDefault != tt.wantDefault {
				t.Errorf("default expiration = %d, want %d", gotDefault, tt.wantDefault)
			}
			if gotMax != tt.wantMax {
				t.Errorf("max expiration = %d, want %d", gotMax, tt.wantMax)
			}
		})
	}
}

func TestCalculateRateLimits(t *testing.T) {
	tests := []struct {
		name         string
		userLoad     string
		uploadMBps   float64
		downloadMBps float64
		wantUpload   int
		wantDownload int
	}{
		{"light load", "light", 10, 50, 20, 200},
		{"moderate load", "moderate", 10, 50, 15, 150},
		{"heavy load", "heavy", 10, 50, 10, 100},
		{"very heavy load", "very_heavy", 10, 50, 5, 50},
		{"default load", "unknown", 10, 50, 10, 100},
		{"low bandwidth", "light", 2, 5, 10, 100},                 // upload reduced by half
		{"high bandwidth light", "light", 60, 150, 30, 300},       // increased by 1.5x
		{"high bandwidth moderate", "moderate", 60, 150, 22, 225}, // increased by 1.5x
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ConfigAssistantRequest{UserLoad: tt.userLoad}
			gotUpload, gotDownload := calculateRateLimits(req, tt.uploadMBps, tt.downloadMBps)
			if gotUpload != tt.wantUpload {
				t.Errorf("upload limit = %d, want %d", gotUpload, tt.wantUpload)
			}
			if gotDownload != tt.wantDownload {
				t.Errorf("download limit = %d, want %d", gotDownload, tt.wantDownload)
			}
		})
	}
}

func TestCalculateChunkedUploadSettings(t *testing.T) {
	tests := []struct {
		name       string
		fileSize   string
		uploadMBps float64
	}{
		{"huge files slow", "huge", 1},
		{"large files", "large", 10},
		{"medium files", "medium", 10},
		{"slow connection", "medium", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ConfigAssistantRequest{TypicalFileSize: tt.fileSize}
			threshold, expiryHours := calculateChunkedUploadSettings(req, tt.uploadMBps)

			if threshold < 50*1024*1024 || threshold > 100*1024*1024 {
				t.Errorf("threshold = %d, want between 50MB and 100MB", threshold)
			}
			if expiryHours < 24 || expiryHours > 72 {
				t.Errorf("expiry hours = %d, want between 24 and 72", expiryHours)
			}
		})
	}
}

func TestCalculateOperationalSettings(t *testing.T) {
	tests := []struct {
		name            string
		deploymentType  string
		storageCapacity int64
		userLoad        string
		wantSession     int
	}{
		// More exposed deployments get shorter login sessions.
		{"LAN", "LAN", 100, "light", 24},
		{"WAN", "WAN", 100, "light", 12},
		{"Internet", "Internet", 100, "light", 8},
		{"default", "unknown", 100, "light", 24},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ConfigAssistantRequest{
				DeploymentType:  tt.deploymentType,
				StorageCapacity: tt.storageCapacity,
				UserLoad:        tt.userLoad,
			}
			sessionExpiry, cleanupInterval := calculateOperationalSettings(req)

			if sessionExpiry != tt.wantSession {
				t.Errorf("session expiry = %d, want %d", sessionExpiry, tt.wantSession)
			}
			if cleanupInterval < 30 || cleanupInterval > 60 {
				t.Errorf("cleanup interval = %d, want between 30 and 60", cleanupInterval)
			}
		})
	}
}

func TestCalculateSecuritySettings(t *testing.T) {
	tests := []struct {
		name           string
		deploymentType string
		userLoad       string
		wantAuth       bool
		wantHTTPS      bool
	}{
		{"Internet heavy", "Internet", "heavy", true, true},
		{"Internet very heavy", "Internet", "very_heavy", true, true},
		{"Internet moderate", "Internet", "moderate", true, true},
		{"Internet light", "Internet", "light", false, true},
		{"WAN", "WAN", "moderate", false, true},
		{"LAN", "LAN", "moderate", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ConfigAssistantRequest{
				DeploymentType: tt.deploymentType,
				UserLoad:       tt.userLoad,
			}
			gotAuth, gotHTTPS, _ := calculateSecuritySettings(req)

			if gotAuth != tt.wantAuth {
				t.Errorf("require auth = %v, want %v", gotAuth, tt.wantAuth)
			}
			if gotHTTPS != tt.wantHTTPS {
				t.Errorf("HTTPS enabled = %v, want %v", gotHTTPS, tt.wantHTTPS)
			}
		})
	}
}

func TestGenerateAnalysisSummary(t *testing.T) {
	tests := []struct {
		name   string
		req    ConfigAssistantRequest
		wantIn string
	}{
		{
			"Internet deployment",
			ConfigAssistantRequest{
				DeploymentType:  "Internet",
				NetworkLatency:  "low",
				TypicalFileSize: "medium",
				UserLoad:        "moderate",
			},
			"Internet",
		},
		{
			"LAN deployment",
			ConfigAssistantRequest{
				DeploymentType:  "LAN",
				NetworkLatency:  "local",
				TypicalFileSize: "small",
				UserLoad:        "light",
			},
			"LAN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := generateAnalysisSummary(tt.req)
			if summary == "" {
				t.Error("summary should not be empty")
			}
		})
	}
}

func TestCalculateRecommendations(t *testing.T) {
	req := ConfigAssistantRequest{
		UploadSpeed:     100,
		DownloadSpeed:   200,
		NetworkLatency:  "low",
		TypicalFileSize: "medium",
		DeploymentType:  "Internet",
		UserLoad:        "moderate",
		StorageCapacity: 500,
		UsingCDN:        false,
	}

	rec := calculateRecommendations(req)

	// Verify all fields are populated with reasonable values
	if rec.MaxFileSize <= 0 {
		t.Error("max file size should be > 0")
	}
	if rec.ChunkedUploadThreshold <= 0 {
		t.Error("chunked upload threshold should be > 0")
	}
	if len(rec.BlockedExtensions) == 0 {
		t.Error("blocked extensions should not be empty")
	}
}

func TestGenerateAnalysis(t *testing.T) {
	req := ConfigAssistantRequest{
		UploadSpeed:     100,
		DownloadSpeed:   200,
		NetworkLatency:  "low",
		TypicalFileSize: "medium",
		DeploymentType:  "Internet",
		UserLoad:        "moderate",
		StorageCapacity: 500,
		UsingCDN:        true,
	}

	current := ConfigRecommendations{
		MaxFileSize:            50 * 1024 * 1024,
		QuotaLimitGB:           0,
		DefaultExpirationHours: 24,
		MaxExpirationHours:     168,
	}

	recommended := calculateRecommendations(req)
	analysis := generateAnalysis(req, current, recommended)

	if analysis.Summary == "" {
		t.Error("analysis summary should not be empty")
	}
	if len(analysis.AdditionalRecommendations) == 0 {
		t.Error("should have additional recommendations for CDN and the reverse proxy")
	}
}

func TestGenerateImpactDescriptions(t *testing.T) {
	req := ConfigAssistantRequest{
		DeploymentType:  "Internet",
		UserLoad:        "heavy",
		UploadSpeed:     50,
		DownloadSpeed:   100,
		StorageCapacity: 500,
	}

	current := ConfigRecommendations{
		MaxFileSize:            50 * 1024 * 1024,
		QuotaLimitGB:           0,
		DefaultExpirationHours: 24,
		MaxExpirationHours:     168,
		RateLimitUpload:        10,
		RateLimitDownload:      100,
	}

	recommended := ConfigRecommendations{
		MaxFileSize:            100 * 1024 * 1024,
		QuotaLimitGB:           400,
		DefaultExpirationHours: 168,
		MaxExpirationHours:     720,
		RateLimitUpload:        5,
		RateLimitDownload:      50,
	}

	analysis := &ConfigAnalysis{
		Impacts: make(map[string]string),
	}

	generateImpactDescriptions(req, current, recommended, analysis)

	if len(analysis.Impacts) == 0 {
		t.Error("should have impact descriptions for changed settings")
	}
}

func TestGeneratePerformanceImpacts(t *testing.T) {
	req := ConfigAssistantRequest{
		UploadSpeed:    50,
		NetworkLatency: "medium",
	}

	current := ConfigRecommendations{
		ChunkedUploadThreshold:   50 * 1024 * 1024,
		PartialUploadExpiryHours: 24,
	}

	recommended := ConfigRecommendations{
		ChunkedUploadThreshold:   100 * 1024 * 1024,
		PartialUploadExpiryHours: 48,
	}

	analysis := &ConfigAnalysis{
		Impacts: make(map[string]string),
	}

	generatePerformanceImpacts(req, current, recommended, analysis)

	if len(analysis.Impacts) != 2 {
		t.Errorf("performance impacts = %v, want threshold and partial expiry", analysis.Impacts)
	}
}

func TestGenerateOperationalImpacts(t *testing.T) {
	req := ConfigAssistantRequest{
		DeploymentType: "Internet",
	}

	current := ConfigRecommendations{
		SessionExpiryHours:     12,
		CleanupIntervalMinutes: 30,
		RequireAuthForUpload:   false,
		HTTPSEnabled:           false,
	}

	recommended := ConfigRecommendations{
		SessionExpiryHours:     8,
		CleanupIntervalMinutes: 60,
		RequireAuthForUpload:   true,
		HTTPSEnabled:           true,
	}

	analysis := &ConfigAnalysis{
		Impacts: make(map[string]string),
	}

	generateOperationalImpacts(req, current, recommended, analysis)

	if len(analysis.Impacts) == 0 {
		t.Error("should have operational impact descriptions")
	}
}

func TestGenerateNetworkRecommendations(t *testing.T) {
	t.Run("high latency", func(t *testing.T) {
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}
		generateNetworkRecommendations(ConfigAssistantRequest{NetworkLatency: "high"}, analysis)
		if len(analysis.AdditionalRecommendations) == 0 {
			t.Error("should have TCP tuning recommendation for high latency")
		}
	})

	t.Run("low latency", func(t *testing.T) {
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}
		generateNetworkRecommendations(ConfigAssistantRequest{NetworkLatency: "low", UploadSpeed: 16}, analysis)
		if len(analysis.AdditionalRecommendations) != 0 {
			t.Errorf("unexpected recommendations: %v", analysis.AdditionalRecommendations)
		}
	})
}

func TestGenerateDeploymentRecommendations(t *testing.T) {
	t.Run("Internet with HTTPS", func(t *testing.T) {
		req := ConfigAssistantRequest{DeploymentType: "Internet"}
		rec := ConfigRecommendations{HTTPSEnabled: true}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateDeploymentRecommendations(req, rec, analysis)

		if len(analysis.AdditionalRecommendations) != 2 {
			t.Fatalf("recommendations = %v, want proxy and HTTPS advice", analysis.AdditionalRecommendations)
		}
		if !strings.Contains(analysis.AdditionalRecommendations[0], "6 hours") {
			t.Errorf("proxy advice should say transfers can take up to 6 hours: %q", analysis.AdditionalRecommendations[0])
		}
	})

	t.Run("LAN deployment", func(t *testing.T) {
		req := ConfigAssistantRequest{DeploymentType: "LAN"}
		rec := ConfigRecommendations{}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateDeploymentRecommendations(req, rec, analysis)

		if len(analysis.AdditionalRecommendations) != 0 {
			t.Errorf("LAN should get no Internet recommendations: %v", analysis.AdditionalRecommendations)
		}
	})
}

func TestGenerateCDNRecommendations(t *testing.T) {
	t.Run("no CDN", func(t *testing.T) {
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}
		generateCDNRecommendations(ConfigAssistantRequest{UsingCDN: false}, analysis)
		if len(analysis.AdditionalRecommendations) != 0 {
			t.Errorf("unexpected recommendations: %v", analysis.AdditionalRecommendations)
		}
	})

	t.Run("CDN", func(t *testing.T) {
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}
		generateCDNRecommendations(ConfigAssistantRequest{UsingCDN: true}, analysis)
		if len(analysis.AdditionalRecommendations) != 1 || !strings.Contains(analysis.AdditionalRecommendations[0], "DOWNLOAD_URL") {
			t.Errorf("want the DOWNLOAD_URL advice, got %v", analysis.AdditionalRecommendations)
		}
	})
}

func TestGenerateResourceRecommendations(t *testing.T) {
	t.Run("heavy load", func(t *testing.T) {
		req := ConfigAssistantRequest{UserLoad: "heavy"}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateResourceRecommendations(req, analysis)

		if len(analysis.AdditionalRecommendations) == 0 {
			t.Error("should have load recommendation")
		}
	})

	t.Run("limited storage", func(t *testing.T) {
		req := ConfigAssistantRequest{StorageCapacity: 30}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateResourceRecommendations(req, analysis)

		if len(analysis.AdditionalRecommendations) == 0 {
			t.Error("should have storage recommendation")
		}
	})
}
