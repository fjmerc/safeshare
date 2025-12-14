package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/config"
)

func TestAdminConfigAssistantHandler(t *testing.T) {
	cfg := &config.Config{
		ChunkSize:                10 * 1024 * 1024,
		ReadTimeoutSeconds:       120,
		WriteTimeoutSeconds:      120,
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
			UploadSpeed:       100,
			DownloadSpeed:     200,
			NetworkLatency:    "low",
			TypicalFileSize:   "medium",
			DeploymentType:    "Internet",
			UserLoad:          "moderate",
			StorageCapacity:   500,
			UsingCDN:          false,
			EncryptionEnabled: false,
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
			UploadSpeed:       50,
			DownloadSpeed:     100,
			NetworkLatency:    "medium",
			TypicalFileSize:   "large",
			DeploymentType:    "Internet",
			UserLoad:          "heavy",
			StorageCapacity:   1000,
			UsingCDN:          true,
			CDNTimeout:        120,
			EncryptionEnabled: true,
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
		{"small capacity", 5, 5},           // < 10GB uses full capacity
		{"normal capacity", 100, 80},       // 80% of 100
		{"large capacity", 1000, 800},      // 80% of 1000
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
		name          string
		userLoad      string
		uploadMBps    float64
		downloadMBps  float64
		wantUpload    int
		wantDownload  int
	}{
		{"light load", "light", 10, 50, 20, 200},
		{"moderate load", "moderate", 10, 50, 15, 150},
		{"heavy load", "heavy", 10, 50, 10, 100},
		{"very heavy load", "very_heavy", 10, 50, 5, 50},
		{"default load", "unknown", 10, 50, 10, 100},
		{"low bandwidth", "light", 2, 5, 10, 100},  // upload reduced by half
		{"high bandwidth light", "light", 60, 150, 30, 300}, // increased by 1.5x
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

func TestCalculateChunkSize(t *testing.T) {
	tests := []struct {
		name         string
		latency      string
		uploadMBps   float64
		fileSize     string
		wantChunkMB  int64
	}{
		{"high latency", "high", 10, "medium", 5},
		{"slow connection", "low", 1, "medium", 5},
		{"medium-slow", "low", 3, "medium", 8},
		{"medium connection", "low", 10, "medium", 10},
		{"fast connection", "low", 20, "medium", 20},
		{"very fast", "low", 50, "medium", 30},
		{"huge files cap", "low", 50, "huge", 10}, // capped at 10MB for huge files
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ConfigAssistantRequest{
				NetworkLatency:  tt.latency,
				TypicalFileSize: tt.fileSize,
			}
			got := calculateChunkSize(req, tt.uploadMBps)
			wantBytes := tt.wantChunkMB * 1024 * 1024
			if got != wantBytes {
				t.Errorf("chunk size = %d MB, want %d MB", got/(1024*1024), tt.wantChunkMB)
			}
		})
	}
}

func TestApplyCDNConstraints(t *testing.T) {
	tests := []struct {
		name        string
		usingCDN    bool
		cdnTimeout  int
		uploadMBps  float64
		chunkSize   int64
		wantChunk   int64
	}{
		{"no CDN", false, 0, 10, 20 * 1024 * 1024, 20 * 1024 * 1024},
		{"CDN no timeout", true, 0, 10, 20 * 1024 * 1024, 20 * 1024 * 1024},
		{"CDN allows larger", true, 120, 10, 10 * 1024 * 1024, 10 * 1024 * 1024},
		{"CDN constrains", true, 30, 5, 100 * 1024 * 1024, int64(5 * 30 * 0.6 * 1024 * 1024)}, // input 100MB, constrained to ~90MB
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ConfigAssistantRequest{
				UsingCDN:   tt.usingCDN,
				CDNTimeout: tt.cdnTimeout,
			}
			got := applyCDNConstraints(req, tt.uploadMBps, tt.chunkSize)
			if got != tt.wantChunk {
				t.Errorf("chunk size = %d, want %d", got, tt.wantChunk)
			}
		})
	}
}

func TestCalculateTimeouts(t *testing.T) {
	tests := []struct {
		name        string
		latency     string
		uploadMBps  float64
		chunkSize   int64
		encryption  bool
		usingCDN    bool
		cdnTimeout  int
	}{
		{"low latency", "low", 10, 10 * 1024 * 1024, false, false, 0},
		{"medium latency", "medium", 10, 10 * 1024 * 1024, false, false, 0},
		{"high latency", "high", 10, 10 * 1024 * 1024, false, false, 0},
		{"with encryption", "low", 10, 10 * 1024 * 1024, true, false, 0},
		{"with CDN", "low", 10, 10 * 1024 * 1024, false, true, 120}, // CDN timeout 120s -> max 96s after 0.8 safety factor
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ConfigAssistantRequest{
				NetworkLatency:    tt.latency,
				EncryptionEnabled: tt.encryption,
				UsingCDN:          tt.usingCDN,
				CDNTimeout:        tt.cdnTimeout,
			}
			readTimeout, writeTimeout := calculateTimeouts(req, tt.uploadMBps, tt.chunkSize)

			// Verify timeouts are within bounds
			if readTimeout < 60 || readTimeout > 600 {
				t.Errorf("read timeout = %d, want between 60 and 600", readTimeout)
			}
			if writeTimeout < 60 || writeTimeout > 600 {
				t.Errorf("write timeout = %d, want between 60 and 600", writeTimeout)
			}
		})
	}
}

func TestApplyTimeoutBounds(t *testing.T) {
	tests := []struct {
		timeout    int
		minTimeout int
		maxTimeout int
		want       int
	}{
		{50, 60, 600, 60},   // below min
		{700, 60, 600, 600}, // above max
		{120, 60, 600, 120}, // within bounds
		{60, 60, 600, 60},   // at min
		{600, 60, 600, 600}, // at max
	}

	for _, tt := range tests {
		got := applyTimeoutBounds(tt.timeout, tt.minTimeout, tt.maxTimeout)
		if got != tt.want {
			t.Errorf("applyTimeoutBounds(%d, %d, %d) = %d, want %d",
				tt.timeout, tt.minTimeout, tt.maxTimeout, got, tt.want)
		}
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
		{"LAN", "LAN", 100, "light", 12},
		{"WAN", "WAN", 100, "light", 24},
		{"Internet", "Internet", 100, "light", 48},
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
		name    string
		req     ConfigAssistantRequest
		wantIn  string
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

func TestMinFunction(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{5, 10, 5},
		{10, 5, 5},
		{5, 5, 5},
		{-5, 5, -5},
		{0, 0, 0},
	}

	for _, tt := range tests {
		got := min(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCalculateRecommendations(t *testing.T) {
	req := ConfigAssistantRequest{
		UploadSpeed:       100,
		DownloadSpeed:     200,
		NetworkLatency:    "low",
		TypicalFileSize:   "medium",
		DeploymentType:    "Internet",
		UserLoad:          "moderate",
		StorageCapacity:   500,
		UsingCDN:          false,
		EncryptionEnabled: false,
	}

	rec := calculateRecommendations(req)

	// Verify all fields are populated with reasonable values
	if rec.MaxFileSize <= 0 {
		t.Error("max file size should be > 0")
	}
	if rec.ChunkSize <= 0 {
		t.Error("chunk size should be > 0")
	}
	if rec.ReadTimeout <= 0 {
		t.Error("read timeout should be > 0")
	}
	if rec.WriteTimeout <= 0 {
		t.Error("write timeout should be > 0")
	}
	if len(rec.BlockedExtensions) == 0 {
		t.Error("blocked extensions should not be empty")
	}
}

func TestGenerateAnalysis(t *testing.T) {
	req := ConfigAssistantRequest{
		UploadSpeed:       100,
		DownloadSpeed:     200,
		NetworkLatency:    "low",
		TypicalFileSize:   "medium",
		DeploymentType:    "Internet",
		UserLoad:          "moderate",
		StorageCapacity:   500,
		UsingCDN:          true,
		CDNTimeout:        60,
		EncryptionEnabled: true,
	}

	current := ConfigRecommendations{
		MaxFileSize:            50 * 1024 * 1024,
		QuotaLimitGB:           0,
		DefaultExpirationHours: 24,
		MaxExpirationHours:     168,
		ChunkSize:              5 * 1024 * 1024,
	}

	recommended := calculateRecommendations(req)
	analysis := generateAnalysis(req, current, recommended)

	if analysis.Summary == "" {
		t.Error("analysis summary should not be empty")
	}
	if len(analysis.AdditionalRecommendations) == 0 {
		t.Error("should have additional recommendations for CDN and encryption")
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
		ChunkSize:                5 * 1024 * 1024,
		ReadTimeout:              60,
		WriteTimeout:             60,
		ChunkedUploadThreshold:   50 * 1024 * 1024,
		PartialUploadExpiryHours: 24,
	}

	recommended := ConfigRecommendations{
		ChunkSize:                10 * 1024 * 1024,
		ReadTimeout:              120,
		WriteTimeout:             120,
		ChunkedUploadThreshold:   100 * 1024 * 1024,
		PartialUploadExpiryHours: 48,
	}

	analysis := &ConfigAnalysis{
		Impacts: make(map[string]string),
	}

	generatePerformanceImpacts(req, current, recommended, analysis)

	if len(analysis.Impacts) == 0 {
		t.Error("should have performance impact descriptions")
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
		SessionExpiryHours:     48,
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
		req := ConfigAssistantRequest{NetworkLatency: "high"}
		rec := ConfigRecommendations{}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateNetworkRecommendations(req, rec, analysis)

		if len(analysis.AdditionalRecommendations) == 0 {
			t.Error("should have TCP tuning recommendation for high latency")
		}
	})

	t.Run("slow upload", func(t *testing.T) {
		req := ConfigAssistantRequest{
			UploadSpeed:    16, // 16 Mbps = 2 MBps
			NetworkLatency: "low",
		}
		rec := ConfigRecommendations{}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateNetworkRecommendations(req, rec, analysis)

		if len(analysis.AdditionalRecommendations) == 0 {
			t.Error("should have recommendation for slow upload")
		}
	})
}

func TestGenerateFileRecommendations(t *testing.T) {
	t.Run("large files", func(t *testing.T) {
		req := ConfigAssistantRequest{TypicalFileSize: "large"}
		rec := ConfigRecommendations{
			ChunkSize:    10 * 1024 * 1024,
			ReadTimeout:  120,
			WriteTimeout: 120,
		}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateFileRecommendations(req, rec, analysis)

		if len(analysis.AdditionalRecommendations) == 0 {
			t.Error("should have recommendation for large files")
		}
	})

	t.Run("huge files", func(t *testing.T) {
		req := ConfigAssistantRequest{TypicalFileSize: "huge"}
		rec := ConfigRecommendations{
			ChunkSize:    10 * 1024 * 1024,
			ReadTimeout:  120,
			WriteTimeout: 120,
		}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateFileRecommendations(req, rec, analysis)

		if len(analysis.AdditionalRecommendations) == 0 {
			t.Error("should have recommendation for huge files")
		}
	})
}

func TestGenerateDeploymentRecommendations(t *testing.T) {
	t.Run("Internet with HTTPS", func(t *testing.T) {
		req := ConfigAssistantRequest{DeploymentType: "Internet"}
		rec := ConfigRecommendations{
			ReadTimeout:  120,
			HTTPSEnabled: true,
		}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateDeploymentRecommendations(req, rec, analysis)

		if len(analysis.AdditionalRecommendations) == 0 {
			t.Error("should have recommendations for Internet deployment")
		}
	})

	t.Run("LAN deployment", func(t *testing.T) {
		req := ConfigAssistantRequest{DeploymentType: "LAN"}
		rec := ConfigRecommendations{}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateDeploymentRecommendations(req, rec, analysis)

		// LAN should not trigger Internet recommendations
		// (depending on implementation)
	})
}

func TestGenerateCDNRecommendations(t *testing.T) {
	t.Run("no CDN", func(t *testing.T) {
		req := ConfigAssistantRequest{UsingCDN: false}
		rec := ConfigRecommendations{}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateCDNRecommendations(req, rec, analysis)

		// Should not add recommendations when not using CDN
	})

	t.Run("CDN with timeout", func(t *testing.T) {
		req := ConfigAssistantRequest{
			UsingCDN:   true,
			CDNTimeout: 60,
		}
		rec := ConfigRecommendations{ChunkSize: 10 * 1024 * 1024}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateCDNRecommendations(req, rec, analysis)

		if len(analysis.AdditionalRecommendations) == 0 {
			t.Error("should have CDN recommendations")
		}
	})

	t.Run("CDN with short timeout", func(t *testing.T) {
		req := ConfigAssistantRequest{
			UsingCDN:   true,
			CDNTimeout: 30, // < 60 seconds
		}
		rec := ConfigRecommendations{ChunkSize: 10 * 1024 * 1024}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateCDNRecommendations(req, rec, analysis)

		// Should warn about short timeout
		if len(analysis.AdditionalRecommendations) < 2 {
			t.Error("should have warning about short CDN timeout")
		}
	})
}

func TestGenerateResourceRecommendations(t *testing.T) {
	t.Run("encryption enabled", func(t *testing.T) {
		req := ConfigAssistantRequest{EncryptionEnabled: true}
		analysis := &ConfigAnalysis{AdditionalRecommendations: []string{}}

		generateResourceRecommendations(req, analysis)

		if len(analysis.AdditionalRecommendations) == 0 {
			t.Error("should have encryption recommendation")
		}
	})

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
