package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
)

func postStorageSettings(t *testing.T, form url.Values) (*httptest.ResponseRecorder, func() (int, int, int64)) {
	t.Helper()
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	// Ghost-style short retention: default 1h, max 24h.
	if err := cfg.SetExpirationHours(1, 24); err != nil {
		t.Fatalf("SetExpirationHours: %v", err)
	}
	if err := cfg.SetQuotaLimitGB(5); err != nil {
		t.Fatalf("SetQuotaLimitGB: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/storage", bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	AdminUpdateStorageSettingsHandler(repos, cfg).ServeHTTP(rr, req)

	return rr, func() (int, int, int64) {
		return cfg.GetDefaultExpirationHours(), cfg.GetMaxExpirationHours(), cfg.GetQuotaLimitGB()
	}
}

// Raising the default above the old max in the same save used to fail,
// because the default was applied before the new max.
func TestAdminUpdateStorageSettings_RaiseDefaultAboveOldMax(t *testing.T) {
	form := url.Values{}
	form.Set("quota_gb", "100")
	form.Set("default_expiration_hours", "168")
	form.Set("max_expiration_hours", "720")

	rr, current := postStorageSettings(t, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if d, m, q := current(); d != 168 || m != 720 || q != 100 {
		t.Errorf("got default=%d max=%d quota=%d, want 168/720/100", d, m, q)
	}
}

// A rejected field must not leave earlier fields applied.
func TestAdminUpdateStorageSettings_RejectsWithoutPartialApply(t *testing.T) {
	tests := []struct {
		name string
		form url.Values
	}{
		{"default above max", url.Values{"quota_gb": {"100"}, "default_expiration_hours": {"48"}, "max_expiration_hours": {"24"}}},
		{"default above current max", url.Values{"quota_gb": {"100"}, "default_expiration_hours": {"48"}}},
		{"bad max expiration", url.Values{"quota_gb": {"100"}, "max_expiration_hours": {"abc"}}},
		{"oversized file size", url.Values{"quota_gb": {"100"}, "max_file_size_mb": {"9223372036854775807"}}},
		{"oversized quota", url.Values{"quota_gb": {"17179869184"}, "default_expiration_hours": {"12"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr, current := postStorageSettings(t, tt.form)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rr.Code)
			}
			if d, m, q := current(); d != 1 || m != 24 || q != 5 {
				t.Errorf("settings changed on rejection: default=%d max=%d quota=%d, want 1/24/5", d, m, q)
			}
		})
	}
}

func TestMergeBlockedExtensions(t *testing.T) {
	got := mergeBlockedExtensions(
		[]string{".html", ".EXE", "svg", " "},
		[]string{".exe", ".bat", ".html"},
	)
	want := []string{".html", ".exe", ".svg", ".bat"}
	if !slices.Equal(got, want) {
		t.Errorf("mergeBlockedExtensions = %v, want %v", got, want)
	}
	if got := mergeBlockedExtensions(nil, []string{".exe"}); !slices.Equal(got, []string{".exe"}) {
		t.Errorf("nil current: got %v", got)
	}
}

func TestCapExpirationsForAnonymousMode(t *testing.T) {
	current := ConfigRecommendations{DefaultExpirationHours: 1, MaxExpirationHours: 24}

	rec := ConfigRecommendations{DefaultExpirationHours: 168, MaxExpirationHours: 720}
	if !capExpirationsForAnonymousMode(&rec, current) {
		t.Error("expected capping to be reported")
	}
	if rec.DefaultExpirationHours != 1 || rec.MaxExpirationHours != 24 {
		t.Errorf("capped = %d/%d, want 1/24", rec.DefaultExpirationHours, rec.MaxExpirationHours)
	}

	// Tighter recommendations are left alone.
	current = ConfigRecommendations{DefaultExpirationHours: 72, MaxExpirationHours: 720}
	rec = ConfigRecommendations{DefaultExpirationHours: 24, MaxExpirationHours: 168}
	if capExpirationsForAnonymousMode(&rec, current) {
		t.Error("did not expect capping")
	}
	if rec.DefaultExpirationHours != 24 || rec.MaxExpirationHours != 168 {
		t.Errorf("rec changed to %d/%d", rec.DefaultExpirationHours, rec.MaxExpirationHours)
	}
}

func runConfigAssistant(t *testing.T, anonymous bool) ConfigAssistantResponse {
	t.Helper()
	if anonymous {
		t.Setenv("ANONYMOUS_MODE", "true")
	}
	cfg := testutil.SetupTestConfig(t)
	if cfg.IsAnonymousMode() != anonymous {
		t.Fatalf("anonymous mode = %v, want %v", cfg.IsAnonymousMode(), anonymous)
	}
	if err := cfg.SetExpirationHours(1, 24); err != nil {
		t.Fatalf("SetExpirationHours: %v", err)
	}
	if err := cfg.SetBlockedExtensions([]string{".html", ".exe"}); err != nil {
		t.Fatalf("SetBlockedExtensions: %v", err)
	}

	body, _ := json.Marshal(ConfigAssistantRequest{
		UploadSpeed: 100, DownloadSpeed: 200, NetworkLatency: "low",
		TypicalFileSize: "medium", DeploymentType: "Internet", UserLoad: "moderate",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/config-assistant/analyze", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	AdminConfigAssistantHandler(cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", rr.Code, rr.Body.String())
	}
	var resp ConfigAssistantResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func TestAdminConfigAssistant_AnonymousModeKeepsShortRetention(t *testing.T) {
	resp := runConfigAssistant(t, true)
	rec := resp.Recommendations
	if rec.DefaultExpirationHours != 1 || rec.MaxExpirationHours != 24 {
		t.Errorf("anonymous mode recommended %d/%d, want 1/24", rec.DefaultExpirationHours, rec.MaxExpirationHours)
	}
	found := false
	for _, r := range resp.Analysis.AdditionalRecommendations {
		if strings.Contains(r, "Anonymous (Ghost) mode is on") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing anonymous-mode note in %v", resp.Analysis.AdditionalRecommendations)
	}
}

func TestAdminConfigAssistant_StandardModeAndBlockedExtensions(t *testing.T) {
	resp := runConfigAssistant(t, false)
	rec := resp.Recommendations
	if rec.DefaultExpirationHours != 168 || rec.MaxExpirationHours != 720 {
		t.Errorf("standard mode recommended %d/%d, want 168/720", rec.DefaultExpirationHours, rec.MaxExpirationHours)
	}
	if !slices.Contains(rec.BlockedExtensions, ".html") {
		t.Errorf("admin's own blocked extension .html was dropped: %v", rec.BlockedExtensions)
	}
	if !slices.Contains(rec.BlockedExtensions, ".bat") {
		t.Errorf("baseline extension .bat missing: %v", rec.BlockedExtensions)
	}
	for _, r := range resp.Analysis.AdditionalRecommendations {
		if strings.Contains(r, "%%") {
			t.Errorf("unformatted %%%% in recommendation: %q", r)
		}
		if strings.Contains(r, "Anonymous (Ghost)") {
			t.Errorf("unexpected anonymous-mode note in standard mode: %q", r)
		}
	}
}

func TestApplyServerConstraints_AnonymousMode(t *testing.T) {
	ghost := assistantServerFacts{anonymous: true, clientEncryption: true}
	base := func() ConfigRecommendations {
		return ConfigRecommendations{
			DefaultExpirationHours: 168, MaxExpirationHours: 720,
			RateLimitUpload: 15, RateLimitDownload: 150,
			RequireAuthForUpload: true, HTTPSEnabled: true,
			MaxFileSize: 1 << 30,
		}
	}

	t.Run("raises rate limits to the service-wide floor", func(t *testing.T) {
		rec := base()
		current := ConfigRecommendations{DefaultExpirationHours: 1, MaxExpirationHours: 24, RateLimitUpload: 10, RateLimitDownload: 50}
		applyServerConstraints(&rec, current, ghost)
		if rec.RateLimitUpload != 100 || rec.RateLimitDownload != 500 {
			t.Errorf("rate limits = %d/%d, want 100/500", rec.RateLimitUpload, rec.RateLimitDownload)
		}
	})

	t.Run("never lowers existing rate limits", func(t *testing.T) {
		rec := base()
		current := ConfigRecommendations{DefaultExpirationHours: 1, MaxExpirationHours: 24, RateLimitUpload: 1000, RateLimitDownload: 5000}
		applyServerConstraints(&rec, current, ghost)
		if rec.RateLimitUpload != 1000 || rec.RateLimitDownload != 5000 {
			t.Errorf("rate limits = %d/%d, want the current 1000/5000 kept", rec.RateLimitUpload, rec.RateLimitDownload)
		}
	})

	t.Run("no login requirement, HTTPS left as it is", func(t *testing.T) {
		rec := base()
		current := ConfigRecommendations{DefaultExpirationHours: 1, MaxExpirationHours: 24, HTTPSEnabled: false}
		notes, _ := applyServerConstraints(&rec, current, ghost)
		if rec.RequireAuthForUpload {
			t.Error("anonymous mode must not recommend requiring login")
		}
		if rec.HTTPSEnabled {
			t.Error("anonymous mode must not turn on HTTPS_ENABLED (onion addresses use http://)")
		}
		if rec.DefaultExpirationHours != 1 || rec.MaxExpirationHours != 24 {
			t.Errorf("expirations = %d/%d, want the current 1/24", rec.DefaultExpirationHours, rec.MaxExpirationHours)
		}
		joined := strings.Join(notes, "\n")
		for _, want := range []string{"one budget for the whole service", "require login", "HTTPS_ENABLED", "500 MB"} {
			if !strings.Contains(joined, want) {
				t.Errorf("notes missing %q:\n%s", want, joined)
			}
		}
	})

	t.Run("standard mode keeps the formula's values", func(t *testing.T) {
		rec := base()
		current := ConfigRecommendations{RateLimitUpload: 1000, RateLimitDownload: 5000}
		applyServerConstraints(&rec, current, assistantServerFacts{})
		if rec.RateLimitUpload != 15 || rec.RateLimitDownload != 150 || !rec.RequireAuthForUpload || !rec.HTTPSEnabled {
			t.Errorf("standard mode changed recommendations: %+v", rec)
		}
	})
}

func TestApplyServerConstraints_MalwareScanning(t *testing.T) {
	const scanMax = 100 * 1024 * 1024

	t.Run("rejecting unscannable files caps the max size", func(t *testing.T) {
		rec := ConfigRecommendations{MaxFileSize: 5 << 30}
		notes, _ := applyServerConstraints(&rec, ConfigRecommendations{}, assistantServerFacts{malwareScan: true, rejectUnscannable: true, scanMaxFileSize: scanMax})
		if rec.MaxFileSize != scanMax {
			t.Errorf("max file size = %d, want the scanner's %d", rec.MaxFileSize, scanMax)
		}
		if !strings.Contains(strings.Join(notes, "\n"), "100 MB") {
			t.Errorf("notes should explain the cap: %v", notes)
		}
	})

	t.Run("accepting unscannable files only notes it", func(t *testing.T) {
		rec := ConfigRecommendations{MaxFileSize: 5 << 30}
		notes, _ := applyServerConstraints(&rec, ConfigRecommendations{}, assistantServerFacts{malwareScan: true, scanMaxFileSize: scanMax})
		if rec.MaxFileSize != 5<<30 {
			t.Errorf("max file size changed to %d", rec.MaxFileSize)
		}
		if !strings.Contains(strings.Join(notes, "\n"), "without a malware scan") {
			t.Errorf("notes should say large files go unscanned: %v", notes)
		}
	})

	t.Run("browser encryption plus rejecting unscannable is flagged, not capped", func(t *testing.T) {
		rec := ConfigRecommendations{MaxFileSize: 5 << 30}
		notes, _ := applyServerConstraints(&rec, ConfigRecommendations{}, assistantServerFacts{malwareScan: true, rejectUnscannable: true, scanMaxFileSize: scanMax, clientEncryption: true})
		if rec.MaxFileSize != 5<<30 {
			t.Errorf("max file size changed to %d", rec.MaxFileSize)
		}
		if !strings.Contains(strings.Join(notes, "\n"), "Uploads will be refused") {
			t.Errorf("notes should flag the contradiction: %v", notes)
		}
	})
}

func TestApplyServerConstraints_QuotaCapsMaxFileSize(t *testing.T) {
	// 8 GB of storage: quota 8 GB, so a 10 GB maximum file could never fit.
	rec := ConfigRecommendations{MaxFileSize: 10 << 30, QuotaLimitGB: 8}
	notes, impacts := applyServerConstraints(&rec, ConfigRecommendations{}, assistantServerFacts{})
	if rec.MaxFileSize != 8<<30 {
		t.Errorf("max file size = %d, want the 8 GB quota", rec.MaxFileSize)
	}
	if !strings.Contains(impacts["max_file_size"], "storage quota") || len(notes) == 0 {
		t.Errorf("cap not explained: impacts=%v notes=%v", impacts, notes)
	}
}

// The handler shows the server rule as a changed value's explanation, not
// the generic text for the environment.
func TestAdminConfigAssistant_ConstrainedValuesExplainedByTheirRule(t *testing.T) {
	resp := runConfigAssistant(t, true)
	for _, key := range []string{"rate_limit_upload", "require_auth_for_upload", "default_expiration_hours"} {
		impact := resp.Analysis.Impacts[key]
		if impact == "" || strings.Contains(impact, "Balanced for") || strings.Contains(impact, "Enabled to prevent") || strings.Contains(impact, "Adjusted for") {
			t.Errorf("%s explanation = %q, want the anonymous-mode reason", key, impact)
		}
	}
}

func TestAdminConfigAssistant_RejectsAbsurdStorageCapacity(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)
	for _, capacity := range []int64{-1, 1 << 40} {
		body, _ := json.Marshal(ConfigAssistantRequest{UploadSpeed: 100, DownloadSpeed: 100, StorageCapacity: capacity})
		rr := httptest.NewRecorder()
		AdminConfigAssistantHandler(cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/admin/api/config-assistant/analyze", bytes.NewReader(body)))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("storage_capacity %d: status %d, want 400", capacity, rr.Code)
		}
	}
}
