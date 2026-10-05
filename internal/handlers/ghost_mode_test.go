package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/privacy"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/webhooks"
)

type ghostEnv struct {
	repos *repository.Repositories
	cfg   *config.Config
}

// newGhostEnv builds a test environment; env is applied before config.Load so
// ANONYMOUS_MODE / REQUIRE_CLIENT_ENCRYPTION take effect like in production.
func newGhostEnv(t *testing.T, env map[string]string) *ghostEnv {
	t.Helper()
	// Start from a clean slate so earlier cases cannot leak into this one.
	for _, k := range []string{"ANONYMOUS_MODE", "REQUIRE_CLIENT_ENCRYPTION", "STRIP_METADATA"} {
		t.Setenv(k, "")
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	return &ghostEnv{repos: repos, cfg: cfg}
}

func postUpload(t *testing.T, h http.Handler, content []byte, name string, form map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, ct := testutil.CreateMultipartForm(t, content, name, form)
	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", ct)
	if form["client_encrypted"] == "true" {
		req.Header.Set(clientEncryptedHeaderName, "true")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

type countingBody struct{ reads int }

func (c *countingBody) Read(p []byte) (int, error) { c.reads++; return 0, io.EOF }

func TestClientEncryptionRequired_RejectsBeforeReadingBody(t *testing.T) {
	e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true"})
	body := &countingBody{}
	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	rr := httptest.NewRecorder()
	UploadHandler(e.repos, e.cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || errorCode(t, rr) != "CLIENT_ENCRYPTION_REQUIRED" {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	if body.reads != 0 {
		t.Errorf("request body was read %d time(s) before rejection", body.reads)
	}

	// Header present but form field missing: the backstop still rejects.
	b, ct := testutil.CreateMultipartForm(t, []byte("x"), "a.txt", nil)
	req = httptest.NewRequest(http.MethodPost, "/api/upload", b)
	req.Header.Set("Content-Type", ct)
	req.Header.Set(clientEncryptedHeaderName, "true")
	rr = httptest.NewRecorder()
	UploadHandler(e.repos, e.cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("backstop status = %d", rr.Code)
	}
}

func TestClientEncryptionRequired_ChunkedInitAcceptsHeader(t *testing.T) {
	e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true"})
	body, _ := json.Marshal(models.UploadInitRequest{Filename: "f.bin", TotalSize: 1024 * 1024})
	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
	req.Header.Set(clientEncryptedHeaderName, "true")
	rr := httptest.NewRecorder()
	UploadInitHandler(e.repos, e.cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d; %s", rr.Code, rr.Body.String())
	}
	var resp models.UploadInitResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	pu, _ := e.repos.PartialUploads.GetByUploadID(context.Background(), resp.UploadID)
	if pu == nil || !pu.ClientEncrypted {
		t.Error("session should record client_encrypted when declared via header")
	}
}

func errorCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON %q: %v", rr.Body.String(), err)
	}
	code, _ := resp["code"].(string)
	return code
}

func TestClientEncryptionRequired_SimpleUpload(t *testing.T) {
	tests := []struct {
		name       string
		env        map[string]string
		form       map[string]string
		wantStatus int
		wantCode   string
	}{
		{"anonymous default rejects plaintext", map[string]string{"ANONYMOUS_MODE": "true"}, nil, http.StatusBadRequest, "CLIENT_ENCRYPTION_REQUIRED"},
		{"anonymous accepts declared E2E", map[string]string{"ANONYMOUS_MODE": "true"}, map[string]string{"client_encrypted": "true"}, http.StatusCreated, ""},
		{"anonymous with explicit opt-out accepts plaintext", map[string]string{"ANONYMOUS_MODE": "true", "REQUIRE_CLIENT_ENCRYPTION": "false"}, nil, http.StatusCreated, ""},
		{"normal mode default accepts plaintext", nil, nil, http.StatusCreated, ""},
		{"normal mode explicit require rejects plaintext", map[string]string{"REQUIRE_CLIENT_ENCRYPTION": "true"}, nil, http.StatusBadRequest, "CLIENT_ENCRYPTION_REQUIRED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newGhostEnv(t, tt.env)
			rr := postUpload(t, UploadHandler(e.repos, e.cfg), []byte("hello"), "a.txt", tt.form)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if tt.wantCode != "" {
				if got := errorCode(t, rr); got != tt.wantCode {
					t.Errorf("code = %q, want %q", got, tt.wantCode)
				}
				files, err := storedFiles(e.cfg.UploadDir)
				if err != nil {
					t.Fatal(err)
				}
				if len(files) != 0 {
					t.Errorf("rejected upload left %d file(s) on disk", len(files))
				}
			}
		})
	}
}

func TestClientEncryptionRequired_ChunkedInit(t *testing.T) {
	tests := []struct {
		name            string
		env             map[string]string
		clientEncrypted bool
		wantStatus      int
	}{
		{"required, plaintext", map[string]string{"ANONYMOUS_MODE": "true"}, false, http.StatusBadRequest},
		{"required, E2E", map[string]string{"ANONYMOUS_MODE": "true"}, true, http.StatusCreated},
		{"not required, plaintext", nil, false, http.StatusCreated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newGhostEnv(t, tt.env)
			body, _ := json.Marshal(models.UploadInitRequest{Filename: "f.bin", TotalSize: 1024 * 1024, ClientEncrypted: tt.clientEncrypted})
			req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			UploadInitHandler(e.repos, e.cfg).ServeHTTP(rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if tt.wantStatus == http.StatusBadRequest && errorCode(t, rr) != "CLIENT_ENCRYPTION_REQUIRED" {
				t.Errorf("code = %q", errorCode(t, rr))
			}
		})
	}
}

func TestPublicConfig_GhostFields(t *testing.T) {
	e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true", "STRIP_METADATA": "true"})
	rr := httptest.NewRecorder()
	PublicConfigHandler(e.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	var raw map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"anonymous_mode", "client_encryption_required", "strip_metadata"} {
		if v, ok := raw[k].(bool); !ok || !v {
			t.Errorf("%s = %v, want true", k, raw[k])
		}
	}

	e = newGhostEnv(t, nil)
	rr = httptest.NewRecorder()
	PublicConfigHandler(e.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	raw = nil
	_ = json.Unmarshal(rr.Body.Bytes(), &raw)
	for _, k := range []string{"anonymous_mode", "client_encryption_required", "strip_metadata"} {
		if v, ok := raw[k].(bool); !ok || v {
			t.Errorf("default %s = %v, want false", k, raw[k])
		}
	}
}

// A PDF-typed upload whose metadata cannot be stripped must be rejected (and
// not stored) in anonymous mode, but accepted best-effort elsewhere.
func TestMetadataStripFailsClosedInAnonymousMode(t *testing.T) {
	badPDF := []byte("%PDF-1.4\nthis is not a parseable pdf body\n")

	t.Run("anonymous rejects", func(t *testing.T) {
		e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true", "STRIP_METADATA": "true"})
		rr := postUpload(t, UploadHandler(e.repos, e.cfg), badPDF, "a.pdf", map[string]string{"client_encrypted": "true"})
		if rr.Code != http.StatusUnprocessableEntity || errorCode(t, rr) != "METADATA_STRIP_FAILED" {
			t.Fatalf("status/code = %d/%q, want 422/METADATA_STRIP_FAILED; body %s", rr.Code, errorCode(t, rr), rr.Body.String())
		}
		files, _ := storedFiles(e.cfg.UploadDir)
		if len(files) != 0 {
			t.Errorf("rejected upload left %d file(s) on disk", len(files))
		}
	})

	t.Run("normal mode stays best-effort", func(t *testing.T) {
		e := newGhostEnv(t, map[string]string{"STRIP_METADATA": "true"})
		rr := postUpload(t, UploadHandler(e.repos, e.cfg), badPDF, "a.pdf", nil)
		if rr.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201; body %s", rr.Code, rr.Body.String())
		}
	})
}

func TestAnonymousMode_NoPlaintextHashStored(t *testing.T) {
	for _, anon := range []bool{true, false} {
		env := map[string]string{"REQUIRE_CLIENT_ENCRYPTION": "false"}
		if anon {
			env["ANONYMOUS_MODE"] = "true"
		}
		e := newGhostEnv(t, env)
		rr := postUpload(t, UploadHandler(e.repos, e.cfg), []byte("hash me"), "h.txt", nil)
		if rr.Code != http.StatusCreated {
			t.Fatalf("anon=%v status = %d; %s", anon, rr.Code, rr.Body.String())
		}
		var resp models.UploadResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		f, err := e.repos.Files.GetByClaimCode(context.Background(), resp.ClaimCode)
		if err != nil || f == nil {
			t.Fatalf("lookup: %v %v", f, err)
		}
		if anon && f.SHA256Hash != "" {
			t.Errorf("anonymous mode stored sha256_hash %q", f.SHA256Hash)
		}
		if !anon && len(f.SHA256Hash) != 64 {
			t.Errorf("normal mode sha256_hash = %q, want 64 hex chars", f.SHA256Hash)
		}

		// /api/claim/{code}/info must omit the hash when it is not recorded.
		req := httptest.NewRequest(http.MethodGet, "/api/claim/"+resp.ClaimCode+"/info", nil)
		irr := httptest.NewRecorder()
		ClaimInfoHandler(e.repos, e.cfg).ServeHTTP(irr, req)
		if irr.Code != http.StatusOK {
			t.Fatalf("info status = %d; %s", irr.Code, irr.Body.String())
		}
		var info map[string]interface{}
		_ = json.Unmarshal(irr.Body.Bytes(), &info)
		_, has := info["sha256_hash"]
		if anon && has {
			t.Error("info response includes sha256_hash in anonymous mode")
		}
		if !anon && !has {
			t.Error("info response lacks sha256_hash in normal mode")
		}
	}
}

func TestAnonymousMode_RefusesToEnableEgressFeatures(t *testing.T) {
	e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true"})
	h := AdminUpdateFeatureFlagsHandler(e.repos, e.cfg)
	for _, field := range []string{"enable_webhooks", "enable_sso"} {
		body, _ := json.Marshal(map[string]bool{field: true})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/api/admin/features", bytes.NewReader(body)))
		if rr.Code != http.StatusConflict || errorCode(t, rr) != "DISABLED_IN_ANONYMOUS_MODE" {
			t.Errorf("%s: status/code = %d/%q, want 409/DISABLED_IN_ANONYMOUS_MODE", field, rr.Code, errorCode(t, rr))
		}
	}
	if e.cfg.Features.IsWebhooksEnabled() || e.cfg.Features.IsSSOEnabled() {
		t.Error("feature flags were changed despite the refusal")
	}

	// Disabling, and unrelated features, still work.
	body, _ := json.Marshal(map[string]bool{"enable_webhooks": false, "enable_api_tokens": true})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/api/admin/features", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Errorf("unrelated update status = %d; %s", rr.Code, rr.Body.String())
	}

	// SSO config endpoint too.
	sso := AdminUpdateSSOConfigHandler(e.repos, e.cfg)
	body, _ = json.Marshal(map[string]bool{"enabled": true})
	rr = httptest.NewRecorder()
	sso.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/api/admin/config/sso", bytes.NewReader(body)))
	if rr.Code != http.StatusConflict {
		t.Errorf("SSO config enable status = %d, want 409", rr.Code)
	}
}

func TestAnonymizingHelpers(t *testing.T) {
	anon := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true"}).cfg
	if got := storeUserAgent("Mozilla", anon); got != "" {
		t.Errorf("storeUserAgent anon = %q", got)
	}
	if got := logUserAgent("Mozilla", anon); got != "redacted" {
		t.Errorf("logUserAgent anon = %q", got)
	}
	if got := logFilename("secret.pdf", anon); got != "[redacted]" {
		t.Errorf("logFilename anon = %q", got)
	}
	if got := storeSHA256("abc", anon); got != "" {
		t.Errorf("storeSHA256 anon = %q", got)
	}
	normal := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "false"}).cfg
	if storeUserAgent("Mozilla", normal) != "Mozilla" || logUserAgent("Mozilla", normal) != "Mozilla" ||
		logFilename("a.pdf", normal) != "a.pdf" || storeSHA256("abc", normal) != "abc" {
		t.Error("normal mode must pass values through unchanged")
	}
}

func TestChunkedAssembly_MetadataStripFailureFailsClosedInAnonymousMode(t *testing.T) {
	for _, anon := range []bool{true, false} {
		env := map[string]string{"STRIP_METADATA": "true", "REQUIRE_CLIENT_ENCRYPTION": "false"}
		if anon {
			env["ANONYMOUS_MODE"] = "true"
		}
		e := newGhostEnv(t, env)
		ctx := context.Background()
		uploadID := "550e8400-e29b-41d4-a716-4466554400a" + map[bool]string{true: "1", false: "2"}[anon]
		pu := &models.PartialUpload{
			UploadID: uploadID, Filename: "doc.pdf", TotalSize: 2048, ChunkSize: 1024, TotalChunks: 2,
			ExpiresInHours: 24, CreatedAt: time.Now(), LastActivity: time.Now(),
		}
		if err := e.repos.PartialUploads.Create(ctx, pu); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(e.cfg.UploadDir, ".partial", uploadID)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		first := append([]byte("%PDF-1.4\nnot a parseable pdf\n"), bytes.Repeat([]byte("A"), 1024)...)[:1024]
		os.WriteFile(filepath.Join(dir, "chunk_0"), first, 0644)
		os.WriteFile(filepath.Join(dir, "chunk_1"), bytes.Repeat([]byte("B"), 1024), 0644)

		rr := httptest.NewRecorder()
		UploadCompleteHandler(e.repos, e.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/upload/complete/"+uploadID, nil))
		if rr.Code != http.StatusAccepted {
			t.Fatalf("anon=%v complete status = %d; %s", anon, rr.Code, rr.Body.String())
		}
		var got *models.PartialUpload
		for i := 0; i < 100; i++ {
			got, _ = e.repos.PartialUploads.GetByUploadID(ctx, uploadID)
			if got != nil && got.Status != "processing" {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if got == nil {
			t.Fatal("upload vanished")
		}
		if anon {
			if got.Status != "failed" || got.ErrorCode == nil || *got.ErrorCode != "METADATA_STRIP_FAILED" || got.ErrorRetryable {
				t.Errorf("anonymous: status=%q code=%v retryable=%v, want failed/METADATA_STRIP_FAILED/terminal", got.Status, got.ErrorCode, got.ErrorRetryable)
			}
			files, _ := storedFiles(e.cfg.UploadDir)
			if len(files) != 0 {
				t.Errorf("failed assembly left %d stored file(s)", len(files))
			}
		} else if got.Status != "completed" {
			t.Errorf("normal mode: status=%q, want completed (best-effort)", got.Status)
		}
	}
}

func TestChunkedChunkAndComplete_RejectPlaintextSessionWhenRequired(t *testing.T) {
	e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true"})
	uploadID := "550e8400-e29b-41d4-a716-4466554400b1"
	pu := &models.PartialUpload{
		UploadID: uploadID, Filename: "f.bin", TotalSize: 2048, ChunkSize: 1024, TotalChunks: 2,
		ExpiresInHours: 24, CreatedAt: time.Now(), LastActivity: time.Now(), ClientEncrypted: false,
	}
	if err := e.repos.PartialUploads.Create(context.Background(), pu); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	UploadCompleteHandler(e.repos, e.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/upload/complete/"+uploadID, nil))
	if rr.Code != http.StatusBadRequest || errorCode(t, rr) != "CLIENT_ENCRYPTION_REQUIRED" {
		t.Errorf("complete: %d %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	UploadChunkHandler(e.repos, e.cfg).ServeHTTP(rr, chunkTestRequest(t, uploadID, 0, bytes.Repeat([]byte("x"), 1024)))
	if rr.Code != http.StatusBadRequest || errorCode(t, rr) != "CLIENT_ENCRYPTION_REQUIRED" {
		t.Errorf("chunk: %d %s", rr.Code, rr.Body.String())
	}
}

func TestAnonymousMode_LogsCarryNoFilenameOrClaimCode(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	privacy.SetAnonymousMode(true)
	t.Cleanup(func() { slog.SetDefault(prev); privacy.SetAnonymousMode(false) })

	e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true"})
	rr := postUpload(t, UploadHandler(e.repos, e.cfg), []byte("payload"), "very-secret-name.pdf", map[string]string{"client_encrypted": "true"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("upload status = %d; %s", rr.Code, rr.Body.String())
	}
	var resp models.UploadResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	out := buf.String()
	if out == "" {
		t.Fatal("expected some log output")
	}
	for _, secret := range []string{"very-secret-name", resp.ClaimCode, resp.ClaimCode[:3] + "..."} {
		if strings.Contains(out, secret) {
			t.Errorf("anonymous-mode log leaks %q:\n%s", secret, out)
		}
	}
}

type fakeWebhookDB struct{ cfgs []*webhooks.Config }

func (f *fakeWebhookDB) GetEnabledWebhookConfigs() ([]*webhooks.Config, error) { return f.cfgs, nil }
func (f *fakeWebhookDB) CreateWebhookDelivery(d *webhooks.Delivery) error      { return nil }
func (f *fakeWebhookDB) UpdateWebhookDelivery(d *webhooks.Delivery) error      { return nil }
func (f *fakeWebhookDB) GetWebhookConfig(id int64) (*webhooks.Config, error)   { return nil, nil }
func (f *fakeWebhookDB) GetPendingRetries() ([]*webhooks.Delivery, error)      { return nil, nil }

type nopWebhookMetrics struct{}

func (nopWebhookMetrics) RecordEvent(string)                           {}
func (nopWebhookMetrics) RecordDelivery(string, string)                {}
func (nopWebhookMetrics) RecordDeliveryDuration(string, time.Duration) {}
func (nopWebhookMetrics) RecordRetry(string)                           {}
func (nopWebhookMetrics) RecordDroppedEvent()                          {}
func (nopWebhookMetrics) SetQueueSize(int)                             {}

// An enabled webhook config must produce no delivery when anonymous mode is
// on, or when the Webhooks feature flag is off; it does when allowed.
func TestEmitWebhookEvent_RespectsAnonymousModeAndFeatureFlag(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	prevAllow := webhooks.SetAllowPrivateNetworks(true)
	defer webhooks.SetAllowPrivateNetworks(prevAllow)

	tests := []struct {
		name     string
		env      map[string]string
		flagOn   bool
		wantHits int32
	}{
		{"normal mode, flag on delivers", nil, true, 1},
		{"normal mode, flag off does not", nil, false, 0},
		{"anonymous mode never delivers", map[string]string{"ANONYMOUS_MODE": "true"}, true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newGhostEnv(t, tt.env)
			e.cfg.Features.SetWebhooksEnabled(tt.flagOn)
			hits.Store(0)

			d := webhooks.NewDispatcher(&fakeWebhookDB{cfgs: []*webhooks.Config{{
				ID: 1, URL: srv.URL, Enabled: true, Format: webhooks.FormatSafeShare, Events: []string{string(webhooks.EventFileUploaded)},
				MaxRetries: 0, TimeoutSeconds: 5,
			}}}, 1, 10, nopWebhookMetrics{})
			d.Start()
			SetWebhookDispatcher(d)
			SetWebhookEmitGate(func() bool { return !e.cfg.IsAnonymousMode() && e.cfg.Features.IsWebhooksEnabled() })
			t.Cleanup(func() {
				SetWebhookEmitGate(nil)
				SetWebhookDispatcher(nil)
				d.Shutdown()
			})

			EmitWebhookEvent(&webhooks.Event{Type: webhooks.EventFileUploaded, Timestamp: time.Now()})
			deadline := time.Now().Add(2 * time.Second)
			for hits.Load() < tt.wantHits && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			time.Sleep(200 * time.Millisecond) // let any wrongly-emitted event land
			if got := hits.Load(); got != tt.wantHits {
				t.Errorf("deliveries = %d, want %d", got, tt.wantHits)
			}
		})
	}
}

func TestSSOProviderTest_RefusedInAnonymousMode(t *testing.T) {
	e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true"})
	rr := httptest.NewRecorder()
	AdminTestSSOProviderHandler(e.repos, e.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/admin/api/sso/providers/1/test", nil))
	if rr.Code != http.StatusConflict || errorCode(t, rr) != "DISABLED_IN_ANONYMOUS_MODE" {
		t.Errorf("got %d %s", rr.Code, rr.Body.String())
	}
}
