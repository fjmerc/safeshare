package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/testutil"
)

func TestPublicConfig_MaxFilesPerBundle(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)
	cfg.MaxFilesPerBundle = 7
	rr := httptest.NewRecorder()
	PublicConfigHandler(cfg)(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["max_files_per_bundle"] != float64(7) {
		t.Fatalf("max_files_per_bundle = %v, want 7", body["max_files_per_bundle"])
	}
}
