package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// TestServeClaimedFile_DirectCall: the claim pipeline extracted from
// ClaimHandler must enforce the password and the download limit on a file
// it is handed directly (the bundle routes find files by other means).
func TestServeClaimedFile_DirectCall(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	ctx := context.Background()

	body := []byte("direct call body")
	stored := "direct-call.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, stored), body, 0o644); err != nil {
		t.Fatal(err)
	}
	hash, err := utils.HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	maxDL := 1
	file := &models.File{
		ClaimCode: "directcall01", OriginalFilename: "d.bin", StoredFilename: stored,
		FileSize: int64(len(body)), MimeType: "application/octet-stream",
		ExpiresAt: time.Now().Add(time.Hour), MaxDownloads: &maxDL, PasswordHash: hash, UploaderIP: "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatal(err)
	}

	call := func(password string) *httptest.ResponseRecorder {
		fresh, err := repos.Files.GetByID(ctx, file.ID)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/anything", nil)
		if password != "" {
			req.Header.Set("X-File-Password", password)
		}
		rr := httptest.NewRecorder()
		serveClaimedFile(rr, req, repos, cfg, fresh)
		return rr
	}

	if rr := call("wrong"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: status %d, want 401", rr.Code)
	}
	rr := call("pw")
	if rr.Code != http.StatusOK || rr.Body.String() != string(body) {
		t.Fatalf("right password: status %d body %q", rr.Code, rr.Body.String())
	}
	if rr := call("pw"); rr.Code != http.StatusGone {
		t.Fatalf("second download: status %d, want 410", rr.Code)
	}
}

// TestClaimInfoPayload: the info map the bundle info route reuses must carry
// the same fields /api/claim/{code}/info returns.
func TestClaimInfoPayload(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)
	maxDL := 2
	file := &models.File{
		ClaimCode: "payload01", OriginalFilename: "p.txt", FileSize: 5, MimeType: "text/plain",
		ExpiresAt: time.Now().Add(time.Hour), MaxDownloads: &maxDL, DownloadCount: 2, SHA256Hash: "abc",
	}
	req := httptest.NewRequest(http.MethodGet, "/api/claim/payload01/info", nil)
	got := claimInfoPayload(req, cfg, file)

	for _, key := range []string{"claim_code", "original_filename", "file_size", "mime_type", "created_at", "expires_at",
		"max_downloads", "download_count", "completed_downloads", "download_limit_reached", "password_required",
		"download_url", "client_encrypted", "scan_status", "download_available", "sha256_hash"} {
		if _, ok := got[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}
	if got["download_limit_reached"] != true || got["password_required"] != false || got["sha256_hash"] != "abc" {
		t.Errorf("wrong values: %+v", got)
	}
}
