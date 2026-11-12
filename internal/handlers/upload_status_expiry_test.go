package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/privacy"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// statusExpiry calls GET /api/upload/status/<id> and returns the reported expires_at.
func statusExpiry(t *testing.T, repos *repository.Repositories, cfg *config.Config, uploadID string) models.UploadStatusResponse {
	t.Helper()
	cfg.ChunkedUploadEnabled = true
	rr := httptest.NewRecorder()
	UploadStatusHandler(repos, cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/upload/status/"+uploadID, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d %s", rr.Code, rr.Body.String())
	}
	var resp models.UploadStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return resp
}

// storedFileExpiry is the expires_at the assembly published for the upload.
func storedFileExpiry(t *testing.T, repos *repository.Repositories, uploadID string) time.Time {
	t.Helper()
	var raw string
	if err := repos.DB.QueryRow(`SELECT expires_at FROM files WHERE partial_upload_id = ?`, uploadID).Scan(&raw); err != nil {
		t.Fatalf("published file row: %v", err)
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05"} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts
		}
	}
	t.Fatalf("unparseable expires_at %q", raw)
	return time.Time{}
}

func assembledUpload(t *testing.T, repos *repository.Repositories, cfg *config.Config, up *models.PartialUpload) {
	t.Helper()
	content := []byte("status expiry content")
	up.Filename, up.TotalSize, up.ChunkSize, up.TotalChunks = "e.txt", int64(len(content)), int64(len(content)), 1
	if err := repos.PartialUploads.Create(context.Background(), up); err != nil {
		t.Fatalf("create partial upload: %v", err)
	}
	if err := utils.SaveChunk(cfg.UploadDir, up.UploadID, 0, content); err != nil {
		t.Fatalf("save chunk: %v", err)
	}
	assembleUploadSync(t, repos, cfg, up)
}

func near(a, b time.Time) bool {
	d := a.Sub(b)
	return d > -2*time.Second && d < 2*time.Second
}

// A finished chunked upload must report when the FILE expires, not when the
// unfinished-upload session would have been cleaned up (LastActivity +
// PARTIAL_UPLOAD_EXPIRY_HOURS). Clients show this value to the uploader.
func TestUploadStatus_CompletedReportsFileExpiry(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("repos: %v", err)
	}

	cases := []struct {
		name  string
		id    string
		hours int
	}{
		{"two hours", "550e8400-e29b-41d4-a716-4466554400e1", 2},
		{"never expires", "550e8400-e29b-41d4-a716-4466554400e2", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			started := time.Now().Add(-30 * time.Minute)
			up := &models.PartialUpload{UploadID: tc.id, ExpiresInHours: tc.hours, CreatedAt: started, LastActivity: started}
			assembledUpload(t, repos, cfg, up)

			resp := statusExpiry(t, repos, cfg, tc.id)
			if resp.Status != "completed" {
				t.Fatalf("status = %q, want completed", resp.Status)
			}
			stored := storedFileExpiry(t, repos, tc.id)
			if !near(resp.ExpiresAt, stored) {
				t.Errorf("status expires_at = %v, stored file expires_at = %v", resp.ExpiresAt, stored)
			}
			if tc.hours > 0 && !near(resp.ExpiresAt, started.Add(time.Duration(tc.hours)*time.Hour)) {
				t.Errorf("expires_at = %v, want upload start + %dh (%v)", resp.ExpiresAt, tc.hours, started.Add(time.Duration(tc.hours)*time.Hour))
			}
			if tc.hours == 0 && time.Until(resp.ExpiresAt) < 90*365*24*time.Hour {
				t.Errorf("never-expire upload reports expires_at %v", resp.ExpiresAt)
			}
		})
	}
}

// While an upload is unfinished, expires_at keeps meaning "when this upload
// session is cleaned up if it goes quiet", which resuming clients rely on.
func TestUploadStatus_InProgressReportsSessionExpiry(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	now := time.Now()
	id := "550e8400-e29b-41d4-a716-4466554400e3"
	up := &models.PartialUpload{
		UploadID: id, Filename: "p.txt", TotalSize: 2048, ChunkSize: 1024, TotalChunks: 2,
		ExpiresInHours: 2, CreatedAt: now, LastActivity: now,
	}
	if err := repos.PartialUploads.Create(context.Background(), up); err != nil {
		t.Fatalf("create partial upload: %v", err)
	}
	resp := statusExpiry(t, repos, cfg, id)
	want := now.Add(time.Duration(cfg.PartialUploadExpiryHours) * time.Hour)
	if !near(resp.ExpiresAt, want) {
		t.Errorf("in-progress expires_at = %v, want session expiry %v", resp.ExpiresAt, want)
	}
}

// A finished bundle member reports its bundle's expiry, which is what its
// file row is stored with.
func TestUploadStatus_CompletedBundleMemberReportsBundleExpiry(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	bundleExpiry := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	res, err := db.Exec(`INSERT INTO bundles (bundle_code, file_count, upload_token_hash, expires_at)
		VALUES ('bundleEXP01', 1, 'hash', ?)`, bundleExpiry.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insert bundle: %v", err)
	}
	bundleID, _ := res.LastInsertId()
	pos := 0
	id := "550e8400-e29b-41d4-a716-4466554400e4"
	now := time.Now()
	// Production creates bundle members with ExpiresInHours = 0 (the bundle decides).
	up := &models.PartialUpload{UploadID: id, ExpiresInHours: 0, CreatedAt: now, LastActivity: now, BundleID: &bundleID, BundlePosition: &pos}
	assembledUpload(t, repos, cfg, up)

	resp := statusExpiry(t, repos, cfg, id)
	if resp.Status != "completed" {
		t.Fatalf("status = %q, want completed", resp.Status)
	}
	if !near(resp.ExpiresAt, bundleExpiry) {
		t.Errorf("bundle member expires_at = %v, want bundle expiry %v", resp.ExpiresAt, bundleExpiry)
	}
	if !near(resp.ExpiresAt, storedFileExpiry(t, repos, id)) {
		t.Errorf("bundle member expires_at %v differs from its stored file", resp.ExpiresAt)
	}
}

// In anonymous mode the stored expiry is rounded up to the hour; status must
// report exactly that value, not an unrounded one that would reveal when
// the upload started.
func TestUploadStatus_AnonymousModeReportsRoundedStoredExpiry(t *testing.T) {
	privacy.SetAnonymousMode(true)
	t.Cleanup(func() { privacy.SetAnonymousMode(false) })
	e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true"})
	if !e.cfg.IsAnonymousMode() {
		t.Fatal("test config is not in anonymous mode")
	}
	id := "550e8400-e29b-41d4-a716-4466554400e5"
	// Whole seconds, as the database keeps them: the worker rounds the
	// in-memory value, so sub-second parts could tip it into the next hour.
	now := time.Now().Truncate(time.Second)
	up := &models.PartialUpload{UploadID: id, ExpiresInHours: 2, CreatedAt: now, LastActivity: now, ClientEncrypted: true}
	assembledUpload(t, e.repos, e.cfg, up)

	resp := statusExpiry(t, e.repos, e.cfg, id)
	stored := storedFileExpiry(t, e.repos, id)
	if !resp.ExpiresAt.Equal(stored) {
		t.Errorf("status expires_at = %v, stored = %v", resp.ExpiresAt, stored)
	}
	if resp.ExpiresAt.Minute() != 0 || resp.ExpiresAt.Second() != 0 || resp.ExpiresAt.Nanosecond() != 0 {
		t.Errorf("expires_at %v is not on the hour", resp.ExpiresAt)
	}
}

// POSTing /complete again on a finished upload replays the completion
// response; its expires_at must match the stored file too.
func TestUploadComplete_ReplayReportsStoredExpiry(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	id := "550e8400-e29b-41d4-a716-4466554400e6"
	started := time.Now().Add(-10 * time.Minute)
	up := &models.PartialUpload{UploadID: id, ExpiresInHours: 5, CreatedAt: started, LastActivity: started}
	assembledUpload(t, repos, cfg, up)

	rr := httptest.NewRecorder()
	UploadCompleteHandler(repos, cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/upload/complete/"+id, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("replayed complete: %d %s", rr.Code, rr.Body.String())
	}
	var resp models.UploadCompleteResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if stored := storedFileExpiry(t, repos, id); !near(resp.ExpiresAt, stored) {
		t.Errorf("replayed complete expires_at = %v, stored = %v", resp.ExpiresAt, stored)
	}
}

// If the owner changes the file's expiry after the upload finished, status
// reports the new value, not the one the upload was created with.
func TestUploadStatus_ReportsEditedExpiry(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	id := "550e8400-e29b-41d4-a716-4466554400e7"
	now := time.Now()
	up := &models.PartialUpload{UploadID: id, ExpiresInHours: 2, CreatedAt: now, LastActivity: now}
	assembledUpload(t, repos, cfg, up)

	edited := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	if _, err := db.Exec(`UPDATE files SET expires_at = ? WHERE partial_upload_id = ?`, edited.Format(time.RFC3339), id); err != nil {
		t.Fatalf("edit expiry: %v", err)
	}
	if resp := statusExpiry(t, repos, cfg, id); !near(resp.ExpiresAt, edited) {
		t.Errorf("status expires_at = %v, want edited %v", resp.ExpiresAt, edited)
	}
}

// If the stored file can't be found by its claim code (regenerated, or
// expired under PostgreSQL), status still reports the file's expiry, not the
// upload session's.
func TestUploadStatus_FileLookupMissReportsCreatedExpiry(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	id := "550e8400-e29b-41d4-a716-4466554400e8"
	started := time.Now().Add(-20 * time.Minute)
	up := &models.PartialUpload{UploadID: id, ExpiresInHours: 3, CreatedAt: started, LastActivity: started}
	assembledUpload(t, repos, cfg, up)

	if _, err := db.Exec(`UPDATE files SET claim_code = 'regeneratedCode1' WHERE partial_upload_id = ?`, id); err != nil {
		t.Fatalf("regenerate claim code: %v", err)
	}
	if resp := statusExpiry(t, repos, cfg, id); !near(resp.ExpiresAt, started.Add(3*time.Hour)) {
		t.Errorf("status expires_at = %v, want created expiry %v", resp.ExpiresAt, started.Add(3*time.Hour))
	}
}
