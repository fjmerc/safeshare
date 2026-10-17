package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/scanning/scanningtest"
)

// assembleChunked runs a two-chunk upload to completion through the real
// complete handler and assembly worker, returning the published file row.
func assembleChunked(t *testing.T, anon bool, sessionStart time.Time) *models.File {
	t.Helper()
	env := map[string]string{"STRIP_METADATA": "false", "REQUIRE_CLIENT_ENCRYPTION": "false"}
	if anon {
		env["ANONYMOUS_MODE"] = "true"
	}
	e := newGhostEnv(t, env)
	enableMalwareScan(e.cfg, scanningtest.New(t, scanningtest.ModeNormal))
	ctx := context.Background()

	uploadID := "550e8400-e29b-41d4-a716-4466554400c" + map[bool]string{true: "1", false: "2"}[anon]
	pu := &models.PartialUpload{
		UploadID: uploadID, Filename: "plain.txt", TotalSize: 2048, ChunkSize: 1024, TotalChunks: 2,
		ExpiresInHours: 24, CreatedAt: sessionStart, LastActivity: time.Now(),
	}
	if err := e.repos.PartialUploads.Create(ctx, pu); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(e.cfg.UploadDir, ".partial", uploadID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "chunk_0"), bytes.Repeat([]byte("A"), 1024), 0644)
	os.WriteFile(filepath.Join(dir, "chunk_1"), bytes.Repeat([]byte("B"), 1024), 0644)

	rr := httptest.NewRecorder()
	UploadCompleteHandler(e.repos, e.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/upload/complete/"+uploadID, nil))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("complete status = %d; %s", rr.Code, rr.Body.String())
	}
	var got *models.PartialUpload
	for i := 0; i < 100; i++ {
		got, _ = e.repos.PartialUploads.GetByUploadID(ctx, uploadID)
		if got != nil && got.Status != "processing" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got == nil || got.Status != "completed" || got.ClaimCode == nil {
		t.Fatalf("assembly did not complete: %+v", got)
	}
	f, err := e.repos.Files.GetByClaimCode(ctx, *got.ClaimCode)
	if err != nil || f == nil {
		t.Fatalf("lookup: %v %v", f, err)
	}
	return f
}

func TestAnonymousMode_ChunkedAssemblyStoresRoundedTimes(t *testing.T) {
	// Session started 90 minutes ago at an unaligned time, so the true expiry
	// (start + 24h) differs from both "now" and any hour boundary.
	start := time.Now().Add(-90 * time.Minute).Truncate(time.Second)
	before := time.Now()
	f := assembleChunked(t, true, start)
	after := time.Now()

	if !onHourUTC(f.CreatedAt) || f.CreatedAt.After(after) || before.Sub(f.CreatedAt) >= time.Hour+time.Second {
		t.Errorf("created_at = %v, want hour-aligned and within the hour before assembly", f.CreatedAt)
	}
	if f.ScannedAt == nil {
		t.Fatal("scanned_at not set; scan did not run")
	}
	if !onHourUTC(*f.ScannedAt) {
		t.Errorf("scanned_at = %v, want hour-aligned", *f.ScannedAt)
	}
	trueExpiry := start.Add(24 * time.Hour)
	if f.ExpiresAt.Before(trueExpiry) {
		t.Errorf("expires_at %v earlier than true expiry %v", f.ExpiresAt, trueExpiry)
	}
	if !f.ExpiresAt.Before(trueExpiry.Add(time.Hour)) {
		t.Errorf("expires_at %v is an hour or more past true expiry %v", f.ExpiresAt, trueExpiry)
	}
	if !onHourUTC(f.ExpiresAt) {
		t.Errorf("expires_at = %v, want hour-aligned", f.ExpiresAt)
	}
}

func TestNormalMode_ChunkedAssemblyKeepsExactTimes(t *testing.T) {
	start := time.Now().Add(-90 * time.Minute).Truncate(time.Second)
	f := assembleChunked(t, false, start)

	if f.ScannedAt == nil {
		t.Fatal("scanned_at not set; scan did not run")
	}
	if time.Since(*f.ScannedAt) > time.Minute || time.Since(f.CreatedAt) > time.Minute {
		t.Errorf("normal mode times look rounded: created %v scanned %v", f.CreatedAt, *f.ScannedAt)
	}
	if want := start.Add(24 * time.Hour); !f.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %v, want exactly %v", f.ExpiresAt, want)
	}
}
