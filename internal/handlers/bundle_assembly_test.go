package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// TestPublishAssemblyCopiesBundleFields: a chunked upload that belongs to a
// bundle must publish a files row that is still a member of that bundle,
// even though assembly can run with no request in hand.
func TestPublishAssemblyCopiesBundleFields(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	ctx := context.Background()

	res, err := db.Exec(`INSERT INTO bundles (bundle_code, file_count, upload_token_hash, expires_at)
		VALUES ('bundleASM01', 2, 'hash', ?)`, time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insert bundle: %v", err)
	}
	bundleID, _ := res.LastInsertId()
	pos := 1

	uploadID := "550e8400-e29b-41d4-a716-4466554400b1"
	content := []byte("bundle member content")
	up := &models.PartialUpload{
		UploadID: uploadID, Filename: "b.txt", TotalSize: int64(len(content)), ChunkSize: int64(len(content)),
		TotalChunks: 1, ExpiresInHours: 24, CreatedAt: time.Now(), LastActivity: time.Now(),
		BundleID: &bundleID, BundlePosition: &pos,
	}
	if err := repos.PartialUploads.Create(ctx, up); err != nil {
		t.Fatalf("create partial upload: %v", err)
	}
	if err := utils.SaveChunk(cfg.UploadDir, uploadID, 0, content); err != nil {
		t.Fatalf("save chunk: %v", err)
	}

	assembleUploadSync(t, repos, cfg, up)

	var gotBundle, gotPos *int64
	if err := db.QueryRow(`SELECT bundle_id, bundle_position FROM files WHERE partial_upload_id = ?`, uploadID).Scan(&gotBundle, &gotPos); err != nil {
		t.Fatalf("published file row: %v", err)
	}
	if gotBundle == nil || *gotBundle != bundleID || gotPos == nil || *gotPos != 1 {
		t.Fatalf("published file bundle fields = %v/%v, want %d/1", gotBundle, gotPos, bundleID)
	}
}
