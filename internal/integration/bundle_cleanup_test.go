package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

func cleanupTestBundle(t *testing.T, repos *repository.Repositories, uploadDir, code string, createdAt time.Time, members int) (*models.Bundle, []string) {
	t.Helper()
	ctx := context.Background()
	b := &models.Bundle{BundleCode: code, FileCount: members, UploadTokenHash: "h", CreatedAt: createdAt, ExpiresAt: time.Now().Add(24 * time.Hour)}
	if err := repos.Bundles.Create(ctx, b); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for i := 0; i < members; i++ {
		pos := i
		stored := code + "-" + string(rune('a'+i)) + ".dat"
		path := filepath.Join(uploadDir, stored)
		if err := os.WriteFile(path, []byte("member"), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
		f := &models.File{ClaimCode: code + "m" + string(rune('a'+i)), StoredFilename: stored, OriginalFilename: "m.txt",
			FileSize: 6, MimeType: "text/plain", ExpiresAt: b.ExpiresAt, UploaderIP: "127.0.0.1", BundleID: &b.ID, BundlePosition: &pos}
		if err := repos.Files.Create(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	return b, paths
}

func TestCleanup_RemovesAbandonedDraftsAndFiles(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	old, oldPaths := cleanupTestBundle(t, repos, cfg.UploadDir, "draftOld01", time.Now().Add(-48*time.Hour), 2)
	fresh, freshPaths := cleanupTestBundle(t, repos, cfg.UploadDir, "draftNew01", time.Now(), 1)

	result, err := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, 24)
	if err != nil {
		t.Fatal(err)
	}
	if result.BundlesDeleted != 1 {
		t.Fatalf("BundlesDeleted = %d, want 1", result.BundlesDeleted)
	}
	if got, _ := repos.Bundles.GetByID(ctx, old.ID); got != nil {
		t.Fatal("abandoned draft still exists")
	}
	for _, p := range oldPaths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("abandoned draft's file still on disk: %s", p)
		}
	}
	if got, _ := repos.Bundles.GetByID(ctx, fresh.ID); got == nil {
		t.Fatal("fresh draft was deleted")
	}
	if _, err := os.Stat(freshPaths[0]); err != nil {
		t.Fatal("fresh draft's file was deleted")
	}
}

func TestCleanup_RemovesEmptyPublishedBundles(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	empty, _ := cleanupTestBundle(t, repos, cfg.UploadDir, "pubEmpty01", time.Now(), 1)
	full, _ := cleanupTestBundle(t, repos, cfg.UploadDir, "pubFull001", time.Now(), 1)
	for _, b := range []*models.Bundle{empty, full} {
		if err := repos.Bundles.Publish(ctx, b.ID, nil, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	members, _ := repos.Bundles.ListMembers(ctx, empty.ID)
	if err := repos.Files.Delete(ctx, members[0].ID); err != nil {
		t.Fatal(err)
	}

	result, err := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, 24)
	if err != nil {
		t.Fatal(err)
	}
	if result.BundlesDeleted != 1 {
		t.Fatalf("BundlesDeleted = %d, want 1", result.BundlesDeleted)
	}
	if got, _ := repos.Bundles.GetByID(ctx, empty.ID); got != nil {
		t.Fatal("empty published bundle still exists")
	}
	if got, _ := repos.Bundles.GetByID(ctx, full.ID); got == nil {
		t.Fatal("bundle with members was deleted")
	}
}

// TestCleanup_DraftGraceCoversHourRounding: in Ghost mode created_at is
// rounded down to the hour, so a draft can look up to an hour older than
// it is. Cleanup allows that hour before treating a draft as abandoned.
func TestCleanup_DraftGraceCoversHourRounding(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	young, _ := cleanupTestBundle(t, repos, cfg.UploadDir, "draftRnd01", time.Now().Add(-24*time.Hour-30*time.Minute), 1)
	old, _ := cleanupTestBundle(t, repos, cfg.UploadDir, "draftRnd02", time.Now().Add(-25*time.Hour-30*time.Minute), 1)

	if _, err := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, 24); err != nil {
		t.Fatal(err)
	}
	if got, _ := repos.Bundles.GetByID(ctx, young.ID); got == nil {
		t.Error("a draft within the rounding hour was deleted")
	}
	if got, _ := repos.Bundles.GetByID(ctx, old.ID); got != nil {
		t.Error("a draft past the grace hour was kept")
	}
}
