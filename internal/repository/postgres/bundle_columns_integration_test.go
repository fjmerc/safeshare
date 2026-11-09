//go:build integration
// +build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

func pgInsertRawBundle(t *testing.T, code string, fileCount int, userID *int64) int64 {
	t.Helper()
	var id int64
	err := testPool.QueryRow(context.Background(),
		`INSERT INTO bundles (bundle_code, file_count, upload_token_hash, expires_at, user_id)
		 VALUES ($1, $2, 'hash', $3, $4) RETURNING id`,
		code, fileCount, time.Now().Add(24*time.Hour), userID).Scan(&id)
	if err != nil {
		t.Fatalf("insert bundle: %v", err)
	}
	return id
}

func pgBundleTestFile(code string, userID, bundleID *int64, pos *int) *models.File {
	return &models.File{
		ClaimCode: code, OriginalFilename: code + ".png", StoredFilename: code + ".stored",
		FileSize: 10, MimeType: "image/png", ExpiresAt: time.Now().Add(24 * time.Hour),
		UploaderIP: "127.0.0.1", UserID: userID, BundleID: bundleID, BundlePosition: pos,
	}
}

func pgIntPtr(i int) *int { return &i }

func TestPGFileBundleColumnsRoundTrip(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()

	bid := pgInsertRawBundle(t, "bundleRT01", 3, nil)
	f := pgBundleTestFile("memberRT01", nil, &bid, pgIntPtr(2))
	if err := repos.Files.Create(ctx, f); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repos.Files.GetByID(ctx, f.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.BundleID == nil || *got.BundleID != bid || got.BundlePosition == nil || *got.BundlePosition != 2 {
		t.Fatalf("GetByID bundle fields = %v/%v", got.BundleID, got.BundlePosition)
	}
	all, _, err := repos.Files.GetAllForAdmin(ctx, 10, 0)
	if err != nil || len(all) != 1 || all[0].BundleID == nil || *all[0].BundleID != bid {
		t.Fatalf("GetAllForAdmin: %v %+v", err, all)
	}
	found, _, err := repos.Files.SearchForAdmin(ctx, "memberRT01", 10, 0)
	if err != nil || len(found) != 1 || found[0].BundlePosition == nil || *found[0].BundlePosition != 2 {
		t.Fatalf("SearchForAdmin: %v %+v", err, found)
	}
}

func TestPGGetByClaimCodeAndUserFiles_ExcludeBundleMembers(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	u, err := repos.Users.Create(ctx, "bundleowner", "owner@example.com", "hash", "user", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	uid := u.ID

	bid := pgInsertRawBundle(t, "bundleEX01", 1, &uid)
	member := pgBundleTestFile("memberEX01", &uid, &bid, pgIntPtr(0))
	plain := pgBundleTestFile("plainEX001", &uid, nil, nil)
	for _, f := range []*models.File{member, plain} {
		if err := repos.Files.Create(ctx, f); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	if got, err := repos.Files.GetByClaimCode(ctx, "memberEX01"); err != nil || got != nil {
		t.Fatalf("GetByClaimCode(member) = %v, %v", got, err)
	}
	list, total, err := repos.Users.GetFiles(ctx, uid, 50, 0)
	if err != nil || total != 1 || len(list) != 1 || list[0].ClaimCode != "plainEX001" {
		t.Fatalf("GetFiles = %d (total %d), err %v", len(list), total, err)
	}
	if f, err := repos.Users.DeleteFileByClaimCode(ctx, "memberEX01", uid); err == nil && f != nil {
		t.Error("DeleteFileByClaimCode deleted a bundle member")
	}
	if err := repos.Users.UpdateFileName(ctx, member.ID, uid, "x.png"); err == nil {
		t.Error("UpdateFileName renamed a bundle member")
	}
	if r, err := repos.Users.RegenerateClaimCode(ctx, member.ID, uid); err == nil && r != nil {
		t.Error("RegenerateClaimCode regenerated a bundle member")
	}
}

func TestPGBundleConstraints(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()

	bid := pgInsertRawBundle(t, "bundleDP01", 2, nil)
	if err := repos.Files.Create(ctx, pgBundleTestFile("memberDP01", nil, &bid, pgIntPtr(0))); err != nil {
		t.Fatalf("create first: %v", err)
	}
	err := repos.Files.Create(ctx, pgBundleTestFile("memberDP02", nil, &bid, pgIntPtr(0)))
	if !errors.Is(err, repository.ErrDuplicateKey) {
		t.Fatalf("duplicate position: err = %v, want ErrDuplicateKey", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM bundles WHERE id = $1`, bid); err == nil {
		t.Fatal("deleting a bundle with members succeeded; want FK error")
	}
}

func TestPGPartialUploadBundleFieldsRoundTrip(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	bid := pgInsertRawBundle(t, "bundlePU01", 2, nil)
	now := time.Now().UTC().Truncate(time.Second)
	up := &models.PartialUpload{
		UploadID: "pu-bundle-member", Filename: "a.png", TotalSize: 10, ChunkSize: 10, TotalChunks: 1,
		CreatedAt: now, LastActivity: now, BundleID: &bid, BundlePosition: pgIntPtr(1),
	}
	if err := repos.PartialUploads.Create(ctx, up); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repos.PartialUploads.GetByUploadID(ctx, "pu-bundle-member")
	if err != nil || got == nil || got.BundleID == nil || *got.BundleID != bid || got.BundlePosition == nil || *got.BundlePosition != 1 {
		t.Fatalf("GetByUploadID = %+v, %v", got, err)
	}
}
