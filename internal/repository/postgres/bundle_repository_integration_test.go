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

func pgNewBundle(code string, fileCount int, userID *int64) *models.Bundle {
	max := 3
	return &models.Bundle{
		BundleCode: code, FileCount: fileCount, UploadTokenHash: "h-" + code,
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second), MaxDownloads: &max,
		PasswordHash: "pw", UserID: userID, ClientEncrypted: true, UploaderIP: "10.0.0.1",
	}
}

func pgAddMember(t *testing.T, repos *repository.Repositories, b *models.Bundle, pos int, scan string) *models.File {
	t.Helper()
	f := pgBundleTestFile(b.BundleCode+"-m"+string(rune('0'+pos)), b.UserID, &b.ID, pgIntPtr(pos))
	f.ScanStatus = scan
	if err := repos.Files.Create(context.Background(), f); err != nil {
		t.Fatalf("create member: %v", err)
	}
	return f
}

func TestPGBundleCreatePublishGet(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()

	b := pgNewBundle("bundleCP01", 2, nil)
	if err := repos.Bundles.Create(ctx, b); err != nil || b.ID == 0 {
		t.Fatalf("create: %v", err)
	}
	if err := repos.Bundles.Create(ctx, pgNewBundle("bundleCP01", 1, nil)); !errors.Is(err, repository.ErrDuplicateKey) {
		t.Fatalf("duplicate: %v", err)
	}
	got, err := repos.Bundles.GetByID(ctx, b.ID)
	if err != nil || got == nil || got.Status != models.BundleStatusDraft || !got.ExpiresAt.Equal(b.ExpiresAt) ||
		got.MaxDownloads == nil || *got.MaxDownloads != 3 || !got.ClientEncrypted || got.UploaderIP != "10.0.0.1" {
		t.Fatalf("round trip: %+v %v", got, err)
	}

	pgAddMember(t, repos, b, 0, "")
	if err := repos.Bundles.Publish(ctx, b.ID, nil, time.Time{}); !errors.Is(err, repository.ErrInvalidInput) {
		t.Fatalf("publish incomplete: %v", err)
	}
	if got, _ := repos.Bundles.GetPublishedByCode(ctx, "bundleCP01"); got != nil {
		t.Fatal("draft visible")
	}
	pgAddMember(t, repos, b, 1, "pending")
	if err := repos.Bundles.Publish(ctx, b.ID, nil, time.Time{}); !errors.Is(err, repository.ErrInvalidInput) {
		t.Fatalf("publish with pending member: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE files SET scan_status = 'clean' WHERE bundle_id = $1`, b.ID); err != nil {
		t.Fatal(err)
	}
	if err := repos.Bundles.Publish(ctx, b.ID, []byte{9}, time.Time{}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := repos.Bundles.Publish(ctx, b.ID, nil, time.Time{}); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("second publish: %v", err)
	}
	pub, err := repos.Bundles.GetPublishedByCode(ctx, "bundleCP01")
	if err != nil || pub == nil || pub.PublishedAt == nil || string(pub.EncryptedManifest) != "\x09" {
		t.Fatalf("published: %+v %v", pub, err)
	}
	if m, err := repos.Bundles.GetMember(ctx, b.ID, 1); err != nil || m == nil || *m.BundlePosition != 1 {
		t.Fatalf("GetMember: %+v %v", m, err)
	}
	list, err := repos.Bundles.ListMembers(ctx, b.ID)
	if err != nil || len(list) != 2 || *list[0].BundlePosition != 0 {
		t.Fatalf("ListMembers: %v %v", list, err)
	}
}

func TestPGBundleOwnerOpsAndDelete(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	u, err := repos.Users.Create(ctx, "bundleowner", "o@example.com", "hash", "user", false)
	if err != nil {
		t.Fatal(err)
	}
	uid := u.ID

	b := pgNewBundle("bundleOO01", 1, &uid)
	repos.Bundles.Create(ctx, b)
	m := pgAddMember(t, repos, b, 0, "")
	if err := repos.Bundles.Publish(ctx, b.ID, nil, time.Time{}); err != nil {
		t.Fatal(err)
	}
	list, total, err := repos.Bundles.ListByUser(ctx, uid, 10, 0)
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("ListByUser: %d %d %v", len(list), total, err)
	}

	newExp := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	if err := repos.Bundles.UpdateExpiration(ctx, b.ID, uid+100, newExp); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("wrong owner: %v", err)
	}
	if err := repos.Bundles.UpdateExpiration(ctx, b.ID, uid, newExp); err != nil {
		t.Fatal(err)
	}
	if gm, _ := repos.Files.GetByID(ctx, m.ID); !gm.ExpiresAt.Equal(newExp) {
		t.Fatalf("member expiry %v, want %v", gm.ExpiresAt, newExp)
	}

	repos.Bundles.Create(ctx, pgNewBundle("bundleOO02", 1, nil))
	if err := repos.Bundles.RegenerateCode(ctx, b.ID, uid, "bundleOO02"); !errors.Is(err, repository.ErrDuplicateKey) {
		t.Fatalf("collision: %v", err)
	}
	if err := repos.Bundles.RegenerateCode(ctx, b.ID, uid, "bundleOO03"); err != nil {
		t.Fatal(err)
	}

	taken, err := repos.Bundles.MemberPositionTaken(ctx, b.ID, 0)
	if err != nil || !taken {
		t.Fatalf("MemberPositionTaken(0) = %v %v", taken, err)
	}

	deleted, err := repos.Bundles.DeleteWithMembers(ctx, b.ID)
	if err != nil || len(deleted) != 1 || deleted[0].StoredFilename == "" {
		t.Fatalf("DeleteWithMembers: %+v %v", deleted, err)
	}
	if got, _ := repos.Bundles.GetByID(ctx, b.ID); got != nil {
		t.Fatal("bundle not deleted")
	}
}

func TestPGBundleCleanupLists(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()

	old := pgNewBundle("bundleCL01", 1, nil)
	old.CreatedAt = time.Now().Add(-48 * time.Hour)
	repos.Bundles.Create(ctx, old)
	repos.Bundles.Create(ctx, pgNewBundle("bundleCL02", 1, nil))
	ids, err := repos.Bundles.ListAbandonedDrafts(ctx, time.Now().Add(-24*time.Hour))
	if err != nil || len(ids) != 1 || ids[0] != old.ID {
		t.Fatalf("ListAbandonedDrafts = %v %v", ids, err)
	}

	empty := pgNewBundle("bundleCL03", 1, nil)
	repos.Bundles.Create(ctx, empty)
	m := pgAddMember(t, repos, empty, 0, "")
	repos.Bundles.Publish(ctx, empty.ID, nil, time.Time{})
	if err := repos.Files.Delete(ctx, m.ID); err != nil {
		t.Fatal(err)
	}
	ids, err = repos.Bundles.ListEmptyPublished(ctx)
	if err != nil || len(ids) != 1 || ids[0] != empty.ID {
		t.Fatalf("ListEmptyPublished = %v %v", ids, err)
	}
}

func TestPGBundleIDForMemberClaimCode(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	b := pgNewBundle("bundleMC01", 1, nil)
	repos.Bundles.Create(ctx, b)
	m := pgAddMember(t, repos, b, 0, "")
	repos.Files.Create(ctx, pgBundleTestFile("plainMC001", nil, nil, nil))

	if id, ok, err := repos.Bundles.BundleIDForMemberClaimCode(ctx, m.ClaimCode); err != nil || !ok || id != b.ID {
		t.Fatalf("member: %d %v %v", id, ok, err)
	}
	for _, code := range []string{"plainMC001", "nosuchcode"} {
		if _, ok, err := repos.Bundles.BundleIDForMemberClaimCode(ctx, code); err != nil || ok {
			t.Fatalf("%s: %v %v", code, ok, err)
		}
	}
}
