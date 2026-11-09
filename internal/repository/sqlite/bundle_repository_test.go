package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

func newTestBundle(code string, fileCount int, userID *int64) *models.Bundle {
	max := 3
	return &models.Bundle{
		BundleCode:      code,
		Status:          models.BundleStatusDraft,
		FileCount:       fileCount,
		UploadTokenHash: "tokenhash-" + code,
		ExpiresAt:       time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
		MaxDownloads:    &max,
		PasswordHash:    "pwhash",
		UserID:          userID,
		ClientEncrypted: true,
		UploaderIP:      "10.0.0.1",
	}
}

type bundleFixture struct {
	db      *sql.DB
	bundles *BundleRepository
	files   *FileRepository
	ctx     context.Context
}

func newBundleFixture(t *testing.T) *bundleFixture {
	db := setupTestDB(t)
	return &bundleFixture{db: db, bundles: NewBundleRepository(db), files: NewFileRepository(db), ctx: context.Background()}
}

func (f *bundleFixture) create(t *testing.T, b *models.Bundle) *models.Bundle {
	t.Helper()
	if err := f.bundles.Create(f.ctx, b); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	return b
}

func (f *bundleFixture) addMember(t *testing.T, b *models.Bundle, pos int, scanStatus string) *models.File {
	t.Helper()
	m := newColumnsTestFile(b.BundleCode+"-m"+string(rune('0'+pos)), b.UserID, &b.ID, intPtr(pos))
	m.ScanStatus = scanStatus
	if err := f.files.Create(f.ctx, m); err != nil {
		t.Fatalf("create member: %v", err)
	}
	return m
}

func TestBundleCreateGet(t *testing.T) {
	f := newBundleFixture(t)
	b := f.create(t, newTestBundle("bundleCG01", 2, nil))
	if b.ID == 0 {
		t.Fatal("Create did not set ID")
	}

	got, err := f.bundles.GetByID(f.ctx, b.ID)
	if err != nil || got == nil {
		t.Fatalf("GetByID: %v %v", got, err)
	}
	if got.BundleCode != b.BundleCode || got.Status != models.BundleStatusDraft || got.FileCount != 2 ||
		got.UploadTokenHash != b.UploadTokenHash || !got.ExpiresAt.Equal(b.ExpiresAt) ||
		got.MaxDownloads == nil || *got.MaxDownloads != 3 || got.PasswordHash != "pwhash" ||
		!got.ClientEncrypted || got.UploaderIP != "10.0.0.1" || got.PublishedAt != nil || got.CreatedAt.IsZero() {
		t.Fatalf("round trip mismatch: %+v", got)
	}

	if missing, err := f.bundles.GetByID(f.ctx, 9999); err != nil || missing != nil {
		t.Fatalf("GetByID(missing) = %v, %v", missing, err)
	}

	dup := newTestBundle("bundleCG01", 1, nil)
	if err := f.bundles.Create(f.ctx, dup); !errors.Is(err, repository.ErrDuplicateKey) {
		t.Fatalf("duplicate code: err = %v, want ErrDuplicateKey", err)
	}
}

func TestBundleGetPublishedByCode_HidesDraftAndExpired(t *testing.T) {
	f := newBundleFixture(t)
	b := f.create(t, newTestBundle("bundlePB01", 1, nil))
	f.addMember(t, b, 0, "")

	if got, err := f.bundles.GetPublishedByCode(f.ctx, "bundlePB01"); err != nil || got != nil {
		t.Fatalf("draft visible: %v %v", got, err)
	}
	if err := f.bundles.Publish(f.ctx, b.ID, nil); err != nil {
		t.Fatalf("publish: %v", err)
	}
	got, err := f.bundles.GetPublishedByCode(f.ctx, "bundlePB01")
	if err != nil || got == nil || got.Status != models.BundleStatusPublished || got.PublishedAt == nil {
		t.Fatalf("published not visible: %+v %v", got, err)
	}

	expired := newTestBundle("bundlePB02", 1, nil)
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	f.create(t, expired)
	f.addMember(t, expired, 0, "")
	if err := f.bundles.Publish(f.ctx, expired.ID, nil); err != nil {
		t.Fatalf("publish expired: %v", err)
	}
	if got, err := f.bundles.GetPublishedByCode(f.ctx, "bundlePB02"); err != nil || got != nil {
		t.Fatalf("expired visible: %v %v", got, err)
	}
	if got, err := f.bundles.GetPublishedByCode(f.ctx, "nosuchcode"); err != nil || got != nil {
		t.Fatalf("unknown visible: %v %v", got, err)
	}
}

func TestBundlePublish_RequiresExactPositions(t *testing.T) {
	f := newBundleFixture(t)
	b := f.create(t, newTestBundle("bundlePX01", 3, nil))
	f.addMember(t, b, 0, "")
	f.addMember(t, b, 1, "")
	if err := f.bundles.Publish(f.ctx, b.ID, nil); !errors.Is(err, repository.ErrInvalidInput) {
		t.Fatalf("publish with 2 of 3: err = %v, want ErrInvalidInput", err)
	}

	gap := f.create(t, newTestBundle("bundlePX02", 2, nil))
	f.addMember(t, gap, 0, "")
	f.addMember(t, gap, 2, "")
	if err := f.bundles.Publish(f.ctx, gap.ID, nil); !errors.Is(err, repository.ErrInvalidInput) {
		t.Fatalf("publish with positions {0,2}: err = %v, want ErrInvalidInput", err)
	}

	f.addMember(t, b, 2, "")
	manifest := []byte{1, 2, 3}
	if err := f.bundles.Publish(f.ctx, b.ID, manifest); err != nil {
		t.Fatalf("publish complete bundle: %v", err)
	}
	got, _ := f.bundles.GetByID(f.ctx, b.ID)
	if string(got.EncryptedManifest) != string(manifest) {
		t.Fatalf("manifest = %v, want %v", got.EncryptedManifest, manifest)
	}
	if err := f.bundles.Publish(f.ctx, b.ID, nil); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("second publish: err = %v, want ErrNotFound", err)
	}
	if err := f.bundles.Publish(f.ctx, 9999, nil); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("publish missing: err = %v, want ErrNotFound", err)
	}
}

func TestBundlePublish_RejectsPendingOrInfectedMember(t *testing.T) {
	for _, status := range []string{"pending", "infected"} {
		f := newBundleFixture(t)
		b := f.create(t, newTestBundle("bundleSC01", 2, nil))
		f.addMember(t, b, 0, "clean")
		f.addMember(t, b, 1, status)
		if err := f.bundles.Publish(f.ctx, b.ID, nil); !errors.Is(err, repository.ErrInvalidInput) {
			t.Fatalf("%s member: err = %v, want ErrInvalidInput", status, err)
		}
	}
}

func TestBundleGetMemberAndListMembers(t *testing.T) {
	f := newBundleFixture(t)
	b := f.create(t, newTestBundle("bundleGM01", 2, nil))
	m1 := f.addMember(t, b, 1, "")
	m0 := f.addMember(t, b, 0, "")

	got, err := f.bundles.GetMember(f.ctx, b.ID, 1)
	if err != nil || got == nil || got.ID != m1.ID {
		t.Fatalf("GetMember(1) = %+v, %v", got, err)
	}
	if got, err := f.bundles.GetMember(f.ctx, b.ID, 5); err != nil || got != nil {
		t.Fatalf("GetMember(5) = %v, %v", got, err)
	}
	list, err := f.bundles.ListMembers(f.ctx, b.ID)
	if err != nil || len(list) != 2 || list[0].ID != m0.ID || list[1].ID != m1.ID {
		t.Fatalf("ListMembers order wrong: %v %v", list, err)
	}

	if _, err := f.db.Exec(`UPDATE files SET expires_at = ? WHERE id = ?`, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), m1.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := f.bundles.GetMember(f.ctx, b.ID, 1); err != nil || got != nil {
		t.Fatalf("GetMember(expired) = %v, %v", got, err)
	}
}

func TestBundleDeleteWithMembers(t *testing.T) {
	f := newBundleFixture(t)
	b := f.create(t, newTestBundle("bundleDM01", 2, nil))
	f.addMember(t, b, 0, "")
	f.addMember(t, b, 1, "")
	other := f.create(t, newTestBundle("bundleDM02", 1, nil))
	keep := f.addMember(t, other, 0, "")

	deleted, err := f.bundles.DeleteWithMembers(f.ctx, b.ID)
	if err != nil || len(deleted) != 2 {
		t.Fatalf("DeleteWithMembers = %d files, %v", len(deleted), err)
	}
	for _, d := range deleted {
		if d.StoredFilename == "" || d.ClaimCode == "" {
			t.Fatalf("deleted file missing stored name or code: %+v", d)
		}
	}
	if got, _ := f.bundles.GetByID(f.ctx, b.ID); got != nil {
		t.Fatal("bundle still exists")
	}
	var n int
	f.db.QueryRow(`SELECT COUNT(*) FROM files WHERE bundle_id = ?`, b.ID).Scan(&n)
	if n != 0 {
		t.Fatalf("%d member rows left", n)
	}
	if got, err := f.files.GetByID(f.ctx, keep.ID); err != nil || got == nil {
		t.Fatal("other bundle's member was deleted")
	}
	if _, err := f.bundles.DeleteWithMembers(f.ctx, b.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("second delete: err = %v, want ErrNotFound", err)
	}
}

func TestBundleListByUser(t *testing.T) {
	f := newBundleFixture(t)
	uid := createColumnsTestUser(t, f.db)
	other := int64(0)
	_ = other

	draft := f.create(t, newTestBundle("bundleLU01", 1, &uid))
	f.addMember(t, draft, 0, "")
	var published []*models.Bundle
	for _, code := range []string{"bundleLU02", "bundleLU03"} {
		b := f.create(t, newTestBundle(code, 1, &uid))
		f.addMember(t, b, 0, "")
		if err := f.bundles.Publish(f.ctx, b.ID, nil); err != nil {
			t.Fatal(err)
		}
		published = append(published, b)
	}
	anon := f.create(t, newTestBundle("bundleLU04", 1, nil))
	f.addMember(t, anon, 0, "")
	f.bundles.Publish(f.ctx, anon.ID, nil)

	list, total, err := f.bundles.ListByUser(f.ctx, uid, 50, 0)
	if err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("ListByUser = %d (total %d), %v", len(list), total, err)
	}
	if list[0].ID != published[1].ID || list[1].ID != published[0].ID {
		t.Fatalf("ListByUser not newest first: %d, %d", list[0].ID, list[1].ID)
	}
	page, total, _ := f.bundles.ListByUser(f.ctx, uid, 1, 1)
	if total != 2 || len(page) != 1 || page[0].ID != published[0].ID {
		t.Fatalf("pagination wrong: %+v total %d", page, total)
	}
}

func TestBundleUpdateExpiration_MirrorsToMembers(t *testing.T) {
	f := newBundleFixture(t)
	uid := createColumnsTestUser(t, f.db)
	b := f.create(t, newTestBundle("bundleUE01", 2, &uid))
	m0 := f.addMember(t, b, 0, "")
	m1 := f.addMember(t, b, 1, "")
	f.bundles.Publish(f.ctx, b.ID, nil)

	newExp := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	if err := f.bundles.UpdateExpiration(f.ctx, b.ID, uid, newExp); err != nil {
		t.Fatalf("UpdateExpiration: %v", err)
	}
	got, _ := f.bundles.GetByID(f.ctx, b.ID)
	if !got.ExpiresAt.Equal(newExp) {
		t.Fatalf("bundle expiry = %v, want %v", got.ExpiresAt, newExp)
	}
	for _, m := range []*models.File{m0, m1} {
		gm, _ := f.files.GetByID(f.ctx, m.ID)
		if !gm.ExpiresAt.Equal(newExp) {
			t.Fatalf("member expiry = %v, want %v", gm.ExpiresAt, newExp)
		}
	}
}

func TestBundleUpdateExpiration_WrongOwner(t *testing.T) {
	f := newBundleFixture(t)
	uid := createColumnsTestUser(t, f.db)
	b := f.create(t, newTestBundle("bundleUE02", 1, &uid))
	f.addMember(t, b, 0, "")
	f.bundles.Publish(f.ctx, b.ID, nil)
	if err := f.bundles.UpdateExpiration(f.ctx, b.ID, uid+100, time.Now().Add(time.Hour)); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("wrong owner: err = %v, want ErrNotFound", err)
	}
}

func TestBundleRegenerateCode(t *testing.T) {
	f := newBundleFixture(t)
	uid := createColumnsTestUser(t, f.db)
	b := f.create(t, newTestBundle("bundleRG01", 1, &uid))
	f.addMember(t, b, 0, "")
	f.bundles.Publish(f.ctx, b.ID, nil)
	taken := f.create(t, newTestBundle("bundleRG02", 1, nil))
	_ = taken

	if err := f.bundles.RegenerateCode(f.ctx, b.ID, uid+100, "bundleRG03"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("wrong owner: err = %v, want ErrNotFound", err)
	}
	if err := f.bundles.RegenerateCode(f.ctx, b.ID, uid, "bundleRG02"); !errors.Is(err, repository.ErrDuplicateKey) {
		t.Fatalf("collision: err = %v, want ErrDuplicateKey", err)
	}
	if err := f.bundles.RegenerateCode(f.ctx, b.ID, uid, "bundleRG03"); err != nil {
		t.Fatalf("RegenerateCode: %v", err)
	}
	if got, _ := f.bundles.GetPublishedByCode(f.ctx, "bundleRG01"); got != nil {
		t.Fatal("old code still resolves")
	}
	if got, _ := f.bundles.GetPublishedByCode(f.ctx, "bundleRG03"); got == nil || got.ID != b.ID {
		t.Fatal("new code does not resolve")
	}
}

func TestBundleListAbandonedDrafts(t *testing.T) {
	f := newBundleFixture(t)
	old := newTestBundle("bundleAD01", 1, nil)
	old.CreatedAt = time.Now().Add(-48 * time.Hour)
	f.create(t, old)
	f.create(t, newTestBundle("bundleAD02", 1, nil)) // fresh draft
	pubOld := newTestBundle("bundleAD03", 1, nil)
	pubOld.CreatedAt = time.Now().Add(-48 * time.Hour)
	f.create(t, pubOld)
	f.addMember(t, pubOld, 0, "")
	f.bundles.Publish(f.ctx, pubOld.ID, nil)

	ids, err := f.bundles.ListAbandonedDrafts(f.ctx, time.Now().Add(-24*time.Hour))
	if err != nil || len(ids) != 1 || ids[0] != old.ID {
		t.Fatalf("ListAbandonedDrafts = %v, %v; want [%d]", ids, err, old.ID)
	}
}

func TestBundleListEmptyPublished(t *testing.T) {
	f := newBundleFixture(t)
	full := f.create(t, newTestBundle("bundleEP01", 1, nil))
	f.addMember(t, full, 0, "")
	f.bundles.Publish(f.ctx, full.ID, nil)
	empty := f.create(t, newTestBundle("bundleEP02", 1, nil))
	m := f.addMember(t, empty, 0, "")
	f.bundles.Publish(f.ctx, empty.ID, nil)
	f.create(t, newTestBundle("bundleEP03", 1, nil)) // empty draft: not this list's job
	if err := f.files.Delete(f.ctx, m.ID); err != nil {
		t.Fatal(err)
	}

	ids, err := f.bundles.ListEmptyPublished(f.ctx)
	if err != nil || len(ids) != 1 || ids[0] != empty.ID {
		t.Fatalf("ListEmptyPublished = %v, %v; want [%d]", ids, err, empty.ID)
	}
}

func TestMemberPositionTaken_CountsPartialUploads(t *testing.T) {
	f := newBundleFixture(t)
	b := f.create(t, newTestBundle("bundleMP01", 3, nil))
	f.addMember(t, b, 0, "")
	now := time.Now().UTC()
	pu := &models.PartialUpload{UploadID: "mp-upload", Filename: "x", TotalSize: 1, ChunkSize: 1, TotalChunks: 1,
		CreatedAt: now, LastActivity: now, BundleID: &b.ID, BundlePosition: intPtr(1)}
	if err := NewPartialUploadRepository(f.db).Create(f.ctx, pu); err != nil {
		t.Fatal(err)
	}

	for pos, want := range map[int]bool{0: true, 1: true, 2: false} {
		got, err := f.bundles.MemberPositionTaken(f.ctx, b.ID, pos)
		if err != nil || got != want {
			t.Errorf("MemberPositionTaken(%d) = %v, %v; want %v", pos, got, err, want)
		}
	}
}

func TestBundleIDForMemberClaimCode(t *testing.T) {
	f := newBundleFixture(t)
	b := f.create(t, newTestBundle("bundleMC01", 1, nil))
	m := f.addMember(t, b, 0, "")
	plain := newColumnsTestFile("plainMC001", nil, nil, nil)
	if err := f.files.Create(f.ctx, plain); err != nil {
		t.Fatal(err)
	}

	id, ok, err := f.bundles.BundleIDForMemberClaimCode(f.ctx, m.ClaimCode)
	if err != nil || !ok || id != b.ID {
		t.Fatalf("member: %d %v %v", id, ok, err)
	}
	for _, code := range []string{"plainMC001", "nosuchcode"} {
		if _, ok, err := f.bundles.BundleIDForMemberClaimCode(f.ctx, code); err != nil || ok {
			t.Fatalf("%s: ok=%v err=%v", code, ok, err)
		}
	}
}
