package sqlite

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// insertRawBundle inserts a draft bundle row directly (the bundle repository
// arrives in a later task) and returns its id.
func insertRawBundle(t *testing.T, db *sql.DB, code string, fileCount int, userID *int64) int64 {
	t.Helper()
	res, err := db.Exec(`INSERT INTO bundles (bundle_code, file_count, upload_token_hash, expires_at, user_id)
		VALUES (?, ?, 'hash', ?, ?)`, code, fileCount, time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339), userID)
	if err != nil {
		t.Fatalf("insert bundle: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func newColumnsTestFile(code string, userID *int64, bundleID *int64, pos *int) *models.File {
	return &models.File{
		ClaimCode:        code,
		OriginalFilename: code + ".png",
		StoredFilename:   code + ".stored",
		FileSize:         10,
		MimeType:         "image/png",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		UserID:           userID,
		BundleID:         bundleID,
		BundlePosition:   pos,
	}
}

func intPtr(i int) *int { return &i }

func TestFileBundleColumnsRoundTrip(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	bid := insertRawBundle(t, db, "bundleRT01", 3, nil)
	f := newColumnsTestFile("memberRT01", nil, &bid, intPtr(2))
	if err := repo.Create(ctx, f); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.GetByID(ctx, f.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.BundleID == nil || *got.BundleID != bid || got.BundlePosition == nil || *got.BundlePosition != 2 {
		t.Fatalf("GetByID bundle fields = %v/%v, want %d/2", got.BundleID, got.BundlePosition, bid)
	}

	all, _, err := repo.GetAllForAdmin(ctx, 10, 0)
	if err != nil {
		t.Fatalf("GetAllForAdmin: %v", err)
	}
	if len(all) != 1 || all[0].BundleID == nil || *all[0].BundleID != bid || all[0].BundlePosition == nil || *all[0].BundlePosition != 2 {
		t.Fatalf("GetAllForAdmin bundle fields wrong: %+v", all)
	}

	found, _, err := repo.SearchForAdmin(ctx, "memberRT01", 10, 0)
	if err != nil {
		t.Fatalf("SearchForAdmin: %v", err)
	}
	if len(found) != 1 || found[0].BundleID == nil || *found[0].BundleID != bid {
		t.Fatalf("SearchForAdmin bundle fields wrong: %+v", found)
	}

	plain := newColumnsTestFile("plainRT001", nil, nil, nil)
	if err := repo.Create(ctx, plain); err != nil {
		t.Fatalf("create plain: %v", err)
	}
	gotPlain, err := repo.GetByID(ctx, plain.ID)
	if err != nil {
		t.Fatalf("GetByID plain: %v", err)
	}
	if gotPlain.BundleID != nil || gotPlain.BundlePosition != nil {
		t.Fatalf("plain file has bundle fields: %v/%v", gotPlain.BundleID, gotPlain.BundlePosition)
	}
}

func TestGetByClaimCode_ExcludesBundleMembers(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	bid := insertRawBundle(t, db, "bundleEX01", 1, nil)
	member := newColumnsTestFile("memberEX01", nil, &bid, intPtr(0))
	plain := newColumnsTestFile("plainEX001", nil, nil, nil)
	for _, f := range []*models.File{member, plain} {
		if err := repo.Create(ctx, f); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	got, err := repo.GetByClaimCode(ctx, "memberEX01")
	if err != nil || got != nil {
		t.Fatalf("GetByClaimCode(member) = %v, %v; want nil, nil", got, err)
	}
	got, err = repo.GetByClaimCode(ctx, "plainEX001")
	if err != nil || got == nil {
		t.Fatalf("GetByClaimCode(plain) = %v, %v; want file", got, err)
	}
}

func createColumnsTestUser(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	u, err := NewUserRepository(db).Create(context.Background(), "bundleowner", "owner@example.com", "hash", "user", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u.ID
}

func TestUsersGetFiles_ExcludesBundleMembers(t *testing.T) {
	db := setupTestDB(t)
	files := NewFileRepository(db)
	users := NewUserRepository(db)
	ctx := context.Background()
	uid := createColumnsTestUser(t, db)

	bid := insertRawBundle(t, db, "bundleUG01", 2, &uid)
	for _, f := range []*models.File{
		newColumnsTestFile("plainUG001", &uid, nil, nil),
		newColumnsTestFile("memberUG01", &uid, &bid, intPtr(0)),
		newColumnsTestFile("memberUG02", &uid, &bid, intPtr(1)),
	} {
		if err := files.Create(ctx, f); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	list, total, err := users.GetFiles(ctx, uid, 50, 0)
	if err != nil {
		t.Fatalf("GetFiles: %v", err)
	}
	if total != 1 || len(list) != 1 || list[0].ClaimCode != "plainUG001" {
		t.Fatalf("GetFiles = %d files (total %d), want only the plain file", len(list), total)
	}
}

func TestUserFileOps_RefuseBundleMembers(t *testing.T) {
	db := setupTestDB(t)
	files := NewFileRepository(db)
	users := NewUserRepository(db)
	ctx := context.Background()
	uid := createColumnsTestUser(t, db)

	bid := insertRawBundle(t, db, "bundleOP01", 1, &uid)
	member := newColumnsTestFile("memberOP01", &uid, &bid, intPtr(0))
	if err := files.Create(ctx, member); err != nil {
		t.Fatalf("create: %v", err)
	}

	if f, err := users.GetFileByClaimCode(ctx, "memberOP01", uid); err == nil && f != nil {
		t.Errorf("GetFileByClaimCode returned a bundle member")
	}
	if f, err := users.DeleteFileByClaimCode(ctx, "memberOP01", uid); err == nil && f != nil {
		t.Errorf("DeleteFileByClaimCode deleted a bundle member")
	}
	if f, err := users.DeleteFile(ctx, member.ID, uid); err == nil && f != nil {
		t.Errorf("DeleteFile deleted a bundle member")
	}
	if err := users.UpdateFileNameByClaimCode(ctx, "memberOP01", uid, "x.png"); err == nil {
		t.Errorf("UpdateFileNameByClaimCode renamed a bundle member")
	}
	if err := users.UpdateFileName(ctx, member.ID, uid, "x.png"); err == nil {
		t.Errorf("UpdateFileName renamed a bundle member")
	}
	newExp := time.Now().Add(48 * time.Hour)
	if err := users.UpdateFileExpirationByClaimCode(ctx, "memberOP01", uid, newExp); err == nil {
		t.Errorf("UpdateFileExpirationByClaimCode changed a bundle member")
	}
	if err := users.UpdateFileExpiration(ctx, member.ID, uid, newExp); err == nil {
		t.Errorf("UpdateFileExpiration changed a bundle member")
	}
	if r, err := users.RegenerateClaimCodeByClaimCode(ctx, "memberOP01", uid); err == nil && r != nil {
		t.Errorf("RegenerateClaimCodeByClaimCode regenerated a bundle member")
	}
	if r, err := users.RegenerateClaimCode(ctx, member.ID, uid); err == nil && r != nil {
		t.Errorf("RegenerateClaimCode regenerated a bundle member")
	}

	got, err := files.GetByID(ctx, member.ID)
	if err != nil {
		t.Fatalf("member row gone: %v", err)
	}
	if got.ClaimCode != "memberOP01" || got.OriginalFilename != "memberOP01.png" {
		t.Fatalf("member row changed: %+v", got)
	}
}

func TestDuplicateBundlePositionRejected(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	bid := insertRawBundle(t, db, "bundleDP01", 2, nil)
	if err := repo.Create(ctx, newColumnsTestFile("memberDP01", nil, &bid, intPtr(0))); err != nil {
		t.Fatalf("create first: %v", err)
	}
	if err := repo.Create(ctx, newColumnsTestFile("memberDP02", nil, &bid, intPtr(0))); err == nil {
		t.Fatal("second member at the same position was accepted")
	}
}

func TestDeleteBundleWithMembersFails(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	bid := insertRawBundle(t, db, "bundleFK01", 1, nil)
	if err := repo.Create(ctx, newColumnsTestFile("memberFK01", nil, &bid, intPtr(0))); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM bundles WHERE id = ?`, bid); err == nil {
		t.Fatal("deleting a bundle with members succeeded; want FK error")
	}
}

func TestPartialUploadBundleFieldsRoundTrip(t *testing.T) {
	db := setupTestDB(t)
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	bid := insertRawBundle(t, db, "bundlePU01", 2, nil)
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		id       string
		bundleID *int64
		pos      *int
		quota    bool
	}{
		{"pu-bundle-plain", nil, nil, false},
		{"pu-bundle-member", &bid, intPtr(1), false},
		{"pu-bundle-member-quota", &bid, intPtr(0), true},
	} {
		up := &models.PartialUpload{
			UploadID: tc.id, Filename: "a.png", TotalSize: 10, ChunkSize: 10, TotalChunks: 1,
			CreatedAt: now, LastActivity: now, BundleID: tc.bundleID, BundlePosition: tc.pos,
		}
		var err error
		if tc.quota {
			err = repo.CreateWithQuotaCheck(ctx, up, 1<<40)
		} else {
			err = repo.Create(ctx, up)
		}
		if err != nil {
			t.Fatalf("%s: create: %v", tc.id, err)
		}
		got, err := repo.GetByUploadID(ctx, tc.id)
		if err != nil || got == nil {
			t.Fatalf("%s: get: %v", tc.id, err)
		}
		if (got.BundleID == nil) != (tc.bundleID == nil) || (got.BundleID != nil && *got.BundleID != *tc.bundleID) {
			t.Errorf("%s: BundleID = %v, want %v", tc.id, got.BundleID, tc.bundleID)
		}
		if (got.BundlePosition == nil) != (tc.pos == nil) || (got.BundlePosition != nil && *got.BundlePosition != *tc.pos) {
			t.Errorf("%s: BundlePosition = %v, want %v", tc.id, got.BundlePosition, tc.pos)
		}
	}
}
