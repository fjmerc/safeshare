package mock

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

func TestMockBundleRepository_Lifecycle(t *testing.T) {
	ctx := context.Background()
	files := NewFileRepository()
	bundles := NewBundleRepository(files)

	uid := int64(7)
	b := &models.Bundle{BundleCode: "mockbundle01", FileCount: 2, UploadTokenHash: "h", ExpiresAt: time.Now().Add(time.Hour), UserID: &uid}
	if err := bundles.Create(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := bundles.Create(ctx, &models.Bundle{BundleCode: "mockbundle01", FileCount: 1}); !errors.Is(err, repository.ErrDuplicateKey) {
		t.Fatalf("duplicate: %v", err)
	}
	for pos := 0; pos < 2; pos++ {
		p := pos
		files.AddFile(&models.File{ClaimCode: "m" + string(rune('0'+pos)), BundleID: &b.ID, BundlePosition: &p, ExpiresAt: time.Now().Add(time.Hour)})
		if pos == 0 {
			if err := bundles.Publish(ctx, b.ID, nil, time.Time{}); !errors.Is(err, repository.ErrInvalidInput) {
				t.Fatalf("publish incomplete: %v", err)
			}
		}
	}
	if err := bundles.Publish(ctx, b.ID, []byte("m"), time.Time{}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got, _ := bundles.GetPublishedByCode(ctx, "mockbundle01"); got == nil || string(got.EncryptedManifest) != "m" {
		t.Fatalf("GetPublishedByCode = %+v", got)
	}
	if m, _ := bundles.GetMember(ctx, b.ID, 1); m == nil || m.ClaimCode != "m1" {
		t.Fatalf("GetMember = %+v", m)
	}
	if f, _ := files.GetByClaimCode(ctx, "m0"); f != nil {
		t.Fatal("member reachable by claim code")
	}
	deleted, err := bundles.DeleteWithMembers(ctx, b.ID)
	if err != nil || len(deleted) != 2 {
		t.Fatalf("DeleteWithMembers = %d, %v", len(deleted), err)
	}
	if got, _ := bundles.GetByID(ctx, b.ID); got != nil {
		t.Fatal("bundle not deleted")
	}
}
