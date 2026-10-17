package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// A caller-supplied CreatedAt is stored as given (anonymous mode passes an
// hour-rounded value); a zero CreatedAt keeps the database-stamped default.
func TestFileRepository_Create_HonoursSuppliedCreatedAt(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	want := time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)
	rounded := &models.File{
		ClaimCode: "rounded1", OriginalFilename: "a.txt", StoredFilename: "a-uuid", FileSize: 1,
		MimeType: "text/plain", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: want,
	}
	if err := repo.Create(ctx, rounded); err != nil {
		t.Fatalf("create rounded: %v", err)
	}
	got, err := repo.GetByClaimCode(ctx, "rounded1")
	if err != nil || got == nil {
		t.Fatalf("get rounded: %v %v", got, err)
	}
	if !got.CreatedAt.Equal(want) {
		t.Errorf("created_at = %v, want %v", got.CreatedAt, want)
	}

	before := time.Now().Add(-2 * time.Second)
	def := &models.File{
		ClaimCode: "default1", OriginalFilename: "b.txt", StoredFilename: "b-uuid", FileSize: 1,
		MimeType: "text/plain", ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := repo.Create(ctx, def); err != nil {
		t.Fatalf("create default: %v", err)
	}
	got, err = repo.GetByClaimCode(ctx, "default1")
	if err != nil || got == nil {
		t.Fatalf("get default: %v %v", got, err)
	}
	if got.CreatedAt.Before(before) || got.CreatedAt.After(time.Now().Add(2*time.Second)) {
		t.Errorf("default created_at = %v, want ~now", got.CreatedAt)
	}
}
