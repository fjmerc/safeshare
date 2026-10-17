//go:build integration
// +build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// A caller-supplied CreatedAt is stored as given (anonymous mode passes an
// hour-rounded value); a zero CreatedAt keeps the database default.
func TestFileRepository_Create_HonoursSuppliedCreatedAt(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()

	want := time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)
	rounded := &models.File{
		ClaimCode: "pgrounded1", OriginalFilename: "a.txt", StoredFilename: "pg-a-uuid", FileSize: 1,
		MimeType: "text/plain", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: want,
	}
	if err := repos.Files.Create(ctx, rounded); err != nil {
		t.Fatalf("create rounded: %v", err)
	}
	if !rounded.CreatedAt.Equal(want) {
		t.Errorf("RETURNING created_at = %v, want %v", rounded.CreatedAt, want)
	}
	got, err := repos.Files.GetByClaimCode(ctx, "pgrounded1")
	if err != nil || got == nil {
		t.Fatalf("get rounded: %v %v", got, err)
	}
	if !got.CreatedAt.Equal(want) {
		t.Errorf("stored created_at = %v, want %v", got.CreatedAt, want)
	}

	before := time.Now().Add(-5 * time.Second)
	def := &models.File{
		ClaimCode: "pgdefault1", OriginalFilename: "b.txt", StoredFilename: "pg-b-uuid", FileSize: 1,
		MimeType: "text/plain", ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := repos.Files.Create(ctx, def); err != nil {
		t.Fatalf("create default: %v", err)
	}
	got, err = repos.Files.GetByClaimCode(ctx, "pgdefault1")
	if err != nil || got == nil {
		t.Fatalf("get default: %v %v", got, err)
	}
	if got.CreatedAt.Before(before) || got.CreatedAt.After(time.Now().Add(5*time.Second)) {
		t.Errorf("default created_at = %v, want ~now", got.CreatedAt)
	}
}
