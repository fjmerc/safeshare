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

// T30: a lapsed reservation counts only received bytes, RenewReservation
// re-reserves the rest (once) or refuses, and RecordChunkProgress never
// lowers received_bytes.
func TestPartialUploadRepository_ReservationLease_Postgres(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()

	lapsed := time.Now().Add(-repository.PartialUploadReservationIdle - 10*time.Minute)
	for _, u := range []struct {
		id       string
		received int64
		last     time.Time
	}{
		{"lease-lapsed", 400, lapsed},
		{"lease-squatter", 0, lapsed},
	} {
		if err := repos.PartialUploads.Create(ctx, &models.PartialUpload{
			UploadID: u.id, Filename: u.id + ".bin", TotalSize: 1000, ChunkSize: 100, TotalChunks: 10,
			ReceivedBytes: u.received, CreatedAt: u.last, LastActivity: u.last, Status: "uploading",
		}); err != nil {
			t.Fatalf("Create(%s) error = %v", u.id, err)
		}
	}

	usage := func() int64 {
		t.Helper()
		var n int64
		if err := testPool.QueryRow(ctx, storageUsageQuery).Scan(&n); err != nil {
			t.Fatalf("usage query error = %v", err)
		}
		return n
	}
	if got := usage(); got != 400 {
		t.Fatalf("usage with two lapsed reservations = %d, want 400", got)
	}

	// The two lapsed 1000-byte reservations no longer block a new upload.
	now := time.Now()
	if err := repos.PartialUploads.CreateWithQuotaCheck(ctx, &models.PartialUpload{
		UploadID: "lease-new", Filename: "new.bin", TotalSize: 1000, ChunkSize: 100, TotalChunks: 10,
		CreatedAt: now, LastActivity: now, Status: "uploading",
	}, 1500); err != nil {
		t.Fatalf("CreateWithQuotaCheck() error = %v, want nil", err)
	}

	// usage 1400; renewing needs another 600.
	if err := repos.PartialUploads.RenewReservation(ctx, "lease-lapsed", 1500); !errors.Is(err, repository.ErrQuotaExceeded) {
		t.Fatalf("RenewReservation() with no room error = %v, want ErrQuotaExceeded", err)
	}
	if err := repos.PartialUploads.RenewReservation(ctx, "lease-lapsed", 2000); err != nil {
		t.Fatalf("RenewReservation() error = %v, want nil", err)
	}
	if got := usage(); got != 2000 {
		t.Errorf("usage after renewal = %d, want 2000", got)
	}
	if err := repos.PartialUploads.RenewReservation(ctx, "lease-lapsed", 0); err != nil {
		t.Errorf("second RenewReservation() error = %v, want nil (no-op)", err)
	}

	if err := repos.PartialUploads.RecordChunkProgress(ctx, "lease-lapsed", 1100); err != nil {
		t.Fatalf("RecordChunkProgress() error = %v", err)
	}
	if err := repos.PartialUploads.RecordChunkProgress(ctx, "lease-lapsed", 100); err != nil {
		t.Fatalf("RecordChunkProgress() error = %v", err)
	}
	got, err := repos.PartialUploads.GetByUploadID(ctx, "lease-lapsed")
	if err != nil || got == nil {
		t.Fatalf("GetByUploadID() = %v, %v", got, err)
	}
	if got.ReceivedBytes != 1000 {
		t.Errorf("ReceivedBytes = %d, want 1000 (capped, never lowered)", got.ReceivedBytes)
	}
}
