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

// createReservationTestUpload inserts an uploading partial upload of
// totalSize bytes that has received receivedBytes and was last active idle
// ago.
func createReservationTestUpload(t *testing.T, db *sql.DB, uploadID string, totalSize, receivedBytes int64, idle time.Duration) {
	t.Helper()
	repo := NewPartialUploadRepository(db)
	last := time.Now().Add(-idle)
	err := repo.Create(context.Background(), &models.PartialUpload{
		UploadID:      uploadID,
		Filename:      uploadID + ".bin",
		TotalSize:     totalSize,
		ChunkSize:     100,
		TotalChunks:   int((totalSize + 99) / 100),
		ReceivedBytes: receivedBytes,
		CreatedAt:     last,
		LastActivity:  last,
	})
	if err != nil {
		t.Fatalf("Create(%s) failed: %v", uploadID, err)
	}
}

func storageUsage(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	var usage int64
	if err := db.QueryRow(storageUsageQuery).Scan(&usage); err != nil {
		t.Fatalf("storage usage query failed: %v", err)
	}
	return usage
}

const lapsedIdle = repository.PartialUploadReservationIdle + 10*time.Minute

// T30: an /init that never sends data must stop holding its full size
// against the quota once its reservation lapses.
func TestStorageUsage_LapsedReservationCountsReceivedBytes(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()

	createReservationTestUpload(t, db, "active", 1000, 100, time.Minute)
	createReservationTestUpload(t, db, "lapsed", 1000, 300, lapsedIdle)
	createReservationTestUpload(t, db, "never-started", 1000, 0, lapsedIdle)
	createReservationTestUpload(t, db, "processing", 1000, 0, lapsedIdle)
	if _, err := db.Exec(`UPDATE partial_uploads SET status = 'processing' WHERE upload_id = 'processing'`); err != nil {
		t.Fatal(err)
	}

	// active: full 1000; lapsed: 300 received; never-started: 0;
	// processing (assembling) keeps its full 1000 whatever its age.
	if got, want := storageUsage(t, db), int64(1000+300+0+1000); got != want {
		t.Errorf("usage = %d, want %d", got, want)
	}
}

// last_activity is stored as RFC3339 in the server's local zone; the lapse
// check must compare instants, not strings, whatever the offset.
func TestStorageUsage_LastActivityOffsets(t *testing.T) {
	for _, offset := range []int{5 * 3600, -7 * 3600} {
		db := setupPartialUploadTestDB(t)
		zone := time.FixedZone("x", offset)
		for id, idle := range map[string]time.Duration{"recent": time.Minute, "old": lapsedIdle} {
			last := time.Now().Add(-idle).In(zone).Format(time.RFC3339)
			if _, err := db.Exec(`INSERT INTO partial_uploads (upload_id, filename, total_size, chunk_size, total_chunks,
				received_bytes, created_at, last_activity) VALUES (?, 'f', 1000, 100, 10, 100, ?, ?)`, id, last, last); err != nil {
				t.Fatal(err)
			}
		}
		if got := storageUsage(t, db); got != 1100 {
			t.Errorf("offset %ds: usage = %d, want 1100 (recent held, old lapsed)", offset, got)
		}
		db.Close()
	}
}

// Only uploading rows lapse; failed ones keep their reservation and
// completed ones count nothing here (they're in files).
func TestStorageUsage_StatusesThatDontLapse(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	createReservationTestUpload(t, db, "failed", 1000, 0, lapsedIdle)
	createReservationTestUpload(t, db, "done", 1000, 1000, lapsedIdle)
	if _, err := db.Exec(`UPDATE partial_uploads SET status = 'failed' WHERE upload_id = 'failed'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE partial_uploads SET status = 'completed', completed = 1 WHERE upload_id = 'done'`); err != nil {
		t.Fatal(err)
	}
	if got := storageUsage(t, db); got != 1000 {
		t.Errorf("usage = %d, want 1000", got)
	}
}

// Unparseable last_activity fails closed: the full size stays reserved.
func TestStorageUsage_BadLastActivityHoldsReservation(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	createReservationTestUpload(t, db, "bad", 1000, 0, lapsedIdle)
	if _, err := db.Exec(`UPDATE partial_uploads SET last_activity = 'garbage' WHERE upload_id = 'bad'`); err != nil {
		t.Fatal(err)
	}
	if got := storageUsage(t, db); got != 1000 {
		t.Errorf("usage = %d, want 1000", got)
	}
	if err := NewPartialUploadRepository(db).RenewReservation(context.Background(), "bad", 0); err != nil {
		t.Errorf("RenewReservation = %v, want nil (treated as held)", err)
	}
}

func TestCreateWithQuotaCheck_IgnoresLapsedReservations(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Two zero-byte inits fill the quota; once they lapse, a new upload fits.
	createReservationTestUpload(t, db, "squatter-1", 1000, 0, lapsedIdle)
	createReservationTestUpload(t, db, "squatter-2", 1000, 0, lapsedIdle)

	now := time.Now()
	err := repo.CreateWithQuotaCheck(ctx, &models.PartialUpload{
		UploadID: "new", Filename: "new.bin", TotalSize: 1500, ChunkSize: 100, TotalChunks: 15,
		CreatedAt: now, LastActivity: now,
	}, 2000)
	if err != nil {
		t.Fatalf("CreateWithQuotaCheck with only lapsed reservations = %v, want nil", err)
	}

	// The same file-side check (simple uploads) agrees.
	fileRepo := NewFileRepository(db)
	err = fileRepo.CreateWithQuotaCheck(ctx, &models.File{
		ClaimCode: "claim", OriginalFilename: "f.bin", StoredFilename: "f.bin", FileSize: 600,
		ExpiresAt: now.Add(time.Hour), UploaderIP: "192.0.2.1",
	}, 2000)
	if !errors.Is(err, repository.ErrQuotaExceeded) {
		t.Errorf("file CreateWithQuotaCheck over the held 1500 = %v, want ErrQuotaExceeded", err)
	}
}

func TestRenewReservation(t *testing.T) {
	ctx := context.Background()

	t.Run("re-reserves when the rest fits", func(t *testing.T) {
		db := setupPartialUploadTestDB(t)
		defer db.Close()
		repo := NewPartialUploadRepository(db)
		createReservationTestUpload(t, db, "u", 1000, 400, lapsedIdle)

		if err := repo.RenewReservation(ctx, "u", 1000); err != nil {
			t.Fatalf("RenewReservation = %v, want nil", err)
		}
		if got := storageUsage(t, db); got != 1000 {
			t.Errorf("usage after renewal = %d, want 1000 (full size held again)", got)
		}
		// Held again, so a parallel chunk's renewal is a no-op even when
		// the quota no longer has room for another 600 bytes.
		if err := repo.RenewReservation(ctx, "u", 1000); err != nil {
			t.Errorf("second RenewReservation = %v, want nil (no double charge)", err)
		}
	})

	t.Run("refuses when the quota has filled", func(t *testing.T) {
		db := setupPartialUploadTestDB(t)
		defer db.Close()
		repo := NewPartialUploadRepository(db)
		createReservationTestUpload(t, db, "u", 1000, 400, lapsedIdle)
		createReservationTestUpload(t, db, "other", 500, 0, time.Minute)

		// usage = 400 (lapsed) + 500 (active); the remaining 600 needs 1500.
		err := repo.RenewReservation(ctx, "u", 1400)
		if !errors.Is(err, repository.ErrQuotaExceeded) {
			t.Fatalf("RenewReservation = %v, want ErrQuotaExceeded", err)
		}
		if got := storageUsage(t, db); got != 900 {
			t.Errorf("usage after refusal = %d, want 900 (still lapsed)", got)
		}
		if err := repo.RenewReservation(ctx, "u", 1500); err != nil {
			t.Errorf("RenewReservation with exactly enough room = %v, want nil", err)
		}
	})

	t.Run("no-op for an active, unknown, or assembling upload", func(t *testing.T) {
		db := setupPartialUploadTestDB(t)
		defer db.Close()
		repo := NewPartialUploadRepository(db)
		createReservationTestUpload(t, db, "active", 1000, 0, time.Minute)
		createReservationTestUpload(t, db, "assembling", 1000, 0, lapsedIdle)
		if _, err := db.Exec(`UPDATE partial_uploads SET status = 'processing' WHERE upload_id = 'assembling'`); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"active", "missing", "assembling"} {
			if err := repo.RenewReservation(ctx, id, 0); err != nil {
				t.Errorf("RenewReservation(%s, quota 0) = %v, want nil", id, err)
			}
		}
	})
}

func TestRecordChunkProgress(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()
	createReservationTestUpload(t, db, "u", 1000, 0, lapsedIdle)

	received := func() int64 {
		t.Helper()
		u, err := repo.GetByUploadID(ctx, "u")
		if err != nil || u == nil {
			t.Fatalf("GetByUploadID = %v, %v", u, err)
		}
		return u.ReceivedBytes
	}

	if err := repo.RecordChunkProgress(ctx, "u", 500); err != nil {
		t.Fatal(err)
	}
	if got := received(); got != 500 {
		t.Errorf("received = %d, want 500", got)
	}
	// It also refreshes last_activity, so the full reservation is held again.
	if got := storageUsage(t, db); got != 1000 {
		t.Errorf("usage = %d, want 1000", got)
	}
	// A late update from a parallel chunk never lowers it...
	if err := repo.RecordChunkProgress(ctx, "u", 200); err != nil {
		t.Fatal(err)
	}
	if got := received(); got != 500 {
		t.Errorf("received after lower update = %d, want 500", got)
	}
	// ...and a whole-chunk overestimate is capped at the upload's size.
	if err := repo.RecordChunkProgress(ctx, "u", 1100); err != nil {
		t.Fatal(err)
	}
	if got := received(); got != 1000 {
		t.Errorf("received after overestimate = %d, want 1000", got)
	}
	if err := repo.RecordChunkProgress(ctx, "u", -1); err == nil {
		t.Error("RecordChunkProgress(-1) = nil, want error")
	}
}
