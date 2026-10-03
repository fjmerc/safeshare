package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
)

const reservationTestUploadID = "550e8400-e29b-41d4-a716-446655440030"

func postReservationTestChunk(t *testing.T, handler http.Handler, chunkNumber int, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, _ := mw.CreateFormFile("chunk", "chunk")
	_, _ = part.Write(data)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/"+reservationTestUploadID+"/"+strconv.Itoa(chunkNumber), &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func lapseReservation(t *testing.T, db *sql.DB) {
	t.Helper()
	old := time.Now().Add(-repository.PartialUploadReservationIdle - 10*time.Minute).Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE partial_uploads SET last_activity = ? WHERE upload_id = ?`, old, reservationTestUploadID); err != nil {
		t.Fatal(err)
	}
}

// setupQuotaLeaseTest creates a 3 KiB, three-chunk upload on a 1 GiB quota
// in which unexpired files leave freeBytes free.
func setupQuotaLeaseTest(t *testing.T, freeBytes int64) (*sql.DB, *repository.Repositories, *config.Config, http.Handler) {
	t.Helper()
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true
	if err := cfg.SetQuotaLimitGB(1); err != nil {
		t.Fatal(err)
	}
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	if err := repos.Files.Create(ctx, &models.File{
		ClaimCode: "reservationfill", OriginalFilename: "fill.bin", StoredFilename: "fill.bin",
		FileSize: 1<<30 - freeBytes, ExpiresAt: time.Now().Add(24 * time.Hour), UploaderIP: "127.0.0.1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := repos.PartialUploads.Create(ctx, &models.PartialUpload{
		UploadID: reservationTestUploadID, Filename: "r.bin", TotalSize: 3072, ChunkSize: 1024, TotalChunks: 3,
		CreatedAt: time.Now(), LastActivity: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return db, repos, cfg, UploadChunkHandler(repos, cfg)
}

func reservationTestUpload(t *testing.T, repos *repository.Repositories) *models.PartialUpload {
	t.Helper()
	u, err := repos.PartialUploads.GetByUploadID(context.Background(), reservationTestUploadID)
	if err != nil || u == nil {
		t.Fatalf("GetByUploadID = %v, %v", u, err)
	}
	return u
}

// T30: once an upload's reservation has lapsed, its next new chunk has to
// re-reserve the rest of its size, and is refused if the quota filled up
// in the meantime.
func TestUploadChunkHandler_LapsedReservation(t *testing.T) {
	chunk := bytes.Repeat([]byte("A"), 1024)

	t.Run("refused when the quota has filled", func(t *testing.T) {
		db, repos, _, handler := setupQuotaLeaseTest(t, 2500)
		if rr := postReservationTestChunk(t, handler, 0, chunk); rr.Code != http.StatusOK {
			t.Fatalf("chunk 0: status = %d, want 200: %s", rr.Code, rr.Body)
		}
		lapseReservation(t, db)

		// 1024 received is still counted; the other 2048 don't fit in
		// the 2500 - 1024 left.
		rr := postReservationTestChunk(t, handler, 1, chunk)
		if rr.Code != http.StatusInsufficientStorage {
			t.Fatalf("chunk 1 after lapse: status = %d, want 507: %s", rr.Code, rr.Body)
		}
		if got := reservationTestUpload(t, repos).ReceivedBytes; got != 1024 {
			t.Errorf("received_bytes = %d, want 1024", got)
		}
	})

	t.Run("re-reserved when the rest fits", func(t *testing.T) {
		db, repos, _, handler := setupQuotaLeaseTest(t, 3072)
		if rr := postReservationTestChunk(t, handler, 0, chunk); rr.Code != http.StatusOK {
			t.Fatalf("chunk 0: status = %d, want 200: %s", rr.Code, rr.Body)
		}
		lapseReservation(t, db)

		if rr := postReservationTestChunk(t, handler, 1, chunk); rr.Code != http.StatusOK {
			t.Fatalf("chunk 1 after lapse: status = %d, want 200: %s", rr.Code, rr.Body)
		}
		u := reservationTestUpload(t, repos)
		if time.Since(u.LastActivity) > time.Minute {
			t.Errorf("last_activity = %v, want refreshed", u.LastActivity)
		}
		if u.ReceivedBytes != 2048 {
			t.Errorf("received_bytes = %d, want 2048", u.ReceivedBytes)
		}
	})

	t.Run("re-sending a stored chunk doesn't renew it", func(t *testing.T) {
		db, repos, _, handler := setupQuotaLeaseTest(t, 3072)
		if rr := postReservationTestChunk(t, handler, 0, chunk); rr.Code != http.StatusOK {
			t.Fatalf("chunk 0: status = %d, want 200: %s", rr.Code, rr.Body)
		}
		lapseReservation(t, db)

		if rr := postReservationTestChunk(t, handler, 0, chunk); rr.Code != http.StatusOK {
			t.Fatalf("chunk 0 again: status = %d, want 200: %s", rr.Code, rr.Body)
		}
		if u := reservationTestUpload(t, repos); time.Since(u.LastActivity) < repository.PartialUploadReservationIdle {
			t.Errorf("last_activity = %v, want still lapsed", u.LastActivity)
		}
	})
}

// T30: /complete moves an upload out of "uploading", which counts its full
// size again, so a lapsed reservation that undercounts what's on disk (rows
// from before received_bytes was tracked) has to fit first.
func TestUploadCompleteHandler_LapsedReservation(t *testing.T) {
	db, repos, cfg, handler := setupQuotaLeaseTest(t, 2500)
	chunk := bytes.Repeat([]byte("A"), 1024)
	for i := 0; i < 3; i++ {
		if rr := postReservationTestChunk(t, handler, i, chunk); rr.Code != http.StatusOK {
			t.Fatalf("chunk %d: status = %d, want 200: %s", i, rr.Code, rr.Body)
		}
	}
	if _, err := db.Exec(`UPDATE partial_uploads SET received_bytes = 0 WHERE upload_id = ?`, reservationTestUploadID); err != nil {
		t.Fatal(err)
	}
	lapseReservation(t, db)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/complete/"+reservationTestUploadID, nil)
	rr := httptest.NewRecorder()
	UploadCompleteHandler(repos, cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusInsufficientStorage {
		t.Fatalf("complete after lapse: status = %d, want 507: %s", rr.Code, rr.Body)
	}
	if u := reservationTestUpload(t, repos); u.Status != "uploading" {
		t.Errorf("status = %q, want still uploading", u.Status)
	}
}
