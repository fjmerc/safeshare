package handlers

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// T51: when two first uploads of the same chunk race, the one that loses
// must be compared with the stored chunk like a retry - not silently
// replace it.
func TestUploadChunkHandler_FirstWriteRace(t *testing.T) {
	for _, tc := range []struct {
		name      string
		otherData []byte
		wantCode  int
	}{
		{"different bytes lose with 409", bytes.Repeat([]byte("B"), 1024), http.StatusConflict},
		{"identical bytes are idempotent", bytes.Repeat([]byte("A"), 1024), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testutil.SetupTestDB(t)
			cfg := testutil.SetupTestConfig(t)
			cfg.ChunkedUploadEnabled = true
			repos, err := sqlite.NewRepositories(cfg, db)
			if err != nil {
				t.Fatal(err)
			}
			if err := repos.PartialUploads.Create(context.Background(), &models.PartialUpload{
				UploadID: reservationTestUploadID, Filename: "r.bin", TotalSize: 2048, ChunkSize: 1024, TotalChunks: 2,
				CreatedAt: time.Now(), LastActivity: time.Now(),
			}); err != nil {
				t.Fatal(err)
			}

			// The concurrent request stores its chunk 0 right before ours
			// commits.
			orig := commitNewChunk
			commitNewChunk = func(tmpPath, uploadDir, uploadID string, chunkNumber int) error {
				if err := utils.SaveChunk(uploadDir, uploadID, chunkNumber, tc.otherData); err != nil {
					t.Fatal(err)
				}
				return orig(tmpPath, uploadDir, uploadID, chunkNumber)
			}
			defer func() { commitNewChunk = orig }()

			rr := postReservationTestChunk(t, UploadChunkHandler(repos, cfg), 0, bytes.Repeat([]byte("A"), 1024))
			if rr.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tc.wantCode, rr.Body)
			}
			stored, err := os.ReadFile(utils.GetChunkPath(cfg.UploadDir, reservationTestUploadID, 0))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stored, tc.otherData) {
				t.Errorf("stored chunk was replaced by the losing request")
			}
			entries, _ := os.ReadDir(utils.GetUploadChunksDir(cfg.UploadDir, reservationTestUploadID))
			if len(entries) != 1 {
				t.Errorf("chunk dir has %d entries, want 1 (losing temp file removed)", len(entries))
			}
		})
	}
}
