package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/mock"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
)

// SH-2.3 test suite — exercises the reservation pattern (Reserve / Commit /
// Cancel) against the four scenarios called out in ADR-012:
//
//   (1) partial-Range probe MUST NOT consume the slot (the original bug)
//   (2) client disconnect mid-stream MUST NOT consume the slot
//   (3) process crash mid-stream MUST be recovered by the reaper after TTL
//   (4) the original P1 race (concurrent claims on max_downloads=1) MUST
//       still admit exactly one downloader (regression)

func setupReservationTest(t *testing.T) (*repository.Repositories, http.HandlerFunc, string, *models.File, func()) {
	t.Helper()
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := ClaimHandler(repos, cfg)
	ctx := context.Background()

	// Realistic-sized file so Range probes are meaningful.
	body := make([]byte, 4096)
	for i := range body {
		body[i] = byte(i % 251)
	}
	storedFilename := "sh23-uuid.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	if err := os.WriteFile(filePath, body, 0o644); err != nil {
		t.Fatalf("failed to write fixture file: %v", err)
	}

	maxDL := 1
	file := &models.File{
		ClaimCode:        "sh23probe",
		OriginalFilename: "sh23.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(body)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     &maxDL,
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to insert file: %v", err)
	}
	cleanup := func() { _ = os.Remove(filePath) }
	return repos, handler, "sh23probe", file, cleanup
}

// TestReservation_PartialRangeProbeDoesNotConsumeSlot — SH-2.3.8 core case.
// A 1-byte Range probe followed by a legitimate full GET must both succeed,
// with the full GET delivering the file and counting the only allowed download.
func TestReservation_PartialRangeProbeDoesNotConsumeSlot(t *testing.T) {
	repos, handler, code, file, cleanup := setupReservationTest(t)
	defer cleanup()

	// Adversarial probe: Range: bytes=0-0 — would have burned the slot pre-SH-2.3.
	probeReq := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	probeReq.Header.Set("Range", "bytes=0-0")
	probeRR := httptest.NewRecorder()
	handler.ServeHTTP(probeRR, probeReq)
	if probeRR.Code != http.StatusPartialContent {
		t.Fatalf("probe: status = %d, want %d; body=%q", probeRR.Code, http.StatusPartialContent, probeRR.Body.String())
	}
	if probeRR.Body.Len() != 1 {
		t.Fatalf("probe: body length = %d, want 1", probeRR.Body.Len())
	}

	// Counters after probe — neither should have moved.
	got, err := repos.Files.GetByID(context.Background(), file.ID)
	if err != nil {
		t.Fatalf("GetByID after probe: %v", err)
	}
	if got.DownloadCount != 0 {
		t.Errorf("after probe: download_count = %d, want 0", got.DownloadCount)
	}
	if got.CompletedDownloads != 0 {
		t.Errorf("after probe: completed_downloads = %d, want 0", got.CompletedDownloads)
	}

	// Legitimate recipient does a full GET.
	fullReq := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	fullRR := httptest.NewRecorder()
	handler.ServeHTTP(fullRR, fullReq)
	if fullRR.Code != http.StatusOK {
		t.Fatalf("full GET: status = %d, want %d; body=%q", fullRR.Code, http.StatusOK, fullRR.Body.String())
	}
	if fullRR.Body.Len() != int(file.FileSize) {
		t.Fatalf("full GET: body length = %d, want %d", fullRR.Body.Len(), file.FileSize)
	}

	got, err = repos.Files.GetByID(context.Background(), file.ID)
	if err != nil {
		t.Fatalf("GetByID after full GET: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Errorf("after full GET: download_count = %d, want 1", got.DownloadCount)
	}
	if got.CompletedDownloads != 1 {
		t.Errorf("after full GET: completed_downloads = %d, want 1", got.CompletedDownloads)
	}

	// And the slot is now actually consumed — a second full GET should be denied.
	denyReq := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	denyRR := httptest.NewRecorder()
	handler.ServeHTTP(denyRR, denyReq)
	if denyRR.Code != http.StatusGone {
		t.Errorf("second full GET: status = %d, want %d (DOWNLOAD_LIMIT_REACHED)", denyRR.Code, http.StatusGone)
	}
}

// TestReservation_FullRangeCommits — a Range request that explicitly covers the
// whole file ([0, fileSize-1]) commits the reservation just like a no-Range GET.
// Exercised in both explicit (`bytes=0-{N-1}`) and open-ended (`bytes=0-`) forms
// because both must resolve to full coverage and therefore commit.
func TestReservation_FullRangeCommits(t *testing.T) {
	cases := []struct {
		name    string
		header  string
	}{
		{"explicit-0-to-N-1", fmt.Sprintf("bytes=0-%d", 4095)},
		{"open-ended-bytes-0-", "bytes=0-"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repos, handler, code, file, cleanup := setupReservationTest(t)
			defer cleanup()

			req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
			req.Header.Set("Range", tc.header)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusPartialContent {
				t.Fatalf("status = %d, want %d (body=%q)", rr.Code, http.StatusPartialContent, rr.Body.String())
			}

			got, err := repos.Files.GetByID(context.Background(), file.ID)
			if err != nil {
				t.Fatalf("GetByID: %v", err)
			}
			if got.DownloadCount != 1 || got.CompletedDownloads != 1 {
				t.Errorf("full-range commit (%s): dc=%d completed=%d, want both 1", tc.header, got.DownloadCount, got.CompletedDownloads)
			}
		})
	}
}

// TestReservation_TailProbeDoesNotConsumeSlot — Range: bytes=N- (tail probe)
// must not commit, even though it covers a real chunk of the file.
func TestReservation_TailProbeDoesNotConsumeSlot(t *testing.T) {
	repos, handler, code, file, cleanup := setupReservationTest(t)
	defer cleanup()

	tail := fmt.Sprintf("bytes=%d-", file.FileSize-100)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	req.Header.Set("Range", tail)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusPartialContent)
	}

	got, _ := repos.Files.GetByID(context.Background(), file.ID)
	if got.DownloadCount != 0 || got.CompletedDownloads != 0 {
		t.Errorf("tail probe: dc=%d completed=%d, want both 0", got.DownloadCount, got.CompletedDownloads)
	}
}

// TestReservation_ClientDisconnectMidStream — SH-2.3.9.
// Simulate a client disconnect by passing a context that is cancelled mid-stream.
// The reservation must be released (in_flight_reservations → 0) and the counter
// must NOT have advanced. Approach: ReserveDownload directly, simulate a mid-
// stream failure, then verify CancelDownload restores state and a fresh GET
// succeeds.
func TestReservation_ClientDisconnectMidStream(t *testing.T) {
	repos, _, _, file, cleanup := setupReservationTest(t)
	defer cleanup()

	ctx := context.Background()
	token, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("ReserveDownload: %v", err)
	}
	if token == "" || token == repository.ReservationTokenUnlimited {
		t.Fatalf("unexpected token: %q", token)
	}

	// Simulate disconnect mid-stream: bytes were written to the wire but the
	// handler returns without committing. The deferred Cancel in the production
	// handler does this. We do it explicitly.
	if err := repos.Files.CancelDownload(ctx, file.ID, token); err != nil {
		t.Fatalf("CancelDownload: %v", err)
	}

	got, _ := repos.Files.GetByID(ctx, file.ID)
	if got.DownloadCount != 0 {
		t.Errorf("after cancel: download_count = %d, want 0", got.DownloadCount)
	}

	// Fresh reservation must succeed — the slot has been released.
	token2, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("second ReserveDownload: %v", err)
	}
	if token2 == "" {
		t.Fatalf("second reserve was rejected; slot leaked")
	}
	_ = repos.Files.CancelDownload(ctx, file.ID, token2)
}

// TestReservation_ProcessCrashRecoveredByReaper — SH-2.3.10.
// A reservation is taken but never committed/cancelled (process crash analog).
// Calling ReapStaleReservations with a negative TTL (which translates to
// "reap everything created before now") must reap the row, decrement
// in_flight, and free the slot.
func TestReservation_ProcessCrashRecoveredByReaper(t *testing.T) {
	repos, _, _, file, cleanup := setupReservationTest(t)
	defer cleanup()

	ctx := context.Background()
	token, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("ReserveDownload: %v", err)
	}
	if token == "" || token == repository.ReservationTokenUnlimited {
		t.Fatalf("unexpected token: %q", token)
	}

	// Another reader is locked out while the (orphaned) reservation is live.
	pre, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("intervening ReserveDownload: %v", err)
	}
	if pre != "" {
		t.Fatalf("intervening reserve unexpectedly succeeded (token=%q); slot was not held", pre)
	}

	// Reaper sweeps anything older than "now" — reaps the orphan immediately.
	// Negative ttl ⇒ cutoff > now ⇒ all existing rows match.
	n, err := repos.Files.ReapStaleReservations(ctx, -1*time.Second)
	if err != nil {
		t.Fatalf("ReapStaleReservations: %v", err)
	}
	if n < 1 {
		t.Fatalf("ReapStaleReservations: count = %d, want >= 1", n)
	}

	// Slot is now free.
	post, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("post-reap ReserveDownload: %v", err)
	}
	if post == "" {
		t.Fatalf("post-reap reserve was rejected; slot did not free up")
	}
	if err := repos.Files.CancelDownload(ctx, file.ID, post); err != nil {
		t.Fatalf("CancelDownload (cleanup): %v", err)
	}

	got, _ := repos.Files.GetByID(ctx, file.ID)
	if got.DownloadCount != 0 {
		t.Errorf("download_count = %d, want 0 (reap should not credit)", got.DownloadCount)
	}
}

// TestReservation_CommitAfterReapStillSucceeds — branch 2b of CommitDownload.
// Simulate: Reserve → reaper runs → Commit. The Commit should attempt to take
// a fresh slot. With no other reader competing, it succeeds and increments the
// counter; if the cap is already taken, it logs and no-ops.
func TestReservation_CommitAfterReapStillSucceeds(t *testing.T) {
	repos, _, _, file, cleanup := setupReservationTest(t)
	defer cleanup()

	ctx := context.Background()
	token, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("ReserveDownload: %v", err)
	}

	// Reaper runs (token row gone, in_flight decremented).
	if _, err := repos.Files.ReapStaleReservations(ctx, -1*time.Second); err != nil {
		t.Fatalf("ReapStaleReservations: %v", err)
	}

	// Commit now — branch 2b path. No other reader has taken the slot, so it
	// re-acquires and increments. This is the "slow legitimate download
	// eventually completes" case from ADR-012 §11.
	if err := repos.Files.CommitDownload(ctx, file.ID, token); err != nil {
		t.Fatalf("CommitDownload after reap: %v", err)
	}

	got, _ := repos.Files.GetByID(ctx, file.ID)
	if got.DownloadCount != 1 || got.CompletedDownloads != 1 {
		t.Errorf("after late commit: dc=%d completed=%d, want both 1", got.DownloadCount, got.CompletedDownloads)
	}
}

// TestReservation_CommitIdempotent — calling Commit twice doesn't double-count.
func TestReservation_CommitIdempotent(t *testing.T) {
	repos, _, _, file, cleanup := setupReservationTest(t)
	defer cleanup()

	ctx := context.Background()
	token, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("ReserveDownload: %v", err)
	}
	if err := repos.Files.CommitDownload(ctx, file.ID, token); err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	// Second Commit — should NOT credit a second download because the slot was
	// already taken (download_count is now 1, equal to max_downloads=1, so the
	// reaped-recovery branch's WHERE clause rejects).
	if err := repos.Files.CommitDownload(ctx, file.ID, token); err != nil {
		t.Fatalf("second Commit: %v", err)
	}
	got, _ := repos.Files.GetByID(ctx, file.ID)
	if got.DownloadCount != 1 {
		t.Errorf("double-Commit: download_count = %d, want 1 (idempotent)", got.DownloadCount)
	}
}

// TestReservation_ConcurrentClaimsOnMaxOne — SH-2.3.12 (the original P1 race).
// Many concurrent requests for the same max_downloads=1 file. Exactly one must
// succeed (HTTP 200 with full body); the rest must be denied (HTTP 410).
//
// A wall-clock guard (30s) protects against a wedged-DB deadlock turning into a
// silent test-runner timeout: if the wait hits the deadline we surface a clear
// failure pointing at the lock contention rather than hanging until CI kills us.
func TestReservation_ConcurrentClaimsOnMaxOne(t *testing.T) {
	repos, handler, code, file, cleanup := setupReservationTest(t)
	defer cleanup()

	const N = 32
	var (
		wg          sync.WaitGroup
		successCnt  int32
		deniedCnt   int32
		othersCnt   int32
		latencyChan = make(chan time.Duration, N)
	)
	wg.Add(N)
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			<-start
			t0 := time.Now()
			req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			latencyChan <- time.Since(t0)
			switch rr.Code {
			case http.StatusOK:
				atomic.AddInt32(&successCnt, 1)
				if rr.Body.Len() != int(file.FileSize) {
					t.Errorf("winning request got body length %d, want %d", rr.Body.Len(), file.FileSize)
				}
			case http.StatusGone:
				atomic.AddInt32(&deniedCnt, 1)
			default:
				atomic.AddInt32(&othersCnt, 1)
				t.Errorf("unexpected status %d: %q", rr.Code, rr.Body.String())
			}
		}()
	}
	close(start)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("concurrent claims test deadlocked after 30s; successes=%d denied=%d",
			atomic.LoadInt32(&successCnt), atomic.LoadInt32(&deniedCnt))
	}
	close(latencyChan)

	if successCnt != 1 {
		t.Errorf("successes = %d, want exactly 1 (P1 race regression)", successCnt)
	}
	if deniedCnt != N-1 {
		t.Errorf("denied = %d, want %d", deniedCnt, N-1)
	}
	if othersCnt != 0 {
		t.Errorf("unexpected statuses: %d", othersCnt)
	}

	got, _ := repos.Files.GetByID(context.Background(), file.ID)
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1", got.DownloadCount)
	}
	if got.CompletedDownloads != 1 {
		t.Errorf("completed_downloads = %d, want 1", got.CompletedDownloads)
	}
}

// TestReservation_UnlimitedDownloadsBypassesReservation — sanity check that
// max_downloads=NULL files don't pay reservation cost and don't leak state.
func TestReservation_UnlimitedDownloadsBypassesReservation(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	handler := ClaimHandler(repos, cfg)
	ctx := context.Background()

	body := []byte("unlimited body")
	storedFilename := "sh23-unlim.txt"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	if err := os.WriteFile(filePath, body, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	defer os.Remove(filePath)

	file := &models.File{
		ClaimCode:        "sh23unlim",
		OriginalFilename: "unlim.txt",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(body)),
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		// MaxDownloads intentionally nil.
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// ReserveDownload should return the sentinel.
	tok, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("ReserveDownload: %v", err)
	}
	if tok != repository.ReservationTokenUnlimited {
		t.Errorf("token = %q, want %q (unlimited)", tok, repository.ReservationTokenUnlimited)
	}

	// And the handler path: many downloads should all succeed and credit the counter.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/claim/sh23unlim", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("download %d: status = %d, want 200", i, rr.Code)
		}
	}
	got, _ := repos.Files.GetByID(ctx, file.ID)
	if got.DownloadCount != 5 {
		t.Errorf("download_count = %d, want 5", got.DownloadCount)
	}
}

// TestReservation_LateCommitRespectsInFlight — bug-hunter C1 regression.
// The CommitDownload reaped-mid-stream recovery branch must enforce
// `(download_count + in_flight_reservations) < max_downloads`, the same guard
// Reserve uses. Without that, a same-token late-commit replay could over-count
// past max_downloads when another reservation has taken the slot in between.
//
// Scenario:
//  1. File has max_downloads = 2. dc=0, in_flight=0.
//  2. User A reserves (in_flight=1).
//  3. Reaper sweeps A's row (in_flight=0).
//  4. A's late Commit fires: recovery branch credits dc=1.
//  5. User B reserves (in_flight=1, dc=1 — total slots accounted = 2, cap hit).
//  6. ATTACK: A's Commit is replayed. The recovery branch sees the row already
//     gone. With the buggy guard `dc < max`, the check 1<2 passes and dc
//     becomes 2 — stealing B's slot. With the fixed guard `(dc + in_flight) <
//     max`, the check (1+1)<2 fails and the replay no-ops.
func TestReservation_LateCommitRespectsInFlight(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	ctx := context.Background()

	body := []byte("late-commit guard regression body")
	storedFilename := "sh23-c1.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	if err := os.WriteFile(filePath, body, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	defer os.Remove(filePath)

	maxDL := 2
	file := &models.File{
		ClaimCode:        "sh23c1",
		OriginalFilename: "c1.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(body)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     &maxDL,
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// (1)-(2): A reserves.
	tokenA, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || tokenA == "" || tokenA == repository.ReservationTokenUnlimited {
		t.Fatalf("Reserve A: token=%q err=%v", tokenA, err)
	}

	// (3) Reaper sweeps A — orphan recovery scenario.
	if _, err := repos.Files.ReapStaleReservations(ctx, -1*time.Second); err != nil {
		t.Fatalf("ReapStaleReservations: %v", err)
	}

	// (4) A's late Commit fires. Recovery branch credits dc=1.
	if err := repos.Files.CommitDownload(ctx, file.ID, tokenA); err != nil {
		t.Fatalf("Commit A (first): %v", err)
	}
	got, _ := repos.Files.GetByID(ctx, file.ID)
	if got.DownloadCount != 1 {
		t.Fatalf("after late commit A: dc = %d, want 1", got.DownloadCount)
	}

	// (5) B reserves — cap is dc(1) + in_flight(0) = 1, room for one more.
	tokenB, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || tokenB == "" || tokenB == repository.ReservationTokenUnlimited {
		t.Fatalf("Reserve B: token=%q err=%v", tokenB, err)
	}

	// (6) Replay A's Commit. Recovery branch must refuse — (dc(1) + in_flight(1)) >= max(2).
	if err := repos.Files.CommitDownload(ctx, file.ID, tokenA); err != nil {
		t.Fatalf("Commit A (replay): %v", err)
	}
	got, _ = repos.Files.GetByID(ctx, file.ID)
	if got.DownloadCount != 1 {
		t.Errorf("after replay: dc = %d, want 1 (replay must NOT steal B's slot)", got.DownloadCount)
	}

	// And B can still successfully commit, reaching the cap legitimately.
	if err := repos.Files.CommitDownload(ctx, file.ID, tokenB); err != nil {
		t.Fatalf("Commit B: %v", err)
	}
	got, _ = repos.Files.GetByID(ctx, file.ID)
	if got.DownloadCount != 2 {
		t.Errorf("after B commit: dc = %d, want 2", got.DownloadCount)
	}
}

// TestReservation_CommitFailureHoldsSlot — code-reviewer M1 regression.
// When the explicit CommitDownload returns an error, the deferred safety-net
// must NOT fire a Cancel. Cancelling after a failed Commit would release the
// slot back to the cap — letting another recipient claim a max_downloads=1
// file even though the first recipient already received the bytes.
//
// Verified via the mock's CommitDownloadError injection: serve a download to
// completion, force Commit to fail, then assert that a follow-up Reserve is
// denied (slot still held until reaper TTL elapses, the intended
// under-deliver-rather-than-over-deliver outcome).
func TestReservation_CommitFailureHoldsSlot(t *testing.T) {
	mockRepo := mock.NewFileRepository()
	repos := &repository.Repositories{Files: mockRepo}
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(repos, cfg)
	ctx := context.Background()

	body := []byte("m1 commit-failure body")
	storedFilename := "sh23-m1.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	if err := os.WriteFile(filePath, body, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	defer os.Remove(filePath)

	maxDL := 1
	file := &models.File{
		ClaimCode:        "sh23m1",
		OriginalFilename: "m1.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(body)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     &maxDL,
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Inject a Commit failure — the handler must log and continue, but the
	// safety-net Cancel must NOT fire.
	mockRepo.CommitDownloadError = errCommitInjected

	req := httptest.NewRequest(http.MethodGet, "/api/claim/sh23m1", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("download: status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}

	// Clear the injection so the next Reserve isn't poisoned by it (only Commit
	// was meant to fail).
	mockRepo.CommitDownloadError = nil

	// A second Reserve must be denied — the slot is still held by the orphaned
	// reservation. If the safety-net had fired Cancel after the failed Commit,
	// this Reserve would succeed and let an extra recipient through.
	tok, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("second Reserve: %v", err)
	}
	if tok != "" {
		t.Errorf("second Reserve succeeded (token=%q); slot was released — M1 regressed", tok)
	}
}

// TestReservation_ReaperRespectsTTLForFreshReservations — bug-hunter M4 regression.
// A reservation created just-now must NOT be reaped by a typical production
// TTL (30 minutes). This guards against a regression where the cutoff was
// computed Go-side (`time.Now().Add(-ttl)`) and could mass-reap legitimate
// in-flight reservations on a wall-clock forward step. The fixed code computes
// the cutoff DB-side, so the only "now" that matters is the DB's own clock.
func TestReservation_ReaperRespectsTTLForFreshReservations(t *testing.T) {
	repos, _, _, file, cleanup := setupReservationTest(t)
	defer cleanup()
	ctx := context.Background()

	token, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}

	// A 30-minute TTL means "reap anything older than 30 minutes". A
	// just-inserted row is ~0 seconds old, so the reaper must leave it alone.
	n, err := repos.Files.ReapStaleReservations(ctx, 30*time.Minute)
	if err != nil {
		t.Fatalf("ReapStaleReservations: %v", err)
	}
	if n != 0 {
		t.Errorf("reaper swept %d fresh reservation(s); want 0", n)
	}

	// The reservation must still be live — a second Reserve should be denied.
	tok2, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("second ReserveDownload: %v", err)
	}
	if tok2 != "" {
		t.Errorf("after reap-with-fresh-TTL: second reserve succeeded (token=%q); the original was reaped despite being fresh", tok2)
	}
}

// errCommitInjected is the sentinel error used by TestReservation_CommitFailureHoldsSlot
// to inject a Commit failure into the mock repository.
var errCommitInjected = errors.New("injected commit failure for M1 regression test")
