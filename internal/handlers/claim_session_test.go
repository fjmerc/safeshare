package handlers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// ADR-014 test suite. setupReservationTest (claim_reservation_test.go) fixes
// the file at 4096 bytes; these tests need control over file size to exercise
// the probe threshold P = clamp(N/16, 1, 64KiB) and budget B = 4*P precisely,
// so they use their own setup helper.
//
//   T1: Range-splitting a download across two requests, with and without the
//       resume token, must count as exactly one download (or be denied once
//       the cap is already spent).
//   Probe threshold/budget: sub-threshold tokenless probes are free up to
//       budget B, after which every tokenless byte counts.
//   Token handling: foreign/garbage tokens are silently treated as new
//       downloads, and the bearer token itself is never written to logs.

// setupSessionTest creates a capped file of the given size and max_downloads,
// backed by a real SQLite DB (so the reservation guards run for real).
func setupSessionTest(t *testing.T, fileSize, maxDL int) (*repository.Repositories, http.HandlerFunc, string, *models.File, func()) {
	t.Helper()
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := ClaimHandler(repos, cfg)
	ctx := context.Background()

	body := make([]byte, fileSize)
	for i := range body {
		body[i] = byte(i % 251)
	}
	storedFilename := fmt.Sprintf("sess-%s.bin", strings.ReplaceAll(t.Name(), "/", "_"))
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	if err := os.WriteFile(filePath, body, 0o644); err != nil {
		t.Fatalf("failed to write fixture file: %v", err)
	}

	claimCode := "sesscode"
	file := &models.File{
		ClaimCode:        claimCode,
		OriginalFilename: "sess.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(fileSize),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     &maxDL,
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("failed to insert file: %v", err)
	}
	cleanup := func() { _ = os.Remove(filePath) }
	return repos, handler, claimCode, file, cleanup
}

// TestSession_RangeSplitWithTokenCountsOnce — T1 regression, resumed path.
// Two Range requests that together cover the whole file (the first past the
// probe threshold, the second the final byte) must count as exactly one
// download when the client presents the X-Download-Session token issued by
// the first response.
func TestSession_RangeSplitWithTokenCountsOnce(t *testing.T) {
	const fileSize = 8000 // P = 500
	repos, handler, code, file, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	req1 := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	req1.Header.Set("Range", fmt.Sprintf("bytes=0-%d", fileSize-2))
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusPartialContent {
		t.Fatalf("first range: status = %d, want 206; body=%q", rr1.Code, rr1.Body.String())
	}
	token := rr1.Header().Get("X-Download-Session")
	if token == "" {
		t.Fatal("first range response missing X-Download-Session header")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	req2.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", fileSize-1, fileSize-1))
	req2.Header.Set("X-Download-Session", token)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusPartialContent {
		t.Fatalf("second range: status = %d, want 206; body=%q", rr2.Code, rr2.Body.String())
	}

	got, err := repos.Files.GetByID(context.Background(), file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1 (counted once across the split)", got.DownloadCount)
	}
}

// TestSession_RangeSplitWithoutTokenDoesNotDoubleServe — T1 regression, the
// original bug. Without the resume token, the second (final-byte) request is
// indistinguishable from a brand-new download attempt and must be denied once
// the first range already spent the only slot.
func TestSession_RangeSplitWithoutTokenDoesNotDoubleServe(t *testing.T) {
	const fileSize = 8000
	_, handler, code, _, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	req1 := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	req1.Header.Set("Range", fmt.Sprintf("bytes=0-%d", fileSize-2))
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusPartialContent {
		t.Fatalf("first range: status = %d, want 206", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	req2.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", fileSize-1, fileSize-1))
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusGone {
		t.Errorf("second (tokenless) range: status = %d, want 410 (T1 regression)", rr2.Code)
	}
}

// TestSession_ProbeUnderAllowanceIsFree mirrors
// TestReservation_PartialRangeProbeDoesNotConsumeSlot but asserts the
// ADR-014-specific contract explicitly: a probe under threshold P is free and
// still returns a session header, and a following full GET commits normally.
func TestSession_ProbeUnderAllowanceIsFree(t *testing.T) {
	const fileSize = 4096 // P = 256
	repos, handler, code, file, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	probe := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	probe.Header.Set("Range", "bytes=0-0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, probe)
	if rr.Code != http.StatusPartialContent {
		t.Fatalf("probe: status = %d, want 206", rr.Code)
	}
	if rr.Header().Get("X-Download-Session") == "" {
		t.Error("probe response missing X-Download-Session header")
	}

	got, _ := repos.Files.GetByID(context.Background(), file.ID)
	if got.DownloadCount != 0 {
		t.Errorf("after probe: download_count = %d, want 0", got.DownloadCount)
	}

	full := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, full)
	if rr2.Code != http.StatusOK {
		t.Fatalf("full GET: status = %d, want 200", rr2.Code)
	}
	got, _ = repos.Files.GetByID(context.Background(), file.ID)
	if got.DownloadCount != 1 {
		t.Errorf("after full GET: download_count = %d, want 1", got.DownloadCount)
	}
}

// TestSession_ProbeBudgetExhaustedNextProbeCounts closes the salami-slicing
// variant of T1: repeatedly staying just under P still exhausts the
// per-file budget B = 4*P, after which the next tokenless probe — even
// though it is exactly as small as all the others — counts immediately.
func TestSession_ProbeBudgetExhaustedNextProbeCounts(t *testing.T) {
	const fileSize = 32 // P = 2, B = 8
	repos, handler, code, file, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	for i := 0; i < 8; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		req.Header.Set("Range", "bytes=0-0")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusPartialContent {
			t.Fatalf("probe %d: status = %d, want 206", i, rr.Code)
		}
	}
	got, err := repos.Files.GetByID(context.Background(), file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 0 {
		t.Fatalf("after 8 free probes: download_count = %d, want 0", got.DownloadCount)
	}
	if got.UncountedBytes < 8 {
		t.Fatalf("after 8 free probes: uncounted_bytes = %d, want >= 8 (budget)", got.UncountedBytes)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	req.Header.Set("Range", "bytes=0-0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusPartialContent {
		t.Fatalf("9th probe: status = %d, want 206", rr.Code)
	}
	got, _ = repos.Files.GetByID(context.Background(), file.ID)
	if got.DownloadCount != 1 {
		t.Errorf("after budget exhausted: download_count = %d, want 1 (P collapsed to 0)", got.DownloadCount)
	}
}

// TestSession_ForeignOrGarbageTokenTreatedAsNew verifies ADR-014's "no
// oracle" contract: a token that doesn't exist, or belongs to a different
// file, is silently treated as if no token had been sent at all.
func TestSession_ForeignOrGarbageTokenTreatedAsNew(t *testing.T) {
	t.Run("garbage token", func(t *testing.T) {
		const fileSize = 4096
		repos, handler, code, file, cleanup := setupSessionTest(t, fileSize, 1)
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		req.Header.Set("X-Download-Session", "garbage-not-a-real-token")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
		}
		if rr.Body.Len() != fileSize {
			t.Fatalf("body length = %d, want %d", rr.Body.Len(), fileSize)
		}
		got, _ := repos.Files.GetByID(context.Background(), file.ID)
		if got.DownloadCount != 1 {
			t.Errorf("download_count = %d, want 1 (garbage token treated as fresh download)", got.DownloadCount)
		}
	})

	t.Run("foreign file token", func(t *testing.T) {
		const fileSize = 8000 // P = 500
		_, handlerA, codeA, _, cleanupA := setupSessionTest(t, fileSize, 1)
		defer cleanupA()
		reposB, handlerB, codeB, fileB, cleanupB := setupSessionTest(t, fileSize, 1)
		defer cleanupB()

		// Commit a session on file A to obtain a real, valid token.
		reqA := httptest.NewRequest(http.MethodGet, "/api/claim/"+codeA, nil)
		rrA := httptest.NewRecorder()
		handlerA.ServeHTTP(rrA, reqA)
		if rrA.Code != http.StatusOK {
			t.Fatalf("file A download: status = %d, want 200", rrA.Code)
		}
		tokenA := rrA.Header().Get("X-Download-Session")
		if tokenA == "" {
			t.Fatal("file A response missing X-Download-Session header")
		}

		// Present A's token against B — must be rejected as foreign and
		// treated as a fresh download of B.
		reqB := httptest.NewRequest(http.MethodGet, "/api/claim/"+codeB, nil)
		reqB.Header.Set("X-Download-Session", tokenA)
		rrB := httptest.NewRecorder()
		handlerB.ServeHTTP(rrB, reqB)
		if rrB.Code != http.StatusOK {
			t.Fatalf("file B download with foreign token: status = %d, want 200", rrB.Code)
		}
		gotB, err := reposB.Files.GetByID(context.Background(), fileB.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if gotB.DownloadCount != 1 {
			t.Errorf("file B download_count = %d, want 1 (foreign token treated as fresh download)", gotB.DownloadCount)
		}
	})
}

// TestSession_ParallelRangesSameTokenCountOnce fires several concurrent Range
// requests against a max_downloads=1 file, all presenting the same
// already-committed session token. All must succeed (206) and the download
// must still count exactly once.
func TestSession_ParallelRangesSameTokenCountOnce(t *testing.T) {
	const fileSize = 8000 // P = 500
	repos, handler, code, file, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	seed := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	seed.Header.Set("Range", "bytes=0-999") // 1000 bytes > P(500): commits immediately.
	seedRR := httptest.NewRecorder()
	handler.ServeHTTP(seedRR, seed)
	if seedRR.Code != http.StatusPartialContent {
		t.Fatalf("seed range: status = %d, want 206", seedRR.Code)
	}
	token := seedRR.Header().Get("X-Download-Session")
	if token == "" {
		t.Fatal("seed response missing X-Download-Session header")
	}

	const N = 8
	var wg sync.WaitGroup
	codes := make([]int, N)
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			start := 1000 + i*100
			end := start + 99
			req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
			req.Header.Set("X-Download-Session", token)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			codes[i] = rr.Code
		}(i)
	}
	wg.Wait()

	for i, c := range codes {
		if c != http.StatusPartialContent {
			t.Errorf("goroutine %d: status = %d, want 206", i, c)
		}
	}
	got, err := repos.Files.GetByID(context.Background(), file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1 (already-committed token, counted once)", got.DownloadCount)
	}
}

// TestSession_ConcurrentFirstRequestsExactlyOneCredited is the ADR-014
// analogue of TestReservation_ConcurrentClaimsOnMaxOne: concurrent, tokenless,
// over-threshold Range requests against a max_downloads=1 file must admit
// exactly one.
func TestSession_ConcurrentFirstRequestsExactlyOneCredited(t *testing.T) {
	const fileSize = 8000 // P = 500
	repos, handler, code, file, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	const N = 16
	var successCnt, deniedCnt, otherCnt int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
			req.Header.Set("Range", "bytes=0-999")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			switch rr.Code {
			case http.StatusPartialContent:
				atomic.AddInt32(&successCnt, 1)
			case http.StatusGone:
				atomic.AddInt32(&deniedCnt, 1)
			default:
				atomic.AddInt32(&otherCnt, 1)
				t.Errorf("unexpected status %d: %q", rr.Code, rr.Body.String())
			}
		}()
	}
	close(start)
	wg.Wait()

	if successCnt != 1 {
		t.Errorf("successes = %d, want 1", successCnt)
	}
	if deniedCnt != N-1 {
		t.Errorf("denied = %d, want %d", deniedCnt, N-1)
	}
	if otherCnt != 0 {
		t.Errorf("unexpected statuses: %d", otherCnt)
	}
	got, _ := repos.Files.GetByID(context.Background(), file.ID)
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1", got.DownloadCount)
	}
}

// TestSession_CacheControlNoStoreOnCappedFiles verifies capped-file responses
// declare Cache-Control: private, no-store — the response depends on
// per-recipient session state, so any CDN/browser cache would be incorrect.
func TestSession_CacheControlNoStoreOnCappedFiles(t *testing.T) {
	const fileSize = 4096
	_, handler, code, _, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	cc := rr.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-store") || !strings.Contains(cc, "private") {
		t.Errorf("Cache-Control = %q, want it to contain both %q and %q", cc, "private", "no-store")
	}
}

// TestSession_TokenNeverLoggedInFull is a regression test for the bearer-
// credential logging fix: claim.go must never write the raw session token
// into logs, even on an error path that references it for correlation.
func TestSession_TokenNeverLoggedInFull(t *testing.T) {
	mockRepo := mock.NewFileRepository()
	repos := &repository.Repositories{Files: mockRepo}
	cfg := testutil.SetupTestConfig(t)
	handler := ClaimHandler(repos, cfg)
	ctx := context.Background()

	body := []byte("token logging regression body")
	storedFilename := "sess-logtoken.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	if err := os.WriteFile(filePath, body, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	defer os.Remove(filePath)

	maxDL := 1
	file := &models.File{
		ClaimCode:        "logtok",
		OriginalFilename: "logtok.bin",
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

	var logBuf bytes.Buffer
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	defer slog.SetDefault(prevLogger)

	// Force the mid-stream commit (and, if reached, the safety-net path) to
	// log with the token in scope, so this test actually exercises the
	// redaction rather than passing vacuously.
	mockRepo.CommitDownloadSessionError = errCommitInjected

	req := httptest.NewRequest(http.MethodGet, "/api/claim/logtok", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockRepo.CommitDownloadSessionError = nil

	token := rr.Header().Get("X-Download-Session")
	if token == "" {
		t.Fatal("missing X-Download-Session header")
	}
	if strings.Contains(logBuf.String(), token) {
		t.Errorf("log output contains the raw session token verbatim:\n%s", logBuf.String())
	}
}

// TestSession_ResumeAgainstDeletedFileDoesNotCredit is a regression test for
// the bug-hunter finding that the resumed-token path used to call
// CommitDownloadSession before serveFileWithRangeSupport had even opened the
// file: a resume request presenting a valid token against a file whose
// on-disk blob has since disappeared (race with cleanup, disk issue, ...)
// must not spend the download credit, because zero bytes were ever
// delivered. The commit must only happen from sessionWriter's first actual
// successful (2xx) write — see session_writer.go's type doc.
func TestSession_ResumeAgainstDeletedFileDoesNotCredit(t *testing.T) {
	newFixture := func(t *testing.T) (*repository.Repositories, http.HandlerFunc, string, *models.File, string) {
		t.Helper()
		db := testutil.SetupTestDB(t)
		cfg := testutil.SetupTestConfig(t)
		repos, err := sqlite.NewRepositories(cfg, db)
		if err != nil {
			t.Fatalf("failed to create repositories: %v", err)
		}
		handler := ClaimHandler(repos, cfg)
		ctx := context.Background()

		const fileSize = 8000 // P = 500
		body := make([]byte, fileSize)
		for i := range body {
			body[i] = byte(i % 251)
		}
		storedFilename := "sess-deleted-" + strings.ReplaceAll(t.Name(), "/", "_") + ".bin"
		filePath := filepath.Join(cfg.UploadDir, storedFilename)
		if err := os.WriteFile(filePath, body, 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}

		maxDL := 1
		file := &models.File{
			ClaimCode:        "sessdeleted",
			OriginalFilename: "sess.bin",
			StoredFilename:   storedFilename,
			FileSize:         int64(fileSize),
			MimeType:         "application/octet-stream",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			MaxDownloads:     &maxDL,
			UploaderIP:       "127.0.0.1",
		}
		if err := repos.Files.Create(ctx, file); err != nil {
			t.Fatalf("Create: %v", err)
		}
		return repos, handler, file.ClaimCode, file, filePath
	}

	t.Run("uncommitted token", func(t *testing.T) {
		repos, handler, code, file, filePath := newFixture(t)

		probe := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		probe.Header.Set("Range", "bytes=0-10") // 11 bytes, under P(500): stays uncommitted.
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, probe)
		if rr.Code != http.StatusPartialContent {
			t.Fatalf("probe: status = %d, want 206", rr.Code)
		}
		token := rr.Header().Get("X-Download-Session")
		if token == "" {
			t.Fatal("missing X-Download-Session header")
		}
		got, _ := repos.Files.GetByID(context.Background(), file.ID)
		if got.DownloadCount != 0 {
			t.Fatalf("after probe: download_count = %d, want 0", got.DownloadCount)
		}

		if err := os.Remove(filePath); err != nil {
			t.Fatalf("failed to remove fixture file: %v", err)
		}

		resume := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		resume.Header.Set("X-Download-Session", token)
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, resume)
		if rr2.Code != http.StatusNotFound {
			t.Errorf("resume against deleted file: status = %d, want 404; body=%q", rr2.Code, rr2.Body.String())
		}

		got, err := repos.Files.GetByID(context.Background(), file.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.DownloadCount != 0 {
			t.Errorf("download_count = %d, want 0 (no bytes were ever delivered)", got.DownloadCount)
		}

		// The slot must have been released too — CancelDownload should have
		// run since the session was never committed.
		token2, _, err := repos.Files.ReserveDownload(context.Background(), file.ID, file.ClaimCode)
		if err != nil {
			t.Fatalf("ReserveDownload after deleted-file resume: %v", err)
		}
		if token2 == "" {
			t.Error("slot still held after a resume against a deleted file delivered zero bytes")
		}
	})

	t.Run("already-committed token", func(t *testing.T) {
		repos, handler, code, file, filePath := newFixture(t)

		full := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		full.Header.Set("Range", "bytes=0-999") // 1000 bytes > P(500): commits.
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, full)
		if rr.Code != http.StatusPartialContent {
			t.Fatalf("first range: status = %d, want 206", rr.Code)
		}
		token := rr.Header().Get("X-Download-Session")
		if token == "" {
			t.Fatal("missing X-Download-Session header")
		}
		got, _ := repos.Files.GetByID(context.Background(), file.ID)
		if got.DownloadCount != 1 {
			t.Fatalf("after first range: download_count = %d, want 1", got.DownloadCount)
		}

		if err := os.Remove(filePath); err != nil {
			t.Fatalf("failed to remove fixture file: %v", err)
		}

		resume := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		resume.Header.Set("Range", "bytes=1000-1099")
		resume.Header.Set("X-Download-Session", token)
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, resume)
		if rr2.Code != http.StatusNotFound {
			t.Errorf("resume against deleted file: status = %d, want 404; body=%q", rr2.Code, rr2.Body.String())
		}

		got, err := repos.Files.GetByID(context.Background(), file.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.DownloadCount != 1 {
			t.Errorf("download_count = %d, want still 1 (no double-credit, no loss)", got.DownloadCount)
		}
	})
}

// TestSession_ReplayAfterCompletionDenied is the end-to-end regression test
// for the bug-hunter finding (HIGH, blocking): once a download session has
// completed, presenting its token again must not redeliver the file. With no
// spare capacity that's a 410; with spare capacity it must be treated as an
// entirely new download (fresh token, fresh credit), never a free replay of
// the finished one.
func TestSession_ReplayAfterCompletionDenied(t *testing.T) {
	t.Run("max_downloads_1_replay_after_completion_is_denied", func(t *testing.T) {
		const fileSize = 4096
		repos, handler, code, file, cleanup := setupSessionTest(t, fileSize, 1)
		defer cleanup()

		req1 := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		rr1 := httptest.NewRecorder()
		handler.ServeHTTP(rr1, req1)
		if rr1.Code != http.StatusOK {
			t.Fatalf("first download: status = %d, want 200", rr1.Code)
		}
		token := rr1.Header().Get("X-Download-Session")
		if token == "" {
			t.Fatal("missing X-Download-Session header")
		}
		got, _ := repos.Files.GetByID(context.Background(), file.ID)
		if got.DownloadCount != 1 || got.CompletedDownloads != 1 {
			t.Fatalf("after first download: dc=%d completed=%d, want both 1", got.DownloadCount, got.CompletedDownloads)
		}

		// curl -H "X-Download-Session: T" .../api/claim/CODE — must not
		// stream the file again; the session is already completed.
		req2 := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		req2.Header.Set("X-Download-Session", token)
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusGone {
			t.Errorf("replay after completion: status = %d, want 410; body=%q", rr2.Code, rr2.Body.String())
		}
		if rr2.Body.Len() == fileSize {
			t.Error("replay after completion returned the full file body")
		}

		got, _ = repos.Files.GetByID(context.Background(), file.ID)
		if got.DownloadCount != 1 {
			t.Errorf("download_count = %d, want still 1 (replay must not credit again)", got.DownloadCount)
		}
	})

	t.Run("max_downloads_gt_1_replay_after_completion_counts_as_new_download", func(t *testing.T) {
		const fileSize = 4096
		repos, handler, code, file, cleanup := setupSessionTest(t, fileSize, 2)
		defer cleanup()

		req1 := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		rr1 := httptest.NewRecorder()
		handler.ServeHTTP(rr1, req1)
		if rr1.Code != http.StatusOK {
			t.Fatalf("first download: status = %d, want 200", rr1.Code)
		}
		token := rr1.Header().Get("X-Download-Session")
		if token == "" {
			t.Fatal("missing X-Download-Session header")
		}

		req2 := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		req2.Header.Set("X-Download-Session", token)
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusOK {
			t.Fatalf("replay with spare capacity: status = %d, want 200 (treated as a fresh download)", rr2.Code)
		}
		if rr2.Body.Len() != fileSize {
			t.Fatalf("replay body length = %d, want %d", rr2.Body.Len(), fileSize)
		}
		if token2 := rr2.Header().Get("X-Download-Session"); token2 == token {
			t.Error("replay reused the completed session's token instead of minting a fresh one")
		}

		got, _ := repos.Files.GetByID(context.Background(), file.ID)
		if got.DownloadCount != 2 || got.CompletedDownloads != 2 {
			t.Errorf("after replay: dc=%d completed=%d, want both 2", got.DownloadCount, got.CompletedDownloads)
		}
	})
}

// TestSession_ParallelTokenlessProbesBoundedByBudget is the end-to-end
// regression test for the bug-hunter MEDIUM finding: round-2's probe budget
// was checked against a snapshot of files.uncounted_bytes read once at the
// top of the handler, so concurrent tokenless probes (e.g. from different
// IPs) could each be granted a full P-byte allowance before any of them
// charged the shared budget — enough disjoint P-sized ranges in parallel
// could reconstruct a whole small file for free. The grant is now atomic
// inside ReserveDownload's transaction, so the file's uncounted_bytes ledger
// must stay bounded by budget B regardless of concurrency.
func TestSession_ParallelTokenlessProbesBoundedByBudget(t *testing.T) {
	const fileSize = 320 // P = 20, B = 80
	const probeBudget = 80
	repos, handler, code, file, cleanup := setupSessionTest(t, fileSize, 1000) // generous cap: isolate the byte budget, not max_downloads
	defer cleanup()

	const N = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
			req.Header.Set("Range", "bytes=0-9") // 10 bytes, under P(20)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
		}()
	}
	close(start)
	wg.Wait()

	got, err := repos.Files.GetByID(context.Background(), file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	// Under the round-2 bug, 16 concurrent probes could each be granted the
	// full P=20 allowance and each add their served bytes to the ledger —
	// up to 160, well past B=80. With the atomic grant, the sum of every
	// grant this file's Reserve calls ever hand out is capped at B, so the
	// ledger can never exceed it no matter how the requests interleaved.
	if got.UncountedBytes > probeBudget {
		t.Errorf("uncounted_bytes = %d, want <= %d (probe budget exceeded under concurrency)", got.UncountedBytes, probeBudget)
	}
}

// partialWriteRecorder wraps httptest.ResponseRecorder and simulates a
// dropped connection: it accepts at most `limit` bytes across all Write
// calls, then returns a short write plus an error for anything past that —
// mirroring how a real dropped TCP connection surfaces to the handler (a
// short n, a non-nil err), which is what makes io.Copy inside
// serveFileWithRangeSupport stop early with commitable=false.
type partialWriteRecorder struct {
	*httptest.ResponseRecorder
	limit   int
	written int
}

func (p *partialWriteRecorder) Write(b []byte) (int, error) {
	remaining := p.limit - p.written
	if remaining <= 0 {
		return 0, io.ErrClosedPipe
	}
	if len(b) > remaining {
		b = b[:remaining]
	}
	n, err := p.ResponseRecorder.Write(b)
	p.written += n
	if err == nil && n < remaining {
		// Truncated relative to what the caller asked to write — signal the
		// same "connection dropped" condition io.Copy reacts to.
		return n, io.ErrShortWrite
	}
	return n, err
}

// TestSession_PauseResumeSequenceEventuallyCompletesOnce is the end-to-end
// regression test for the bug-hunter MEDIUM finding: resumable-downloader.js
// resumes a paused download with `Range: bytes=<received>-`, and each such
// resume request charges its *whole* remaining range against the session's
// replay ceiling up front (ReserveSessionBytes), before anything is known
// about how much will actually be sent. Without refunding the unsent portion
// on abort, several pause/resume cycles on a large file blow through the 2x
// ceiling from charged-but-undelivered bytes alone, and the very next resume
// — the recipient's only legitimate attempt to finish their one download —
// gets treated as tokenless and 410s against the already-spent cap.
func TestSession_PauseResumeSequenceEventuallyCompletesOnce(t *testing.T) {
	const fileSize = 10000 // P = 625, replay ceiling = 20000
	repos, handler, code, file, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	var token string
	received := 0
	abort := func(chunk int) {
		req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		if received > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", received))
		}
		if token != "" {
			req.Header.Set("X-Download-Session", token)
		}
		rec := &partialWriteRecorder{ResponseRecorder: httptest.NewRecorder(), limit: chunk}
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get("X-Download-Session"); got != "" {
			token = got
		}
		received += rec.written
	}

	// Four pause/resume cycles, each dropped after only 500 more bytes —
	// simulating a flaky connection pausing the same download repeatedly.
	for i := 0; i < 4; i++ {
		abort(500)
	}
	if received == 0 || received >= fileSize {
		t.Fatalf("test setup: received = %d after 4 aborted cycles, want progress but not completion", received)
	}
	if token == "" {
		t.Fatal("never obtained a session token across the aborted cycles")
	}

	got, err := repos.Files.GetByID(context.Background(), file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Fatalf("after aborted cycles: download_count = %d, want 1 (committed by the first, whole-file attempt)", got.DownloadCount)
	}
	if got.CompletedDownloads != 0 {
		t.Fatalf("after aborted cycles: completed_downloads = %d, want 0 (never delivered a range ending at EOF)", got.CompletedDownloads)
	}

	// Final resume: let it actually finish.
	final := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	final.Header.Set("Range", fmt.Sprintf("bytes=%d-", received))
	final.Header.Set("X-Download-Session", token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, final)
	if rr.Code != http.StatusPartialContent {
		t.Fatalf("final resume: status = %d, want 206; body=%q", rr.Code, rr.Body.String())
	}
	if rr.Body.Len() != fileSize-received {
		t.Fatalf("final resume: body length = %d, want %d", rr.Body.Len(), fileSize-received)
	}

	got, err = repos.Files.GetByID(context.Background(), file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 || got.CompletedDownloads != 1 {
		t.Errorf("after final resume: dc=%d completed=%d, want both 1", got.DownloadCount, got.CompletedDownloads)
	}

	// Replay after completion must now be denied — max_downloads=1 is spent.
	replay := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	replay.Header.Set("X-Download-Session", token)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, replay)
	if rr2.Code != http.StatusGone {
		t.Errorf("replay after completion: status = %d, want 410", rr2.Code)
	}
}

// TestSession_AbortedRequestsExceedingFileSizeDoNotComplete is the end-to-end
// regression test for the bug-hunter MEDIUM finding that completion used to
// be judged from cumulative bytes_served across every request that ever
// touched the session. Two separate whole-file requests, each aborted
// partway, together hand more bytes to a ResponseWriter than the file is
// large — but neither one individually reaches EOF, so the session must not
// be marked complete; a real, fully-successful resume afterwards must still
// be the one that completes it.
func TestSession_AbortedRequestsExceedingFileSizeDoNotComplete(t *testing.T) {
	const fileSize = 1000
	repos, handler, code, file, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	req1 := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	rec1 := &partialWriteRecorder{ResponseRecorder: httptest.NewRecorder(), limit: 600}
	handler.ServeHTTP(rec1, req1)
	token := rec1.Header().Get("X-Download-Session")
	if token == "" {
		t.Fatal("missing X-Download-Session header")
	}

	got, err := repos.Files.GetByID(context.Background(), file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Fatalf("download_count = %d, want 1", got.DownloadCount)
	}
	if got.CompletedDownloads != 0 {
		t.Fatalf("completed_downloads = %d, want 0 (aborted at %d/%d bytes)", got.CompletedDownloads, rec1.written, fileSize)
	}

	// A retried whole-file request (not a Range resume — a naive client
	// retrying from scratch) reusing the same token, also aborted partway.
	req2 := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	req2.Header.Set("X-Download-Session", token)
	rec2 := &partialWriteRecorder{ResponseRecorder: httptest.NewRecorder(), limit: 500}
	handler.ServeHTTP(rec2, req2)

	cumulative := rec1.written + rec2.written
	if cumulative < fileSize {
		t.Fatalf("test setup: cumulative bytes written = %d, want >= %d to exercise the over-count scenario", cumulative, fileSize)
	}

	got, err = repos.Files.GetByID(context.Background(), file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.CompletedDownloads != 0 {
		t.Errorf("completed_downloads = %d, want 0 (no single request ever reached EOF)", got.CompletedDownloads)
	}
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want still 1 (no double-credit)", got.DownloadCount)
	}

	// A real, successful full resume must still complete the download.
	req3 := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	req3.Header.Set("X-Download-Session", token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req3)
	if rr.Code != http.StatusOK {
		t.Fatalf("final resume: status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	if rr.Body.Len() != fileSize {
		t.Fatalf("final resume: body length = %d, want %d", rr.Body.Len(), fileSize)
	}

	got, err = repos.Files.GetByID(context.Background(), file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 || got.CompletedDownloads != 1 {
		t.Errorf("after final resume: dc=%d completed=%d, want both 1", got.DownloadCount, got.CompletedDownloads)
	}
}
