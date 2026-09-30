//go:build integration
// +build integration

// Package postgres — download_sessions integration tests (T37).
//
// Mirrors the SQLite coverage in
// internal/repository/sqlite/file_repository_test.go for the ADR-014
// download-session repository methods: ReserveDownload, LookupDownloadSession,
// CommitDownloadSession, TouchDownloadSession, CompleteDownloadSession,
// ReapDownloadSessions, ReserveSessionBytes, and ReleaseSessionBytes. These
// were previously compiled but untested against a live PostgreSQL database
// (see Project-Audit-2026-07-05.md, T37).
package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// createSessionTestFile creates a file with the given claim code and
// max_downloads cap, for exercising the download-session lifecycle.
func createSessionTestFile(t *testing.T, repos *repository.Repositories, claimCode string, maxDL int) *models.File {
	t.Helper()
	file := &models.File{
		ClaimCode:        claimCode,
		OriginalFilename: "session-test.bin",
		StoredFilename:   "session-test-stored.bin",
		FileSize:         4096,
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     &maxDL,
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(context.Background(), file); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return file
}

// TestFileRepository_ReserveDownload_Unlimited — a file with no
// max_downloads cap must short-circuit to the unlimited sentinel token
// without ever inserting a download_sessions row.
func TestFileRepository_ReserveDownload_Unlimited(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()

	file := &models.File{
		ClaimCode:        "sesunlimited",
		OriginalFilename: "unlimited.bin",
		StoredFilename:   "unlimited-stored.bin",
		FileSize:         2048,
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("Create: %v", err)
	}

	token, granted, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("ReserveDownload: %v", err)
	}
	if token != repository.ReservationTokenUnlimited {
		t.Errorf("token = %q, want %q", token, repository.ReservationTokenUnlimited)
	}
	if granted != 0 {
		t.Errorf("granted = %d, want 0", granted)
	}
}

// TestFileRepository_ReserveDownload_CapEnforced — a max_downloads=1 file
// must deny a second concurrent reservation while the first is still
// uncommitted.
func TestFileRepository_ReserveDownload_CapEnforced(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "sescapenforce", 1)

	token1, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token1 == "" {
		t.Fatalf("first ReserveDownload: token=%q err=%v", token1, err)
	}

	token2, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("second ReserveDownload: %v", err)
	}
	if token2 != "" {
		t.Errorf("second ReserveDownload succeeded (token=%q); want denied (cap=1, slot already held)", token2)
	}
}

// TestFileRepository_ReserveDownload_ClaimCodeChanged — a stale claim code
// must be reported distinctly from "cap full".
func TestFileRepository_ReserveDownload_ClaimCodeChanged(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "sesclaimchanged", 1)

	_, _, err := repos.Files.ReserveDownload(ctx, file.ID, "wrong-claim-code")
	if err != repository.ErrClaimCodeChanged {
		t.Errorf("ReserveDownload with stale claim code: err = %v, want ErrClaimCodeChanged", err)
	}
}

// TestFileRepository_CommitDownloadSession_CreditsAndIdempotent mirrors
// sqlite's TestFileRepository_CommitDownloadSession_Idempotent: the first
// commit credits download_count exactly once, and a second commit against
// the same token is a no-op reported as AlreadyCommitted.
func TestFileRepository_CommitDownloadSession_CreditsAndIdempotent(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "sesidem", 1)

	token, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}

	result, err := repos.Files.CommitDownloadSession(ctx, file.ID, token)
	if err != nil {
		t.Fatalf("first CommitDownloadSession: %v", err)
	}
	if result != repository.DownloadCommitCredited {
		t.Fatalf("first CommitDownloadSession result = %v, want Credited", result)
	}

	result, err = repos.Files.CommitDownloadSession(ctx, file.ID, token)
	if err != nil {
		t.Fatalf("second CommitDownloadSession: %v", err)
	}
	if result != repository.DownloadCommitAlreadyCommitted {
		t.Errorf("second CommitDownloadSession result = %v, want AlreadyCommitted", result)
	}

	got, err := repos.Files.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1 (idempotent)", got.DownloadCount)
	}
}

// TestFileRepository_TouchDownloadSession_UpdatesBytesServed verifies Touch
// updates bytes_served and last_seen_at (observed indirectly via
// LookupDownloadSession).
func TestFileRepository_TouchDownloadSession_UpdatesBytesServed(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "sestouch", 1)

	token, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}

	if err := repos.Files.TouchDownloadSession(ctx, file.ID, token, 1024); err != nil {
		t.Fatalf("TouchDownloadSession: %v", err)
	}
	if err := repos.Files.TouchDownloadSession(ctx, file.ID, token, 512); err != nil {
		t.Fatalf("TouchDownloadSession (second): %v", err)
	}

	sess, err := repos.Files.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess == nil {
		t.Fatal("session not found")
	}
	if sess.BytesServed != 1536 {
		t.Errorf("BytesServed = %d, want 1536 (cumulative)", sess.BytesServed)
	}
}

// TestFileRepository_CompleteDownloadSession_IncrementsCompletedDownloads
// mirrors sqlite coverage: Complete only succeeds after Commit, and it's the
// completed_downloads counter (not download_count) that moves.
func TestFileRepository_CompleteDownloadSession_IncrementsCompletedDownloads(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "sescomplete", 1)

	token, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}

	// Complete before Commit must be a no-op (false, no error).
	completed, err := repos.Files.CompleteDownloadSession(ctx, file.ID, token)
	if err != nil {
		t.Fatalf("CompleteDownloadSession (pre-commit): %v", err)
	}
	if completed {
		t.Error("CompleteDownloadSession succeeded before Commit; want false")
	}

	if _, err := repos.Files.CommitDownloadSession(ctx, file.ID, token); err != nil {
		t.Fatalf("CommitDownloadSession: %v", err)
	}

	completed, err = repos.Files.CompleteDownloadSession(ctx, file.ID, token)
	if err != nil {
		t.Fatalf("CompleteDownloadSession: %v", err)
	}
	if !completed {
		t.Fatal("CompleteDownloadSession returned false after Commit; want true")
	}

	// A second Complete call is a no-op.
	completed, err = repos.Files.CompleteDownloadSession(ctx, file.ID, token)
	if err != nil {
		t.Fatalf("second CompleteDownloadSession: %v", err)
	}
	if completed {
		t.Error("second CompleteDownloadSession succeeded; want false (idempotent)")
	}

	got, err := repos.Files.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.CompletedDownloads != 1 {
		t.Errorf("completed_downloads = %d, want 1", got.CompletedDownloads)
	}
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1", got.DownloadCount)
	}
}

// TestFileRepository_LookupDownloadSession_RejectsCompleted — bug-hunter
// finding (HIGH): a completed session's token must resolve as "not found"
// (no replay oracle), same as sqlite's coverage.
func TestFileRepository_LookupDownloadSession_RejectsCompleted(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "sescompleted", 1)

	token, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}
	if _, err := repos.Files.CommitDownloadSession(ctx, file.ID, token); err != nil {
		t.Fatalf("CommitDownloadSession: %v", err)
	}
	if _, err := repos.Files.CompleteDownloadSession(ctx, file.ID, token); err != nil {
		t.Fatalf("CompleteDownloadSession: %v", err)
	}

	sess, err := repos.Files.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess != nil {
		t.Error("LookupDownloadSession resolved a completed session; want nil (no replay oracle)")
	}
}

// TestFileRepository_LookupDownloadSession_ExpiredByMaxAge verifies the "no
// oracle" contract: a session older than maxAge is reported as absent
// (nil, nil).
func TestFileRepository_LookupDownloadSession_ExpiredByMaxAge(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "sesexpired", 1)

	token, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}

	sess, err := repos.Files.LookupDownloadSession(ctx, file.ID, token, time.Hour, 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess != nil {
		t.Error("LookupDownloadSession returned a session past maxAge; want nil (no oracle)")
	}
}

// TestFileRepository_LookupDownloadSession_NotFound — an unknown token must
// resolve as (nil, nil), not an error.
func TestFileRepository_LookupDownloadSession_NotFound(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "sesnotfound", 1)

	sess, err := repos.Files.LookupDownloadSession(ctx, file.ID, "bogus-token-that-was-never-issued", time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess != nil {
		t.Error("LookupDownloadSession resolved an unknown token; want nil")
	}
}

// TestFileRepository_ReapDownloadSessions_StalledLeaseThenSlotLost mirrors
// sqlite coverage: an abandoned uncommitted session gets reaped, freeing the
// slot for another reader; the orphaned token's late commit then reports
// SlotLost rather than over-crediting past the cap.
func TestFileRepository_ReapDownloadSessions_StalledLeaseThenSlotLost(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "sesstalled", 1)

	orphanToken, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || orphanToken == "" {
		t.Fatalf("ReserveDownload (orphan): token=%q err=%v", orphanToken, err)
	}

	// Negative TTL == "reap everything created before now".
	cancelled, _, err := repos.Files.ReapDownloadSessions(ctx, -1*time.Second, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("ReapDownloadSessions: %v", err)
	}
	if cancelled < 1 {
		t.Fatalf("cancelled = %d, want >= 1", cancelled)
	}

	otherToken, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || otherToken == "" {
		t.Fatalf("ReserveDownload (other): token=%q err=%v", otherToken, err)
	}
	if result, err := repos.Files.CommitDownloadSession(ctx, file.ID, otherToken); err != nil || result != repository.DownloadCommitCredited {
		t.Fatalf("CommitDownloadSession (other): result=%v err=%v", result, err)
	}

	result, err := repos.Files.CommitDownloadSession(ctx, file.ID, orphanToken)
	if err != nil {
		t.Fatalf("CommitDownloadSession (orphan, late): %v", err)
	}
	if result != repository.DownloadCommitSlotLost {
		t.Errorf("orphan late-commit result = %v, want SlotLost", result)
	}

	got, err := repos.Files.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1 (orphan must not over-credit past the cap)", got.DownloadCount)
	}
}

// TestFileRepository_ReapDownloadSessions_CommittedIdleExpiryNoCounterChange
// — an idle, already-committed-and-completed session is deleted by the
// reaper as pure record cleanup: no counter changes.
func TestFileRepository_ReapDownloadSessions_CommittedIdleExpiryNoCounterChange(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "sesidle", 1)

	token, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}
	if _, err := repos.Files.CommitDownloadSession(ctx, file.ID, token); err != nil {
		t.Fatalf("CommitDownloadSession: %v", err)
	}
	if _, err := repos.Files.CompleteDownloadSession(ctx, file.ID, token); err != nil {
		t.Fatalf("CompleteDownloadSession: %v", err)
	}

	before, err := repos.Files.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID (before): %v", err)
	}

	// Negative idle TTL: reaps the committed row immediately via the
	// idle-cutoff branch, not the lease-cutoff branch.
	cancelled, expired, err := repos.Files.ReapDownloadSessions(ctx, time.Hour, -1*time.Second, 24*time.Hour)
	if err != nil {
		t.Fatalf("ReapDownloadSessions: %v", err)
	}
	if cancelled != 0 {
		t.Errorf("cancelled = %d, want 0 (this is the committed/idle path, not the lease path)", cancelled)
	}
	if expired < 1 {
		t.Fatalf("expired = %d, want >= 1", expired)
	}

	after, err := repos.Files.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID (after): %v", err)
	}
	if after.DownloadCount != before.DownloadCount || after.CompletedDownloads != before.CompletedDownloads {
		t.Errorf("counters changed after idle-expiry reap: before dc=%d completed=%d, after dc=%d completed=%d",
			before.DownloadCount, before.CompletedDownloads, after.DownloadCount, after.CompletedDownloads)
	}

	sess, err := repos.Files.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess != nil {
		t.Error("session row still present after idle-expiry reap")
	}
}

// TestFileRepository_ReserveSessionBytes_BoundedByLimit mirrors the sqlite
// coverage for the trusted-token-replay byte ceiling (ReserveSessionBytes).
func TestFileRepository_ReserveSessionBytes_BoundedByLimit(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "sesreplaybound", 100) // generous cap: isolate the byte bound

	token, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}
	if result, err := repos.Files.CommitDownloadSession(ctx, file.ID, token); err != nil || result != repository.DownloadCommitCredited {
		t.Fatalf("CommitDownloadSession: result=%v err=%v", result, err)
	}
	// Committed but not completed — the state a large in-flight download is
	// in while its token gets replayed for subsequent Range requests.

	const rangeLen = 500
	limit := repository.SessionByteLimit(file.FileSize)
	maxGrantable := int(limit / rangeLen)

	grantedCount := 0
	const attempts = 30
	for i := 0; i < attempts; i++ {
		granted, err := repos.Files.ReserveSessionBytes(ctx, file.ID, token, rangeLen, limit)
		if err != nil {
			t.Fatalf("ReserveSessionBytes attempt %d: %v", i, err)
		}
		if granted {
			grantedCount++
		}
	}
	if grantedCount != maxGrantable {
		t.Errorf("grantedCount = %d, want exactly %d (limit=%d, rangeLen=%d, attempts=%d)", grantedCount, maxGrantable, limit, rangeLen, attempts)
	}

	sess, err := repos.Files.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess == nil {
		t.Fatal("session not found")
	}
	if sess.BytesReserved > limit {
		t.Errorf("BytesReserved = %d, want <= %d", sess.BytesReserved, limit)
	}
}

// TestFileRepository_ReleaseSessionBytes_Decrements verifies
// ReleaseSessionBytes refunds a reservation without underflowing below zero.
func TestFileRepository_ReleaseSessionBytes_Decrements(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "sesrelease", 100)

	token, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}
	if result, err := repos.Files.CommitDownloadSession(ctx, file.ID, token); err != nil || result != repository.DownloadCommitCredited {
		t.Fatalf("CommitDownloadSession: result=%v err=%v", result, err)
	}

	limit := repository.SessionByteLimit(file.FileSize)
	granted, err := repos.Files.ReserveSessionBytes(ctx, file.ID, token, 1000, limit)
	if err != nil {
		t.Fatalf("ReserveSessionBytes: %v", err)
	}
	if !granted {
		t.Fatal("ReserveSessionBytes was not granted")
	}

	if err := repos.Files.ReleaseSessionBytes(ctx, file.ID, token, 400); err != nil {
		t.Fatalf("ReleaseSessionBytes: %v", err)
	}

	sess, err := repos.Files.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess == nil {
		t.Fatal("session not found")
	}
	if sess.BytesReserved != 600 {
		t.Errorf("BytesReserved = %d, want 600 (1000 - 400)", sess.BytesReserved)
	}

	// Releasing more than is reserved must clamp at zero, not underflow.
	if err := repos.Files.ReleaseSessionBytes(ctx, file.ID, token, 10000); err != nil {
		t.Fatalf("ReleaseSessionBytes (over-release): %v", err)
	}
	sess, err = repos.Files.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("LookupDownloadSession (after over-release): %v", err)
	}
	if sess == nil {
		t.Fatal("session not found (after over-release)")
	}
	if sess.BytesReserved != 0 {
		t.Errorf("BytesReserved = %d, want 0 (clamped, not underflowed)", sess.BytesReserved)
	}
}

// TestFileRepository_CancelDownload_ReleasesSlotForAnotherReader verifies
// Cancel frees an uncommitted reservation's slot without crediting a
// download.
func TestFileRepository_CancelDownload_ReleasesSlotForAnotherReader(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "sescancelpg", 1)

	token, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}

	if err := repos.Files.CancelDownload(ctx, file.ID, token); err != nil {
		t.Fatalf("CancelDownload: %v", err)
	}

	got, err := repos.Files.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 0 {
		t.Errorf("download_count = %d, want 0 (Cancel must not credit a download)", got.DownloadCount)
	}

	token2, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("second ReserveDownload: %v", err)
	}
	if token2 == "" {
		t.Error("second ReserveDownload denied; Cancel should have freed the slot")
	}
}
