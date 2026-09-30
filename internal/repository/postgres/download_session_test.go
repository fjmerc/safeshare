//go:build integration
// +build integration

// Package postgres provides PostgreSQL implementations of repository interfaces.
// This file contains integration tests for the ADR-014 resumable
// download-session flow, focused on the T42 post-completion grace window
// (see docs/SafeShare-Planning/06-Architecture-Decisions/ADR-014-download-sessions.md
// and its T42 addendum). Run with:
//
//	go test -tags=integration -v ./internal/repository/postgres/... -run DownloadSession
//
// or via scripts/test-postgres.sh.
package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// createSessionTestFile creates a capped (max_downloads = maxDL) file for
// download-session tests. Mirrors the sqlite package's helper of the same
// name/shape.
func createSessionTestFile(t *testing.T, repos *repository.Repositories, claimCode string, maxDL int) *models.File {
	t.Helper()
	file := &models.File{
		ClaimCode:        claimCode,
		OriginalFilename: "session-test.bin",
		StoredFilename:   "session-test-stored-" + claimCode + ".bin",
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

// completeSession reserves, commits and completes a fresh download session
// for file, returning the bearer token. Test helper for the T42 grace-window
// tests below, which all start from an already-completed session.
func completeSession(t *testing.T, repos *repository.Repositories, file *models.File) string {
	t.Helper()
	ctx := context.Background()

	token, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}
	if result, err := repos.Files.CommitDownloadSession(ctx, file.ID, token); err != nil || result != repository.DownloadCommitCredited {
		t.Fatalf("CommitDownloadSession: result=%v err=%v", result, err)
	}
	if first, err := repos.Files.CompleteDownloadSession(ctx, file.ID, token); err != nil || !first {
		t.Fatalf("CompleteDownloadSession: first=%v err=%v", first, err)
	}
	return token
}

// TestFileRepository_LookupDownloadSession_RejectsCompleted mirrors the
// sqlite test of the same name: with the T42 grace window disabled (0), a
// completed session's token must resolve to nil — the original ADR-014
// bug-hunter "no replay oracle" contract.
func TestFileRepository_LookupDownloadSession_RejectsCompleted(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "pgsescompleted", 1)
	token := completeSession(t, repos, file)

	sess, err := repos.Files.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour, 0)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess != nil {
		t.Error("LookupDownloadSession resolved a completed session with grace disabled; want nil")
	}
}

// TestFileRepository_LookupDownloadSession_ResumesCompletedWithinGrace — T42:
// a completed session's token must still resolve while inside completeGrace
// of its own completed_at.
func TestFileRepository_LookupDownloadSession_ResumesCompletedWithinGrace(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "pgsesgraceresume", 1)
	token := completeSession(t, repos, file)

	sess, err := repos.Files.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess == nil {
		t.Fatal("LookupDownloadSession returned nil for a completed session still inside its grace window")
	}
	if !sess.Committed || !sess.Completed {
		t.Errorf("Committed=%v Completed=%v, want both true", sess.Committed, sess.Completed)
	}
	if sess.CompletedAt.IsZero() {
		t.Error("CompletedAt is zero, want the time CompleteDownloadSession ran")
	}
}

// TestFileRepository_LookupDownloadSession_RejectsCompletedPastGrace — the
// grace window is bounded: once completeGrace has elapsed, Lookup goes back
// to treating the token like "not found".
func TestFileRepository_LookupDownloadSession_RejectsCompletedPastGrace(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "pgsesgraceexpired", 1)
	token := completeSession(t, repos, file)

	sess, err := repos.Files.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour, 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess != nil {
		t.Error("LookupDownloadSession resolved a completed session past its grace window; want nil")
	}
}

// TestFileRepository_ReserveSessionBytes_AllowsCompletedWithinGrace — T42:
// ReserveSessionBytes re-checks grace-window eligibility atomically, and the
// replay it allows is still bounded by `limit` (SessionByteLimit).
func TestFileRepository_ReserveSessionBytes_AllowsCompletedWithinGrace(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "pgsesgracereserve", 1)
	token := completeSession(t, repos, file)

	limit := repository.SessionByteLimit(file.FileSize)
	granted, err := repos.Files.ReserveSessionBytes(ctx, file.ID, token, 100, limit, 5*time.Minute)
	if err != nil {
		t.Fatalf("ReserveSessionBytes: %v", err)
	}
	if !granted {
		t.Error("ReserveSessionBytes did not grant bytes for a completed session inside its grace window")
	}

	granted, err = repos.Files.ReserveSessionBytes(ctx, file.ID, token, limit, limit, 5*time.Minute)
	if err != nil {
		t.Fatalf("ReserveSessionBytes (over limit): %v", err)
	}
	if granted {
		t.Error("ReserveSessionBytes granted bytes past the 2x-file-size ceiling for a grace-window resume")
	}
}

// TestFileRepository_ReserveSessionBytes_RejectsCompletedWhenGraceDisabled —
// grace=0 restores the pre-T42 behaviour: a completed session is never
// eligible for ReserveSessionBytes.
func TestFileRepository_ReserveSessionBytes_RejectsCompletedWhenGraceDisabled(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "pgsesgracedisabled", 1)
	token := completeSession(t, repos, file)

	limit := repository.SessionByteLimit(file.FileSize)
	granted, err := repos.Files.ReserveSessionBytes(ctx, file.ID, token, 100, limit, 0)
	if err != nil {
		t.Fatalf("ReserveSessionBytes: %v", err)
	}
	if granted {
		t.Error("ReserveSessionBytes granted bytes for a completed session with grace disabled (0)")
	}
}

// TestFileRepository_ReapDownloadSessions_ProtectsCompletedWithinGrace — T42:
// a just-completed session must survive the reaper for as long as its own
// completeGrace window is open, even if idleTTL/maxAge alone would otherwise
// reap it.
func TestFileRepository_ReapDownloadSessions_ProtectsCompletedWithinGrace(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "pgsesgracereap", 1)
	token := completeSession(t, repos, file)

	cancelled, expired, err := repos.Files.ReapDownloadSessions(ctx, time.Hour, -1*time.Second, -1*time.Second, 5*time.Minute)
	if err != nil {
		t.Fatalf("ReapDownloadSessions: %v", err)
	}
	if cancelled != 0 || expired != 0 {
		t.Errorf("cancelled=%d expired=%d, want 0/0 (grace must protect the row)", cancelled, expired)
	}

	sess, err := repos.Files.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess == nil {
		t.Fatal("session was reaped despite being inside its completeGrace window")
	}
}

// TestFileRepository_ReapDownloadSessions_ReapsCompletedPastGrace — once
// completeGrace has elapsed, the reaper's normal idle/max-age rule applies to
// a completed row exactly as it does to any other committed row.
func TestFileRepository_ReapDownloadSessions_ReapsCompletedPastGrace(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "pgsesgracereaped", 1)
	completeSession(t, repos, file)

	cancelled, expired, err := repos.Files.ReapDownloadSessions(ctx, time.Hour, -1*time.Second, -1*time.Second, 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("ReapDownloadSessions: %v", err)
	}
	if cancelled != 0 {
		t.Errorf("cancelled = %d, want 0 (this is the committed/completed path)", cancelled)
	}
	if expired < 1 {
		t.Fatalf("expired = %d, want >= 1 (grace elapsed, row should be reaped)", expired)
	}
}

// TestFileRepository_ReapDownloadSessions_GraceDisabledMatchesPreT42Behaviour
// — grace=0 must reap a completed row under the same idle/max-age rule as
// before T42, with no special protection.
func TestFileRepository_ReapDownloadSessions_GraceDisabledMatchesPreT42Behaviour(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "pgsesgracedisabledreap", 1)
	completeSession(t, repos, file)

	cancelled, expired, err := repos.Files.ReapDownloadSessions(ctx, time.Hour, -1*time.Second, -1*time.Second, 0)
	if err != nil {
		t.Fatalf("ReapDownloadSessions: %v", err)
	}
	if cancelled != 0 {
		t.Errorf("cancelled = %d, want 0", cancelled)
	}
	if expired < 1 {
		t.Fatalf("expired = %d, want >= 1 (grace disabled restores pre-T42 idle/max-age reap)", expired)
	}
}

// TestFileRepository_GraceWindowResume_NoDoubleCount — end-to-end T42 safety
// argument: replaying commit/complete against an already-completed session
// found inside the grace window must not touch download_count or
// completed_downloads a second time.
func TestFileRepository_GraceWindowResume_NoDoubleCount(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()
	file := createSessionTestFile(t, repos, "pgsesgracenodouble", 5)
	token := completeSession(t, repos, file)

	before, err := repos.Files.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID (before resume): %v", err)
	}
	if before.DownloadCount != 1 || before.CompletedDownloads != 1 {
		t.Fatalf("before resume: download_count=%d completed_downloads=%d, want 1/1", before.DownloadCount, before.CompletedDownloads)
	}

	sess, err := repos.Files.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatalf("LookupDownloadSession (resume): %v", err)
	}
	if sess == nil || !sess.Completed {
		t.Fatalf("expected a resolved, completed session; got %+v", sess)
	}
	limit := repository.SessionByteLimit(file.FileSize)
	if granted, err := repos.Files.ReserveSessionBytes(ctx, file.ID, token, 100, limit, 5*time.Minute); err != nil || !granted {
		t.Fatalf("ReserveSessionBytes (resume): granted=%v err=%v", granted, err)
	}
	if result, err := repos.Files.CommitDownloadSession(ctx, file.ID, token); err != nil || result != repository.DownloadCommitAlreadyCommitted {
		t.Fatalf("CommitDownloadSession (resume): result=%v err=%v, want AlreadyCommitted", result, err)
	}
	if first, err := repos.Files.CompleteDownloadSession(ctx, file.ID, token); err != nil || first {
		t.Fatalf("CompleteDownloadSession (resume): first=%v err=%v, want first=false (no re-fire)", first, err)
	}

	after, err := repos.Files.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID (after resume): %v", err)
	}
	if after.DownloadCount != before.DownloadCount {
		t.Errorf("download_count changed on grace-window resume: before=%d after=%d", before.DownloadCount, after.DownloadCount)
	}
	if after.CompletedDownloads != before.CompletedDownloads {
		t.Errorf("completed_downloads changed on grace-window resume: before=%d after=%d", before.CompletedDownloads, after.CompletedDownloads)
	}
}
