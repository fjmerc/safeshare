package handlers

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/mock"
)

// TestSessionWriter_SlotLostAbortsWithNoBytesPastThreshold exercises the core
// ADR-014 safety property: if a mid-stream commit discovers the reaper
// already cancelled this session AND the cap is genuinely full (no slot to
// re-acquire), Write must return ErrDownloadSlotLost and MUST NOT have
// forwarded any bytes to the underlying ResponseWriter — byte P+1 is never
// delivered without a held slot backing it.
func TestSessionWriter_SlotLostAbortsWithNoBytesPastThreshold(t *testing.T) {
	mockRepo := mock.NewFileRepository()
	repos := &repository.Repositories{Files: mockRepo}
	ctx := context.Background()

	maxDL := 1
	file := &models.File{
		ClaimCode:    "swtest",
		FileSize:     1000,
		MaxDownloads: &maxDL,
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Fill the file's only slot via a completely separate, legitimate
	// session so the cap is genuinely full.
	otherToken, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || otherToken == "" {
		t.Fatalf("ReserveDownload (other): token=%q err=%v", otherToken, err)
	}
	if _, err := repos.Files.CommitDownloadSession(ctx, file.ID, otherToken); err != nil {
		t.Fatalf("CommitDownloadSession (other): %v", err)
	}

	// Our own token was never reserved at all — simulating one the reaper
	// already cancelled mid-stream. sessionWriter must discover this on its
	// first over-threshold write and abort without forwarding any bytes.
	rec := httptest.NewRecorder()
	sw := newSessionWriter(ctx, rec, repos, file.ID, "orphaned-token", repository.ProbeThreshold(file.FileSize), false, false)

	n, err := sw.Write(bytes.Repeat([]byte{'x'}, int(file.FileSize)))
	if n != 0 {
		t.Errorf("Write returned n = %d, want 0", n)
	}
	if !errors.Is(err, ErrDownloadSlotLost) {
		t.Errorf("Write error = %v, want ErrDownloadSlotLost", err)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("recorder body length = %d, want 0 (no bytes past P without a held slot)", rec.Body.Len())
	}
	if !sw.CommitAttempted() {
		t.Error("CommitAttempted() = false, want true (claim.go relies on this to skip the Cancel fallback)")
	}
	if sw.Committed() {
		t.Error("Committed() = true, want false (the commit failed)")
	}
}

// TestSessionWriter_WholeFileCommitsBeforeFirstByte verifies that a
// wholeFile-flagged writer commits on the very first Write call regardless of
// the probe threshold — ADR-012 Policy A always counts full-file delivery.
func TestSessionWriter_WholeFileCommitsBeforeFirstByte(t *testing.T) {
	mockRepo := mock.NewFileRepository()
	repos := &repository.Repositories{Files: mockRepo}
	ctx := context.Background()

	maxDL := 5
	file := &models.File{
		ClaimCode:    "swwhole",
		FileSize:     1_000_000, // threshold would be clamped to 64KiB
		MaxDownloads: &maxDL,
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("Create: %v", err)
	}
	token, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}

	rec := httptest.NewRecorder()
	sw := newSessionWriter(ctx, rec, repos, file.ID, token, 0, false, true /* wholeFile */)

	// A single tiny write — far under any threshold — must still commit
	// immediately because wholeFile bypasses the threshold entirely.
	if _, err := sw.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !sw.Committed() {
		t.Error("Committed() = false, want true (wholeFile must commit on the first byte)")
	}

	got, err := repos.Files.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1", got.DownloadCount)
	}
}

// TestSessionWriter_TrustedTokenCommitsOnFirstWriteNotBeforehand is a
// regression test for the bug-hunter finding that a resumed-token session
// used to be committed before the caller had confirmed any bytes could
// actually be delivered. A trustedToken writer must NOT be committed at
// construction time (threshold 0 means "commit on the very first successful
// write", not "skip the commit"): if the caller never writes anything — e.g.
// because the file turned out to be unreadable and the request 404s instead
// — no commit must ever have been attempted, and the counters must be
// untouched.
func TestSessionWriter_TrustedTokenCommitsOnFirstWriteNotBeforehand(t *testing.T) {
	mockRepo := mock.NewFileRepository()
	repos := &repository.Repositories{Files: mockRepo}
	ctx := context.Background()

	maxDL := 1
	file := &models.File{
		ClaimCode:    "swtrusted",
		FileSize:     100,
		MaxDownloads: &maxDL,
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rec := httptest.NewRecorder()
	sw := newSessionWriter(ctx, rec, repos, file.ID, "never-reserved", 0, true /* trustedToken */, false)

	// Construction alone must not have committed anything — no Write has
	// happened yet.
	if sw.CommitAttempted() {
		t.Error("CommitAttempted() = true before any Write; construction must not commit")
	}
	got, err := repos.Files.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 0 {
		t.Errorf("download_count = %d, want 0 before any Write", got.DownloadCount)
	}

	// The first real write, however, must commit immediately (threshold 0
	// for a trusted token) — this is what makes a resume that DOES stream
	// bytes still count once the file is actually being delivered.
	if _, err := sw.Write(bytes.Repeat([]byte{'y'}, 100)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !sw.CommitAttempted() || !sw.Committed() {
		t.Error("first Write did not commit a trusted-token session")
	}
	got, err = repos.Files.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1 after the first Write", got.DownloadCount)
	}
}

// TestSessionWriter_TrustedTokenAlreadyCommittedIsIdempotent verifies that a
// trusted token whose session was already committed by an earlier request
// does not double-credit download_count on this request's first write.
func TestSessionWriter_TrustedTokenAlreadyCommittedIsIdempotent(t *testing.T) {
	mockRepo := mock.NewFileRepository()
	repos := &repository.Repositories{Files: mockRepo}
	ctx := context.Background()

	maxDL := 2
	file := &models.File{
		ClaimCode:    "swtrustedidem",
		FileSize:     100,
		MaxDownloads: &maxDL,
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("Create: %v", err)
	}
	token, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}
	if result, err := repos.Files.CommitDownloadSession(ctx, file.ID, token); err != nil || result != repository.DownloadCommitCredited {
		t.Fatalf("CommitDownloadSession: result=%v err=%v", result, err)
	}

	rec := httptest.NewRecorder()
	sw := newSessionWriter(ctx, rec, repos, file.ID, token, 0, true /* trustedToken */, false)
	if _, err := sw.Write(bytes.Repeat([]byte{'z'}, 100)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !sw.Committed() {
		t.Error("Committed() = false, want true")
	}
	if sw.CreditedNow() {
		t.Error("CreditedNow() = true, want false (session was already committed by an earlier request)")
	}
	got, err := repos.Files.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1 (no double-credit)", got.DownloadCount)
	}
}
