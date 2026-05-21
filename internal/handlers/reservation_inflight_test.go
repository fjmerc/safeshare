package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
)

// TestInFlightTracker_NilSafe — bug-hunter SH-2.3 M3.
// A nil tracker (cap disabled) must accept everything and never panic.
func TestInFlightTracker_NilSafe(t *testing.T) {
	var tr *InFlightTracker // nil
	if !tr.TryAcquire(1, "10.0.0.1") {
		t.Errorf("nil tracker TryAcquire returned false; want true (cap disabled)")
	}
	tr.Release(1, "10.0.0.1") // must not panic
	if got := tr.MaxPerIP(); got != 0 {
		t.Errorf("nil tracker MaxPerIP = %d, want 0", got)
	}
}

// TestInFlightTracker_DisabledOnZeroMax — NewInFlightTracker(0) returns nil
// so the cap is bypassed without per-call overhead.
func TestInFlightTracker_DisabledOnZeroMax(t *testing.T) {
	for _, max := range []int{0, -1, -100} {
		tr := NewInFlightTracker(max)
		if tr != nil {
			t.Errorf("NewInFlightTracker(%d) = %v, want nil (cap disabled)", max, tr)
		}
	}
}

// TestInFlightTracker_CapPerIPPerFile — the core invariant. Up to maxPerIP
// concurrent acquires per (file, IP) succeed; one more is rejected. Other
// IPs and other files are independent.
func TestInFlightTracker_CapPerIPPerFile(t *testing.T) {
	tr := NewInFlightTracker(2)

	// IP A on file 1: 2 acquires OK, 3rd rejected.
	if !tr.TryAcquire(1, "ipA") {
		t.Fatal("first acquire (ipA, file1) rejected")
	}
	if !tr.TryAcquire(1, "ipA") {
		t.Fatal("second acquire (ipA, file1) rejected")
	}
	if tr.TryAcquire(1, "ipA") {
		t.Fatal("third acquire (ipA, file1) accepted; cap broken")
	}

	// Different IP on the same file: independent.
	if !tr.TryAcquire(1, "ipB") {
		t.Fatal("first acquire (ipB, file1) rejected — different IPs must not share counters")
	}

	// Same IP on a different file: independent.
	if !tr.TryAcquire(2, "ipA") {
		t.Fatal("first acquire (ipA, file2) rejected — different files must not share counters")
	}

	// Release a slot for (ipA, file1) — should re-open one acquire.
	tr.Release(1, "ipA")
	if !tr.TryAcquire(1, "ipA") {
		t.Fatal("post-release acquire (ipA, file1) rejected; slot not freed")
	}
}

// TestInFlightTracker_ReleaseIdempotentAtZero — Release on an empty counter
// must not underflow or panic.
func TestInFlightTracker_ReleaseIdempotentAtZero(t *testing.T) {
	tr := NewInFlightTracker(1)

	// Release without acquire — must no-op.
	tr.Release(1, "ipX")
	// And we must still be able to acquire normally.
	if !tr.TryAcquire(1, "ipX") {
		t.Fatal("post-spurious-release acquire rejected; cap state corrupted")
	}
	tr.Release(1, "ipX")
	// Double-release tolerated.
	tr.Release(1, "ipX")
	// Re-acquire still works.
	if !tr.TryAcquire(1, "ipX") {
		t.Fatal("re-acquire after double-release rejected")
	}
}

// TestClaimHandler_InFlightCapReturns429 — the integration assertion.
// When the tracker is pre-loaded with `max` reservations for (file, IP),
// the next request from that IP must be refused with HTTP 429 and the
// reservation table must NOT be touched (the 429 is enforced before
// ReserveDownload).
func TestClaimHandler_InFlightCapReturns429(t *testing.T) {
	// Install a tracker with cap=2 for the duration of this test.
	prev := GetInFlightTracker()
	SetInFlightTracker(NewInFlightTracker(2))
	t.Cleanup(func() { SetInFlightTracker(prev) })

	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	handler := ClaimHandler(repos, cfg)
	ctx := context.Background()

	body := []byte("m3 inflight-cap body")
	storedFilename := "sh23-m3.bin"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	if err := os.WriteFile(filePath, body, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	defer os.Remove(filePath)

	// max_downloads is large so the DB-level reservation cap can't reject;
	// any 429 we see must come from the in-flight tracker.
	maxDL := 100
	file := &models.File{
		ClaimCode:        "sh23m3",
		OriginalFilename: "m3.bin",
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

	// Pre-load the tracker: 2 in-flight reservations for this (file, IP) —
	// simulates two concurrent slow streams from the same attacker IP.
	tracker := GetInFlightTracker()
	const attackerIP = "192.0.2.10"
	if !tracker.TryAcquire(file.ID, attackerIP) {
		t.Fatal("pre-load acquire #1 rejected")
	}
	if !tracker.TryAcquire(file.ID, attackerIP) {
		t.Fatal("pre-load acquire #2 rejected")
	}

	// A third request from the same attacker IP must be refused at the
	// in-flight layer, without touching ReserveDownload.
	req := httptest.NewRequest(http.MethodGet, "/api/claim/sh23m3", nil)
	req.RemoteAddr = attackerIP + ":54321"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d (in-flight cap); body=%q", rr.Code, http.StatusTooManyRequests, rr.Body.String())
	}
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Errorf("Retry-After header missing on 429")
	}

	// The reservation table must NOT have a row from this attacker — the
	// rejection happened pre-Reserve. Probe via Reserve from a different
	// IP-like context (mock repo would expose this directly; here, we just
	// verify counters are clean).
	got, _ := repos.Files.GetByID(ctx, file.ID)
	if got.DownloadCount != 0 {
		t.Errorf("download_count = %d, want 0 (429 must not credit)", got.DownloadCount)
	}

	// A DIFFERENT IP must still be allowed through (independence guarantee).
	legitReq := httptest.NewRequest(http.MethodGet, "/api/claim/sh23m3", nil)
	legitReq.RemoteAddr = "198.51.100.5:12345"
	legitRR := httptest.NewRecorder()
	handler.ServeHTTP(legitRR, legitReq)
	if legitRR.Code != http.StatusOK {
		t.Errorf("legitimate IP got status = %d, want 200; body=%q", legitRR.Code, legitRR.Body.String())
	}

	// After releasing one attacker slot, that IP can claim again.
	tracker.Release(file.ID, attackerIP)
	retryReq := httptest.NewRequest(http.MethodGet, "/api/claim/sh23m3", nil)
	retryReq.RemoteAddr = attackerIP + ":54322"
	retryRR := httptest.NewRecorder()
	handler.ServeHTTP(retryRR, retryReq)
	if retryRR.Code != http.StatusOK {
		t.Errorf("post-release retry: status = %d, want 200", retryRR.Code)
	}

	// Cleanup the pre-loaded slot.
	tracker.Release(file.ID, attackerIP)
}
