package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// T42 test suite (amending ADR-014's session-resume tests in
// claim_session_test.go): a capped download's session is marked complete the
// instant the server finishes writing the response — but a client can be
// interrupted between receiving the last byte and finishing its own write.
// The grace window lets a trusted-token resume still resolve a just-
// completed session for a short window, without double-crediting
// download_count/completed_downloads (the gate the file.downloaded webhook
// itself depends on — see CompleteDownloadSession's `first` return).
//
// Security-audit follow-up: the handler no longer resolves
// DOWNLOAD_SESSION_COMPLETE_GRACE from the environment per request — it
// reads the package-level completeGraceWindow variable that main.go installs
// once at startup via SetCompleteGrace (see session_grace.go). These tests
// call SetCompleteGrace directly instead of setting the env var, and always
// reset it back to 0 afterward so one test's setting can't leak into a
// sibling test (package tests run sequentially by default, but this makes
// that assumption unnecessary to rely on).

// TestSession_GraceWindowResume_PartialContentNoDoubleCount — a resume
// against an already-completed session, presented inside the grace window,
// must succeed (206) with the correct tail bytes and must not touch
// download_count or completed_downloads a second time (the same counter
// CompleteDownloadSession's `first` return gates the file.downloaded webhook
// on, so this also proves the webhook can't re-fire).
func TestSession_GraceWindowResume_PartialContentNoDoubleCount(t *testing.T) {
	SetCompleteGrace(5 * time.Minute)
	t.Cleanup(func() { SetCompleteGrace(0) })
	const fileSize = 4096
	repos, handler, code, file, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	// A full, tokenless GET completes the download in one request.
	full := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, full)
	if rr.Code != http.StatusOK {
		t.Fatalf("initial full GET: status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	token := rr.Header().Get("X-Download-Session")
	if token == "" {
		t.Fatal("initial GET response missing X-Download-Session header")
	}
	fullBody := append([]byte(nil), rr.Body.Bytes()...)

	before, err := repos.Files.GetByID(context.Background(), file.ID)
	if err != nil {
		t.Fatalf("GetByID (before resume): %v", err)
	}
	if before.DownloadCount != 1 || before.CompletedDownloads != 1 {
		t.Fatalf("before resume: download_count=%d completed_downloads=%d, want 1/1", before.DownloadCount, before.CompletedDownloads)
	}

	// Simulate a paused-then-resumed download manager that sends the
	// session token back: it already has every byte
	// except the tail, and asks for the rest with the token from the first
	// response — exactly what happens when the server finished writing but
	// the client hadn't finished reading yet. This is a genuine tail resume
	// (Range starting after byte 0, reaching EOF) — the only shape a
	// completed session's token is accepted for (security-audit follow-up).
	const tailStart = fileSize - 10
	resume := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	resume.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", tailStart, fileSize-1))
	resume.Header.Set("X-Download-Session", token)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, resume)
	if rr2.Code != http.StatusPartialContent {
		t.Fatalf("grace-window resume: status = %d, want 206; body=%q", rr2.Code, rr2.Body.String())
	}
	if got, want := rr2.Body.Bytes(), fullBody[tailStart:]; string(got) != string(want) {
		t.Errorf("grace-window resume body = %x, want %x (the actual tail bytes)", got, want)
	}

	after, err := repos.Files.GetByID(context.Background(), file.ID)
	if err != nil {
		t.Fatalf("GetByID (after resume): %v", err)
	}
	if after.DownloadCount != before.DownloadCount {
		t.Errorf("download_count changed on grace-window resume: before=%d after=%d", before.DownloadCount, after.DownloadCount)
	}
	if after.CompletedDownloads != before.CompletedDownloads {
		t.Errorf("completed_downloads changed on grace-window resume (would double-fire file.downloaded): before=%d after=%d", before.CompletedDownloads, after.CompletedDownloads)
	}
}

// TestSession_GraceWindowResume_ExpiresAfterGrace — once completeGrace has
// elapsed, a resume against a completed, cap-exhausted session must 410
// exactly like pre-T42 behaviour, not resolve indefinitely.
func TestSession_GraceWindowResume_ExpiresAfterGrace(t *testing.T) {
	SetCompleteGrace(1 * time.Second) // minCompleteGrace; keeps the test fast
	t.Cleanup(func() { SetCompleteGrace(0) })
	const fileSize = 4096
	_, handler, code, _, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	full := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, full)
	if rr.Code != http.StatusOK {
		t.Fatalf("initial full GET: status = %d, want 200", rr.Code)
	}
	token := rr.Header().Get("X-Download-Session")
	if token == "" {
		t.Fatal("initial GET response missing X-Download-Session header")
	}

	time.Sleep(1100 * time.Millisecond) // cross the 1s grace boundary

	resume := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	resume.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", fileSize-10, fileSize-1))
	resume.Header.Set("X-Download-Session", token)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, resume)
	if rr2.Code != http.StatusGone {
		t.Errorf("resume past grace window: status = %d, want 410 (cap already spent, grace elapsed)", rr2.Code)
	}
}

// TestSession_GraceWindowResume_ZeroDisablesGraceMatchesPreT42 — grace "0"
// (the default when SetCompleteGrace is never called) must reproduce the
// exact pre-T42 behaviour: a completed session's token never resolves,
// regardless of how recently it completed.
func TestSession_GraceWindowResume_ZeroDisablesGraceMatchesPreT42(t *testing.T) {
	SetCompleteGrace(0)
	const fileSize = 4096
	_, handler, code, _, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	full := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, full)
	if rr.Code != http.StatusOK {
		t.Fatalf("initial full GET: status = %d, want 200", rr.Code)
	}
	token := rr.Header().Get("X-Download-Session")
	if token == "" {
		t.Fatal("initial GET response missing X-Download-Session header")
	}

	// Immediately resume — with grace disabled this must still 410, exactly
	// as it did before T42, even though no time has passed at all.
	resume := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	resume.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", fileSize-10, fileSize-1))
	resume.Header.Set("X-Download-Session", token)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, resume)
	if rr2.Code != http.StatusGone {
		t.Errorf("resume with grace=0: status = %d, want 410 (pre-T42 behaviour restored)", rr2.Code)
	}
}

// TestSession_GraceWindowResume_RejectsNonTailShapes — security-audit
// follow-up: a completed session's token must only resolve for a genuine
// tail resume (a partial Range starting after byte 0 and reaching EOF).
// Anything else presented against a completed session — a plain GET, a
// Range starting at byte 0, or a Range that doesn't reach EOF — must be
// treated exactly like an unresolved token, not stream the file again.
func TestSession_GraceWindowResume_RejectsNonTailShapes(t *testing.T) {
	SetCompleteGrace(5 * time.Minute)
	t.Cleanup(func() { SetCompleteGrace(0) })
	const fileSize = 4096

	newCompletedSession := func(t *testing.T) (http.HandlerFunc, string, string) {
		t.Helper()
		_, handler, code, _, cleanup := setupSessionTest(t, fileSize, 1)
		t.Cleanup(cleanup)
		full := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, full)
		if rr.Code != http.StatusOK {
			t.Fatalf("initial full GET: status = %d, want 200", rr.Code)
		}
		token := rr.Header().Get("X-Download-Session")
		if token == "" {
			t.Fatal("initial GET response missing X-Download-Session header")
		}
		return handler, code, token
	}

	cases := []struct {
		name  string
		apply func(r *http.Request)
	}{
		{"plain_get_no_range", func(r *http.Request) {}},
		{"range_starting_at_zero", func(r *http.Request) {
			r.Header.Set("Range", fmt.Sprintf("bytes=0-%d", fileSize-1))
		}},
		{"range_not_reaching_eof", func(r *http.Request) {
			r.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", fileSize-100, fileSize-2))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler, code, token := newCompletedSession(t)
			req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
			c.apply(req)
			req.Header.Set("X-Download-Session", token)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusGone {
				t.Errorf("non-tail resume shape %q against completed session: status = %d, want 410", c.name, rr.Code)
			}
		})
	}
}

// TestSession_GraceWindowResume_CeilingStillEnforced — a grace-window resume
// is still bounded by the 2x-file-size ReserveSessionBytes ceiling, and
// (security-audit follow-up) that ceiling now covers the WHOLE session,
// including the request that created it — not just resumes. Enough genuine
// tail resumes against the same completed, cap-exhausted session must
// eventually exhaust the ceiling and fall back to a fresh reservation, which
// then 410s because the cap is already spent.
func TestSession_GraceWindowResume_CeilingStillEnforced(t *testing.T) {
	SetCompleteGrace(5 * time.Minute)
	t.Cleanup(func() { SetCompleteGrace(0) })
	const fileSize = 1000 // ceiling = 2 * 1000 = 2000 bytes
	_, handler, code, _, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	// The initial full GET now charges its own fileSize bytes against the
	// ceiling (1000/2000 used) — this is the fix: previously this request
	// was uncharged, leaving the full 2000-byte ceiling available for
	// resumes on top of it (~3x the file size extractable in total).
	full := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, full)
	if rr.Code != http.StatusOK {
		t.Fatalf("initial full GET: status = %d, want 200", rr.Code)
	}
	token := rr.Header().Get("X-Download-Session")
	if token == "" {
		t.Fatal("initial GET response missing X-Download-Session header")
	}

	// Each genuine tail resume (Start>0, reaching EOF — the only shape a
	// completed session accepts) charges its own length against the same
	// ceiling. 500 bytes/resume: 1000 (initial) + 500 + 500 = 2000 fits
	// exactly; a third 500-byte resume would push to 2500 > 2000 and must be
	// refused, falling back to a fresh reservation — which 410s because
	// download_count already reached max_downloads=1 on the very first
	// request.
	const tailRange = "bytes=500-999"
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		req.Header.Set("Range", tailRange)
		req.Header.Set("X-Download-Session", token)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusPartialContent {
			t.Fatalf("tail resume %d: status = %d, want 206; body=%q", i, rr.Code, rr.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	req.Header.Set("Range", tailRange)
	req.Header.Set("X-Download-Session", token)
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req)
	if rr3.Code != http.StatusGone {
		t.Errorf("resume past the 2x ceiling: status = %d, want 410 (ceiling must still bound grace-window replay)", rr3.Code)
	}
}

// TestSession_HostilePreCompletionSequence_BoundedByCeiling — security-audit
// follow-up: the finding was pre-existing even before T42's grace window.
// Splitting a download into an uncharged initial request (`Range:
// bytes=0-(N-2)`) plus trusted-token resumes could extract up to ~3x the
// file size from a max_downloads=1 file, because only resumes charged
// against the 2x-file-size ceiling. This drives a hostile-shaped sequence
// (near-whole-file initial request, then repeated large tail resumes, some
// of them after the download has actually completed — i.e. exercising both
// the pre-completion and the T42 grace-window paths against the same
// ceiling) and asserts the cumulative bytes actually delivered across the
// ENTIRE sequence never exceeds 2x the file size.
func TestSession_HostilePreCompletionSequence_BoundedByCeiling(t *testing.T) {
	SetCompleteGrace(5 * time.Minute)
	t.Cleanup(func() { SetCompleteGrace(0) })
	const fileSize = 1000
	const ceiling = 2 * fileSize
	_, handler, code, _, cleanup := setupSessionTest(t, fileSize, 1)
	defer cleanup()

	totalDelivered := 0

	// Leg 1: a tokenless request for [0, N-2] — deliberately NOT the whole
	// file (doesn't reach EOF), so it doesn't complete the session by
	// itself, but it's well past the probe threshold so it commits and
	// credits download_count. This is the "free" half of the classic T1
	// split-download attack.
	req1 := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	req1.Header.Set("Range", fmt.Sprintf("bytes=0-%d", fileSize-2))
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusPartialContent {
		t.Fatalf("leg 1 (near-whole-file, tokenless): status = %d, want 206", rr1.Code)
	}
	token := rr1.Header().Get("X-Download-Session")
	if token == "" {
		t.Fatal("leg 1 response missing X-Download-Session header")
	}
	totalDelivered += rr1.Body.Len()

	// Leg 2: a trusted tail resume for the final byte — completes the
	// session (this is the legitimate half of a Range-split resume, not
	// abuse by itself).
	req2 := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
	req2.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", fileSize-1, fileSize-1))
	req2.Header.Set("X-Download-Session", token)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusPartialContent {
		t.Fatalf("leg 2 (completing tail byte): status = %d, want 206", rr2.Code)
	}
	totalDelivered += rr2.Body.Len()

	// From here on, the session is completed — every further request must
	// be a genuine tail resume to resolve at all (security-audit follow-up).
	// Hammer it with large, redundant tail resumes (almost the whole file
	// each time) until the ceiling refuses one.
	const hostileRange = "bytes=1-999" // 999 bytes, Start>0, reaches EOF
	var lastCode int
	const maxAttempts = 10
	attempts := 0
	for ; attempts < maxAttempts; attempts++ {
		req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
		req.Header.Set("Range", hostileRange)
		req.Header.Set("X-Download-Session", token)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		lastCode = rr.Code
		if rr.Code == http.StatusPartialContent {
			totalDelivered += rr.Body.Len()
			continue
		}
		break
	}
	if lastCode != http.StatusGone {
		t.Fatalf("hostile tail-resume loop did not terminate in 410 within %d attempts (last status %d) — ceiling may not be enforced", maxAttempts, lastCode)
	}
	if attempts >= maxAttempts {
		t.Fatalf("ceiling never refused a hostile resume within %d attempts — ceiling not enforced", maxAttempts)
	}

	if totalDelivered > ceiling {
		t.Errorf("total bytes delivered across the whole hostile sequence = %d, want <= %d (2x file size)", totalDelivered, ceiling)
	}
}
