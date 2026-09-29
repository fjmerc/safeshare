package handlers

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// fakeDeadlineWriter is a minimal http.ResponseWriter that also implements
// the unexported interface http.ResponseController.SetWriteDeadline looks
// for (interface{ SetWriteDeadline(time.Time) error }), recording every
// SetWriteDeadline/Write call in order so tests can assert exactly when
// idleDeadlineWriter arms/re-arms the deadline relative to Write calls —
// without needing a real, timing-dependent socket.
type fakeDeadlineWriter struct {
	*httptest.ResponseRecorder

	mu           sync.Mutex
	events       []string
	lastDeadline time.Time
}

func newFakeDeadlineWriter() *fakeDeadlineWriter {
	return &fakeDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
}

func (f *fakeDeadlineWriter) SetWriteDeadline(d time.Time) error {
	f.mu.Lock()
	f.events = append(f.events, "deadline")
	f.lastDeadline = d
	f.mu.Unlock()
	return nil
}

func (f *fakeDeadlineWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	f.events = append(f.events, "write")
	f.mu.Unlock()
	return f.ResponseRecorder.Write(p)
}

func (f *fakeDeadlineWriter) snapshot() (events []string, lastDeadline time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...), f.lastDeadline
}

// --- Fix 1 (HIGH, round 3): the idle deadline must be armed before the ---
// --- very first Write, not only after writes that already succeeded.  ---

// TestIdleDeadlineWriter_ArmsDeadlineBeforeFirstWrite is the deterministic
// regression test for the round-3 HIGH finding: the previous implementation
// only reset the write deadline *after* a successful Write, so a client
// that blocks the very first Write (an h2c client advertising a zero
// initial flow-control window and never sending WINDOW_UPDATE — see
// TestClaimHandler_H2C_ZeroInitialWindow_ReleasesDecryptAdmission below —
// or an HTTP/1.1 client whose first ~32KB write blocks before ever
// returning) held admission until the full absolute transfer deadline,
// because the shortening reset never got a chance to run. This proves the
// fix structurally: SetWriteDeadline must be called at construction, before
// any Write.
func TestIdleDeadlineWriter_ArmsDeadlineBeforeFirstWrite(t *testing.T) {
	fw := newFakeDeadlineWriter()
	rc := http.NewResponseController(fw)
	_ = newIdleDeadlineWriter(fw, rc, time.Now().Add(time.Hour))

	events, _ := fw.snapshot()
	if len(events) != 1 || events[0] != "deadline" {
		t.Fatalf("expected exactly one SetWriteDeadline call before any Write, got events=%v", events)
	}
}

// --- Fix 2 (MEDIUM, round 3): slow-drip — average-progress floor ---------

// TestIdleDeadlineWriter_ComputeDeadline verifies the exact three-way
// minimum formula (deadline = min(absolute, now+idle,
// start+grace+written/minDecryptWriteRate), grace == idle) against
// hand-computed expectations, with each scenario's terms separated widely
// enough that a few milliseconds of test-execution jitter can't change
// which term is the minimum.
func TestIdleDeadlineWriter_ComputeDeadline(t *testing.T) {
	originalRate := minDecryptWriteRate
	t.Cleanup(func() { minDecryptWriteRate = originalRate })
	minDecryptWriteRate = 100 // 100 B/s, fixed and deterministic for this test

	t.Run("absolute binds when it is the earliest", func(t *testing.T) {
		now := time.Now()
		idw := &idleDeadlineWriter{
			idle:     time.Hour,
			absolute: now.Add(2 * time.Second),
			start:    now,
			written:  0,
		}
		got := idw.computeDeadline()
		if got.Sub(idw.absolute).Abs() > 10*time.Millisecond {
			t.Errorf("computeDeadline() = %v, want absolute %v", got, idw.absolute)
		}
	})

	t.Run("per-write idle binds when ahead of the average-rate pace", func(t *testing.T) {
		now := time.Now()
		idw := &idleDeadlineWriter{
			idle:     2 * time.Second,
			absolute: now.Add(time.Hour),
			start:    now.Add(-1 * time.Second), // started 1s ago
			written:  1000,                      // at 100 B/s that's 10s worth — way ahead of the 1s actually elapsed
		}
		got := idw.computeDeadline()
		want := now.Add(idw.idle) // now + idle
		if got.Sub(want).Abs() > 10*time.Millisecond {
			t.Errorf("computeDeadline() = %v, want ~%v (per-write idle cap)", got, want)
		}
	})

	t.Run("average-rate floor binds when far behind pace (slow-drip)", func(t *testing.T) {
		now := time.Now()
		idw := &idleDeadlineWriter{
			idle:     2 * time.Second,
			absolute: now.Add(time.Hour),
			start:    now.Add(-100 * time.Second), // started 100s ago
			written:  500,                         // at 100 B/s that's only 5s worth — far behind
		}
		got := idw.computeDeadline()
		want := idw.start.Add(idw.idle).Add(5 * time.Second) // start + grace + written/rate
		if got.Sub(want).Abs() > 10*time.Millisecond {
			t.Errorf("computeDeadline() = %v, want ~%v (average-rate floor)", got, want)
		}
		if !got.Before(now) {
			t.Errorf("a transfer this far behind minDecryptWriteRate should already have a deadline in the past (would be cut off on its next Write), got %v (now=%v)", got, now)
		}
	})

	// Security-audit finding (round 4, latent): a zero absolute must mean
	// "no cap from that bound," not "the deadline itself is zero" — to
	// net.Conn.SetWriteDeadline, a zero Time means "no deadline at all,"
	// the opposite of protection. Should be unreachable via the production
	// call path (serveFileWithRangeSupport only constructs an
	// idleDeadlineWriter when transferDeadline is non-zero), but
	// computeDeadline must fail safe regardless of caller discipline.
	t.Run("zero absolute means no cap, not no deadline", func(t *testing.T) {
		now := time.Now()
		idw := &idleDeadlineWriter{
			idle:     2 * time.Second,
			absolute: time.Time{}, // zero
			start:    now,
			written:  0,
		}
		got := idw.computeDeadline()
		if got.IsZero() {
			t.Fatal("computeDeadline() returned the zero Time for a zero absolute — this disables the write deadline entirely instead of falling back to the per-write/average-rate bounds")
		}
		want := now.Add(idw.idle) // per-write cap: the only other bound in play here
		if got.Sub(want).Abs() > 10*time.Millisecond {
			t.Errorf("computeDeadline() = %v, want ~%v (per-write idle cap, with absolute excluded)", got, want)
		}
	})
}

// TestIdleDeadlineWriter_SlowDripVsAdequateRate exercises the same formula
// through repeated real Write calls with real (short) sleeps between them,
// proving the end-to-end behavioral property the audit asked for: a client
// sustaining less than minDecryptWriteRate on average eventually has its
// deadline fall behind "now" (i.e. its next Write would block past an
// already-expired deadline and get cut off), while a client at or above
// that rate never does.
func TestIdleDeadlineWriter_SlowDripVsAdequateRate(t *testing.T) {
	originalRate := minDecryptWriteRate
	t.Cleanup(func() { minDecryptWriteRate = originalRate })
	minDecryptWriteRate = 1000 // 1000 B/s

	t.Run("below minRate eventually falls behind", func(t *testing.T) {
		fw := newFakeDeadlineWriter()
		rc := http.NewResponseController(fw)
		idw := newIdleDeadlineWriter(fw, rc, time.Now().Add(time.Hour))
		idw.idle = time.Second

		fellBehind := false
		for i := 0; i < 20; i++ {
			time.Sleep(50 * time.Millisecond)
			// 10 bytes every 50ms ~= 200 B/s, well under the 1000 B/s floor.
			if _, err := idw.Write(make([]byte, 10)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if time.Now().After(idw.absolute) {
				break // guard against a pathologically slow CI runner
			}
			_, lastDeadline := fw.snapshot()
			if time.Now().After(lastDeadline) {
				fellBehind = true
				break
			}
		}
		if !fellBehind {
			t.Error("a client sustaining well under minDecryptWriteRate should eventually have a deadline that has already passed")
		}
	})

	t.Run("at or above minRate never falls behind", func(t *testing.T) {
		fw := newFakeDeadlineWriter()
		rc := http.NewResponseController(fw)
		idw := newIdleDeadlineWriter(fw, rc, time.Now().Add(time.Hour))
		idw.idle = time.Second

		for i := 0; i < 20; i++ {
			time.Sleep(50 * time.Millisecond)
			// 150 bytes every 50ms = 3000 B/s, comfortably at/above the 1000 B/s floor.
			if _, err := idw.Write(make([]byte, 150)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			_, lastDeadline := fw.snapshot()
			if time.Now().After(lastDeadline) {
				t.Fatalf("a client at/above minDecryptWriteRate must not have its deadline fall behind now (iteration %d)", i)
			}
		}
	})
}

// --- Fix 3 (MEDIUM, round 3): MAX_ENCRYPTED_DOWNLOADS_PER_IP=0 must also -
// --- disable the per-IP decrypt-memory share, not just concurrency.    ---

func TestPerIPShareCap_DisabledWhenIPTrackerDisabled(t *testing.T) {
	admission := utils.NewDecryptAdmission(1024)

	if got := perIPShareCap(admission, NewInFlightTracker(8)); got != 256 {
		t.Errorf("perIPShareCap with an enabled tracker = %d, want 256 (capacity/4)", got)
	}
	if got := perIPShareCap(admission, nil); got != 0 {
		t.Errorf("perIPShareCap with a disabled (nil) tracker = %d, want 0 (disabled — security-audit finding)", got)
	}
}

// TestClaimHandler_PerIPShare_DisabledEndToEndWhenIPTrackerDisabled proves
// the wiring end-to-end: with MAX_ENCRYPTED_DOWNLOADS_PER_IP=0 (nil
// encryptedRangeIPTracker), two concurrent encrypted downloads from the
// same IP — which would exhaust a quarter-of-budget share if enforcement
// were still active — must both be admitted; only the global budget still
// applies.
func TestClaimHandler_PerIPShare_DisabledEndToEndWhenIPTrackerDisabled(t *testing.T) {
	originalIdle := defaultIdleWriteInterval
	defaultIdleWriteInterval = 5 * time.Second
	t.Cleanup(func() { defaultIdleWriteInterval = originalIdle })

	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testClaimEncKey
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	plaintext := bytes.Repeat([]byte("Z"), 4*1024*1024)
	encrypted, err := utils.EncryptFile(plaintext, testClaimEncKey)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	storedFilename := "sc-share-disabled-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), encrypted, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file := &models.File{
		ClaimCode:        "scsharedisabled",
		OriginalFilename: "share.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	// Budget big enough for two full concurrent downloads of this file
	// (global budget still applies — only the per-IP share is disabled).
	originalAdmission := decryptAdmission
	admission := utils.NewDecryptAdmission(int64(len(encrypted)) * 2)
	decryptAdmission = admission
	t.Cleanup(func() { decryptAdmission = originalAdmission })

	// The key fix under test: a disabled (nil) per-IP tracker.
	originalTracker := encryptedRangeIPTracker
	encryptedRangeIPTracker = nil
	t.Cleanup(func() { encryptedRangeIPTracker = originalTracker })

	handler := ClaimHandler(repos, cfg)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	req := "GET /api/claim/scsharedisabled HTTP/1.1\r\nHost: " + addr + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Give the first request time to be admitted and start streaming
	// before the second, same-IP request arrives.
	time.Sleep(300 * time.Millisecond)

	req2 := httptest.NewRequest(http.MethodGet, "/api/claim/scsharedisabled", nil)
	req2.RemoteAddr = "127.0.0.1:55556" // same IPv4 key as the raw conn above
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	// With per-IP limits disabled, this must be admitted (200 or 206), not
	// rejected with 429 — only the still-active global budget could ever
	// reject it, and it was sized to allow two concurrent downloads.
	if rr2.Code != http.StatusOK && rr2.Code != http.StatusPartialContent {
		t.Fatalf("second concurrent request from the same IP with per-IP limits disabled: status = %d, want 200 or 206 (per-IP share must not apply)", rr2.Code)
	}
}

// --- Fix 1 (HIGH, round 3), h2c reproduction ------------------------------

// TestClaimHandler_H2C_ZeroInitialWindow_ReleasesDecryptAdmission
// reproduces the audit's h2c scenario directly at the protocol level: a
// client that completes the h2c (cleartext HTTP/2) preface, advertises
// SETTINGS_INITIAL_WINDOW_SIZE=0, and then never reads anything (so it
// never sends a WINDOW_UPDATE) can receive precisely zero DATA-frame bytes
// for its stream — the server's very first attempt to write the response
// body blocks deterministically, at the protocol level, regardless of any
// OS socket-buffer sizing. This exercises exactly the "blocks inside the
// first Write" case the round-3 HIGH finding describes, independent of
// (and a more reliable reproduction than) the OS-buffer-dependent
// HTTP/1.1 case below.
func TestClaimHandler_H2C_ZeroInitialWindow_ReleasesDecryptAdmission(t *testing.T) {
	originalIdle := defaultIdleWriteInterval
	defaultIdleWriteInterval = 300 * time.Millisecond
	t.Cleanup(func() { defaultIdleWriteInterval = originalIdle })

	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testClaimEncKey
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	plaintext := bytes.Repeat([]byte("H"), 1024*1024)
	encrypted, err := utils.EncryptFile(plaintext, testClaimEncKey)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	storedFilename := "sc-h2c-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), encrypted, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file := &models.File{
		ClaimCode:        "sch2c1",
		OriginalFilename: "h2c.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	originalAdmission := decryptAdmission
	admission := utils.NewDecryptAdmission(int64(len(encrypted)))
	decryptAdmission = admission
	t.Cleanup(func() { decryptAdmission = originalAdmission })

	handler := ClaimHandler(repos, cfg)

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: handler, Protocols: protocols}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	addr := ln.Addr().String()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("write client preface: %v", err)
	}
	framer := http2.NewFramer(conn, conn)

	// Advertise a zero initial flow-control window for every stream this
	// connection opens — the server can never send a DATA frame byte until
	// a WINDOW_UPDATE raises it, which this client (deliberately, matching
	// the audit's repro) never sends.
	if err := framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
		t.Fatalf("write SETTINGS: %v", err)
	}

	var headerBuf bytes.Buffer
	henc := hpack.NewEncoder(&headerBuf)
	henc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	henc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "http"})
	henc.WriteField(hpack.HeaderField{Name: ":authority", Value: addr})
	henc.WriteField(hpack.HeaderField{Name: ":path", Value: "/api/claim/sch2c1"})
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: headerBuf.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}

	// Never read anything further on this connection — the server's first
	// DATA-frame write for this stream blocks against the permanently-zero
	// window. Wait long enough for the idle deadline (300ms) to fire and
	// release admission.
	time.Sleep(2 * time.Second)

	rr := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/claim/sch2c1", nil)
	req2.RemoteAddr = "203.0.113.44:9999"
	handler.ServeHTTP(rr, req2)
	testutil.AssertStatusCode(t, rr, http.StatusOK)
	if !bytes.Equal(rr.Body.Bytes(), plaintext) {
		t.Error("probe download body mismatch")
	}
}
