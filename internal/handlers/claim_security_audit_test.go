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
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// --- Fix 1(a): stalled reader must not pin decrypt admission -------------

// TestClaimHandler_StalledReader_ReleasesDecryptAdmission is the security-
// audit HIGH regression test: a client that stops reading mid-download must
// not pin this download's decrypt-admission weight for up to the full
// transfer deadline (6h) — the write deadline must be re-tightened to a
// short idle window after each successful Write (idleDeadlineWriter), so a
// stalled connection is torn down, and its admission weight released,
// within that window instead.
func TestClaimHandler_StalledReader_ReleasesDecryptAdmission(t *testing.T) {
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

	// A few MB so ServeContent's copy loop issues many Write calls (the
	// legacy path's bytes.Reader is copied through a plain buffered loop —
	// see idleDeadlineWriter's doc for why that matters), giving the OS
	// socket send buffer a real chance to fill against a reader that never
	// drains it.
	plaintext := bytes.Repeat([]byte("S"), 8*1024*1024)
	encrypted, err := utils.EncryptFile(plaintext, testClaimEncKey)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	storedFilename := "sc-stall-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), encrypted, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file := &models.File{
		ClaimCode:        "scstall1",
		OriginalFilename: "stall.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	// Only one legacy decrypt of this size can be admitted at once.
	originalAdmission := decryptAdmission
	admission := utils.NewDecryptAdmission(int64(len(encrypted)))
	decryptAdmission = admission
	t.Cleanup(func() { decryptAdmission = originalAdmission })

	handler := ClaimHandler(repos, cfg)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Open a raw TCP connection, send the request, and deliberately never
	// read the response — simulating the audit's repro (two raw TCP
	// clients that GET and never read).
	addr := strings.TrimPrefix(srv.URL, "http://")
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// Security-audit finding (round 3): shrink this side's advertised
	// receive window as far as the OS allows, so the server's very first
	// Write (not just some later one, once the kernel's default buffers
	// have already filled) has the best achievable chance of blocking
	// immediately — the specific case the round-3 HIGH fix (arming the
	// idle deadline before the first Write, not only after it) targets.
	// The OS is free to clamp this up to its own minimum (Linux typically
	// enforces a floor in the low KB), so this is best-effort, not a
	// guarantee — see TestClaimHandler_H2C_ZeroInitialWindow_ReleasesDecryptAdmission
	// for a deterministic (protocol-level, not OS-buffer-dependent)
	// reproduction of the exact same first-write-blocks scenario.
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetReadBuffer(1)
	}
	req := "GET /api/claim/scstall1 HTTP/1.1\r\nHost: " + addr + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Give the handler time to start streaming, fill the socket buffer,
	// stall, and have its write deadline fire and release admission.
	// Generous relative to the shrunk idle window (300ms).
	time.Sleep(2 * time.Second)

	// A second, well-behaved request must now succeed — proving the
	// stalled holder's admission weight was released, not held for the
	// full (6h) transfer deadline.
	rr := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/claim/scstall1", nil)
	handler.ServeHTTP(rr, req2)
	testutil.AssertStatusCode(t, rr, http.StatusOK)
	if !bytes.Equal(rr.Body.Bytes(), plaintext) {
		t.Error("second (well-behaved) download body mismatch")
	}
}

// --- Fix 1(b): per-IP decrypt-memory budget share -------------------------

func TestDecryptShareTracker_CapsConcurrentPerIPUsage(t *testing.T) {
	tr := &decryptShareTracker{used: make(map[string]int64)}
	const capShare = 100

	if admitted, reserved := tr.tryReserve("1.2.3.4", 60, capShare); !admitted || !reserved {
		t.Fatalf("first reservation (60/100) should succeed and be recorded, got admitted=%v reserved=%v", admitted, reserved)
	}
	if admitted, _ := tr.tryReserve("1.2.3.4", 50, capShare); admitted {
		t.Fatal("second reservation (60+50=110 > 100) should be rejected")
	}
	if admitted, reserved := tr.tryReserve("5.6.7.8", 90, capShare); !admitted || !reserved {
		t.Fatalf("a different IP's reservation must be unaffected, got admitted=%v reserved=%v", admitted, reserved)
	}

	tr.release("1.2.3.4", 60)
	if admitted, reserved := tr.tryReserve("1.2.3.4", 50, capShare); !admitted || !reserved {
		t.Fatalf("after releasing, a reservation that now fits should succeed and be recorded, got admitted=%v reserved=%v", admitted, reserved)
	}

	// A lone request larger than capShare is still admitted (it can't be
	// split, and its own size is already bounded elsewhere — LEGACY_DECRYPT_MAX_BYTES
	// or an SFSE chunk size) — the share cap only rejects a request that
	// would push an already-nonzero holder over the top.
	if admitted, reserved := tr.tryReserve("9.9.9.9", 500, capShare); !admitted || !reserved {
		t.Fatalf("a lone oversized request must still be admitted and recorded, got admitted=%v reserved=%v", admitted, reserved)
	}
	if admitted, _ := tr.tryReserve("9.9.9.9", 1, capShare); admitted {
		t.Fatal("a second request for an IP already over the cap must be rejected")
	}
}

func TestDecryptShareTracker_NonPositiveCapShareDisablesEnforcement(t *testing.T) {
	tr := &decryptShareTracker{used: make(map[string]int64)}
	// Security-audit finding (round 4): capShare<=0 must report admitted
	// but NOT reserved — nothing is actually recorded, so a caller that
	// (correctly) conditions its eventual release() on `reserved` alone
	// never calls release() for these. See
	// TestDecryptShareTracker_UnreservedReleaseDoesNotCorruptADifferentReservation
	// for what goes wrong if a caller releases anyway.
	if admitted, reserved := tr.tryReserve("1.2.3.4", 1000, 0); !admitted || reserved {
		t.Errorf("capShare <= 0: admitted=%v (want true), reserved=%v (want false — nothing should be recorded)", admitted, reserved)
	}
	if admitted, reserved := tr.tryReserve("1.2.3.4", 1000, -1); !admitted || reserved {
		t.Errorf("negative capShare: admitted=%v (want true), reserved=%v (want false)", admitted, reserved)
	}
}

// TestDecryptShareTracker_UnreservedReleaseDoesNotCorruptADifferentReservation
// is the security-audit regression test (round 4) motivating the
// (admitted, reserved) split: a caller that mistakenly calls release() for
// a tryReserve that returned admitted=true but reserved=false (share
// enforcement disabled for that call) must not be able to corrupt a
// *different*, still-legitimately-recorded reservation for the same key —
// which is exactly what release()'s "decrement whatever's in the map"
// logic would do if a caller didn't guard on `reserved`.
func TestDecryptShareTracker_UnreservedReleaseDoesNotCorruptADifferentReservation(t *testing.T) {
	tr := &decryptShareTracker{used: make(map[string]int64)}
	const capShare = 100

	// A legitimate reservation is recorded for this key while sharing is
	// enabled (capShare=100).
	admitted, reserved := tr.tryReserve("1.2.3.4", 60, capShare)
	if !admitted || !reserved {
		t.Fatalf("initial reservation: admitted=%v reserved=%v, want true,true", admitted, reserved)
	}

	// A second call for the SAME key arrives with sharing disabled (e.g. a
	// config change, or simply a call site that always passes 0) — it must
	// be admitted, but NOT recorded.
	admitted2, reserved2 := tr.tryReserve("1.2.3.4", 999, 0)
	if !admitted2 || reserved2 {
		t.Fatalf("disabled-share call: admitted=%v reserved=%v, want true,false", admitted2, reserved2)
	}

	// A correct caller never calls release() for the second (unreserved)
	// call. Simulate that correct behavior, then verify the first
	// reservation's accounting is untouched: a third request for the same
	// key, sized so it only fits if the first 60 is still correctly
	// recorded (60+41=101 > 100 -> reject; 60+40=100 -> admit), proves
	// nothing was corrupted by the interleaved disabled-share call.
	if admitted3, _ := tr.tryReserve("1.2.3.4", 41, capShare); admitted3 {
		t.Fatal("60 (still legitimately reserved) + 41 > 100 should be rejected — the first reservation's accounting was corrupted")
	}
	if admitted4, reserved4 := tr.tryReserve("1.2.3.4", 40, capShare); !admitted4 || !reserved4 {
		t.Fatalf("60 + 40 == 100 should be admitted and recorded, got admitted=%v reserved=%v (first reservation's accounting was corrupted)", admitted4, reserved4)
	}
}

func TestDecryptShareIPKey(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		same bool
	}{
		{"same IPv4", "203.0.113.5", "203.0.113.5", true},
		{"different IPv4", "203.0.113.5", "203.0.113.6", false},
		{"IPv6 same /64", "2001:db8:1234:5678::1", "2001:db8:1234:5678:aaaa:bbbb:cccc:dddd", true},
		{"IPv6 different /64", "2001:db8:1234:5678::1", "2001:db8:1234:9999::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ka := decryptShareIPKey(tc.a)
			kb := decryptShareIPKey(tc.b)
			if (ka == kb) != tc.same {
				t.Errorf("decryptShareIPKey(%q)=%q, decryptShareIPKey(%q)=%q; same=%v, want %v", tc.a, ka, tc.b, kb, ka == kb, tc.same)
			}
		})
	}
}

// TestClaimHandler_PerIPDecryptShare_RejectsSecondConcurrentFromSameIP
// proves the per-IP share is actually wired into acquireDecryptAdmission:
// a second concurrent encrypted download from the same client IP, while
// the first is still holding its share, is rejected even though the
// global memory budget alone would have had room for it.
func TestClaimHandler_PerIPDecryptShare_RejectsSecondConcurrentFromSameIP(t *testing.T) {
	originalIdle := defaultIdleWriteInterval
	defaultIdleWriteInterval = 5 * time.Second // long enough not to fire during this test
	t.Cleanup(func() { defaultIdleWriteInterval = originalIdle })

	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testClaimEncKey
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	plaintext := bytes.Repeat([]byte("P"), 4*1024*1024) // 4MB: big enough to stall on a real socket
	encrypted, err := utils.EncryptFile(plaintext, testClaimEncKey)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	storedFilename := "sc-share-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), encrypted, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file := &models.File{
		ClaimCode:        "scshare1",
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

	// Budget big enough for this one file's weight twice over (so the
	// global budget alone would admit a second concurrent request), but
	// each IP's share (capacity/4) is smaller than one file's weight — so
	// a second concurrent request from the same IP is rejected purely by
	// the per-IP share, not the global budget.
	originalAdmission := decryptAdmission
	admission := utils.NewDecryptAdmission(int64(len(encrypted)) * 2)
	decryptAdmission = admission
	t.Cleanup(func() { decryptAdmission = originalAdmission })

	handler := ClaimHandler(repos, cfg)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	req := "GET /api/claim/scshare1 HTTP/1.1\r\nHost: " + addr + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Give the first request time to be admitted and start streaming
	// (reserving its share) before the second one arrives.
	time.Sleep(300 * time.Millisecond)

	req2 := httptest.NewRequest(http.MethodGet, "/api/claim/scshare1", nil)
	req2.RemoteAddr = "127.0.0.1:55555" // same IPv4 key as the raw conn above (loopback)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second concurrent request from the same IP: status = %d, want %d (per-IP decrypt share exhausted)", rr2.Code, http.StatusTooManyRequests)
	}
}

// --- Fix 3: mid-stream integrity failures must be logged/counted ---------

// TestClaimHandler_SFSE2_WrongHash_LogsIntegrityFailure proves a mid-stream
// (post-headers) SFSE2 whole-file hash mismatch increments
// DownloadsTotal{integrity_failed}. The file has two chunks so Prime(0)
// (which only decrypts chunk 0, not the last chunk) succeeds and headers
// are written normally — the hash check only fires on the actual last
// chunk, reached during http.ServeContent's copy, i.e. after a 200 has
// already been sent. This is the gap fix 3 closes: previously nothing
// observed that failure at all.
func TestClaimHandler_SFSE2_WrongHash_LogsIntegrityFailure(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testClaimEncKey
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// DefaultChunkSize (10MB) + 1KB forces exactly two chunks: chunk 0
	// (primed before headers, not last, hash check doesn't fire) and chunk
	// 1 (the real last chunk, reached only during ServeContent's copy).
	plaintext := bytes.Repeat([]byte("W"), utils.DefaultChunkSize+1024)
	srcPath := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	encFileID, err := utils.GenerateEncFileID()
	if err != nil {
		t.Fatalf("GenerateEncFileID: %v", err)
	}
	storedFilename := "sc-wronghash-uuid.bin"
	dstPath := filepath.Join(cfg.UploadDir, storedFilename)
	if err := utils.EncryptFileStreamingV2(srcPath, dstPath, testClaimEncKey, encFileID); err != nil {
		t.Fatalf("EncryptFileStreamingV2: %v", err)
	}

	// A hash that does not match the real plaintext.
	wrongHash := strings.Repeat("00", 32)
	file := &models.File{
		ClaimCode:        "scwronghash",
		OriginalFilename: "encrypted.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		EncFileID:        encFileID,
		SHA256Hash:       wrongHash,
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	before := promtestutil.ToFloat64(metrics.DownloadsTotal.WithLabelValues("integrity_failed"))

	handler := ClaimHandler(repos, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/scwronghash", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// The response still starts as 200 (headers were already committed
	// before the hash mismatch is discovered on the last chunk) — the
	// failure is only observable server-side via the metric/log, which is
	// exactly the gap being fixed.
	after := promtestutil.ToFloat64(metrics.DownloadsTotal.WithLabelValues("integrity_failed"))
	if after != before+1 {
		t.Errorf("DownloadsTotal{integrity_failed} = %v, want %v (+1)", after, before+1)
	}
}

// --- Fix 4(a): HEAD must not count toward success/size metrics -----------

func TestClaimHandler_HEAD_DoesNotCountSuccessMetricsOrSize(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	content := bytes.Repeat([]byte("M"), 2048)
	storedFilename := "sc-head-metrics-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file := &models.File{
		ClaimCode:        "scheadmetrics",
		OriginalFilename: "metrics.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(content)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	beforeSuccess := promtestutil.ToFloat64(metrics.DownloadsTotal.WithLabelValues("success"))
	beforeSizeCount := histogramSampleCount(t, metrics.DownloadSizeBytes)

	handler := ClaimHandler(repos, cfg)
	req := httptest.NewRequest(http.MethodHead, "/api/claim/scheadmetrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	testutil.AssertStatusCode(t, rr, http.StatusOK)

	afterSuccess := promtestutil.ToFloat64(metrics.DownloadsTotal.WithLabelValues("success"))
	afterSizeCount := histogramSampleCount(t, metrics.DownloadSizeBytes)

	if afterSuccess != beforeSuccess {
		t.Errorf("DownloadsTotal{success} changed by HEAD: before=%v after=%v, want unchanged", beforeSuccess, afterSuccess)
	}
	if afterSizeCount != beforeSizeCount {
		t.Errorf("DownloadSizeBytes sample count changed by HEAD: before=%d after=%d, want unchanged", beforeSizeCount, afterSizeCount)
	}
}

// --- Fix 4(c): conditional headers take precedence over an unsatisfiable Range ---

func TestClaimHandler_UnsatisfiableRange_IfNoneMatchTakesPrecedence(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	content := bytes.Repeat([]byte("C"), 512)
	storedFilename := "sc-pre-inm-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file := &models.File{
		ClaimCode:        "scpreinm",
		OriginalFilename: "pre.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(content)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}
	created, err := repos.Files.GetByClaimCode(ctx, "scpreinm")
	if err != nil || created == nil {
		t.Fatalf("get file: %v", err)
	}
	etag := utils.ComputeClaimETag(created.StoredFilename, created.FileSize, created.CreatedAt)

	handler := ClaimHandler(repos, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/scpreinm", nil)
	req.Header.Set("Range", "bytes=99999-999999") // start beyond file size -> unsatisfiable
	req.Header.Set("If-None-Match", etag)         // client's cache is current
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// RFC 9110 precedence: If-None-Match is evaluated before Range is even
	// considered, so this must be 304, not 416.
	testutil.AssertStatusCode(t, rr, http.StatusNotModified)
	if rr.Body.Len() != 0 {
		t.Errorf("304 response body length = %d, want 0", rr.Body.Len())
	}
}

func TestClaimHandler_UnsatisfiableRange_IfMatchFailureTakesPrecedence(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	content := bytes.Repeat([]byte("D"), 512)
	storedFilename := "sc-pre-im-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file := &models.File{
		ClaimCode:        "scpreim",
		OriginalFilename: "pre.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(content)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	handler := ClaimHandler(repos, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/scpreim", nil)
	req.Header.Set("Range", "bytes=99999-999999")
	req.Header.Set("If-Match", `"does-not-match"`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusPreconditionFailed)
}

func TestClaimHandler_UnsatisfiableRange_NoPreconditions_Still416(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	content := bytes.Repeat([]byte("E"), 512)
	storedFilename := "sc-pre-none-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file := &models.File{
		ClaimCode:        "scprenone",
		OriginalFilename: "pre.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(content)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	handler := ClaimHandler(repos, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/scprenone", nil)
	req.Header.Set("Range", "bytes=99999-999999")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusRequestedRangeNotSatisfiable)
}

// histogramSampleCount extracts a prometheus.Histogram's current observation
// count. promtestutil.ToFloat64 only supports single-value metrics
// (Counter/Gauge/Untyped), so a histogram like metrics.DownloadSizeBytes
// needs its collected proto read directly instead.
func histogramSampleCount(t *testing.T, h prometheus.Histogram) uint64 {
	t.Helper()
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		t.Fatalf("failed to collect histogram: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}
