package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

// --- sessionWriter.ReadFrom: equivalence with the Write path ---------------
//
// rfFakeWriter is a minimal http.ResponseWriter that also implements
// io.ReaderFrom (delegating to the same failure-aware Write logic via
// io.Copy), so tests can exercise sessionWriter.ReadFrom's Phase 3 fast-path
// loop (claimServeWriter/sw.ResponseWriter.(io.ReaderFrom) type assertion)
// rather than only ever falling back to the plain io.Copy-through-Write
// path. failAfter, when >= 0, makes the underlying write fail (simulating a
// client disconnect) once that many bytes have been accepted — shared by
// both Write and ReadFrom so the two paths see an identical failure point.
type rfFakeWriter struct {
	header    http.Header
	buf       bytes.Buffer
	status    int
	failAfter int64
	written   int64
}

func newRFFakeWriter(failAfter int64) *rfFakeWriter {
	return &rfFakeWriter{header: http.Header{}, failAfter: failAfter}
}

func (w *rfFakeWriter) Header() http.Header  { return w.header }
func (w *rfFakeWriter) WriteHeader(code int) { w.status = code }

func (w *rfFakeWriter) Write(p []byte) (int, error) {
	allowed := len(p)
	failing := false
	if w.failAfter >= 0 && w.written+int64(len(p)) > w.failAfter {
		allowed = int(w.failAfter - w.written)
		if allowed < 0 {
			allowed = 0
		}
		failing = true
	}
	n, _ := w.buf.Write(p[:allowed])
	w.written += int64(n)
	if failing {
		return n, fmt.Errorf("simulated write failure at byte %d", w.written)
	}
	return n, nil
}

// ReadFrom gives rfFakeWriter a genuine io.ReaderFrom method (distinct from
// onlyWriter-wrapped Write) so sessionWriter.ReadFrom's fast-path type
// assertion succeeds in tests, exercising the bounded-chunk loop instead of
// only ever falling back to io.Copy-through-Write.
func (w *rfFakeWriter) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(onlyWriter{w}, r)
}

// sessionWriterTestFile creates a fresh file + repos + (optionally reserved)
// token for one ReadFrom-vs-Write comparison subtest. claimCode must be
// unique per subtest (the mock repo keys on it).
func sessionWriterTestFile(t *testing.T, claimCode string, fileSize int64, maxDL int, reserve bool) (*repository.Repositories, *models.File, string, int64) {
	t.Helper()
	mockRepo := mock.NewFileRepository()
	repos := &repository.Repositories{Files: mockRepo}
	ctx := context.Background()

	file := &models.File{
		ClaimCode:    claimCode,
		FileSize:     fileSize,
		MaxDownloads: &maxDL,
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !reserve {
		return repos, file, "", 0
	}
	token, granted, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}
	return repos, file, token, granted
}

// sessionWriterRunResult captures every externally observable outcome of
// driving a sessionWriter, for comparing the Write path against the
// ReadFrom path.
type sessionWriterRunResult struct {
	total           int64
	err             error
	committed       bool
	creditedNow     bool
	commitAttempted bool
	bytesWritten    int64
	destBytes       []byte
	downloadCount   int
}

func captureResult(t *testing.T, repos *repository.Repositories, file *models.File, sw *sessionWriter, dest *rfFakeWriter, total int64, err error) sessionWriterRunResult {
	t.Helper()
	got, gerr := repos.Files.GetByID(context.Background(), file.ID)
	if gerr != nil {
		t.Fatalf("GetByID: %v", gerr)
	}
	return sessionWriterRunResult{
		total:           total,
		err:             err,
		committed:       sw.Committed(),
		creditedNow:     sw.CreditedNow(),
		commitAttempted: sw.CommitAttempted(),
		bytesWritten:    sw.BytesWritten(),
		destBytes:       append([]byte(nil), dest.buf.Bytes()...),
		downloadCount:   got.DownloadCount,
	}
}

// runViaWrite drives data through sw.Write in fixed-size chunks — mimicking
// io.Copy's internal buffering, which is what http.ServeContent's io.CopyN
// falls back to when the destination has no ReadFrom of its own.
func runViaWrite(sw *sessionWriter, data []byte, chunkSize int) (int64, error) {
	var total int64
	for len(data) > 0 {
		n := chunkSize
		if n > len(data) {
			n = len(data)
		}
		w, err := sw.Write(data[:n])
		total += int64(w)
		if err != nil {
			return total, err
		}
		data = data[n:]
	}
	return total, nil
}

func assertResultsEqual(t *testing.T, name string, write, readFrom sessionWriterRunResult) {
	t.Helper()
	if (write.err == nil) != (readFrom.err == nil) {
		t.Errorf("%s: err mismatch: write=%v readFrom=%v", name, write.err, readFrom.err)
	}
	if write.total != readFrom.total {
		t.Errorf("%s: total bytes mismatch: write=%d readFrom=%d", name, write.total, readFrom.total)
	}
	if write.committed != readFrom.committed {
		t.Errorf("%s: committed mismatch: write=%v readFrom=%v", name, write.committed, readFrom.committed)
	}
	if write.creditedNow != readFrom.creditedNow {
		t.Errorf("%s: creditedNow mismatch: write=%v readFrom=%v", name, write.creditedNow, readFrom.creditedNow)
	}
	if write.commitAttempted != readFrom.commitAttempted {
		t.Errorf("%s: commitAttempted mismatch: write=%v readFrom=%v", name, write.commitAttempted, readFrom.commitAttempted)
	}
	if write.bytesWritten != readFrom.bytesWritten {
		t.Errorf("%s: BytesWritten mismatch: write=%d readFrom=%d", name, write.bytesWritten, readFrom.bytesWritten)
	}
	if write.downloadCount != readFrom.downloadCount {
		t.Errorf("%s: download_count mismatch: write=%d readFrom=%d", name, write.downloadCount, readFrom.downloadCount)
	}
	if !bytes.Equal(write.destBytes, readFrom.destBytes) {
		t.Errorf("%s: delivered bytes mismatch (write %d bytes, readFrom %d bytes)", name, len(write.destBytes), len(readFrom.destBytes))
	}
}

// TestSessionWriter_ReadFromMatchesWrite is the core equivalence suite
// (3c-3 scope item 3): for a range of content lengths relative to the probe
// threshold — including exactly at the boundary, where neither path may
// ever commit — sw.ReadFrom(src) in one call must produce identical
// externally observable results to driving the same bytes through
// sw.Write in arbitrary chunking.
func TestSessionWriter_ReadFromMatchesWrite(t *testing.T) {
	const fileSize = int64(2*sessionWriterReadFromChunk + 12345)
	threshold := repository.ProbeThreshold(fileSize)

	cases := []struct {
		name    string
		dataLen int64
	}{
		{"shorter than threshold, never commits", threshold - 100},
		{"exactly at threshold, never commits (boundary)", threshold},
		{"one byte past threshold, commits at the crossing", threshold + 1},
		{"far past threshold, spans multiple ReadFrom chunks", fileSize},
		{"threshold crossing mid-large-transfer", threshold + sessionWriterReadFromChunk + 777},
	}

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := bytes.Repeat([]byte{'a', 'b', 'c', 'd'}, int(c.dataLen/4+1))[:c.dataLen]

			// Write path.
			reposW, fileW, tokenW, grantedW := sessionWriterTestFile(t, fmt.Sprintf("rfcmp-write-%d", i), fileSize, 5, true)
			destW := newRFFakeWriter(-1)
			swW := newSessionWriter(context.Background(), destW, reposW, fileW.ID, tokenW, grantedW, false, false)
			totalW, errW := runViaWrite(swW, data, 4096)
			resW := captureResult(t, reposW, fileW, swW, destW, totalW, errW)

			// ReadFrom path: identical setup, single ReadFrom call.
			reposR, fileR, tokenR, grantedR := sessionWriterTestFile(t, fmt.Sprintf("rfcmp-read-%d", i), fileSize, 5, true)
			destR := newRFFakeWriter(-1)
			swR := newSessionWriter(context.Background(), destR, reposR, fileR.ID, tokenR, grantedR, false, false)
			totalR, errR := swR.ReadFrom(bytes.NewReader(data))
			resR := captureResult(t, reposR, fileR, swR, destR, totalR, errR)

			assertResultsEqual(t, c.name, resW, resR)
		})
	}
}

// TestSessionWriter_ReadFromMatchesWrite_WholeFile mirrors the above for a
// wholeFile-flagged writer, which must commit before the very first byte
// regardless of the threshold value (ADR-012 Policy A).
func TestSessionWriter_ReadFromMatchesWrite_WholeFile(t *testing.T) {
	const fileSize = int64(sessionWriterReadFromChunk + 999)
	data := bytes.Repeat([]byte{'w'}, int(fileSize))

	reposW, fileW, tokenW, _ := sessionWriterTestFile(t, "rfwhole-write", fileSize, 3, true)
	destW := newRFFakeWriter(-1)
	swW := newSessionWriter(context.Background(), destW, reposW, fileW.ID, tokenW, 0, false, true /* wholeFile */)
	totalW, errW := runViaWrite(swW, data, 8192)
	resW := captureResult(t, reposW, fileW, swW, destW, totalW, errW)

	reposR, fileR, tokenR, _ := sessionWriterTestFile(t, "rfwhole-read", fileSize, 3, true)
	destR := newRFFakeWriter(-1)
	swR := newSessionWriter(context.Background(), destR, reposR, fileR.ID, tokenR, 0, false, true /* wholeFile */)
	totalR, errR := swR.ReadFrom(bytes.NewReader(data))
	resR := captureResult(t, reposR, fileR, swR, destR, totalR, errR)

	assertResultsEqual(t, "wholeFile", resW, resR)
	if !resW.committed || resW.bytesWritten != fileSize {
		t.Fatalf("sanity: wholeFile write path should have committed and sent the whole file, got committed=%v bytesWritten=%d", resW.committed, resW.bytesWritten)
	}
}

// TestSessionWriter_ReadFromMatchesWrite_TrustedTokenResume covers the
// "resume with a token" case: a trustedToken writer forces threshold to 0
// (commit on the very first byte), both for a session not yet committed and
// for one an earlier request already committed (idempotent no-op, exercised
// by CommitDownloadSession itself — see TestSessionWriter_
// TrustedTokenAlreadyCommittedIsIdempotent above for the Write-only case).
func TestSessionWriter_ReadFromMatchesWrite_TrustedTokenResume(t *testing.T) {
	const fileSize = int64(50_000)
	data := bytes.Repeat([]byte{'t'}, int(fileSize))

	t.Run("not yet committed", func(t *testing.T) {
		reposW, fileW, tokenW, _ := sessionWriterTestFile(t, "rftrusted-write-fresh", fileSize, 2, true)
		destW := newRFFakeWriter(-1)
		swW := newSessionWriter(context.Background(), destW, reposW, fileW.ID, tokenW, 0, true /* trustedToken */, false)
		totalW, errW := runViaWrite(swW, data, 4096)
		resW := captureResult(t, reposW, fileW, swW, destW, totalW, errW)

		reposR, fileR, tokenR, _ := sessionWriterTestFile(t, "rftrusted-read-fresh", fileSize, 2, true)
		destR := newRFFakeWriter(-1)
		swR := newSessionWriter(context.Background(), destR, reposR, fileR.ID, tokenR, 0, true /* trustedToken */, false)
		totalR, errR := swR.ReadFrom(bytes.NewReader(data))
		resR := captureResult(t, reposR, fileR, swR, destR, totalR, errR)

		assertResultsEqual(t, "trustedToken fresh", resW, resR)
	})

	t.Run("already committed by an earlier request", func(t *testing.T) {
		runOne := func(claimSuffix string) sessionWriterRunResult {
			mockRepo := mock.NewFileRepository()
			repos := &repository.Repositories{Files: mockRepo}
			ctx := context.Background()
			maxDL := 2
			file := &models.File{ClaimCode: "rftrusted-idem-" + claimSuffix, FileSize: fileSize, MaxDownloads: &maxDL, ExpiresAt: time.Now().Add(time.Hour)}
			if err := repos.Files.Create(ctx, file); err != nil {
				t.Fatalf("Create: %v", err)
			}
			token, _, err := repos.Files.ReserveDownload(ctx, file.ID, file.ClaimCode)
			if err != nil || token == "" {
				t.Fatalf("ReserveDownload: %v", err)
			}
			if _, err := repos.Files.CommitDownloadSession(ctx, file.ID, token); err != nil {
				t.Fatalf("CommitDownloadSession: %v", err)
			}
			dest := newRFFakeWriter(-1)
			sw := newSessionWriter(ctx, dest, repos, file.ID, token, 0, true /* trustedToken */, false)
			total, err := sw.ReadFrom(bytes.NewReader(data))
			return captureResult(t, repos, file, sw, dest, total, err)
		}
		res := runOne("read")
		if !res.committed || res.creditedNow {
			t.Errorf("already-committed resume: committed=%v creditedNow=%v, want committed=true creditedNow=false (no double-credit)", res.committed, res.creditedNow)
		}
		if res.downloadCount != 1 {
			t.Errorf("download_count = %d, want 1 (no double-credit)", res.downloadCount)
		}
	})
}

// TestSessionWriter_ReadFromMatchesWrite_Disconnect verifies that a
// destination write failure partway through — simulating a client
// disconnect — produces the same outcome (bytes actually delivered before
// the failure, and commit state) on both paths, for a disconnect that lands
// before the commit threshold (never commits) and one that lands after
// (already committed, then the underlying write fails).
func TestSessionWriter_ReadFromMatchesWrite_Disconnect(t *testing.T) {
	const fileSize = int64(sessionWriterReadFromChunk + 50_000)
	threshold := repository.ProbeThreshold(fileSize)
	data := bytes.Repeat([]byte{'d'}, int(fileSize))

	cases := []struct {
		name      string
		failAfter int64
	}{
		{"disconnect before threshold", threshold / 2},
		{"disconnect after commit, mid-fast-path", threshold + sessionWriterReadFromChunk/2},
	}

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reposW, fileW, tokenW, grantedW := sessionWriterTestFile(t, fmt.Sprintf("rfdisc-write-%d", i), fileSize, 4, true)
			destW := newRFFakeWriter(c.failAfter)
			swW := newSessionWriter(context.Background(), destW, reposW, fileW.ID, tokenW, grantedW, false, false)
			totalW, errW := runViaWrite(swW, data, 4096)
			resW := captureResult(t, reposW, fileW, swW, destW, totalW, errW)

			reposR, fileR, tokenR, grantedR := sessionWriterTestFile(t, fmt.Sprintf("rfdisc-read-%d", i), fileSize, 4, true)
			destR := newRFFakeWriter(c.failAfter)
			swR := newSessionWriter(context.Background(), destR, reposR, fileR.ID, tokenR, grantedR, false, false)
			totalR, errR := swR.ReadFrom(bytes.NewReader(data))
			resR := captureResult(t, reposR, fileR, swR, destR, totalR, errR)

			if resW.err == nil || resR.err == nil {
				t.Fatalf("%s: expected both paths to error, got write=%v readFrom=%v", c.name, resW.err, resR.err)
			}
			assertResultsEqual(t, c.name, resW, resR)
		})
	}
}

// limitedReaderIdentityWriter is a fake ResponseWriter that also implements
// io.ReaderFrom, built specifically to catch the "double io.LimitReader
// wrapping" regression: it asserts that every ReadFrom call receives an
// *io.LimitedReader whose R field is identical (same object, ==) to the
// *os.File wantR captured on construction — never a nested *io.LimitedReader
// wrapping some other *io.LimitedReader. This is exactly what
// net.sendFile's single-level unwrap (net/sendfile.go) and net/http's own
// (*response).ReadFrom require in production; a second wrapping layer here
// would make that same assertion fail against the real stdlib and silently
// defeat sendfile.
type limitedReaderIdentityWriter struct {
	header  http.Header
	buf     bytes.Buffer
	wantR   io.Reader
	calls   int
	failure error // set on the first call that violates the identity invariant
}

func newLimitedReaderIdentityWriter(wantR io.Reader) *limitedReaderIdentityWriter {
	return &limitedReaderIdentityWriter{header: http.Header{}, wantR: wantR}
}

func (w *limitedReaderIdentityWriter) Header() http.Header { return w.header }
func (w *limitedReaderIdentityWriter) WriteHeader(int)     {}
func (w *limitedReaderIdentityWriter) Write(p []byte) (int, error) {
	return w.buf.Write(p)
}

func (w *limitedReaderIdentityWriter) ReadFrom(src io.Reader) (int64, error) {
	w.calls++
	lr, ok := src.(*io.LimitedReader)
	if !ok {
		if w.failure == nil {
			w.failure = fmt.Errorf("ReadFrom call %d: src is %T, want *io.LimitedReader", w.calls, src)
		}
		return 0, w.failure
	}
	if lr.R != w.wantR {
		if w.failure == nil {
			w.failure = fmt.Errorf("ReadFrom call %d: lr.R = %#v, want the original %#v (src was wrapped in a second io.LimitedReader — this defeats net.sendFile's single-level unwrap)", w.calls, lr.R, w.wantR)
		}
		return 0, w.failure
	}
	// Drain via io.Copy against the real lr (not a copy of it) so lr.N is
	// decremented exactly as net.sendFile itself would leave it.
	n, err := io.Copy(&w.buf, lr)
	return n, err
}

// TestSessionWriter_ReadFromPreservesLimitedReaderForSendfile is the
// regression test for the code-review finding that Phase 3 re-wrapped an
// already-*io.LimitedReader src in a second io.LimitReader per chunk,
// which — confirmed directly against the golang:1.27.1 stdlib source —
// makes net.sendFile's single-level *io.LimitedReader unwrap land on the
// inner wrapper instead of the real *os.File, so the syscall.Conn assertion
// fails and sendfile is silently skipped for every capped download.
//
// It drives content large enough (3x sessionWriterReadFromChunk) to force
// several Phase-3 chunk iterations, and asserts every single one of them
// receives the identical *io.LimitedReader object (same lr.R) that
// http.ServeContent's io.CopyN would have constructed exactly once.
func TestSessionWriter_ReadFromPreservesLimitedReaderForSendfile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "sendfile-identity-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()
	content := bytes.Repeat([]byte{'z'}, 3*sessionWriterReadFromChunk+12345)
	if _, err := f.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}

	fileSize := int64(len(content))
	repos, file, token, granted := sessionWriterTestFile(t, "sendfile-identity", fileSize, 2, true)
	dest := newLimitedReaderIdentityWriter(f)
	sw := newSessionWriter(context.Background(), dest, repos, file.ID, token, granted, false, false)

	// Exactly what http.ServeContent's io.CopyN constructs: one
	// *io.LimitedReader wrapping the *os.File, created once, never
	// re-wrapped by anything upstream of ReadFrom.
	lr := &io.LimitedReader{R: f, N: fileSize}

	total, err := sw.ReadFrom(lr)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if total != fileSize {
		t.Fatalf("total = %d, want %d", total, fileSize)
	}
	if dest.failure != nil {
		t.Fatalf("sendfile identity violated: %v", dest.failure)
	}
	if dest.calls < 3 {
		t.Errorf("ReadFrom calls = %d, want >= 3 (content is 3x sessionWriterReadFromChunk, expected multiple chunked calls)", dest.calls)
	}
	if !bytes.Equal(dest.buf.Bytes(), content) {
		t.Error("delivered content mismatch")
	}
	if !sw.Committed() {
		t.Error("Committed() = false, want true (content far exceeds the probe threshold)")
	}
}

// TestSessionWriter_ReadFromFallsBackWithoutReaderFrom verifies ReadFrom
// still produces correct results — just without the fast path — when the
// wrapped ResponseWriter doesn't implement io.ReaderFrom (e.g.
// httptest.ResponseRecorder, or any middleware that strips it).
func TestSessionWriter_ReadFromFallsBackWithoutReaderFrom(t *testing.T) {
	const fileSize = int64(20_000)
	data := bytes.Repeat([]byte{'n'}, int(fileSize))

	repos, file, token, granted := sessionWriterTestFile(t, "rfnofast", fileSize, 1, true)
	rec := httptest.NewRecorder()
	sw := newSessionWriter(context.Background(), rec, repos, file.ID, token, granted, false, false)

	total, err := sw.ReadFrom(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if total != fileSize {
		t.Errorf("total = %d, want %d", total, fileSize)
	}
	if !bytes.Equal(rec.Body.Bytes(), data) {
		t.Error("delivered bytes mismatch")
	}
	if !sw.Committed() {
		t.Error("Committed() = false, want true (content exceeds the probe threshold)")
	}
}
