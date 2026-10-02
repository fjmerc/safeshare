package handlers

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

func TestIdleDeadlineReader_ComputeDeadline(t *testing.T) {
	now := time.Now()
	idle := time.Minute

	t.Run("idle bound when progressing well", func(t *testing.T) {
		idr := &idleDeadlineReader{idle: idle, minRate: 1024, absolute: now.Add(time.Hour), start: now, read: 1 << 30}
		got := idr.computeDeadline()
		if got.Before(now.Add(idle-time.Second)) || got.After(time.Now().Add(idle)) {
			t.Errorf("deadline %v, want about now+%v", got, idle)
		}
	})
	t.Run("absolute caps it", func(t *testing.T) {
		abs := now.Add(10 * time.Second)
		idr := &idleDeadlineReader{idle: idle, minRate: 1024, absolute: abs, start: now, read: 1 << 30}
		if got := idr.computeDeadline(); !got.Equal(abs) {
			t.Errorf("deadline %v, want absolute %v", got, abs)
		}
	})
	t.Run("average-rate floor catches a slow drip", func(t *testing.T) {
		// Started 10 minutes ago and only 10 KiB arrived: at 1 KiB/s that
		// earns start + idle + 10s, long past.
		start := now.Add(-10 * time.Minute)
		idr := &idleDeadlineReader{idle: idle, minRate: 1024, absolute: now.Add(time.Hour), start: start, read: 10 * 1024}
		if got := idr.computeDeadline(); !got.Before(time.Now()) {
			t.Errorf("deadline %v should already have passed", got)
		}
	})
	t.Run("zero absolute never yields a zero deadline", func(t *testing.T) {
		idr := &idleDeadlineReader{idle: idle, minRate: 0, start: now}
		if got := idr.computeDeadline(); got.IsZero() {
			t.Error("got zero deadline (would mean no deadline at all)")
		}
	})
}

// stallUpload sends a request's headers and the first part of its body to
// srv over a raw connection, then stops sending, and returns the status code
// the server answers with and how long that took.
//
// It also checks that the server then closes the connection promptly: a
// stalled body must not leave the connection (and its handler goroutine)
// waiting on the rest of the body, e.g. while net/http tries to drain a
// small unread remainder after the response.
func stallUpload(t *testing.T, srv *httptest.Server, path, contentType string, declaredLen int, partial string) (int, time.Duration) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: test\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s", path, contentType, declaredLen, partial); err != nil {
		t.Fatalf("write request: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading response after stalling: %v (after %v)", err, time.Since(start))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	took := time.Since(start)
	if !resp.Close {
		t.Error("response to a stalled upload should close the connection")
	}

	// The server must actually hang up, not just say it will.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.ReadByte(); err != io.EOF {
		t.Errorf("connection not closed by server after the response: %v", err)
	}
	return resp.StatusCode, took
}

func shrinkIdleReadInterval(t *testing.T, d time.Duration) {
	t.Helper()
	orig := defaultIdleReadInterval
	defaultIdleReadInterval = d
	t.Cleanup(func() { defaultIdleReadInterval = orig })
}

// TestUploadHandler_StalledBodyTimesOut covers T50 on the simple upload
// path: a client that sends part of the body and stops is answered with 408
// after the idle interval, not held until the full transfer deadline.
func TestUploadHandler_StalledBodyTimesOut(t *testing.T) {
	shrinkIdleReadInterval(t, 500*time.Millisecond)
	repos, cfg := testutil.SetupTestRepos(t)
	srv := httptest.NewServer(UploadHandler(repos, cfg))
	defer srv.Close()

	partial := "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n\r\n" + strings.Repeat("x", 4096)
	code, took := stallUpload(t, srv, "/api/upload", "multipart/form-data; boundary=b", 10<<20, partial)
	if code != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want 408", code)
	}
	if took > 8*time.Second {
		t.Fatalf("took %v to time out; idle interval is 500ms", took)
	}
	assertSpoolEmpty(t, cfg.UploadDir)
}

// TestUploadHandler_StalledSmallBody covers a stall with a small unread
// remainder (under net/http's 256 KiB post-response drain threshold) and a
// stall before any body byte arrives at all.
func TestUploadHandler_StalledSmallBody(t *testing.T) {
	shrinkIdleReadInterval(t, 500*time.Millisecond)
	repos, cfg := testutil.SetupTestRepos(t)
	srv := httptest.NewServer(UploadHandler(repos, cfg))
	defer srv.Close()

	partial := "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n\r\n" + strings.Repeat("x", 4096)
	for name, tc := range map[string]struct {
		declared int
		sent     string
	}{
		"small remainder": {8 << 10, partial},
		"no body at all":  {8 << 10, ""},
	} {
		t.Run(name, func(t *testing.T) {
			code, took := stallUpload(t, srv, "/api/upload", "multipart/form-data; boundary=b", tc.declared, tc.sent)
			if code != http.StatusRequestTimeout {
				t.Fatalf("status = %d, want 408", code)
			}
			if took > 8*time.Second {
				t.Fatalf("took %v to time out", took)
			}
		})
	}
}

// TestUploadChunkHandler_StalledBodyTimesOut covers T50 on the chunk path.
func TestUploadChunkHandler_StalledBodyTimesOut(t *testing.T) {
	shrinkIdleReadInterval(t, 500*time.Millisecond)
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("repositories: %v", err)
	}
	const uploadID = "550e8400-e29b-41d4-a716-4466554400bb"
	if err := repos.PartialUploads.Create(context.Background(), &models.PartialUpload{
		UploadID: uploadID, Filename: "a.bin", TotalSize: 2 << 20, ChunkSize: 1 << 20, TotalChunks: 2,
		CreatedAt: time.Now(), LastActivity: time.Now(),
	}); err != nil {
		t.Fatalf("create partial upload: %v", err)
	}
	srv := httptest.NewServer(UploadChunkHandler(repos, cfg))
	defer srv.Close()

	partial := "--b\r\nContent-Disposition: form-data; name=\"chunk\"; filename=\"chunk\"\r\n\r\n" + strings.Repeat("x", 4096)
	code, took := stallUpload(t, srv, "/api/upload/chunk/"+uploadID+"/0", "multipart/form-data; boundary=b", (1<<20)+500, partial)
	if code != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want 408", code)
	}
	if took > 8*time.Second {
		t.Fatalf("took %v to time out; idle interval is 500ms", took)
	}
}

// TestUploadHandler_ProcessingOutlastsIdleInterval checks that a normal
// upload still succeeds end to end when its processing (encrypting 30 MB)
// can take longer than the idle interval: the short idle read deadline must not
// carry over past the body. (On this path UploadHandler re-extends the
// deadlines before scanning anyway, so idleDeadlineReader.restore is a
// second line of defense here.)
func TestUploadHandler_ProcessingOutlastsIdleInterval(t *testing.T) {
	// Long enough that a slow write on a loaded machine can't trip the idle
	// deadline while the body streams; encrypting 30 MB still outlasts it.
	shrinkIdleReadInterval(t, 2*time.Second)
	repos, cfg := testutil.SetupTestRepos(t)
	cfg.EncryptionKey = strings.Repeat("ab", 32)
	cfg.SetMaxFileSize(64 << 20)
	srv := httptest.NewServer(UploadHandler(repos, cfg))
	defer srv.Close()

	body, contentType := buildMultipart(t, multipartPart{name: "file", filename: "big.bin", content: strings.Repeat("z", 30<<20)})
	start := time.Now()
	resp, err := http.Post(srv.URL+"/api/upload", contentType, body)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	t.Logf("upload + processing took %v", time.Since(start))
}

func TestIsUploadTimeout(t *testing.T) {
	timeout := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	cases := map[string]struct {
		err  error
		want bool
	}{
		"raw":                {timeout, true},
		"wrapped":            {fmt.Errorf("skip part: %w", timeout), true},
		"chunk read error":   {&utils.ChunkReadError{Err: timeout}, true},
		"other read failure": {&utils.ChunkReadError{Err: io.ErrUnexpectedEOF}, false},
		"nil":                {nil, false},
	}
	for name, tc := range cases {
		if got := isUploadTimeout(tc.err); got != tc.want {
			t.Errorf("%s: isUploadTimeout = %v, want %v", name, got, tc.want)
		}
	}
}

// TestUploadHandler_StalledBodyAfterParseError covers an error path: the
// body is rejected before being read (not multipart) and then stalls. The
// error response must not wait on the stalled body for the full transfer
// deadline while net/http drains it (it always does for a chunked-encoding
// body).
func TestUploadHandler_StalledBodyAfterParseError(t *testing.T) {
	shrinkIdleReadInterval(t, 500*time.Millisecond)
	repos, cfg := testutil.SetupTestRepos(t)
	srv := httptest.NewServer(UploadHandler(repos, cfg))
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	start := time.Now()
	if _, err := fmt.Fprint(conn, "POST /api/upload HTTP/1.1\r\nHost: test\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n1000\r\n"+strings.Repeat("x", 100)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("no response after %v: %v", time.Since(start), err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Fatalf("status = %d, want an error", resp.StatusCode)
	}
	if took := time.Since(start); took > 8*time.Second {
		t.Fatalf("error response took %v; should not wait out the transfer deadline", took)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.ReadByte(); err != io.EOF {
		t.Errorf("connection not closed after the error response: %v", err)
	}
}
