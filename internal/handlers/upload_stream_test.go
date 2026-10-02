package handlers

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// storedFiles lists the regular files directly in dir, skipping
// subdirectories such as the upload spool and partial-upload directories.
func storedFiles(dir string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []os.DirEntry
	for _, e := range entries {
		if e.Type().IsRegular() {
			files = append(files, e)
		}
	}
	return files, nil
}

// multipartPart is one part for buildMultipart: a file part when filename
// is set, a plain field otherwise.
type multipartPart struct {
	name, filename, content string
}

func buildMultipart(t *testing.T, parts ...multipartPart) (*bytes.Buffer, string) {
	t.Helper()
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	for _, p := range parts {
		var dst io.Writer
		var err error
		if p.filename != "" {
			dst, err = w.CreateFormFile(p.name, p.filename)
		} else {
			dst, err = w.CreateFormField(p.name)
		}
		if err != nil {
			t.Fatalf("create part %q: %v", p.name, err)
		}
		if _, err := io.WriteString(dst, p.content); err != nil {
			t.Fatalf("write part %q: %v", p.name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return body, w.FormDataContentType()
}

func newMultipartRequest(t *testing.T, target string, parts ...multipartPart) *http.Request {
	t.Helper()
	body, contentType := buildMultipart(t, parts...)
	req := httptest.NewRequest(http.MethodPost, target, body)
	req.Header.Set("Content-Type", contentType)
	return req
}

// assertSpoolEmpty fails if anything is left in the upload spool directory.
func assertSpoolEmpty(t *testing.T, uploadDir string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(uploadDir, uploadSpoolDirName))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read spool dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("spool dir has %d leftover entries", len(entries))
	}
}

func TestSpoolUploadForm_FieldsAroundFile(t *testing.T) {
	dir := t.TempDir()
	req := newMultipartRequest(t, "/api/upload?expires_in_hours=1&source=query",
		multipartPart{name: "password", content: "before"},
		multipartPart{name: "file", filename: "a.txt", content: "hello world"},
		multipartPart{name: "max_downloads", content: "3"},
		multipartPart{name: "file", filename: "second.txt", content: "ignored"},
		multipartPart{name: "expires_in_hours", content: "24"},
	)

	f, header, err := spoolUploadForm(req, "file", dir)
	if err != nil {
		t.Fatalf("spoolUploadForm: %v", err)
	}
	defer f.Close()

	// The first file part wins; the spool file is already unlinked, but
	// stays fully readable through the handle - including the ReadAt and
	// Seek the malware scan and storage steps use.
	got, _ := io.ReadAll(f)
	if string(got) != "hello world" {
		t.Errorf("file content = %q, want %q", got, "hello world")
	}
	buf := make([]byte, 5)
	if _, err := f.ReadAt(buf, 6); err != nil || string(buf) != "world" {
		t.Errorf("ReadAt = %q, %v; want world", buf, err)
	}
	if header.Filename != "a.txt" || header.Size != int64(len("hello world")) {
		t.Errorf("header = %q/%d, want a.txt/%d", header.Filename, header.Size, len("hello world"))
	}
	if ct := header.Header.Get("Content-Type"); ct == "" {
		t.Error("part headers not carried over")
	}
	assertSpoolEmpty(t, dir)

	// Fields before and after the file part are both visible, and the query
	// string wins over the body, as with ParseMultipartForm.
	for field, want := range map[string]string{
		"password":         "before",
		"max_downloads":    "3",
		"expires_in_hours": "1",
		"source":           "query",
	} {
		if got := req.FormValue(field); got != want {
			t.Errorf("FormValue(%q) = %q, want %q", field, got, want)
		}
	}
	if got := req.PostFormValue("expires_in_hours"); got != "24" {
		t.Errorf("PostFormValue(expires_in_hours) = %q, want 24 (body only)", got)
	}
	if got := req.PostFormValue("source"); got != "" {
		t.Errorf("PostFormValue(source) = %q, want empty (query-only)", got)
	}
}

func TestSpoolUploadForm_Errors(t *testing.T) {
	tooMany := make([]multipartPart, maxUploadFormParts+1)
	for i := range tooMany {
		tooMany[i] = multipartPart{name: "f", content: "x"}
	}

	tests := []struct {
		name    string
		parts   []multipartPart
		wantErr error
	}{
		{"no file part", []multipartPart{{name: "password", content: "x"}}, errNoFormFile},
		{"file under another name", []multipartPart{{name: "other", filename: "a.txt", content: "x"}}, errNoFormFile},
		{"field too large", []multipartPart{
			{name: "file", filename: "a.txt", content: "x"},
			{name: "password", content: strings.Repeat("p", maxUploadFormValueSize+1)},
		}, errFormValueTooLarge},
		{"too many parts", tooMany, errTooManyFormParts},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			req := newMultipartRequest(t, "/api/upload", tt.parts...)
			f, _, err := spoolUploadForm(req, "file", dir)
			if f != nil {
				f.Close()
				t.Error("got a file alongside an error")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			assertSpoolEmpty(t, dir)
		})
	}
}

func TestSpoolUploadForm_BodyTooLarge(t *testing.T) {
	dir := t.TempDir()
	req := newMultipartRequest(t, "/api/upload",
		multipartPart{name: "file", filename: "a.txt", content: strings.Repeat("x", 4096)})
	rr := httptest.NewRecorder()
	req.Body = http.MaxBytesReader(rr, req.Body, 1024)

	_, _, err := spoolUploadForm(req, "file", dir)
	var maxErr *http.MaxBytesError
	if !errors.As(err, &maxErr) {
		t.Fatalf("err = %v, want *http.MaxBytesError", err)
	}
	var spoolErr *spoolError
	if errors.As(err, &spoolErr) {
		t.Fatal("a body read failure was reported as a local spool failure")
	}
	assertSpoolEmpty(t, dir)
}

func TestNextFormFilePart_SkipsEarlierParts(t *testing.T) {
	req := newMultipartRequest(t, "/api/upload/chunk/x/0",
		multipartPart{name: "note", content: "skip me"},
		multipartPart{name: "other", filename: "o.bin", content: "skip me too"},
		multipartPart{name: "chunk", filename: "chunk_0", content: "payload"},
	)
	part, err := nextFormFilePart(req, "chunk")
	if err != nil {
		t.Fatalf("nextFormFilePart: %v", err)
	}
	got, _ := io.ReadAll(part)
	if string(got) != "payload" {
		t.Errorf("part content = %q, want payload", got)
	}

	req = newMultipartRequest(t, "/api/upload/chunk/x/0", multipartPart{name: "chunk", content: "no filename"})
	if _, err := nextFormFilePart(req, "chunk"); !errors.Is(err, errNoFormFile) {
		t.Errorf("non-file chunk field: err = %v, want errNoFormFile", err)
	}
}

// TestUploadHandler_SpoolCleanedUp checks that a successful simple upload
// and a rejected one both leave nothing in the spool directory.
func TestUploadHandler_SpoolCleanedUp(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := UploadHandler(repos, cfg)

	tests := []struct {
		name       string
		filename   string
		wantStatus int
	}{
		{"accepted", "ok.txt", http.StatusCreated},
		{"rejected after spooling", "blocked.exe", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newMultipartRequest(t, "/api/upload",
				multipartPart{name: "file", filename: tt.filename, content: "some content"})
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			assertSpoolEmpty(t, cfg.UploadDir)
		})
	}
}

// TestSpoolUploadForm_EmptyFilenameIsNotAFile matches FormFile: a part
// named "file" with filename="" is a plain field, not an uploaded file.
func TestSpoolUploadForm_EmptyFilenameIsNotAFile(t *testing.T) {
	body := "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"\"\r\n\r\ndata\r\n--b--\r\n"
	req := httptest.NewRequest(http.MethodPost, "/api/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	if _, _, err := spoolUploadForm(req, "file", t.TempDir()); !errors.Is(err, errNoFormFile) {
		t.Fatalf("err = %v, want errNoFormFile", err)
	}
}

// TestUploadChunkHandler_StreamedChunkCleanup checks the streamed chunk path:
// an oversized or wrong-sized chunk is rejected without leaving a temp file
// behind, and a correct one is stored with the right checksum.
func TestUploadChunkHandler_StreamedChunkCleanup(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("repositories: %v", err)
	}

	const uploadID = "550e8400-e29b-41d4-a716-4466554400aa"
	if err := repos.PartialUploads.Create(context.Background(), &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "test.txt",
		TotalSize:    1536,
		ChunkSize:    1024,
		TotalChunks:  2,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}); err != nil {
		t.Fatalf("create partial upload: %v", err)
	}
	handler := UploadChunkHandler(repos, cfg)
	chunksDir := utils.GetUploadChunksDir(cfg.UploadDir, uploadID)

	send := func(chunk int, content string) *httptest.ResponseRecorder {
		req := newMultipartRequest(t, "/api/upload/chunk/"+uploadID+"/"+strconv.Itoa(chunk),
			multipartPart{name: "chunk", filename: "chunk", content: content})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	assertNoTemp := func() {
		t.Helper()
		entries, err := os.ReadDir(chunksDir)
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("read chunks dir: %v", err)
		}
		for _, e := range entries {
			if strings.Contains(e.Name(), ".tmp-") {
				t.Fatalf("temp chunk file left behind: %s", e.Name())
			}
		}
	}

	// Last chunk (512 bytes expected) sent with 600 bytes: over the
	// expected size but under the body limit, so an exact size mismatch.
	if rr := send(1, strings.Repeat("B", 600)); rr.Code != http.StatusBadRequest {
		t.Fatalf("oversized last chunk: status = %d, want 400", rr.Code)
	}
	assertNoTemp()

	// Over the body limit (ChunkSize + 1KiB): 413, as before streaming.
	if rr := send(0, strings.Repeat("A", 4096)); rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunk over body limit: status = %d, want 413", rr.Code)
	}
	assertNoTemp()

	// Too short.
	if rr := send(0, strings.Repeat("A", 100)); rr.Code != http.StatusBadRequest {
		t.Fatalf("short chunk: status = %d, want 400", rr.Code)
	}
	assertNoTemp()

	// Correct.
	content := strings.Repeat("A", 1024)
	if rr := send(0, content); rr.Code != http.StatusOK {
		t.Fatalf("valid chunk: status = %d, body %s", rr.Code, rr.Body.String())
	}
	assertNoTemp()
	stored, err := os.ReadFile(utils.GetChunkPath(cfg.UploadDir, uploadID, 0))
	if err != nil || string(stored) != content {
		t.Fatalf("stored chunk mismatch (err %v)", err)
	}

	// Idempotent retry with different bytes conflicts, and leaves no temp.
	if rr := send(0, strings.Repeat("Z", 1024)); rr.Code != http.StatusConflict {
		t.Fatalf("conflicting retry: status = %d, want 409", rr.Code)
	}
	assertNoTemp()
}

func TestStreamChunkToTemp(t *testing.T) {
	dir := t.TempDir()
	const uploadID = "u1"

	tmp, size, sum, err := utils.StreamChunkToTemp(dir, uploadID, 0, strings.NewReader("abc"), 3)
	if err != nil {
		t.Fatalf("exact size: %v", err)
	}
	if size != 3 || sum != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("size/sum = %d/%s", size, sum)
	}
	if err := utils.CommitChunk(tmp, dir, uploadID, 0); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if _, _, _, err := utils.StreamChunkToTemp(dir, uploadID, 1, strings.NewReader("abcd"), 3); !errors.Is(err, utils.ErrChunkTooLarge) {
		t.Errorf("too large: err = %v, want ErrChunkTooLarge", err)
	}

	failing := io.MultiReader(strings.NewReader("ab"), errReader{errors.New("client went away")})
	_, _, _, err = utils.StreamChunkToTemp(dir, uploadID, 2, failing, 10)
	var readErr *utils.ChunkReadError
	if !errors.As(err, &readErr) {
		t.Errorf("read failure: err = %v, want *ChunkReadError", err)
	}

	entries, _ := os.ReadDir(utils.GetUploadChunksDir(dir, uploadID))
	if len(entries) != 1 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("chunks dir = %v, want only the committed chunk", names)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot count open fds: %v", err)
	}
	return len(entries)
}

// TestSpoolUploadForm_ClosesSpoolOnLaterError is a regression test: when the
// file part has been spooled and a later part fails, the spool file must be
// closed (it's unlinked, so only its open descriptor keeps its disk space
// allocated - a directory listing can't show the leak).
func TestSpoolUploadForm_ClosesSpoolOnLaterError(t *testing.T) {
	dir := t.TempDir()
	content := strings.Repeat("x", 1<<20)

	tooLargeField := func() *http.Request {
		return newMultipartRequest(t, "/api/upload",
			multipartPart{name: "file", filename: "a.bin", content: content},
			multipartPart{name: "password", content: strings.Repeat("p", maxUploadFormValueSize+1)})
	}
	// The file part completes, then the next part's header is malformed, so
	// the failure comes from NextPart after spooling has finished.
	malformedNextPart := func() *http.Request {
		body := "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n\r\n" +
			content + "\r\n--b\r\nthis header line has no colon\r\n\r\nx\r\n--b--\r\n"
		req := httptest.NewRequest(http.MethodPost, "/api/upload", strings.NewReader(body))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
		return req
	}

	for name, build := range map[string]func() *http.Request{"field too large": tooLargeField, "malformed next part": malformedNextPart} {
		t.Run(name, func(t *testing.T) {
			before := openFDs(t)
			for i := 0; i < 5; i++ {
				if f, _, err := spoolUploadForm(build(), "file", dir); err == nil {
					f.Close()
					t.Fatal("expected an error")
				}
			}
			if after := openFDs(t); after > before {
				t.Fatalf("open fds grew from %d to %d: spool file not closed", before, after)
			}
		})
	}
}
