package handlers

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/scanning"
)

type dropEnv struct {
	*ghostEnv
	identity *age.X25519Identity
	handler  http.HandlerFunc
}

// newDropEnv builds a test server config with the drop page on, plus the
// identity that opens its drops. env is applied before config.Load.
func newDropEnv(t *testing.T, env map[string]string) *dropEnv {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"DROP_MAX_SIZE", "DROP_MAX_CONCURRENT", "DROP_EXPIRATION_HOURS"} {
		t.Setenv(k, "")
	}
	all := map[string]string{"DROP_RECIPIENT": id.Recipient().String()}
	for k, v := range env {
		all[k] = v
	}
	e := newGhostEnv(t, all)
	return &dropEnv{ghostEnv: e, identity: id, handler: DropHandler(e.repos, e.cfg)}
}

func (e *dropEnv) post(t *testing.T, parts ...multipartPart) *httptest.ResponseRecorder {
	t.Helper()
	req := newMultipartRequest(t, "/drop", parts...)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	return rr
}

// claimCodeFrom pulls the claim code out of a success page.
func claimCodeFrom(t *testing.T, page string) string {
	t.Helper()
	const open = `<code class="drop-code">`
	i := strings.Index(page, open)
	if i < 0 {
		t.Fatalf("no claim code on the page:\n%s", page)
	}
	rest := page[i+len(open):]
	return rest[:strings.Index(rest, "<")]
}

// download fetches a drop with ClaimHandler, as the recipient would.
func (e *dropEnv) download(t *testing.T, code string) []byte {
	t.Helper()
	rr := httptest.NewRecorder()
	ClaimHandler(e.repos, e.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("download status = %d: %s", rr.Code, rr.Body.String())
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, DropStoredFilename) {
		t.Errorf("Content-Disposition = %q, want it to name %s", cd, DropStoredFilename)
	}
	return rr.Body.Bytes()
}

type tarEntry struct {
	hdr  *tar.Header
	data []byte
}

// openDrop decrypts a downloaded drop and reads its archive. It also returns
// the decrypted archive's total size, padding included.
func (e *dropEnv) openDrop(t *testing.T, ciphertext []byte) ([]tarEntry, int64) {
	t.Helper()
	r, err := age.Decrypt(bytes.NewReader(ciphertext), e.identity)
	if err != nil {
		t.Fatalf("age decrypt: %v", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("age read: %v", err)
	}
	var entries []tarEntry
	tr := tar.NewReader(bytes.NewReader(plain))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, tarEntry{hdr, data})
	}
	return entries, int64(len(plain))
}

func (e *dropEnv) record(t *testing.T, code string) *models.File {
	t.Helper()
	f, err := e.repos.Files.GetByClaimCode(t.Context(), code)
	if err != nil || f == nil {
		t.Fatalf("no record for %s: %v", code, err)
	}
	return f
}

func assertNothingStored(t *testing.T, e *dropEnv) {
	t.Helper()
	files, err := storedFiles(e.cfg.UploadDir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("%d file(s) stored after a refused drop", len(files))
	}
}

// jpegWithEXIF is a minimal JPEG carrying an APP1 Exif segment with a marker.
func jpegWithEXIF(marker string) []byte {
	app1 := append([]byte("Exif\x00\x00"), []byte(marker)...)
	n := len(app1) + 2
	b := []byte{0xFF, 0xD8, 0xFF, 0xE1, byte(n >> 8), byte(n)}
	b = append(b, app1...)
	// APP0 JFIF so the file stays a JPEG once APP1 is gone
	b = append(b, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00)
	b = append(b, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00) // SOS
	b = append(b, 0x12, 0x34, 0x56)                                           // scan data
	return append(b, 0xFF, 0xD9)
}

func TestDrop_DisabledIs404(t *testing.T) {
	t.Setenv("DROP_RECIPIENT", "")
	e := newGhostEnv(t, nil)
	rr := httptest.NewRecorder()
	DropHandler(e.repos, e.cfg).ServeHTTP(rr, newMultipartRequest(t, "/drop", multipartPart{name: "message", content: "hi"}))
	if rr.Code != http.StatusNotFound {
		t.Errorf("POST status = %d, want 404", rr.Code)
	}
	rr = httptest.NewRecorder()
	DropPageHandler(e.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/drop", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("GET status = %d, want 404", rr.Code)
	}
}

func TestDropPage_ServesStaticForm(t *testing.T) {
	e := newDropEnv(t, nil)
	rr := httptest.NewRecorder()
	DropPageHandler(e.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/drop", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `action="/drop"`) || !strings.Contains(body, `enctype="multipart/form-data"`) {
		t.Error("page has no multipart form posting to /drop")
	}
	if strings.Contains(strings.ToLower(body), "<script") {
		t.Error("the drop page must not load any script")
	}
}

func TestDrop_FileAndMessage(t *testing.T) {
	// No Go code on the drop path may write the plaintext to the temp dir.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	e := newDropEnv(t, nil)
	content := strings.Repeat("the evidence ", 500)
	rr := e.post(t,
		multipartPart{name: "file", filename: "notes from source.txt", content: content},
		multipartPart{name: "message", content: "Call me never."},
	)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	page := rr.Body.String()
	code := claimCodeFrom(t, page)
	if strings.Contains(page, "notes from source") || strings.Contains(page, "Call me never") {
		t.Error("the result page repeats what was sent")
	}
	if !strings.Contains(page, e.cfg.Drop.RecipientKey) {
		t.Error("the result page doesn't show the key the drop was encrypted to")
	}

	rec := e.record(t, code)
	if rec.OriginalFilename != DropStoredFilename || rec.MimeType != "application/octet-stream" || rec.ClientEncrypted {
		t.Errorf("record = %q %q client_encrypted=%v", rec.OriginalFilename, rec.MimeType, rec.ClientEncrypted)
	}
	if !strings.HasSuffix(rec.StoredFilename, ".age") {
		t.Errorf("stored as %q", rec.StoredFilename)
	}
	if d := time.Until(rec.ExpiresAt); d < 167*time.Hour || d > 169*time.Hour {
		t.Errorf("expires in %v, want about a week", d)
	}

	stored, err := os.ReadFile(filepath.Join(e.cfg.UploadDir, rec.StoredFilename))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("the evidence")) || bytes.Contains(stored, []byte("Call me never")) {
		t.Fatal("plaintext found in the stored file")
	}
	if rec.FileSize != int64(len(stored)) {
		t.Errorf("file_size = %d, stored %d bytes", rec.FileSize, len(stored))
	}

	entries, total := e.openDrop(t, e.download(t, code))
	if len(entries) != 2 {
		t.Fatalf("archive has %d entries, want 2", len(entries))
	}
	if entries[0].hdr.Name != "notes from source.txt" || string(entries[0].data) != content {
		t.Errorf("file entry = %q (%d bytes)", entries[0].hdr.Name, len(entries[0].data))
	}
	if entries[1].hdr.Name != dropMessageName || string(entries[1].data) != "Call me never." {
		t.Errorf("message entry = %q %q", entries[1].hdr.Name, entries[1].data)
	}
	for _, en := range entries {
		h := en.hdr
		if !h.ModTime.Equal(time.Unix(0, 0)) || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || h.Mode != 0o644 {
			t.Errorf("%s header leaks something: mtime=%v uid=%d gid=%d uname=%q gname=%q mode=%o", h.Name, h.ModTime, h.Uid, h.Gid, h.Uname, h.Gname, h.Mode)
		}
	}
	if total != dropPaddedLength(total) {
		t.Errorf("archive is %d bytes, not a padding bucket (next is %d)", total, dropPaddedLength(total))
	}

	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("drop wrote %d file(s) to the temp dir", len(left))
	}
	if files, _ := storedFiles(e.cfg.UploadDir); len(files) != 1 {
		t.Errorf("%d files in the upload dir, want only the ciphertext", len(files))
	}
}

func TestDrop_AtRestEncryption(t *testing.T) {
	e := newDropEnv(t, nil)
	e.cfg.EncryptionKey = strings.Repeat("ab", 32)
	rr := e.post(t, multipartPart{name: "message", content: "layered"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	code := claimCodeFrom(t, rr.Body.String())
	if rec := e.record(t, code); len(rec.EncFileID) == 0 {
		t.Error("no enc_file_id: not encrypted at rest")
	}
	entries, _ := e.openDrop(t, e.download(t, code))
	if len(entries) != 1 || string(entries[0].data) != "layered" {
		t.Errorf("entries = %+v", entries)
	}
}

func TestDrop_GhostModeRecordsNothingIdentifying(t *testing.T) {
	e := newDropEnv(t, map[string]string{"ANONYMOUS_MODE": "true"})
	rr := e.post(t, multipartPart{name: "file", filename: "a.txt", content: "x"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	rec := e.record(t, claimCodeFrom(t, rr.Body.String()))
	if rec.UploaderIP != "anonymous" || rec.SHA256Hash != "" {
		t.Errorf("uploader_ip=%q sha256=%q", rec.UploaderIP, rec.SHA256Hash)
	}
	if rec.CreatedAt.Truncate(time.Hour) != rec.CreatedAt || rec.ExpiresAt.Truncate(time.Hour) != rec.ExpiresAt {
		t.Errorf("times not rounded: created %v expires %v", rec.CreatedAt, rec.ExpiresAt)
	}
}

func TestDrop_StripsJPEGMetadata(t *testing.T) {
	e := newDropEnv(t, nil)
	rr := e.post(t, multipartPart{name: "file", filename: "photo.jpg", content: string(jpegWithEXIF("GPS-SECRET-4711"))})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Hidden information was removed") {
		t.Error("page doesn't say the file was cleaned")
	}
	entries, _ := e.openDrop(t, e.download(t, claimCodeFrom(t, rr.Body.String())))
	if len(entries) != 1 || entries[0].hdr.Name != "photo.jpg" {
		t.Fatalf("entries = %d", len(entries))
	}
	if bytes.Contains(entries[0].data, []byte("GPS-SECRET-4711")) || bytes.Contains(entries[0].data, []byte("Exif")) {
		t.Error("EXIF survived")
	}
	if !bytes.HasPrefix(entries[0].data, []byte{0xFF, 0xD8}) {
		t.Error("cleaned file is no longer a JPEG")
	}
}

func TestDrop_RefusesWhatCantBeCleaned(t *testing.T) {
	cases := []struct {
		name, filename, content, want string
	}{
		{"broken pdf", "report.pdf", "%PDF-1.4\nthis is not really a pdf", "couldn"},
		{"named like a jpeg", "photo.JPG", "plain text, not a photo", "recognised"},
		{"named like a docx", "memo.docx", "plain text, not a document", "recognised"},
		{"docx that is a broken zip", "memo.docx", "PK\x03\x04 not a document", "couldn"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newDropEnv(t, nil)
			rr := e.post(t, multipartPart{name: "file", filename: tc.filename, content: tc.content})
			if rr.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422: %s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tc.want) {
				t.Errorf("page doesn't explain: %s", rr.Body.String())
			}
			assertNothingStored(t, e)
		})
	}
}

func TestDrop_Rejections(t *testing.T) {
	cases := []struct {
		name   string
		env    map[string]string
		parts  []multipartPart
		status int
		want   string
	}{
		{"nothing", nil, []multipartPart{{name: "message", content: "  "}}, http.StatusBadRequest, "Nothing to send"},
		{"no file chosen", nil, []multipartPart{{name: "file", content: ""}, {name: "message", content: ""}}, http.StatusBadRequest, "Nothing to send"},
		{"empty file", nil, []multipartPart{{name: "file", filename: "e.txt", content: ""}}, http.StatusBadRequest, "empty"},
		{"blocked extension", nil, []multipartPart{{name: "file", filename: "run.sh", content: "echo"}}, http.StatusBadRequest, ".sh"},
		{"too large", map[string]string{"DROP_MAX_SIZE": "1024"}, []multipartPart{{name: "file", filename: "big.txt", content: strings.Repeat("x", 2048)}}, http.StatusRequestEntityTooLarge, "1 KB"},
		{"message too long", nil, []multipartPart{{name: "message", content: strings.Repeat("y", dropMaxMessage+1)}}, http.StatusRequestEntityTooLarge, "message is too long"},
		{"control character in name", nil, []multipartPart{{name: "file", filename: "a\x07.txt", content: "x"}}, http.StatusBadRequest, "name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newDropEnv(t, tc.env)
			rr := e.post(t, tc.parts...)
			if rr.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tc.status, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tc.want) {
				t.Errorf("page doesn't mention %q: %s", tc.want, rr.Body.String())
			}
			if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("Content-Type = %q, want an HTML page", ct)
			}
			assertNothingStored(t, e)
		})
	}
}

func TestDrop_MessageOnlyAndNameClash(t *testing.T) {
	e := newDropEnv(t, nil)
	rr := e.post(t,
		multipartPart{name: "file", filename: dropMessageName, content: "a file called message.txt"},
		multipartPart{name: "message", content: "the real message"},
	)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	entries, _ := e.openDrop(t, e.download(t, claimCodeFrom(t, rr.Body.String())))
	if len(entries) != 2 || entries[0].hdr.Name == entries[1].hdr.Name {
		t.Fatalf("entries clash: %v", entries)
	}
	if entries[1].hdr.Name != dropMessageName || string(entries[1].data) != "the real message" {
		t.Errorf("message entry = %q", entries[1].hdr.Name)
	}
}

// slowDrop starts a drop whose body arrives in two parts: first is sent at
// once, the rest when the returned function is called, which then waits
// for the handler and returns its status.
func slowDrop(t *testing.T, e *dropEnv, first int, parts ...multipartPart) func() int {
	t.Helper()
	body, contentType := buildMultipart(t, parts...)
	pr, pw := io.Pipe()
	req := httptest.NewRequest(http.MethodPost, "/drop", pr)
	req.Header.Set("Content-Type", contentType)
	done := make(chan int, 1)
	go func() {
		rr := httptest.NewRecorder()
		e.handler.ServeHTTP(rr, req)
		done <- rr.Code
	}()
	// io.Pipe hands over each write only once the handler has read it.
	if _, err := pw.Write(body.Bytes()[:first]); err != nil {
		t.Fatal(err)
	}
	return func() int {
		if _, err := pw.Write(body.Bytes()[first:]); err != nil {
			t.Fatal(err)
		}
		pw.Close()
		return <-done
	}
}

// A slow sender holds only the memory for what it has sent, so it can't
// lock others out; a full budget turns new drops away.
func TestDrop_SlowSendersShareAMemoryBudget(t *testing.T) {
	const maxSize = 300 * 1024
	e := newDropEnv(t, map[string]string{"DROP_MAX_CONCURRENT": "1", "DROP_MAX_SIZE": "307200"})
	// The budget is one full drop: maxSize + dropMaxMessage.

	// Stalled after a few bytes: others still get through.
	finishSmall := slowDrop(t, e, 10, multipartPart{name: "message", content: "slow"})
	if rr := e.post(t, multipartPart{name: "message", content: "meanwhile"}); rr.Code != http.StatusOK {
		t.Fatalf("drop behind a stalled sender: status %d: %s", rr.Code, rr.Body.String())
	}

	// Stalled after most of a large file: the budget is nearly used up.
	big := strings.Repeat("z", maxSize-1024)
	finishBig := slowDrop(t, e, maxSize-4096, multipartPart{name: "file", filename: "big.txt", content: big})
	rr := e.post(t, multipartPart{name: "file", filename: "second.txt", content: strings.Repeat("y", 200*1024)})
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Errorf("drop past the budget: status %d, Retry-After %q", rr.Code, rr.Header().Get("Retry-After"))
	}

	if code := finishBig(); code != http.StatusOK {
		t.Errorf("large slow drop: status %d", code)
	}
	if code := finishSmall(); code != http.StatusOK {
		t.Errorf("small slow drop: status %d", code)
	}
	if rr := e.post(t, multipartPart{name: "file", filename: "third.txt", content: strings.Repeat("x", 200*1024)}); rr.Code != http.StatusOK {
		t.Errorf("budget not released: status %d", rr.Code)
	}
}

func TestDrop_PostQuantumRecipient(t *testing.T) {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e := newDropEnv(t, map[string]string{"DROP_RECIPIENT": id.Recipient().String()})
	rr := e.post(t, multipartPart{name: "message", content: "quantum-safe"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	r, err := age.Decrypt(bytes.NewReader(e.download(t, claimCodeFrom(t, rr.Body.String()))), id)
	if err != nil {
		t.Fatalf("decrypt with the hybrid identity: %v", err)
	}
	plain, _ := io.ReadAll(r)
	if !bytes.Contains(plain, []byte("quantum-safe")) {
		t.Error("message not found")
	}
	key := id.Recipient().String()
	if page := rr.Body.String(); strings.Contains(page, key) || !strings.Contains(page, key[:24]) || !strings.Contains(page, key[len(key)-24:]) {
		t.Error("result page should show the start and end of a post-quantum key, not all of it")
	}
}

// padmeReference is crypto.js's padmeLength, in floating point as there.
func padmeReference(n int64) int64 {
	if n < 2 {
		return n
	}
	e := math.Floor(math.Log2(float64(n)))
	for math.Pow(2, e+1) <= float64(n) {
		e++
	}
	for math.Pow(2, e) > float64(n) {
		e--
	}
	s := 0.0
	for t := e; t > 0; t = math.Floor(t / 2) {
		s++
	}
	lastBits := e - s
	if lastBits <= 0 {
		return n
	}
	unit := math.Pow(2, lastBits)
	return int64(math.Ceil(float64(n)/unit) * unit)
}

func TestPadmeLength_MatchesBrowser(t *testing.T) {
	check := func(n int64) {
		if got, want := padmeLength(n), padmeReference(n); got != want {
			t.Fatalf("padmeLength(%d) = %d, want %d", n, got, want)
		}
	}
	for n := int64(0); n < 70000; n++ {
		check(n)
	}
	for _, n := range []int64{1 << 20, 1<<20 + 1, 50*1024*1024 - 1, 50 * 1024 * 1024, 123456789, 1<<31 + 7} {
		check(n)
	}
	if got := dropPaddedLength(10); got != dropPadMin {
		t.Errorf("dropPaddedLength(10) = %d, want %d", got, dropPadMin)
	}
}

func TestSealDrop_PaddingIsZeroAfterArchive(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	sealed, err := sealDrop("f.bin", bytes.Repeat([]byte{0xAA}, 5000), "", id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(sealed), id)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(r)
	tr := tar.NewReader(bytes.NewReader(plain))
	if _, err := tr.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("second entry: %v, want EOF", err)
	}
	// 512 header + 5120 data + 1024 end blocks = 6656, padded up to 6656's bucket
	if int64(len(plain)) != dropPaddedLength(6656) {
		t.Errorf("archive = %d bytes, want %d", len(plain), dropPaddedLength(6656))
	}
	if bytes.ContainsFunc(plain[6656:], func(r rune) bool { return r != 0 }) {
		t.Error("padding isn't all zero bytes")
	}
}

type fakeScanner struct {
	result *scanning.ScanResult
	err    error
}

func (f fakeScanner) ScanReader(_ context.Context, r io.Reader, _ int64) (*scanning.ScanResult, error) {
	_, _ = io.Copy(io.Discard, r)
	return f.result, f.err
}

func withFakeScanner(t *testing.T, e *dropEnv, s fakeScanner) {
	t.Helper()
	orig := newScanner
	newScanner = func(*config.Config) malwareScanner { return s }
	t.Cleanup(func() { newScanner = orig })
	e.cfg.Features.SetMalwareScanEnabled(true)
}

func TestDrop_ScanOutcomes(t *testing.T) {
	file := multipartPart{name: "file", filename: "a.txt", content: "hello"}
	t.Run("clean", func(t *testing.T) {
		e := newDropEnv(t, nil)
		withFakeScanner(t, e, fakeScanner{result: &scanning.ScanResult{Clean: true}})
		rr := e.post(t, file)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d", rr.Code)
		}
		if rec := e.record(t, claimCodeFrom(t, rr.Body.String())); rec.ScanStatus != scanning.ScanStatusClean {
			t.Errorf("scan_status = %q", rec.ScanStatus)
		}
	})
	t.Run("infected", func(t *testing.T) {
		e := newDropEnv(t, nil)
		withFakeScanner(t, e, fakeScanner{result: &scanning.ScanResult{Infected: true, VirusName: "Eicar"}})
		if rr := e.post(t, file); rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d", rr.Code)
		}
		assertNothingStored(t, e)
	})
	t.Run("scanner down", func(t *testing.T) {
		e := newDropEnv(t, nil)
		withFakeScanner(t, e, fakeScanner{err: errors.New("clamd unreachable")})
		rr := e.post(t, file)
		if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
			t.Fatalf("status %d, Retry-After %q", rr.Code, rr.Header().Get("Retry-After"))
		}
		assertNothingStored(t, e)
	})
	t.Run("scanner down, unverified allowed", func(t *testing.T) {
		e := newDropEnv(t, nil)
		withFakeScanner(t, e, fakeScanner{err: errors.New("clamd unreachable")})
		e.cfg.ClamAV.AllowUnverified = true
		rr := e.post(t, file)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d", rr.Code)
		}
		if rec := e.record(t, claimCodeFrom(t, rr.Body.String())); rec.ScanStatus != scanning.ScanStatusError {
			t.Errorf("scan_status = %q, want error (not clean)", rec.ScanStatus)
		}
	})
	t.Run("too large to scan", func(t *testing.T) {
		e := newDropEnv(t, nil)
		withFakeScanner(t, e, fakeScanner{result: &scanning.ScanResult{Skipped: true}})
		rr := e.post(t, file)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d", rr.Code)
		}
		if rec := e.record(t, claimCodeFrom(t, rr.Body.String())); rec.ScanStatus == scanning.ScanStatusClean {
			t.Error("a skipped scan is recorded as clean")
		}
	})
	t.Run("message only", func(t *testing.T) {
		e := newDropEnv(t, nil)
		withFakeScanner(t, e, fakeScanner{result: &scanning.ScanResult{Clean: true}})
		rr := e.post(t, multipartPart{name: "message", content: "hi"})
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d", rr.Code)
		}
		if rec := e.record(t, claimCodeFrom(t, rr.Body.String())); rec.ScanStatus != scanning.ScanStatusNotScanned {
			t.Errorf("scan_status = %q", rec.ScanStatus)
		}
	})
}

func TestDrop_FormLimits(t *testing.T) {
	e := newDropEnv(t, nil)
	var parts []multipartPart
	for i := 0; i <= dropMaxParts; i++ {
		parts = append(parts, multipartPart{name: fmt.Sprintf("x%d", i), content: "1"})
	}
	if rr := e.post(t, parts...); rr.Code != http.StatusBadRequest {
		t.Errorf("too many parts: status %d", rr.Code)
	}

	// Only the first file part counts.
	rr := e.post(t,
		multipartPart{name: "file", filename: "first.txt", content: "one"},
		multipartPart{name: "file", filename: "second.txt", content: "two"},
	)
	if rr.Code != http.StatusOK {
		t.Fatalf("two file parts: status %d", rr.Code)
	}
	entries, _ := e.openDrop(t, e.download(t, claimCodeFrom(t, rr.Body.String())))
	if len(entries) != 1 || entries[0].hdr.Name != "first.txt" {
		t.Errorf("entries = %v", entries)
	}

	// A body past the overall limit (file limit plus form slack) is cut off.
	e2 := newDropEnv(t, map[string]string{"DROP_MAX_SIZE": "1024"})
	rr = e2.post(t, multipartPart{name: "junk", content: strings.Repeat("j", dropFormSlack+4096)})
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: status %d", rr.Code)
	}
}

func TestDrop_StripperPanicRefusesDrop(t *testing.T) {
	orig := stripMetadataBytes
	stripMetadataBytes = func([]byte, string) ([]byte, error) { panic("crafted file") }
	t.Cleanup(func() { stripMetadataBytes = orig })

	e := newDropEnv(t, nil)
	rr := e.post(t, multipartPart{name: "file", filename: "photo.jpg", content: string(jpegWithEXIF("x"))})
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422", rr.Code)
	}
	assertNothingStored(t, e)
}

func TestDrop_RealWordDocument(t *testing.T) {
	data, err := os.ReadFile("../../tests/js/fixtures/sample.docx")
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	e := newDropEnv(t, nil)
	rr := e.post(t, multipartPart{name: "file", filename: "memo.docx", content: string(data)})
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Hidden information was removed") {
		t.Error("docx not cleaned")
	}
	entries, _ := e.openDrop(t, e.download(t, claimCodeFrom(t, rr.Body.String())))
	if len(entries) != 1 || bytes.Contains(entries[0].data, []byte("docProps/core.xml")) {
		t.Error("docProps left in the document")
	}
}

func TestDrop_StalledUploadTimesOut(t *testing.T) {
	shrinkIdleReadInterval(t, 200*time.Millisecond)
	e := newDropEnv(t, nil)
	srv := httptest.NewServer(e.handler)
	defer srv.Close()
	status, _ := stallUpload(t, srv, "/drop", "multipart/form-data; boundary=x", 4096, "--x\r\nContent-Disposition: form-data; name=\"message\"\r\n\r\nhel")
	if status != http.StatusRequestTimeout {
		t.Errorf("status %d, want 408", status)
	}
}
