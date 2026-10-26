package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	safeshare "github.com/fjmerc/safeshare/sdk/go"
)

// fakeServer answers the API calls the CLI makes, counting uploads. It
// refuses files named reject*. Files: plain0001 (not encrypted), encr0001
// (end-to-end encrypted); claim codes starting "missing" don't exist.
func fakeServer(t *testing.T, uploads *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/claim/plain0001/info":
			_, _ = io.WriteString(w, `{"claim_code":"plain0001","original_filename":"a.txt","file_size":5,"mime_type":"text/plain","download_available":true}`)
		case r.URL.Path == "/api/claim/encr0001/info":
			_, _ = io.WriteString(w, `{"claim_code":"encr0001","original_filename":"encrypted.bin","file_size":64,"client_encrypted":true}`)
		case r.URL.Path == "/api/claim/plain0001":
			_, _ = io.WriteString(w, "hello")
		case r.Method == http.MethodDelete && r.URL.Path == "/api/user/files/plain0001":
			_, _ = io.WriteString(w, `{"message":"deleted"}`)
		case r.URL.Path == "/api/user/files/plain0001/rename":
			_, _ = io.WriteString(w, `{"message":"renamed","new_filename":"b.txt"}`)
		case r.URL.Path == "/api/config":
			_, _ = io.WriteString(w, `{"max_file_size":1048576,"chunked_upload_threshold":1048576,"chunk_size":65536,"version":"1.17.1"}`)
		case r.URL.Path == "/api/upload":
			_ = r.ParseMultipartForm(1 << 20)
			_, hdr, _ := r.FormFile("file")
			name := "?"
			if hdr != nil {
				name = hdr.Filename
			}
			if strings.HasPrefix(name, "reject") {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_, _ = io.WriteString(w, `{"error":"File too large","code":"FILE_TOO_LARGE"}`)
				return
			}
			n := uploads.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"claim_code": fmt.Sprintf("code%04d", n), "original_filename": name, "file_size": 5,
				"mime_type": "text/plain", "expires_at": nil, "max_downloads": nil, "user_id": 7,
			})
		case r.URL.Path == "/api/user/files":
			_, _ = io.WriteString(w, `{"files":[],"total":0}`)
		case strings.HasPrefix(r.URL.Path, "/api/claim/missing"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"File not found","code":"NOT_FOUND"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runCLI runs safeshare-cli with args, without proxies (which would make
// uploads encrypt), and returns everything it wrote to stdout and stderr.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	for _, n := range []string{"SAFESHARE_PROXY", "ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(n, "")
	}
	stdout, stderr = captureOutput(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs(args)
		err = cmd.Execute()
	})
	return stdout, stderr, err
}

// captureOutput runs f with os.Stdout and os.Stderr sent to files, and
// returns what was written to each.
func captureOutput(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	dir := t.TempDir()
	outF, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	errF, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outF, errF
	defer func() {
		os.Stdout, os.Stderr = oldOut, oldErr
		outF.Close()
		errF.Close()
	}()
	f()
	o, _ := os.ReadFile(outF.Name())
	e, _ := os.ReadFile(errF.Name())
	return string(o), string(e)
}

// decodeOne checks out is exactly one line of JSON and decodes it.
func decodeOne(t *testing.T, out string, v any) {
	t.Helper()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("want one line of JSON, got %q", out)
	}
	if err := json.Unmarshal([]byte(out), v); err != nil {
		t.Fatalf("%v: %q", err, out)
	}
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUploadJSON(t *testing.T) {
	var uploads atomic.Int32
	srv := fakeServer(t, &uploads)
	file := writeTemp(t, "a.txt", "hello")

	out, _, err := runCLI(t, "--url", srv.URL, "--json", "upload", file)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	decodeOne(t, out, &got)
	want := map[string]any{
		"schema": 1.0, "file": file, "claim_code": "code0001", "filename": "a.txt", "size": 5.0,
		"mime_type": "text/plain", "expires_at": nil, "download_limit": nil,
		"password_protected": false, "encrypted": false, "url": srv.URL + "/claim/code0001",
	}
	if len(got) != len(want) {
		t.Errorf("fields: got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %#v, want %#v", k, got[k], v)
		}
	}
}

func TestUploadJSONEncryptedHasShareLink(t *testing.T) {
	var uploads atomic.Int32
	srv := fakeServer(t, &uploads)
	file := writeTemp(t, "secret.txt", "hello")

	out, _, err := runCLI(t, "--url", srv.URL, "--json", "upload", "--encrypt", file)
	if err != nil {
		t.Fatal(err)
	}
	var got uploadJSON
	decodeOne(t, out, &got)
	if !got.Encrypted {
		t.Fatalf("not encrypted: %s", out)
	}
	link, err := safeshare.ParseShareURL(got.URL)
	if err != nil {
		t.Fatalf("url %q: %v", got.URL, err)
	}
	if link.BaseURL != srv.URL || link.ClaimCode != got.ClaimCode || link.Key == "" {
		t.Errorf("share link %+v doesn't match %s", link, out)
	}
}

func TestJSONErrors(t *testing.T) {
	var uploads atomic.Int32
	srv := fakeServer(t, &uploads)

	_, _, err := runCLI(t, "--url", srv.URL, "--json", "info", "missing1")
	if err == nil {
		t.Fatal("no error")
	}
	je := newJSONError(err)
	if je.Code != "NOT_FOUND" || je.Status != http.StatusNotFound || je.Error == "" {
		t.Errorf("got %+v", je)
	}
	var buf bytes.Buffer
	if err := printJSON(&buf, newJSONError(errors.New("plain"))); err != nil || buf.String() != `{"error":"plain"}`+"\n" {
		t.Errorf("plain error: %q %v", buf.String(), err)
	}

	// delete can't ask for confirmation under --json.
	if _, _, err := runCLI(t, "--url", srv.URL, "--token", "t", "--json", "delete", "abc"); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("delete without --force: %v", err)
	}
}

func TestListAndVersionJSON(t *testing.T) {
	var uploads atomic.Int32
	srv := fakeServer(t, &uploads)

	out, _, err := runCLI(t, "--url", srv.URL, "--token", "t", "--json", "list")
	if err != nil {
		t.Fatal(err)
	}
	var list map[string]any
	decodeOne(t, out, &list)
	if files, ok := list["files"].([]any); !ok || len(files) != 0 || list["schema"] != 1.0 {
		t.Errorf("list: %s", out)
	}

	out, _, err = runCLI(t, "--json", "version")
	if err != nil {
		t.Fatal(err)
	}
	var ver map[string]any
	decodeOne(t, out, &ver)
	if ver["version"] != cliVersion() || ver["go"] == "" || ver["schema"] != 1.0 {
		t.Errorf("version: %s", out)
	}

	out, _, err = runCLI(t, "--url", srv.URL, "--json", "config")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	decodeOne(t, out, &cfg)
	if cfg["version"] != "1.17.1" || cfg["url"] != srv.URL || cfg["max_file_size"] != 1048576.0 {
		t.Errorf("config: %s", out)
	}
}

func TestUploadSeveralFiles(t *testing.T) {
	var uploads atomic.Int32
	srv := fakeServer(t, &uploads)
	a, b := writeTemp(t, "a.txt", "hello"), writeTemp(t, "b.txt", "hello")
	dir := t.TempDir()

	// A missing file or a directory stops everything before any upload.
	for _, bad := range []string{filepath.Join(dir, "nope"), dir} {
		if _, _, err := runCLI(t, "--url", srv.URL, "upload", a, bad); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
	if n := uploads.Load(); n != 0 {
		t.Fatalf("%d uploads before a bad argument was refused", n)
	}

	out, _, err := runCLI(t, "--url", srv.URL, "--json", "upload", a, b)
	if err != nil {
		t.Fatal(err)
	}
	var docs []uploadJSON
	decodeOne(t, out, &docs)
	if len(docs) != 2 || docs[0].File != a || docs[1].File != b || docs[0].ClaimCode == docs[1].ClaimCode ||
		docs[1].URL != srv.URL+"/claim/"+docs[1].ClaimCode {
		t.Errorf("got %s", out)
	}

	out, _, err = runCLI(t, "--url", srv.URL, "upload", a, b)
	if err != nil || strings.Count(out, srv.URL+"/claim/") != 2 || !strings.Contains(out, "Uploaded 2 of 2 files") {
		t.Errorf("text summary (%v):\n%s", err, out)
	}
}

func TestUploadSeveralFilesWithFailure(t *testing.T) {
	var uploads atomic.Int32
	srv := fakeServer(t, &uploads)
	ok := writeTemp(t, "ok.txt", "hello")
	bad := writeTemp(t, "reject.txt", "hello")

	out, _, err := runCLI(t, "--url", srv.URL, "--json", "upload", bad, ok)
	if err == nil || !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("err = %v", err)
	}
	var docs []map[string]any
	decodeOne(t, out, &docs)
	if len(docs) != 2 || docs[0]["code"] != "FILE_TOO_LARGE" || docs[0]["status"] != 413.0 || docs[0]["claim_code"] != nil ||
		docs[1]["error"] != nil || docs[1]["url"] == nil || uploads.Load() != 1 {
		t.Errorf("got %s", out)
	}

	uploads.Store(0)
	out, _, err = runCLI(t, "--url", srv.URL, "--json", "upload", "--fail-fast", bad, ok)
	if err == nil {
		t.Fatal("no error")
	}
	decodeOne(t, out, &docs)
	if uploads.Load() != 0 || len(docs) != 2 || !strings.Contains(docs[1]["error"].(string), "fail-fast") || !strings.Contains(err.Error(), "1 not attempted") {
		t.Errorf("--fail-fast uploaded %d: %s", uploads.Load(), out)
	}
}

func TestJSONOtherCommands(t *testing.T) {
	var uploads atomic.Int32
	srv := fakeServer(t, &uploads)
	dest := filepath.Join(t.TempDir(), "got.txt")

	cases := []struct {
		args []string
		want map[string]any
	}{
		{[]string{"info", "plain0001"}, map[string]any{"claim_code": "plain0001", "filename": "a.txt", "size": 5.0, "client_encrypted": false}},
		{[]string{"--token", "t", "rename", "plain0001", "b.txt"}, map[string]any{"claim_code": "plain0001", "filename": "b.txt"}},
		{[]string{"--token", "t", "delete", "--force", "plain0001"}, map[string]any{"claim_code": "plain0001", "deleted": true}},
		{[]string{"download", "plain0001", dest}, map[string]any{"claim_code": "plain0001", "filename": "a.txt", "path": dest, "decrypted": false}},
	}
	for _, tc := range cases {
		out, _, err := runCLI(t, append([]string{"--url", srv.URL, "--json"}, tc.args...)...)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		var got map[string]any
		decodeOne(t, out, &got)
		if got["schema"] != 1.0 {
			t.Errorf("%v: no schema: %s", tc.args, out)
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("%v: %s = %#v, want %#v", tc.args, k, got[k], v)
			}
		}
	}
	if data, err := os.ReadFile(dest); err != nil || string(data) != "hello" {
		t.Errorf("downloaded %q, %v", data, err)
	}
}

func TestPrintErrorJSON(t *testing.T) {
	apiErr := &safeshare.APIError{StatusCode: 404, Message: "File not found", Code: "NOT_FOUND"}
	jsonOut = true
	defer func() { jsonOut = false }()
	stdout, stderr := captureOutput(t, func() { printError(apiErr) })
	var got jsonError
	if err := json.Unmarshal([]byte(stderr), &got); err != nil || stdout != "" || got.Code != "NOT_FOUND" || got.Status != 404 {
		t.Errorf("stdout %q, stderr %q (%v)", stdout, stderr, err)
	}

	for args, want := range map[string]bool{"--json list": true, "list --json=true": true, "list": false, "upload -- --json": false} {
		if got := jsonRequested(strings.Fields(args)); got != want {
			t.Errorf("jsonRequested(%q) = %v", args, got)
		}
	}
}

// With --json, verify's report is the only thing on stdout; the text goes
// to stderr.
func TestVerifyJSONOutput(t *testing.T) {
	const page, script = "<html>page</html>", "console.log(1)"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/config":
			_, _ = io.WriteString(w, `{"version":"1.17.0"}`)
		case "/":
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
			_, _ = io.WriteString(w, page)
		case "/assets/app.js", "/assets/crypto.js":
			_, _ = io.WriteString(w, script)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	manifest := writeTemp(t, "web-assets.sha256",
		fmt.Sprintf("%s  assets/app.js\n%s  assets/crypto.js\n%s  index.html\n", hexSum(script), hexSum(script), hexSum(page)))

	out, stderr, err := runCLI(t, "--json", "verify", srv.URL, "--manifest", manifest)
	if err != nil {
		t.Fatal(err)
	}
	var report verifyJSON
	decodeOne(t, out, &report)
	if report.Result != "verified" || !strings.Contains(stderr, "VERIFIED") {
		t.Errorf("stdout %s\nstderr %s", out, stderr)
	}
}
