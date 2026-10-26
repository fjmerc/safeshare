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

// fakeServer answers the API calls the CLI makes, counting uploads.
func fakeServer(t *testing.T, uploads *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/config":
			_, _ = io.WriteString(w, `{"max_file_size":1048576,"chunked_upload_threshold":1048576,"chunk_size":65536,"version":"1.17.1"}`)
		case r.URL.Path == "/api/upload":
			n := uploads.Add(1)
			_ = r.ParseMultipartForm(1 << 20)
			_, hdr, _ := r.FormFile("file")
			name := "?"
			if hdr != nil {
				name = hdr.Filename
			}
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

// runCLI runs safeshare-cli with args and returns what it wrote to stdout.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	return out.String(), err
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

	out, err := runCLI(t, "--url", srv.URL, "--json", "upload", file)
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

	out, err := runCLI(t, "--url", srv.URL, "--json", "upload", "--encrypt", file)
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

	_, err := runCLI(t, "--url", srv.URL, "--json", "info", "missing1")
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
	if _, err := runCLI(t, "--url", srv.URL, "--token", "t", "--json", "delete", "abc"); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("delete without --force: %v", err)
	}
}

func TestListAndVersionJSON(t *testing.T) {
	var uploads atomic.Int32
	srv := fakeServer(t, &uploads)

	out, err := runCLI(t, "--url", srv.URL, "--token", "t", "--json", "list")
	if err != nil {
		t.Fatal(err)
	}
	var list map[string]any
	decodeOne(t, out, &list)
	if files, ok := list["files"].([]any); !ok || len(files) != 0 || list["schema"] != 1.0 {
		t.Errorf("list: %s", out)
	}

	out, err = runCLI(t, "--json", "version")
	if err != nil {
		t.Fatal(err)
	}
	var ver map[string]any
	decodeOne(t, out, &ver)
	if ver["version"] != cliVersion() || ver["go"] == "" || ver["schema"] != 1.0 {
		t.Errorf("version: %s", out)
	}

	out, err = runCLI(t, "--url", srv.URL, "--json", "config")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	decodeOne(t, out, &cfg)
	if cfg["version"] != "1.17.1" || cfg["url"] != srv.URL || cfg["max_file_size"] != 1048576.0 {
		t.Errorf("config: %s", out)
	}
}
