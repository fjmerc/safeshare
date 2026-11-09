package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// cliBundleFake is a bundle API for CLI tests: create, member upload,
// publish, delete, info, file download and the owner's list.
type cliBundleFake struct {
	mu        sync.Mutex
	members   map[int][]byte
	names     map[int]string
	encrypted bool
	manifest  []byte
	published bool
	deleted   bool
	failAt    int
}

const cliBundleCode = "CliBundle01"

func newCLIBundleFake(t *testing.T) (*cliBundleFake, *httptest.Server) {
	f := &cliBundleFake{members: map[int][]byte{}, names: map[int]string{}, failAt: -1}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"max_file_size":10485760,"chunked_upload_threshold":104857600,"chunk_size":1048576}`)
	})
	mux.HandleFunc("/api/bundles", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.encrypted, _ = body["client_encrypted"].(bool)
		f.mu.Unlock()
		w.WriteHeader(201)
		io.WriteString(w, `{"bundle_id":3,"bundle_code":"`+cliBundleCode+`","upload_token":"tok","expires_at":"2030-01-01T00:00:00Z"}`)
	})
	mux.HandleFunc("/api/bundles/3/publish", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			M []byte `json:"encrypted_manifest"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.manifest, f.published = body.M, true
		f.mu.Unlock()
		io.WriteString(w, `{"bundle_code":"`+cliBundleCode+`","expires_at":"2030-01-01T00:00:00Z","max_downloads":null,"files":[]}`)
	})
	mux.HandleFunc("/api/bundles/3", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.deleted = true
		f.mu.Unlock()
		w.WriteHeader(204)
	})
	mux.HandleFunc("/api/upload", func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(32 << 20)
		pos, _ := strconv.Atoi(r.FormValue("bundle_position"))
		if pos == f.failAt {
			w.WriteHeader(422)
			io.WriteString(w, `{"error":"Malware detected: test","code":"MALWARE_DETECTED"}`)
			return
		}
		file, h, _ := r.FormFile("file")
		data, _ := io.ReadAll(file)
		f.mu.Lock()
		f.members[pos], f.names[pos] = data, h.Filename
		f.mu.Unlock()
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"bundle_id": 3, "bundle_position": pos, "original_filename": h.Filename, "file_size": len(data)})
	})
	mux.HandleFunc("/api/bundle/"+cliBundleCode+"/info", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var files []map[string]any
		for i := 0; i < len(f.members); i++ {
			files = append(files, map[string]any{"position": i, "original_filename": f.names[i], "file_size": len(f.members[i])})
		}
		info := map[string]any{"bundle_code": cliBundleCode, "file_count": len(files), "client_encrypted": f.encrypted, "files": files}
		if f.manifest != nil {
			info["encrypted_manifest"] = f.manifest
		}
		json.NewEncoder(w).Encode(info)
	})
	mux.HandleFunc("/api/bundle/"+cliBundleCode+"/files/", func(w http.ResponseWriter, r *http.Request) {
		pos, _ := strconv.Atoi(r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Write(f.members[pos])
	})
	mux.HandleFunc("/api/user/bundles", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"bundles":[{"id":3,"bundle_code":"`+cliBundleCode+`","created_at":"2030-01-01T00:00:00Z","expires_at":"2030-01-02T00:00:00Z","max_downloads":null,"password_protected":false,"client_encrypted":false,"file_count":2,"total_size":7,"files":[{"position":0,"name":"a.txt","size":3,"completed_downloads":0},{"position":1,"name":"b.txt","size":4,"completed_downloads":1}]}],"total":1,"limit":50,"offset":0}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return f, srv
}

func TestUploadBundleJSON(t *testing.T) {
	f, srv := newCLIBundleFake(t)
	a, b := writeTemp(t, "a.txt", "aaa"), writeTemp(t, "b.txt", "bbbb")
	out, _, err := runCLI(t, "--url", srv.URL, "--json", "upload", "--bundle", a, b)
	if err != nil {
		t.Fatal(err)
	}
	var doc bundleJSON
	decodeOne(t, out, &doc)
	if doc.Schema != 1 || doc.BundleCode != cliBundleCode || doc.URL != srv.URL+"/#/bundle/"+cliBundleCode || doc.Encrypted ||
		len(doc.Files) != 2 || doc.Files[0].File != a || doc.Files[1].Name != "b.txt" || doc.Files[1].Size != 4 || doc.Files[1].Position != 1 {
		t.Fatalf("doc: %s", out)
	}
	if !f.published || string(f.members[1]) != "bbbb" {
		t.Fatal("bundle not uploaded")
	}

	// A failed file: one error object naming it, the draft deleted, exit status non-zero.
	f2, srv2 := newCLIBundleFake(t)
	f2.failAt = 1
	out, _, err = runCLI(t, "--url", srv2.URL, "--json", "upload", "--bundle", a, b)
	var errDoc uploadErrorJSON
	decodeOne(t, out, &errDoc)
	if err == nil || errDoc.File != b || errDoc.Code != "MALWARE_DETECTED" || !f2.deleted || f2.published {
		t.Fatalf("failure: err=%v doc=%s deleted=%v", err, out, f2.deleted)
	}
}

func TestUploadBundleQR(t *testing.T) {
	_, srv := newCLIBundleFake(t)
	a, b := writeTemp(t, "a.txt", "aaa"), writeTemp(t, "b.txt", "bbbb")
	out, _, err := runCLI(t, "--url", srv.URL, "upload", "--bundle", "--no-progress", "--qr", a, b)
	if err != nil {
		t.Fatal(err)
	}
	link := srv.URL + "/#/bundle/" + cliBundleCode
	if !strings.Contains(out, link) || !strings.Contains(out, "a.txt") || !strings.Contains(out, "b.txt") {
		t.Fatalf("output:\n%s", out)
	}
	var want bytes.Buffer
	if err := printQR(&want, link); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, want.String()) != 1 || strings.Count(out, "█") != strings.Count(want.String(), "█") {
		t.Fatalf("want exactly one QR code, of %s:\n%s", link, out)
	}
}

func TestUploadBundleFailFastConflict(t *testing.T) {
	_, srv := newCLIBundleFake(t)
	a := writeTemp(t, "a.txt", "aaa")
	if _, _, err := runCLI(t, "--url", srv.URL, "upload", "--bundle", "--fail-fast", a); err == nil || !strings.Contains(err.Error(), "--fail-fast") {
		t.Fatalf("err = %v", err)
	}
}

func TestDownloadBundleLink(t *testing.T) {
	for _, encrypt := range []bool{false, true} {
		_, srv := newCLIBundleFake(t)
		a, b := writeTemp(t, "a.txt", "aaa"), writeTemp(t, "b.txt", "bbbb")
		args := []string{"--url", srv.URL, "--json", "upload", "--bundle"}
		if encrypt {
			args = append(args, "--encrypt")
		}
		out, _, err := runCLI(t, append(args, a, b)...)
		if err != nil {
			t.Fatal(err)
		}
		var up bundleJSON
		decodeOne(t, out, &up)

		dir := filepath.Join(t.TempDir(), "got")
		out, _, err = runCLI(t, "--json", "download", up.URL, dir)
		if err != nil {
			t.Fatalf("encrypt=%v: %v", encrypt, err)
		}
		var down bundleDownloadJSON
		decodeOne(t, out, &down)
		if down.BundleCode != cliBundleCode || down.Dir != dir || len(down.Files) != 2 || down.Decrypted != encrypt {
			t.Fatalf("encrypt=%v: %s", encrypt, out)
		}
		for _, want := range [][2]string{{"a.txt", "aaa"}, {"b.txt", "bbbb"}} {
			got, _ := os.ReadFile(filepath.Join(dir, want[0]))
			if string(got) != want[1] {
				t.Fatalf("encrypt=%v: %s = %q", encrypt, want[0], got)
			}
		}
	}
}

func TestDownloadBundleFromStdin(t *testing.T) {
	_, srv := newCLIBundleFake(t)
	a := writeTemp(t, "a.txt", "aaa")
	out, _, err := runCLI(t, "--url", srv.URL, "--json", "upload", "--bundle", "--encrypt", a)
	if err != nil {
		t.Fatal(err)
	}
	var up bundleJSON
	decodeOne(t, out, &up)

	stdin := writeTemp(t, "link.txt", up.URL+"\n")
	in, _ := os.Open(stdin)
	old := os.Stdin
	os.Stdin = in
	t.Cleanup(func() { os.Stdin = old; in.Close() })

	dir := filepath.Join(t.TempDir(), "in")
	if _, _, err := runCLI(t, "download", "-", dir); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(got) != "aaa" {
		t.Fatalf("a.txt = %q", got)
	}
}

func TestListBundlesJSON(t *testing.T) {
	_, srv := newCLIBundleFake(t)
	out, _, err := runCLI(t, "--url", srv.URL, "--token", "safeshare_test", "--json", "list", "--bundles")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema  int `json:"schema"`
		Bundles []struct {
			BundleCode string `json:"bundle_code"`
			FileCount  int    `json:"file_count"`
		} `json:"bundles"`
		Total int `json:"total"`
	}
	decodeOne(t, out, &doc)
	if doc.Schema != 1 || doc.Total != 1 || len(doc.Bundles) != 1 || doc.Bundles[0].BundleCode != cliBundleCode || doc.Bundles[0].FileCount != 2 {
		t.Fatalf("doc: %s", out)
	}

	out, _, err = runCLI(t, "--url", srv.URL, "--token", "safeshare_test", "list", "--bundles")
	if err != nil || !strings.Contains(out, cliBundleCode) || !strings.Contains(out, "b.txt") {
		t.Fatalf("text (%v):\n%s", err, out)
	}
}
