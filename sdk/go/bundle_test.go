package safeshare

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// bundleFake is a minimal bundle API: create, member upload (direct), publish,
// delete, info and file download.
type bundleFake struct {
	mu          sync.Mutex
	createBody  map[string]any
	members     map[int][]byte
	names       map[int]string
	memberForms []map[string]string
	manifest    []byte
	published   bool
	deleted     bool
	failAt      int  // member position whose upload answers 429 (-1: none)
	swap        bool // serve members 0 and 1 swapped
	drop        bool // list one member fewer in info
	encrypted   bool
}

const fakeBundleCode = "BundleCode01"

func newBundleFake(t *testing.T, cfg map[string]any) (*bundleFake, *httptest.Server) {
	f := &bundleFake{members: map[int][]byte{}, names: map[int]string{}, failAt: -1}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(cfg) })
	mux.HandleFunc("/api/bundles", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		json.NewDecoder(r.Body).Decode(&f.createBody)
		f.encrypted, _ = f.createBody["client_encrypted"].(bool)
		f.mu.Unlock()
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"bundle_id": 7, "bundle_code": fakeBundleCode, "upload_token": "tok", "expires_at": "2030-01-01T00:00:00Z"})
	})
	mux.HandleFunc("/api/bundles/7/publish", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Manifest string `json:"encrypted_manifest"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		if body.Manifest != "" {
			f.manifest, _ = base64.StdEncoding.DecodeString(body.Manifest)
		}
		f.published = true
		n := len(f.members)
		f.mu.Unlock()
		files := []map[string]any{}
		for i := 0; i < n; i++ {
			files = append(files, map[string]any{"position": i, "name": f.names[i], "size": len(f.members[i])})
		}
		json.NewEncoder(w).Encode(map[string]any{"bundle_code": fakeBundleCode, "bundle_url": "x", "expires_at": "2030-01-01T00:00:00Z",
			"max_downloads": nil, "client_encrypted": f.encrypted, "files": files})
	})
	mux.HandleFunc("/api/bundles/7", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.Header.Get("X-Bundle-Upload-Token") == "tok" {
			f.mu.Lock()
			f.deleted = true
			f.mu.Unlock()
			w.WriteHeader(204)
			return
		}
		http.Error(w, "no", 404)
	})
	mux.HandleFunc("/api/upload", func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(64 << 20)
		pos, _ := strconv.Atoi(r.FormValue("bundle_position"))
		form := map[string]string{"bundle_id": r.FormValue("bundle_id"), "bundle_position": r.FormValue("bundle_position"),
			"token": r.Header.Get("X-Bundle-Upload-Token"), "max_downloads": r.FormValue("max_downloads"), "password": r.FormValue("password")}
		f.mu.Lock()
		f.memberForms = append(f.memberForms, form)
		fail := pos == f.failAt
		f.mu.Unlock()
		if fail {
			w.WriteHeader(429)
			json.NewEncoder(w).Encode(map[string]any{"error": "slow down", "code": "RATE_LIMIT_EXCEEDED"})
			return
		}
		file, h, _ := r.FormFile("file")
		data, _ := io.ReadAll(file)
		f.mu.Lock()
		f.members[pos], f.names[pos] = data, sanitizeLikeServer(h.Filename)
		f.mu.Unlock()
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"bundle_id": 7, "bundle_position": pos, "original_filename": h.Filename, "file_size": len(data)})
	})
	mux.HandleFunc("/api/bundle/"+fakeBundleCode+"/info", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		n := len(f.members)
		if f.drop {
			n--
		}
		files := []map[string]any{}
		for i := 0; i < n; i++ {
			files = append(files, map[string]any{"position": i, "original_filename": f.names[i], "file_size": len(f.members[i]),
				"mime_type": "application/octet-stream", "download_available": true})
		}
		info := map[string]any{"bundle_code": fakeBundleCode, "expires_at": "2030-01-01T00:00:00Z", "file_count": n,
			"max_downloads": nil, "password_required": false, "client_encrypted": f.encrypted, "files": files}
		if f.manifest != nil {
			info["encrypted_manifest"] = f.manifest
		}
		json.NewEncoder(w).Encode(info)
	})
	mux.HandleFunc("/api/bundle/"+fakeBundleCode+"/files/", func(w http.ResponseWriter, r *http.Request) {
		pos, _ := strconv.Atoi(r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.swap && pos < 2 {
			pos = 1 - pos
		}
		data, ok := f.members[pos]
		if !ok {
			http.Error(w, "missing", 404)
			return
		}
		w.Write(data)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return f, srv
}

var bundleTestConfig = map[string]any{"max_file_size": 10 << 20, "chunked_upload_threshold": 100 << 20, "chunk_size": 1 << 20}

func writeBundleFiles(t *testing.T, contents ...string) []string {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for i, c := range contents {
		p := filepath.Join(dir, "file"+strconv.Itoa(i)+".txt")
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	return paths
}

func bundleClient(t *testing.T, srv *httptest.Server) *Client {
	c, err := NewClient(ClientConfig{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUploadBundle_Plain(t *testing.T) {
	f, srv := newBundleFake(t, bundleTestConfig)
	c := bundleClient(t, srv)
	limit := 2
	res, err := c.UploadBundle(context.Background(), writeBundleFiles(t, "aaa", "bb"), &UploadOptions{Encrypt: EncryptNever, DownloadLimit: &limit, Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if res.BundleCode != fakeBundleCode || res.Encrypted || res.EncryptionKey != "" || res.BundleURL != srv.URL+"/#/bundle/"+fakeBundleCode ||
		len(res.Files) != 2 || res.Files[1].Name != "file1.txt" || res.Files[1].Size != 2 || !res.PasswordProtected {
		t.Fatalf("result: %+v", res)
	}
	if f.createBody["file_count"] != float64(2) || f.createBody["max_downloads"] != float64(2) || f.createBody["password"] != "pw" {
		t.Fatalf("create body: %+v", f.createBody)
	}
	for _, form := range f.memberForms {
		if form["bundle_id"] != "7" || form["token"] != "tok" || form["max_downloads"] != "" || form["password"] != "" {
			t.Fatalf("member upload form: %+v", form)
		}
	}
	if string(f.members[0]) != "aaa" || f.manifest != nil || !f.published {
		t.Fatalf("server state: %q manifest=%v published=%v", f.members[0], f.manifest, f.published)
	}
}

func TestUploadBundle_EncryptedOneKeyAndManifest(t *testing.T) {
	f, srv := newBundleFake(t, bundleTestConfig)
	c := bundleClient(t, srv)
	res, err := c.UploadBundle(context.Background(), writeBundleFiles(t, "first", "second"), &UploadOptions{Encrypt: EncryptAlways})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Encrypted || res.EncryptionKey == "" || res.BundleURL != BuildBundleURL(srv.URL, fakeBundleCode, res.EncryptionKey) {
		t.Fatalf("result: %+v", res)
	}
	key, _ := decodeKey(res.EncryptionKey)
	for pos, want := range []string{"first", "second"} {
		pt, err := decryptBlob(key, append([]byte(nil), f.members[pos]...))
		if err != nil {
			t.Fatalf("member %d does not open with the bundle key: %v", pos, err)
		}
		df, err := unwrapDownload(pt, f.names[pos])
		if err != nil || string(df.Data) != want || df.Filename != "file"+strconv.Itoa(pos)+".txt" {
			t.Fatalf("member %d: %+v %v", pos, df, err)
		}
	}
	m, err := OpenManifest(res.EncryptionKey, f.manifest)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	sum := sha256.Sum256([]byte("second"))
	if len(m.Files) != 2 || m.Files[1].Name != "file1.txt" || m.Files[1].Size != 6 || m.Files[1].SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("manifest: %+v", m)
	}
}

func TestUploadBundle_FailureDeletesDraft(t *testing.T) {
	f, srv := newBundleFake(t, bundleTestConfig)
	f.failAt = 2
	c := bundleClient(t, srv)
	paths := writeBundleFiles(t, "a", "b", "c")
	_, err := c.UploadBundle(context.Background(), paths, &UploadOptions{Encrypt: EncryptNever})
	var bErr *BundleUploadError
	if !errors.As(err, &bErr) || bErr.Path != paths[2] || bErr.Position != 2 || !errors.Is(err, ErrRateLimit) {
		t.Fatalf("err = %v", err)
	}
	if !f.deleted || f.published {
		t.Fatalf("draft deleted=%v published=%v", f.deleted, f.published)
	}
}

func TestUploadBundle_RejectsNonRegularFiles(t *testing.T) {
	_, srv := newBundleFake(t, bundleTestConfig)
	c := bundleClient(t, srv)
	if _, err := c.UploadBundle(context.Background(), nil, nil); err == nil {
		t.Fatal("empty path list accepted")
	}
	if _, err := c.UploadBundle(context.Background(), []string{t.TempDir()}, nil); err == nil {
		t.Fatal("directory accepted")
	}
}

func uploadThenDownload(t *testing.T, f *bundleFake, srv *httptest.Server, encrypt EncryptMode, contents ...string) (*BundleResult, string, []string, error) {
	t.Helper()
	c := bundleClient(t, srv)
	res, err := c.UploadBundle(context.Background(), writeBundleFiles(t, contents...), &UploadOptions{Encrypt: encrypt})
	if err != nil {
		t.Fatal(err)
	}
	link, err := ParseBundleURL(res.BundleURL)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "out")
	paths, err := c.DownloadBundle(context.Background(), link, dir, nil)
	return res, dir, paths, err
}

func TestDownloadBundle_RoundTrip(t *testing.T) {
	for _, mode := range []EncryptMode{EncryptNever, EncryptAlways} {
		f, srv := newBundleFake(t, bundleTestConfig)
		_, dir, paths, err := uploadThenDownload(t, f, srv, mode, "one", "two")
		if err != nil || len(paths) != 2 {
			t.Fatalf("mode %v: %v %v", mode, paths, err)
		}
		for i, want := range []string{"one", "two"} {
			got, _ := os.ReadFile(paths[i])
			if string(got) != want || filepath.Dir(paths[i]) != dir || filepath.Base(paths[i]) != "file"+strconv.Itoa(i)+".txt" {
				t.Fatalf("mode %v file %d: %s = %q", mode, i, paths[i], got)
			}
		}
	}
}

func TestDownloadBundle_VerifiesManifest(t *testing.T) {
	f, srv := newBundleFake(t, bundleTestConfig)
	f.swap = true
	_, dir, _, err := uploadThenDownload(t, f, srv, EncryptAlways, "one", "two")
	if !errors.Is(err, ErrManifestMismatch) {
		t.Fatalf("swapped members: err = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("files written despite mismatch: %v", entries)
	}
}

func TestDownloadBundle_DropsMember(t *testing.T) {
	f, srv := newBundleFake(t, bundleTestConfig)
	f.drop = true
	_, dir, _, err := uploadThenDownload(t, f, srv, EncryptAlways, "one", "two", "three")
	if !errors.Is(err, ErrManifestMismatch) {
		t.Fatalf("dropped member: err = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("files written despite mismatch: %v", entries)
	}
}

func TestDownloadBundle_EncryptedLinkNeedsKey(t *testing.T) {
	f, srv := newBundleFake(t, bundleTestConfig)
	c := bundleClient(t, srv)
	if _, err := c.UploadBundle(context.Background(), writeBundleFiles(t, "x"), &UploadOptions{Encrypt: EncryptAlways}); err != nil {
		t.Fatal(err)
	}
	_ = f
	_, err := c.DownloadBundle(context.Background(), &BundleLink{BaseURL: srv.URL, BundleCode: fakeBundleCode}, t.TempDir(), nil)
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("encrypted bundle without key: %v", err)
	}
}

// TestDownloadBundle_KeyedLinkRefusesUnencryptedClaim: a link with a key
// means the sender encrypted the bundle. A server that then claims the
// bundle is not encrypted must not get its plaintext saved unchecked.
func TestDownloadBundle_KeyedLinkRefusesUnencryptedClaim(t *testing.T) {
	f, srv := newBundleFake(t, bundleTestConfig)
	c := bundleClient(t, srv)
	res, err := c.UploadBundle(context.Background(), writeBundleFiles(t, "x"), &UploadOptions{Encrypt: EncryptAlways})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.encrypted, f.manifest = false, nil
	f.members[0] = []byte("attacker content")
	f.mu.Unlock()

	link, _ := ParseBundleURL(res.BundleURL)
	dir := filepath.Join(t.TempDir(), "out")
	if _, err := c.DownloadBundle(context.Background(), link, dir, nil); !errors.Is(err, ErrManifestMismatch) {
		t.Fatalf("err = %v, want ErrManifestMismatch", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("saved files: %v", entries)
	}
}

// sanitizeLikeServer mirrors utils.SanitizeFilename: anything but letters,
// digits, space, '-', '_' and '.' becomes '_'.
func sanitizeLikeServer(name string) string {
	out := []rune(name)
	for i, r := range out {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == ' ' || r == '-' || r == '_' || r == '.') {
			out[i] = '_'
		}
	}
	return string(out)
}

// TestDownloadBundle_VisibleNameWithSpecialCharacters: with the name left
// visible (ShowFilename), the server stores a cleaned-up name; the
// encrypted manifest's name is the real one and must win, not count as tampering.
func TestDownloadBundle_VisibleNameWithSpecialCharacters(t *testing.T) {
	_, srv := newBundleFake(t, bundleTestConfig)
	c := bundleClient(t, srv)
	dir := t.TempDir()
	p := filepath.Join(dir, "photo (1)&co.txt")
	if err := os.WriteFile(p, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := c.UploadBundle(context.Background(), []string{p}, &UploadOptions{Encrypt: EncryptAlways, ShowFilename: true})
	if err != nil {
		t.Fatal(err)
	}
	link, _ := ParseBundleURL(res.BundleURL)
	out := filepath.Join(t.TempDir(), "out")
	saved, err := c.DownloadBundle(context.Background(), link, out, nil)
	if err != nil || len(saved) != 1 || filepath.Base(saved[0]) != "photo (1)&co.txt" {
		t.Fatalf("saved %v, err %v", saved, err)
	}
}
