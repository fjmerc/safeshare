package static

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

func TestFileSystem(t *testing.T) {
	fs := FileSystem()
	if fs == nil {
		t.Fatal("FileSystem() returned nil")
	}

	// Try to open a known file (index.html should exist in embedded files)
	file, err := fs.Open("index.html")
	if err != nil {
		t.Fatalf("failed to open index.html: %v", err)
	}
	defer file.Close()

	// Verify we can read from it
	stat, err := file.Stat()
	if err != nil {
		t.Fatalf("failed to stat index.html: %v", err)
	}

	if stat.Size() == 0 {
		t.Error("index.html should not be empty")
	}
}

func TestHandler(t *testing.T) {
	handler := Handler()
	if handler == nil {
		t.Fatal("Handler() returned nil")
	}

	// Test serving a known file (use assets/app.js instead of index.html
	// since http.FileServer may redirect index.html requests)
	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Should have content
	body, _ := io.ReadAll(rr.Body)
	if len(body) == 0 {
		t.Error("response body should not be empty")
	}
}

func TestHandler_NotFound(t *testing.T) {
	handler := Handler()

	req := httptest.NewRequest(http.MethodGet, "/nonexistent-file.xyz", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 404 Not Found
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestFileSystem_OpenMultipleFiles(t *testing.T) {
	fs := FileSystem()

	// Test opening multiple common static files
	files := []string{
		"index.html",
		"app.js",
		"style.css",
	}

	for _, filename := range files {
		t.Run(filename, func(t *testing.T) {
			file, err := fs.Open(filename)
			if err != nil {
				t.Skipf("file %s not found (might not exist): %v", filename, err)
				return
			}
			defer file.Close()

			stat, err := file.Stat()
			if err != nil {
				t.Errorf("failed to stat %s: %v", filename, err)
				return
			}

			if stat.IsDir() {
				t.Errorf("%s should be a file, not a directory", filename)
			}
		})
	}
}

// TestWebAssetHashesScript checks scripts/web-asset-hashes.sh, whose output
// each release publishes, lists exactly the embedded files with their hashes.
func TestWebAssetHashesScript(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	out, err := exec.Command("sh", "../../scripts/web-asset-hashes.sh").Output()
	if err != nil {
		t.Fatalf("web-asset-hashes.sh: %v", err)
	}

	var paths []string
	sums := map[string]string{}
	err = fs.WalkDir(content, "web", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := content.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		name := strings.TrimPrefix(p, "web/")
		paths = append(paths, name)
		sums[name] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths) // byte order, like the script's LC_ALL=C sort
	var want []string
	for _, p := range paths {
		want = append(want, sums[p]+"  "+p)
	}

	got := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("script output does not match the embedded files\n got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestAnonymousServiceWorkerEmbedded checks the anonymous-mode kill-switch
// worker that cmd/safeshare serves is embedded.
func TestAnonymousServiceWorkerEmbedded(t *testing.T) {
	data, err := content.ReadFile("web/service-worker-anonymous.js")
	if err != nil {
		t.Fatalf("service-worker-anonymous.js not embedded: %v", err)
	}
	if !strings.Contains(string(data), "registration.unregister()") {
		t.Error("service-worker-anonymous.js does not unregister itself")
	}
}
