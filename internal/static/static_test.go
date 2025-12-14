package static

import (
	"io"
	"net/http"
	"net/http/httptest"
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
