package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/claimcode"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/static"
)

// TestServeAdminPage tests that admin pages are served correctly
func TestServeAdminPage(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{
			name:           "valid admin page",
			path:           "admin/login.html",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "nonexistent admin page",
			path:           "admin/nonexistent.html",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/admin/"+tt.path, nil)
			w := httptest.NewRecorder()

			handler := serveAdminPage(tt.path)
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if w.Code == http.StatusOK {
				contentType := w.Header().Get("Content-Type")
				if contentType != "text/html; charset=utf-8" {
					t.Errorf("expected Content-Type 'text/html; charset=utf-8', got %q", contentType)
				}
			}
		})
	}
}

// TestServeUserPage tests that user pages are served correctly
func TestServeUserPage(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{
			name:           "valid user page",
			path:           "login.html",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "dashboard page",
			path:           "dashboard.html",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "nonexistent user page",
			path:           "nonexistent.html",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/"+tt.path, nil)
			w := httptest.NewRecorder()

			handler := serveUserPage(tt.path)
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if w.Code == http.StatusOK {
				contentType := w.Header().Get("Content-Type")
				if contentType != "text/html; charset=utf-8" {
					t.Errorf("expected Content-Type 'text/html; charset=utf-8', got %q", contentType)
				}
			}
		})
	}
}

// TestServeAdminDashboard tests that the admin dashboard handler sets CSRF token
func TestServeAdminDashboard(t *testing.T) {
	// Create a minimal config - most fields have defaults
	cfg, err := config.Load()
	if err != nil {
		// If config loading fails (missing env vars), create minimal config manually
		// This is acceptable for testing the dashboard serving functionality
		t.Skip("config loading requires environment variables - skipping")
		return
	}

	req := httptest.NewRequest("GET", "/admin/dashboard", nil)
	w := httptest.NewRecorder()

	handler := serveAdminDashboard(cfg)
	handler(w, req)

	// Check that response is OK
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Check that CSRF cookie was set
	cookies := w.Result().Cookies()
	var csrfCookieFound bool
	for _, cookie := range cookies {
		if cookie.Name == "csrf_token" {
			csrfCookieFound = true
			if cookie.Value == "" {
				t.Error("CSRF cookie value should not be empty")
			}
		}
	}

	if !csrfCookieFound {
		t.Error("CSRF cookie should be set by serveAdminDashboard")
	}

	// Check that HTML page was served
	contentType := w.Header().Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("expected Content-Type 'text/html; charset=utf-8', got %q", contentType)
	}
}

// TestStaticFileSystem tests that embedded files can be accessed
func TestStaticFileSystem(t *testing.T) {
	fs := static.FileSystem()

	tests := []string{
		"index.html",
		"assets/app.js",
		"assets/style.css",
		"login.html",
		"dashboard.html",
		"admin/login.html",
		"admin/dashboard.html",
		"service-worker.js",
	}

	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			file, err := fs.Open(path)
			if err != nil {
				t.Errorf("failed to open %s: %v", path, err)
				return
			}
			defer file.Close()

			stat, err := file.Stat()
			if err != nil {
				t.Errorf("failed to stat %s: %v", path, err)
				return
			}

			if stat.Size() == 0 {
				t.Errorf("%s should not be empty", path)
			}
		})
	}
}

// TestServeServiceWorker tests that the service worker is served correctly
func TestServeServiceWorker(t *testing.T) {
	req := httptest.NewRequest("GET", "/service-worker.js", nil)
	w := httptest.NewRecorder()

	handler := serveServiceWorker()
	handler(w, req)

	// Check status code
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Check Content-Type header
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/javascript" {
		t.Errorf("expected Content-Type 'application/javascript', got %q", contentType)
	}

	// Check Cache-Control header
	cacheControl := w.Header().Get("Cache-Control")
	if cacheControl != "no-cache" {
		t.Errorf("expected Cache-Control 'no-cache', got %q", cacheControl)
	}

	// Check that response body is not empty
	body := w.Body.String()
	if len(body) == 0 {
		t.Error("service worker response body should not be empty")
	}

	// Verify response contains service worker code (basic sanity check)
	if !strings.Contains(body, "service worker") && !strings.Contains(body, "Service Worker") {
		t.Error("response body should contain service worker code")
	}

	// Verify it contains expected service worker functionality
	expectedStrings := []string{
		"addEventListener",
		"install",
		"activate",
		"fetch",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(body, expected) {
			t.Errorf("service worker should contain '%s'", expected)
		}
	}
}

// TestMain_InvalidConfig tests that run() returns error for invalid config
func TestMain_InvalidConfig(t *testing.T) {
	// This test is tricky because config.Load() reads from environment
	// We can't easily test this without mocking the config package
	// Skip for now - config loading is tested in internal/config/config_test.go
	t.Skip("config loading tested in internal/config package")
}

// TestMain_Integration tests basic server setup (without actually starting server)
func TestMain_Integration(t *testing.T) {
	// This is more of an integration test and would require:
	// - Setting up test database
	// - Setting environment variables
	// - Not actually starting the server (hard to test signal handling)
	// Skip for now - integration tested manually and in deployment
	t.Skip("full integration tested manually")
}

func TestRootHandler(t *testing.T) {
	const code = "Xy9kLm8pQz4vDwE_"

	tests := []struct {
		name         string
		cfg          *config.Config
		method       string
		target       string
		wantStatus   int
		wantLocation string
	}{
		{"root serves index", &config.Config{}, http.MethodGet, "/", http.StatusOK, ""},
		{"root serves index with short links on", &config.Config{ShortClaimLinks: true}, http.MethodGet, "/", http.StatusOK, ""},
		{"flag off: code is 404", &config.Config{}, http.MethodGet, "/" + code, http.StatusNotFound, ""},
		{"flag on: code redirects", &config.Config{ShortClaimLinks: true}, http.MethodGet, "/" + code, http.StatusFound, "/api/claim/" + code},
		{"flag on: query preserved", &config.Config{ShortClaimLinks: true}, http.MethodGet, "/" + code + "?a=b", http.StatusFound, "/api/claim/" + code + "?a=b"},
		{"flag on: DOWNLOAD_URL target", &config.Config{ShortClaimLinks: true, DownloadURL: "https://dl.example.com"}, http.MethodGet, "/" + code, http.StatusFound, "https://dl.example.com/api/claim/" + code},
		{"flag on: PUBLIC_URL ignored (relative)", &config.Config{ShortClaimLinks: true, PublicURL: "https://pub.example.com"}, http.MethodGet, "/" + code, http.StatusFound, "/api/claim/" + code},
		{"flag on: reserved name not redirected", &config.Config{ShortClaimLinks: true}, http.MethodGet, "/dashboard", http.StatusNotFound, ""},
		{"flag on: 7 chars 404", &config.Config{ShortClaimLinks: true}, http.MethodGet, "/abcdefg", http.StatusNotFound, ""},
		{"flag on: 33 chars 404", &config.Config{ShortClaimLinks: true}, http.MethodGet, "/" + strings.Repeat("a", 33), http.StatusNotFound, ""},
		{"flag on: bad chars 404", &config.Config{ShortClaimLinks: true}, http.MethodGet, "/abcdef!!", http.StatusNotFound, ""},
		{"flag on: nested path 404", &config.Config{ShortClaimLinks: true}, http.MethodGet, "/abcdefgh/ijklmnop", http.StatusNotFound, ""},
		{"flag on: unknown api path 404", &config.Config{ShortClaimLinks: true}, http.MethodGet, "/api/foo", http.StatusNotFound, ""},
		{"flag on: POST 404", &config.Config{ShortClaimLinks: true}, http.MethodPost, "/" + code, http.StatusNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// rootHandler takes only the config: it has no repository or
			// database handle, so a short link redirect cannot look the code up.
			req := httptest.NewRequest(tt.method, "http://example.com"+tt.target, nil)
			rr := httptest.NewRecorder()
			rootHandler(tt.cfg).ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
			if got := rr.Header().Get("Location"); got != tt.wantLocation {
				t.Errorf("Location = %q, want %q", got, tt.wantLocation)
			}
			if tt.target == "/" && !strings.Contains(strings.ToLower(rr.Body.String()), "<html") {
				t.Error("root did not serve index.html")
			}
		})
	}
}

// TestRegisteredRootRoutesNeverLookLikeShortLinks guards against a future
// single-segment route (e.g. "/settings") that is also a valid claim code but
// missing from claimcode's reserved list: with SHORT_CLAIM_LINKS on, a route
// served by the "/" catch-all would shadow or be shadowed by a file's code.
func TestRegisteredRootRoutesNeverLookLikeShortLinks(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	re := regexp.MustCompile(`mux\.Handle(?:Func)?\("(/[^"]*)"`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatal("found no mux registrations in main.go; the route scan is broken")
	}
	for _, m := range matches {
		pattern := m[1]
		// First path segment is what a "/<code>" request would collide with
		// (exact "/name" routes and "/name/" subtree routes alike).
		seg := strings.SplitN(strings.TrimPrefix(pattern, "/"), "/", 2)[0]
		if seg == "" {
			continue // the "/" catch-all itself
		}
		if code, ok := claimcode.ShortPath("/" + seg); ok {
			t.Errorf("route %q has first segment %q that is a valid claim code; add it to claimcode's reserved names", pattern, code)
		}
	}
}
