package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
