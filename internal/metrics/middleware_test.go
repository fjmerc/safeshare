package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMiddleware(t *testing.T) {
	// Create a test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with metrics middleware
	wrapped := Middleware(handler)

	// Record initial count
	initial := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("GET", "/api/upload", "200"))

	// Create test request
	req := httptest.NewRequest("GET", "/api/upload", nil)
	rec := httptest.NewRecorder()

	// Serve request
	wrapped.ServeHTTP(rec, req)

	// Verify response
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	// Verify metrics were recorded
	count := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("GET", "/api/upload", "200"))
	if count <= initial {
		t.Errorf("Expected count to increase from %f, got %f", initial, count)
	}
}

func TestMiddleware_MultipleRequests(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := Middleware(handler)

	// Record initial counts
	initialGetUpload := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("GET", "/api/upload", "200"))
	initialPostUpload := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("POST", "/api/upload", "200"))
	initialError := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("GET", "/other", "500"))

	// Make multiple requests
	tests := []struct {
		method string
		path   string
		status int
	}{
		{"GET", "/api/upload", 200},
		{"POST", "/api/upload", 200},
		{"GET", "/api/claim/abc123", 200},
		{"GET", "/error", 500},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if rec.Code != tt.status {
			t.Errorf("Expected status %d for %s %s, got %d", tt.status, tt.method, tt.path, rec.Code)
		}
	}

	// Verify metrics increased
	getUpload := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("GET", "/api/upload", "200"))
	if getUpload < initialGetUpload+1.0 {
		t.Errorf("Expected at least %.0f GET /api/upload, got %f", initialGetUpload+1.0, getUpload)
	}

	postUpload := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("POST", "/api/upload", "200"))
	if postUpload < initialPostUpload+1.0 {
		t.Errorf("Expected at least %.0f POST /api/upload, got %f", initialPostUpload+1.0, postUpload)
	}

	errorCount := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("GET", "/other", "500"))
	if errorCount < initialError+1.0 {
		t.Errorf("Expected at least %.0f error requests, got %f", initialError+1.0, errorCount)
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/", "/"},
		{"/health", "/health"},
		{"/metrics", "/metrics"},
		{"/api/upload", "/api/upload"},
		{"/api/config", "/api/config"},
		{"/api/claim/abc123xyz", "/api/claim/:code"},
		{"/api/claim/abc123xyz/info", "/api/claim/:code/info"},
		{"/api/upload/init", "/api/upload/init"},
		{"/api/upload/chunk/uuid-1234/0", "/api/upload/chunk/:id/:number"},
		{"/api/upload/chunk/uuid-1234/99", "/api/upload/chunk/:id/:number"},
		{"/api/upload/complete/uuid-1234", "/api/upload/complete/:id"},
		{"/api/upload/status/uuid-1234", "/api/upload/status/:id"},
		{"/admin/login", "/admin/login"},
		{"/admin/dashboard", "/admin/dashboard"},
		{"/admin/api/dashboard", "/admin/api/*"},
		{"/admin/api/files/delete", "/admin/api/*"},
		{"/admin/api/users/123", "/admin/api/*"},
		{"/login", "/login"},
		{"/dashboard", "/dashboard"},
		{"/api/auth/login", "/api/auth/*"},
		{"/api/auth/logout", "/api/auth/*"},
		{"/api/user/files", "/api/user/*"},
		{"/assets/app.js", "/assets/*"},
		{"/assets/style.css", "/assets/*"},
		{"/admin/assets/admin.css", "/admin/assets/*"},
		{"/some/random/path", "/other"},
	}

	for _, tt := range tests {
		result := normalizePath(tt.input)
		if result != tt.expected {
			t.Errorf("normalizePath(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMiddleware_CapturesStatusCode(t *testing.T) {
	// Reset metrics
	HTTPRequestsTotal.Reset()

	tests := []struct {
		name           string
		handler        http.HandlerFunc
		expectedStatus int
	}{
		{
			name: "200 OK",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			expectedStatus: 200,
		},
		{
			name: "201 Created",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
			},
			expectedStatus: 201,
		},
		{
			name: "404 Not Found",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectedStatus: 404,
		},
		{
			name: "500 Internal Server Error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedStatus: 500,
		},
		{
			name: "Default status (no WriteHeader call)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("OK"))
			},
			expectedStatus: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := Middleware(tt.handler)
			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()

			wrapped.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
		})
	}
}
