package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Verify response is successful
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Test all security headers
	tests := []struct {
		name  string
		header string
		want   string
	}{
		{
			name:   "X-Frame-Options prevents clickjacking",
			header: "X-Frame-Options",
			want:   "DENY",
		},
		{
			name:   "X-Content-Type-Options prevents MIME sniffing",
			header: "X-Content-Type-Options",
			want:   "nosniff",
		},
		{
			name:   "X-XSS-Protection enables XSS filter",
			header: "X-XSS-Protection",
			want:   "1; mode=block",
		},
		{
			name:   "Referrer-Policy protects claim codes",
			header: "Referrer-Policy",
			want:   "same-origin",
		},
		{
			name:   "Permissions-Policy disables unnecessary features",
			header: "Permissions-Policy",
			want:   "camera=(), microphone=(), geolocation=(), interest-cohort=()",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rr.Header().Get(tt.header)
			if got != tt.want {
				t.Errorf("%s = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestSecurityHeadersMiddleware_CSP(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header not set")
	}

	// Verify critical CSP directives
	requiredDirectives := []string{
		"default-src 'self'",
		"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net", // QR code library
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: blob:", // QR codes use data URLs
		"frame-ancestors 'none'",     // Prevent clickjacking
		"base-uri 'self'",
		"form-action 'self'",
	}

	for _, directive := range requiredDirectives {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP missing directive: %q\nFull CSP: %s", directive, csp)
		}
	}
}

func TestSecurityHeadersMiddleware_MultipleRequests(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make multiple requests to ensure headers are set consistently
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("request %d: X-Frame-Options not set correctly", i+1)
		}

		if rr.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("request %d: CSP not set", i+1)
		}
	}
}

func TestSecurityHeadersMiddleware_DifferentPaths(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	paths := []string{
		"/",
		"/api/upload",
		"/api/claim/test123",
		"/admin/dashboard",
		"/assets/style.css",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			// All paths should have security headers
			if rr.Header().Get("X-Frame-Options") == "" {
				t.Errorf("path %s: X-Frame-Options not set", path)
			}

			if rr.Header().Get("X-Content-Type-Options") == "" {
				t.Errorf("path %s: X-Content-Type-Options not set", path)
			}

			if rr.Header().Get("Content-Security-Policy") == "" {
				t.Errorf("path %s: CSP not set", path)
			}
		})
	}
}

func TestSecurityHeadersMiddleware_DifferentMethods(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/test", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			// All HTTP methods should have security headers
			if rr.Header().Get("X-Frame-Options") != "DENY" {
				t.Errorf("method %s: X-Frame-Options not set correctly", method)
			}
		})
	}
}

func TestSecurityHeadersMiddleware_PreservesHandlerResponse(t *testing.T) {
	expectedBody := "test response body"
	expectedStatus := http.StatusCreated

	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "custom-value")
		w.WriteHeader(expectedStatus)
		w.Write([]byte(expectedBody))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Verify middleware preserves handler's status code
	if rr.Code != expectedStatus {
		t.Errorf("status = %d, want %d", rr.Code, expectedStatus)
	}

	// Verify middleware preserves handler's body
	if rr.Body.String() != expectedBody {
		t.Errorf("body = %q, want %q", rr.Body.String(), expectedBody)
	}

	// Verify middleware preserves handler's custom headers
	if rr.Header().Get("X-Custom-Header") != "custom-value" {
		t.Error("middleware did not preserve custom header")
	}

	// Verify security headers are still added
	if rr.Header().Get("X-Frame-Options") == "" {
		t.Error("security headers not added")
	}
}
