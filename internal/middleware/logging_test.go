package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoggingMiddleware_BasicRequest(t *testing.T) {
	handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Verify response is successful
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	if rr.Body.String() != "OK" {
		t.Errorf("body = %q, want %q", rr.Body.String(), "OK")
	}
}

func TestLoggingMiddleware_CapturesStatusCode(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"200 OK", http.StatusOK},
		{"201 Created", http.StatusCreated},
		{"400 Bad Request", http.StatusBadRequest},
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.statusCode {
				t.Errorf("status = %d, want %d", rr.Code, tt.statusCode)
			}
		})
	}
}

func TestLoggingMiddleware_DifferentMethods(t *testing.T) {
	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(method, "/api/test", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("method %s: status = %d, want %d", method, rr.Code, http.StatusOK)
			}
		})
	}
}

func TestLoggingMiddleware_DifferentPaths(t *testing.T) {
	paths := []string{
		"/",
		"/api/upload",
		"/api/claim/test123",
		"/api/claim/test123/info",
		"/admin/dashboard",
		"/health",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("path %s: status = %d, want %d", path, rr.Code, http.StatusOK)
			}
		})
	}
}

func TestLoggingMiddleware_WithUserAgent(t *testing.T) {
	handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "TestAgent/1.0")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestLoggingMiddleware_WithXForwardedFor(t *testing.T) {
	handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestLoggingMiddleware_WithXRealIP(t *testing.T) {
	handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Real-IP", "203.0.113.5")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestLoggingMiddleware_PreservesHandlerResponse(t *testing.T) {
	expectedBody := "test response"
	expectedStatus := http.StatusCreated

	handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}

func TestLoggingMiddleware_DefaultStatusCode(t *testing.T) {
	// Handler that writes body without explicit WriteHeader call
	handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should default to 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestLoggingMiddleware_MultipleWriteHeader(t *testing.T) {
	// Handler that tries to call WriteHeader multiple times
	handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.WriteHeader(http.StatusBadRequest) // Should be ignored
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// First WriteHeader should win
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestRedactPathClaimCodes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantFunc func(string) bool // Function to validate output
	}{
		{
			name:  "short claim code",
			input: "/api/claim/ABC",
			wantFunc: func(output string) bool {
				return strings.Contains(output, "***")
			},
		},
		{
			name:  "long claim code",
			input: "/api/claim/Xy9kLm8pQz4vDwE",
			wantFunc: func(output string) bool {
				// Should show first 3 and last 2 chars
				return strings.Contains(output, "Xy9") && strings.Contains(output, "wE") && strings.Contains(output, "...")
			},
		},
		{
			name:  "claim code with info endpoint",
			input: "/api/claim/Xy9kLm8pQz4vDwE/info",
			wantFunc: func(output string) bool {
				return strings.Contains(output, "Xy9") && strings.Contains(output, "wE") && strings.Contains(output, "/info")
			},
		},
		{
			name:  "non-claim path",
			input: "/api/upload",
			wantFunc: func(output string) bool {
				return output == "/api/upload"
			},
		},
		{
			name:  "multiple claim codes",
			input: "/api/claim/Code123ABC /api/claim/XYZ789def",
			wantFunc: func(output string) bool {
				// Both should be redacted
				return strings.Contains(output, "Cod...BC") && strings.Contains(output, "XYZ...ef")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := redactPathClaimCodes(tt.input)
			if !tt.wantFunc(output) {
				t.Errorf("redactPathClaimCodes(%q) = %q, validation failed", tt.input, output)
			}
		})
	}
}
