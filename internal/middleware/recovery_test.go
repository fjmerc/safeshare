package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/models"
)

func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	handler := RecoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Normal execution should work fine
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	if rr.Body.String() != "OK" {
		t.Errorf("body = %q, want %q", rr.Body.String(), "OK")
	}
}

func TestRecoveryMiddleware_PanicWithString(t *testing.T) {
	handler := RecoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("something went wrong")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()

	// Middleware should recover from panic and not crash
	handler.ServeHTTP(rr, req)

	// Should return 500 Internal Server Error
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}

	// Verify response is JSON
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	// Verify error response structure
	var errResp models.ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Error != "Internal server error" {
		t.Errorf("error message = %q, want %q", errResp.Error, "Internal server error")
	}

	if errResp.Code != "INTERNAL_ERROR" {
		t.Errorf("error code = %q, want %q", errResp.Code, "INTERNAL_ERROR")
	}
}

func TestRecoveryMiddleware_PanicWithError(t *testing.T) {
	handler := RecoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestRecoveryMiddleware_PanicWithNil(t *testing.T) {
	handler := RecoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var nilPointer *string
		_ = *nilPointer // Nil pointer dereference panic
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}

	var errResp models.ErrorResponse
	json.NewDecoder(rr.Body).Decode(&errResp)

	if errResp.Error != "Internal server error" {
		t.Errorf("error message = %q, want %q", errResp.Error, "Internal server error")
	}
}

func TestRecoveryMiddleware_PanicInDifferentPaths(t *testing.T) {
	paths := []string{
		"/",
		"/api/upload",
		"/api/claim/test123",
		"/admin/dashboard",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			handler := RecoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic("test panic")
			}))

			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusInternalServerError {
				t.Errorf("path %s: status = %d, want %d", path, rr.Code, http.StatusInternalServerError)
			}
		})
	}
}

func TestRecoveryMiddleware_PanicInDifferentMethods(t *testing.T) {
	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			handler := RecoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic("test panic")
			}))

			req := httptest.NewRequest(method, "/api/test", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusInternalServerError {
				t.Errorf("method %s: status = %d, want %d", method, rr.Code, http.StatusInternalServerError)
			}
		})
	}
}

func TestRecoveryMiddleware_PreservesNonPanicResponse(t *testing.T) {
	expectedBody := "custom response"
	expectedStatus := http.StatusCreated

	handler := RecoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "custom-value")
		w.WriteHeader(expectedStatus)
		w.Write([]byte(expectedBody))
		// No panic - normal execution
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Verify middleware preserves normal response
	if rr.Code != expectedStatus {
		t.Errorf("status = %d, want %d", rr.Code, expectedStatus)
	}

	if rr.Body.String() != expectedBody {
		t.Errorf("body = %q, want %q", rr.Body.String(), expectedBody)
	}

	if rr.Header().Get("X-Custom-Header") != "custom-value" {
		t.Error("middleware did not preserve custom header")
	}
}

func TestRecoveryMiddleware_PanicAfterWrite(t *testing.T) {
	handler := RecoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("partial"))
		panic("panic after write")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Recovery middleware should catch the panic
	// Note: Status might be 200 if WriteHeader was already called
	// The important thing is that the server doesn't crash
	body := rr.Body.String()
	if body == "" {
		t.Error("expected some response body")
	}
}

func TestRecoveryMiddleware_MultiplePanics(t *testing.T) {
	handler := RecoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("first panic")
	}))

	// Test that multiple panics in sequence are handled
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("request %d: status = %d, want %d", i+1, rr.Code, http.StatusInternalServerError)
		}
	}
}
