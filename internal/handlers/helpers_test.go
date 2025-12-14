package handlers

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
)

func TestBuildDownloadURL(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.Config
		claimCode string
		headers   map[string]string
		want      string
	}{
		{
			name: "uses DOWNLOAD_URL when configured",
			cfg: &config.Config{
				DownloadURL: "https://downloads.example.com",
				PublicURL:   "https://example.com",
			},
			claimCode: "test123",
			want:      "https://downloads.example.com/api/claim/test123",
		},
		{
			name: "uses PUBLIC_URL when DOWNLOAD_URL not set",
			cfg: &config.Config{
				DownloadURL: "",
				PublicURL:   "https://example.com",
			},
			claimCode: "test123",
			want:      "https://example.com/api/claim/test123",
		},
		{
			name: "auto-detects from X-Forwarded-Proto and X-Forwarded-Host",
			cfg: &config.Config{
				DownloadURL: "",
				PublicURL:   "",
			},
			claimCode: "test123",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "proxy.example.com",
			},
			want: "https://proxy.example.com/api/claim/test123",
		},
		{
			name: "falls back to Host header",
			cfg: &config.Config{
				DownloadURL: "",
				PublicURL:   "",
			},
			claimCode: "test123",
			want:      "http://localhost:8080/api/claim/test123",
		},
		{
			name: "DOWNLOAD_URL takes priority over PUBLIC_URL",
			cfg: &config.Config{
				DownloadURL: "https://cdn-bypass.example.com",
				PublicURL:   "https://example.com",
			},
			claimCode: "abc123",
			want:      "https://cdn-bypass.example.com/api/claim/abc123",
		},
		{
			name: "strips trailing slash from DOWNLOAD_URL",
			cfg: &config.Config{
				DownloadURL: "https://downloads.example.com/",
			},
			claimCode: "test123",
			want:      "https://downloads.example.com/api/claim/test123",
		},
		{
			name: "strips trailing slash from PUBLIC_URL",
			cfg: &config.Config{
				PublicURL: "https://example.com/",
			},
			claimCode: "test123",
			want:      "https://example.com/api/claim/test123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://localhost:8080/", nil)

			// Add custom headers
			for key, val := range tt.headers {
				req.Header.Set(key, val)
			}

			got := buildDownloadURL(req, tt.cfg, tt.claimCode)
			if got != tt.want {
				t.Errorf("buildDownloadURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetScheme(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		useTLS  bool
		want    string
	}{
		{
			name: "X-Forwarded-Proto https",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
			},
			want: "https",
		},
		{
			name: "X-Forwarded-Proto http",
			headers: map[string]string{
				"X-Forwarded-Proto": "http",
			},
			want: "http",
		},
		{
			name:   "TLS connection",
			useTLS: true,
			want:   "https",
		},
		{
			name: "no TLS, no proxy header",
			want: "http",
		},
		{
			name: "X-Forwarded-Proto takes priority over TLS",
			headers: map[string]string{
				"X-Forwarded-Proto": "http",
			},
			useTLS: true,
			want:   "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://localhost:8080/", nil)

			// Add headers
			for key, val := range tt.headers {
				req.Header.Set(key, val)
			}

			// Simulate TLS if needed
			if tt.useTLS {
				req.TLS = &tls.ConnectionState{} // Non-nil TLS indicates HTTPS
			}

			got := getScheme(req)
			if got != tt.want {
				t.Errorf("getScheme() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetHost(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		host    string
		want    string
	}{
		{
			name: "X-Forwarded-Host present",
			headers: map[string]string{
				"X-Forwarded-Host": "proxy.example.com",
			},
			host: "localhost:8080",
			want: "proxy.example.com",
		},
		{
			name: "falls back to Host header",
			host: "localhost:8080",
			want: "localhost:8080",
		},
		{
			name: "X-Forwarded-Host with port",
			headers: map[string]string{
				"X-Forwarded-Host": "proxy.example.com:443",
			},
			host: "localhost:8080",
			want: "proxy.example.com:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/", nil)

			// Add headers
			for key, val := range tt.headers {
				req.Header.Set(key, val)
			}

			got := getHost(req)
			if got != tt.want {
				t.Errorf("getHost() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		want       string
	}{
		{
			name: "X-Forwarded-For single IP",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
			},
			remoteAddr: "10.0.0.1:12345",
			want:       "203.0.113.1",
		},
		{
			name: "X-Forwarded-For multiple IPs (takes first)",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1, 198.51.100.1, 192.0.2.1",
			},
			remoteAddr: "10.0.0.1:12345",
			want:       "203.0.113.1",
		},
		{
			name: "X-Real-IP header",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.5",
			},
			remoteAddr: "10.0.0.1:12345",
			want:       "203.0.113.5",
		},
		{
			name: "X-Forwarded-For takes priority over X-Real-IP",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
				"X-Real-IP":       "203.0.113.5",
			},
			remoteAddr: "10.0.0.1:12345",
			want:       "203.0.113.1",
		},
		{
			name:       "falls back to RemoteAddr",
			remoteAddr: "10.0.0.1:12345",
			want:       "10.0.0.1",
		},
		{
			name:       "RemoteAddr without port",
			remoteAddr: "10.0.0.1",
			want:       "10.0.0.1",
		},
		{
			name:       "IPv6 RemoteAddr",
			remoteAddr: "[2001:db8::1]:12345",
			want:       "2001:db8::1",
		},
		{
			name: "X-Forwarded-For with whitespace",
			headers: map[string]string{
				"X-Forwarded-For": " 203.0.113.1 , 198.51.100.1 ",
			},
			remoteAddr: "10.0.0.1:12345",
			want:       "203.0.113.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://localhost:8080/", nil)
			req.RemoteAddr = tt.remoteAddr

			// Add headers
			for key, val := range tt.headers {
				req.Header.Set(key, val)
			}

			got := getClientIP(req)
			if got != tt.want {
				t.Errorf("getClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		{
			name:      "normal user agent",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			want:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		},
		{
			name:      "empty user agent",
			userAgent: "",
			want:      "unknown",
		},
		{
			name:      "curl user agent",
			userAgent: "curl/7.68.0",
			want:      "curl/7.68.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://localhost:8080/", nil)
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}

			got := getUserAgent(req)
			if got != tt.want {
				t.Errorf("getUserAgent() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedactClaimCode(t *testing.T) {
	tests := []struct {
		name string
		code string
		want string
	}{
		{
			name: "normal claim code",
			code: "Xy9kLm8pQz4vDwE",
			want: "Xy9...wE",
		},
		{
			name: "16 character code",
			code: "abcdefghijklmnop",
			want: "abc...op",
		},
		{
			name: "short code (5 chars or less)",
			code: "abc",
			want: "***",
		},
		{
			name: "exactly 5 chars",
			code: "abcde",
			want: "***",
		},
		{
			name: "6 chars (first redaction)",
			code: "abcdef",
			want: "abc...ef",
		},
		{
			name: "empty code",
			code: "",
			want: "***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactClaimCode(tt.code)
			if got != tt.want {
				t.Errorf("redactClaimCode(%q) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

func TestIsHTMLRequest(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   bool
	}{
		{
			name:   "browser Accept header",
			accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			want:   true,
		},
		{
			name:   "JSON only",
			accept: "application/json",
			want:   false,
		},
		{
			name:   "any Accept",
			accept: "*/*",
			want:   false,
		},
		{
			name:   "HTML only",
			accept: "text/html",
			want:   true,
		},
		{
			name:   "empty Accept",
			accept: "",
			want:   false,
		},
		{
			name:   "JSON before HTML",
			accept: "application/json,text/html",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://localhost:8080/", nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}

			got := isHTMLRequest(req)
			if got != tt.want {
				t.Errorf("isHTMLRequest() = %v, want %v (Accept: %q)", got, tt.want, tt.accept)
			}
		})
	}
}

func TestShouldRetryError(t *testing.T) {
	tests := []struct {
		name           string
		errorCode      string
		wantRetry      bool
		wantRetryAfter int
	}{
		// Retryable errors
		{
			name:           "INTERNAL_ERROR",
			errorCode:      "INTERNAL_ERROR",
			wantRetry:      true,
			wantRetryAfter: 5,
		},
		{
			name:           "DATABASE_ERROR",
			errorCode:      "DATABASE_ERROR",
			wantRetry:      true,
			wantRetryAfter: 3,
		},
		{
			name:           "INSUFFICIENT_STORAGE",
			errorCode:      "INSUFFICIENT_STORAGE",
			wantRetry:      true,
			wantRetryAfter: 30,
		},
		{
			name:           "RATE_LIMITED",
			errorCode:      "RATE_LIMITED",
			wantRetry:      true,
			wantRetryAfter: 60,
		},
		{
			name:           "NETWORK_ERROR",
			errorCode:      "NETWORK_ERROR",
			wantRetry:      true,
			wantRetryAfter: 2,
		},
		{
			name:           "TIMEOUT",
			errorCode:      "TIMEOUT",
			wantRetry:      true,
			wantRetryAfter: 5,
		},

		// Non-retryable errors
		{
			name:           "INVALID_JSON",
			errorCode:      "INVALID_JSON",
			wantRetry:      false,
			wantRetryAfter: 0,
		},
		{
			name:           "MISSING_FILENAME",
			errorCode:      "MISSING_FILENAME",
			wantRetry:      false,
			wantRetryAfter: 0,
		},
		{
			name:           "BLOCKED_EXTENSION",
			errorCode:      "BLOCKED_EXTENSION",
			wantRetry:      false,
			wantRetryAfter: 0,
		},
		{
			name:           "FILE_TOO_LARGE",
			errorCode:      "FILE_TOO_LARGE",
			wantRetry:      false,
			wantRetryAfter: 0,
		},
		{
			name:           "EXPIRATION_TOO_LONG",
			errorCode:      "EXPIRATION_TOO_LONG",
			wantRetry:      false,
			wantRetryAfter: 0,
		},
		{
			name:           "METHOD_NOT_ALLOWED",
			errorCode:      "METHOD_NOT_ALLOWED",
			wantRetry:      false,
			wantRetryAfter: 0,
		},
		{
			name:           "UNAUTHORIZED",
			errorCode:      "UNAUTHORIZED",
			wantRetry:      false,
			wantRetryAfter: 0,
		},
		{
			name:           "FORBIDDEN",
			errorCode:      "FORBIDDEN",
			wantRetry:      false,
			wantRetryAfter: 0,
		},
		{
			name:           "CHECKSUM_MISMATCH",
			errorCode:      "CHECKSUM_MISMATCH",
			wantRetry:      false,
			wantRetryAfter: 0,
		},

		// Special case - quota exceeded (production code treats as retryable with retryAfter=0)
		{
			name:           "QUOTA_EXCEEDED",
			errorCode:      "QUOTA_EXCEEDED",
			wantRetry:      true, // Production code has QUOTA_EXCEEDED in retryableErrors map
			wantRetryAfter: 0,
		},

		// Unknown error (default: retryable)
		{
			name:           "UNKNOWN_ERROR",
			errorCode:      "UNKNOWN_ERROR",
			wantRetry:      true,
			wantRetryAfter: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRetry, gotRetryAfter := shouldRetryError(tt.errorCode)

			if gotRetry != tt.wantRetry {
				t.Errorf("shouldRetryError(%q) retry = %v, want %v", tt.errorCode, gotRetry, tt.wantRetry)
			}

			if gotRetryAfter != tt.wantRetryAfter {
				t.Errorf("shouldRetryError(%q) retryAfter = %d, want %d", tt.errorCode, gotRetryAfter, tt.wantRetryAfter)
			}
		})
	}
}

// Test that helpers handle edge cases gracefully
func TestHelpers_EdgeCases(t *testing.T) {
	t.Run("buildDownloadURL with empty claim code", func(t *testing.T) {
		cfg := &config.Config{PublicURL: "https://example.com"}
		req := httptest.NewRequest("GET", "http://localhost:8080/", nil)

		got := buildDownloadURL(req, cfg, "")
		want := "https://example.com/api/claim/"

		if got != want {
			t.Errorf("buildDownloadURL() with empty claim code = %q, want %q", got, want)
		}
	})

	t.Run("getClientIP with malformed RemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://localhost:8080/", nil)
		req.RemoteAddr = "malformed"

		got := getClientIP(req)
		// Should return as-is if no colon found
		if got != "malformed" {
			t.Errorf("getClientIP() with malformed RemoteAddr = %q, want %q", got, "malformed")
		}
	})

	t.Run("redactClaimCode preserves first 3 and last 2", func(t *testing.T) {
		code := "1234567890ABCDEF"
		got := redactClaimCode(code)

		if got[:3] != code[:3] {
			t.Errorf("redactClaimCode() didn't preserve first 3 chars: %q", got)
		}

		if got[len(got)-2:] != code[len(code)-2:] {
			t.Errorf("redactClaimCode() didn't preserve last 2 chars: %q", got)
		}

		if got[3:len(got)-2] != "..." {
			t.Errorf("redactClaimCode() middle should be '...': %q", got)
		}
	})
}

func TestSendError(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		code       string
		statusCode int
	}{
		{
			name:       "bad request",
			message:    "Invalid input",
			code:       "INVALID_INPUT",
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "not found",
			message:    "File not found",
			code:       "NOT_FOUND",
			statusCode: http.StatusNotFound,
		},
		{
			name:       "internal error",
			message:    "Something went wrong",
			code:       "INTERNAL_ERROR",
			statusCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			sendError(rr, tt.message, tt.code, tt.statusCode)

			if rr.Code != tt.statusCode {
				t.Errorf("status = %d, want %d", rr.Code, tt.statusCode)
			}

			contentType := rr.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", contentType)
			}

			var response models.ErrorResponse
			if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if response.Error != tt.message {
				t.Errorf("error = %q, want %q", response.Error, tt.message)
			}

			if response.Code != tt.code {
				t.Errorf("code = %q, want %q", response.Code, tt.code)
			}
		})
	}
}

func TestSendErrorWithRetry(t *testing.T) {
	t.Run("with retry recommended", func(t *testing.T) {
		rr := httptest.NewRecorder()
		retryRecommended := true
		retryAfter := 30

		sendErrorWithRetry(rr, "Retry later", "RATE_LIMITED", http.StatusTooManyRequests, &retryRecommended, &retryAfter)

		var response models.ErrorResponse
		json.NewDecoder(rr.Body).Decode(&response)

		if response.RetryRecommended == nil || !*response.RetryRecommended {
			t.Error("expected retry_recommended to be true")
		}

		if response.RetryAfter == nil || *response.RetryAfter != 30 {
			t.Error("expected retry_after to be 30")
		}
	})

	t.Run("without retry", func(t *testing.T) {
		rr := httptest.NewRecorder()
		retryRecommended := false

		sendErrorWithRetry(rr, "Bad request", "INVALID_INPUT", http.StatusBadRequest, &retryRecommended, nil)

		var response models.ErrorResponse
		json.NewDecoder(rr.Body).Decode(&response)

		if response.RetryRecommended == nil || *response.RetryRecommended {
			t.Error("expected retry_recommended to be false")
		}

		if response.RetryAfter != nil {
			t.Error("expected retry_after to be nil")
		}
	})

	t.Run("nil retry params", func(t *testing.T) {
		rr := httptest.NewRecorder()

		sendErrorWithRetry(rr, "Error", "ERROR", http.StatusInternalServerError, nil, nil)

		var response models.ErrorResponse
		json.NewDecoder(rr.Body).Decode(&response)

		if response.RetryRecommended != nil {
			t.Error("expected retry_recommended to be nil")
		}
	})
}

func TestSendHTMLError(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		message    string
		code       string
		statusCode int
	}{
		{
			name:       "not found page",
			title:      "File Not Found",
			message:    "The requested file could not be found.",
			code:       "NOT_FOUND",
			statusCode: http.StatusNotFound,
		},
		{
			name:       "error page",
			title:      "Server Error",
			message:    "An internal error occurred.",
			code:       "INTERNAL_ERROR",
			statusCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			sendHTMLError(rr, tt.title, tt.message, tt.code, tt.statusCode)

			if rr.Code != tt.statusCode {
				t.Errorf("status = %d, want %d", rr.Code, tt.statusCode)
			}

			contentType := rr.Header().Get("Content-Type")
			// Should be either text/html or text/plain (fallback)
			if !strings.HasPrefix(contentType, "text/html") && !strings.HasPrefix(contentType, "text/plain") {
				t.Errorf("Content-Type = %q, want text/html or text/plain", contentType)
			}

			// Response body should contain the message
			body := rr.Body.String()
			if !strings.Contains(body, tt.message) {
				t.Errorf("body should contain message %q", tt.message)
			}
		})
	}
}

func TestSendErrorResponse(t *testing.T) {
	tests := []struct {
		name       string
		accept     string
		wantHTML   bool
	}{
		{
			name:     "browser request",
			accept:   "text/html,application/xhtml+xml",
			wantHTML: true,
		},
		{
			name:     "API request",
			accept:   "application/json",
			wantHTML: false,
		},
		{
			name:     "curl request",
			accept:   "*/*",
			wantHTML: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Accept", tt.accept)

			sendErrorResponse(rr, req, "Error Title", "Error message", "ERROR_CODE", http.StatusBadRequest)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
			}

			contentType := rr.Header().Get("Content-Type")
			if tt.wantHTML {
				if !strings.HasPrefix(contentType, "text/html") && !strings.HasPrefix(contentType, "text/plain") {
					t.Errorf("expected HTML content type, got %q", contentType)
				}
			} else {
				if contentType != "application/json" {
					t.Errorf("expected JSON content type, got %q", contentType)
				}
			}
		})
	}
}

func TestSendSmartError(t *testing.T) {
	tests := []struct {
		name           string
		errorCode      string
		wantRetry      bool
		wantRetryAfter int
	}{
		{
			name:           "retryable error",
			errorCode:      "INTERNAL_ERROR",
			wantRetry:      true,
			wantRetryAfter: 5,
		},
		{
			name:           "non-retryable error",
			errorCode:      "INVALID_JSON",
			wantRetry:      false,
			wantRetryAfter: 0,
		},
		{
			name:           "rate limited",
			errorCode:      "RATE_LIMITED",
			wantRetry:      true,
			wantRetryAfter: 60,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			sendSmartError(rr, "Error message", tt.errorCode, http.StatusBadRequest)

			var response models.ErrorResponse
			json.NewDecoder(rr.Body).Decode(&response)

			if response.RetryRecommended == nil {
				t.Fatal("expected retry_recommended to be set")
			}

			if *response.RetryRecommended != tt.wantRetry {
				t.Errorf("retry_recommended = %v, want %v", *response.RetryRecommended, tt.wantRetry)
			}

			if tt.wantRetry && tt.wantRetryAfter > 0 {
				if response.RetryAfter == nil {
					t.Error("expected retry_after to be set")
				} else if *response.RetryAfter != tt.wantRetryAfter {
					t.Errorf("retry_after = %d, want %d", *response.RetryAfter, tt.wantRetryAfter)
				}
			}
		})
	}
}

func TestGetClientIPWithConfig(t *testing.T) {
	tests := []struct {
		name              string
		headers           map[string]string
		remoteAddr        string
		trustProxyHeaders string
		trustedProxyIPs   string
		want              string
	}{
		{
			name: "trusted proxy with X-Forwarded-For",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
			},
			remoteAddr:        "10.0.0.1:12345",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   "10.0.0.0/8",
			want:              "203.0.113.1",
		},
		{
			name: "untrusted proxy ignores headers",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
			},
			remoteAddr:        "8.8.8.8:12345",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   "10.0.0.0/8",
			want:              "8.8.8.8",
		},
		{
			name:              "no headers, use remote addr",
			headers:           map[string]string{},
			remoteAddr:        "192.168.1.1:12345",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   "10.0.0.0/8",
			want:              "192.168.1.1",
		},
		{
			name: "trust all with true",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
			},
			remoteAddr:        "8.8.8.8:12345",
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "203.0.113.1",
		},
		{
			name: "never trust headers with false",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
			},
			remoteAddr:        "10.0.0.1:12345",
			trustProxyHeaders: "false",
			trustedProxyIPs:   "10.0.0.0/8",
			want:              "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://localhost:8080/", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, val := range tt.headers {
				req.Header.Set(key, val)
			}

			cfg := &config.Config{
				TrustProxyHeaders: tt.trustProxyHeaders,
				TrustedProxyIPs:   tt.trustedProxyIPs,
			}

			got := getClientIPWithConfig(req, cfg)
			if got != tt.want {
				t.Errorf("getClientIPWithConfig() = %q, want %q", got, tt.want)
			}
		})
	}
}
