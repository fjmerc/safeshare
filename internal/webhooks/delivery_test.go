package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestComputeHMACSignature(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		secret   string
		expected string
	}{
		{
			name:     "basic signature",
			payload:  `{"event":"file.uploaded"}`,
			secret:   "test-secret",
			expected: computeExpectedHMAC(`{"event":"file.uploaded"}`, "test-secret"),
		},
		{
			name:     "empty payload",
			payload:  "",
			secret:   "test-secret",
			expected: computeExpectedHMAC("", "test-secret"),
		},
		{
			name:     "long secret",
			payload:  "test payload",
			secret:   "very-long-secret-key-12345678901234567890",
			expected: computeExpectedHMAC("test payload", "very-long-secret-key-12345678901234567890"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeHMACSignature(tt.payload, tt.secret)
			if result != tt.expected {
				t.Errorf("ComputeHMACSignature() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func computeExpectedHMAC(payload, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func TestCalculateRetryDelay(t *testing.T) {
	tests := []struct {
		name         string
		attemptCount int
		expected     time.Duration
	}{
		{"first retry", 0, 1 * time.Second},
		{"second retry", 1, 2 * time.Second},
		{"third retry", 2, 4 * time.Second},
		{"fourth retry", 3, 8 * time.Second},
		{"fifth retry", 4, 16 * time.Second},
		{"sixth retry", 5, 32 * time.Second},
		{"max capped at 60s", 6, 60 * time.Second},
		{"negative input", -1, 1 * time.Second},
		{"overflow protection", 31, 60 * time.Second},
		{"large value", 100, 60 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateRetryDelay(tt.attemptCount)
			if result != tt.expected {
				t.Errorf("CalculateRetryDelay(%d) = %v, want %v", tt.attemptCount, result, tt.expected)
			}
		})
	}
}

func TestShouldRetry(t *testing.T) {
	tests := []struct {
		name         string
		attemptCount int
		maxRetries   int
		expected     bool
	}{
		{"first attempt under max", 1, 5, true},
		{"at max retries", 5, 5, false},
		{"over max retries", 6, 5, false},
		{"zero attempts", 0, 5, true},
		{"max retries zero", 1, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldRetry(tt.attemptCount, tt.maxRetries)
			if result != tt.expected {
				t.Errorf("ShouldRetry(%d, %d) = %v, want %v", tt.attemptCount, tt.maxRetries, result, tt.expected)
			}
		})
	}
}

func TestDeliverWebhook_Success(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type: application/json, got %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("X-SafeShare-Signature") == "" {
			t.Error("Expected X-SafeShare-Signature header")
		}
		if r.Header.Get("X-SafeShare-Signature-Algorithm") != "sha256" {
			t.Errorf("Expected X-SafeShare-Signature-Algorithm: sha256, got %s", r.Header.Get("X-SafeShare-Signature-Algorithm"))
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"received"}`))
	}))
	defer server.Close()

	result := DeliverWebhook(server.URL, "test-secret", `{"event":"test"}`, 5)

	if !result.Success {
		t.Errorf("Expected success, got failure: %v", result.Error)
	}
	if result.ResponseCode != 200 {
		t.Errorf("Expected response code 200, got %d", result.ResponseCode)
	}
	if result.ResponseBody != `{"status":"received"}` {
		t.Errorf("Expected response body {\"status\":\"received\"}, got %s", result.ResponseBody)
	}
}

func TestDeliverWebhook_Failure(t *testing.T) {
	// Create test server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	result := DeliverWebhook(server.URL, "test-secret", `{"event":"test"}`, 5)

	if result.Success {
		t.Error("Expected failure, got success")
	}
	if result.ResponseCode != 500 {
		t.Errorf("Expected response code 500, got %d", result.ResponseCode)
	}
}

func TestDeliverWebhook_Timeout(t *testing.T) {
	// Create test server with delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Set very short timeout
	result := DeliverWebhook(server.URL, "test-secret", `{"event":"test"}`, 1)

	if result.Success {
		t.Error("Expected timeout failure, got success")
	}
	if result.Error == nil {
		t.Error("Expected error for timeout")
	}
}

func TestDeliverWebhook_ResponseBodyTruncation(t *testing.T) {
	// Create test server with large response
	largeResponse := string(make([]byte, 2048)) // 2KB response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(largeResponse))
	}))
	defer server.Close()

	result := DeliverWebhook(server.URL, "test-secret", `{"event":"test"}`, 5)

	if !result.Success {
		t.Errorf("Expected success, got failure: %v", result.Error)
	}

	// Response should be truncated to 1KB + "... (truncated)"
	maxSize := 1024 + len("... (truncated)")
	if len(result.ResponseBody) > maxSize {
		t.Errorf("Response body not truncated: got %d bytes, max should be ~%d", len(result.ResponseBody), maxSize)
	}
}
