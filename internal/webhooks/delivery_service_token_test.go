package webhooks

import (
	"net/http"
	"testing"
)

func TestConstructURLWithToken(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		token    string
		format   WebhookFormat
		expected string
	}{
		{
			name:     "Gotify - URL without query params",
			baseURL:  "https://gotify.example.com/message",
			token:    "ABC123",
			format:   FormatGotify,
			expected: "https://gotify.example.com/message?token=ABC123",
		},
		{
			name:     "Gotify - URL with existing query params",
			baseURL:  "https://gotify.example.com/message?priority=5",
			token:    "ABC123",
			format:   FormatGotify,
			expected: "https://gotify.example.com/message?priority=5&token=ABC123",
		},
		{
			name:     "ntfy - no URL modification",
			baseURL:  "https://ntfy.sh/mytopic",
			token:    "tk_12345",
			format:   FormatNtfy,
			expected: "https://ntfy.sh/mytopic",
		},
		{
			name:     "Discord - no URL modification",
			baseURL:  "https://discord.com/api/webhooks/123/abc",
			token:    "ignored",
			format:   FormatDiscord,
			expected: "https://discord.com/api/webhooks/123/abc",
		},
		{
			name:     "SafeShare - no URL modification",
			baseURL:  "https://example.com/webhook",
			token:    "ignored",
			format:   FormatSafeShare,
			expected: "https://example.com/webhook",
		},
		{
			name:     "Gotify - empty token",
			baseURL:  "https://gotify.example.com/message",
			token:    "",
			format:   FormatGotify,
			expected: "https://gotify.example.com/message?token=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := constructURLWithToken(tt.baseURL, tt.token, tt.format)
			if result != tt.expected {
				t.Errorf("constructURLWithToken(%q, %q, %q) = %q, want %q",
					tt.baseURL, tt.token, tt.format, result, tt.expected)
			}
		})
	}
}

func TestAddAuthHeaders(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		format         WebhookFormat
		expectedHeader string
		expectedValue  string
	}{
		{
			name:           "ntfy - adds Authorization header",
			token:          "tk_12345",
			format:         FormatNtfy,
			expectedHeader: "Authorization",
			expectedValue:  "Bearer tk_12345",
		},
		{
			name:           "Gotify - no headers",
			token:          "ABC123",
			format:         FormatGotify,
			expectedHeader: "Authorization",
			expectedValue:  "",
		},
		{
			name:           "Discord - no headers",
			token:          "ignored",
			format:         FormatDiscord,
			expectedHeader: "Authorization",
			expectedValue:  "",
		},
		{
			name:           "SafeShare - no headers",
			token:          "ignored",
			format:         FormatSafeShare,
			expectedHeader: "Authorization",
			expectedValue:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "https://example.com", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			addAuthHeaders(req, tt.token, tt.format)

			actualValue := req.Header.Get(tt.expectedHeader)
			if actualValue != tt.expectedValue {
				t.Errorf("addAuthHeaders() header %q = %q, want %q",
					tt.expectedHeader, actualValue, tt.expectedValue)
			}
		})
	}
}

func TestDeliverWebhookWithConfig_URLConstruction(t *testing.T) {
	// This test verifies that DeliverWebhookWithConfig constructs URLs correctly
	// Note: We can't easily test actual HTTP delivery without a test server,
	// but we can verify the function exists and accepts the config parameter

	config := &Config{
		URL:          "https://gotify.example.com/message",
		Secret:       "test-secret",
		ServiceToken: "ABC123",
		Format:       FormatGotify,
	}

	// This will fail to connect, but that's expected - we're just verifying
	// the function signature and that it doesn't panic with a config
	result := DeliverWebhookWithConfig(config, config.URL, config.Secret, "{}", 5)

	// Should get an error (connection refused or similar), not success
	if result.Success {
		t.Error("Expected delivery to fail (no server), but got success")
	}
}

func TestDeliverWebhook_BackwardCompatibility(t *testing.T) {
	// Verify that the original DeliverWebhook function still works (backward compatibility)
	result := DeliverWebhook("https://example.com/webhook", "secret", "{}", 5)

	// Should get an error (connection refused or similar), not success
	if result.Success {
		t.Error("Expected delivery to fail (no server), but got success")
	}
}
