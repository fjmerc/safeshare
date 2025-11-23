package webhooks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTransformPayload(t *testing.T) {
	testTime := time.Date(2025, 1, 23, 12, 0, 0, 0, time.UTC)
	expiresTime := time.Date(2025, 1, 24, 12, 0, 0, 0, time.UTC)

	testEvent := &Event{
		Type:      EventFileUploaded,
		Timestamp: testTime,
		File: FileData{
			ID:        1,
			ClaimCode: "TEST123",
			Filename:  "example.txt",
			Size:      1048576, // 1 MB
			MimeType:  "text/plain",
			ExpiresAt: expiresTime,
		},
	}

	tests := []struct {
		name        string
		format      WebhookFormat
		wantErr     bool
		validateFn  func(*testing.T, string)
	}{
		{
			name:    "SafeShare format",
			format:  FormatSafeShare,
			wantErr: false,
			validateFn: func(t *testing.T, payload string) {
				var result map[string]interface{}
				if err := json.Unmarshal([]byte(payload), &result); err != nil {
					t.Fatalf("Failed to parse SafeShare payload: %v", err)
				}
				if result["event"] != string(EventFileUploaded) {
					t.Errorf("Expected event %s, got %v", EventFileUploaded, result["event"])
				}
			},
		},
		{
			name:    "Gotify format",
			format:  FormatGotify,
			wantErr: false,
			validateFn: func(t *testing.T, payload string) {
				var result map[string]interface{}
				if err := json.Unmarshal([]byte(payload), &result); err != nil {
					t.Fatalf("Failed to parse Gotify payload: %v", err)
				}
				if result["title"] == nil {
					t.Error("Gotify payload missing title field")
				}
				if result["message"] == nil {
					t.Error("Gotify payload missing message field")
				}
				if result["priority"] == nil {
					t.Error("Gotify payload missing priority field")
				}
			},
		},
		{
			name:    "ntfy format",
			format:  FormatNtfy,
			wantErr: false,
			validateFn: func(t *testing.T, payload string) {
				var result map[string]interface{}
				if err := json.Unmarshal([]byte(payload), &result); err != nil {
					t.Fatalf("Failed to parse ntfy payload: %v", err)
				}
				if result["title"] == nil {
					t.Error("ntfy payload missing title field")
				}
				if result["message"] == nil {
					t.Error("ntfy payload missing message field")
				}
			},
		},
		{
			name:    "Discord format",
			format:  FormatDiscord,
			wantErr: false,
			validateFn: func(t *testing.T, payload string) {
				var result map[string]interface{}
				if err := json.Unmarshal([]byte(payload), &result); err != nil {
					t.Fatalf("Failed to parse Discord payload: %v", err)
				}
				embeds, ok := result["embeds"].([]interface{})
				if !ok || len(embeds) == 0 {
					t.Error("Discord payload missing embeds array")
				}
			},
		},
		{
			name:    "Unsupported format",
			format:  WebhookFormat("invalid"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := TransformPayload(testEvent, tt.format)
			if (err != nil) != tt.wantErr {
				t.Errorf("TransformPayload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.validateFn != nil {
				tt.validateFn(t, payload)
			}
		})
	}
}

func TestFormatGotifyTitle(t *testing.T) {
	tests := []struct {
		eventType EventType
		want      string
	}{
		{EventFileUploaded, "SafeShare: File Uploaded"},
		{EventFileDownloaded, "SafeShare: File Downloaded"},
		{EventFileDeleted, "SafeShare: File Deleted"},
		{EventFileExpired, "SafeShare: File Expired"},
	}

	for _, tt := range tests {
		t.Run(string(tt.eventType), func(t *testing.T) {
			event := &Event{Type: tt.eventType}
			got := formatGotifyTitle(event)
			if got != tt.want {
				t.Errorf("formatGotifyTitle() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetGotifyPriority(t *testing.T) {
	tests := []struct {
		eventType    EventType
		wantPriority int
	}{
		{EventFileUploaded, 7},
		{EventFileDownloaded, 5},
		{EventFileDeleted, 3},
		{EventFileExpired, 3},
	}

	for _, tt := range tests {
		t.Run(string(tt.eventType), func(t *testing.T) {
			event := &Event{Type: tt.eventType}
			got := getGotifyPriority(event)
			if got != tt.wantPriority {
				t.Errorf("getGotifyPriority() = %v, want %v", got, tt.wantPriority)
			}
		})
	}
}

func TestGetNtfyPriority(t *testing.T) {
	tests := []struct {
		eventType    EventType
		wantPriority int
	}{
		{EventFileUploaded, 4},
		{EventFileDownloaded, 3},
		{EventFileDeleted, 2},
		{EventFileExpired, 2},
	}

	for _, tt := range tests {
		t.Run(string(tt.eventType), func(t *testing.T) {
			event := &Event{Type: tt.eventType}
			got := getNtfyPriority(event)
			if got != tt.wantPriority {
				t.Errorf("getNtfyPriority() = %v, want %v", got, tt.wantPriority)
			}
		})
	}
}

func TestGetDiscordColor(t *testing.T) {
	tests := []struct {
		eventType EventType
		wantColor int
	}{
		{EventFileUploaded, 3066993},   // Green
		{EventFileDownloaded, 3447003}, // Blue
		{EventFileDeleted, 15158332},   // Red
		{EventFileExpired, 15844367},   // Gold
	}

	for _, tt := range tests {
		t.Run(string(tt.eventType), func(t *testing.T) {
			event := &Event{Type: tt.eventType}
			got := getDiscordColor(event)
			if got != tt.wantColor {
				t.Errorf("getDiscordColor() = %v, want %v", got, tt.wantColor)
			}
		})
	}
}

func TestFormatFileSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1.0 GB"},
		{1610612736, "1.5 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatFileSize(tt.bytes)
			if got != tt.want {
				t.Errorf("formatFileSize(%d) = %v, want %v", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestTransformToGotify(t *testing.T) {
	testTime := time.Date(2025, 1, 23, 12, 0, 0, 0, time.UTC)
	expiresTime := time.Date(2025, 1, 24, 12, 0, 0, 0, time.UTC)

	event := &Event{
		Type:      EventFileUploaded,
		Timestamp: testTime,
		File: FileData{
			ClaimCode: "ABC123",
			Filename:  "test.pdf",
			Size:      2097152, // 2 MB
			ExpiresAt: expiresTime,
		},
	}

	payload, err := transformToGotify(event)
	if err != nil {
		t.Fatalf("transformToGotify() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &result); err != nil {
		t.Fatalf("Failed to parse payload: %v", err)
	}

	// Check required fields
	if title, ok := result["title"].(string); !ok || title == "" {
		t.Error("Missing or empty title")
	}
	if message, ok := result["message"].(string); !ok || message == "" {
		t.Error("Missing or empty message")
	}
	if !strings.Contains(result["message"].(string), "ABC123") {
		t.Error("Message should contain claim code")
	}
	if !strings.Contains(result["message"].(string), "test.pdf") {
		t.Error("Message should contain filename")
	}
}

func TestTransformToDiscord(t *testing.T) {
	testTime := time.Date(2025, 1, 23, 12, 0, 0, 0, time.UTC)
	expiresTime := time.Date(2025, 1, 24, 12, 0, 0, 0, time.UTC)

	event := &Event{
		Type:      EventFileUploaded,
		Timestamp: testTime,
		File: FileData{
			ClaimCode: "XYZ789",
			Filename:  "document.docx",
			Size:      5242880, // 5 MB
			ExpiresAt: expiresTime,
		},
	}

	payload, err := transformToDiscord(event)
	if err != nil {
		t.Fatalf("transformToDiscord() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &result); err != nil {
		t.Fatalf("Failed to parse payload: %v", err)
	}

	// Check embeds structure
	embeds, ok := result["embeds"].([]interface{})
	if !ok || len(embeds) == 0 {
		t.Fatal("Missing embeds array")
	}

	embed := embeds[0].(map[string]interface{})
	if embed["title"] == nil {
		t.Error("Embed missing title")
	}
	if embed["description"] == nil {
		t.Error("Embed missing description")
	}
	if embed["color"] == nil {
		t.Error("Embed missing color")
	}
	if embed["fields"] == nil {
		t.Error("Embed missing fields")
	}
}

func TestValidateFormat(t *testing.T) {
	tests := []struct {
		format string
		want   bool
	}{
		{"safeshare", true},
		{"gotify", true},
		{"ntfy", true},
		{"discord", true},
		{"invalid", false},
		{"", false},
		{"SAFESHARE", false}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			got := ValidateFormat(tt.format)
			if got != tt.want {
				t.Errorf("ValidateFormat(%q) = %v, want %v", tt.format, got, tt.want)
			}
		})
	}
}
