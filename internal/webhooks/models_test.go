package webhooks

import (
	"encoding/json"
	"testing"
	"time"
)

func TestConfig_SubscribedTo(t *testing.T) {
	tests := []struct {
		name      string
		events    []string
		eventType EventType
		expected  bool
	}{
		{
			name:      "subscribed to file.uploaded",
			events:    []string{"file.uploaded", "file.downloaded"},
			eventType: EventFileUploaded,
			expected:  true,
		},
		{
			name:      "not subscribed to file.deleted",
			events:    []string{"file.uploaded", "file.downloaded"},
			eventType: EventFileDeleted,
			expected:  false,
		},
		{
			name:      "empty events list",
			events:    []string{},
			eventType: EventFileUploaded,
			expected:  false,
		},
		{
			name:      "all events subscribed",
			events:    []string{"file.uploaded", "file.downloaded", "file.deleted", "file.expired"},
			eventType: EventFileExpired,
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Events: tt.events}
			result := config.SubscribedTo(tt.eventType)
			if result != tt.expected {
				t.Errorf("SubscribedTo(%v) = %v, want %v", tt.eventType, result, tt.expected)
			}
		})
	}
}

func TestEncodeEventsJSON(t *testing.T) {
	tests := []struct {
		name    string
		events  []string
		wantErr bool
	}{
		{
			name:    "valid events",
			events:  []string{"file.uploaded", "file.downloaded"},
			wantErr: false,
		},
		{
			name:    "empty events",
			events:  []string{},
			wantErr: false,
		},
		{
			name:    "single event",
			events:  []string{"file.uploaded"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := EncodeEventsJSON(tt.events)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeEventsJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify it's valid JSON
				var decoded []string
				if err := json.Unmarshal([]byte(result), &decoded); err != nil {
					t.Errorf("EncodeEventsJSON() produced invalid JSON: %v", err)
				}
				// Verify decoded matches original
				if len(decoded) != len(tt.events) {
					t.Errorf("EncodeEventsJSON() decoded length = %d, want %d", len(decoded), len(tt.events))
				}
			}
		})
	}
}

func TestParseEventsJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
		wantErr  bool
	}{
		{
			name:     "valid JSON array",
			input:    `["file.uploaded","file.downloaded"]`,
			expected: []string{"file.uploaded", "file.downloaded"},
			wantErr:  false,
		},
		{
			name:     "empty array",
			input:    `[]`,
			expected: []string{},
			wantErr:  false,
		},
		{
			name:     "invalid JSON",
			input:    `not valid json`,
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "single event",
			input:    `["file.uploaded"]`,
			expected: []string{"file.uploaded"},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseEventsJSON(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseEventsJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(result) != len(tt.expected) {
					t.Errorf("ParseEventsJSON() length = %d, want %d", len(result), len(tt.expected))
				}
				for i, v := range result {
					if v != tt.expected[i] {
						t.Errorf("ParseEventsJSON()[%d] = %v, want %v", i, v, tt.expected[i])
					}
				}
			}
		})
	}
}

func TestEvent_ToJSON(t *testing.T) {
	now := time.Now()
	event := &Event{
		Type:      EventFileUploaded,
		Timestamp: now,
		File: FileData{
			ID:        1,
			ClaimCode: "TEST123",
			Filename:  "test.txt",
			Size:      1024,
			MimeType:  "text/plain",
			ExpiresAt: now.Add(24 * time.Hour),
		},
	}

	result, err := event.ToJSON()
	if err != nil {
		t.Errorf("ToJSON() error = %v", err)
		return
	}

	// Verify it's valid JSON
	var decoded Event
	if err := json.Unmarshal([]byte(result), &decoded); err != nil {
		t.Errorf("ToJSON() produced invalid JSON: %v", err)
	}

	// Verify key fields
	if decoded.Type != EventFileUploaded {
		t.Errorf("ToJSON() event type = %v, want %v", decoded.Type, EventFileUploaded)
	}
	if decoded.File.ClaimCode != "TEST123" {
		t.Errorf("ToJSON() claim code = %v, want TEST123", decoded.File.ClaimCode)
	}
	if decoded.File.Filename != "test.txt" {
		t.Errorf("ToJSON() filename = %v, want test.txt", decoded.File.Filename)
	}
}

func TestEventTypes(t *testing.T) {
	// Verify event type constants
	tests := []struct {
		name     string
		event    EventType
		expected string
	}{
		{"file uploaded", EventFileUploaded, "file.uploaded"},
		{"file downloaded", EventFileDownloaded, "file.downloaded"},
		{"file deleted", EventFileDeleted, "file.deleted"},
		{"file expired", EventFileExpired, "file.expired"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.event) != tt.expected {
				t.Errorf("EventType = %v, want %v", tt.event, tt.expected)
			}
		})
	}
}

func TestDeliveryStatus(t *testing.T) {
	// Verify delivery status constants
	tests := []struct {
		name     string
		status   DeliveryStatus
		expected string
	}{
		{"pending", DeliveryStatusPending, "pending"},
		{"success", DeliveryStatusSuccess, "success"},
		{"failed", DeliveryStatusFailed, "failed"},
		{"retrying", DeliveryStatusRetrying, "retrying"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.status) != tt.expected {
				t.Errorf("DeliveryStatus = %v, want %v", tt.status, tt.expected)
			}
		})
	}
}
