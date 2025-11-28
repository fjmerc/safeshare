package webhooks

import (
	"encoding/json"
	"time"
)

// EventType represents the type of webhook event
type EventType string

const (
	EventFileUploaded   EventType = "file.uploaded"
	EventFileDownloaded EventType = "file.downloaded"
	EventFileDeleted    EventType = "file.deleted"
	EventFileExpired    EventType = "file.expired"
)

// WebhookFormat represents the format/protocol for webhook payloads
type WebhookFormat string

const (
	FormatSafeShare WebhookFormat = "safeshare" // Default SafeShare JSON format
	FormatGotify    WebhookFormat = "gotify"    // Gotify notification format
	FormatNtfy      WebhookFormat = "ntfy"      // ntfy.sh notification format
	FormatDiscord   WebhookFormat = "discord"   // Discord webhook format
)

// ValidateFormat checks if a webhook format is valid
func ValidateFormat(format string) bool {
	switch WebhookFormat(format) {
	case FormatSafeShare, FormatGotify, FormatNtfy, FormatDiscord:
		return true
	default:
		return false
	}
}

// Config represents a webhook configuration
type Config struct {
	ID             int64         `json:"id"`
	URL            string        `json:"url"`
	Secret         string        `json:"secret"`
	ServiceToken   string        `json:"service_token,omitempty"` // Authentication token for services (Gotify, ntfy)
	Enabled        bool          `json:"enabled"`
	Events         []string      `json:"events"`
	Format         WebhookFormat `json:"format"`
	MaxRetries     int           `json:"max_retries"`
	TimeoutSeconds int           `json:"timeout_seconds"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

// Delivery represents a webhook delivery attempt
type Delivery struct {
	ID              int64      `json:"id"`
	WebhookConfigID int64      `json:"webhook_config_id"`
	EventType       string     `json:"event_type"`
	Payload         string     `json:"payload"`
	AttemptCount    int        `json:"attempt_count"`
	Status          string     `json:"status"`
	ResponseCode    *int       `json:"response_code,omitempty"`
	ResponseBody    *string    `json:"response_body,omitempty"`
	ErrorMessage    *string    `json:"error_message,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	NextRetryAt     *time.Time `json:"next_retry_at,omitempty"`
}

// DeliveryStatus represents the status of a webhook delivery
type DeliveryStatus string

const (
	DeliveryStatusPending   DeliveryStatus = "pending"
	DeliveryStatusSuccess   DeliveryStatus = "success"
	DeliveryStatusFailed    DeliveryStatus = "failed"
	DeliveryStatusRetrying  DeliveryStatus = "retrying"
)

// Event represents a webhook event to be delivered
type Event struct {
	Type      EventType `json:"event"`
	Timestamp time.Time `json:"timestamp"`
	File      FileData  `json:"file"`
}

// FileData represents file metadata in webhook payloads
type FileData struct {
	ID           int64      `json:"id,omitempty"`
	ClaimCode    string     `json:"claim_code"`
	Filename     string     `json:"filename"`
	Size         int64      `json:"size"`
	MimeType     string     `json:"mime_type,omitempty"`
	ExpiresAt    time.Time  `json:"expires_at"`
	DownloadedAt *time.Time `json:"downloaded_at,omitempty"` // For file.downloaded events
	Reason       *string    `json:"reason,omitempty"`        // For file.deleted/expired events
}

// ToJSON converts an Event to JSON string
func (e *Event) ToJSON() (string, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ParseEventsJSON parses a JSON array of event types
func ParseEventsJSON(eventsJSON string) ([]string, error) {
	var events []string
	if err := json.Unmarshal([]byte(eventsJSON), &events); err != nil {
		return nil, err
	}
	return events, nil
}

// EncodeEventsJSON encodes event types to JSON array
func EncodeEventsJSON(events []string) (string, error) {
	data, err := json.Marshal(events)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SubscribedTo checks if a config is subscribed to an event type
func (c *Config) SubscribedTo(eventType EventType) bool {
	eventStr := string(eventType)
	for _, event := range c.Events {
		if event == eventStr {
			return true
		}
	}
	return false
}
