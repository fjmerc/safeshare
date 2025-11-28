package webhooks

import (
	"encoding/json"
	"fmt"
	"time"
)

// TransformPayload transforms a webhook event into the specified format
func TransformPayload(event *Event, format WebhookFormat) (string, error) {
	switch format {
	case FormatGotify:
		return transformToGotify(event)
	case FormatNtfy:
		return transformToNtfy(event)
	case FormatDiscord:
		return transformToDiscord(event)
	case FormatSafeShare:
		return event.ToJSON()
	default:
		return "", fmt.Errorf("unsupported webhook format: %s", format)
	}
}

// transformToGotify transforms an event to Gotify message format
func transformToGotify(event *Event) (string, error) {
	// Gotify payload structure
	payload := map[string]interface{}{
		"title":    formatGotifyTitle(event),
		"message":  formatGotifyMessage(event),
		"priority": getGotifyPriority(event),
		"extras": map[string]interface{}{
			"client::display": map[string]string{
				"contentType": "text/markdown",
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Gotify payload: %w", err)
	}

	return string(data), nil
}

// formatGotifyTitle creates a title for Gotify notifications
func formatGotifyTitle(event *Event) string {
	switch event.Type {
	case EventFileUploaded:
		return "SafeShare: File Uploaded"
	case EventFileDownloaded:
		return "SafeShare: File Downloaded"
	case EventFileDeleted:
		return "SafeShare: File Deleted"
	case EventFileExpired:
		return "SafeShare: File Expired"
	default:
		return "SafeShare: Event"
	}
}

// formatGotifyMessage creates a message body for Gotify notifications
func formatGotifyMessage(event *Event) string {
	size := formatFileSize(event.File.Size)

	switch event.Type {
	case EventFileUploaded:
		return fmt.Sprintf("**%s** (%s)\n\n**Claim Code:** `%s`\n**Expires:** %s",
			event.File.Filename,
			size,
			event.File.ClaimCode,
			event.File.ExpiresAt.Format("2006-01-02 15:04 MST"))
	case EventFileDownloaded:
		downloadTime := ""
		if event.File.DownloadedAt != nil {
			downloadTime = event.File.DownloadedAt.Format("2006-01-02 15:04 MST")
		}
		return fmt.Sprintf("**%s** (%s)\n\n**Claim Code:** `%s`\n**Downloaded:** %s",
			event.File.Filename,
			size,
			event.File.ClaimCode,
			downloadTime)
	case EventFileDeleted:
		reason := "Manual deletion"
		if event.File.Reason != nil {
			reason = *event.File.Reason
		}
		return fmt.Sprintf("**%s** (%s)\n\n**Claim Code:** `%s`\n**Reason:** %s",
			event.File.Filename,
			size,
			event.File.ClaimCode,
			reason)
	case EventFileExpired:
		reason := "Time-based expiration"
		if event.File.Reason != nil {
			reason = *event.File.Reason
		}
		return fmt.Sprintf("**%s** (%s)\n\n**Claim Code:** `%s`\n**Expired:** %s\n**Reason:** %s",
			event.File.Filename,
			size,
			event.File.ClaimCode,
			event.File.ExpiresAt.Format("2006-01-02 15:04 MST"),
			reason)
	default:
		return fmt.Sprintf("**%s** (%s)\n\n**Claim Code:** `%s`",
			event.File.Filename,
			size,
			event.File.ClaimCode)
	}
}

// getGotifyPriority returns priority level for Gotify (0-10)
func getGotifyPriority(event *Event) int {
	switch event.Type {
	case EventFileExpired, EventFileDeleted:
		return 3 // Low priority for cleanup events
	case EventFileDownloaded:
		return 5 // Normal priority
	case EventFileUploaded:
		return 7 // Higher priority for new uploads
	default:
		return 5
	}
}

// transformToNtfy transforms an event to ntfy.sh format
func transformToNtfy(event *Event) (string, error) {
	// ntfy uses HTTP headers for metadata, but we can send JSON payload
	// with title, message, tags, and priority fields
	payload := map[string]interface{}{
		"topic":    "safeshare", // Default topic, users should configure URL with their topic
		"title":    formatNtfyTitle(event),
		"message":  formatNtfyMessage(event),
		"tags":     getNtfyTags(event),
		"priority": getNtfyPriority(event),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal ntfy payload: %w", err)
	}

	return string(data), nil
}

// formatNtfyTitle creates a title for ntfy notifications
func formatNtfyTitle(event *Event) string {
	switch event.Type {
	case EventFileUploaded:
		return "File Uploaded"
	case EventFileDownloaded:
		return "File Downloaded"
	case EventFileDeleted:
		return "File Deleted"
	case EventFileExpired:
		return "File Expired"
	default:
		return "SafeShare Event"
	}
}

// formatNtfyMessage creates a message body for ntfy notifications
func formatNtfyMessage(event *Event) string {
	size := formatFileSize(event.File.Size)

	switch event.Type {
	case EventFileUploaded:
		return fmt.Sprintf("%s (%s)\nClaim: %s\nExpires: %s",
			event.File.Filename,
			size,
			event.File.ClaimCode,
			event.File.ExpiresAt.Format("2006-01-02 15:04"))
	case EventFileDownloaded:
		return fmt.Sprintf("%s (%s)\nClaim: %s",
			event.File.Filename,
			size,
			event.File.ClaimCode)
	case EventFileDeleted:
		reason := "Deleted"
		if event.File.Reason != nil {
			reason = *event.File.Reason
		}
		return fmt.Sprintf("%s (%s)\nClaim: %s\nReason: %s",
			event.File.Filename,
			size,
			event.File.ClaimCode,
			reason)
	case EventFileExpired:
		reason := "Time-based expiration"
		if event.File.Reason != nil {
			reason = *event.File.Reason
		}
		return fmt.Sprintf("%s (%s)\nClaim: %s\nReason: %s",
			event.File.Filename,
			size,
			event.File.ClaimCode,
			reason)
	default:
		return fmt.Sprintf("%s (%s)",
			event.File.Filename,
			size)
	}
}

// getNtfyTags returns emoji tags for ntfy notifications
func getNtfyTags(event *Event) []string {
	switch event.Type {
	case EventFileUploaded:
		return []string{"inbox"}
	case EventFileDownloaded:
		return []string{"white_check_mark"}
	case EventFileDeleted:
		return []string{"wastebasket"}
	case EventFileExpired:
		return []string{"hourglass"}
	default:
		return []string{"file_folder"}
	}
}

// getNtfyPriority returns priority level for ntfy (1-5)
func getNtfyPriority(event *Event) int {
	switch event.Type {
	case EventFileExpired, EventFileDeleted:
		return 2 // Low priority
	case EventFileDownloaded:
		return 3 // Default priority
	case EventFileUploaded:
		return 4 // High priority
	default:
		return 3
	}
}

// transformToDiscord transforms an event to Discord webhook format
func transformToDiscord(event *Event) (string, error) {
	// Discord webhook payload with embeds
	embed := map[string]interface{}{
		"title":       formatDiscordTitle(event),
		"description": formatDiscordDescription(event),
		"color":       getDiscordColor(event),
		"fields":      getDiscordFields(event),
		"timestamp":   event.Timestamp.Format(time.RFC3339),
		"footer": map[string]string{
			"text": "SafeShare",
		},
	}

	payload := map[string]interface{}{
		"embeds": []interface{}{embed},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Discord payload: %w", err)
	}

	return string(data), nil
}

// formatDiscordTitle creates a title for Discord embeds
func formatDiscordTitle(event *Event) string {
	switch event.Type {
	case EventFileUploaded:
		return "📤 File Uploaded"
	case EventFileDownloaded:
		return "📥 File Downloaded"
	case EventFileDeleted:
		return "🗑️ File Deleted"
	case EventFileExpired:
		return "⏰ File Expired"
	default:
		return "📁 SafeShare Event"
	}
}

// formatDiscordDescription creates a description for Discord embeds
func formatDiscordDescription(event *Event) string {
	size := formatFileSize(event.File.Size)
	return fmt.Sprintf("**%s** (%s)", event.File.Filename, size)
}

// getDiscordColor returns color code for Discord embeds (decimal)
func getDiscordColor(event *Event) int {
	switch event.Type {
	case EventFileUploaded:
		return 3066993 // Green
	case EventFileDownloaded:
		return 3447003 // Blue
	case EventFileDeleted:
		return 15158332 // Red
	case EventFileExpired:
		return 15844367 // Gold
	default:
		return 9807270 // Gray
	}
}

// getDiscordFields returns fields for Discord embeds
func getDiscordFields(event *Event) []map[string]interface{} {
	fields := []map[string]interface{}{
		{
			"name":   "Claim Code",
			"value":  fmt.Sprintf("`%s`", event.File.ClaimCode),
			"inline": true,
		},
	}

	switch event.Type {
	case EventFileUploaded:
		fields = append(fields, map[string]interface{}{
			"name":   "Expires",
			"value":  event.File.ExpiresAt.Format("2006-01-02 15:04 MST"),
			"inline": true,
		})
	case EventFileDownloaded:
		if event.File.DownloadedAt != nil {
			fields = append(fields, map[string]interface{}{
				"name":   "Downloaded",
				"value":  event.File.DownloadedAt.Format("2006-01-02 15:04 MST"),
				"inline": true,
			})
		}
	case EventFileDeleted, EventFileExpired:
		if event.File.Reason != nil {
			fields = append(fields, map[string]interface{}{
				"name":   "Reason",
				"value":  *event.File.Reason,
				"inline": false,
			})
		}
	}

	return fields
}

// formatFileSize formats file size in human-readable format
func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
