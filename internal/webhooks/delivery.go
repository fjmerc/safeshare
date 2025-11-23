package webhooks

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
	"unicode"
)

var (
	httpClientOnce sync.Once
	httpClient     *http.Client
)

// getHTTPClient returns a reusable HTTP client with connection pooling
func getHTTPClient(timeoutSeconds int) *http.Client {
	httpClientOnce.Do(func() {
		httpClient = &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
				DisableKeepAlives:   false,
			},
		}
	})
	
	// Update timeout if different from current
	httpClient.Timeout = time.Duration(timeoutSeconds) * time.Second
	
	return httpClient
}

// DeliveryResult represents the result of a webhook delivery attempt
type DeliveryResult struct {
	Success      bool
	ResponseCode int
	ResponseBody string
	Error        error
}

// ComputeHMACSignature computes HMAC-SHA256 signature for a payload
func ComputeHMACSignature(payload, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// DeliverWebhook delivers a webhook to the specified URL with HMAC signature
func DeliverWebhook(url, secret, payload string, timeoutSeconds int) DeliveryResult {
	return DeliverWebhookWithConfig(nil, url, secret, payload, timeoutSeconds)
}

// DeliverWebhookWithConfig delivers a webhook with full config support (including service tokens)
func DeliverWebhookWithConfig(config *Config, url, secret, payload string, timeoutSeconds int) DeliveryResult {
	// Construct final URL based on config format (for Gotify token injection)
	finalURL := url
	if config != nil && config.ServiceToken != "" {
		finalURL = constructURLWithToken(url, config.ServiceToken, config.Format)
	}

	// Compute HMAC signature
	signature := ComputeHMACSignature(payload, secret)

	// Use shared HTTP client with connection pooling
	client := getHTTPClient(timeoutSeconds)

	// Create request
	req, err := http.NewRequest("POST", finalURL, bytes.NewBufferString(payload))
	if err != nil {
		slog.Error("failed to create webhook request", "url", url, "error", err)
		return DeliveryResult{
			Success: false,
			Error:   fmt.Errorf("failed to create request: %w", err),
		}
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SafeShare-Webhook/1.0")
	req.Header.Set("X-SafeShare-Signature", signature)
	req.Header.Set("X-SafeShare-Signature-Algorithm", "sha256")

	// Add service-specific auth headers (for ntfy)
	if config != nil && config.ServiceToken != "" {
		addAuthHeaders(req, config.ServiceToken, config.Format)
	}

	// Send request
	startTime := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		slog.Error("webhook delivery failed", "url", url, "duration", duration, "error", err)
		return DeliveryResult{
			Success: false,
			Error:   fmt.Errorf("request failed: %w", err),
		}
	}
	defer resp.Body.Close()

	// Read response body (limit to 10KB for logging, 1KB for storage)
	const maxStoredResponseSize = 1024      // 1KB stored in DB
	const maxLoggedResponseSize = 10 * 1024 // 10KB for logs
	
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxLoggedResponseSize))
	responseBody := string(bodyBytes)
	if err != nil {
		slog.Warn("failed to read webhook response body", "url", url, "error", err)
		responseBody = fmt.Sprintf("failed to read response: %v", err)
	}
	
	// Truncate for database storage to prevent bloat
	storedResponseBody := responseBody
	if len(storedResponseBody) > maxStoredResponseSize {
		storedResponseBody = storedResponseBody[:maxStoredResponseSize] + "... (truncated)"
	}

	// Check if successful (2xx status codes)
	success := resp.StatusCode >= 200 && resp.StatusCode < 300

	if success {
		slog.Info("webhook delivered successfully", 
			"url", url, 
			"status_code", resp.StatusCode, 
			"duration", duration)
	} else {
		slog.Warn("webhook delivery received non-2xx status", 
			"url", url, 
			"status_code", resp.StatusCode, 
			"duration", duration,
			"response_body", responseBody)
	}

	return DeliveryResult{
		Success:      success,
		ResponseCode: resp.StatusCode,
		ResponseBody: storedResponseBody, // Use truncated version
		Error:        nil,
	}
}

// CalculateRetryDelay calculates the delay before next retry using exponential backoff
func CalculateRetryDelay(attemptCount int) time.Duration {
	// Validate input to prevent overflow
	if attemptCount < 0 {
		return 1 * time.Second // Default to minimum delay
	}
	
	// Cap attempt count to prevent overflow
	// 1<<30 = 1073741824 seconds = ~34 years (safe on 32-bit and 64-bit)
	if attemptCount > 30 {
		attemptCount = 30
	}
	
	// Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, ...
	delay := time.Second * time.Duration(1<<uint(attemptCount))
	
	// Cap at 60 seconds maximum
	if delay > 60*time.Second {
		delay = 60 * time.Second
	}
	
	return delay
}

// ShouldRetry determines if a delivery should be retried based on attempt count and max retries
func ShouldRetry(attemptCount, maxRetries int) bool {
	return attemptCount < maxRetries
}

// constructURLWithToken constructs the final webhook URL with service token based on format
func constructURLWithToken(baseURL, token string, format WebhookFormat) string {
	switch format {
	case FormatGotify:
		// Gotify: Append token as query parameter with proper URL encoding
		parsedURL, err := url.Parse(baseURL)
		if err != nil {
			// Return original URL on parse error (will fail later in request)
			slog.Error("failed to parse webhook URL for token injection", "url", baseURL, "error", err)
			return baseURL
		}
		
		// Use url.Values for proper encoding (prevents injection)
		query := parsedURL.Query()
		query.Set("token", token) // Properly encodes special characters
		parsedURL.RawQuery = query.Encode()
		
		return parsedURL.String()
	case FormatNtfy, FormatDiscord, FormatSafeShare:
		// No URL modification needed for these formats
		return baseURL
	default:
		return baseURL
	}
}

// validateToken checks if token contains forbidden control characters
func validateToken(token string) bool {
	// Reject tokens with control characters (newlines, carriage returns, etc.)
	for _, r := range token {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// addAuthHeaders adds service-specific authentication headers based on format
func addAuthHeaders(req *http.Request, token string, format WebhookFormat) {
	switch format {
	case FormatNtfy:
		// Validate token before use (prevents header injection)
		if !validateToken(token) {
			slog.Error("invalid service token contains control characters",
				"format", format)
			return // Don't set header with invalid token
		}
		// ntfy: Add Authorization Bearer header
		req.Header.Set("Authorization", "Bearer "+token)
	case FormatGotify, FormatDiscord, FormatSafeShare:
		// No auth headers needed for these formats
		// Gotify uses URL query param (handled in constructURLWithToken)
		// Discord token is in webhook URL itself
		// SafeShare uses HMAC signature only
	}
}
