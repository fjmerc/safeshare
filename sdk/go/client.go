package safeshare

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Validation patterns
var (
	claimCodePattern = regexp.MustCompile(`^[a-zA-Z0-9]{8,32}$`)
	uploadIDPattern  = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
)

// Pagination limits
const (
	maxPerPage = 100
	minPage    = 1
	minPerPage = 1
)

// Client is the SafeShare API client.
type Client struct {
	baseURL     string
	apiToken    string
	httpClient  *http.Client
	configCache *PublicConfig
}

// NewClient creates a new SafeShare client with the given configuration.
//
// Example:
//
//	client, err := safeshare.NewClient(safeshare.ClientConfig{
//	    BaseURL:  "https://share.example.com",
//	    APIToken: "safeshare_abc123...",
//	})
func NewClient(cfg ClientConfig) (*Client, error) {
	// Validate base URL
	if cfg.BaseURL == "" {
		return nil, &ValidationError{Field: "BaseURL", Message: "is required"}
	}

	parsedURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, &ValidationError{Field: "BaseURL", Message: "must be a valid URL"}
	}

	// Validate URL scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, &ValidationError{Field: "BaseURL", Message: "must use http or https protocol"}
	}

	// Validate URL has a host
	if parsedURL.Host == "" {
		return nil, &ValidationError{Field: "BaseURL", Message: "must include a host"}
	}

	// Set default timeout
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	if cfg.InsecureSkipVerify {
		// Log warning about disabled TLS verification to stderr
		fmt.Fprintln(os.Stderr, "[SafeShare SDK] WARNING: TLS certificate verification is disabled. This is insecure.")
	}

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	return &Client{
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		apiToken:   cfg.APIToken,
		httpClient: httpClient,
	}, nil
}

// String returns a string representation with the API token redacted.
func (c *Client) String() string {
	tokenDisplay := "none"
	if c.apiToken != "" {
		tokenDisplay = "***redacted***"
	}
	return fmt.Sprintf("SafeShareClient(baseURL=%q, apiToken=%s)", c.baseURL, tokenDisplay)
}

// BaseURL returns the configured base URL.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// validateClaimCode validates a claim code format.
func validateClaimCode(code string) error {
	if code == "" || !claimCodePattern.MatchString(code) {
		return &ValidationError{
			Field:   "claimCode",
			Message: "must be 8-32 alphanumeric characters",
		}
	}
	return nil
}

// validateUploadID validates an upload ID format (UUID v4).
func validateUploadID(id string) error {
	if id == "" || !uploadIDPattern.MatchString(id) {
		return &ValidationError{
			Field:   "uploadID",
			Message: "must be a valid UUID",
		}
	}
	return nil
}

// validateFilename validates a filename.
func validateFilename(name string) error {
	if name == "" {
		return &ValidationError{Field: "filename", Message: "cannot be empty"}
	}
	if len(name) > 255 {
		return &ValidationError{Field: "filename", Message: "cannot exceed 255 characters"}
	}
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return &ValidationError{Field: "filename", Message: "cannot contain path components"}
	}
	return nil
}

// validatePagination validates pagination parameters.
func validatePagination(page, perPage int) error {
	if page < minPage {
		return &ValidationError{Field: "page", Message: "must be a positive integer"}
	}
	if perPage < minPerPage || perPage > maxPerPage {
		return &ValidationError{
			Field:   "perPage",
			Message: fmt.Sprintf("must be between %d and %d", minPerPage, maxPerPage),
		}
	}
	return nil
}

// validateTokenID validates a token ID.
func validateTokenID(id int) error {
	if id < 1 {
		return &ValidationError{Field: "tokenID", Message: "must be a positive integer"}
	}
	return nil
}

// request makes an HTTP request to the API.
func (c *Client) request(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	reqURL := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set headers
	if c.apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiToken)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}

	return resp, nil
}

// handleResponse checks for errors and decodes JSON response.
func handleResponse(resp *http.Response, target interface{}) error {
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// Try to decode error message
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			errResp.Error = resp.Status
		}
		return newAPIError(resp.StatusCode, errResp.Error)
	}

	if target != nil {
		if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}

// GetConfig retrieves the server's public configuration.
// The result is cached after the first call.
func (c *Client) GetConfig(ctx context.Context) (*PublicConfig, error) {
	if c.configCache != nil {
		return c.configCache, nil
	}

	resp, err := c.request(ctx, http.MethodGet, "/api/config", nil, "")
	if err != nil {
		return nil, err
	}

	var apiResp apiConfigResponse
	if err := handleResponse(resp, &apiResp); err != nil {
		return nil, err
	}

	c.configCache = &PublicConfig{
		MaxFileSize:          apiResp.MaxFileSize,
		ChunkUploadThreshold: apiResp.ChunkUploadThreshold,
		ChunkSize:            apiResp.ChunkSize,
		MaxExpirationHours:   apiResp.MaxExpirationHours,
		RegistrationEnabled:  apiResp.RegistrationEnabled,
	}

	return c.configCache, nil
}

// parseTime parses an ISO 8601 time string.
func parseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	return &t
}

// parseTimeRequired parses a required ISO 8601 time string.
func parseTimeRequired(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}
