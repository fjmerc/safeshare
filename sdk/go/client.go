package safeshare

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Validation patterns
var (
	// Server uses base64 URL-safe encoding which includes - and _ characters
	claimCodePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,32}$`)
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

	proxy, err := proxyFunc(cfg)
	if err != nil {
		return nil, err
	}

	// Create HTTP client
	transport := &http.Transport{
		Proxy: proxy,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 30 * time.Second, // generous for Tor circuits
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	if cfg.InsecureSkipVerify {
		// Log warning about disabled TLS verification to stderr
		fmt.Fprintln(os.Stderr, "[SafeShare SDK] WARNING: TLS certificate verification is disabled. This is insecure.")
	}

	httpClient := &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: sameOriginRedirect,
	}

	return &Client{
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		apiToken:   cfg.APIToken,
		httpClient: httpClient,
	}, nil
}

// sameOriginRedirect follows redirects only within the same scheme and host.
// The API has no cross-origin redirects; following one could send the token
// or a file password elsewhere, downgrade https to http, or (for an http URL
// not covered by the proxy) connect directly and reveal a Tor user's address.
func sameOriginRedirect(r *http.Request, via []*http.Request) error {
	if r.URL.Scheme != via[0].URL.Scheme || r.URL.Host != via[0].URL.Host {
		return fmt.Errorf("refusing redirect to %s://%s", r.URL.Scheme, r.URL.Host)
	}
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	return nil
}

// proxyFunc picks the proxy for every request:
//   - ClientConfig.Proxy, if set, for all requests (no NO_PROXY or loopback
//     exceptions);
//   - otherwise, with DisableProxy, none;
//   - otherwise, a single proxy from the environment (ALL_PROXY alone, or only
//     one of HTTPS_PROXY/HTTP_PROXY) for all requests, so a Tor setup that
//     names one proxy can't be bypassed by an http:// URL;
//   - otherwise Go's usual per-scheme HTTPS_PROXY/HTTP_PROXY/NO_PROXY rules.
//
// A socks5:// proxy is handed host names unresolved, so DNS goes through it too.
func proxyFunc(cfg ClientConfig) (func(*http.Request) (*url.URL, error), error) {
	fixed := cfg.Proxy
	if fixed == "" {
		if cfg.DisableProxy {
			return nil, nil
		}
		httpsP, httpP, allP := envAny("HTTPS_PROXY", "https_proxy"), envAny("HTTP_PROXY", "http_proxy"), envAny("ALL_PROXY", "all_proxy")
		switch {
		case httpsP != "" && httpP != "":
			return http.ProxyFromEnvironment, nil
		case httpsP != "":
			fixed = httpsP
		case httpP != "":
			fixed = httpP
		default:
			fixed = allP
		}
		if fixed == "" {
			return nil, nil
		}
	}
	u, err := ParseProxyURL(fixed)
	if err != nil {
		return nil, err
	}
	return http.ProxyURL(u), nil
}

// ParseProxyURL parses a proxy URL (socks5://, socks5h:// or http(s)://).
// socks5h is accepted as socks5, which Go already resolves at the proxy.
func ParseProxyURL(s string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" {
		return nil, &ValidationError{Field: "Proxy", Message: "must be a URL such as socks5://127.0.0.1:9050"}
	}
	switch u.Scheme {
	case "socks5h":
		u.Scheme = "socks5"
	case "socks5", "http", "https":
	default:
		return nil, &ValidationError{Field: "Proxy", Message: "scheme must be socks5, socks5h, http or https"}
	}
	return u, nil
}

func envAny(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
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
			Message: "must be 8-32 alphanumeric characters (including - and _)",
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
	return c.requestWithPassword(ctx, method, path, body, contentType, "")
}

// requestWithPassword is request plus an optional file password, sent in the
// X-File-Password header. The password used to go in the query string, which
// the server deprecated because URLs end up in proxy logs and history.
//
// Unlike Authorization, Go's http.Client forwards custom headers on a
// redirect to another host, so password requests refuse cross-host redirects.
func (c *Client) requestWithPassword(ctx context.Context, method, path string, body io.Reader, contentType, password string) (*http.Response, error) {
	return c.doRequest(ctx, method, path, body, contentType, password, nil)
}

// doRequest is requestWithPassword plus extra request headers.
func (c *Client) doRequest(ctx context.Context, method, path string, body io.Reader, contentType, password string, extra http.Header) (*http.Response, error) {
	reqURL := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set headers
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if c.apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiToken)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	if password != "" {
		// Safe to send on redirects: sameOriginRedirect refuses other hosts
		// and schemes, which would otherwise receive this custom header.
		req.Header.Set("X-File-Password", password)
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
		// Try to decode error message and machine-readable code
		var errResp struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&errResp); err != nil {
			errResp.Error = resp.Status
		}
		apiErr := newAPIError(resp.StatusCode, errResp.Error, errResp.Code)
		// ADR-015: SCAN_PENDING/SCAN_UNAVAILABLE responses carry a
		// Retry-After header telling the caller how long to wait.
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if seconds, err := strconv.Atoi(ra); err == nil && seconds >= 0 {
				apiErr.RetryAfter = time.Duration(seconds) * time.Second
			}
		}
		return apiErr
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
		MaxFileSize:              apiResp.MaxFileSize,
		ChunkUploadThreshold:     apiResp.ChunkUploadThreshold,
		ChunkSize:                apiResp.ChunkSize,
		MaxExpirationHours:       apiResp.MaxExpirationHours,
		RegistrationEnabled:      apiResp.RegistrationEnabled,
		AnonymousMode:            apiResp.AnonymousMode,
		ClientEncryptionRequired: apiResp.ClientEncryptionRequired,
		StripMetadata:            apiResp.StripMetadata,
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

// parseTimeNonPointer parses a non-pointer string and returns a pointer to time.
// Used when the API returns a non-optional time string but we want a pointer.
func parseTimeNonPointer(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}
