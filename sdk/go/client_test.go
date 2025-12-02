package safeshare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ClientConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid HTTPS URL",
			cfg: ClientConfig{
				BaseURL: "https://share.example.com",
			},
			wantErr: false,
		},
		{
			name: "valid HTTP URL",
			cfg: ClientConfig{
				BaseURL: "http://localhost:8080",
			},
			wantErr: false,
		},
		{
			name: "valid URL with trailing slash",
			cfg: ClientConfig{
				BaseURL: "https://share.example.com/",
			},
			wantErr: false,
		},
		{
			name:    "empty URL",
			cfg:     ClientConfig{},
			wantErr: true,
			errMsg:  "BaseURL",
		},
		{
			name: "invalid URL - no scheme",
			cfg: ClientConfig{
				BaseURL: "not-a-url",
			},
			wantErr: true,
			errMsg:  "http or https",
		},
		{
			name: "invalid protocol",
			cfg: ClientConfig{
				BaseURL: "ftp://share.example.com",
			},
			wantErr: true,
			errMsg:  "http or https",
		},
		{
			name: "missing host",
			cfg: ClientConfig{
				BaseURL: "http://",
			},
			wantErr: true,
			errMsg:  "host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.cfg)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errMsg != "" && !containsAny(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if client == nil {
					t.Error("expected client but got nil")
				}
			}
		})
	}
}

func TestClientString(t *testing.T) {
	tests := []struct {
		name      string
		apiToken  string
		wantToken string
	}{
		{
			name:      "with token",
			apiToken:  "safeshare_secret123",
			wantToken: "***redacted***",
		},
		{
			name:      "without token",
			apiToken:  "",
			wantToken: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := NewClient(ClientConfig{
				BaseURL:  "https://share.example.com",
				APIToken: tt.apiToken,
			})

			str := client.String()
			if tt.apiToken != "" && containsAny(str, tt.apiToken) {
				t.Error("token should be redacted")
			}
			if !containsAny(str, tt.wantToken) {
				t.Errorf("string %q should contain %q", str, tt.wantToken)
			}
		})
	}
}

func TestValidateClaimCode(t *testing.T) {
	tests := []struct {
		code    string
		wantErr bool
	}{
		{"abc12345", false},
		{"ABCD1234EFGH5678", false},
		{"a1234567890123456789012345678901", false}, // 32 chars
		{"ab", true},                                // too short
		{"", true},                                  // empty
		{"abc!@#$", true},                           // invalid chars
		{"abc/def", true},                           // path separator
		{"a1234567890123456789012345678901X", true}, // 33 chars, too long
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			err := validateClaimCode(tt.code)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateClaimCode(%q) error = %v, wantErr %v", tt.code, err, tt.wantErr)
			}
		})
	}
}

func TestValidateUploadID(t *testing.T) {
	tests := []struct {
		id      string
		wantErr bool
	}{
		{"12345678-1234-1234-1234-123456789012", false}, // valid UUID
		{"abcdef12-3456-7890-abcd-ef1234567890", false}, // valid UUID lowercase
		{"", true},                                     // empty
		{"not-a-uuid", true},                           // invalid format
		{"12345678-1234-1234-1234", true},              // incomplete
		{"------------------------------------", true}, // all dashes
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			err := validateUploadID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUploadID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestValidateFilename(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"file.txt", false},
		{"my-document.pdf", false},
		{"image_2024.png", false},
		{"", true},               // empty
		{"../etc/passwd", true},  // path traversal
		{"file/name.txt", true},  // forward slash
		{"file\\name.txt", true}, // backslash
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFilename(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFilename(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePagination(t *testing.T) {
	tests := []struct {
		page    int
		perPage int
		wantErr bool
	}{
		{1, 20, false},
		{1, 1, false},
		{1, 100, false},
		{10, 50, false},
		{0, 20, true},  // page < 1
		{-1, 20, true}, // negative page
		{1, 0, true},   // perPage < 1
		{1, -1, true},  // negative perPage
		{1, 101, true}, // perPage > 100
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			err := validatePagination(tt.page, tt.perPage)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePagination(%d, %d) error = %v, wantErr %v", tt.page, tt.perPage, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTokenID(t *testing.T) {
	tests := []struct {
		id      int
		wantErr bool
	}{
		{1, false},
		{100, false},
		{0, true},
		{-1, true},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			err := validateTokenID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTokenID(%d) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestGetConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/config" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		resp := apiConfigResponse{
			MaxFileSize:          1073741824,
			ChunkUploadThreshold: 104857600,
			ChunkSize:            5242880,
			MaxExpirationHours:   8760,
			RegistrationEnabled:  true,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient error: %v", err)
	}

	ctx := context.Background()
	config, err := client.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig error: %v", err)
	}

	if config.MaxFileSize != 1073741824 {
		t.Errorf("MaxFileSize = %d, want 1073741824", config.MaxFileSize)
	}
	if config.ChunkUploadThreshold != 104857600 {
		t.Errorf("ChunkUploadThreshold = %d, want 104857600", config.ChunkUploadThreshold)
	}
	if !config.RegistrationEnabled {
		t.Error("RegistrationEnabled should be true")
	}

	// Test caching
	config2, err := client.GetConfig(ctx)
	if err != nil {
		t.Fatalf("second GetConfig error: %v", err)
	}
	if config != config2 {
		t.Error("config should be cached")
	}
}

func TestGetFileInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/claim/abc12345/info" {
			http.NotFound(w, r)
			return
		}

		// Mock server response matching actual server field names
		resp := apiFileInfoResponse{
			ClaimCode:         "abc12345",
			Filename:          "test.txt",
			Size:              1024,
			MimeType:          "text/plain",
			PasswordProtected: false,
			MaxDownloads:      intPtr(10),  // max_downloads from server
			DownloadCount:     5,           // download_count from server
			// SDK calculates DownloadsRemaining = MaxDownloads - DownloadCount = 5
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, _ := NewClient(ClientConfig{BaseURL: server.URL})

	ctx := context.Background()
	info, err := client.GetFileInfo(ctx, "abc12345")
	if err != nil {
		t.Fatalf("GetFileInfo error: %v", err)
	}

	if info.Filename != "test.txt" {
		t.Errorf("Filename = %q, want %q", info.Filename, "test.txt")
	}
	if info.Size != 1024 {
		t.Errorf("Size = %d, want 1024", info.Size)
	}
	// DownloadsRemaining should be MaxDownloads - DownloadCount = 10 - 5 = 5
	if info.DownloadsRemaining == nil || *info.DownloadsRemaining != 5 {
		t.Errorf("DownloadsRemaining = %v, want 5", info.DownloadsRemaining)
	}
}

func TestGetFileInfo_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "File not found"})
	}))
	defer server.Close()

	client, _ := NewClient(ClientConfig{BaseURL: server.URL})

	ctx := context.Background()
	_, err := client.GetFileInfo(ctx, "notfound1234")
	if err == nil {
		t.Fatal("expected error")
	}

	if !errors.Is(err, ErrNotFound) {
		t.Errorf("error should be ErrNotFound, got %v", err)
	}
}

func TestErrorSanitization(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Invalid token", "request failed"},
		{"Invalid password", "request failed"},
		{"Secret key missing", "request failed"},
		{"Authorization failed", "request failed"},
		{"File not found", "File not found"}, // Should not be sanitized
		{"Upload failed", "Upload failed"},   // Should not be sanitized
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeErrorMessage(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeErrorMessage(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestAPIError(t *testing.T) {
	err := newAPIError(401, "Authentication required")

	if !errors.Is(err, ErrAuthentication) {
		t.Errorf("401 error should wrap ErrAuthentication")
	}

	if err.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", err.StatusCode)
	}
}

func TestValidationError(t *testing.T) {
	err := &ValidationError{Field: "claimCode", Message: "must be 8-32 characters"}

	if !errors.Is(err, ErrValidation) {
		t.Error("ValidationError should wrap ErrValidation")
	}

	errStr := err.Error()
	if !containsAny(errStr, "claimCode") {
		t.Errorf("error string should contain field name: %s", errStr)
	}
}

func intPtr(i int) *int {
	return &i
}
