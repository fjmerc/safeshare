// Package sdk_contract provides integration tests that validate the Go SDK
// can correctly parse responses from the actual server handlers.
//
// PURPOSE: These tests catch SDK/Server API contract mismatches that unit tests miss.
//
// HOW IT WORKS:
//  1. Creates a real HTTP test server with actual SafeShare handlers
//  2. Uses the real Go SDK client to make requests
//  3. Verifies SDK types correctly parse server responses
//
// WHAT THIS CATCHES:
//   - JSON field name mismatches (e.g., server sends "original_filename", SDK expects "filename")
//   - Type mismatches (e.g., server sends int, SDK expects string)
//   - Missing fields that SDK requires
//   - Response structure changes that break SDK parsing
//
// WHY THIS EXISTS:
// Unit tests for SDK mock server responses based on what SDK *expects*.
// Unit tests for server verify server behavior in isolation.
// Neither catches when the two don't match. These contract tests do.
package sdk_contract

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	safeshare "github.com/fjmerc/safeshare/sdk/go"

	"github.com/fjmerc/safeshare/internal/handlers"
	"github.com/fjmerc/safeshare/internal/testutil"
)

// setupTestServer creates an httptest.Server with real SafeShare handlers.
// This allows the SDK to make actual HTTP requests against real server code.
func setupTestServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()

	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	mux := http.NewServeMux()

	// Upload endpoint
	mux.HandleFunc("/api/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handlers.UploadHandler(db, cfg).ServeHTTP(w, r)
	})

	// Claim info endpoint (GET /api/claim/{code}/info)
	mux.HandleFunc("/api/claim/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "/info") && r.Method == http.MethodGet {
			handlers.ClaimInfoHandler(db, cfg).ServeHTTP(w, r)
		} else if r.Method == http.MethodGet {
			handlers.ClaimHandler(db, cfg).ServeHTTP(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	server := httptest.NewServer(mux)

	cleanup := func() {
		server.Close()
	}

	return server, cleanup
}

// createSDKClient creates an SDK client pointing at the test server.
func createSDKClient(t *testing.T, serverURL string) *safeshare.Client {
	t.Helper()

	client, err := safeshare.NewClient(safeshare.ClientConfig{
		BaseURL: serverURL,
	})
	if err != nil {
		t.Fatalf("Failed to create SDK client: %v", err)
	}
	return client
}

// uploadTestFile uploads a file directly via HTTP (not SDK) to isolate test setup
// from the SDK functionality being tested.
func uploadTestFile(t *testing.T, serverURL string, filename string, content []byte, options map[string]string) string {
	t.Helper()

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add file
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("failed to write file content: %v", err)
	}

	// Add options
	for key, value := range options {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("failed to write field %s: %v", key, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close multipart writer: %v", err)
	}

	// Make request
	resp, err := http.Post(serverURL+"/api/upload", writer.FormDataContentType(), &buf)
	if err != nil {
		t.Fatalf("upload request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("upload failed: status=%d, body=%s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode upload response: %v", err)
	}

	claimCode, ok := result["claim_code"].(string)
	if !ok || claimCode == "" {
		t.Fatalf("upload response missing claim_code: %v", result)
	}

	return claimCode
}

// TestGetFileInfoContract validates that the SDK's GetFileInfo method
// correctly parses the server's ClaimInfoHandler response.
//
// This test would have caught the bug where:
//   - Server returns: original_filename, file_size, password_required
//   - SDK expected: filename, size, password_protected
func TestGetFileInfoContract(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Upload a test file with specific options
	testContent := []byte("Contract test file content for GetFileInfo validation")
	claimCode := uploadTestFile(t, server.URL, "contract_test.txt", testContent, map[string]string{
		"expires_in_hours": "24",
		"max_downloads":    "5",
	})

	// Create SDK client pointing at test server
	client := createSDKClient(t, server.URL)

	// Use SDK to get file info (requires context as first argument)
	ctx := context.Background()
	info, err := client.GetFileInfo(ctx, claimCode)
	if err != nil {
		t.Fatalf("SDK GetFileInfo failed: %v", err)
	}

	// Validate all fields are correctly parsed
	t.Run("Filename", func(t *testing.T) {
		if info.Filename != "contract_test.txt" {
			t.Errorf("Filename = %q, want %q", info.Filename, "contract_test.txt")
		}
	})

	t.Run("Size", func(t *testing.T) {
		expectedSize := int64(len(testContent))
		if info.Size != expectedSize {
			t.Errorf("Size = %d, want %d", info.Size, expectedSize)
		}
	})

	t.Run("MimeType", func(t *testing.T) {
		if info.MimeType == "" {
			t.Error("MimeType should not be empty")
		}
	})

	t.Run("PasswordProtected", func(t *testing.T) {
		// File was uploaded without password
		if info.PasswordProtected {
			t.Error("PasswordProtected = true, want false (no password set)")
		}
	})

	t.Run("DownloadsRemaining", func(t *testing.T) {
		// max_downloads=5, download_count=0, so remaining=5
		if info.DownloadsRemaining == nil {
			t.Fatal("DownloadsRemaining should not be nil when max_downloads is set")
		}
		if *info.DownloadsRemaining != 5 {
			t.Errorf("DownloadsRemaining = %d, want 5", *info.DownloadsRemaining)
		}
	})

	t.Run("ExpiresAt", func(t *testing.T) {
		if info.ExpiresAt == nil {
			t.Error("ExpiresAt should not be nil when expires_in_hours is set")
		}
	})
}

// TestGetFileInfoWithPasswordContract validates password-protected file info parsing.
func TestGetFileInfoWithPasswordContract(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Upload a password-protected file
	testContent := []byte("Password protected content")
	claimCode := uploadTestFile(t, server.URL, "secret.txt", testContent, map[string]string{
		"password": "secretpass123",
	})

	client := createSDKClient(t, server.URL)
	ctx := context.Background()

	info, err := client.GetFileInfo(ctx, claimCode)
	if err != nil {
		t.Fatalf("SDK GetFileInfo failed: %v", err)
	}

	// Validate password_protected is correctly parsed
	if !info.PasswordProtected {
		t.Error("PasswordProtected = false, want true (password was set)")
	}
}

// TestGetFileInfoNoLimitsContract validates files without download limits.
func TestGetFileInfoNoLimitsContract(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Upload without max_downloads
	testContent := []byte("Unlimited downloads file")
	claimCode := uploadTestFile(t, server.URL, "unlimited.txt", testContent, nil)

	client := createSDKClient(t, server.URL)
	ctx := context.Background()

	info, err := client.GetFileInfo(ctx, claimCode)
	if err != nil {
		t.Fatalf("SDK GetFileInfo failed: %v", err)
	}

	// DownloadsRemaining should be nil when no limit is set
	if info.DownloadsRemaining != nil {
		t.Errorf("DownloadsRemaining = %d, want nil (no limit set)", *info.DownloadsRemaining)
	}
}

// TestDownloadContract validates the SDK can download files from the server.
func TestDownloadContract(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Upload a test file
	testContent := []byte("Download contract test content - verify bytes match exactly")
	claimCode := uploadTestFile(t, server.URL, "download_test.txt", testContent, nil)

	client := createSDKClient(t, server.URL)
	ctx := context.Background()

	// Download using SDK's DownloadToWriter method
	var buf bytes.Buffer
	err := client.DownloadToWriter(ctx, claimCode, &buf, nil)
	if err != nil {
		t.Fatalf("SDK DownloadToWriter failed: %v", err)
	}

	// Verify content matches
	downloaded := buf.Bytes()
	if !bytes.Equal(downloaded, testContent) {
		t.Errorf("Downloaded content doesn't match.\nGot: %q\nWant: %q", downloaded, testContent)
	}
}

// TestDownloadWithPasswordContract validates password-protected downloads.
func TestDownloadWithPasswordContract(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	testContent := []byte("Secret download content")
	password := "mysecretpass"
	claimCode := uploadTestFile(t, server.URL, "secret_download.txt", testContent, map[string]string{
		"password": password,
	})

	client := createSDKClient(t, server.URL)
	ctx := context.Background()

	// Download without password should fail
	var buf1 bytes.Buffer
	err := client.DownloadToWriter(ctx, claimCode, &buf1, nil)
	if err == nil {
		t.Error("Expected error when downloading password-protected file without password")
	}

	// Download with correct password should succeed
	var buf2 bytes.Buffer
	err = client.DownloadToWriter(ctx, claimCode, &buf2, &safeshare.DownloadOptions{
		Password: password,
	})
	if err != nil {
		t.Fatalf("SDK DownloadToWriter with password failed: %v", err)
	}

	downloaded := buf2.Bytes()
	if !bytes.Equal(downloaded, testContent) {
		t.Error("Downloaded content doesn't match with correct password")
	}
}

// TestUploadResponseContract validates the upload response structure.
// While we upload via HTTP helper, this tests the response format SDK would receive.
func TestUploadResponseContract(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", "upload_response_test.txt")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	if _, err := part.Write([]byte("Test content")); err != nil {
		t.Fatalf("failed to write content: %v", err)
	}
	if err := writer.WriteField("expires_in_hours", "48"); err != nil {
		t.Fatalf("failed to write field: %v", err)
	}
	if err := writer.WriteField("max_downloads", "10"); err != nil {
		t.Fatalf("failed to write field: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	resp, err := http.Post(server.URL+"/api/upload", writer.FormDataContentType(), &buf)
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Validate required fields exist
	requiredFields := []string{"claim_code", "download_url", "expires_at"}
	for _, field := range requiredFields {
		if _, ok := result[field]; !ok {
			t.Errorf("Upload response missing required field: %s", field)
		}
	}

	// Validate claim_code format
	claimCode, _ := result["claim_code"].(string)
	if len(claimCode) < 8 {
		t.Errorf("claim_code too short: %q", claimCode)
	}
}

// TestGetFileInfoAfterDownloadContract validates that downloads_remaining
// is correctly calculated after downloads occur.
func TestGetFileInfoAfterDownloadContract(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Upload with max_downloads=3
	testContent := []byte("Limited download content")
	claimCode := uploadTestFile(t, server.URL, "limited.txt", testContent, map[string]string{
		"max_downloads": "3",
	})

	client := createSDKClient(t, server.URL)
	ctx := context.Background()

	// Check initial state
	info, err := client.GetFileInfo(ctx, claimCode)
	if err != nil {
		t.Fatalf("GetFileInfo failed: %v", err)
	}
	if info.DownloadsRemaining == nil || *info.DownloadsRemaining != 3 {
		t.Errorf("Initial DownloadsRemaining = %v, want 3", info.DownloadsRemaining)
	}

	// Download once
	var buf bytes.Buffer
	if err := client.DownloadToWriter(ctx, claimCode, &buf, nil); err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	// Check after download
	info, err = client.GetFileInfo(ctx, claimCode)
	if err != nil {
		t.Fatalf("GetFileInfo after download failed: %v", err)
	}
	if info.DownloadsRemaining == nil || *info.DownloadsRemaining != 2 {
		t.Errorf("After 1 download, DownloadsRemaining = %v, want 2", info.DownloadsRemaining)
	}
}
