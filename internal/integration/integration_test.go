package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/handlers"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// TestUploadDownloadWorkflow tests the complete file upload and download lifecycle.
//
// This integration test verifies:
//  1. Client uploads a file with options (expiration: 24h, max_downloads: 3)
//  2. Server stores file and returns claim code with download URL
//  3. Client downloads file using claim code
//  4. Downloaded content matches uploaded content
//  5. Download count increments correctly in database
//
// This test exercises the core file-sharing workflow that users experience
// and validates end-to-end functionality including database, filesystem,
// and HTTP handlers.
func TestUploadDownloadWorkflow(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Step 1: Upload a file
	fileContent := []byte("This is a test file for integration testing.")
	filename := "integration_test.txt"

	uploadHandler := handlers.UploadHandler(repos, cfg)

	body, contentType := testutil.CreateMultipartForm(t, fileContent, filename, map[string]string{
		"expires_in_hours": "24",
		"max_downloads":    "3",
	})

	uploadReq := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	uploadReq.Header.Set("Content-Type", contentType)
	uploadRR := httptest.NewRecorder()

	uploadHandler.ServeHTTP(uploadRR, uploadReq)

	if uploadRR.Code != http.StatusCreated {
		t.Fatalf("upload failed: status = %d, want %d (Created)", uploadRR.Code, http.StatusCreated)
	}

	var uploadResp map[string]interface{}
	json.NewDecoder(uploadRR.Body).Decode(&uploadResp)

	claimCode := uploadResp["claim_code"].(string)
	if claimCode == "" {
		t.Fatal("claim_code should not be empty")
	}

	t.Logf("File uploaded successfully, claim_code: %s", claimCode)

	// Step 2: Download the file
	downloadHandler := handlers.ClaimHandler(repos, cfg)

	downloadReq := httptest.NewRequest(http.MethodGet, "/api/claim/"+claimCode, nil)
	downloadRR := httptest.NewRecorder()

	downloadHandler.ServeHTTP(downloadRR, downloadReq)

	if downloadRR.Code != http.StatusOK {
		t.Fatalf("download failed: status = %d, want %d", downloadRR.Code, http.StatusOK)
	}

	// Step 3: Verify downloaded content matches uploaded content
	downloadedContent := downloadRR.Body.Bytes()
	if !bytes.Equal(downloadedContent, fileContent) {
		t.Errorf("downloaded content doesn't match uploaded content")
	}

	// Step 4: Verify filename in Content-Disposition header
	contentDisposition := downloadRR.Header().Get("Content-Disposition")
	if contentDisposition == "" {
		t.Error("Content-Disposition header not set")
	}

	// Step 5: Verify download count increased
	file, _ := repos.Files.GetByClaimCode(ctx, claimCode)
	if file.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1", file.DownloadCount)
	}

	t.Log("Download workflow completed successfully")
}

// TestUploadDownloadWithPassword tests upload/download with password protection
func TestUploadDownloadWithPassword(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	fileContent := []byte("Secret content")
	password := "supersecret123"

	// Upload with password
	uploadHandler := handlers.UploadHandler(repos, cfg)

	body, contentType := testutil.CreateMultipartForm(t, fileContent, "secret.txt", map[string]string{
		"password": password,
	})

	uploadReq := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	uploadReq.Header.Set("Content-Type", contentType)
	uploadRR := httptest.NewRecorder()

	uploadHandler.ServeHTTP(uploadRR, uploadReq)

	var uploadResp map[string]interface{}
	json.NewDecoder(uploadRR.Body).Decode(&uploadResp)
	claimCode := uploadResp["claim_code"].(string)

	// Try download without password - should fail
	downloadHandler := handlers.ClaimHandler(repos, cfg)

	downloadReq1 := httptest.NewRequest(http.MethodGet, "/api/claim/"+claimCode, nil)
	downloadRR1 := httptest.NewRecorder()

	downloadHandler.ServeHTTP(downloadRR1, downloadReq1)

	// Should return 401 Unauthorized when no password is provided for password-protected file
	if downloadRR1.Code != http.StatusUnauthorized {
		t.Errorf("no password: status = %d, want %d", downloadRR1.Code, http.StatusUnauthorized)
	}

	// Try download with wrong password - should fail
	downloadReq2 := httptest.NewRequest(http.MethodGet, "/api/claim/"+claimCode+"?password=wrongpassword", nil)
	downloadRR2 := httptest.NewRecorder()

	downloadHandler.ServeHTTP(downloadRR2, downloadReq2)

	if downloadRR2.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: status = %d, want %d", downloadRR2.Code, http.StatusUnauthorized)
	}

	// Try download with correct password - should succeed
	downloadReq3 := httptest.NewRequest(http.MethodGet, "/api/claim/"+claimCode+"?password="+password, nil)
	downloadRR3 := httptest.NewRecorder()

	downloadHandler.ServeHTTP(downloadRR3, downloadReq3)

	if downloadRR3.Code != http.StatusOK {
		t.Errorf("correct password: status = %d, want %d", downloadRR3.Code, http.StatusOK)
	}

	// Verify content
	if !bytes.Equal(downloadRR3.Body.Bytes(), fileContent) {
		t.Error("downloaded content doesn't match")
	}

	t.Log("Password-protected download workflow completed successfully")
}

// TestDownloadLimit tests max_downloads enforcement
func TestDownloadLimit(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	fileContent := []byte("Limited download file")

	// Upload with max_downloads=2
	uploadHandler := handlers.UploadHandler(repos, cfg)

	body, contentType := testutil.CreateMultipartForm(t, fileContent, "limited.txt", map[string]string{
		"max_downloads": "2",
	})

	uploadReq := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	uploadReq.Header.Set("Content-Type", contentType)
	uploadRR := httptest.NewRecorder()

	uploadHandler.ServeHTTP(uploadRR, uploadReq)

	var uploadResp map[string]interface{}
	json.NewDecoder(uploadRR.Body).Decode(&uploadResp)
	claimCode := uploadResp["claim_code"].(string)

	downloadHandler := handlers.ClaimHandler(repos, cfg)

	// Download 1 - should succeed
	download1 := httptest.NewRequest(http.MethodGet, "/api/claim/"+claimCode, nil)
	rr1 := httptest.NewRecorder()
	downloadHandler.ServeHTTP(rr1, download1)

	if rr1.Code != http.StatusOK {
		t.Errorf("download 1: status = %d, want %d", rr1.Code, http.StatusOK)
	}

	// Download 2 - should succeed
	download2 := httptest.NewRequest(http.MethodGet, "/api/claim/"+claimCode, nil)
	rr2 := httptest.NewRecorder()
	downloadHandler.ServeHTTP(rr2, download2)

	if rr2.Code != http.StatusOK {
		t.Errorf("download 2: status = %d, want %d", rr2.Code, http.StatusOK)
	}

	// Download 3 - should fail (limit exceeded)
	download3 := httptest.NewRequest(http.MethodGet, "/api/claim/"+claimCode, nil)
	rr3 := httptest.NewRecorder()
	downloadHandler.ServeHTTP(rr3, download3)

	if rr3.Code != http.StatusGone {
		t.Errorf("download 3 (exceeded): status = %d, want %d", rr3.Code, http.StatusGone)
	}

	// Verify file still exists in database but access is blocked
	// (Implementation doesn't auto-delete files when limit reached, just blocks access)
	file, _ := repos.Files.GetByClaimCode(ctx, claimCode)
	if file == nil {
		t.Error("file record should still exist in database")
	}
	if file.DownloadCount != 2 {
		t.Errorf("download_count = %d, want 2", file.DownloadCount)
	}

	t.Log("Download limit workflow completed successfully")
}

// TestFileExpiration tests that expired files cannot be downloaded
func TestFileExpiration(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create an expired file directly in database
	claimCode, _ := utils.GenerateClaimCode()
	storedFilename := "expired_file.dat"

	repos.Files.Create(ctx, &models.File{
		ClaimCode:        claimCode,
		StoredFilename:   storedFilename,
		OriginalFilename: "expired.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		UploaderIP:       "127.0.0.1",
	})

	// Create physical file
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, []byte("expired content"), 0644)

	// Try to download expired file
	downloadHandler := handlers.ClaimHandler(repos, cfg)

	downloadReq := httptest.NewRequest(http.MethodGet, "/api/claim/"+claimCode, nil)
	downloadRR := httptest.NewRecorder()

	downloadHandler.ServeHTTP(downloadRR, downloadReq)

	// Should return 404 Not Found (implementation returns 404 for both not found and expired)
	if downloadRR.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (Not Found)", downloadRR.Code, http.StatusNotFound)
	}

	t.Log("File expiration check completed successfully")
}

// TestUserAuthenticationFlow tests complete user authentication workflow
func TestUserAuthenticationFlow(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Step 1: Create user
	username := "testuser"
	password := "testpassword123"
	email := "test@example.com"

	hashedPassword, _ := utils.HashPassword(password)
	repos.Users.Create(ctx, username, email, hashedPassword, "user", true)

	// Step 2: Login
	loginHandler := handlers.UserLoginHandler(repos, cfg)

	loginReq := map[string]string{
		"username": username,
		"password": password,
	}
	loginBody, _ := json.Marshal(loginReq)

	req := httptest.NewRequest(http.MethodPost, "/api/user/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	loginHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("login failed: status = %d", rr.Code)
	}

	var loginResp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&loginResp)

	if loginResp["username"] != username {
		t.Errorf("username = %v, want %s", loginResp["username"], username)
	}

	// Verify session cookie is set
	cookies := rr.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "user_session" {
			sessionCookie = cookie
			break
		}
	}

	if sessionCookie == nil {
		t.Fatal("user_session cookie not set")
	}

	// Step 3: Validate session
	session, _ := repos.Users.GetSession(ctx, sessionCookie.Value)
	if session == nil {
		t.Error("session should be valid")
	}

	// Step 4: Logout
	logoutHandler := handlers.UserLogoutHandler(repos, cfg)

	logoutReq := httptest.NewRequest(http.MethodPost, "/api/user/logout", nil)
	logoutReq.AddCookie(sessionCookie)
	logoutRR := httptest.NewRecorder()

	logoutHandler.ServeHTTP(logoutRR, logoutReq)

	if logoutRR.Code != http.StatusOK {
		t.Errorf("logout failed: status = %d", logoutRR.Code)
	}

	// Step 5: Verify session is invalidated
	session, _ = repos.Users.GetSession(ctx, sessionCookie.Value)
	if session != nil {
		t.Error("session should be invalid after logout")
	}

	t.Log("User authentication workflow completed successfully")
}

// TestRateLimitingIntegration tests rate limiting across multiple requests
func TestRateLimitingIntegration(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	// Set low rate limit for testing
	cfg.SetRateLimitUpload(3)

	rateLimiter := middleware.NewRateLimiter(cfg)
	defer rateLimiter.Stop()
	uploadHandler := middleware.RateLimitMiddleware(rateLimiter)(handlers.UploadHandler(repos, cfg))

	fileContent := []byte("test")

	// Make 3 successful uploads (within limit)
	for i := 0; i < 3; i++ {
		body, contentType := testutil.CreateMultipartForm(t, fileContent, "test.txt", nil)

		req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.RemoteAddr = "192.168.1.100:12345" // Same IP
		rr := httptest.NewRecorder()

		uploadHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("upload %d: status = %d, want %d", i+1, rr.Code, http.StatusCreated)
		}
	}

	// 4th upload should be rate limited
	body, contentType := testutil.CreateMultipartForm(t, fileContent, "test.txt", nil)
	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	req.RemoteAddr = "192.168.1.100:12345"
	rr := httptest.NewRecorder()

	uploadHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("4th upload: status = %d, want %d (rate limited)", rr.Code, http.StatusTooManyRequests)
	}

	t.Log("Rate limiting integration test completed successfully")
}

// TestIPBlockingIntegration tests IP blocking across handlers
func TestIPBlockingIntegration(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Block an IP
	blockedIP := "192.168.1.200"
	repos.Admin.BlockIP(ctx, blockedIP, "Testing", "admin")

	// Wrap handler with IP blocking middleware
	uploadHandler := middleware.IPBlockCheck(repos, cfg)(handlers.UploadHandler(repos, cfg))

	fileContent := []byte("test")
	body, contentType := testutil.CreateMultipartForm(t, fileContent, "test.txt", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	req.RemoteAddr = blockedIP + ":12345"
	rr := httptest.NewRecorder()

	uploadHandler.ServeHTTP(rr, req)

	// Should be blocked
	if rr.Code != http.StatusForbidden {
		t.Errorf("blocked IP upload: status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	// Unblock and retry
	repos.Admin.UnblockIP(ctx, blockedIP)

	body2, contentType2 := testutil.CreateMultipartForm(t, fileContent, "test.txt", nil)
	req2 := httptest.NewRequest(http.MethodPost, "/api/upload", body2)
	req2.Header.Set("Content-Type", contentType2)
	req2.RemoteAddr = blockedIP + ":12345"
	rr2 := httptest.NewRecorder()

	uploadHandler.ServeHTTP(rr2, req2)

	// Should succeed after unblocking
	if rr2.Code != http.StatusCreated {
		t.Errorf("unblocked IP upload: status = %d, want %d", rr2.Code, http.StatusCreated)
	}

	t.Log("IP blocking integration test completed successfully")
}

// TestMultipleUploadsAndCleanup tests uploading multiple files and cleanup
func TestMultipleUploadsAndCleanup(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	uploadHandler := handlers.UploadHandler(repos, cfg)

	claimCodes := make([]string, 5)

	// Upload 5 files
	for i := 0; i < 5; i++ {
		fileContent := []byte(fmt.Sprintf("File content %d", i))
		filename := fmt.Sprintf("file%d.txt", i)

		body, contentType := testutil.CreateMultipartForm(t, fileContent, filename, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
		req.Header.Set("Content-Type", contentType)
		rr := httptest.NewRecorder()

		uploadHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("upload %d failed: status = %d, body = %s", i, rr.Code, rr.Body.String())
		}

		var resp map[string]interface{}
		json.NewDecoder(rr.Body).Decode(&resp)
		claimCodes[i] = resp["claim_code"].(string)
	}

	// Verify all files exist in database
	for i, code := range claimCodes {
		file, err := repos.Files.GetByClaimCode(ctx, code)
		if err != nil || file == nil {
			t.Errorf("file %d not found in database", i)
		}
	}

	// Manually expire some files (2 hours ago to account for 1-hour grace period)
	// IMPORTANT: Must format as RFC3339 to match SQLite datetime() format expectations.
	// Raw Go time.Time includes monotonic clock that SQLite cannot parse.
	expiredAt := time.Now().Add(-2 * time.Hour).Format(time.RFC3339)
	for i := 0; i < 3; i++ {
		repos.DB.Exec("UPDATE files SET expires_at = ? WHERE claim_code = ?",
			expiredAt, claimCodes[i])
	}

	// Run cleanup
	deleted, _ := repos.Files.DeleteExpired(ctx, cfg.UploadDir, nil)

	if deleted != 3 {
		t.Errorf("deleted = %d, want 3", deleted)
	}

	// Verify expired files are gone
	for i := 0; i < 3; i++ {
		file, _ := repos.Files.GetByClaimCode(ctx, claimCodes[i])
		if file != nil {
			t.Errorf("expired file %d should be deleted", i)
		}
	}

	// Verify non-expired files still exist
	for i := 3; i < 5; i++ {
		file, _ := repos.Files.GetByClaimCode(ctx, claimCodes[i])
		if file == nil {
			t.Errorf("active file %d should still exist", i)
		}
	}

	t.Log("Multiple uploads and cleanup test completed successfully")
}
