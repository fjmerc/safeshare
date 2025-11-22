package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

func TestAdminLoginHandler_ValidAdminCredentials(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create admin credentials (InitializeAdminCredentials hashes internally)
	database.InitializeAdminCredentials(db, "admin", "adminpassword123")

	handler := AdminLoginHandler(db, cfg)

	// Create login request (JSON format)
	loginReq := map[string]string{
		"username": "admin",
		"password": "adminpassword123",
	}
	body, _ := json.Marshal(loginReq)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify response contains success and CSRF token
	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("login should return success: true")
	}

	if csrfToken, ok := response["csrf_token"].(string); !ok || csrfToken == "" {
		t.Error("login should return a CSRF token")
	}

	// Verify admin_session cookie is set
	cookies := rr.Result().Cookies()
	foundSession := false
	for _, cookie := range cookies {
		if cookie.Name == "admin_session" {
			foundSession = true
			if cookie.Value == "" {
				t.Error("admin_session cookie should have a value")
			}
		}
	}
	if !foundSession {
		t.Error("admin_session cookie not set")
	}
}

func TestAdminLoginHandler_ValidUserWithAdminRole(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create user with admin role
	hashedPassword, _ := utils.HashPassword("adminpassword123")
	database.CreateUser(db, "adminuser", "admin@example.com", hashedPassword, "admin", true)

	handler := AdminLoginHandler(db, cfg)

	// Create login request
	loginReq := map[string]string{
		"username": "adminuser",
		"password": "adminpassword123",
	}
	body, _ := json.Marshal(loginReq)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify user_session cookie is set
	cookies := rr.Result().Cookies()
	foundSession := false
	for _, cookie := range cookies {
		if cookie.Name == "user_session" {
			foundSession = true
		}
	}
	if !foundSession {
		t.Error("user_session cookie not set for admin user")
	}
}

func TestAdminLoginHandler_InvalidCredentials(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminLoginHandler(db, cfg)

	loginReq := map[string]string{
		"username": "admin",
		"password": "wrongpassword",
	}
	body, _ := json.Marshal(loginReq)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 401 Unauthorized
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}

	var response map[string]string
	json.NewDecoder(rr.Body).Decode(&response)

	if response["error"] == "" {
		t.Error("should return error message")
	}
}

func TestAdminLoginHandler_DisabledUser(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create disabled admin user
	hashedPassword, _ := utils.HashPassword("adminpassword123")
	user, _ := database.CreateUser(db, "disabledadmin", "disabled@example.com", hashedPassword, "admin", false)
	database.SetUserActive(db, user.ID, false)

	handler := AdminLoginHandler(db, cfg)

	loginReq := map[string]string{
		"username": "disabledadmin",
		"password": "adminpassword123",
	}
	body, _ := json.Marshal(loginReq)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should reject disabled users
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("disabled user login: status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestAdminLoginHandler_FormData(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create admin credentials (InitializeAdminCredentials hashes internally)
	database.InitializeAdminCredentials(db, "admin", "adminpassword123")

	handler := AdminLoginHandler(db, cfg)

	// Create form data request
	formData := url.Values{}
	formData.Set("username", "admin")
	formData.Set("password", "adminpassword123")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/login", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("form login: status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestAdminLoginHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminLoginHandler(db, cfg)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/admin/api/login", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: status = %d, want %d", method, rr.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestAdminLoginHandler_MissingCredentials(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminLoginHandler(db, cfg)

	// Empty JSON body
	req := httptest.NewRequest(http.MethodPost, "/admin/api/login", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestAdminLogoutHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create session
	sessionToken := "test-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	database.CreateSession(db, sessionToken, expiresAt, "127.0.0.1", "test-agent")

	handler := AdminLogoutHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/logout", nil)
	req.AddCookie(&http.Cookie{
		Name:  "admin_session",
		Value: sessionToken,
	})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify session is deleted from database
	session, _ := database.GetSession(db, sessionToken)
	if session != nil {
		t.Error("session should be deleted after logout")
	}

	// Verify cookies are cleared (MaxAge = -1)
	cookies := rr.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "admin_session" && cookie.MaxAge != -1 {
			t.Errorf("admin_session cookie should be deleted (MaxAge = -1), got MaxAge = %d", cookie.MaxAge)
		}
	}
}

func TestAdminDashboardDataHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create some test files in database
	for i := 1; i <= 5; i++ {
		claimCode, _ := utils.GenerateClaimCode()
		database.CreateFile(db, &models.File{
			ClaimCode:        claimCode,
			StoredFilename:   fmt.Sprintf("stored_%d.dat", i),
			OriginalFilename: fmt.Sprintf("file_%d.txt", i),
			FileSize:         int64(i * 1024),
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "127.0.0.1",
		})
	}

	handler := AdminDashboardDataHandler(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/dashboard?page=1&page_size=10", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	// Verify response structure
	if _, ok := response["files"]; !ok {
		t.Error("response should contain 'files'")
	}

	if _, ok := response["pagination"]; !ok {
		t.Error("response should contain 'pagination'")
	}

	if _, ok := response["stats"]; !ok {
		t.Error("response should contain 'stats'")
	}

	if _, ok := response["blocked_ips"]; !ok {
		t.Error("response should contain 'blocked_ips'")
	}
}

func TestAdminDashboardDataHandler_Pagination(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create 25 test files
	for i := 1; i <= 25; i++ {
		claimCode, _ := utils.GenerateClaimCode()
		database.CreateFile(db, &models.File{
			ClaimCode:        claimCode,
			StoredFilename:   fmt.Sprintf("stored_%d.dat", i),
			OriginalFilename: fmt.Sprintf("file_%d.txt", i),
			FileSize:         1024,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "127.0.0.1",
		})
	}

	handler := AdminDashboardDataHandler(db, cfg)

	// Request page 1 with page_size=10
	req := httptest.NewRequest(http.MethodGet, "/admin/api/dashboard?page=1&page_size=10", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	files := response["files"].([]interface{})
	if len(files) != 10 {
		t.Errorf("page 1 should return 10 files, got %d", len(files))
	}

	pagination := response["pagination"].(map[string]interface{})
	totalPages := int(pagination["total_pages"].(float64))
	if totalPages != 3 {
		t.Errorf("total_pages = %d, want 3", totalPages)
	}
}

func TestAdminDeleteFileHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create a test file in database
	claimCode, _ := utils.GenerateClaimCode()
	storedFilename := "stored_test.dat"
	database.CreateFile(db, &models.File{
		ClaimCode:        claimCode,
		StoredFilename:   storedFilename,
		OriginalFilename: "test.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	})

	// Create physical file
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	os.WriteFile(filePath, []byte("test content"), 0644)

	handler := AdminDeleteFileHandler(db, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/files?claim_code="+claimCode, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify file is deleted from database (GetFileByClaimCode returns nil, nil when not found)
	file, err := database.GetFileByClaimCode(db, claimCode)
	if err != nil {
		t.Fatalf("unexpected error querying deleted file: %v", err)
	}
	if file != nil {
		t.Error("file should be deleted from database")
	}

	// Verify physical file is deleted
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("physical file should be deleted")
	}
}

func TestAdminDeleteFileHandler_MissingClaimCode(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminDeleteFileHandler(db, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/files", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminDeleteFileHandler_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminDeleteFileHandler(db, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/files?claim_code=nonexistent", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 404
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestAdminBulkDeleteFilesHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create 3 test files
	claimCodes := make([]string, 3)
	for i := 0; i < 3; i++ {
		claimCode, _ := utils.GenerateClaimCode()
		claimCodes[i] = claimCode
		storedFilename := fmt.Sprintf("stored_%d.dat", i)

		database.CreateFile(db, &models.File{
			ClaimCode:        claimCode,
			StoredFilename:   storedFilename,
			OriginalFilename: fmt.Sprintf("file_%d.txt", i),
			FileSize:         1024,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "127.0.0.1",
		})

		// Create physical file
		filePath := filepath.Join(cfg.UploadDir, storedFilename)
		os.WriteFile(filePath, []byte("test"), 0644)
	}

	handler := AdminBulkDeleteFilesHandler(db, cfg)

	// Create form data with comma-separated claim codes
	formData := url.Values{}
	formData.Set("claim_codes", claimCodes[0]+","+claimCodes[1]+","+claimCodes[2])

	req := httptest.NewRequest(http.MethodPost, "/admin/api/files/bulk-delete", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	deletedCount := int(response["deleted_count"].(float64))
	if deletedCount != 3 {
		t.Errorf("deleted_count = %d, want 3", deletedCount)
	}

	// Verify files are deleted from database (GetFileByClaimCode returns nil, nil when not found)
	for _, code := range claimCodes {
		file, err := database.GetFileByClaimCode(db, code)
		if err != nil {
			t.Fatalf("unexpected error querying deleted file %s: %v", code, err)
		}
		if file != nil {
			t.Errorf("file %s should be deleted from database", code)
		}
	}
}

func TestAdminBulkDeleteFilesHandler_EmptyRequest(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminBulkDeleteFilesHandler(db, cfg)

	// Send empty claim_codes
	formData := url.Values{}
	formData.Set("claim_codes", "")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/files/bulk-delete", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminBulkDeleteFilesHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminBulkDeleteFilesHandler(db, cfg)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/admin/api/files/bulk-delete", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: status = %d, want %d", method, rr.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestAdminBulkDeleteFilesHandler_PartialSuccess(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create only 2 out of 3 files
	validCode1, _ := utils.GenerateClaimCode()
	validCode2, _ := utils.GenerateClaimCode()
	invalidCode := "INVALIDCODE123"

	database.CreateFile(db, &models.File{
		ClaimCode:        validCode1,
		StoredFilename:   "stored_1.dat",
		OriginalFilename: "file_1.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	})

	database.CreateFile(db, &models.File{
		ClaimCode:        validCode2,
		StoredFilename:   "stored_2.dat",
		OriginalFilename: "file_2.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	})

	// Create physical files
	os.WriteFile(filepath.Join(cfg.UploadDir, "stored_1.dat"), []byte("test"), 0644)
	os.WriteFile(filepath.Join(cfg.UploadDir, "stored_2.dat"), []byte("test"), 0644)

	handler := AdminBulkDeleteFilesHandler(db, cfg)

	// Send 2 valid + 1 invalid claim code
	formData := url.Values{}
	formData.Set("claim_codes", validCode1+","+invalidCode+","+validCode2)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/files/bulk-delete", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	deletedCount := int(response["deleted_count"].(float64))
	if deletedCount != 2 {
		t.Errorf("deleted_count = %d, want 2 (only valid files should be deleted)", deletedCount)
	}
}

func TestAdminGetConfigHandler_Success(t *testing.T) {
	_ = testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Set some config values
	cfg.SetMaxFileSize(50 * 1024 * 1024) // 50MB
	cfg.SetDefaultExpirationHours(48)
	cfg.SetMaxExpirationHours(168)

	handler := AdminGetConfigHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/config", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	if response["max_file_size_bytes"] == nil {
		t.Error("max_file_size_bytes should be present in response")
	}

	if response["default_expiration_hours"] == nil {
		t.Error("default_expiration_hours should be present in response")
	}
}

func TestAdminGetConfigHandler_MethodNotAllowed(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	handler := AdminGetConfigHandler(cfg)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/admin/api/config", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: status = %d, want %d", method, rr.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestAdminBlockIPHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	handler := AdminBlockIPHandler(db)

	formData := url.Values{}
	formData.Set("ip_address", "192.168.1.100")
	formData.Set("reason", "Abuse detected")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/ip/block", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify IP is blocked
	blocked, _ := database.IsIPBlocked(db, "192.168.1.100")
	if !blocked {
		t.Error("IP should be blocked")
	}
}

func TestAdminBlockIPHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)

	handler := AdminBlockIPHandler(db)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/admin/api/ip/block", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: status = %d, want %d", method, rr.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestAdminBlockIPHandler_MissingIP(t *testing.T) {
	db := testutil.SetupTestDB(t)

	handler := AdminBlockIPHandler(db)

	// Empty IP address
	formData := url.Values{}
	formData.Set("ip_address", "")
	formData.Set("reason", "Test")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/ip/block", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminUnblockIPHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Block an IP first
	database.BlockIP(db, "192.168.1.100", "Test", "admin")

	handler := AdminUnblockIPHandler(db)

	formData := url.Values{}
	formData.Set("ip_address", "192.168.1.100")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/ip/unblock", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify IP is unblocked
	blocked, _ := database.IsIPBlocked(db, "192.168.1.100")
	if blocked {
		t.Error("IP should be unblocked")
	}
}

func TestAdminUpdateQuotaHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminUpdateQuotaHandler(db, cfg)

	formData := url.Values{}
	formData.Set("quota_gb", "100")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/quota", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify quota is updated
	if cfg.GetQuotaLimitGB() != 100 {
		t.Errorf("quota = %d GB, want 100 GB", cfg.GetQuotaLimitGB())
	}
}

func TestAdminUpdateQuotaHandler_InvalidValue(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminUpdateQuotaHandler(db, cfg)

	formData := url.Values{}
	formData.Set("quota_gb", "-10") // Negative quota

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/quota", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should reject negative values
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminGetConfigHandler(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	handler := AdminGetConfigHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/config", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	// Verify all config fields are present
	requiredFields := []string{
		"max_file_size_bytes",
		"default_expiration_hours",
		"max_expiration_hours",
		"rate_limit_upload",
		"rate_limit_download",
		"blocked_extensions",
		"quota_limit_gb",
	}

	for _, field := range requiredFields {
		if _, ok := response[field]; !ok {
			t.Errorf("response missing field: %s", field)
		}
	}
}

// User management tests

func TestAdminCreateUserHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	handler := AdminCreateUserHandler(db)

	createReq := models.CreateUserRequest{
		Username: "newuser",
		Email:    "newuser@example.com",
		Password: "", // Should generate temporary password
	}
	body, _ := json.Marshal(createReq)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusCreated)
	}

	var response models.CreateUserResponse
	json.NewDecoder(rr.Body).Decode(&response)

	if response.Username != "newuser" {
		t.Errorf("username = %s, want newuser", response.Username)
	}

	if response.TemporaryPassword == "" {
		t.Error("should return temporary password")
	}

	// Verify user exists in database
	user, _ := database.GetUserByUsername(db, "newuser")
	if user == nil {
		t.Error("user should be created in database")
	}
}

func TestAdminCreateUserHandler_DuplicateUsername(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create existing user
	hashedPassword, _ := utils.HashPassword("password123")
	database.CreateUser(db, "existing", "existing@example.com", hashedPassword, "user", true)

	handler := AdminCreateUserHandler(db)

	createReq := models.CreateUserRequest{
		Username: "existing",
		Email:    "newemail@example.com",
	}
	body, _ := json.Marshal(createReq)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 409 Conflict
	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestAdminCreateUserHandler_InvalidUsername(t *testing.T) {
	db := testutil.SetupTestDB(t)

	handler := AdminCreateUserHandler(db)

	createReq := models.CreateUserRequest{
		Username: "user@invalid!", // Invalid characters
		Email:    "user@example.com",
	}
	body, _ := json.Marshal(createReq)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminListUsersHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create test users
	for i := 1; i <= 5; i++ {
		hashedPassword, _ := utils.HashPassword("password")
		database.CreateUser(db, fmt.Sprintf("user%d", i), fmt.Sprintf("user%d@example.com", i), hashedPassword, "user", true)
	}

	handler := AdminListUsersHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/users?limit=10&offset=0", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	users := response["users"].([]interface{})
	if len(users) != 5 {
		t.Errorf("users count = %d, want 5", len(users))
	}

	total := int(response["total"].(float64))
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
}

func TestAdminToggleUserActiveHandler_Disable(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create active user
	hashedPassword, _ := utils.HashPassword("password")
	user, _ := database.CreateUser(db, "activeuser", "active@example.com", hashedPassword, "user", true)

	handler := AdminToggleUserActiveHandler(db)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/admin/api/users/%d/disable", user.ID), nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify user is disabled
	updatedUser, _ := database.GetUserByID(db, user.ID)
	if updatedUser.IsActive {
		t.Error("user should be disabled")
	}
}

func TestAdminToggleUserActiveHandler_Enable(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create disabled user
	hashedPassword, _ := utils.HashPassword("password")
	user, _ := database.CreateUser(db, "disableduser", "disabled@example.com", hashedPassword, "user", false)

	handler := AdminToggleUserActiveHandler(db)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/admin/api/users/%d/enable", user.ID), nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify user is enabled
	updatedUser, _ := database.GetUserByID(db, user.ID)
	if !updatedUser.IsActive {
		t.Error("user should be enabled")
	}
}

func TestAdminResetUserPasswordHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create user
	hashedPassword, _ := utils.HashPassword("oldpassword")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", hashedPassword, "user", true)

	handler := AdminResetUserPasswordHandler(db)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/admin/api/users/%d/reset-password", user.ID), nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response map[string]string
	json.NewDecoder(rr.Body).Decode(&response)

	if response["temporary_password"] == "" {
		t.Error("should return temporary password")
	}

	// Verify old password no longer works
	updatedUser, _ := database.GetUserByID(db, user.ID)
	if utils.VerifyPassword(updatedUser.PasswordHash, "oldpassword") {
		t.Error("old password should not work after reset")
	}

	// Verify new password works
	if !utils.VerifyPassword(updatedUser.PasswordHash, response["temporary_password"]) {
		t.Error("new temporary password should work")
	}
}

func TestAdminDeleteUserHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create user
	hashedPassword, _ := utils.HashPassword("password")
	user, _ := database.CreateUser(db, "deleteuser", "delete@example.com", hashedPassword, "user", true)

	handler := AdminDeleteUserHandler(db, cfg)

	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/admin/api/users/%d", user.ID), nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify user is deleted
	deletedUser, _ := database.GetUserByID(db, user.ID)
	if deletedUser != nil {
		t.Error("user should be deleted from database")
	}
}

func TestAdminDeleteUserHandler_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminDeleteUserHandler(db, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/users/99999", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 404
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestAdminUpdateUserHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create user
	hashedPassword, _ := utils.HashPassword("password")
	user, _ := database.CreateUser(db, "oldusername", "old@example.com", hashedPassword, "user", true)

	handler := AdminUpdateUserHandler(db)

	updateReq := models.UpdateUserRequest{
		Username: "newusername",
		Email:    "new@example.com",
		Role:     "admin",
	}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/admin/api/users/%d", user.ID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify user is updated
	updatedUser, _ := database.GetUserByID(db, user.ID)
	if updatedUser.Username != "newusername" {
		t.Errorf("username = %s, want newusername", updatedUser.Username)
	}

	if updatedUser.Email != "new@example.com" {
		t.Errorf("email = %s, want new@example.com", updatedUser.Email)
	}

	if updatedUser.Role != "admin" {
		t.Errorf("role = %s, want admin", updatedUser.Role)
	}
}

func TestAdminUpdateUserHandler_InvalidRole(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create user
	hashedPassword, _ := utils.HashPassword("password")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", hashedPassword, "user", true)

	handler := AdminUpdateUserHandler(db)

	updateReq := models.UpdateUserRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Role:     "superadmin", // Invalid role
	}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/admin/api/users/%d", user.ID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// AdminChangePasswordHandler tests

func TestAdminChangePasswordHandler_Success(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	// Set initial admin password
	cfg.SetAdminPassword("currentpassword123")

	handler := AdminChangePasswordHandler(cfg)

	formData := url.Values{}
	formData.Set("current_password", "currentpassword123")
	formData.Set("new_password", "newpassword456")
	formData.Set("confirm_password", "newpassword456")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/password", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify password is updated in config
	if cfg.GetAdminPassword() != "newpassword456" {
		t.Error("admin password should be updated in config")
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("response should contain success: true")
	}
}

func TestAdminChangePasswordHandler_IncorrectCurrentPassword(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	cfg.SetAdminPassword("correctpassword")

	handler := AdminChangePasswordHandler(cfg)

	formData := url.Values{}
	formData.Set("current_password", "wrongpassword")
	formData.Set("new_password", "newpassword456")
	formData.Set("confirm_password", "newpassword456")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/password", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 401 Unauthorized
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestAdminChangePasswordHandler_PasswordMismatch(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	cfg.SetAdminPassword("currentpassword123")

	handler := AdminChangePasswordHandler(cfg)

	formData := url.Values{}
	formData.Set("current_password", "currentpassword123")
	formData.Set("new_password", "newpassword456")
	formData.Set("confirm_password", "differentpassword789")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/password", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminChangePasswordHandler_PasswordTooShort(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	cfg.SetAdminPassword("currentpassword123")

	handler := AdminChangePasswordHandler(cfg)

	formData := url.Values{}
	formData.Set("current_password", "currentpassword123")
	formData.Set("new_password", "short")
	formData.Set("confirm_password", "short")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/password", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request (password must be >= 8 characters)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminChangePasswordHandler_MissingFields(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)

	cfg.SetAdminPassword("currentpassword123")

	handler := AdminChangePasswordHandler(cfg)

	formData := url.Values{}
	formData.Set("current_password", "currentpassword123")
	// Missing new_password and confirm_password

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/password", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// AdminUpdateStorageSettingsHandler tests

func TestAdminUpdateStorageSettingsHandler_QuotaOnly(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminUpdateStorageSettingsHandler(db, cfg)

	formData := url.Values{}
	formData.Set("quota_gb", "50")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/storage", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify quota is updated
	if cfg.GetQuotaLimitGB() != 50 {
		t.Errorf("quota = %d GB, want 50 GB", cfg.GetQuotaLimitGB())
	}

	// Verify database persistence
	settings, _ := database.GetSettings(db)
	if settings != nil && settings.QuotaLimitGB != 50 {
		t.Errorf("database quota = %d GB, want 50 GB", settings.QuotaLimitGB)
	}
}

func TestAdminUpdateStorageSettingsHandler_AllSettings(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminUpdateStorageSettingsHandler(db, cfg)

	formData := url.Values{}
	formData.Set("quota_gb", "100")
	formData.Set("max_file_size_mb", "200")
	formData.Set("default_expiration_hours", "48")
	formData.Set("max_expiration_hours", "336")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/storage", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify all settings are updated
	if cfg.GetQuotaLimitGB() != 100 {
		t.Errorf("quota = %d GB, want 100 GB", cfg.GetQuotaLimitGB())
	}

	expectedMaxFileSize := int64(200 * 1024 * 1024)
	if cfg.GetMaxFileSize() != expectedMaxFileSize {
		t.Errorf("max_file_size = %d bytes, want %d bytes", cfg.GetMaxFileSize(), expectedMaxFileSize)
	}

	if cfg.GetDefaultExpirationHours() != 48 {
		t.Errorf("default_expiration = %d hours, want 48 hours", cfg.GetDefaultExpirationHours())
	}

	if cfg.GetMaxExpirationHours() != 336 {
		t.Errorf("max_expiration = %d hours, want 336 hours", cfg.GetMaxExpirationHours())
	}
}

func TestAdminUpdateStorageSettingsHandler_InvalidQuota(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminUpdateStorageSettingsHandler(db, cfg)

	formData := url.Values{}
	formData.Set("quota_gb", "-50")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/storage", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request for negative quota
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminUpdateStorageSettingsHandler_InvalidMaxFileSize(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminUpdateStorageSettingsHandler(db, cfg)

	formData := url.Values{}
	formData.Set("max_file_size_mb", "0")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/storage", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request for zero/negative file size
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminUpdateStorageSettingsHandler_NoSettings(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminUpdateStorageSettingsHandler(db, cfg)

	formData := url.Values{}
	// No settings provided

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/storage", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request when no settings provided
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// AdminUpdateSecuritySettingsHandler tests

func TestAdminUpdateSecuritySettingsHandler_RateLimitsOnly(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminUpdateSecuritySettingsHandler(db, cfg)

	formData := url.Values{}
	formData.Set("rate_limit_upload", "20")
	formData.Set("rate_limit_download", "200")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/security", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify rate limits are updated
	if cfg.GetRateLimitUpload() != 20 {
		t.Errorf("upload_rate_limit = %d, want 20", cfg.GetRateLimitUpload())
	}

	if cfg.GetRateLimitDownload() != 200 {
		t.Errorf("download_rate_limit = %d, want 200", cfg.GetRateLimitDownload())
	}

	// Verify database persistence
	settings, _ := database.GetSettings(db)
	if settings != nil && settings.RateLimitUpload != 20 {
		t.Errorf("database upload_rate_limit = %d, want 20", settings.RateLimitUpload)
	}
	if settings != nil && settings.RateLimitDownload != 200 {
		t.Errorf("database download_rate_limit = %d, want 200", settings.RateLimitDownload)
	}
}

func TestAdminUpdateSecuritySettingsHandler_BlockedExtensions(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminUpdateSecuritySettingsHandler(db, cfg)

	formData := url.Values{}
	formData.Set("blocked_extensions", ".exe,.bat,.sh,.dll")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/security", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify blocked extensions are updated
	blockedExts := cfg.GetBlockedExtensions()
	if len(blockedExts) != 4 {
		t.Errorf("blocked_extensions count = %d, want 4", len(blockedExts))
	}

	// Verify extensions are normalized (lowercase, with leading dot)
	expectedExts := []string{".exe", ".bat", ".sh", ".dll"}
	for i, ext := range expectedExts {
		if blockedExts[i] != ext {
			t.Errorf("blocked_extensions[%d] = %s, want %s", i, blockedExts[i], ext)
		}
	}
}

func TestAdminUpdateSecuritySettingsHandler_AllSettings(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminUpdateSecuritySettingsHandler(db, cfg)

	formData := url.Values{}
	formData.Set("rate_limit_upload", "15")
	formData.Set("rate_limit_download", "150")
	formData.Set("blocked_extensions", ".exe,.dll,.so")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/security", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify all settings are updated
	if cfg.GetRateLimitUpload() != 15 {
		t.Errorf("upload_rate_limit = %d, want 15", cfg.GetRateLimitUpload())
	}

	if cfg.GetRateLimitDownload() != 150 {
		t.Errorf("download_rate_limit = %d, want 150", cfg.GetRateLimitDownload())
	}

	blockedExts := cfg.GetBlockedExtensions()
	if len(blockedExts) != 3 {
		t.Errorf("blocked_extensions count = %d, want 3", len(blockedExts))
	}
}

func TestAdminUpdateSecuritySettingsHandler_InvalidRateLimit(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminUpdateSecuritySettingsHandler(db, cfg)

	formData := url.Values{}
	formData.Set("rate_limit_upload", "0")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/security", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request for zero/negative rate limit
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdminUpdateSecuritySettingsHandler_NoSettings(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	handler := AdminUpdateSecuritySettingsHandler(db, cfg)

	formData := url.Values{}
	// No settings provided

	req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/security", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request when no settings provided
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// Additional IP blocking handler tests

func TestAdminBlockIPHandler_WithoutReason(t *testing.T) {
	db := testutil.SetupTestDB(t)

	handler := AdminBlockIPHandler(db)

	formData := url.Values{}
	formData.Set("ip_address", "10.0.0.1")
	// No reason provided

	req := httptest.NewRequest(http.MethodPost, "/admin/api/ip/block", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify IP is blocked with default reason
	blocked, _ := database.IsIPBlocked(db, "10.0.0.1")
	if !blocked {
		t.Error("IP should be blocked with default reason")
	}
}

func TestAdminUnblockIPHandler_NotBlocked(t *testing.T) {
	db := testutil.SetupTestDB(t)

	handler := AdminUnblockIPHandler(db)

	formData := url.Values{}
	formData.Set("ip_address", "10.0.0.99")

	req := httptest.NewRequest(http.MethodPost, "/admin/api/ip/unblock", bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 404 Not Found for IP not in blocklist
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// TestAdminDashboardDataHandler_Search tests search functionality
func TestAdminDashboardDataHandler_Search(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create test files with searchable terms
	claimCode1, _ := utils.GenerateClaimCode()
	database.CreateFile(db, &models.File{
		ClaimCode:        claimCode1,
		StoredFilename:   "stored1.dat",
		OriginalFilename: "searchable.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	})

	claimCode2, _ := utils.GenerateClaimCode()
	database.CreateFile(db, &models.File{
		ClaimCode:        claimCode2,
		StoredFilename:   "stored2.dat",
		OriginalFilename: "other.txt",
		FileSize:         2048,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.2",
	})

	handler := AdminDashboardDataHandler(db, cfg)

	// Search by filename
	req := httptest.NewRequest(http.MethodGet, "/admin/api/dashboard?search=searchable", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	files := response["files"].([]interface{})
	// Search should return only matching files
	if len(files) < 1 {
		t.Error("search should return at least one matching file")
	}
}

// TestAdminDashboardDataHandler_MethodNotAllowed tests HTTP method validation
func TestAdminDashboardDataHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := AdminDashboardDataHandler(db, cfg)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/dashboard", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// TestAdminUpdateQuotaHandler_MissingParameter tests missing quota_gb parameter
func TestAdminUpdateQuotaHandler_MissingParameter(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := AdminUpdateQuotaHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/quota/update", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

// TestAdminUpdateQuotaHandler_MethodNotAllowed tests HTTP method validation
func TestAdminUpdateQuotaHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := AdminUpdateQuotaHandler(db, cfg)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/quota/update", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}
