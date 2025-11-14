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

	// Create admin credentials
	hashedPassword, _ := utils.HashPassword("adminpassword123")
	database.InitializeAdminCredentials(db, "admin", hashedPassword)

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

	// Create admin credentials
	hashedPassword, _ := utils.HashPassword("adminpassword123")
	database.InitializeAdminCredentials(db, "admin", hashedPassword)

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

	// Verify file is deleted from database
	_, err := database.GetFileByClaimCode(db, claimCode)
	if err == nil {
		t.Error("file should be deleted from database")
	}

	// Verify physical file is deleted
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("physical file should be deleted")
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

	// Verify files are deleted from database
	for _, code := range claimCodes {
		_, err := database.GetFileByClaimCode(db, code)
		if err == nil {
			t.Errorf("file %s should be deleted from database", code)
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

	// Create user
	hashedPassword, _ := utils.HashPassword("password")
	user, _ := database.CreateUser(db, "deleteuser", "delete@example.com", hashedPassword, "user", true)

	handler := AdminDeleteUserHandler(db)

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

	handler := AdminDeleteUserHandler(db)

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
