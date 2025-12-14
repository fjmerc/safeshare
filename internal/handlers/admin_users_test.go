package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// TestAdminCreateUserHandler_Success tests successful user creation
func TestAdminCreateUserHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := AdminCreateUserHandler(repos)

	createReq := models.CreateUserRequest{
		Username: "newuser",
		Email:    "newuser@example.com",
		Password: "custompassword123",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusCreated)

	var resp models.CreateUserResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Username != "newuser" {
		t.Errorf("username = %q, want newuser", resp.Username)
	}

	if resp.Email != "newuser@example.com" {
		t.Errorf("email = %q, want newuser@example.com", resp.Email)
	}

	if resp.TemporaryPassword != "custompassword123" {
		t.Errorf("temporary_password = %q, want custompassword123", resp.TemporaryPassword)
	}

	// Verify user exists in database
	user, err := repos.Users.GetByUsername(ctx, "newuser")
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if user == nil {
		t.Fatal("user not found in database")
	}
}

// TestAdminCreateUserHandler_AutoGeneratePassword tests password auto-generation
func TestAdminCreateUserHandler_AutoGeneratePassword(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminCreateUserHandler(repos)

	createReq := models.CreateUserRequest{
		Username: "autopassuser",
		Email:    "auto@example.com",
		// No password provided
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusCreated)

	var resp models.CreateUserResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp.TemporaryPassword == "" {
		t.Error("temporary_password should be generated")
	}

	// Password should be in the format: word-word-word-### (at least 15 chars)
	if len(resp.TemporaryPassword) < 15 {
		t.Errorf("generated password too short: %q", resp.TemporaryPassword)
	}
}

// TestAdminCreateUserHandler_ValidationErrors tests input validation
func TestAdminCreateUserHandler_ValidationErrors(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminCreateUserHandler(repos)

	tests := []struct {
		name       string
		req        models.CreateUserRequest
		wantStatus int
		wantError  string
	}{
		{
			name: "missing username",
			req: models.CreateUserRequest{
				Email: "test@example.com",
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "Username and email are required",
		},
		{
			name: "missing email",
			req: models.CreateUserRequest{
				Username: "testuser",
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "Username and email are required",
		},
		{
			name: "invalid username characters",
			req: models.CreateUserRequest{
				Username: "user@name!",
				Email:    "test@example.com",
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "Username can only contain letters, numbers, underscore, and dash",
		},
		{
			name: "invalid email format - no @",
			req: models.CreateUserRequest{
				Username: "testuser",
				Email:    "invalid-email",
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "Invalid email format",
		},
		{
			name: "invalid email format - no dot",
			req: models.CreateUserRequest{
				Username: "testuser",
				Email:    "test@example",
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "Invalid email format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req := httptest.NewRequest(http.MethodPost, "/admin/api/users/create", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, tt.wantStatus)

			var errResp map[string]string
			json.Unmarshal(rr.Body.Bytes(), &errResp)

			if errResp["error"] != tt.wantError {
				t.Errorf("error = %q, want %q", errResp["error"], tt.wantError)
			}
		})
	}
}

// TestAdminCreateUserHandler_DuplicateEmail tests duplicate email handling
func TestAdminCreateUserHandler_DuplicateEmail(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := AdminCreateUserHandler(repos)

	// Create first user
	passwordHash, _ := utils.HashPassword("password123")
	_, _ = repos.Users.Create(ctx, "user1", "duplicate@example.com", passwordHash, "user", false)

	// Try to create user with same email
	createReq := models.CreateUserRequest{
		Username: "user2",
		Email:    "duplicate@example.com",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should fail with conflict error
	testutil.AssertStatusCode(t, rr, http.StatusConflict)
}

// TestAdminCreateUserHandler_InvalidJSON tests malformed request handling
func TestAdminCreateUserHandler_InvalidJSON(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminCreateUserHandler(repos)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/create", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

// TestAdminCreateUserHandler_MethodNotAllowed tests HTTP method validation
func TestAdminCreateUserHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminCreateUserHandler(repos)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/users/create", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// TestAdminListUsersHandler_Success tests user listing with pagination
func TestAdminListUsersHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := AdminListUsersHandler(repos)

	// Create test users
	passwordHash, _ := utils.HashPassword("password123")
	for i := 0; i < 5; i++ {
		username := fmt.Sprintf("user%d", i)
		email := fmt.Sprintf("user%d@example.com", i)
		_, _ = repos.Users.Create(ctx, username, email, passwordHash, "user", false)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/users?limit=10&offset=0", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if int(resp["total"].(float64)) != 5 {
		t.Errorf("total = %v, want 5", resp["total"])
	}

	if int(resp["limit"].(float64)) != 10 {
		t.Errorf("limit = %v, want 10", resp["limit"])
	}

	users := resp["users"].([]interface{})
	if len(users) != 5 {
		t.Errorf("users count = %d, want 5", len(users))
	}
}

// TestAdminListUsersHandler_Pagination tests pagination parameters
func TestAdminListUsersHandler_Pagination(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := AdminListUsersHandler(repos)

	// Create 25 test users
	passwordHash, _ := utils.HashPassword("password123")
	for i := 0; i < 25; i++ {
		username := fmt.Sprintf("user%d", i)
		email := fmt.Sprintf("user%d@example.com", i)
		_, _ = repos.Users.Create(ctx, username, email, passwordHash, "user", false)
	}

	tests := []struct {
		name          string
		limit         string
		offset        string
		expectedLimit int
		expectedCount int
	}{
		{"default", "", "", 50, 25},                // All users fit in default limit
		{"limit 10", "10", "0", 10, 10},            // First page of 10
		{"limit 10 offset 10", "10", "10", 10, 10}, // Second page of 10
		{"limit 10 offset 20", "10", "20", 10, 5},  // Third page (only 5 left)
		{"invalid limit", "invalid", "0", 50, 25},  // Falls back to default
		{"negative offset", "10", "-1", 10, 10},    // Negative treated as 0
		{"too large limit", "200", "0", 50, 25},    // Falls back to default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/admin/api/users"
			if tt.limit != "" || tt.offset != "" {
				url += "?"
				if tt.limit != "" {
					url += "limit=" + tt.limit
				}
				if tt.offset != "" && tt.limit != "" {
					url += "&"
				}
				if tt.offset != "" {
					url += "offset=" + tt.offset
				}
			}

			req := httptest.NewRequest(http.MethodGet, url, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusOK)

			var resp map[string]interface{}
			json.Unmarshal(rr.Body.Bytes(), &resp)

			if int(resp["limit"].(float64)) != tt.expectedLimit {
				t.Errorf("limit = %v, want %d", resp["limit"], tt.expectedLimit)
			}

			users := resp["users"].([]interface{})
			if len(users) != tt.expectedCount {
				t.Errorf("user count = %d, want %d", len(users), tt.expectedCount)
			}
		})
	}
}

// TestAdminListUsersHandler_MethodNotAllowed tests HTTP method validation
func TestAdminListUsersHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminListUsersHandler(repos)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/users", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// TestAdminUpdateUserHandler_Success tests successful user update
func TestAdminUpdateUserHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := AdminUpdateUserHandler(repos)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, _ := repos.Users.Create(ctx, "oldusername", "old@example.com", passwordHash, "user", false)

	// Update user
	updateReq := models.UpdateUserRequest{
		Username: "newusername",
		Email:    "new@example.com",
		Role:     "admin",
	}

	body, _ := json.Marshal(updateReq)
	url := fmt.Sprintf("/admin/api/users/%d", user.ID)
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Verify update
	updatedUser, _ := repos.Users.GetByID(ctx, user.ID)
	if updatedUser.Username != "newusername" {
		t.Errorf("username = %q, want newusername", updatedUser.Username)
	}
	if updatedUser.Email != "new@example.com" {
		t.Errorf("email = %q, want new@example.com", updatedUser.Email)
	}
	if updatedUser.Role != "admin" {
		t.Errorf("role = %q, want admin", updatedUser.Role)
	}
}

// TestAdminUpdateUserHandler_PartialUpdate tests partial field updates
func TestAdminUpdateUserHandler_PartialUpdate(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := AdminUpdateUserHandler(repos)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, _ := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)

	// Update only email
	updateReq := models.UpdateUserRequest{
		Email: "updated@example.com",
	}

	body, _ := json.Marshal(updateReq)
	url := fmt.Sprintf("/admin/api/users/%d", user.ID)
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Verify other fields unchanged
	updatedUser, _ := repos.Users.GetByID(ctx, user.ID)
	if updatedUser.Username != "testuser" {
		t.Errorf("username changed unexpectedly to %q", updatedUser.Username)
	}
	if updatedUser.Email != "updated@example.com" {
		t.Errorf("email = %q, want updated@example.com", updatedUser.Email)
	}
	if updatedUser.Role != "user" {
		t.Errorf("role changed unexpectedly to %q", updatedUser.Role)
	}
}

// TestAdminUpdateUserHandler_ConflictUsername tests username conflict handling
func TestAdminUpdateUserHandler_ConflictUsername(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := AdminUpdateUserHandler(repos)

	passwordHash, _ := utils.HashPassword("password123")
	user1, _ := repos.Users.Create(ctx, "user1", "user1@example.com", passwordHash, "user", false)
	_, _ = repos.Users.Create(ctx, "user2", "user2@example.com", passwordHash, "user", false)

	// Try to update user1 to have user2's username
	updateReq := models.UpdateUserRequest{
		Username: "user2",
	}

	body, _ := json.Marshal(updateReq)
	url := fmt.Sprintf("/admin/api/users/%d", user1.ID)
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should fail with conflict error
	testutil.AssertStatusCode(t, rr, http.StatusConflict)
}

// TestAdminUpdateUserHandler_UserNotFound tests non-existent user
func TestAdminUpdateUserHandler_UserNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminUpdateUserHandler(repos)

	updateReq := models.UpdateUserRequest{
		Username: "newname",
	}

	body, _ := json.Marshal(updateReq)
	req := httptest.NewRequest(http.MethodPut, "/admin/api/users/99999", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

// TestAdminUpdateUserHandler_InvalidUserID tests invalid user ID handling
func TestAdminUpdateUserHandler_InvalidUserID(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminUpdateUserHandler(repos)

	req := httptest.NewRequest(http.MethodPut, "/admin/api/users/invalid", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

// TestAdminToggleUserActiveHandler_EnableSuccess tests enabling a disabled user
func TestAdminToggleUserActiveHandler_EnableSuccess(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := AdminToggleUserActiveHandler(repos)

	// Create inactive user
	passwordHash, _ := utils.HashPassword("password123")
	user, _ := repos.Users.Create(ctx, "inactiveuser", "inactive@example.com", passwordHash, "user", false)

	// Disable user first
	repos.Users.SetActive(ctx, user.ID, false)

	// Enable user
	url := fmt.Sprintf("/admin/api/users/%d/enable", user.ID)
	req := httptest.NewRequest(http.MethodPost, url, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Verify user is enabled
	updatedUser, _ := repos.Users.GetByID(ctx, user.ID)
	if !updatedUser.IsActive {
		t.Error("user should be active after enable")
	}
}

// TestAdminToggleUserActiveHandler_DisableSuccess tests disabling an active user
func TestAdminToggleUserActiveHandler_DisableSuccess(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := AdminToggleUserActiveHandler(repos)

	// Create active user
	passwordHash, _ := utils.HashPassword("password123")
	user, _ := repos.Users.Create(ctx, "activeuser", "active@example.com", passwordHash, "user", false)

	// Disable user
	url := fmt.Sprintf("/admin/api/users/%d/disable", user.ID)
	req := httptest.NewRequest(http.MethodPost, url, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Verify user is disabled
	updatedUser, _ := repos.Users.GetByID(ctx, user.ID)
	if updatedUser.IsActive {
		t.Error("user should be inactive after disable")
	}
}

// TestAdminToggleUserActiveHandler_UserNotFound tests toggling non-existent user
func TestAdminToggleUserActiveHandler_UserNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminToggleUserActiveHandler(repos)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/99999/enable", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

// TestAdminToggleUserActiveHandler_InvalidUserID tests invalid user ID
func TestAdminToggleUserActiveHandler_InvalidUserID(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminToggleUserActiveHandler(repos)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/invalid/enable", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

// TestAdminToggleUserActiveHandler_MethodNotAllowed tests HTTP method validation
func TestAdminToggleUserActiveHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminToggleUserActiveHandler(repos)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/users/1/enable", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// TestAdminResetUserPasswordHandler_Success tests password reset
func TestAdminResetUserPasswordHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := AdminResetUserPasswordHandler(repos)

	// Create user
	passwordHash, _ := utils.HashPassword("oldpassword")
	user, _ := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)

	// Reset password
	url := fmt.Sprintf("/admin/api/users/%d/reset-password", user.ID)
	req := httptest.NewRequest(http.MethodPost, url, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp["message"] != "Password reset successfully" {
		t.Errorf("message = %q, want Password reset successfully", resp["message"])
	}

	if resp["temporary_password"] == "" {
		t.Error("temporary_password should be provided")
	}

	if len(resp["temporary_password"]) < 15 {
		t.Errorf("temporary password too short: %q", resp["temporary_password"])
	}

	// Verify old password no longer works
	updatedUser, _ := repos.Users.GetByID(ctx, user.ID)
	if utils.VerifyPassword(updatedUser.PasswordHash, "oldpassword") {
		t.Error("old password should not work")
	}

	// Verify new password works
	if !utils.VerifyPassword(updatedUser.PasswordHash, resp["temporary_password"]) {
		t.Error("new temporary password should work")
	}
}

// TestAdminResetUserPasswordHandler_UserNotFound tests non-existent user
func TestAdminResetUserPasswordHandler_UserNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminResetUserPasswordHandler(repos)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/99999/reset-password", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

// TestAdminResetUserPasswordHandler_InvalidUserID tests invalid user ID
func TestAdminResetUserPasswordHandler_InvalidUserID(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminResetUserPasswordHandler(repos)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/invalid/reset-password", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

// TestAdminResetUserPasswordHandler_MethodNotAllowed tests HTTP method validation
func TestAdminResetUserPasswordHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminResetUserPasswordHandler(repos)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/users/1/reset-password", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// TestAdminDeleteUserHandler_Success tests user deletion
func TestAdminDeleteUserHandler_Success(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	handler := AdminDeleteUserHandler(repos, cfg)

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, _ := repos.Users.Create(ctx, "deleteuser", "delete@example.com", passwordHash, "user", false)

	// Delete user
	url := fmt.Sprintf("/admin/api/users/%d", user.ID)
	req := httptest.NewRequest(http.MethodDelete, url, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp["message"] != "User deleted successfully" {
		t.Errorf("message = %q, want User deleted successfully", resp["message"])
	}

	// Verify user no longer exists
	deletedUser, _ := repos.Users.GetByID(ctx, user.ID)
	if deletedUser != nil {
		t.Error("user should be deleted")
	}
}

// TestAdminDeleteUserHandler_UserNotFound tests deleting non-existent user
func TestAdminDeleteUserHandler_UserNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminDeleteUserHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/users/99999", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

// TestAdminDeleteUserHandler_InvalidUserID tests invalid user ID
func TestAdminDeleteUserHandler_InvalidUserID(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminDeleteUserHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/users/invalid", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

// TestAdminDeleteUserHandler_MethodNotAllowed tests HTTP method validation
func TestAdminDeleteUserHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := AdminDeleteUserHandler(repos, cfg)

	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/users/1", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}
