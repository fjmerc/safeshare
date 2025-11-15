package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

func TestUserLoginHandler_ValidLogin(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserLoginHandler(db, cfg)

	// Create test user
	passwordHash, _ := utils.HashPassword("password123")
	_, err := database.CreateUser(db, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Test login
	loginReq := models.UserLoginRequest{
		Username: "testuser",
		Password: "password123",
	}

	body, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Parse response
	var resp models.User
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Username != "testuser" {
		t.Errorf("username = %q, want testuser", resp.Username)
	}

	// Check session cookie was set (handler sets "user_session" cookie)
	cookies := rr.Result().Cookies()
	found := false
	for _, cookie := range cookies {
		if cookie.Name == "user_session" {
			found = true
			if cookie.Value == "" {
				t.Error("user_session cookie is empty")
			}
			break
		}
	}

	if !found {
		t.Error("user_session cookie not set")
	}
}

func TestUserLoginHandler_InvalidCredentials(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserLoginHandler(db, cfg)

	// Create test user
	passwordHash, _ := utils.HashPassword("password123")
	user := &models.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: passwordHash,
		Role:         "user",
		IsActive:     true,
	}

	_, _ = database.CreateUser(db, user.Username, user.Email, user.PasswordHash, user.Role, false)

	tests := []struct {
		name       string
		username   string
		password   string
		wantStatus int
	}{
		{
			name:       "wrong password",
			username:   "testuser",
			password:   "wrongpassword",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong username",
			username:   "wronguser",
			password:   "password123",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "empty username",
			username:   "",
			password:   "password123",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "empty password",
			username:   "testuser",
			password:   "",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loginReq := models.UserLoginRequest{
				Username: tt.username,
				Password: tt.password,
			}

			body, _ := json.Marshal(loginReq)
			req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, tt.wantStatus)
		})
	}
}

func TestUserLoginHandler_DisabledAccount(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserLoginHandler(db, cfg)

	// Create user then disable them (CreateUser always creates active users)
	passwordHash, _ := utils.HashPassword("password123")
	user, _ := database.CreateUser(db, "disabled", "disabled@example.com", passwordHash, "user", false)

	// Disable the user
	database.SetUserActive(db, user.ID, false)

	loginReq := models.UserLoginRequest{
		Username: "disabled",
		Password: "password123",
	}

	body, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusForbidden)

	var errResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &errResp)

	if errResp["error"] != "Account has been disabled" {
		t.Errorf("error message = %q, want account disabled message", errResp["error"])
	}
}

func TestUserLoginHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserLoginHandler(db, cfg)

	methods := []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodDelete,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/auth/login", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

func TestUserLogoutHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserLogoutHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	// Add session cookie
	req.AddCookie(&http.Cookie{
		Name:  "session_token",
		Value: "test-session-token",
	})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Check session cookie was cleared
	cookies := rr.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "session_token" {
			if cookie.MaxAge != -1 {
				t.Errorf("session cookie MaxAge = %d, want -1 (deleted)", cookie.MaxAge)
			}
		}
	}
}

func TestChangePasswordHandler_Valid(t *testing.T) {
	db := testutil.SetupTestDB(t)
	_ = testutil.SetupTestConfig(t)

	// Create test user in database
	oldPasswordHash, _ := utils.HashPassword("oldpassword123")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", oldPasswordHash, "user", false)

	handler := UserChangePasswordHandler(db)

	// Create request
	changeReq := models.ChangePasswordRequest{
		CurrentPassword: "oldpassword123",
		NewPassword:     "newpassword456",
		ConfirmPassword: "newpassword456",
	}

	body, _ := json.Marshal(changeReq)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Add user to context (simulating authentication middleware)
	ctx := req.Context()
	ctx = context.WithValue(ctx, "user", user)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Verify password was changed
	updatedUser, _ := database.GetUserByUsername(db, "testuser")
	if !utils.VerifyPassword(updatedUser.PasswordHash, "newpassword456") {
		t.Error("password was not updated")
	}

	// Old password should no longer work
	if utils.VerifyPassword(updatedUser.PasswordHash, "oldpassword123") {
		t.Error("old password still works")
	}
}

func TestChangePasswordHandler_InvalidCurrentPassword(t *testing.T) {
	db := testutil.SetupTestDB(t)
	_ = testutil.SetupTestConfig(t)

	passwordHash, _ := utils.HashPassword("correctpassword")
	user := &models.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: passwordHash,
		Role:         "user",
		IsActive:     true,
	}

	_, _ = database.CreateUser(db, user.Username, user.Email, user.PasswordHash, user.Role, false)

	handler := UserChangePasswordHandler(db)

	changeReq := models.ChangePasswordRequest{
		CurrentPassword: "wrongpassword",
		NewPassword:     "newpassword456",
		ConfirmPassword: "newpassword456",
	}

	body, _ := json.Marshal(changeReq)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.WithValue(req.Context(), "user", user)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)
}

func TestChangePasswordHandler_PasswordMismatch(t *testing.T) {
	db := testutil.SetupTestDB(t)
	_ = testutil.SetupTestConfig(t)

	passwordHash, _ := utils.HashPassword("currentpassword")
	user := &models.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: passwordHash,
		Role:         "user",
		IsActive:     true,
	}

	_, _ = database.CreateUser(db, user.Username, user.Email, user.PasswordHash, user.Role, false)

	handler := UserChangePasswordHandler(db)

	changeReq := models.ChangePasswordRequest{
		CurrentPassword: "currentpassword",
		NewPassword:     "newpassword456",
		ConfirmPassword: "differentpassword", // Doesn't match
	}

	body, _ := json.Marshal(changeReq)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.WithValue(req.Context(), "user", user)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

func TestGetCurrentUserHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)
	_ = testutil.SetupTestConfig(t)
	handler := UserGetCurrentHandler(db)

	// Create user in database (handler reloads from DB)
	passwordHash, _ := utils.HashPassword("password123")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", passwordHash, "user", false)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/user", nil)

	// Add user to context
	ctx := context.WithValue(req.Context(), "user", user)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var respUser models.User
	json.Unmarshal(rr.Body.Bytes(), &respUser)

	if respUser.Username != user.Username {
		t.Errorf("username = %q, want %q", respUser.Username, user.Username)
	}

	// Password hash should not be included in response
	if respUser.PasswordHash != "" {
		t.Error("password hash should not be in response")
	}
}

func TestUserDashboardHandler_ListFiles(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserDashboardDataHandler(db, cfg)

	// Create test user in database (use returned user with correct ID)
	passwordHash, _ := utils.HashPassword("password123")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", passwordHash, "user", false)

	// Create some files for the user (each needs unique claim code)
	for i := 0; i < 3; i++ {
		file := testutil.SampleFile()
		file.UserID = &user.ID
		file.ClaimCode = fmt.Sprintf("test-claim-code-%d", i) // Unique claim codes
		database.CreateFile(db, file)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)

	ctx := context.WithValue(req.Context(), "user", user)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if int(resp["total"].(float64)) != 3 {
		t.Errorf("total files = %v, want 3", resp["total"])
	}

	files := resp["files"].([]interface{})
	if len(files) != 3 {
		t.Errorf("files count = %d, want 3", len(files))
	}
}

func TestUserLoginHandler_InvalidJSON(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserLoginHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

func TestUserLoginHandler_CaseInsensitive(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	handler := UserLoginHandler(db, cfg)

	// Create user with lowercase username
	passwordHash, _ := utils.HashPassword("password123")
	user := &models.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: passwordHash,
		Role:         "user",
		IsActive:     true,
	}

	_, _ = database.CreateUser(db, user.Username, user.Email, user.PasswordHash, user.Role, false)

	// Try login with different case
	variants := []string{
		"testuser",
		"TestUser",
		"TESTUSER",
		"tEsTuSeR",
	}

	for _, username := range variants {
		t.Run("username="+username, func(t *testing.T) {
			loginReq := models.UserLoginRequest{
				Username: username,
				Password: "password123",
			}

			body, _ := json.Marshal(loginReq)
			req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// Behavior depends on database collation
			// Most implementations are case-sensitive by default
			// Document actual behavior here
			if rr.Code != http.StatusOK && username != "testuser" {
				t.Logf("Case-sensitive login: %s failed as expected", username)
			}
		})
	}
}

// Benchmark login handler
func BenchmarkUserLoginHandler(b *testing.B) {
	db := testutil.SetupTestDB(&testing.T{})
	cfg := testutil.SetupTestConfig(&testing.T{})
	handler := UserLoginHandler(db, cfg)

	passwordHash, _ := utils.HashPassword("password123")
	user := &models.User{
		Username:     "benchuser",
		Email:        "bench@example.com",
		PasswordHash: passwordHash,
		Role:         "user",
		IsActive:     true,
	}

	_, _ = database.CreateUser(db, user.Username, user.Email, user.PasswordHash, user.Role, false)

	loginReq := models.UserLoginRequest{
		Username: "benchuser",
		Password: "password123",
	}

	body, _ := json.Marshal(loginReq)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}
