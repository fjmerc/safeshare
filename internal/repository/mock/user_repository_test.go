package mock

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

func TestNewUserRepository(t *testing.T) {
	repo := NewUserRepository()
	if repo == nil {
		t.Fatal("NewUserRepository returned nil")
	}
	if repo.users == nil {
		t.Error("users map should be initialized")
	}
	if repo.byUsername == nil {
		t.Error("byUsername map should be initialized")
	}
	if repo.sessions == nil {
		t.Error("sessions map should be initialized")
	}
	if repo.nextUserID != 1 {
		t.Errorf("nextUserID should be 1, got %d", repo.nextUserID)
	}
}

func TestUserRepository_AddUser(t *testing.T) {
	repo := NewUserRepository()

	user := &models.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hash",
		Role:         "user",
	}

	repo.AddUser(user)

	if user.ID == 0 {
		t.Error("user ID should be assigned")
	}

	users := repo.GetUsers()
	if len(users) != 1 {
		t.Errorf("expected 1 user, got %d", len(users))
	}

	// Verify deep copy
	user.Username = "modified"
	users = repo.GetUsers()
	if users[0].Username == "modified" {
		t.Error("stored user should be independent of original")
	}
}

func TestUserRepository_Create(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	user, err := repo.Create(ctx, "newuser", "new@example.com", "hash", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if user.ID == 0 {
		t.Error("user ID should be assigned")
	}
	if user.Username != "newuser" {
		t.Errorf("expected username newuser, got %s", user.Username)
	}

	// Test duplicate username
	_, err = repo.Create(ctx, "newuser", "another@example.com", "hash", "user", false)
	if !errors.Is(err, repository.ErrDuplicateKey) {
		t.Errorf("expected ErrDuplicateKey, got %v", err)
	}
}

func TestUserRepository_GetByID(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	user := &models.User{
		Username:     "getbyid",
		Email:        "getbyid@example.com",
		PasswordHash: "hash",
	}
	repo.AddUser(user)

	retrieved, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if retrieved.Username != user.Username {
		t.Errorf("expected username %s, got %s", user.Username, retrieved.Username)
	}

	// Non-existent user
	retrieved, err = repo.GetByID(ctx, 999)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if retrieved != nil {
		t.Error("expected nil for non-existent user")
	}
}

func TestUserRepository_GetByUsername(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	user := &models.User{
		Username:     "findme",
		Email:        "findme@example.com",
		PasswordHash: "hash",
	}
	repo.AddUser(user)

	retrieved, err := repo.GetByUsername(ctx, "findme")
	if err != nil {
		t.Fatalf("GetByUsername failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected user, got nil")
	}
	if retrieved.Email != user.Email {
		t.Errorf("expected email %s, got %s", user.Email, retrieved.Email)
	}

	// Non-existent username
	retrieved, err = repo.GetByUsername(ctx, "nonexistent")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if retrieved != nil {
		t.Error("expected nil for non-existent username")
	}
}

func TestUserRepository_UpdatePassword(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	user := &models.User{
		Username:              "passuser",
		PasswordHash:          "oldhash",
		RequirePasswordChange: true,
	}
	repo.AddUser(user)

	err := repo.UpdatePassword(ctx, user.ID, "newhash", true)
	if err != nil {
		t.Fatalf("UpdatePassword failed: %v", err)
	}

	retrieved, _ := repo.GetByID(ctx, user.ID)
	if retrieved.PasswordHash != "newhash" {
		t.Error("password should be updated")
	}
	if retrieved.RequirePasswordChange {
		t.Error("RequirePasswordChange should be cleared")
	}
}

func TestUserRepository_UpdatePasswordWithSessionInvalidation(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	user := &models.User{
		Username:     "sessuser",
		PasswordHash: "oldhash",
	}
	repo.AddUser(user)

	// Create session
	err := repo.CreateSession(ctx, user.ID, "token123", time.Now().Add(24*time.Hour), "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Update password with session invalidation
	err = repo.UpdatePasswordWithSessionInvalidation(ctx, user.ID, "newhash", false)
	if err != nil {
		t.Fatalf("UpdatePasswordWithSessionInvalidation failed: %v", err)
	}

	// Session should be deleted
	session, _ := repo.GetSession(ctx, "token123")
	if session != nil {
		t.Error("session should be invalidated")
	}
}

func TestUserRepository_Sessions(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	user := &models.User{Username: "sesstest"}
	repo.AddUser(user)

	// Create session
	expiresAt := time.Now().Add(24 * time.Hour)
	err := repo.CreateSession(ctx, user.ID, "testtoken", expiresAt, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Get session
	session, err := repo.GetSession(ctx, "testtoken")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if session == nil {
		t.Fatal("expected session, got nil")
	}
	if session.UserID != user.ID {
		t.Errorf("expected user ID %d, got %d", user.ID, session.UserID)
	}

	// Update activity
	err = repo.UpdateSessionActivity(ctx, "testtoken")
	if err != nil {
		t.Fatalf("UpdateSessionActivity failed: %v", err)
	}

	// Delete session
	err = repo.DeleteSession(ctx, "testtoken")
	if err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}

	session, _ = repo.GetSession(ctx, "testtoken")
	if session != nil {
		t.Error("session should be deleted")
	}
}

func TestUserRepository_ExpiredSessions(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	user := &models.User{Username: "exptest"}
	repo.AddUser(user)

	// Create expired session
	err := repo.CreateSession(ctx, user.ID, "expired", time.Now().Add(-1*time.Hour), "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Create valid session
	err = repo.CreateSession(ctx, user.ID, "valid", time.Now().Add(24*time.Hour), "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Expired session should return nil
	session, _ := repo.GetSession(ctx, "expired")
	if session != nil {
		t.Error("expired session should return nil")
	}

	// Valid session should work
	session, _ = repo.GetSession(ctx, "valid")
	if session == nil {
		t.Error("valid session should be returned")
	}

	// Cleanup expired
	err = repo.CleanupExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("CleanupExpiredSessions failed: %v", err)
	}
}

func TestUserRepository_UserFiles(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	user := &models.User{Username: "fileuser"}
	repo.AddUser(user)

	// Add user file
	file := &models.File{
		ClaimCode:        "userfile",
		OriginalFilename: "test.txt",
		FileSize:         1024,
	}
	repo.AddUserFile(user.ID, file)

	// Get files
	files, total, err := repo.GetFiles(ctx, user.ID, 10, 0)
	if err != nil {
		t.Fatalf("GetFiles failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 file, got %d", total)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file returned, got %d", len(files))
	}

	// Delete file
	deleted, err := repo.DeleteFile(ctx, file.ID, user.ID)
	if err != nil {
		t.Fatalf("DeleteFile failed: %v", err)
	}
	if deleted.ClaimCode != "userfile" {
		t.Error("wrong file deleted")
	}

	// File should be gone
	files, total, _ = repo.GetFiles(ctx, user.ID, 10, 0)
	if total != 0 {
		t.Error("file should be deleted")
	}
}

func TestUserRepository_DeleteFileByClaimCode(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	user := &models.User{Username: "claimuser"}
	repo.AddUser(user)

	repo.AddUserFile(user.ID, &models.File{
		ClaimCode:        "claimtest",
		OriginalFilename: "test.txt",
	})

	deleted, err := repo.DeleteFileByClaimCode(ctx, "claimtest", user.ID)
	if err != nil {
		t.Fatalf("DeleteFileByClaimCode failed: %v", err)
	}
	if deleted.ClaimCode != "claimtest" {
		t.Error("wrong file deleted")
	}
}

func TestUserRepository_UpdateFileName(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	user := &models.User{Username: "renameuser"}
	repo.AddUser(user)

	file := &models.File{
		ClaimCode:        "renametest",
		OriginalFilename: "old.txt",
	}
	repo.AddUserFile(user.ID, file)

	err := repo.UpdateFileName(ctx, file.ID, user.ID, "new.txt")
	if err != nil {
		t.Fatalf("UpdateFileName failed: %v", err)
	}

	files, _, _ := repo.GetFiles(ctx, user.ID, 10, 0)
	if files[0].OriginalFilename != "new.txt" {
		t.Error("filename should be updated")
	}
}

func TestUserRepository_RegenerateClaimCode(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	user := &models.User{Username: "regenuser"}
	repo.AddUser(user)

	file := &models.File{
		ClaimCode:        "oldcode",
		OriginalFilename: "test.txt",
	}
	repo.AddUserFile(user.ID, file)

	result, err := repo.RegenerateClaimCode(ctx, file.ID, user.ID)
	if err != nil {
		t.Fatalf("RegenerateClaimCode failed: %v", err)
	}

	if result.OldClaimCode != "oldcode" {
		t.Errorf("expected old code oldcode, got %s", result.OldClaimCode)
	}
	if result.NewClaimCode == "oldcode" {
		t.Error("new claim code should be different")
	}
	if result.NewClaimCode == "" {
		t.Error("new claim code should not be empty")
	}
}

func TestUserRepository_Delete(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	user := &models.User{Username: "deleteuser"}
	repo.AddUser(user)

	// Add session and file
	repo.CreateSession(ctx, user.ID, "token", time.Now().Add(24*time.Hour), "127.0.0.1", "test")
	repo.AddUserFile(user.ID, &models.File{ClaimCode: "file"})

	err := repo.Delete(ctx, user.ID, "/tmp")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify user deleted
	retrieved, _ := repo.GetByID(ctx, user.ID)
	if retrieved != nil {
		t.Error("user should be deleted")
	}

	// Verify session deleted
	session, _ := repo.GetSession(ctx, "token")
	if session != nil {
		t.Error("session should be deleted")
	}

	// Verify files deleted
	files, _, _ := repo.GetFiles(ctx, user.ID, 10, 0)
	if len(files) != 0 {
		t.Error("files should be deleted")
	}
}

func TestUserRepository_ErrorInjection(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	testErr := errors.New("test error")

	// Test Create error injection
	repo.CreateError = testErr
	_, err := repo.Create(ctx, "test", "test@example.com", "hash", "user", false)
	if err != testErr {
		t.Errorf("expected injected error, got %v", err)
	}
	repo.CreateError = nil

	// Test GetByID error injection
	repo.GetByIDError = testErr
	_, err = repo.GetByID(ctx, 1)
	if err != testErr {
		t.Errorf("expected injected error, got %v", err)
	}
	repo.GetByIDError = nil
}

func TestUserRepository_Reset(t *testing.T) {
	ctx := context.Background()
	repo := NewUserRepository()

	// Add data
	repo.AddUser(&models.User{Username: "test"})
	repo.CreateSession(ctx, 1, "token", time.Now().Add(24*time.Hour), "127.0.0.1", "test")
	repo.CreateError = errors.New("test")

	// Reset
	repo.Reset()

	// Verify cleared
	if len(repo.GetUsers()) != 0 {
		t.Error("users should be cleared after reset")
	}
	if repo.CreateError != nil {
		t.Error("errors should be cleared after reset")
	}
}

func TestUserRepository_ContextCancellation(t *testing.T) {
	repo := NewUserRepository()
	repo.AddUser(&models.User{ID: 1, Username: "test"})

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Operations should return context error
	_, err := repo.GetByID(ctx, 1)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}
