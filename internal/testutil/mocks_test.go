package testutil

import (
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

func TestNewMockRepositories(t *testing.T) {
	mocks := NewMockRepositories()
	if mocks == nil {
		t.Fatal("NewMockRepositories returned nil")
	}
	if mocks.Files == nil {
		t.Error("Files repository should be initialized")
	}
	if mocks.Users == nil {
		t.Error("Users repository should be initialized")
	}
}

func TestMockRepositories_Reset(t *testing.T) {
	mocks := NewMockRepositories()

	// Add some data
	mocks.Files.AddFile(&models.File{
		ClaimCode: "test",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	mocks.Users.AddUser(&models.User{Username: "testuser"})

	// Reset
	mocks.Reset()

	// Verify cleared
	if len(mocks.Files.GetFiles()) != 0 {
		t.Error("files should be cleared after reset")
	}
	if len(mocks.Users.GetUsers()) != 0 {
		t.Error("users should be cleared after reset")
	}
}

func TestNewMockStorageBackend(t *testing.T) {
	storage := NewMockStorageBackend()
	if storage == nil {
		t.Fatal("NewMockStorageBackend returned nil")
	}
}

func TestNewMockTestEnv(t *testing.T) {
	env := NewMockTestEnv(t)
	if env == nil {
		t.Fatal("NewMockTestEnv returned nil")
	}
	if env.Config == nil {
		t.Error("Config should be initialized")
	}
	if env.Mocks == nil {
		t.Error("Mocks should be initialized")
	}
	if env.Storage == nil {
		t.Error("Storage should be initialized")
	}
}

func TestMockTestEnv_Reset(t *testing.T) {
	env := NewMockTestEnv(t)

	// Add data
	env.Mocks.Files.AddFile(&models.File{
		ClaimCode: "test",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	env.Storage.AddFile("test.txt", []byte("content"))

	// Reset
	env.Reset()

	// Verify cleared
	if len(env.Mocks.Files.GetFiles()) != 0 {
		t.Error("files should be cleared after reset")
	}
	if len(env.Storage.GetAllFiles()) != 0 {
		t.Error("storage should be cleared after reset")
	}
}

func TestSetupMockFile(t *testing.T) {
	mocks := NewMockRepositories()

	file := SetupMockFile(t, mocks.Files)
	if file == nil {
		t.Fatal("SetupMockFile returned nil")
	}
	if file.ID == 0 {
		t.Error("file should have ID assigned")
	}
	if file.ClaimCode == "" {
		t.Error("file should have claim code")
	}

	// Verify in repository
	files := mocks.Files.GetFiles()
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
}

func TestSetupMockFile_WithOptions(t *testing.T) {
	mocks := NewMockRepositories()

	maxDownloads := 5
	userID := int64(123)

	file := SetupMockFile(t, mocks.Files,
		WithClaimCode("custom-code"),
		WithFilename("custom.pdf"),
		WithFileSize(2048),
		WithMimeType("application/pdf"),
		WithMaxDownloads(maxDownloads),
		WithDownloadCount(3),
		WithUserID(userID),
		WithPassword("hashedpass"),
	)

	if file.ClaimCode != "custom-code" {
		t.Errorf("expected claim code custom-code, got %s", file.ClaimCode)
	}
	if file.OriginalFilename != "custom.pdf" {
		t.Errorf("expected filename custom.pdf, got %s", file.OriginalFilename)
	}
	if file.FileSize != 2048 {
		t.Errorf("expected size 2048, got %d", file.FileSize)
	}
	if file.MimeType != "application/pdf" {
		t.Errorf("expected mime application/pdf, got %s", file.MimeType)
	}
	if file.MaxDownloads == nil || *file.MaxDownloads != 5 {
		t.Error("max downloads should be 5")
	}
	if file.DownloadCount != 3 {
		t.Errorf("expected download count 3, got %d", file.DownloadCount)
	}
	if file.UserID == nil || *file.UserID != 123 {
		t.Error("user ID should be 123")
	}
	if file.PasswordHash != "hashedpass" {
		t.Error("password hash should be set")
	}
}

func TestSetupMockFile_WithExpired(t *testing.T) {
	mocks := NewMockRepositories()

	file := SetupMockFile(t, mocks.Files, WithExpired())

	if time.Now().Before(file.ExpiresAt) {
		t.Error("file should be expired")
	}
}

func TestSetupMockFile_WithExpiresAt(t *testing.T) {
	mocks := NewMockRepositories()

	future := time.Now().Add(48 * time.Hour)
	file := SetupMockFile(t, mocks.Files, WithExpiresAt(future))

	if !file.ExpiresAt.Equal(future) {
		t.Error("expiration time should match")
	}
}

func TestSetupMockUser(t *testing.T) {
	mocks := NewMockRepositories()

	user := SetupMockUser(t, mocks.Users)
	if user == nil {
		t.Fatal("SetupMockUser returned nil")
	}
	if user.ID == 0 {
		t.Error("user should have ID assigned")
	}
	if user.Username == "" {
		t.Error("user should have username")
	}

	// Verify in repository
	users := mocks.Users.GetUsers()
	if len(users) != 1 {
		t.Errorf("expected 1 user, got %d", len(users))
	}
}

func TestSetupMockUser_WithOptions(t *testing.T) {
	mocks := NewMockRepositories()

	user := SetupMockUser(t, mocks.Users,
		WithUsername("customuser"),
		WithEmail("custom@example.com"),
		WithRole("admin"),
	)

	if user.Username != "customuser" {
		t.Errorf("expected username customuser, got %s", user.Username)
	}
	if user.Email != "custom@example.com" {
		t.Errorf("expected email custom@example.com, got %s", user.Email)
	}
	if user.Role != "admin" {
		t.Errorf("expected role admin, got %s", user.Role)
	}
}

func TestSetupMockUser_WithAdmin(t *testing.T) {
	mocks := NewMockRepositories()

	user := SetupMockUser(t, mocks.Users, WithAdmin())

	if user.Role != "admin" {
		t.Errorf("expected role admin, got %s", user.Role)
	}
}

func TestSetupMockUser_WithInactive(t *testing.T) {
	mocks := NewMockRepositories()

	user := SetupMockUser(t, mocks.Users, WithInactive())

	if user.IsActive {
		t.Error("user should be inactive")
	}
}

func TestSetupMockUser_WithPasswordChangeRequired(t *testing.T) {
	mocks := NewMockRepositories()

	user := SetupMockUser(t, mocks.Users, WithPasswordChangeRequired())

	if !user.RequirePasswordChange {
		t.Error("user should require password change")
	}
}

func TestSetupMockStorage(t *testing.T) {
	storage := NewMockStorageBackend()
	content := []byte("test content")

	returned := SetupMockStorage(t, storage, "test.txt", content)

	if string(returned) != string(content) {
		t.Error("returned content should match")
	}

	// Verify in storage
	stored, ok := storage.GetFileContent("test.txt")
	if !ok {
		t.Error("file should exist in storage")
	}
	if string(stored) != string(content) {
		t.Error("stored content should match")
	}
}

func TestSetupMockChunks(t *testing.T) {
	storage := NewMockStorageBackend()
	chunks := [][]byte{
		[]byte("chunk0"),
		[]byte("chunk1"),
		[]byte("chunk2"),
	}

	SetupMockChunks(t, storage, "upload1", chunks)

	// Verify chunks
	for i, expected := range chunks {
		stored, ok := storage.GetChunkContent("upload1", i)
		if !ok {
			t.Errorf("chunk %d should exist", i)
		}
		if string(stored) != string(expected) {
			t.Errorf("chunk %d content should match", i)
		}
	}
}
