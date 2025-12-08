package testutil

import (
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	repoMock "github.com/fjmerc/safeshare/internal/repository/mock"
	"github.com/fjmerc/safeshare/internal/storage"
	storageMock "github.com/fjmerc/safeshare/internal/storage/mock"
)

// MockRepositories contains all mock repository implementations for testing.
// This provides a convenient way to set up and access mocks in tests.
type MockRepositories struct {
	Files *repoMock.FileRepository
	Users *repoMock.UserRepository
	// Note: Admin, Settings, PartialUploads, Webhooks, APITokens mocks
	// can be added here as needed in future iterations
}

// NewMockRepositories creates a new set of mock repositories for testing.
func NewMockRepositories() *MockRepositories {
	return &MockRepositories{
		Files: repoMock.NewFileRepository(),
		Users: repoMock.NewUserRepository(),
	}
}

// Reset clears all mock repositories to a fresh state.
func (m *MockRepositories) Reset() {
	m.Files.Reset()
	m.Users.Reset()
}

// NewMockStorageBackend creates a new mock storage backend for testing.
func NewMockStorageBackend() *storageMock.StorageBackend {
	return storageMock.NewStorageBackend()
}

// MockTestEnv provides a complete mock test environment including
// configuration, mock repositories, and mock storage.
type MockTestEnv struct {
	Config   *config.Config
	Mocks    *MockRepositories
	Storage  *storageMock.StorageBackend
}

// NewMockTestEnv creates a new mock test environment for testing.
// This is useful for unit tests that don't need a real database.
func NewMockTestEnv(t *testing.T) *MockTestEnv {
	t.Helper()

	cfg := SetupTestConfig(t)
	mocks := NewMockRepositories()
	storage := NewMockStorageBackend()

	return &MockTestEnv{
		Config:  cfg,
		Mocks:   mocks,
		Storage: storage,
	}
}

// Reset clears all mock state for a fresh test.
func (env *MockTestEnv) Reset() {
	env.Mocks.Reset()
	env.Storage.Reset()
}

// SetupMockFile creates a test file in the mock repository with sensible defaults.
// Returns the created file.
func SetupMockFile(t *testing.T, fileRepo *repoMock.FileRepository, opts ...MockFileOption) *models.File {
	t.Helper()

	file := &models.File{
		ClaimCode:        "test-claim-code",
		OriginalFilename: "test-file.txt",
		StoredFilename:   "stored-test-file.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		DownloadCount:    0,
		UploaderIP:       "127.0.0.1",
	}

	// Apply options
	for _, opt := range opts {
		opt(file)
	}

	fileRepo.AddFile(file)
	return file
}

// MockFileOption is a function that modifies a File for testing.
type MockFileOption func(*models.File)

// WithClaimCode sets the claim code on a mock file.
func WithClaimCode(code string) MockFileOption {
	return func(f *models.File) {
		f.ClaimCode = code
	}
}

// WithFilename sets the original filename on a mock file.
func WithFilename(name string) MockFileOption {
	return func(f *models.File) {
		f.OriginalFilename = name
	}
}

// WithFileSize sets the file size on a mock file.
func WithFileSize(size int64) MockFileOption {
	return func(f *models.File) {
		f.FileSize = size
	}
}

// WithMimeType sets the MIME type on a mock file.
func WithMimeType(mimeType string) MockFileOption {
	return func(f *models.File) {
		f.MimeType = mimeType
	}
}

// WithExpiresAt sets the expiration time on a mock file.
func WithExpiresAt(t time.Time) MockFileOption {
	return func(f *models.File) {
		f.ExpiresAt = t
	}
}

// WithExpired creates a mock file that has already expired.
func WithExpired() MockFileOption {
	return func(f *models.File) {
		f.ExpiresAt = time.Now().Add(-1 * time.Hour)
	}
}

// WithMaxDownloads sets the max downloads limit on a mock file.
func WithMaxDownloads(max int) MockFileOption {
	return func(f *models.File) {
		f.MaxDownloads = &max
	}
}

// WithDownloadCount sets the download count on a mock file.
func WithDownloadCount(count int) MockFileOption {
	return func(f *models.File) {
		f.DownloadCount = count
	}
}

// WithUserID sets the user ID on a mock file.
func WithUserID(userID int64) MockFileOption {
	return func(f *models.File) {
		f.UserID = &userID
	}
}

// WithPassword sets a password hash on a mock file.
func WithPassword(hash string) MockFileOption {
	return func(f *models.File) {
		f.PasswordHash = hash
	}
}

// SetupMockUser creates a test user in the mock repository with sensible defaults.
// Returns the created user.
func SetupMockUser(t *testing.T, userRepo *repoMock.UserRepository, opts ...MockUserOption) *models.User {
	t.Helper()

	user := &models.User{
		Username:              "testuser",
		Email:                 "test@example.com",
		PasswordHash:          "$2a$10$mockhash", // Mock bcrypt hash
		Role:                  "user",
		IsApproved:            true,
		IsActive:              true,
		RequirePasswordChange: false,
		CreatedAt:             time.Now(),
	}

	// Apply options
	for _, opt := range opts {
		opt(user)
	}

	userRepo.AddUser(user)
	return user
}

// MockUserOption is a function that modifies a User for testing.
type MockUserOption func(*models.User)

// WithUsername sets the username on a mock user.
func WithUsername(name string) MockUserOption {
	return func(u *models.User) {
		u.Username = name
	}
}

// WithEmail sets the email on a mock user.
func WithEmail(email string) MockUserOption {
	return func(u *models.User) {
		u.Email = email
	}
}

// WithRole sets the role on a mock user.
func WithRole(role string) MockUserOption {
	return func(u *models.User) {
		u.Role = role
	}
}

// WithAdmin sets the user as an admin.
func WithAdmin() MockUserOption {
	return func(u *models.User) {
		u.Role = "admin"
	}
}

// WithInactive sets the user as inactive.
func WithInactive() MockUserOption {
	return func(u *models.User) {
		u.IsActive = false
	}
}

// WithPasswordChangeRequired sets the require_password_change flag.
func WithPasswordChangeRequired() MockUserOption {
	return func(u *models.User) {
		u.RequirePasswordChange = true
	}
}

// SetupMockStorage adds a file to the mock storage backend.
// Returns the content for verification.
func SetupMockStorage(t *testing.T, storage *storageMock.StorageBackend, filename string, content []byte) []byte {
	t.Helper()

	storage.AddFile(filename, content)
	return content
}

// SetupMockChunks adds chunks for a mock upload session.
func SetupMockChunks(t *testing.T, storage *storageMock.StorageBackend, uploadID string, chunks [][]byte) {
	t.Helper()

	for i, chunk := range chunks {
		storage.AddChunk(uploadID, i, chunk)
	}
}

// MockFileRepository is an alias to repoMock.FileRepository for convenience.
type MockFileRepository = repoMock.FileRepository

// MockUserRepository is an alias to repoMock.UserRepository for convenience.
type MockUserRepository = repoMock.UserRepository

// MockStorageBackend is an alias to storageMock.StorageBackend for convenience.
type MockStorageBackend = storageMock.StorageBackend

// Verify interface implementations at compile time
var (
	_ repository.FileRepository = (*repoMock.FileRepository)(nil)
	_ repository.UserRepository = (*repoMock.UserRepository)(nil)
	_ storage.StorageBackend    = (*storageMock.StorageBackend)(nil)
)
