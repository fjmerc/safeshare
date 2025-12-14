package mock

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// UserRepository is a mock implementation of repository.UserRepository for testing.
// It stores users and sessions in memory and provides configurable behavior for tests.
//
// IMPORTANT: Error injection fields and hooks should be set BEFORE any concurrent
// operations begin. They are not protected by the mutex for performance reasons.
type UserRepository struct {
	mu sync.RWMutex

	// Storage
	users      map[int64]*models.User           // by ID
	byUsername map[string]*models.User          // by username (separate copy)
	sessions   map[string]*models.UserSession   // by token
	userFiles  map[int64]map[int64]*models.File // userID -> fileID -> file
	nextUserID int64
	nextFileID int64

	// Error injection for testing
	// NOTE: Set these BEFORE concurrent access begins
	CreateError                         error
	GetByIDError                        error
	GetByUsernameError                  error
	UpdateLastLoginError                error
	UpdatePasswordError                 error
	UpdatePasswordWithSessionInvError   error
	UpdateError                         error
	SetActiveError                      error
	DeleteError                         error
	GetAllError                         error
	CreateSessionError                  error
	GetSessionError                     error
	UpdateSessionActivityError          error
	DeleteSessionError                  error
	DeleteSessionsByUserIDError         error
	CleanupExpiredSessionsError         error
	GetFilesError                       error
	DeleteFileError                     error
	DeleteFileByClaimCodeError          error
	UpdateFileNameError                 error
	UpdateFileNameByClaimCodeError      error
	UpdateFileExpirationError           error
	UpdateFileExpirationByClaimCodeErr  error
	GetFileByClaimCodeError             error
	RegenerateClaimCodeError            error
	RegenerateClaimCodeByClaimCodeError error

	// Custom behavior hooks
	// NOTE: Set these BEFORE concurrent access begins
	OnCreate        func(ctx context.Context, username, email, passwordHash, role string, requirePasswordChange bool) (*models.User, error)
	OnGetByID       func(ctx context.Context, id int64) (*models.User, error)
	OnGetByUsername func(ctx context.Context, username string) (*models.User, error)
	OnGetSession    func(ctx context.Context, token string) (*models.UserSession, error)
}

// NewUserRepository creates a new mock UserRepository with default behavior.
func NewUserRepository() *UserRepository {
	return &UserRepository{
		users:      make(map[int64]*models.User),
		byUsername: make(map[string]*models.User),
		sessions:   make(map[string]*models.UserSession),
		userFiles:  make(map[int64]map[int64]*models.File),
		nextUserID: 1,
		nextFileID: 1,
	}
}

// Ensure UserRepository implements repository.UserRepository
var _ repository.UserRepository = (*UserRepository)(nil)

// Reset clears all users, sessions, and errors for a fresh test state.
func (r *UserRepository) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.users = make(map[int64]*models.User)
	r.byUsername = make(map[string]*models.User)
	r.sessions = make(map[string]*models.UserSession)
	r.userFiles = make(map[int64]map[int64]*models.File)
	r.nextUserID = 1
	r.nextFileID = 1

	// Clear all errors
	r.CreateError = nil
	r.GetByIDError = nil
	r.GetByUsernameError = nil
	r.UpdateLastLoginError = nil
	r.UpdatePasswordError = nil
	r.UpdatePasswordWithSessionInvError = nil
	r.UpdateError = nil
	r.SetActiveError = nil
	r.DeleteError = nil
	r.GetAllError = nil
	r.CreateSessionError = nil
	r.GetSessionError = nil
	r.UpdateSessionActivityError = nil
	r.DeleteSessionError = nil
	r.DeleteSessionsByUserIDError = nil
	r.CleanupExpiredSessionsError = nil
	r.GetFilesError = nil
	r.DeleteFileError = nil
	r.DeleteFileByClaimCodeError = nil
	r.UpdateFileNameError = nil
	r.UpdateFileNameByClaimCodeError = nil
	r.UpdateFileExpirationError = nil
	r.UpdateFileExpirationByClaimCodeErr = nil
	r.GetFileByClaimCodeError = nil
	r.RegenerateClaimCodeError = nil
	r.RegenerateClaimCodeByClaimCodeError = nil

	// Clear hooks
	r.OnCreate = nil
	r.OnGetByID = nil
	r.OnGetByUsername = nil
	r.OnGetSession = nil
}

// deepCopyUser creates a deep copy of a user including pointer fields.
func deepCopyUser(src *models.User) *models.User {
	if src == nil {
		return nil
	}
	dst := *src
	if src.LastLogin != nil {
		lastLogin := *src.LastLogin
		dst.LastLogin = &lastLogin
	}
	return &dst
}

// deepCopySession creates a deep copy of a session.
func deepCopySession(src *models.UserSession) *models.UserSession {
	if src == nil {
		return nil
	}
	dst := *src
	return &dst
}

// AddUser directly adds a user to the mock repository for test setup.
func (r *UserRepository) AddUser(user *models.User) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if user.ID == 0 {
		user.ID = r.nextUserID
		r.nextUserID++
	}
	if user.ID >= r.nextUserID {
		r.nextUserID = user.ID + 1
	}

	// Store separate copies in each map
	r.users[user.ID] = deepCopyUser(user)
	r.byUsername[user.Username] = deepCopyUser(user)
}

// AddUserFile adds a file owned by a user for test setup.
func (r *UserRepository) AddUserFile(userID int64, file *models.File) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if file.ID == 0 {
		file.ID = r.nextFileID
		r.nextFileID++
	}
	if file.ID >= r.nextFileID {
		r.nextFileID = file.ID + 1
	}

	if r.userFiles[userID] == nil {
		r.userFiles[userID] = make(map[int64]*models.File)
	}

	uid := userID
	file.UserID = &uid
	r.userFiles[userID][file.ID] = deepCopyFile(file)
}

// GetUsers returns all users in the mock repository.
func (r *UserRepository) GetUsers() []*models.User {
	r.mu.RLock()
	defer r.mu.RUnlock()

	users := make([]*models.User, 0, len(r.users))
	for _, u := range r.users {
		users = append(users, deepCopyUser(u))
	}
	return users
}

// Create implements repository.UserRepository.Create
func (r *UserRepository) Create(ctx context.Context, username, email, passwordHash, role string, requirePasswordChange bool) (*models.User, error) {
	if r.CreateError != nil {
		return nil, r.CreateError
	}

	if r.OnCreate != nil {
		return r.OnCreate(ctx, username, email, passwordHash, role, requirePasswordChange)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Check for duplicate username
	if _, exists := r.byUsername[username]; exists {
		return nil, repository.ErrDuplicateKey
	}

	user := &models.User{
		ID:                    r.nextUserID,
		Username:              username,
		Email:                 email,
		PasswordHash:          passwordHash,
		Role:                  role,
		IsApproved:            true,
		IsActive:              true,
		RequirePasswordChange: requirePasswordChange,
		CreatedAt:             time.Now(),
	}
	r.nextUserID++

	// Store separate copies in each map
	r.users[user.ID] = deepCopyUser(user)
	r.byUsername[user.Username] = deepCopyUser(user)

	return deepCopyUser(user), nil
}

// GetByID implements repository.UserRepository.GetByID
func (r *UserRepository) GetByID(ctx context.Context, id int64) (*models.User, error) {
	if r.GetByIDError != nil {
		return nil, r.GetByIDError
	}

	if r.OnGetByID != nil {
		return r.OnGetByID(ctx, id)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	user, exists := r.users[id]
	if !exists {
		return nil, nil // Match SQLite behavior
	}

	return deepCopyUser(user), nil
}

// GetByUsername implements repository.UserRepository.GetByUsername
func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	if r.GetByUsernameError != nil {
		return nil, r.GetByUsernameError
	}

	if r.OnGetByUsername != nil {
		return r.OnGetByUsername(ctx, username)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	user, exists := r.byUsername[username]
	if !exists {
		return nil, nil // Match SQLite behavior
	}

	return deepCopyUser(user), nil
}

// UpdateLastLogin implements repository.UserRepository.UpdateLastLogin
func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID int64) error {
	if r.UpdateLastLoginError != nil {
		return r.UpdateLastLoginError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	user, exists := r.users[userID]
	if !exists {
		return repository.ErrNotFound
	}

	now := time.Now()
	user.LastLogin = &now
	// Update byUsername map separately
	if u, ok := r.byUsername[user.Username]; ok {
		u.LastLogin = &now
	}

	return nil
}

// UpdatePassword implements repository.UserRepository.UpdatePassword
func (r *UserRepository) UpdatePassword(ctx context.Context, userID int64, passwordHash string, clearPasswordChangeFlag bool) error {
	if r.UpdatePasswordError != nil {
		return r.UpdatePasswordError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	user, exists := r.users[userID]
	if !exists {
		return repository.ErrNotFound
	}

	user.PasswordHash = passwordHash
	if clearPasswordChangeFlag {
		user.RequirePasswordChange = false
	}

	// Update byUsername map separately
	if u, ok := r.byUsername[user.Username]; ok {
		u.PasswordHash = passwordHash
		if clearPasswordChangeFlag {
			u.RequirePasswordChange = false
		}
	}

	return nil
}

// UpdatePasswordWithSessionInvalidation implements repository.UserRepository.UpdatePasswordWithSessionInvalidation
func (r *UserRepository) UpdatePasswordWithSessionInvalidation(ctx context.Context, userID int64, passwordHash string, clearPasswordChangeFlag bool) error {
	if r.UpdatePasswordWithSessionInvError != nil {
		return r.UpdatePasswordWithSessionInvError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	user, exists := r.users[userID]
	if !exists {
		return repository.ErrNotFound
	}

	// Update password
	user.PasswordHash = passwordHash
	if clearPasswordChangeFlag {
		user.RequirePasswordChange = false
	}

	// Update byUsername map
	if u, ok := r.byUsername[user.Username]; ok {
		u.PasswordHash = passwordHash
		if clearPasswordChangeFlag {
			u.RequirePasswordChange = false
		}
	}

	// Delete all sessions for this user
	for token, session := range r.sessions {
		if session.UserID == userID {
			delete(r.sessions, token)
		}
	}

	return nil
}

// Update implements repository.UserRepository.Update
func (r *UserRepository) Update(ctx context.Context, userID int64, username, email, role string) error {
	if r.UpdateError != nil {
		return r.UpdateError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	user, exists := r.users[userID]
	if !exists {
		return repository.ErrNotFound
	}

	// Check if new username conflicts with existing user
	oldUsername := user.Username
	if username != oldUsername {
		if _, exists := r.byUsername[username]; exists {
			return repository.ErrDuplicateKey
		}
		delete(r.byUsername, oldUsername)
	}

	user.Username = username
	user.Email = email
	user.Role = role

	// Store updated user in byUsername map
	r.byUsername[username] = deepCopyUser(user)

	return nil
}

// SetActive implements repository.UserRepository.SetActive
func (r *UserRepository) SetActive(ctx context.Context, userID int64, isActive bool) error {
	if r.SetActiveError != nil {
		return r.SetActiveError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	user, exists := r.users[userID]
	if !exists {
		return repository.ErrNotFound
	}

	user.IsActive = isActive
	// Update byUsername map
	if u, ok := r.byUsername[user.Username]; ok {
		u.IsActive = isActive
	}

	return nil
}

// Delete implements repository.UserRepository.Delete
func (r *UserRepository) Delete(ctx context.Context, userID int64, uploadDir string) error {
	if r.DeleteError != nil {
		return r.DeleteError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	user, exists := r.users[userID]
	if !exists {
		return repository.ErrNotFound
	}

	// Delete sessions
	for token, session := range r.sessions {
		if session.UserID == userID {
			delete(r.sessions, token)
		}
	}

	// Delete user files
	delete(r.userFiles, userID)

	// Delete user
	delete(r.byUsername, user.Username)
	delete(r.users, userID)

	return nil
}

// GetAll implements repository.UserRepository.GetAll
func (r *UserRepository) GetAll(ctx context.Context, limit, offset int) ([]models.UserListItem, int, error) {
	if r.GetAllError != nil {
		return nil, 0, r.GetAllError
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	default:
	}

	// Collect all users
	allUsers := make([]models.UserListItem, 0, len(r.users))
	for _, u := range r.users {
		fileCount := 0
		if files, ok := r.userFiles[u.ID]; ok {
			fileCount = len(files)
		}

		item := models.UserListItem{
			ID:        u.ID,
			Username:  u.Username,
			Email:     u.Email,
			Role:      u.Role,
			IsActive:  u.IsActive,
			CreatedAt: u.CreatedAt,
			FileCount: fileCount,
		}
		if u.LastLogin != nil {
			lastLogin := *u.LastLogin
			item.LastLogin = &lastLogin
		}
		allUsers = append(allUsers, item)
	}

	total := len(allUsers)

	// Apply pagination
	if offset >= len(allUsers) {
		return []models.UserListItem{}, total, nil
	}

	end := offset + limit
	if end > len(allUsers) {
		end = len(allUsers)
	}

	return allUsers[offset:end], total, nil
}

// CreateSession implements repository.UserRepository.CreateSession
func (r *UserRepository) CreateSession(ctx context.Context, userID int64, token string, expiresAt time.Time, ipAddress, userAgent string) error {
	if r.CreateSessionError != nil {
		return r.CreateSessionError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	session := &models.UserSession{
		UserID:       userID,
		SessionToken: token,
		CreatedAt:    time.Now(),
		ExpiresAt:    expiresAt,
		LastActivity: time.Now(),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
	}

	r.sessions[token] = session
	return nil
}

// GetSession implements repository.UserRepository.GetSession
func (r *UserRepository) GetSession(ctx context.Context, token string) (*models.UserSession, error) {
	if r.GetSessionError != nil {
		return nil, r.GetSessionError
	}

	if r.OnGetSession != nil {
		return r.OnGetSession(ctx, token)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	session, exists := r.sessions[token]
	if !exists {
		return nil, nil // Match SQLite behavior
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		return nil, nil
	}

	return deepCopySession(session), nil
}

// UpdateSessionActivity implements repository.UserRepository.UpdateSessionActivity
func (r *UserRepository) UpdateSessionActivity(ctx context.Context, token string) error {
	if r.UpdateSessionActivityError != nil {
		return r.UpdateSessionActivityError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	session, exists := r.sessions[token]
	if !exists {
		return repository.ErrNotFound
	}

	session.LastActivity = time.Now()
	return nil
}

// DeleteSession implements repository.UserRepository.DeleteSession
func (r *UserRepository) DeleteSession(ctx context.Context, token string) error {
	if r.DeleteSessionError != nil {
		return r.DeleteSessionError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	delete(r.sessions, token)
	return nil
}

// DeleteSessionsByUserID implements repository.UserRepository.DeleteSessionsByUserID
func (r *UserRepository) DeleteSessionsByUserID(ctx context.Context, userID int64) error {
	if r.DeleteSessionsByUserIDError != nil {
		return r.DeleteSessionsByUserIDError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	for token, session := range r.sessions {
		if session.UserID == userID {
			delete(r.sessions, token)
		}
	}

	return nil
}

// CleanupExpiredSessions implements repository.UserRepository.CleanupExpiredSessions
func (r *UserRepository) CleanupExpiredSessions(ctx context.Context) error {
	if r.CleanupExpiredSessionsError != nil {
		return r.CleanupExpiredSessionsError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	now := time.Now()
	for token, session := range r.sessions {
		if now.After(session.ExpiresAt) {
			delete(r.sessions, token)
		}
	}

	return nil
}

// GetFiles implements repository.UserRepository.GetFiles
func (r *UserRepository) GetFiles(ctx context.Context, userID int64, limit, offset int) ([]models.File, int, error) {
	if r.GetFilesError != nil {
		return nil, 0, r.GetFilesError
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	default:
	}

	files, ok := r.userFiles[userID]
	if !ok {
		return []models.File{}, 0, nil
	}

	allFiles := make([]models.File, 0, len(files))
	for _, f := range files {
		allFiles = append(allFiles, *deepCopyFile(f))
	}

	total := len(allFiles)

	if offset >= len(allFiles) {
		return []models.File{}, total, nil
	}

	end := offset + limit
	if end > len(allFiles) {
		end = len(allFiles)
	}

	return allFiles[offset:end], total, nil
}

// DeleteFile implements repository.UserRepository.DeleteFile
func (r *UserRepository) DeleteFile(ctx context.Context, fileID, userID int64) (*models.File, error) {
	if r.DeleteFileError != nil {
		return nil, r.DeleteFileError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	files, ok := r.userFiles[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}

	file, exists := files[fileID]
	if !exists {
		return nil, repository.ErrNotFound
	}

	fileCopy := deepCopyFile(file)
	delete(files, fileID)

	return fileCopy, nil
}

// DeleteFileByClaimCode implements repository.UserRepository.DeleteFileByClaimCode
func (r *UserRepository) DeleteFileByClaimCode(ctx context.Context, claimCode string, userID int64) (*models.File, error) {
	if r.DeleteFileByClaimCodeError != nil {
		return nil, r.DeleteFileByClaimCodeError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	files, ok := r.userFiles[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}

	for id, file := range files {
		if file.ClaimCode == claimCode {
			fileCopy := deepCopyFile(file)
			delete(files, id)
			return fileCopy, nil
		}
	}

	return nil, repository.ErrNotFound
}

// UpdateFileName implements repository.UserRepository.UpdateFileName
func (r *UserRepository) UpdateFileName(ctx context.Context, fileID, userID int64, newFilename string) error {
	if r.UpdateFileNameError != nil {
		return r.UpdateFileNameError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	files, ok := r.userFiles[userID]
	if !ok {
		return repository.ErrNotFound
	}

	file, exists := files[fileID]
	if !exists {
		return repository.ErrNotFound
	}

	file.OriginalFilename = newFilename
	return nil
}

// UpdateFileNameByClaimCode implements repository.UserRepository.UpdateFileNameByClaimCode
func (r *UserRepository) UpdateFileNameByClaimCode(ctx context.Context, claimCode string, userID int64, newFilename string) error {
	if r.UpdateFileNameByClaimCodeError != nil {
		return r.UpdateFileNameByClaimCodeError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	files, ok := r.userFiles[userID]
	if !ok {
		return repository.ErrNotFound
	}

	for _, file := range files {
		if file.ClaimCode == claimCode {
			file.OriginalFilename = newFilename
			return nil
		}
	}

	return repository.ErrNotFound
}

// UpdateFileExpiration implements repository.UserRepository.UpdateFileExpiration
func (r *UserRepository) UpdateFileExpiration(ctx context.Context, fileID, userID int64, newExpiration time.Time) error {
	if r.UpdateFileExpirationError != nil {
		return r.UpdateFileExpirationError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	files, ok := r.userFiles[userID]
	if !ok {
		return repository.ErrNotFound
	}

	file, exists := files[fileID]
	if !exists {
		return repository.ErrNotFound
	}

	file.ExpiresAt = newExpiration
	return nil
}

// UpdateFileExpirationByClaimCode implements repository.UserRepository.UpdateFileExpirationByClaimCode
func (r *UserRepository) UpdateFileExpirationByClaimCode(ctx context.Context, claimCode string, userID int64, newExpiration time.Time) error {
	if r.UpdateFileExpirationByClaimCodeErr != nil {
		return r.UpdateFileExpirationByClaimCodeErr
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	files, ok := r.userFiles[userID]
	if !ok {
		return repository.ErrNotFound
	}

	for _, file := range files {
		if file.ClaimCode == claimCode {
			file.ExpiresAt = newExpiration
			return nil
		}
	}

	return repository.ErrNotFound
}

// GetFileByClaimCode implements repository.UserRepository.GetFileByClaimCode
func (r *UserRepository) GetFileByClaimCode(ctx context.Context, claimCode string, userID int64) (*models.File, error) {
	if r.GetFileByClaimCodeError != nil {
		return nil, r.GetFileByClaimCodeError
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	files, ok := r.userFiles[userID]
	if !ok {
		return nil, nil
	}

	for _, file := range files {
		if file.ClaimCode == claimCode {
			return deepCopyFile(file), nil
		}
	}

	return nil, nil
}

// RegenerateClaimCode implements repository.UserRepository.RegenerateClaimCode
func (r *UserRepository) RegenerateClaimCode(ctx context.Context, fileID, userID int64) (*repository.ClaimCodeRegenerationResult, error) {
	if r.RegenerateClaimCodeError != nil {
		return nil, r.RegenerateClaimCodeError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	files, ok := r.userFiles[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}

	file, exists := files[fileID]
	if !exists {
		return nil, repository.ErrNotFound
	}

	oldClaimCode := file.ClaimCode
	newClaimCode := generateMockClaimCode()

	file.ClaimCode = newClaimCode

	return &repository.ClaimCodeRegenerationResult{
		NewClaimCode:     newClaimCode,
		OldClaimCode:     oldClaimCode,
		FileID:           fileID,
		OriginalFilename: file.OriginalFilename,
	}, nil
}

// RegenerateClaimCodeByClaimCode implements repository.UserRepository.RegenerateClaimCodeByClaimCode
func (r *UserRepository) RegenerateClaimCodeByClaimCode(ctx context.Context, oldClaimCode string, userID int64) (*repository.ClaimCodeRegenerationResult, error) {
	if r.RegenerateClaimCodeByClaimCodeError != nil {
		return nil, r.RegenerateClaimCodeByClaimCodeError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	files, ok := r.userFiles[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}

	for _, file := range files {
		if file.ClaimCode == oldClaimCode {
			newClaimCode := generateMockClaimCode()
			file.ClaimCode = newClaimCode

			return &repository.ClaimCodeRegenerationResult{
				NewClaimCode:     newClaimCode,
				OldClaimCode:     oldClaimCode,
				FileID:           file.ID,
				OriginalFilename: file.OriginalFilename,
			}, nil
		}
	}

	return nil, repository.ErrNotFound
}

// generateMockClaimCode generates a random claim code for testing
func generateMockClaimCode() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based code if crypto/rand fails
		return "mock" + time.Now().Format("20060102150405.000000")
	}
	return base64.URLEncoding.EncodeToString(b)[:16]
}
