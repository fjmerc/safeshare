// Package mock provides mock implementations of repository interfaces for testing.
// These mocks allow tests to run without a real database and provide
// configurable behavior for testing error conditions and edge cases.
//
// IMPORTANT: Error injection fields (e.g., CreateError) and hooks (e.g., OnCreate)
// should be set BEFORE any concurrent operations begin. They are not protected
// by the mutex for performance reasons in typical test scenarios.
package mock

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// FileRepository is a mock implementation of repository.FileRepository for testing.
// It stores files in memory and provides configurable behavior for tests.
type FileRepository struct {
	mu sync.RWMutex

	// Storage
	files       map[int64]*models.File  // by ID
	byClaimCode map[string]*models.File // by claim code (separate copy from files map)
	nextID      int64

	// Error injection for testing error handling
	// NOTE: Set these BEFORE concurrent access begins
	CreateError                          error
	CreateWithQuotaCheckError            error
	GetByIDError                         error
	GetByClaimCodeError                  error
	IncrementDownloadCountError          error
	IncrementDownloadCountIfUnchangedErr error
	TryIncrementDownloadWithLimitError   error
	IncrementCompletedDownloadsError     error
	DeleteError                          error
	DeleteByClaimCodeError               error
	DeleteByClaimCodesError              error
	DeleteExpiredError                   error
	GetTotalUsageError                   error
	GetStatsError                        error
	GetAllError                          error
	GetAllStoredFilenamesError           error
	GetAllForAdminError                  error
	SearchForAdminError                  error

	// Custom behavior hooks
	// NOTE: Set these BEFORE concurrent access begins
	OnCreate               func(ctx context.Context, file *models.File) error
	OnGetByID              func(ctx context.Context, id int64) (*models.File, error)
	OnGetByClaimCode       func(ctx context.Context, claimCode string) (*models.File, error)
	OnDeleteExpired        func(ctx context.Context, uploadDir string, onExpired repository.ExpiredFileCallback) (int, error)
	OnTryIncrementDownload func(ctx context.Context, id int64, claimCode string) (bool, error)
}

// NewFileRepository creates a new mock FileRepository with default behavior.
func NewFileRepository() *FileRepository {
	return &FileRepository{
		files:       make(map[int64]*models.File),
		byClaimCode: make(map[string]*models.File),
		nextID:      1,
	}
}

// Ensure FileRepository implements repository.FileRepository
var _ repository.FileRepository = (*FileRepository)(nil)

// Reset clears all files and errors for a fresh test state.
func (r *FileRepository) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.files = make(map[int64]*models.File)
	r.byClaimCode = make(map[string]*models.File)
	r.nextID = 1

	// Clear error injection
	r.CreateError = nil
	r.CreateWithQuotaCheckError = nil
	r.GetByIDError = nil
	r.GetByClaimCodeError = nil
	r.IncrementDownloadCountError = nil
	r.IncrementDownloadCountIfUnchangedErr = nil
	r.TryIncrementDownloadWithLimitError = nil
	r.IncrementCompletedDownloadsError = nil
	r.DeleteError = nil
	r.DeleteByClaimCodeError = nil
	r.DeleteByClaimCodesError = nil
	r.DeleteExpiredError = nil
	r.GetTotalUsageError = nil
	r.GetStatsError = nil
	r.GetAllError = nil
	r.GetAllStoredFilenamesError = nil
	r.GetAllForAdminError = nil
	r.SearchForAdminError = nil

	// Clear hooks
	r.OnCreate = nil
	r.OnGetByID = nil
	r.OnGetByClaimCode = nil
	r.OnDeleteExpired = nil
	r.OnTryIncrementDownload = nil
}

// deepCopyFile creates a deep copy of a file including pointer fields.
func deepCopyFile(src *models.File) *models.File {
	if src == nil {
		return nil
	}
	dst := *src
	if src.MaxDownloads != nil {
		maxDl := *src.MaxDownloads
		dst.MaxDownloads = &maxDl
	}
	if src.UserID != nil {
		uid := *src.UserID
		dst.UserID = &uid
	}
	if src.Username != nil {
		uname := *src.Username
		dst.Username = &uname
	}
	return &dst
}

// AddFile directly adds a file to the mock repository for test setup.
func (r *FileRepository) AddFile(file *models.File) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if file.ID == 0 {
		file.ID = r.nextID
		r.nextID++
	}
	if file.ID >= r.nextID {
		r.nextID = file.ID + 1
	}

	// Deep copy to avoid shared state - store separate copies in each map
	r.files[file.ID] = deepCopyFile(file)
	if file.ClaimCode != "" {
		r.byClaimCode[file.ClaimCode] = deepCopyFile(file)
	}
}

// GetFiles returns all files in the mock repository.
func (r *FileRepository) GetFiles() []*models.File {
	r.mu.RLock()
	defer r.mu.RUnlock()

	files := make([]*models.File, 0, len(r.files))
	for _, f := range r.files {
		files = append(files, deepCopyFile(f))
	}
	return files
}

// Create implements repository.FileRepository.Create
func (r *FileRepository) Create(ctx context.Context, file *models.File) error {
	if r.CreateError != nil {
		return r.CreateError
	}

	if r.OnCreate != nil {
		return r.OnCreate(ctx, file)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Check for duplicate claim code
	if _, exists := r.byClaimCode[file.ClaimCode]; exists {
		return repository.ErrDuplicateKey
	}

	file.ID = r.nextID
	r.nextID++
	if file.CreatedAt.IsZero() {
		file.CreatedAt = time.Now()
	}

	// Store separate copies in each map
	r.files[file.ID] = deepCopyFile(file)
	r.byClaimCode[file.ClaimCode] = deepCopyFile(file)

	return nil
}

// CreateWithQuotaCheck implements repository.FileRepository.CreateWithQuotaCheck
func (r *FileRepository) CreateWithQuotaCheck(ctx context.Context, file *models.File, quotaLimitBytes int64) error {
	if r.CreateWithQuotaCheckError != nil {
		return r.CreateWithQuotaCheckError
	}

	// Check quota
	r.mu.RLock()
	var totalUsage int64
	for _, f := range r.files {
		totalUsage += f.FileSize
	}
	r.mu.RUnlock()

	if quotaLimitBytes > 0 && totalUsage+file.FileSize > quotaLimitBytes {
		return repository.ErrQuotaExceeded
	}

	return r.Create(ctx, file)
}

// GetByID implements repository.FileRepository.GetByID
func (r *FileRepository) GetByID(ctx context.Context, id int64) (*models.File, error) {
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

	file, exists := r.files[id]
	if !exists {
		return nil, repository.ErrNotFound
	}

	// Return a deep copy
	return deepCopyFile(file), nil
}

// GetByClaimCode implements repository.FileRepository.GetByClaimCode
func (r *FileRepository) GetByClaimCode(ctx context.Context, claimCode string) (*models.File, error) {
	if r.GetByClaimCodeError != nil {
		return nil, r.GetByClaimCodeError
	}

	if r.OnGetByClaimCode != nil {
		return r.OnGetByClaimCode(ctx, claimCode)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	file, exists := r.byClaimCode[claimCode]
	if !exists {
		return nil, nil // Matches SQLite behavior
	}

	// Check if expired
	if time.Now().After(file.ExpiresAt) {
		return nil, nil
	}

	// Return a deep copy
	return deepCopyFile(file), nil
}

// IncrementDownloadCount implements repository.FileRepository.IncrementDownloadCount
func (r *FileRepository) IncrementDownloadCount(ctx context.Context, id int64) error {
	if r.IncrementDownloadCountError != nil {
		return r.IncrementDownloadCountError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	file, exists := r.files[id]
	if !exists {
		return repository.ErrNotFound
	}

	file.DownloadCount++
	// Update byClaimCode map separately (since it's a separate copy)
	if ccFile, ok := r.byClaimCode[file.ClaimCode]; ok {
		ccFile.DownloadCount = file.DownloadCount
	}

	return nil
}

// IncrementDownloadCountIfUnchanged implements repository.FileRepository.IncrementDownloadCountIfUnchanged
func (r *FileRepository) IncrementDownloadCountIfUnchanged(ctx context.Context, id int64, expectedClaimCode string) error {
	if r.IncrementDownloadCountIfUnchangedErr != nil {
		return r.IncrementDownloadCountIfUnchangedErr
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	file, exists := r.files[id]
	if !exists {
		return repository.ErrNotFound
	}

	if file.ClaimCode != expectedClaimCode {
		return repository.ErrClaimCodeChanged
	}

	file.DownloadCount++
	// Update byClaimCode map separately
	if ccFile, ok := r.byClaimCode[file.ClaimCode]; ok {
		ccFile.DownloadCount = file.DownloadCount
	}

	return nil
}

// TryIncrementDownloadWithLimit implements repository.FileRepository.TryIncrementDownloadWithLimit
func (r *FileRepository) TryIncrementDownloadWithLimit(ctx context.Context, id int64, expectedClaimCode string) (bool, error) {
	if r.TryIncrementDownloadWithLimitError != nil {
		return false, r.TryIncrementDownloadWithLimitError
	}

	if r.OnTryIncrementDownload != nil {
		return r.OnTryIncrementDownload(ctx, id, expectedClaimCode)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	file, exists := r.files[id]
	if !exists {
		return false, repository.ErrNotFound
	}

	if file.ClaimCode != expectedClaimCode {
		return false, repository.ErrClaimCodeChanged
	}

	// Check download limit
	if file.MaxDownloads != nil && file.DownloadCount >= *file.MaxDownloads {
		return false, nil
	}

	file.DownloadCount++
	// Update byClaimCode map separately
	if ccFile, ok := r.byClaimCode[file.ClaimCode]; ok {
		ccFile.DownloadCount = file.DownloadCount
	}

	return true, nil
}

// IncrementCompletedDownloads implements repository.FileRepository.IncrementCompletedDownloads
func (r *FileRepository) IncrementCompletedDownloads(ctx context.Context, id int64) error {
	if r.IncrementCompletedDownloadsError != nil {
		return r.IncrementCompletedDownloadsError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	file, exists := r.files[id]
	if !exists {
		return repository.ErrNotFound
	}

	file.CompletedDownloads++
	// Update byClaimCode map separately
	if ccFile, ok := r.byClaimCode[file.ClaimCode]; ok {
		ccFile.CompletedDownloads = file.CompletedDownloads
	}

	return nil
}

// Delete implements repository.FileRepository.Delete
func (r *FileRepository) Delete(ctx context.Context, id int64) error {
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

	file, exists := r.files[id]
	if !exists {
		return repository.ErrNotFound
	}

	delete(r.byClaimCode, file.ClaimCode)
	delete(r.files, id)

	return nil
}

// DeleteByClaimCode implements repository.FileRepository.DeleteByClaimCode
func (r *FileRepository) DeleteByClaimCode(ctx context.Context, claimCode string) (*models.File, error) {
	if r.DeleteByClaimCodeError != nil {
		return nil, r.DeleteByClaimCodeError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	file, exists := r.byClaimCode[claimCode]
	if !exists {
		return nil, repository.ErrNotFound
	}

	// Make a deep copy before deleting
	fileCopy := deepCopyFile(file)

	delete(r.byClaimCode, claimCode)
	delete(r.files, file.ID)

	return fileCopy, nil
}

// DeleteByClaimCodes implements repository.FileRepository.DeleteByClaimCodes
func (r *FileRepository) DeleteByClaimCodes(ctx context.Context, claimCodes []string) ([]*models.File, error) {
	if r.DeleteByClaimCodesError != nil {
		return nil, r.DeleteByClaimCodesError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var deleted []*models.File
	for _, claimCode := range claimCodes {
		if file, exists := r.byClaimCode[claimCode]; exists {
			deleted = append(deleted, deepCopyFile(file))
			delete(r.byClaimCode, claimCode)
			delete(r.files, file.ID)
		}
	}

	return deleted, nil
}

// DeleteExpired implements repository.FileRepository.DeleteExpired
func (r *FileRepository) DeleteExpired(ctx context.Context, uploadDir string, onExpired repository.ExpiredFileCallback) (int, error) {
	if r.DeleteExpiredError != nil {
		return 0, r.DeleteExpiredError
	}

	if r.OnDeleteExpired != nil {
		return r.OnDeleteExpired(ctx, uploadDir, onExpired)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	now := time.Now()
	var toDelete []int64

	for id, file := range r.files {
		if now.After(file.ExpiresAt) {
			toDelete = append(toDelete, id)
			if onExpired != nil {
				onExpired(file.ClaimCode, file.OriginalFilename, file.FileSize, file.MimeType, file.ExpiresAt)
			}
		}
	}

	for _, id := range toDelete {
		file := r.files[id]
		delete(r.byClaimCode, file.ClaimCode)
		delete(r.files, id)
	}

	return len(toDelete), nil
}

// GetTotalUsage implements repository.FileRepository.GetTotalUsage
func (r *FileRepository) GetTotalUsage(ctx context.Context) (int64, error) {
	if r.GetTotalUsageError != nil {
		return 0, r.GetTotalUsageError
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	var total int64
	for _, file := range r.files {
		total += file.FileSize
	}

	return total, nil
}

// GetStats implements repository.FileRepository.GetStats
func (r *FileRepository) GetStats(ctx context.Context, uploadDir string) (*repository.FileStats, error) {
	if r.GetStatsError != nil {
		return nil, r.GetStatsError
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	stats := &repository.FileStats{}
	now := time.Now()

	for _, file := range r.files {
		stats.TotalFiles++
		stats.StorageUsed += file.FileSize
		stats.TotalUsage += file.FileSize

		if now.After(file.ExpiresAt) {
			stats.ExpiredFiles++
		} else {
			stats.ActiveFiles++
		}
	}

	return stats, nil
}

// GetAll implements repository.FileRepository.GetAll
func (r *FileRepository) GetAll(ctx context.Context) ([]*models.File, error) {
	if r.GetAllError != nil {
		return nil, r.GetAllError
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	files := make([]*models.File, 0, len(r.files))
	for _, f := range r.files {
		files = append(files, deepCopyFile(f))
	}

	return files, nil
}

// GetAllStoredFilenames implements repository.FileRepository.GetAllStoredFilenames
func (r *FileRepository) GetAllStoredFilenames(ctx context.Context) (map[string]bool, error) {
	if r.GetAllStoredFilenamesError != nil {
		return nil, r.GetAllStoredFilenamesError
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	filenames := make(map[string]bool)
	for _, file := range r.files {
		filenames[file.StoredFilename] = true
	}

	return filenames, nil
}

// GetAllForAdmin implements repository.FileRepository.GetAllForAdmin
func (r *FileRepository) GetAllForAdmin(ctx context.Context, limit, offset int) ([]models.File, int, error) {
	if r.GetAllForAdminError != nil {
		return nil, 0, r.GetAllForAdminError
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	default:
	}

	// Collect all files (deep copy)
	allFiles := make([]models.File, 0, len(r.files))
	for _, f := range r.files {
		allFiles = append(allFiles, *deepCopyFile(f))
	}

	total := len(allFiles)

	// Apply pagination
	if offset >= len(allFiles) {
		return []models.File{}, total, nil
	}

	end := offset + limit
	if end > len(allFiles) {
		end = len(allFiles)
	}

	return allFiles[offset:end], total, nil
}

// SearchForAdmin implements repository.FileRepository.SearchForAdmin
func (r *FileRepository) SearchForAdmin(ctx context.Context, searchTerm string, limit, offset int) ([]models.File, int, error) {
	if r.SearchForAdminError != nil {
		return nil, 0, r.SearchForAdminError
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	default:
	}

	// Simple search implementation - matches claim code, filename, or IP
	searchLower := strings.ToLower(searchTerm)
	var matches []models.File
	for _, f := range r.files {
		if strings.Contains(strings.ToLower(f.ClaimCode), searchLower) ||
			strings.Contains(strings.ToLower(f.OriginalFilename), searchLower) ||
			strings.Contains(strings.ToLower(f.UploaderIP), searchLower) {
			matches = append(matches, *deepCopyFile(f))
		}
	}

	total := len(matches)

	// Apply pagination
	if offset >= len(matches) {
		return []models.File{}, total, nil
	}

	end := offset + limit
	if end > len(matches) {
		end = len(matches)
	}

	return matches[offset:end], total, nil
}
