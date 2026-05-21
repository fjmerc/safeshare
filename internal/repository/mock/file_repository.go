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
	"crypto/rand"
	"encoding/hex"
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

	// SH-2.3: reservations side-table mirror. Tokens → (fileID, createdAt).
	// in_flight counter per file lives implicitly as len(reservations where file_id = X).
	reservations map[string]mockReservation

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
	ReserveDownloadError                 error
	CommitDownloadError                  error
	CancelDownloadError                  error
	ReapStaleReservationsError           error
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
	UpdateScanStatusError                error

	// Custom behavior hooks
	// NOTE: Set these BEFORE concurrent access begins
	OnCreate               func(ctx context.Context, file *models.File) error
	OnGetByID              func(ctx context.Context, id int64) (*models.File, error)
	OnGetByClaimCode       func(ctx context.Context, claimCode string) (*models.File, error)
	OnDeleteExpired        func(ctx context.Context, uploadDir string, onExpired repository.ExpiredFileCallback) (int, error)
	OnTryIncrementDownload func(ctx context.Context, id int64, claimCode string) (bool, error)
}

// mockReservation is the in-memory mirror of a download_reservations row.
type mockReservation struct {
	fileID    int64
	createdAt time.Time
}

// NewFileRepository creates a new mock FileRepository with default behavior.
func NewFileRepository() *FileRepository {
	return &FileRepository{
		files:        make(map[int64]*models.File),
		byClaimCode:  make(map[string]*models.File),
		reservations: make(map[string]mockReservation),
		nextID:       1,
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
	r.reservations = make(map[string]mockReservation)
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
	r.ReserveDownloadError = nil
	r.CommitDownloadError = nil
	r.CancelDownloadError = nil
	r.ReapStaleReservationsError = nil
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
	r.UpdateScanStatusError = nil

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
	if src.ScannedAt != nil {
		t := *src.ScannedAt
		dst.ScannedAt = &t
	}
	if len(src.EncFileID) > 0 {
		dst.EncFileID = append([]byte(nil), src.EncFileID...)
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

// countInFlight returns the live reservation count for fileID (caller must hold r.mu).
func (r *FileRepository) countInFlight(fileID int64) int {
	n := 0
	for _, res := range r.reservations {
		if res.fileID == fileID {
			n++
		}
	}
	return n
}

// ReserveDownload implements repository.FileRepository.ReserveDownload
func (r *FileRepository) ReserveDownload(ctx context.Context, fileID int64, expectedClaimCode string) (string, error) {
	if r.ReserveDownloadError != nil {
		return "", r.ReserveDownloadError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	file, exists := r.files[fileID]
	if !exists {
		return "", repository.ErrClaimCodeChanged
	}
	if file.ClaimCode != expectedClaimCode {
		return "", repository.ErrClaimCodeChanged
	}

	// Unlimited cap: fast-path sentinel.
	if file.MaxDownloads == nil || *file.MaxDownloads == 0 {
		return repository.ReservationTokenUnlimited, nil
	}

	inFlight := r.countInFlight(fileID)
	if file.DownloadCount+inFlight >= *file.MaxDownloads {
		return "", nil // cap hit
	}

	token, err := mockReservationToken()
	if err != nil {
		return "", err
	}
	r.reservations[token] = mockReservation{fileID: fileID, createdAt: time.Now()}
	return token, nil
}

// CommitDownload implements repository.FileRepository.CommitDownload
func (r *FileRepository) CommitDownload(ctx context.Context, fileID int64, token string) error {
	if r.CommitDownloadError != nil {
		return r.CommitDownloadError
	}
	if token == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if token == repository.ReservationTokenUnlimited {
		if file, ok := r.files[fileID]; ok {
			file.DownloadCount++
			file.CompletedDownloads++
			if ccFile, ok := r.byClaimCode[file.ClaimCode]; ok {
				ccFile.DownloadCount = file.DownloadCount
				ccFile.CompletedDownloads = file.CompletedDownloads
			}
		}
		return nil
	}

	res, present := r.reservations[token]
	if present && res.fileID == fileID {
		delete(r.reservations, token)
		if file, ok := r.files[fileID]; ok {
			file.DownloadCount++
			file.CompletedDownloads++
			if ccFile, ok := r.byClaimCode[file.ClaimCode]; ok {
				ccFile.DownloadCount = file.DownloadCount
				ccFile.CompletedDownloads = file.CompletedDownloads
			}
		}
		return nil
	}

	// Reaped-mid-stream recovery.
	// Guard MUST match ReserveDownload: (download_count + in_flight) < max_downloads.
	// Using `download_count >= max_downloads` alone would let a late-committing
	// reservation jump past a still-live reservation and over-count past the cap
	// (bug-hunter C1: same-token replay or retry-race could double-credit).
	file, ok := r.files[fileID]
	if !ok {
		return nil
	}
	if file.MaxDownloads != nil && *file.MaxDownloads > 0 &&
		file.DownloadCount+r.countInFlight(fileID) >= *file.MaxDownloads {
		// cap already taken by another reader; under-count rather than over-count.
		return nil
	}
	file.DownloadCount++
	file.CompletedDownloads++
	if ccFile, ok := r.byClaimCode[file.ClaimCode]; ok {
		ccFile.DownloadCount = file.DownloadCount
		ccFile.CompletedDownloads = file.CompletedDownloads
	}
	return nil
}

// CancelDownload implements repository.FileRepository.CancelDownload
func (r *FileRepository) CancelDownload(ctx context.Context, fileID int64, token string) error {
	if r.CancelDownloadError != nil {
		return r.CancelDownloadError
	}
	if token == "" || token == repository.ReservationTokenUnlimited {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if res, present := r.reservations[token]; present && res.fileID == fileID {
		delete(r.reservations, token)
	}
	return nil
}

// ReapStaleReservations implements repository.FileRepository.ReapStaleReservations
func (r *FileRepository) ReapStaleReservations(ctx context.Context, ttl time.Duration) (int, error) {
	if r.ReapStaleReservationsError != nil {
		return 0, r.ReapStaleReservationsError
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	cutoff := time.Now().Add(-ttl)
	reaped := 0
	for token, res := range r.reservations {
		if res.createdAt.Before(cutoff) {
			// Find the file backing this reservation so we can keep the file's
			// implicit in_flight count consistent (mock tracks in_flight as len of
			// reservation entries; deleting the entry decrements automatically).
			delete(r.reservations, token)
			reaped++
		}
	}
	return reaped, nil
}

// mockReservationToken produces an opaque 32-char hex token for the mock.
func mockReservationToken() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
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

// UpdateScanStatus implements repository.FileRepository.UpdateScanStatus
func (r *FileRepository) UpdateScanStatus(ctx context.Context, id int64, status string, result string) error {
	if r.UpdateScanStatusError != nil {
		return r.UpdateScanStatusError
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

	now := time.Now()
	file.ScanStatus = status
	file.ScanResult = result
	file.ScannedAt = &now

	// Update byClaimCode map separately
	if ccFile, ok := r.byClaimCode[file.ClaimCode]; ok {
		t := now
		ccFile.ScanStatus = status
		ccFile.ScanResult = result
		ccFile.ScannedAt = &t
	}

	return nil
}
