package mock

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// BundleRepository is an in-memory repository.BundleRepository. Members
// live in the FileRepository it was created with, as in the real backends.
type BundleRepository struct {
	mu      sync.RWMutex
	bundles map[int64]*models.Bundle
	nextID  int64
	files   *FileRepository

	// Error injection: when set, the matching method returns it.
	CreateError  error
	PublishError error
	DeleteError  error
}

var _ repository.BundleRepository = (*BundleRepository)(nil)

// NewBundleRepository creates a mock bundle repository whose members are
// the files in files that carry a BundleID.
func NewBundleRepository(files *FileRepository) *BundleRepository {
	return &BundleRepository{bundles: map[int64]*models.Bundle{}, nextID: 1, files: files}
}

// Reset clears all bundles and injected errors.
func (r *BundleRepository) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bundles = map[int64]*models.Bundle{}
	r.nextID = 1
	r.CreateError, r.PublishError, r.DeleteError = nil, nil, nil
}

func copyBundle(b *models.Bundle) *models.Bundle {
	c := *b
	if b.MaxDownloads != nil {
		v := *b.MaxDownloads
		c.MaxDownloads = &v
	}
	if b.UserID != nil {
		v := *b.UserID
		c.UserID = &v
	}
	if b.PublishedAt != nil {
		v := *b.PublishedAt
		c.PublishedAt = &v
	}
	if b.EncryptedManifest != nil {
		c.EncryptedManifest = append([]byte(nil), b.EncryptedManifest...)
	}
	return &c
}

// members returns copies of the bundle's member files ordered by position.
func (r *BundleRepository) members(bundleID int64) []*models.File {
	r.files.mu.RLock()
	defer r.files.mu.RUnlock()
	var out []*models.File
	for _, f := range r.files.files {
		if f.BundleID != nil && *f.BundleID == bundleID {
			out = append(out, deepCopyFile(f))
		}
	}
	sort.Slice(out, func(i, j int) bool { return *out[i].BundlePosition < *out[j].BundlePosition })
	return out
}

func (r *BundleRepository) Create(ctx context.Context, b *models.Bundle) error {
	if r.CreateError != nil {
		return r.CreateError
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.bundles {
		if existing.BundleCode == b.BundleCode {
			return fmt.Errorf("%w: bundle code already exists", repository.ErrDuplicateKey)
		}
	}
	if b.Status == "" {
		b.Status = models.BundleStatusDraft
	}
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now()
	}
	b.ID = r.nextID
	r.nextID++
	r.bundles[b.ID] = copyBundle(b)
	return nil
}

func (r *BundleRepository) GetByID(ctx context.Context, id int64) (*models.Bundle, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if b, ok := r.bundles[id]; ok {
		return copyBundle(b), nil
	}
	return nil, nil
}

func (r *BundleRepository) GetPublishedByCode(ctx context.Context, code string) (*models.Bundle, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, b := range r.bundles {
		if b.BundleCode == code && b.Status == models.BundleStatusPublished && time.Now().Before(b.ExpiresAt) {
			return copyBundle(b), nil
		}
	}
	return nil, nil
}

func (r *BundleRepository) GetMember(ctx context.Context, bundleID int64, position int) (*models.File, error) {
	for _, f := range r.members(bundleID) {
		if *f.BundlePosition == position {
			if !time.Now().Before(f.ExpiresAt) {
				return nil, nil
			}
			return f, nil
		}
	}
	return nil, nil
}

func (r *BundleRepository) ListMembers(ctx context.Context, bundleID int64) ([]*models.File, error) {
	return r.members(bundleID), nil
}

func (r *BundleRepository) MemberPositionTaken(ctx context.Context, bundleID int64, position int) (bool, error) {
	for _, f := range r.members(bundleID) {
		if *f.BundlePosition == position {
			return true, nil
		}
	}
	return false, nil
}

func (r *BundleRepository) Publish(ctx context.Context, bundleID int64, manifest []byte) error {
	if r.PublishError != nil {
		return r.PublishError
	}
	members := r.members(bundleID)
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.bundles[bundleID]
	if !ok || b.Status != models.BundleStatusDraft {
		return repository.ErrNotFound
	}
	if len(members) != b.FileCount {
		return fmt.Errorf("%w: bundle has %d of %d files", repository.ErrInvalidInput, len(members), b.FileCount)
	}
	for i, f := range members {
		if *f.BundlePosition != i || f.ScanStatus == "pending" || f.ScanStatus == "infected" {
			return fmt.Errorf("%w: bundle is incomplete or not clean", repository.ErrInvalidInput)
		}
	}
	now := time.Now()
	b.Status = models.BundleStatusPublished
	b.PublishedAt = &now
	b.EncryptedManifest = append([]byte(nil), manifest...)
	if len(manifest) == 0 {
		b.EncryptedManifest = nil
	}
	return nil
}

func (r *BundleRepository) DeleteWithMembers(ctx context.Context, bundleID int64) ([]*models.File, error) {
	if r.DeleteError != nil {
		return nil, r.DeleteError
	}
	r.mu.Lock()
	if _, ok := r.bundles[bundleID]; !ok {
		r.mu.Unlock()
		return nil, repository.ErrNotFound
	}
	delete(r.bundles, bundleID)
	r.mu.Unlock()

	members := r.members(bundleID)
	r.files.mu.Lock()
	for _, f := range members {
		delete(r.files.files, f.ID)
		delete(r.files.byClaimCode, f.ClaimCode)
	}
	r.files.mu.Unlock()
	return members, nil
}

func (r *BundleRepository) ListByUser(ctx context.Context, userID int64, limit, offset int) ([]models.Bundle, int, error) {
	r.mu.RLock()
	var all []models.Bundle
	for _, b := range r.bundles {
		if b.UserID != nil && *b.UserID == userID && b.Status == models.BundleStatusPublished {
			all = append(all, *copyBundle(b))
		}
	}
	r.mu.RUnlock()
	sort.Slice(all, func(i, j int) bool { return all[i].ID > all[j].ID })
	total := len(all)
	if offset >= total {
		return []models.Bundle{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total, nil
}

func (r *BundleRepository) UpdateExpiration(ctx context.Context, bundleID, userID int64, expiresAt time.Time) error {
	r.mu.Lock()
	b, ok := r.bundles[bundleID]
	if !ok || b.UserID == nil || *b.UserID != userID || b.Status != models.BundleStatusPublished {
		r.mu.Unlock()
		return repository.ErrNotFound
	}
	b.ExpiresAt = expiresAt
	r.mu.Unlock()

	r.files.mu.Lock()
	defer r.files.mu.Unlock()
	for _, f := range r.files.files {
		if f.BundleID != nil && *f.BundleID == bundleID {
			f.ExpiresAt = expiresAt
			if c, ok := r.files.byClaimCode[f.ClaimCode]; ok {
				c.ExpiresAt = expiresAt
			}
		}
	}
	return nil
}

func (r *BundleRepository) RegenerateCode(ctx context.Context, bundleID, userID int64, newCode string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.bundles[bundleID]
	if !ok || b.UserID == nil || *b.UserID != userID || b.Status != models.BundleStatusPublished {
		return repository.ErrNotFound
	}
	for id, other := range r.bundles {
		if id != bundleID && other.BundleCode == newCode {
			return fmt.Errorf("%w: bundle code already exists", repository.ErrDuplicateKey)
		}
	}
	b.BundleCode = newCode
	return nil
}

func (r *BundleRepository) ListAbandonedDrafts(ctx context.Context, olderThan time.Time) ([]int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var ids []int64
	for id, b := range r.bundles {
		if b.Status == models.BundleStatusDraft && b.CreatedAt.Before(olderThan) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

func (r *BundleRepository) ListEmptyPublished(ctx context.Context) ([]int64, error) {
	r.mu.RLock()
	var candidates []int64
	for id, b := range r.bundles {
		if b.Status == models.BundleStatusPublished {
			candidates = append(candidates, id)
		}
	}
	r.mu.RUnlock()
	var ids []int64
	for _, id := range candidates {
		if len(r.members(id)) == 0 {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}
