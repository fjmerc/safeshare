package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// bundleColumns is the column list every bundles SELECT uses, in scanBundle's order.
const bundleColumns = `id, bundle_code, status, file_count, upload_token_hash, created_at, published_at,
	expires_at, max_downloads, password_hash, user_id, client_encrypted, encrypted_manifest, uploader_ip`

// BundleRepository implements repository.BundleRepository for SQLite.
type BundleRepository struct {
	db    *sql.DB
	files *FileRepository
}

// NewBundleRepository creates a new SQLite bundle repository.
func NewBundleRepository(db *sql.DB) *BundleRepository {
	return &BundleRepository{db: db, files: NewFileRepository(db)}
}

var _ repository.BundleRepository = (*BundleRepository)(nil)

type rowScanner interface {
	Scan(dest ...interface{}) error
}

// parseSQLiteTime accepts both RFC3339 text and SQLite's
// CURRENT_TIMESTAMP form ("YYYY-MM-DD HH:MM:SS", UTC).
func parseSQLiteTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, normalizeSQLiteTimestamp(s))
}

func scanBundle(row rowScanner) (*models.Bundle, error) {
	b := &models.Bundle{}
	var createdAt, expiresAt string
	var publishedAt, passwordHash, uploaderIP sql.NullString
	var maxDownloads, userID sql.NullInt64
	var manifest []byte

	if err := row.Scan(&b.ID, &b.BundleCode, &b.Status, &b.FileCount, &b.UploadTokenHash, &createdAt, &publishedAt,
		&expiresAt, &maxDownloads, &passwordHash, &userID, &b.ClientEncrypted, &manifest, &uploaderIP); err != nil {
		return nil, err
	}

	var err error
	if b.CreatedAt, err = parseSQLiteTime(createdAt); err != nil {
		return nil, fmt.Errorf("failed to parse bundle created_at: %w", err)
	}
	if b.ExpiresAt, err = parseSQLiteTime(expiresAt); err != nil {
		return nil, fmt.Errorf("failed to parse bundle expires_at: %w", err)
	}
	if publishedAt.Valid {
		t, err := parseSQLiteTime(publishedAt.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bundle published_at: %w", err)
		}
		b.PublishedAt = &t
	}
	if maxDownloads.Valid {
		v := int(maxDownloads.Int64)
		b.MaxDownloads = &v
	}
	if userID.Valid {
		v := userID.Int64
		b.UserID = &v
	}
	b.PasswordHash = passwordHash.String
	b.UploaderIP = uploaderIP.String
	if len(manifest) > 0 {
		b.EncryptedManifest = manifest
	}
	return b, nil
}

// Create inserts b and sets b.ID.
func (r *BundleRepository) Create(ctx context.Context, b *models.Bundle) error {
	status := b.Status
	if status == "" {
		status = models.BundleStatusDraft
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO bundles (bundle_code, status, file_count, upload_token_hash, created_at, expires_at,
			max_downloads, password_hash, user_id, client_encrypted, encrypted_manifest, uploader_ip)
		VALUES (?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), ?, ?, ?, ?, ?, ?, ?)`,
		b.BundleCode, status, b.FileCount, b.UploadTokenHash, nullableCreatedAt(b.CreatedAt),
		b.ExpiresAt.UTC().Format(time.RFC3339), b.MaxDownloads, nullableString(b.PasswordHash), b.UserID,
		b.ClientEncrypted, nullableBlob(b.EncryptedManifest), nullableString(b.UploaderIP))
	if err != nil {
		if isUniqueConstraintViolation(err) {
			return fmt.Errorf("%w: bundle code already exists", repository.ErrDuplicateKey)
		}
		return fmt.Errorf("failed to create bundle: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get bundle id: %w", err)
	}
	b.ID = id
	b.Status = status
	return nil
}

// GetByID returns the bundle in any status, or nil, nil if it does not exist.
func (r *BundleRepository) GetByID(ctx context.Context, id int64) (*models.Bundle, error) {
	b, err := scanBundle(r.db.QueryRowContext(ctx, `SELECT `+bundleColumns+` FROM bundles WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get bundle: %w", err)
	}
	return b, nil
}

// GetPublishedByCode returns a published, unexpired bundle, or nil, nil.
func (r *BundleRepository) GetPublishedByCode(ctx context.Context, code string) (*models.Bundle, error) {
	b, err := scanBundle(r.db.QueryRowContext(ctx,
		`SELECT `+bundleColumns+` FROM bundles WHERE bundle_code = ? AND status = ?`, code, models.BundleStatusPublished))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get bundle: %w", err)
	}
	if !time.Now().Before(b.ExpiresAt) {
		return nil, nil
	}
	return b, nil
}

// GetMember returns the unexpired member at position, or nil, nil.
func (r *BundleRepository) GetMember(ctx context.Context, bundleID int64, position int) (*models.File, error) {
	var id int64
	err := r.db.QueryRowContext(ctx, `SELECT id FROM files WHERE bundle_id = ? AND bundle_position = ?`, bundleID, position).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find bundle member: %w", err)
	}
	f, err := r.files.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !time.Now().Before(f.ExpiresAt) {
		return nil, nil
	}
	return f, nil
}

// ListMembers returns all member files ordered by position.
func (r *BundleRepository) ListMembers(ctx context.Context, bundleID int64) ([]*models.File, error) {
	ids, err := r.queryIDs(ctx, `SELECT id FROM files WHERE bundle_id = ? ORDER BY bundle_position`, bundleID)
	if err != nil {
		return nil, fmt.Errorf("failed to list bundle members: %w", err)
	}
	members := make([]*models.File, 0, len(ids))
	for _, id := range ids {
		f, err := r.files.GetByID(ctx, id)
		if errors.Is(err, repository.ErrNotFound) {
			continue // deleted between the two queries
		}
		if err != nil {
			return nil, err
		}
		members = append(members, f)
	}
	return members, nil
}

// MemberPositionTaken reports whether a member or an incomplete chunked upload holds position.
func (r *BundleRepository) MemberPositionTaken(ctx context.Context, bundleID int64, position int) (bool, error) {
	var taken bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM files WHERE bundle_id = ? AND bundle_position = ?)
		    OR EXISTS(SELECT 1 FROM partial_uploads WHERE bundle_id = ? AND bundle_position = ? AND completed = 0)`,
		bundleID, position, bundleID, position).Scan(&taken)
	if err != nil {
		return false, fmt.Errorf("failed to check bundle position: %w", err)
	}
	return taken, nil
}

// Publish marks a complete, clean draft published.
func (r *BundleRepository) Publish(ctx context.Context, bundleID int64, manifest []byte) error {
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var status string
	var fileCount int
	err = tx.QueryRowContext(ctx, `SELECT status, file_count FROM bundles WHERE id = ?`, bundleID).Scan(&status, &fileCount)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && status != models.BundleStatusDraft) {
		return repository.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to read bundle: %w", err)
	}

	var count, minPos, maxPos, unclean int
	err = tx.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(MIN(bundle_position), -1), COALESCE(MAX(bundle_position), -1),
		       COALESCE(SUM(CASE WHEN scan_status IN ('pending', 'infected') THEN 1 ELSE 0 END), 0)
		FROM files WHERE bundle_id = ?`, bundleID).Scan(&count, &minPos, &maxPos, &unclean)
	if err != nil {
		return fmt.Errorf("failed to check bundle members: %w", err)
	}
	// Positions are unique per bundle (idx_files_bundle_position), so the
	// right count plus min 0 and max file_count-1 means exactly 0..n-1.
	if count != fileCount || minPos != 0 || maxPos != fileCount-1 {
		return fmt.Errorf("%w: bundle has %d of %d files", repository.ErrInvalidInput, count, fileCount)
	}
	if unclean > 0 {
		return fmt.Errorf("%w: bundle has files that are not clean", repository.ErrInvalidInput)
	}

	if _, err := tx.ExecContext(ctx, `UPDATE bundles SET status = ?, published_at = ?, encrypted_manifest = ? WHERE id = ? AND status = ?`,
		models.BundleStatusPublished, time.Now().UTC().Format(time.RFC3339), nullableBlob(manifest), bundleID, models.BundleStatusDraft); err != nil {
		return fmt.Errorf("failed to publish bundle: %w", err)
	}
	return tx.Commit()
}

// DeleteWithMembers deletes the member rows and the bundle in one transaction.
func (r *BundleRepository) DeleteWithMembers(ctx context.Context, bundleID int64) ([]*models.File, error) {
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM bundles WHERE id = ?`, bundleID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to read bundle: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `SELECT id, claim_code, original_filename, stored_filename, file_size
		FROM files WHERE bundle_id = ? ORDER BY bundle_position`, bundleID)
	if err != nil {
		return nil, fmt.Errorf("failed to list bundle members: %w", err)
	}
	var deleted []*models.File
	for rows.Next() {
		f := &models.File{BundleID: &bundleID}
		if err := rows.Scan(&f.ID, &f.ClaimCode, &f.OriginalFilename, &f.StoredFilename, &f.FileSize); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed to scan bundle member: %w", err)
		}
		deleted = append(deleted, f)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM files WHERE bundle_id = ?`, bundleID); err != nil {
		return nil, fmt.Errorf("failed to delete bundle members: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM bundles WHERE id = ?`, bundleID); err != nil {
		return nil, fmt.Errorf("failed to delete bundle: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return deleted, nil
}

// ListByUser returns the user's published bundles, newest first.
func (r *BundleRepository) ListByUser(ctx context.Context, userID int64, limit, offset int) ([]models.Bundle, int, error) {
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bundles WHERE user_id = ? AND status = ?`,
		userID, models.BundleStatusPublished).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count bundles: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+bundleColumns+` FROM bundles WHERE user_id = ? AND status = ?
		ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, userID, models.BundleStatusPublished, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list bundles: %w", err)
	}
	defer rows.Close()
	bundles := []models.Bundle{}
	for rows.Next() {
		b, err := scanBundle(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan bundle: %w", err)
		}
		bundles = append(bundles, *b)
	}
	return bundles, total, rows.Err()
}

// UpdateExpiration sets the expiry of a published bundle and all its members.
func (r *BundleRepository) UpdateExpiration(ctx context.Context, bundleID, userID int64, expiresAt time.Time) error {
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	exp := expiresAt.UTC().Format(time.RFC3339)
	res, err := tx.ExecContext(ctx, `UPDATE bundles SET expires_at = ? WHERE id = ? AND user_id = ? AND status = ?`,
		exp, bundleID, userID, models.BundleStatusPublished)
	if err != nil {
		return fmt.Errorf("failed to update bundle expiration: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return repository.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE files SET expires_at = ? WHERE bundle_id = ?`, exp, bundleID); err != nil {
		return fmt.Errorf("failed to update bundle member expiration: %w", err)
	}
	return tx.Commit()
}

// RegenerateCode replaces a published bundle's code.
func (r *BundleRepository) RegenerateCode(ctx context.Context, bundleID, userID int64, newCode string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE bundles SET bundle_code = ? WHERE id = ? AND user_id = ? AND status = ?`,
		newCode, bundleID, userID, models.BundleStatusPublished)
	if err != nil {
		if isUniqueConstraintViolation(err) {
			return fmt.Errorf("%w: bundle code already exists", repository.ErrDuplicateKey)
		}
		return fmt.Errorf("failed to regenerate bundle code: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// ListAbandonedDrafts returns ids of drafts created before olderThan.
func (r *BundleRepository) ListAbandonedDrafts(ctx context.Context, olderThan time.Time) ([]int64, error) {
	return r.queryIDs(ctx, `SELECT id FROM bundles WHERE status = ? AND datetime(created_at) < datetime(?) ORDER BY id`,
		models.BundleStatusDraft, olderThan.UTC().Format("2006-01-02 15:04:05"))
}

// ListEmptyPublished returns ids of published bundles with no members left.
func (r *BundleRepository) ListEmptyPublished(ctx context.Context) ([]int64, error) {
	return r.queryIDs(ctx, `SELECT id FROM bundles b WHERE status = ?
		AND NOT EXISTS (SELECT 1 FROM files f WHERE f.bundle_id = b.id) ORDER BY id`, models.BundleStatusPublished)
}

func (r *BundleRepository) queryIDs(ctx context.Context, query string, args ...interface{}) ([]int64, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// BundleIDForMemberClaimCode returns the bundle that owns the file with claimCode.
func (r *BundleRepository) BundleIDForMemberClaimCode(ctx context.Context, claimCode string) (int64, bool, error) {
	var id sql.NullInt64
	err := r.db.QueryRowContext(ctx, `SELECT bundle_id FROM files WHERE claim_code = ?`, claimCode).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("failed to look up file bundle: %w", err)
	}
	return id.Int64, id.Valid, nil
}
