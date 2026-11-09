package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// bundleColumns is the column list every bundles SELECT uses, in scanBundle's order.
const bundleColumns = `id, bundle_code, status, file_count, upload_token_hash, created_at, published_at,
	expires_at, max_downloads, password_hash, user_id, client_encrypted, encrypted_manifest, uploader_ip`

// BundleRepository implements repository.BundleRepository for PostgreSQL.
type BundleRepository struct {
	pool  *Pool
	files *FileRepository
}

// NewBundleRepository creates a new PostgreSQL bundle repository.
func NewBundleRepository(pool *Pool) *BundleRepository {
	return &BundleRepository{pool: pool, files: NewFileRepository(pool)}
}

var _ repository.BundleRepository = (*BundleRepository)(nil)

func scanBundle(row pgx.Row) (*models.Bundle, error) {
	b := &models.Bundle{}
	var publishedAt sql.NullTime
	var passwordHash, uploaderIP sql.NullString
	var maxDownloads, userID sql.NullInt64
	var manifest []byte

	if err := row.Scan(&b.ID, &b.BundleCode, &b.Status, &b.FileCount, &b.UploadTokenHash, &b.CreatedAt, &publishedAt,
		&b.ExpiresAt, &maxDownloads, &passwordHash, &userID, &b.ClientEncrypted, &manifest, &uploaderIP); err != nil {
		return nil, err
	}
	if publishedAt.Valid {
		t := publishedAt.Time
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
	var createdAt *time.Time
	if !b.CreatedAt.IsZero() {
		createdAt = &b.CreatedAt
	}
	id, err := repository.NewBundleID()
	if err != nil {
		return fmt.Errorf("failed to generate bundle id: %w", err)
	}
	err = r.pool.QueryRow(ctx, `
		INSERT INTO bundles (id, bundle_code, status, file_count, upload_token_hash, created_at, expires_at,
			max_downloads, password_hash, user_id, client_encrypted, encrypted_manifest, uploader_ip)
		VALUES ($1, $2, $3, $4, $5, COALESCE($6::timestamptz, CURRENT_TIMESTAMP), $7, $8, $9, $10, $11, $12, $13)
		RETURNING id, created_at`,
		id, b.BundleCode, status, b.FileCount, b.UploadTokenHash, createdAt, b.ExpiresAt, b.MaxDownloads,
		pgNullableString(b.PasswordHash), b.UserID, b.ClientEncrypted, nullableBytea(b.EncryptedManifest),
		pgNullableString(b.UploaderIP)).Scan(&b.ID, &b.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: bundle code already exists", repository.ErrDuplicateKey)
		}
		return fmt.Errorf("failed to create bundle: %w", err)
	}
	b.Status = status
	return nil
}

// GetByID returns the bundle in any status, or nil, nil if it does not exist.
func (r *BundleRepository) GetByID(ctx context.Context, id int64) (*models.Bundle, error) {
	b, err := scanBundle(r.pool.QueryRow(ctx, `SELECT `+bundleColumns+` FROM bundles WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get bundle: %w", err)
	}
	return b, nil
}

// GetPublishedByCode returns a published, unexpired bundle, or nil, nil.
func (r *BundleRepository) GetPublishedByCode(ctx context.Context, code string) (*models.Bundle, error) {
	b, err := scanBundle(r.pool.QueryRow(ctx,
		`SELECT `+bundleColumns+` FROM bundles WHERE bundle_code = $1 AND status = $2 AND expires_at > NOW()`,
		code, models.BundleStatusPublished))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get bundle: %w", err)
	}
	return b, nil
}

// GetMember returns the unexpired member at position, or nil, nil.
func (r *BundleRepository) GetMember(ctx context.Context, bundleID int64, position int) (*models.File, error) {
	var id int64
	err := r.pool.QueryRow(ctx, `SELECT id FROM files WHERE bundle_id = $1 AND bundle_position = $2`, bundleID, position).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
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
	ids, err := r.queryIDs(ctx, `SELECT id FROM files WHERE bundle_id = $1 ORDER BY bundle_position`, bundleID)
	if err != nil {
		return nil, fmt.Errorf("failed to list bundle members: %w", err)
	}
	members := make([]*models.File, 0, len(ids))
	for _, id := range ids {
		f, err := r.files.GetByID(ctx, id)
		if errors.Is(err, repository.ErrNotFound) {
			continue
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
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM files WHERE bundle_id = $1 AND bundle_position = $2)
		    OR EXISTS(SELECT 1 FROM partial_uploads WHERE bundle_id = $1 AND bundle_position = $2 AND completed = FALSE)`,
		bundleID, position).Scan(&taken)
	if err != nil {
		return false, fmt.Errorf("failed to check bundle position: %w", err)
	}
	return taken, nil
}

// Publish marks a complete, clean draft published.
func (r *BundleRepository) Publish(ctx context.Context, bundleID int64, manifest []byte, publishedAt time.Time) error {
	if publishedAt.IsZero() {
		publishedAt = time.Now()
	}
	return withRetryNoReturn(ctx, 3, func() error {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)

		var status string
		var fileCount int
		err = tx.QueryRow(ctx, `SELECT status, file_count FROM bundles WHERE id = $1 FOR UPDATE`, bundleID).Scan(&status, &fileCount)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && status != models.BundleStatusDraft) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("failed to read bundle: %w", err)
		}

		var count, minPos, maxPos, unclean int
		err = tx.QueryRow(ctx, `
			SELECT COUNT(*), COALESCE(MIN(bundle_position), -1), COALESCE(MAX(bundle_position), -1),
			       COUNT(*) FILTER (WHERE scan_status IN ('pending', 'infected'))
			FROM files WHERE bundle_id = $1`, bundleID).Scan(&count, &minPos, &maxPos, &unclean)
		if err != nil {
			return fmt.Errorf("failed to check bundle members: %w", err)
		}
		if count != fileCount || minPos != 0 || maxPos != fileCount-1 {
			return fmt.Errorf("%w: bundle has %d of %d files", repository.ErrInvalidInput, count, fileCount)
		}
		if unclean > 0 {
			return fmt.Errorf("%w: bundle has files that are not clean", repository.ErrInvalidInput)
		}

		if _, err := tx.Exec(ctx, `UPDATE bundles SET status = $1, published_at = $2, encrypted_manifest = $3 WHERE id = $4`,
			models.BundleStatusPublished, publishedAt, nullableBytea(manifest), bundleID); err != nil {
			return fmt.Errorf("failed to publish bundle: %w", err)
		}
		return tx.Commit(ctx)
	})
}

// DeleteWithMembers deletes the member rows and the bundle in one transaction.
func (r *BundleRepository) DeleteWithMembers(ctx context.Context, bundleID int64) ([]*models.File, error) {
	return withRetry(ctx, 3, func() ([]*models.File, error) {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return nil, err
		}
		defer tx.Rollback(ctx)

		var exists int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM bundles WHERE id = $1 FOR UPDATE`, bundleID).Scan(&exists); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, repository.ErrNotFound
			}
			return nil, fmt.Errorf("failed to read bundle: %w", err)
		}

		rows, err := tx.Query(ctx, `DELETE FROM files WHERE bundle_id = $1
			RETURNING id, claim_code, original_filename, stored_filename, file_size`, bundleID)
		if err != nil {
			return nil, fmt.Errorf("failed to delete bundle members: %w", err)
		}
		var deleted []*models.File
		for rows.Next() {
			id := bundleID
			f := &models.File{BundleID: &id}
			if err := rows.Scan(&f.ID, &f.ClaimCode, &f.OriginalFilename, &f.StoredFilename, &f.FileSize); err != nil {
				rows.Close()
				return nil, fmt.Errorf("failed to scan bundle member: %w", err)
			}
			deleted = append(deleted, f)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}

		if _, err := tx.Exec(ctx, `DELETE FROM bundles WHERE id = $1`, bundleID); err != nil {
			return nil, fmt.Errorf("failed to delete bundle: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return deleted, nil
	})
}

// ListByUser returns the user's published bundles, newest first.
func (r *BundleRepository) ListByUser(ctx context.Context, userID int64, limit, offset int) ([]models.Bundle, int, error) {
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM bundles WHERE user_id = $1 AND status = $2`,
		userID, models.BundleStatusPublished).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count bundles: %w", err)
	}
	rows, err := r.pool.Query(ctx, `SELECT `+bundleColumns+` FROM bundles WHERE user_id = $1 AND status = $2
		ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4`, userID, models.BundleStatusPublished, limit, offset)
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
	return withRetryNoReturn(ctx, 3, func() error {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)

		tag, err := tx.Exec(ctx, `UPDATE bundles SET expires_at = $1 WHERE id = $2 AND user_id = $3 AND status = $4`,
			expiresAt, bundleID, userID, models.BundleStatusPublished)
		if err != nil {
			return fmt.Errorf("failed to update bundle expiration: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		if _, err := tx.Exec(ctx, `UPDATE files SET expires_at = $1 WHERE bundle_id = $2`, expiresAt, bundleID); err != nil {
			return fmt.Errorf("failed to update bundle member expiration: %w", err)
		}
		return tx.Commit(ctx)
	})
}

// RegenerateCode replaces a published bundle's code.
func (r *BundleRepository) RegenerateCode(ctx context.Context, bundleID, userID int64, newCode string) error {
	tag, err := r.pool.Exec(ctx, `UPDATE bundles SET bundle_code = $1 WHERE id = $2 AND user_id = $3 AND status = $4`,
		newCode, bundleID, userID, models.BundleStatusPublished)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: bundle code already exists", repository.ErrDuplicateKey)
		}
		return fmt.Errorf("failed to regenerate bundle code: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// ListAbandonedDrafts returns ids of drafts created before olderThan.
func (r *BundleRepository) ListAbandonedDrafts(ctx context.Context, olderThan time.Time) ([]int64, error) {
	return r.queryIDs(ctx, `SELECT id FROM bundles WHERE status = $1 AND created_at < $2 ORDER BY id`,
		models.BundleStatusDraft, olderThan)
}

// ListEmptyPublished returns ids of published bundles with no members left.
func (r *BundleRepository) ListEmptyPublished(ctx context.Context) ([]int64, error) {
	return r.queryIDs(ctx, `SELECT id FROM bundles b WHERE status = $1
		AND NOT EXISTS (SELECT 1 FROM files f WHERE f.bundle_id = b.id) ORDER BY id`, models.BundleStatusPublished)
}

func (r *BundleRepository) queryIDs(ctx context.Context, query string, args ...interface{}) ([]int64, error) {
	rows, err := r.pool.Query(ctx, query, args...)
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
	err := r.pool.QueryRow(ctx, `SELECT bundle_id FROM files WHERE claim_code = $1`, claimCode).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("failed to look up file bundle: %w", err)
	}
	return id.Int64, id.Valid, nil
}
