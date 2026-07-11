// Package postgres provides PostgreSQL implementations of repository interfaces.
package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// FileRepository implements repository.FileRepository for PostgreSQL.
type FileRepository struct {
	pool *Pool
}

// NewFileRepository creates a new PostgreSQL file repository.
func NewFileRepository(pool *Pool) *FileRepository {
	return &FileRepository{pool: pool}
}

// Create inserts a new file record into the database.
func (r *FileRepository) Create(ctx context.Context, file *models.File) error {
	query := `
		INSERT INTO files (
			claim_code, original_filename, stored_filename, file_size,
			mime_type, expires_at, max_downloads, uploader_ip, password_hash, user_id, sha256_hash,
			client_encrypted, enc_file_id, scan_status, scan_result, scanned_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING id, created_at
	`

	err := r.pool.QueryRow(ctx, query, fileInsertArgs(file)...).Scan(&file.ID, &file.CreatedAt)

	if err != nil {
		if isUniqueViolation(err) {
			return repository.ErrDuplicateKey
		}
		return fmt.Errorf("failed to insert file: %w", err)
	}

	return nil
}

// CreateWithQuotaCheck atomically checks quota and inserts file record in a transaction.
func (r *FileRepository) CreateWithQuotaCheck(ctx context.Context, file *models.File, quotaLimitBytes int64) error {
	return withRetryNoReturn(ctx, 3, func() error {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }() // Safe to ignore: no-op after commit

		// Check quota within transaction
		var currentUsage int64
		query := `
			SELECT
				COALESCE(SUM(file_size), 0) +
				COALESCE((SELECT SUM(total_size) FROM partial_uploads WHERE completed = false), 0)
			FROM files
			WHERE expires_at > NOW()
		`
		if err := tx.QueryRow(ctx, query).Scan(&currentUsage); err != nil {
			return fmt.Errorf("failed to get current usage: %w", err)
		}

		// Check if adding this file would exceed quota (overflow-safe)
		if currentUsage > quotaLimitBytes || file.FileSize > quotaLimitBytes-currentUsage {
			return repository.ErrQuotaExceeded
		}

		// Insert file record
		insertQuery := `
			INSERT INTO files (
				claim_code, original_filename, stored_filename, file_size,
				mime_type, expires_at, max_downloads, uploader_ip, password_hash, user_id, sha256_hash,
				client_encrypted, enc_file_id, scan_status, scan_result, scanned_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
			RETURNING id, created_at
		`

		err = tx.QueryRow(ctx, insertQuery, fileInsertArgs(file)...).Scan(&file.ID, &file.CreatedAt)

		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrDuplicateKey
			}
			return fmt.Errorf("failed to insert file: %w", err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		return nil
	})
}

// GetByID retrieves a file by its database ID.
func (r *FileRepository) GetByID(ctx context.Context, id int64) (*models.File, error) {
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads, download_count, completed_downloads,
			uploader_ip, password_hash, user_id, sha256_hash,
			scan_status, scan_result, scanned_at, client_encrypted, enc_file_id
		FROM files
		WHERE id = $1
	`

	file := &models.File{}
	var passwordHash sql.NullString
	var userID sql.NullInt64
	var sha256Hash sql.NullString
	var maxDownloads sql.NullInt64
	var scanStatus sql.NullString
	var scanResult sql.NullString
	var scannedAt sql.NullTime
	var encFileID []byte

	err := r.pool.QueryRow(ctx, query, id).Scan(
		&file.ID,
		&file.ClaimCode,
		&file.OriginalFilename,
		&file.StoredFilename,
		&file.FileSize,
		&file.MimeType,
		&file.CreatedAt,
		&file.ExpiresAt,
		&maxDownloads,
		&file.DownloadCount,
		&file.CompletedDownloads,
		&file.UploaderIP,
		&passwordHash,
		&userID,
		&sha256Hash,
		&scanStatus,
		&scanResult,
		&scannedAt,
		&file.ClientEncrypted,
		&encFileID,
	)

	if err == pgx.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query file: %w", err)
	}

	// Handle nullable fields
	if maxDownloads.Valid {
		val := int(maxDownloads.Int64)
		file.MaxDownloads = &val
	}
	if passwordHash.Valid {
		file.PasswordHash = passwordHash.String
	}
	if userID.Valid {
		file.UserID = &userID.Int64
	}
	if sha256Hash.Valid {
		file.SHA256Hash = sha256Hash.String
	}
	file.ScanStatus = scanStatus.String
	file.ScanResult = scanResult.String
	if scannedAt.Valid {
		file.ScannedAt = &scannedAt.Time
	}
	file.EncFileID = encFileID // SQL NULL maps to nil via *[]byte scan

	return file, nil
}

// GetByClaimCode retrieves a file by its claim code.
// Returns nil, nil if not found or expired (for backward compatibility).
func (r *FileRepository) GetByClaimCode(ctx context.Context, claimCode string) (*models.File, error) {
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads, download_count, completed_downloads,
			uploader_ip, password_hash, user_id, sha256_hash,
			scan_status, scan_result, scanned_at, client_encrypted, enc_file_id
		FROM files
		WHERE claim_code = $1 AND expires_at > NOW()
	`

	file := &models.File{}
	var passwordHash sql.NullString
	var userID sql.NullInt64
	var sha256Hash sql.NullString
	var maxDownloads sql.NullInt64
	var scanStatus sql.NullString
	var scanResult sql.NullString
	var scannedAt sql.NullTime
	var encFileID []byte

	err := r.pool.QueryRow(ctx, query, claimCode).Scan(
		&file.ID,
		&file.ClaimCode,
		&file.OriginalFilename,
		&file.StoredFilename,
		&file.FileSize,
		&file.MimeType,
		&file.CreatedAt,
		&file.ExpiresAt,
		&maxDownloads,
		&file.DownloadCount,
		&file.CompletedDownloads,
		&file.UploaderIP,
		&passwordHash,
		&userID,
		&sha256Hash,
		&scanStatus,
		&scanResult,
		&scannedAt,
		&file.ClientEncrypted,
		&encFileID,
	)

	if err == pgx.ErrNoRows {
		return nil, nil // File not found or expired
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query file: %w", err)
	}

	// Handle nullable fields
	if maxDownloads.Valid {
		val := int(maxDownloads.Int64)
		file.MaxDownloads = &val
	}
	if passwordHash.Valid {
		file.PasswordHash = passwordHash.String
	}
	if userID.Valid {
		file.UserID = &userID.Int64
	}
	if sha256Hash.Valid {
		file.SHA256Hash = sha256Hash.String
	}
	file.ScanStatus = scanStatus.String
	file.ScanResult = scanResult.String
	if scannedAt.Valid {
		file.ScannedAt = &scannedAt.Time
	}
	file.EncFileID = encFileID // SQL NULL maps to nil via *[]byte scan

	return file, nil
}

// IncrementDownloadCount atomically increments the download counter.
func (r *FileRepository) IncrementDownloadCount(ctx context.Context, id int64) error {
	query := `UPDATE files SET download_count = download_count + 1 WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to increment download count: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// IncrementDownloadCountIfUnchanged increments download count only if claim code matches.
func (r *FileRepository) IncrementDownloadCountIfUnchanged(ctx context.Context, id int64, expectedClaimCode string) error {
	query := `
		UPDATE files
		SET download_count = download_count + 1
		WHERE id = $1 AND claim_code = $2
	`

	result, err := r.pool.Exec(ctx, query, id, expectedClaimCode)
	if err != nil {
		return fmt.Errorf("failed to increment download count: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrClaimCodeChanged
	}

	return nil
}

// TryIncrementDownloadWithLimit atomically increments download count only if under limit.
func (r *FileRepository) TryIncrementDownloadWithLimit(ctx context.Context, id int64, expectedClaimCode string) (bool, error) {
	// Atomic compare-and-increment
	query := `
		UPDATE files
		SET download_count = download_count + 1
		WHERE id = $1
		  AND claim_code = $2
		  AND (max_downloads IS NULL OR max_downloads = 0 OR download_count < max_downloads)
	`

	result, err := r.pool.Exec(ctx, query, id, expectedClaimCode)
	if err != nil {
		return false, fmt.Errorf("failed to increment download count: %w", err)
	}

	if result.RowsAffected() == 0 {
		// Check which case it is: claim code changed OR limit reached
		var currentCount int
		var maxDownloads sql.NullInt64
		checkQuery := `SELECT download_count, max_downloads FROM files WHERE id = $1 AND claim_code = $2`
		err := r.pool.QueryRow(ctx, checkQuery, id, expectedClaimCode).Scan(&currentCount, &maxDownloads)
		if err == pgx.ErrNoRows {
			return false, repository.ErrClaimCodeChanged
		}
		if err != nil {
			return false, fmt.Errorf("failed to check download limit: %w", err)
		}

		// Claim code is valid but limit was reached
		if maxDownloads.Valid {
			maxDL := int(maxDownloads.Int64)
			if maxDL > 0 && currentCount >= maxDL {
				return false, nil // Limit reached
			}
		}

		return false, nil
	}

	return true, nil // Success
}

// newReservationToken returns 16 random bytes hex-encoded (32 ASCII chars).
func newReservationToken() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("failed to generate reservation token: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// ReserveDownload atomically increments in_flight_reservations and inserts a reservation row.
// See ADR-012 for the semantics; the guard is `download_count + in_flight_reservations < max_downloads`.
//
// Wrapped in withRetry because the transaction uses Serializable isolation; under
// concurrent claims on a small cap, Postgres will reject one of two racers with
// serialization_failure (40001) at commit. We re-try with a fresh token on each
// attempt — the rollback guarantees the previous INSERT did not persist.
func (r *FileRepository) ReserveDownload(ctx context.Context, fileID int64, expectedClaimCode string) (string, error) {
	// Fast path: files with no cap don't need a row in download_reservations.
	// Outside the retry loop — max_downloads doesn't move under us in any race we care about.
	var maxDL sql.NullInt64
	if err := r.pool.QueryRow(ctx, `SELECT max_downloads FROM files WHERE id = $1 AND claim_code = $2`, fileID, expectedClaimCode).Scan(&maxDL); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", repository.ErrClaimCodeChanged
		}
		return "", fmt.Errorf("failed to read file metadata for reservation: %w", err)
	}
	if !maxDL.Valid || maxDL.Int64 == 0 {
		return repository.ReservationTokenUnlimited, nil
	}

	return withRetry(ctx, 3, func() (string, error) {
		token, err := newReservationToken()
		if err != nil {
			return "", err
		}

		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return "", fmt.Errorf("failed to begin reserve transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		updateQuery := `
			UPDATE files
			SET in_flight_reservations = in_flight_reservations + 1
			WHERE id = $1
			  AND claim_code = $2
			  AND (download_count + in_flight_reservations) < max_downloads
		`
		res, err := tx.Exec(ctx, updateQuery, fileID, expectedClaimCode)
		if err != nil {
			return "", fmt.Errorf("failed to reserve download slot: %w", err)
		}
		if res.RowsAffected() == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT TRUE FROM files WHERE id = $1 AND claim_code = $2`, fileID, expectedClaimCode).Scan(&exists); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return "", repository.ErrClaimCodeChanged
				}
				return "", fmt.Errorf("failed to disambiguate reservation failure: %w", err)
			}
			return "", nil
		}

		if _, err := tx.Exec(ctx, `INSERT INTO download_reservations (token, file_id) VALUES ($1, $2)`, token, fileID); err != nil {
			return "", fmt.Errorf("failed to insert reservation row: %w", err)
		}

		if err := tx.Commit(ctx); err != nil {
			return "", fmt.Errorf("failed to commit reservation: %w", err)
		}
		return token, nil
	})
}

// CommitDownload finalises a reservation. See ADR-012 §4 for the two-branch semantics.
//
// Wrapped in withRetryNoReturn so a serialization_failure under contention is
// retried rather than bubbling up as a 500 to the user whose download already
// completed.
func (r *FileRepository) CommitDownload(ctx context.Context, fileID int64, token string) error {
	if token == "" {
		return nil
	}
	if token == repository.ReservationTokenUnlimited {
		// No reservation row to delete; just credit the counters. Single-statement
		// UPDATE; no serialization-failure risk — no retry needed.
		_, err := r.pool.Exec(ctx, `
			UPDATE files
			SET download_count      = download_count + 1,
			    completed_downloads = completed_downloads + 1
			WHERE id = $1
		`, fileID)
		if err != nil {
			return fmt.Errorf("failed to credit unlimited download: %w", err)
		}
		return nil
	}

	return withRetryNoReturn(ctx, 3, func() error {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return fmt.Errorf("failed to begin commit transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		res, err := tx.Exec(ctx, `DELETE FROM download_reservations WHERE token = $1 AND file_id = $2`, token, fileID)
		if err != nil {
			return fmt.Errorf("failed to delete reservation: %w", err)
		}

		if res.RowsAffected() == 1 {
			_, err := tx.Exec(ctx, `
				UPDATE files
				SET in_flight_reservations = GREATEST(in_flight_reservations - 1, 0),
				    download_count          = download_count + 1,
				    completed_downloads     = completed_downloads + 1
				WHERE id = $1
			`, fileID)
			if err != nil {
				return fmt.Errorf("failed to finalise download counters: %w", err)
			}
		} else {
			// Reaped-mid-stream recovery: try to atomically take a slot now.
			// Guard MUST match ReserveDownload: (download_count + in_flight) < max_downloads.
			// Using `download_count < max_downloads` alone would let a late-committing
			// reservation jump past a still-live reservation and over-count past the cap
			// (bug-hunter C1: same-token replay or retry-race could double-credit).
			res, err := tx.Exec(ctx, `
				UPDATE files
				SET download_count      = download_count + 1,
				    completed_downloads = completed_downloads + 1
				WHERE id = $1
				  AND (max_downloads IS NULL OR max_downloads = 0
				       OR (download_count + in_flight_reservations) < max_downloads)
			`, fileID)
			if err != nil {
				return fmt.Errorf("failed reaped-recovery increment: %w", err)
			}
			if res.RowsAffected() == 0 {
				slog.Warn("download committed after reaper deleted reservation; cap already taken by another reader — not counting",
					"file_id", fileID,
				)
			}
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit download finalisation: %w", err)
		}
		return nil
	})
}

// CancelDownload releases a reservation without crediting a download.
func (r *FileRepository) CancelDownload(ctx context.Context, fileID int64, token string) error {
	if token == "" || token == repository.ReservationTokenUnlimited {
		return nil
	}

	return withRetryNoReturn(ctx, 3, func() error {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return fmt.Errorf("failed to begin cancel transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		res, err := tx.Exec(ctx, `DELETE FROM download_reservations WHERE token = $1 AND file_id = $2`, token, fileID)
		if err != nil {
			return fmt.Errorf("failed to delete reservation: %w", err)
		}
		if res.RowsAffected() == 1 {
			_, err := tx.Exec(ctx, `
				UPDATE files
				SET in_flight_reservations = GREATEST(in_flight_reservations - 1, 0)
				WHERE id = $1
			`, fileID)
			if err != nil {
				return fmt.Errorf("failed to decrement in_flight: %w", err)
			}
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit cancel: %w", err)
		}
		return nil
	})
}

// ReapStaleReservations deletes rows older than `ttl` and decrements in_flight_reservations accordingly.
// The cutoff is `NOW() - ($1 * interval '1 second')` evaluated DB-side — see interface doc for rationale.
func (r *FileRepository) ReapStaleReservations(ctx context.Context, ttl time.Duration) (int, error) {
	return withRetry(ctx, 3, func() (int, error) {
		return r.reapStaleReservationsOnce(ctx, ttl)
	})
}

func (r *FileRepository) reapStaleReservationsOnce(ctx context.Context, ttl time.Duration) (int, error) {
	// ttl seconds as a float so make_interval / arithmetic stays in the type Postgres
	// expects; negative values are allowed (tests use them to mean "reap everything
	// created before now").
	ttlSecs := ttl.Seconds()

	tx, err := r.pool.BeginTx(ctx, TxOptions())
	if err != nil {
		return 0, fmt.Errorf("failed to begin reaper transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT file_id, COUNT(*)
		FROM download_reservations
		WHERE created_at < NOW() - ($1 * interval '1 second')
		GROUP BY file_id
	`, ttlSecs)
	if err != nil {
		return 0, fmt.Errorf("failed to query stale reservations: %w", err)
	}

	type counter struct {
		fileID int64
		n      int
	}
	var buckets []counter
	for rows.Next() {
		var c counter
		if err := rows.Scan(&c.fileID, &c.n); err != nil {
			rows.Close()
			return 0, fmt.Errorf("failed to scan reaper row: %w", err)
		}
		buckets = append(buckets, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("reaper row iteration error: %w", err)
	}

	if len(buckets) == 0 {
		if err := tx.Commit(ctx); err != nil {
			return 0, fmt.Errorf("failed to commit empty reaper tx: %w", err)
		}
		return 0, nil
	}

	// Delete first, then decrement. The two statements are atomic together
	// inside this Serializable transaction — outside readers (concurrent
	// ReserveDownload calls) see either the pre-reaper state or the
	// post-reaper state, never an intermediate state. Doing DELETE first is
	// belt-and-suspenders for any future refactor that might split the work.
	delRes, err := tx.Exec(ctx, `DELETE FROM download_reservations WHERE created_at < NOW() - ($1 * interval '1 second')`, ttlSecs)
	if err != nil {
		return 0, fmt.Errorf("failed to delete stale reservations: %w", err)
	}
	deleted := delRes.RowsAffected()

	total := 0
	for _, c := range buckets {
		_, err := tx.Exec(ctx, `
			UPDATE files
			SET in_flight_reservations = GREATEST(in_flight_reservations - $1, 0)
			WHERE id = $2
		`, c.n, c.fileID)
		if err != nil {
			return 0, fmt.Errorf("failed to clamp in_flight for file %d: %w", c.fileID, err)
		}
		total += c.n
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("failed to commit reaper tx: %w", err)
	}

	if int(deleted) != total {
		slog.Warn("reaper delete/count mismatch",
			"deleted", deleted,
			"counted", total,
		)
	}
	return int(deleted), nil
}

// IncrementCompletedDownloads increments the completed downloads counter.
//
// Deprecated: see FileRepository.IncrementCompletedDownloads.
func (r *FileRepository) IncrementCompletedDownloads(ctx context.Context, id int64) error {
	query := `UPDATE files SET completed_downloads = completed_downloads + 1 WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to increment completed downloads: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// Delete removes a file record by ID.
func (r *FileRepository) Delete(ctx context.Context, id int64) error {
	query := `DELETE FROM files WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// DeleteByClaimCode removes a file record by claim code.
func (r *FileRepository) DeleteByClaimCode(ctx context.Context, claimCode string) (*models.File, error) {
	return withRetry(ctx, 3, func() (*models.File, error) {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return nil, fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }() // Safe to ignore: no-op after commit

		// Get the file info within transaction
		query := `
			SELECT
				id, claim_code, original_filename, stored_filename, file_size,
				mime_type, created_at, expires_at, max_downloads, download_count, completed_downloads,
				uploader_ip, password_hash, user_id, client_encrypted
			FROM files
			WHERE claim_code = $1
			FOR UPDATE
		`

		file := &models.File{}
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userID sql.NullInt64

		err = tx.QueryRow(ctx, query, claimCode).Scan(
			&file.ID,
			&file.ClaimCode,
			&file.OriginalFilename,
			&file.StoredFilename,
			&file.FileSize,
			&file.MimeType,
			&file.CreatedAt,
			&file.ExpiresAt,
			&maxDownloads,
			&file.DownloadCount,
			&file.CompletedDownloads,
			&file.UploaderIP,
			&passwordHash,
			&userID,
			&file.ClientEncrypted,
		)

		if err == pgx.ErrNoRows {
			return nil, repository.ErrNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("failed to query file: %w", err)
		}

		// Handle nullable fields
		if maxDownloads.Valid {
			val := int(maxDownloads.Int64)
			file.MaxDownloads = &val
		}
		if passwordHash.Valid {
			file.PasswordHash = passwordHash.String
		}
		if userID.Valid {
			file.UserID = &userID.Int64
		}

		// Delete from database within same transaction
		deleteQuery := `DELETE FROM files WHERE claim_code = $1`
		result, err := tx.Exec(ctx, deleteQuery, claimCode)
		if err != nil {
			return nil, fmt.Errorf("failed to delete file from database: %w", err)
		}

		// Verify deletion occurred
		if result.RowsAffected() == 0 {
			return nil, repository.ErrNotFound
		}

		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("failed to commit transaction: %w", err)
		}

		return file, nil
	})
}

// DeleteByClaimCodes removes multiple files by claim codes (bulk operation).
func (r *FileRepository) DeleteByClaimCodes(ctx context.Context, claimCodes []string) ([]*models.File, error) {
	if len(claimCodes) == 0 {
		return nil, repository.ErrInvalidInput
	}

	files := make([]*models.File, 0, len(claimCodes))

	for _, claimCode := range claimCodes {
		query := `
			SELECT
				id, claim_code, original_filename, stored_filename, file_size,
				mime_type, created_at, expires_at, max_downloads, download_count, completed_downloads,
				uploader_ip, password_hash, user_id, client_encrypted
			FROM files
			WHERE claim_code = $1
		`

		file := &models.File{}
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userID sql.NullInt64

		err := r.pool.QueryRow(ctx, query, claimCode).Scan(
			&file.ID,
			&file.ClaimCode,
			&file.OriginalFilename,
			&file.StoredFilename,
			&file.FileSize,
			&file.MimeType,
			&file.CreatedAt,
			&file.ExpiresAt,
			&maxDownloads,
			&file.DownloadCount,
			&file.CompletedDownloads,
			&file.UploaderIP,
			&passwordHash,
			&userID,
			&file.ClientEncrypted,
		)

		if err == pgx.ErrNoRows {
			continue // Skip files that don't exist
		}
		if err != nil {
			return nil, fmt.Errorf("failed to query file %s: %w", claimCode, err)
		}

		// Handle nullable fields
		if maxDownloads.Valid {
			val := int(maxDownloads.Int64)
			file.MaxDownloads = &val
		}
		if passwordHash.Valid {
			file.PasswordHash = passwordHash.String
		}
		if userID.Valid {
			file.UserID = &userID.Int64
		}

		files = append(files, file)
	}

	// Delete all files from database
	if len(files) > 0 {
		claimCodeValues := make([]string, len(files))
		for i, file := range files {
			claimCodeValues[i] = file.ClaimCode
		}

		deleteQuery := `DELETE FROM files WHERE claim_code = ANY($1)`
		_, err := r.pool.Exec(ctx, deleteQuery, claimCodeValues)
		if err != nil {
			return nil, fmt.Errorf("failed to delete files from database: %w", err)
		}
	}

	return files, nil
}

// DeleteExpired removes expired files from database and filesystem.
func (r *FileRepository) DeleteExpired(ctx context.Context, uploadDir string, onExpired repository.ExpiredFileCallback) (int, error) {
	// Find expired files with 1-hour grace period
	query := `
		SELECT id, claim_code, original_filename, stored_filename, file_size, mime_type, expires_at
		FROM files
		WHERE expires_at <= NOW() - INTERVAL '1 hour'
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to query expired files: %w", err)
	}
	// Defensive defer — the explicit Close below normally fires first. pgx.Rows
	// tolerates a second Close.
	defer rows.Close()

	type expiredFileData struct {
		ID               int64
		ClaimCode        string
		OriginalFilename string
		StoredFilename   string
		FileSize         int64
		MimeType         string
		ExpiresAt        time.Time
	}
	var expiredFiles []expiredFileData

	for rows.Next() {
		var f expiredFileData
		if err := rows.Scan(&f.ID, &f.ClaimCode, &f.OriginalFilename, &f.StoredFilename, &f.FileSize, &f.MimeType, &f.ExpiresAt); err != nil {
			slog.Error("failed to scan expired file", "error", err)
			continue
		}
		expiredFiles = append(expiredFiles, f)
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("error iterating expired files: %w", err)
	}

	// SH-3.4: close the read cursor explicitly before doing filesystem deletions
	// and the subsequent batch DELETE. Without this, the pgx connection backing
	// this query stays checked out from the pool across all of the file I/O.
	// (The SQLite path additionally suffers from WAL pinning — see the SQLite
	// implementation for the longer comment.)
	rows.Close()

	// Delete files (file first, then database record)
	var deletedIDs []int64

	for _, f := range expiredFiles {
		// Validate stored filename first
		if err := validateStoredFilename(f.StoredFilename); err != nil {
			slog.Error("stored filename validation failed during cleanup",
				"filename", f.StoredFilename,
				"error", err,
				"file_id", f.ID,
			)
			continue
		}

		// Delete physical file FIRST
		filePath := filepath.Join(uploadDir, f.StoredFilename)
		if err := os.Remove(filePath); err != nil {
			if !os.IsNotExist(err) {
				slog.Error("failed to delete physical file, keeping DB record for retry",
					"path", filePath,
					"file_id", f.ID,
					"error", err,
				)
				continue
			}
			slog.Warn("physical file already deleted", "path", filePath, "file_id", f.ID)
		}

		deletedIDs = append(deletedIDs, f.ID)
		slog.Debug("successfully deleted physical file",
			"file_id", f.ID,
			"filename", f.StoredFilename,
		)
	}

	// Batch delete database records
	deletedCount := 0
	if len(deletedIDs) > 0 {
		deletedCount = r.batchDeleteFiles(ctx, deletedIDs)
	}

	// Invoke callback for each successfully deleted file
	if deletedCount > 0 && onExpired != nil {
		deletedIDSet := make(map[int64]bool)
		for _, id := range deletedIDs {
			deletedIDSet[id] = true
		}

		for _, f := range expiredFiles {
			if deletedIDSet[f.ID] {
				onExpired(f.ClaimCode, f.OriginalFilename, f.FileSize, f.MimeType, f.ExpiresAt)
			}
		}
	}

	// Update query planner statistics after bulk deletes
	if deletedCount >= 100 {
		slog.Info("updating query planner statistics after bulk file deletion",
			"deleted_count", deletedCount)

		if _, err := r.pool.Exec(ctx, "ANALYZE files"); err != nil {
			slog.Warn("failed to analyze files table", "error", err)
		}
	}

	return deletedCount, nil
}

// batchDeleteFiles deletes multiple file records using batch DELETE operations.
func (r *FileRepository) batchDeleteFiles(ctx context.Context, fileIDs []int64) int {
	const batchSize = 500
	deletedCount := 0

	tx, err := r.pool.BeginTx(ctx, TxOptions())
	if err != nil {
		slog.Error("failed to begin transaction for batch delete", "error", err)
		return 0
	}
	defer func() { _ = tx.Rollback(ctx) }() // Safe to ignore: no-op after commit

	// Process in chunks
	for i := 0; i < len(fileIDs); i += batchSize {
		end := i + batchSize
		if end > len(fileIDs) {
			end = len(fileIDs)
		}
		batch := fileIDs[i:end]

		deleteQuery := `DELETE FROM files WHERE id = ANY($1)`
		result, err := tx.Exec(ctx, deleteQuery, batch)
		if err != nil {
			slog.Error("failed to batch delete file records",
				"batch_size", len(batch),
				"error", err,
			)
			return 0
		}

		deletedCount += int(result.RowsAffected())
		slog.Debug("batch deleted file records",
			"batch_size", len(batch),
			"deleted", result.RowsAffected(),
		)
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("failed to commit batch delete transaction", "error", err)
		return 0
	}

	return deletedCount
}

// GetTotalUsage returns the total storage used by active files and partial uploads.
func (r *FileRepository) GetTotalUsage(ctx context.Context) (int64, error) {
	query := `
		SELECT
			COALESCE(SUM(file_size), 0) +
			COALESCE((SELECT SUM(total_size) FROM partial_uploads WHERE completed = false), 0)
		FROM files
		WHERE expires_at > NOW()
	`

	var totalUsage int64
	err := r.pool.QueryRow(ctx, query).Scan(&totalUsage)
	if err != nil {
		return 0, fmt.Errorf("failed to get total usage: %w", err)
	}

	return totalUsage, nil
}

// GetStats returns statistics about file storage.
func (r *FileRepository) GetStats(ctx context.Context, uploadDir string) (*repository.FileStats, error) {
	query := `
		SELECT COUNT(*), COALESCE(SUM(file_size), 0)
		FROM files
		WHERE expires_at > NOW()
	`

	var totalFiles int
	var storageUsed int64
	err := r.pool.QueryRow(ctx, query).Scan(&totalFiles, &storageUsed)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	return &repository.FileStats{
		TotalFiles:  totalFiles,
		StorageUsed: storageUsed,
		ActiveFiles: totalFiles,
		TotalUsage:  storageUsed,
	}, nil
}

// GetAll returns all files in the database (including expired files).
func (r *FileRepository) GetAll(ctx context.Context) ([]*models.File, error) {
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads,
			completed_downloads, uploader_ip, password_hash, user_id, sha256_hash,
			scan_status, scan_result, scanned_at, client_encrypted, enc_file_id
		FROM files
		ORDER BY created_at DESC
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all files: %w", err)
	}
	defer rows.Close()

	var files []*models.File
	for rows.Next() {
		file := &models.File{}
		var passwordHash sql.NullString
		var userID sql.NullInt64
		var sha256Hash sql.NullString
		var maxDownloads sql.NullInt64
		var scanStatus sql.NullString
		var scanResult sql.NullString
		var scannedAt sql.NullTime
		var encFileID []byte

		err := rows.Scan(
			&file.ID,
			&file.ClaimCode,
			&file.OriginalFilename,
			&file.StoredFilename,
			&file.FileSize,
			&file.MimeType,
			&file.CreatedAt,
			&file.ExpiresAt,
			&maxDownloads,
			&file.CompletedDownloads,
			&file.UploaderIP,
			&passwordHash,
			&userID,
			&sha256Hash,
			&scanStatus,
			&scanResult,
			&scannedAt,
			&file.ClientEncrypted,
			&encFileID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan file row: %w", err)
		}

		if maxDownloads.Valid {
			val := int(maxDownloads.Int64)
			file.MaxDownloads = &val
		}
		if passwordHash.Valid {
			file.PasswordHash = passwordHash.String
		}
		if userID.Valid {
			uid := userID.Int64
			file.UserID = &uid
		}
		if sha256Hash.Valid {
			file.SHA256Hash = sha256Hash.String
		}
		file.ScanStatus = scanStatus.String
		file.ScanResult = scanResult.String
		if scannedAt.Valid {
			file.ScannedAt = &scannedAt.Time
		}
		file.EncFileID = encFileID // SQL NULL maps to nil via *[]byte scan

		files = append(files, file)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating file rows: %w", err)
	}

	return files, nil
}

// GetAllStoredFilenames returns all stored filenames as a set.
func (r *FileRepository) GetAllStoredFilenames(ctx context.Context) (map[string]bool, error) {
	query := `SELECT stored_filename FROM files`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query stored filenames: %w", err)
	}
	defer rows.Close()

	filenames := make(map[string]bool)
	for rows.Next() {
		var filename string
		if err := rows.Scan(&filename); err != nil {
			return nil, fmt.Errorf("failed to scan stored filename: %w", err)
		}
		filenames[filename] = true
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating stored filenames: %w", err)
	}

	return filenames, nil
}

// GetAllForAdmin returns all files with pagination for admin dashboard.
func (r *FileRepository) GetAllForAdmin(ctx context.Context, limit, offset int) ([]models.File, int, error) {
	// Validate pagination bounds
	if limit < 0 {
		limit = 0
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM files`
	err := r.pool.QueryRow(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count files: %w", err)
	}

	// Get paginated files with username via LEFT JOIN
	query := `
		SELECT f.id, f.claim_code, f.original_filename, f.stored_filename, f.file_size, f.mime_type,
			f.created_at, f.expires_at, f.max_downloads, f.download_count, f.completed_downloads,
			f.uploader_ip, f.password_hash, f.user_id, u.username,
			f.scan_status, f.scan_result, f.scanned_at, f.client_encrypted
		FROM files f
		LEFT JOIN users u ON f.user_id = u.id
		ORDER BY f.created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query files: %w", err)
	}
	defer rows.Close()

	var files []models.File
	for rows.Next() {
		var file models.File
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userID sql.NullInt64
		var username sql.NullString
		var scanStatus sql.NullString
		var scanResult sql.NullString
		var scannedAt sql.NullTime

		err := rows.Scan(
			&file.ID,
			&file.ClaimCode,
			&file.OriginalFilename,
			&file.StoredFilename,
			&file.FileSize,
			&file.MimeType,
			&file.CreatedAt,
			&file.ExpiresAt,
			&maxDownloads,
			&file.DownloadCount,
			&file.CompletedDownloads,
			&file.UploaderIP,
			&passwordHash,
			&userID,
			&username,
			&scanStatus,
			&scanResult,
			&scannedAt,
			&file.ClientEncrypted,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan file: %w", err)
		}

		// Handle nullable fields
		if maxDownloads.Valid {
			val := int(maxDownloads.Int64)
			file.MaxDownloads = &val
		}
		if passwordHash.Valid {
			file.PasswordHash = passwordHash.String
		}
		if userID.Valid {
			file.UserID = &userID.Int64
		}
		if username.Valid {
			file.Username = &username.String
		}
		file.ScanStatus = scanStatus.String
		file.ScanResult = scanResult.String
		if scannedAt.Valid {
			file.ScannedAt = &scannedAt.Time
		}

		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating files: %w", err)
	}

	return files, total, nil
}

// SearchForAdmin searches files by claim code, filename, IP, or username.
func (r *FileRepository) SearchForAdmin(ctx context.Context, searchTerm string, limit, offset int) ([]models.File, int, error) {
	// Validate pagination bounds
	if limit < 0 {
		limit = 0
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	// Escape LIKE wildcards to prevent LIKE injection
	escapedTerm := escapeLikePattern(searchTerm)
	searchPattern := "%" + escapedTerm + "%"

	// Get total count
	var total int
	countQuery := `
		SELECT COUNT(*) FROM files f
		LEFT JOIN users u ON f.user_id = u.id
		WHERE f.claim_code ILIKE $1 ESCAPE '\' 
		   OR f.original_filename ILIKE $1 ESCAPE '\' 
		   OR f.uploader_ip ILIKE $1 ESCAPE '\' 
		   OR u.username ILIKE $1 ESCAPE '\'
	`
	err := r.pool.QueryRow(ctx, countQuery, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	// Get paginated results with username via LEFT JOIN
	query := `
		SELECT f.id, f.claim_code, f.original_filename, f.stored_filename, f.file_size, f.mime_type,
			f.created_at, f.expires_at, f.max_downloads, f.download_count, f.completed_downloads,
			f.uploader_ip, f.password_hash, f.user_id, u.username,
			f.scan_status, f.scan_result, f.scanned_at, f.client_encrypted
		FROM files f
		LEFT JOIN users u ON f.user_id = u.id
		WHERE f.claim_code ILIKE $1 ESCAPE '\'
		   OR f.original_filename ILIKE $1 ESCAPE '\'
		   OR f.uploader_ip ILIKE $1 ESCAPE '\'
		   OR u.username ILIKE $1 ESCAPE '\'
		ORDER BY f.created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.pool.Query(ctx, query, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search files: %w", err)
	}
	defer rows.Close()

	var files []models.File
	for rows.Next() {
		var file models.File
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userID sql.NullInt64
		var username sql.NullString
		var scanStatus sql.NullString
		var scanResult sql.NullString
		var scannedAt sql.NullTime

		err := rows.Scan(
			&file.ID,
			&file.ClaimCode,
			&file.OriginalFilename,
			&file.StoredFilename,
			&file.FileSize,
			&file.MimeType,
			&file.CreatedAt,
			&file.ExpiresAt,
			&maxDownloads,
			&file.DownloadCount,
			&file.CompletedDownloads,
			&file.UploaderIP,
			&passwordHash,
			&userID,
			&username,
			&scanStatus,
			&scanResult,
			&scannedAt,
			&file.ClientEncrypted,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan file: %w", err)
		}

		// Handle nullable fields
		if maxDownloads.Valid {
			val := int(maxDownloads.Int64)
			file.MaxDownloads = &val
		}
		if passwordHash.Valid {
			file.PasswordHash = passwordHash.String
		}
		if userID.Valid {
			file.UserID = &userID.Int64
		}
		if username.Valid {
			file.Username = &username.String
		}
		file.ScanStatus = scanStatus.String
		file.ScanResult = scanResult.String
		if scannedAt.Valid {
			file.ScannedAt = &scannedAt.Time
		}

		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating search results: %w", err)
	}

	return files, total, nil
}

// UpdateScanStatus updates the malware scan status for a file.
func (r *FileRepository) UpdateScanStatus(ctx context.Context, id int64, status string, result string) error {
	query := `UPDATE files SET scan_status = $1, scan_result = $2, scanned_at = $3 WHERE id = $4`
	res, err := r.pool.Exec(ctx, query, status, result, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update scan status: %w", err)
	}
	if res.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// Ensure FileRepository implements repository.FileRepository.
var _ repository.FileRepository = (*FileRepository)(nil)
