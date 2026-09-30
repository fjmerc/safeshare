// Package postgres provides PostgreSQL implementations of repository interfaces.
package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
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
	if err := insertFile(ctx, r.pool, file); err != nil {
		if isUniqueViolation(err) {
			return repository.ErrDuplicateKey
		}
		return err
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
		// Defense in depth (bug-hunter finding, ADR-015): infected-audit rows
		// are already inserted with file_size=0, but exclude them explicitly
		// too, so a future insert bug can't silently reintroduce quota inflation.
		query := `
			SELECT
				COALESCE(SUM(file_size), 0) +
				COALESCE((SELECT SUM(total_size) FROM partial_uploads WHERE completed = false), 0)
			FROM files
			WHERE expires_at > NOW()
			AND (scan_status IS NULL OR scan_status != 'infected')
		`
		if err := tx.QueryRow(ctx, query).Scan(&currentUsage); err != nil {
			return fmt.Errorf("failed to get current usage: %w", err)
		}

		// Check if adding this file would exceed quota (overflow-safe)
		if currentUsage > quotaLimitBytes || file.FileSize > quotaLimitBytes-currentUsage {
			return repository.ErrQuotaExceeded
		}

		// Insert file record
		if err := insertFile(ctx, tx, file); err != nil {
			if isUniqueViolation(err) {
				return repository.ErrDuplicateKey
			}
			return err
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
			scan_status, scan_result, scanned_at, client_encrypted, enc_file_id, uncounted_bytes
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
		&file.UncountedBytes,
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
			scan_status, scan_result, scanned_at, client_encrypted, enc_file_id, uncounted_bytes
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
		&file.UncountedBytes,
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

// newDownloadSessionToken generates a 32-byte crypto/rand bearer token,
// base64url-encoded (43 ASCII chars, no padding) for the X-Download-Session
// header, plus the hex-encoded SHA-256 hash under which it is stored and
// looked up. Only the hash ever touches the database — see the SQLite
// counterpart for the full rationale.
func newDownloadSessionToken() (token, hash string, err error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", "", fmt.Errorf("failed to generate download session token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(buf[:])
	return token, hashDownloadSessionToken(token), nil
}

// hashDownloadSessionToken returns the hex-encoded SHA-256 hash used as the
// download_sessions primary key.
func hashDownloadSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ReserveDownload atomically increments in_flight_reservations and inserts an
// UNCOMMITTED download_sessions row, atomically charging that session's
// probe-threshold allowance against files.uncounted_bytes in the same
// transaction. See ADR-014 (amending ADR-012); the guard is
// `download_count + in_flight_reservations < max_downloads`.
//
// Wrapped in withRetry because the transaction uses Serializable isolation; under
// concurrent claims on a small cap, Postgres will reject one of two racers with
// serialization_failure (40001) at commit. We re-try with a fresh token on each
// attempt — the rollback guarantees the previous INSERT did not persist.
func (r *FileRepository) ReserveDownload(ctx context.Context, fileID int64, expectedClaimCode string) (string, int64, error) {
	// Fast path: files with no cap don't need a row in download_sessions.
	// Outside the retry loop — max_downloads doesn't move under us in any race we care about.
	var maxDL sql.NullInt64
	if err := r.pool.QueryRow(ctx, `SELECT max_downloads FROM files WHERE id = $1 AND claim_code = $2`, fileID, expectedClaimCode).Scan(&maxDL); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", 0, repository.ErrClaimCodeChanged
		}
		return "", 0, fmt.Errorf("failed to read file metadata for reservation: %w", err)
	}
	if !maxDL.Valid || maxDL.Int64 == 0 {
		return repository.ReservationTokenUnlimited, 0, nil
	}

	type reserveResult struct {
		token   string
		granted int64
	}
	result, err := withRetry(ctx, 3, func() (reserveResult, error) {
		token, hash, err := newDownloadSessionToken()
		if err != nil {
			return reserveResult{}, err
		}

		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return reserveResult{}, fmt.Errorf("failed to begin reserve transaction: %w", err)
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
			return reserveResult{}, fmt.Errorf("failed to reserve download slot: %w", err)
		}
		if res.RowsAffected() == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT TRUE FROM files WHERE id = $1 AND claim_code = $2`, fileID, expectedClaimCode).Scan(&exists); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return reserveResult{}, repository.ErrClaimCodeChanged
				}
				return reserveResult{}, fmt.Errorf("failed to disambiguate reservation failure: %w", err)
			}
			return reserveResult{}, nil
		}

		// Compute and charge this session's probe-threshold allowance from a
		// FRESH read of file_size/uncounted_bytes taken inside this
		// Serializable transaction — not from a snapshot the caller may have
		// read before this call — so concurrent reservations on the same
		// file can't each be granted a full allowance before any of them
		// charges the shared budget (bug-hunter finding).
		var fileSize, uncountedBytes int64
		if err := tx.QueryRow(ctx, `SELECT file_size, uncounted_bytes FROM files WHERE id = $1`, fileID).Scan(&fileSize, &uncountedBytes); err != nil {
			return reserveResult{}, fmt.Errorf("failed to read file size for probe grant: %w", err)
		}
		threshold := repository.ProbeThreshold(fileSize)
		remaining := repository.ProbeBudget(threshold) - uncountedBytes
		if remaining < 0 {
			remaining = 0
		}
		granted := threshold
		if granted > remaining {
			granted = remaining
		}
		if granted > 0 {
			if _, err := tx.Exec(ctx, `UPDATE files SET uncounted_bytes = uncounted_bytes + $1 WHERE id = $2`, granted, fileID); err != nil {
				return reserveResult{}, fmt.Errorf("failed to charge probe grant: %w", err)
			}
		}

		if _, err := tx.Exec(ctx, `INSERT INTO download_sessions (token_hash, file_id, probe_bytes_granted) VALUES ($1, $2, $3)`, hash, fileID, granted); err != nil {
			return reserveResult{}, fmt.Errorf("failed to insert download session row: %w", err)
		}

		if err := tx.Commit(ctx); err != nil {
			return reserveResult{}, fmt.Errorf("failed to commit reservation: %w", err)
		}
		return reserveResult{token: token, granted: granted}, nil
	})
	if err != nil {
		return "", 0, err
	}
	return result.token, result.granted, nil
}

// ReserveSessionBytes implements repository.FileRepository.ReserveSessionBytes.
//
// T42: a completed session is also eligible while it is still within
// completeGrace of its own completed_at — re-checked atomically here (not
// just trusted from an earlier LookupDownloadSession call) so a session that
// crosses the grace boundary between the two calls can't sneak past it. The
// `$5 > 0` guard means a disabled grace (<= 0) makes the whole clause
// collapse to the original `completed_at IS NULL` check.
func (r *FileRepository) ReserveSessionBytes(ctx context.Context, fileID int64, token string, length, limit int64, completeGrace time.Duration) (bool, error) {
	if token == "" || token == repository.ReservationTokenUnlimited {
		return false, nil
	}
	hash := hashDownloadSessionToken(token)
	// int64 seconds, matching sqlite's own int64(completeGrace.Seconds())
	// conversion for this same boolean-guard/interval-multiplier value.
	completeGraceSecs := int64(completeGrace.Seconds())

	res, err := r.pool.Exec(ctx, `
		UPDATE download_sessions
		SET bytes_reserved = bytes_reserved + $1, last_seen_at = NOW()
		WHERE token_hash = $2 AND file_id = $3
		  AND (completed_at IS NULL OR ($5 > 0 AND completed_at >= NOW() - ($5 * interval '1 second')))
		  AND bytes_reserved + $1 <= $4
	`, length, hash, fileID, limit, completeGraceSecs)
	if err != nil {
		return false, fmt.Errorf("failed to reserve session bytes: %w", err)
	}
	return res.RowsAffected() == 1, nil
}

// ReleaseSessionBytes implements repository.FileRepository.ReleaseSessionBytes.
func (r *FileRepository) ReleaseSessionBytes(ctx context.Context, fileID int64, token string, amount int64) error {
	if token == "" || token == repository.ReservationTokenUnlimited || amount <= 0 {
		return nil
	}
	hash := hashDownloadSessionToken(token)
	_, err := r.pool.Exec(ctx, `
		UPDATE download_sessions
		SET bytes_reserved = GREATEST(bytes_reserved - $1, 0)
		WHERE token_hash = $2 AND file_id = $3
	`, amount, hash, fileID)
	if err != nil {
		return fmt.Errorf("failed to release session bytes: %w", err)
	}
	return nil
}

// LookupDownloadSession implements repository.FileRepository.LookupDownloadSession.
func (r *FileRepository) LookupDownloadSession(ctx context.Context, fileID int64, token string, idleTTL, maxAge, completeGrace time.Duration) (*repository.DownloadSession, error) {
	if token == "" || token == repository.ReservationTokenUnlimited {
		return nil, nil
	}
	hash := hashDownloadSessionToken(token)

	var (
		createdAt, lastSeenAt      time.Time
		committedAt, completedAt   sql.NullTime
		bytesServed, bytesReserved int64
	)
	err := r.pool.QueryRow(ctx, `
		SELECT created_at, last_seen_at, committed_at, completed_at, bytes_served, bytes_reserved
		FROM download_sessions
		WHERE token_hash = $1 AND file_id = $2
	`, hash, fileID).Scan(&createdAt, &lastSeenAt, &committedAt, &completedAt, &bytesServed, &bytesReserved)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to look up download session: %w", err)
	}

	// A completed session has already delivered the whole file once.
	// Unconditionally letting it resolve would let its token be replayed
	// indefinitely (bounded only by idleTTL/maxAge, up to SessionMaxAge) to
	// redeliver the file to anyone holding the token (bug-hunter finding —
	// HIGH). T42 (amending ADR-014): a short completeGrace window after
	// completed_at is the one exception — it lets a client that paused right
	// after the server wrote the last byte (but before the client received
	// it) resume with its still-valid token instead of getting a 410, without
	// reopening the original replay concern: ReserveSessionBytes re-checks
	// (and bounds) eligibility atomically, and CommitDownloadSession /
	// CompleteDownloadSession are idempotent no-ops for an already-committed /
	// -completed session, so a grace-window resume can never double-credit
	// download_count or re-fire file.downloaded. completeGrace <= 0 disables
	// this and restores the original unconditional rejection.
	if completedAt.Valid {
		if completeGrace <= 0 {
			return nil, nil
		}
		if time.Since(completedAt.Time) > completeGrace {
			return nil, nil
		}
		// A completed session's lifecycle inside the grace window is governed
		// solely by completeGrace, not by idleTTL/maxAge — those bound how
		// long a still-in-flight (not yet completed) session stays resumable,
		// a different question.
		return &repository.DownloadSession{
			FileID:        fileID,
			Committed:     true,
			Completed:     true,
			BytesServed:   bytesServed,
			BytesReserved: bytesReserved,
			CreatedAt:     createdAt,
			LastSeenAt:    lastSeenAt,
			CompletedAt:   completedAt.Time,
		}, nil
	}

	// A foreign/expired token gets no oracle: treat it exactly like "not
	// found" so the caller falls back to a fresh, tokenless download.
	//
	// This cutoff check is deliberately Go-side (unlike ReapDownloadSessions'
	// DB-side NOW() - interval cutoffs): worst case under application/DB
	// clock skew is that a borderline-fresh token is rejected a little early
	// or a little late, which just falls back to (or delays falling back to)
	// a fresh reservation — it can never let a session be double-counted or
	// push download_count past max_downloads, so the skew risk that matters
	// for the reaper's cutoffs (bug-hunter M4) doesn't apply here.
	now := time.Now()
	if maxAge > 0 && now.Sub(createdAt) > maxAge {
		return nil, nil
	}
	if idleTTL > 0 && now.Sub(lastSeenAt) > idleTTL {
		return nil, nil
	}

	return &repository.DownloadSession{
		FileID:        fileID,
		Committed:     committedAt.Valid,
		Completed:     completedAt.Valid,
		BytesServed:   bytesServed,
		BytesReserved: bytesReserved,
		CreatedAt:     createdAt,
		LastSeenAt:    lastSeenAt,
	}, nil
}

// CommitDownloadSession implements repository.FileRepository.CommitDownloadSession.
// See ADR-014 for the three-outcome semantics.
//
// Wrapped in withRetry so a serialization_failure under contention is retried
// rather than bubbling up as a 500 to a client whose download already committed.
func (r *FileRepository) CommitDownloadSession(ctx context.Context, fileID int64, token string) (repository.DownloadCommitResult, error) {
	if token == "" || token == repository.ReservationTokenUnlimited {
		return repository.DownloadCommitAlreadyCommitted, nil
	}
	hash := hashDownloadSessionToken(token)

	return withRetry(ctx, 3, func() (repository.DownloadCommitResult, error) {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return 0, fmt.Errorf("failed to begin commit-session transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		res, err := tx.Exec(ctx, `
			UPDATE download_sessions
			SET committed_at = NOW(), last_seen_at = NOW()
			WHERE token_hash = $1 AND file_id = $2 AND committed_at IS NULL
		`, hash, fileID)
		if err != nil {
			return 0, fmt.Errorf("failed to mark download session committed: %w", err)
		}

		if res.RowsAffected() == 1 {
			// Refund this session's entire probe grant — it's a real,
			// credited download now, not an uncounted probe (the UPDATE
			// above didn't touch probe_bytes_granted).
			var granted int64
			if err := tx.QueryRow(ctx, `SELECT probe_bytes_granted FROM download_sessions WHERE token_hash = $1 AND file_id = $2`, hash, fileID).Scan(&granted); err != nil {
				return 0, fmt.Errorf("failed to read probe grant for refund: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE files
				SET in_flight_reservations = GREATEST(in_flight_reservations - 1, 0),
				    download_count          = download_count + 1,
				    uncounted_bytes         = GREATEST(uncounted_bytes - $1, 0)
				WHERE id = $2
			`, granted, fileID); err != nil {
				return 0, fmt.Errorf("failed to finalise download-session counters: %w", err)
			}
			if err := tx.Commit(ctx); err != nil {
				return 0, fmt.Errorf("failed to commit download-session finalisation: %w", err)
			}
			return repository.DownloadCommitCredited, nil
		}

		// Either already committed, or the row is gone entirely (reaped mid-stream).
		var exists bool
		err = tx.QueryRow(ctx, `SELECT TRUE FROM download_sessions WHERE token_hash = $1 AND file_id = $2`, hash, fileID).Scan(&exists)
		switch {
		case err == nil:
			if cErr := tx.Commit(ctx); cErr != nil {
				return 0, fmt.Errorf("failed to commit no-op session commit: %w", cErr)
			}
			return repository.DownloadCommitAlreadyCommitted, nil
		case errors.Is(err, pgx.ErrNoRows):
			// Reaped-mid-stream recovery: try to atomically take a slot now.
			// Guard MUST match ReserveDownload: (download_count + in_flight) < max_downloads.
			// Using `download_count < max_downloads` alone would let a late-committing
			// session jump past a still-live reservation and over-count past the cap
			// (bug-hunter C1: same-token replay or retry-race could double-credit).
			recover, err := tx.Exec(ctx, `
				UPDATE files
				SET download_count = download_count + 1
				WHERE id = $1
				  AND (max_downloads IS NULL OR max_downloads = 0
				       OR (download_count + in_flight_reservations) < max_downloads)
			`, fileID)
			if err != nil {
				return 0, fmt.Errorf("failed reaped-recovery increment: %w", err)
			}
			if recover.RowsAffected() == 0 {
				slog.Warn("download session committed after reaper cancelled it; cap already taken by another reader — not counting",
					"file_id", fileID,
				)
				if cErr := tx.Commit(ctx); cErr != nil {
					return 0, fmt.Errorf("failed to commit slot-lost no-op: %w", cErr)
				}
				return repository.DownloadCommitSlotLost, nil
			}
			// Re-insert a committed row under the same hash so a later
			// CompleteDownloadSession call can still find it.
			// probe_bytes_granted defaults to 0: the original row's grant
			// was already refunded by whatever swept it (ReapDownloadSessions'
			// phase 1 refunds probe_bytes_granted - bytes_served as it
			// deletes the row), so refunding again here would over-credit
			// the file's uncounted-bytes budget.
			if _, err := tx.Exec(ctx, `
				INSERT INTO download_sessions (token_hash, file_id, committed_at, last_seen_at)
				VALUES ($1, $2, NOW(), NOW())
			`, hash, fileID); err != nil {
				return 0, fmt.Errorf("failed to re-insert recovered download session: %w", err)
			}
			if err := tx.Commit(ctx); err != nil {
				return 0, fmt.Errorf("failed to commit reaped-recovery: %w", err)
			}
			return repository.DownloadCommitCredited, nil
		default:
			return 0, fmt.Errorf("failed to disambiguate commit-session failure: %w", err)
		}
	})
}

// TouchDownloadSession implements repository.FileRepository.TouchDownloadSession.
func (r *FileRepository) TouchDownloadSession(ctx context.Context, fileID int64, token string, bytesDelta int64) error {
	if token == "" || token == repository.ReservationTokenUnlimited {
		return nil
	}
	hash := hashDownloadSessionToken(token)
	_, err := r.pool.Exec(ctx, `
		UPDATE download_sessions
		SET last_seen_at = NOW(), bytes_served = bytes_served + $1
		WHERE token_hash = $2 AND file_id = $3
	`, bytesDelta, hash, fileID)
	if err != nil {
		return fmt.Errorf("failed to touch download session: %w", err)
	}
	return nil
}

// CompleteDownloadSession implements repository.FileRepository.CompleteDownloadSession.
func (r *FileRepository) CompleteDownloadSession(ctx context.Context, fileID int64, token string) (bool, error) {
	if token == "" || token == repository.ReservationTokenUnlimited {
		return false, nil
	}
	hash := hashDownloadSessionToken(token)

	return withRetry(ctx, 3, func() (bool, error) {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return false, fmt.Errorf("failed to begin complete-session transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		res, err := tx.Exec(ctx, `
			UPDATE download_sessions
			SET completed_at = NOW()
			WHERE token_hash = $1 AND file_id = $2 AND committed_at IS NOT NULL AND completed_at IS NULL
		`, hash, fileID)
		if err != nil {
			return false, fmt.Errorf("failed to mark download session complete: %w", err)
		}
		if res.RowsAffected() != 1 {
			if err := tx.Commit(ctx); err != nil {
				return false, fmt.Errorf("failed to commit no-op session completion: %w", err)
			}
			return false, nil
		}

		if _, err := tx.Exec(ctx, `UPDATE files SET completed_downloads = completed_downloads + 1 WHERE id = $1`, fileID); err != nil {
			return false, fmt.Errorf("failed to increment completed_downloads: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf("failed to commit session completion: %w", err)
		}
		return true, nil
	})
}

// CommitDownload finalises a reservation/session and credits both
// download_count and completed_downloads in one call. See the interface doc
// for why this exists alongside CommitDownloadSession/CompleteDownloadSession.
func (r *FileRepository) CommitDownload(ctx context.Context, fileID int64, token string) error {
	if token == "" {
		return nil
	}
	if token == repository.ReservationTokenUnlimited {
		// No session row to update; just credit the counters. Single-statement
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

	result, err := r.CommitDownloadSession(ctx, fileID, token)
	if err != nil {
		return err
	}
	if result == repository.DownloadCommitSlotLost {
		return nil
	}
	if _, err := r.CompleteDownloadSession(ctx, fileID, token); err != nil {
		return err
	}
	return nil
}

// CancelDownload releases an uncommitted download session without crediting a
// download. A no-op if the row is missing or already committed.
func (r *FileRepository) CancelDownload(ctx context.Context, fileID int64, token string) error {
	if token == "" || token == repository.ReservationTokenUnlimited {
		return nil
	}
	hash := hashDownloadSessionToken(token)

	return withRetryNoReturn(ctx, 3, func() error {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return fmt.Errorf("failed to begin cancel transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		var bytesServed, probeGranted int64
		err = tx.QueryRow(ctx, `
			SELECT bytes_served, probe_bytes_granted FROM download_sessions
			WHERE token_hash = $1 AND file_id = $2 AND committed_at IS NULL
		`, hash, fileID).Scan(&bytesServed, &probeGranted)
		if errors.Is(err, pgx.ErrNoRows) {
			// Missing, or already committed — nothing to cancel.
			return tx.Commit(ctx)
		}
		if err != nil {
			return fmt.Errorf("failed to read download session for cancel: %w", err)
		}

		if _, err := tx.Exec(ctx, `DELETE FROM download_sessions WHERE token_hash = $1 AND file_id = $2`, hash, fileID); err != nil {
			return fmt.Errorf("failed to delete download session: %w", err)
		}
		// Refund only the unspent portion of the grant: it was charged in
		// full at Reserve time, and bytes the session actually served stay
		// charged against the file's probe budget even though this download
		// itself was never credited.
		refund := probeGranted - bytesServed
		if refund < 0 {
			refund = 0
		}
		if _, err := tx.Exec(ctx, `
			UPDATE files
			SET in_flight_reservations = GREATEST(in_flight_reservations - 1, 0),
			    uncounted_bytes         = GREATEST(uncounted_bytes - $1, 0)
			WHERE id = $2
		`, refund, fileID); err != nil {
			return fmt.Errorf("failed to decrement in_flight / refund uncounted_bytes: %w", err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit cancel: %w", err)
		}
		return nil
	})
}

// ReapDownloadSessions implements repository.FileRepository.ReapDownloadSessions.
// See the interface doc for the two independent sweep classes. The cutoffs are
// computed DB-side (`NOW() - ($n * interval '1 second')`) — see interface doc
// for rationale.
func (r *FileRepository) ReapDownloadSessions(ctx context.Context, leaseTTL, idleTTL, maxAge, completeGrace time.Duration) (int, int, error) {
	res, err := withRetry(ctx, 3, func() (reapDownloadSessionsResult, error) {
		return r.reapDownloadSessionsOnce(ctx, leaseTTL, idleTTL, maxAge, completeGrace)
	})
	if err != nil {
		return 0, 0, err
	}
	return res.cancelled, res.expired, nil
}

// reapDownloadSessionsResult bundles ReapDownloadSessions' two counts through
// withRetry's single generic return value.
type reapDownloadSessionsResult struct {
	cancelled int
	expired   int
}

func (r *FileRepository) reapDownloadSessionsOnce(ctx context.Context, leaseTTL, idleTTL, maxAge, completeGrace time.Duration) (reapDownloadSessionsResult, error) {
	leaseSecs := leaseTTL.Seconds()
	idleSecs := idleTTL.Seconds()
	maxAgeSecs := maxAge.Seconds()
	// int64, matching sqlite's own int64(completeGrace.Seconds()) conversion
	// — graceSecs doubles as the `$3 <= 0` boolean guard below, not just an
	// interval multiplier like the other three.
	graceSecs := int64(completeGrace.Seconds())

	tx, err := r.pool.BeginTx(ctx, TxOptions())
	if err != nil {
		return reapDownloadSessionsResult{}, fmt.Errorf("failed to begin reaper transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Resolve every cutoff to a concrete instant ONCE, inside this
	// transaction, and bind that same value to every statement that needs
	// it. Letting the SELECT and the DELETE below each independently
	// evaluate NOW() - interval meant a row whose last_seen_at fell in the
	// (real, if narrow) gap between the two statements' evaluations could be
	// swept by the DELETE's later "now" without ever appearing in the
	// SELECT's bucket — deleted but never refunded (bug-hunter finding).
	var leaseCutoff, idleCutoff, maxAgeCutoff, graceCutoff time.Time
	if err := tx.QueryRow(ctx, `SELECT NOW() - ($1 * interval '1 second'), NOW() - ($2 * interval '1 second'), NOW() - ($3 * interval '1 second'), NOW() - ($4 * interval '1 second')`,
		leaseSecs, idleSecs, maxAgeSecs, graceSecs).Scan(&leaseCutoff, &idleCutoff, &maxAgeCutoff, &graceCutoff); err != nil {
		return reapDownloadSessionsResult{}, fmt.Errorf("failed to resolve reaper cutoffs: %w", err)
	}

	// Phase 1: uncommitted rows whose lease has lapsed — treated as abandoned.
	// Refunds in_flight and, per row, GREATEST(0, probe_bytes_granted -
	// bytes_served) — computed per row inside SQL (not on the file's
	// aggregated totals), so one session that over-served its own grant
	// can't cancel out the refund genuinely owed by another session on the
	// same file (matches the mock's already-per-row behaviour) — before
	// deleting.
	rows, err := tx.Query(ctx, `
		SELECT file_id, COUNT(*), COALESCE(SUM(GREATEST(probe_bytes_granted - bytes_served, 0)), 0)
		FROM download_sessions
		WHERE committed_at IS NULL AND last_seen_at < $1
		GROUP BY file_id
	`, leaseCutoff)
	if err != nil {
		return reapDownloadSessionsResult{}, fmt.Errorf("failed to query abandoned download sessions: %w", err)
	}

	type bucket struct {
		fileID int64
		n      int
		refund int64
	}
	var buckets []bucket
	for rows.Next() {
		var b bucket
		if err := rows.Scan(&b.fileID, &b.n, &b.refund); err != nil {
			rows.Close()
			return reapDownloadSessionsResult{}, fmt.Errorf("failed to scan reaper row: %w", err)
		}
		buckets = append(buckets, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return reapDownloadSessionsResult{}, fmt.Errorf("reaper row iteration error: %w", err)
	}

	cancelled := 0
	if len(buckets) > 0 {
		// Same pre-resolved leaseCutoff as the SELECT above, so this can
		// never delete a row the SELECT didn't also see.
		delRes, err := tx.Exec(ctx, `DELETE FROM download_sessions WHERE committed_at IS NULL AND last_seen_at < $1`, leaseCutoff)
		if err != nil {
			return reapDownloadSessionsResult{}, fmt.Errorf("failed to delete abandoned download sessions: %w", err)
		}
		deleted := delRes.RowsAffected()

		total := 0
		for _, b := range buckets {
			if _, err := tx.Exec(ctx, `
				UPDATE files
				SET in_flight_reservations = GREATEST(in_flight_reservations - $1, 0),
				    uncounted_bytes         = GREATEST(uncounted_bytes - $2, 0)
				WHERE id = $3
			`, b.n, b.refund, b.fileID); err != nil {
				return reapDownloadSessionsResult{}, fmt.Errorf("failed to clamp in_flight for file %d: %w", b.fileID, err)
			}
			total += b.n
		}
		if int(deleted) != total {
			slog.Warn("reaper delete/count mismatch (abandoned sessions)",
				"deleted", deleted,
				"counted", total,
			)
		}
		cancelled = int(deleted)
	}

	// Phase 2: committed rows idle too long, or past the absolute max age.
	// Pure record cleanup — the download was already credited at commit time,
	// so no counter change.
	//
	// T42: a completed row is additionally protected until completeGrace has
	// elapsed since its own completed_at, so LookupDownloadSession's grace
	// window (see its doc comment) always has a row left to find — otherwise
	// an operator-configured idleTTL shorter than completeGrace could let the
	// reaper delete a just-completed session before the client gets a chance
	// to resume with it. The `$3 <= 0` guard collapses this back to the
	// original, ungated idle/max-age-only rule when completeGrace is
	// disabled, matching pre-T42 behaviour exactly.
	expiredRes, err := tx.Exec(ctx, `
		DELETE FROM download_sessions
		WHERE committed_at IS NOT NULL
		  AND (
		        (completed_at IS NOT NULL
		         AND ($3 <= 0 OR completed_at < $4)
		         AND (last_seen_at < $1 OR created_at < $2))
		        OR
		        (completed_at IS NULL AND (last_seen_at < $1 OR created_at < $2))
		      )
	`, idleCutoff, maxAgeCutoff, graceSecs, graceCutoff)
	if err != nil {
		return reapDownloadSessionsResult{}, fmt.Errorf("failed to delete expired committed download sessions: %w", err)
	}
	expiredCount := expiredRes.RowsAffected()

	if err := tx.Commit(ctx); err != nil {
		return reapDownloadSessionsResult{}, fmt.Errorf("failed to commit reaper tx: %w", err)
	}
	return reapDownloadSessionsResult{cancelled: cancelled, expired: int(expiredCount)}, nil
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
	// Defense in depth (bug-hunter finding, ADR-015): see CreateWithQuotaCheck.
	query := `
		SELECT
			COALESCE(SUM(file_size), 0) +
			COALESCE((SELECT SUM(total_size) FROM partial_uploads WHERE completed = false), 0)
		FROM files
		WHERE expires_at > NOW()
		AND (scan_status IS NULL OR scan_status != 'infected')
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
	// Defense in depth (bug-hunter finding, ADR-015): infected-audit rows
	// count toward the file total but never toward storageUsed — see
	// CreateWithQuotaCheck.
	query := `
		SELECT COUNT(*), COALESCE(SUM(CASE WHEN scan_status IS NULL OR scan_status != 'infected' THEN file_size ELSE 0 END), 0)
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
