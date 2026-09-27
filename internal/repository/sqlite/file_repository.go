// Package sqlite provides SQLite implementations of repository interfaces.
package sqlite

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
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// FileRepository implements repository.FileRepository for SQLite.
type FileRepository struct {
	db *sql.DB
}

// NewFileRepository creates a new SQLite file repository.
func NewFileRepository(db *sql.DB) *FileRepository {
	return &FileRepository{db: db}
}

// Create inserts a new file record into the database.
func (r *FileRepository) Create(ctx context.Context, file *models.File) error {
	query := `
		INSERT INTO files (
			claim_code, original_filename, stored_filename, file_size,
			mime_type, expires_at, max_downloads, uploader_ip, password_hash, user_id, sha256_hash,
			client_encrypted, enc_file_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	// Format ExpiresAt as RFC3339 for consistent SQLite datetime() parsing
	expiresAtRFC3339 := file.ExpiresAt.Format(time.RFC3339)

	result, err := r.db.ExecContext(
		ctx,
		query,
		file.ClaimCode,
		file.OriginalFilename,
		file.StoredFilename,
		file.FileSize,
		file.MimeType,
		expiresAtRFC3339,
		file.MaxDownloads,
		file.UploaderIP,
		file.PasswordHash,
		file.UserID,
		file.SHA256Hash,
		file.ClientEncrypted,
		nullableBlob(file.EncFileID),
	)
	if err != nil {
		return fmt.Errorf("failed to insert file: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	file.ID = id
	return nil
}

// CreateWithQuotaCheck atomically checks quota and inserts file record in a transaction.
func (r *FileRepository) CreateWithQuotaCheck(ctx context.Context, file *models.File, quotaLimitBytes int64) error {
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.Warn("failed to rollback transaction", "error", err)
		}
	}()

	// Check quota within transaction
	var currentUsage int64
	query := `
		SELECT
			COALESCE(SUM(file_size), 0) +
			COALESCE((SELECT SUM(total_size) FROM partial_uploads WHERE completed = 0), 0)
		FROM files
		WHERE datetime(expires_at) > datetime('now')
	`
	if err := tx.QueryRowContext(ctx, query).Scan(&currentUsage); err != nil {
		return fmt.Errorf("failed to get current usage: %w", err)
	}

	// Check if adding this file would exceed quota
	if currentUsage+file.FileSize > quotaLimitBytes {
		return repository.ErrQuotaExceeded
	}

	// Insert file record
	insertQuery := `
		INSERT INTO files (
			claim_code, original_filename, stored_filename, file_size,
			mime_type, expires_at, max_downloads, uploader_ip, password_hash, user_id, sha256_hash,
			client_encrypted, enc_file_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	expiresAtRFC3339 := file.ExpiresAt.Format(time.RFC3339)

	result, err := tx.ExecContext(
		ctx,
		insertQuery,
		file.ClaimCode,
		file.OriginalFilename,
		file.StoredFilename,
		file.FileSize,
		file.MimeType,
		expiresAtRFC3339,
		file.MaxDownloads,
		file.UploaderIP,
		file.PasswordHash,
		file.UserID,
		file.SHA256Hash,
		file.ClientEncrypted,
		nullableBlob(file.EncFileID),
	)
	if err != nil {
		return fmt.Errorf("failed to insert file: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	file.ID = id

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
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
		WHERE id = ?
	`

	file := &models.File{}
	var createdAt, expiresAt string
	var passwordHash sql.NullString
	var userID sql.NullInt64
	var sha256Hash sql.NullString
	var maxDownloads sql.NullInt64
	var scanStatus sql.NullString
	var scanResult sql.NullString
	var scannedAt sql.NullString
	var encFileID []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&file.ID,
		&file.ClaimCode,
		&file.OriginalFilename,
		&file.StoredFilename,
		&file.FileSize,
		&file.MimeType,
		&createdAt,
		&expiresAt,
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

	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query file: %w", err)
	}

	// Parse timestamps
	file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", err)
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
		if t, err := time.Parse(time.RFC3339, scannedAt.String); err == nil {
			file.ScannedAt = &t
		}
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
		WHERE claim_code = ?
	`

	file := &models.File{}
	var createdAt, expiresAt string
	var passwordHash sql.NullString
	var userID sql.NullInt64
	var sha256Hash sql.NullString
	var maxDownloads sql.NullInt64
	var scanStatus sql.NullString
	var scanResult sql.NullString
	var scannedAt sql.NullString
	var encFileID []byte

	err := r.db.QueryRowContext(ctx, query, claimCode).Scan(
		&file.ID,
		&file.ClaimCode,
		&file.OriginalFilename,
		&file.StoredFilename,
		&file.FileSize,
		&file.MimeType,
		&createdAt,
		&expiresAt,
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

	if err == sql.ErrNoRows {
		return nil, nil // File not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query file: %w", err)
	}

	// Parse timestamps
	file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", err)
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
		if t, err := time.Parse(time.RFC3339, scannedAt.String); err == nil {
			file.ScannedAt = &t
		}
	}
	file.EncFileID = encFileID // SQL NULL maps to nil via *[]byte scan

	// Check if expired
	if time.Now().After(file.ExpiresAt) {
		return nil, nil // Expired file treated as not found
	}

	return file, nil
}

// IncrementDownloadCount atomically increments the download counter.
func (r *FileRepository) IncrementDownloadCount(ctx context.Context, id int64) error {
	query := `UPDATE files SET download_count = download_count + 1 WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to increment download count: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// IncrementDownloadCountIfUnchanged increments download count only if claim code matches.
func (r *FileRepository) IncrementDownloadCountIfUnchanged(ctx context.Context, id int64, expectedClaimCode string) error {
	query := `
		UPDATE files
		SET download_count = download_count + 1
		WHERE id = ? AND claim_code = ?
	`

	result, err := r.db.ExecContext(ctx, query, id, expectedClaimCode)
	if err != nil {
		return fmt.Errorf("failed to increment download count: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
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
		WHERE id = ?
		  AND claim_code = ?
		  AND (max_downloads IS NULL OR max_downloads = 0 OR download_count < max_downloads)
	`

	result, err := r.db.ExecContext(ctx, query, id, expectedClaimCode)
	if err != nil {
		return false, fmt.Errorf("failed to increment download count: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		// Check which case it is: claim code changed OR limit reached
		var currentCount int
		var maxDownloadsNull sql.NullInt64
		checkQuery := `SELECT download_count, max_downloads FROM files WHERE id = ? AND claim_code = ?`
		err := r.db.QueryRowContext(ctx, checkQuery, id, expectedClaimCode).Scan(&currentCount, &maxDownloadsNull)
		if err == sql.ErrNoRows {
			return false, repository.ErrClaimCodeChanged
		}
		if err != nil {
			return false, fmt.Errorf("failed to check download limit: %w", err)
		}

		// Claim code is valid but limit was reached
		if maxDownloadsNull.Valid {
			maxDownloads := int(maxDownloadsNull.Int64)
			if maxDownloads > 0 && currentCount >= maxDownloads {
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
// looked up. Only the hash ever touches the database — the token itself is a
// bearer credential (ADR-014), so a DB read (backup, replica lag, admin
// query) must never be able to reconstruct it.
func newDownloadSessionToken() (token, hash string, err error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", "", fmt.Errorf("failed to generate download session token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(buf[:])
	return token, hashDownloadSessionToken(token), nil
}

// hashDownloadSessionToken returns the hex-encoded SHA-256 hash used as the
// download_sessions primary key. A plain hash (no HMAC/salt) is sufficient
// here: the token itself already carries 256 bits of entropy from
// crypto/rand, so it isn't guessable/brute-forceable from the hash the way a
// low-entropy password would be.
func hashDownloadSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// sqliteAgoModifier turns a Duration into a `datetime('now', modifier)`
// SQLite time modifier. `%+d seconds` formats positive durations as
// `-N seconds` (subtracting from now, the normal case) and negative
// durations as `+N seconds` (used by tests to mean "everything before now").
func sqliteAgoModifier(d time.Duration) string {
	return fmt.Sprintf("%+d seconds", -int64(d.Seconds()))
}

// ReserveDownload atomically increments in_flight_reservations and inserts an
// UNCOMMITTED download_sessions row, atomically charging that session's
// probe-threshold allowance against files.uncounted_bytes in the same
// transaction. See ADR-014 (amending ADR-012); the guard is
// `download_count + in_flight_reservations < max_downloads`.
func (r *FileRepository) ReserveDownload(ctx context.Context, fileID int64, expectedClaimCode string) (string, int64, error) {
	// Fast path: files with no cap don't need a row in download_sessions.
	// We still validate the claim code in the same query so concurrent rotation
	// of the code is observed.
	//
	// This SELECT runs outside the transaction below — a concurrent claim-code
	// rotation between this read and the UPDATE is benign because the UPDATE
	// uses `WHERE claim_code = ?` and reports `rows == 0` if the code changed,
	// at which point we return ErrClaimCodeChanged from the disambiguating
	// SELECT. The transaction is the authoritative guard; this fast path only
	// short-circuits the unlimited case.
	var maxDL sql.NullInt64
	checkQuery := `SELECT max_downloads FROM files WHERE id = ? AND claim_code = ?`
	if err := r.db.QueryRowContext(ctx, checkQuery, fileID, expectedClaimCode).Scan(&maxDL); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", 0, repository.ErrClaimCodeChanged
		}
		return "", 0, fmt.Errorf("failed to read file metadata for reservation: %w", err)
	}
	if !maxDL.Valid || maxDL.Int64 == 0 {
		return repository.ReservationTokenUnlimited, 0, nil
	}

	token, hash, err := newDownloadSessionToken()
	if err != nil {
		return "", 0, err
	}

	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return "", 0, fmt.Errorf("failed to begin reserve transaction: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			slog.Warn("failed to rollback reserve transaction", "error", rbErr)
		}
	}()

	// Atomic guard: take the slot only if download_count + in_flight < max_downloads.
	// max_downloads = 0 or NULL was already filtered above; here it's always a positive cap.
	updateQuery := `
		UPDATE files
		SET in_flight_reservations = in_flight_reservations + 1
		WHERE id = ?
		  AND claim_code = ?
		  AND (download_count + in_flight_reservations) < max_downloads
	`
	res, err := tx.ExecContext(ctx, updateQuery, fileID, expectedClaimCode)
	if err != nil {
		return "", 0, fmt.Errorf("failed to reserve download slot: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return "", 0, fmt.Errorf("failed to read reserve rows affected: %w", err)
	}
	if rows == 0 {
		// Either the claim code changed or the slot was full. Distinguish.
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM files WHERE id = ? AND claim_code = ?`, fileID, expectedClaimCode).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return "", 0, repository.ErrClaimCodeChanged
			}
			return "", 0, fmt.Errorf("failed to disambiguate reservation failure: %w", err)
		}
		// Claim code still matches — the cap was hit.
		return "", 0, nil
	}

	// Compute and charge this session's probe-threshold allowance from a
	// FRESH read of file_size/uncounted_bytes taken under the BEGIN IMMEDIATE
	// lock — not from a snapshot the caller may have read before this call —
	// so concurrent reservations on the same file can't each be granted a
	// full allowance before any of them charges the shared budget
	// (bug-hunter finding).
	var fileSize, uncountedBytes int64
	if err := tx.QueryRowContext(ctx, `SELECT file_size, uncounted_bytes FROM files WHERE id = ?`, fileID).Scan(&fileSize, &uncountedBytes); err != nil {
		return "", 0, fmt.Errorf("failed to read file size for probe grant: %w", err)
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
		if _, err := tx.ExecContext(ctx, `UPDATE files SET uncounted_bytes = uncounted_bytes + ? WHERE id = ?`, granted, fileID); err != nil {
			return "", 0, fmt.Errorf("failed to charge probe grant: %w", err)
		}
	}

	// Slot taken; record the uncommitted session row.
	if _, err := tx.ExecContext(ctx, `INSERT INTO download_sessions (token_hash, file_id, probe_bytes_granted) VALUES (?, ?, ?)`, hash, fileID, granted); err != nil {
		return "", 0, fmt.Errorf("failed to insert download session row: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", 0, fmt.Errorf("failed to commit reservation: %w", err)
	}
	return token, granted, nil
}

// ReserveSessionBytes implements repository.FileRepository.ReserveSessionBytes.
func (r *FileRepository) ReserveSessionBytes(ctx context.Context, fileID int64, token string, length, limit int64) (bool, error) {
	if token == "" || token == repository.ReservationTokenUnlimited {
		return false, nil
	}
	hash := hashDownloadSessionToken(token)

	res, err := r.db.ExecContext(ctx, `
		UPDATE download_sessions
		SET bytes_reserved = bytes_reserved + ?, last_seen_at = CURRENT_TIMESTAMP
		WHERE token_hash = ? AND file_id = ? AND completed_at IS NULL AND bytes_reserved + ? <= ?
	`, length, hash, fileID, length, limit)
	if err != nil {
		return false, fmt.Errorf("failed to reserve session bytes: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read reserve-session-bytes rows affected: %w", err)
	}
	return rows == 1, nil
}

// ReleaseSessionBytes implements repository.FileRepository.ReleaseSessionBytes.
func (r *FileRepository) ReleaseSessionBytes(ctx context.Context, fileID int64, token string, amount int64) error {
	if token == "" || token == repository.ReservationTokenUnlimited || amount <= 0 {
		return nil
	}
	hash := hashDownloadSessionToken(token)
	_, err := r.db.ExecContext(ctx, `
		UPDATE download_sessions
		SET bytes_reserved = CASE WHEN bytes_reserved > ? THEN bytes_reserved - ? ELSE 0 END
		WHERE token_hash = ? AND file_id = ?
	`, amount, amount, hash, fileID)
	if err != nil {
		return fmt.Errorf("failed to release session bytes: %w", err)
	}
	return nil
}

// LookupDownloadSession implements repository.FileRepository.LookupDownloadSession.
func (r *FileRepository) LookupDownloadSession(ctx context.Context, fileID int64, token string, idleTTL, maxAge time.Duration) (*repository.DownloadSession, error) {
	if token == "" || token == repository.ReservationTokenUnlimited {
		return nil, nil
	}
	hash := hashDownloadSessionToken(token)

	var (
		createdAt, lastSeenAt      string
		committedAt, completedAt   sql.NullString
		bytesServed, bytesReserved int64
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT created_at, last_seen_at, committed_at, completed_at, bytes_served, bytes_reserved
		FROM download_sessions
		WHERE token_hash = ? AND file_id = ?
	`, hash, fileID).Scan(&createdAt, &lastSeenAt, &committedAt, &completedAt, &bytesServed, &bytesReserved)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to look up download session: %w", err)
	}

	// A completed session has already delivered the whole file once; letting
	// it resolve here would let its token be replayed indefinitely (bounded
	// only by idleTTL/maxAge, up to SessionMaxAge) to redeliver the file to
	// anyone holding the token (bug-hunter finding — HIGH). Treat it exactly
	// like "not found": the caller falls back to ReserveDownload, which
	// re-applies the max_downloads guard (410 once the cap is spent, or a
	// genuinely new counted download if the cap allows more).
	if completedAt.Valid {
		return nil, nil
	}

	created, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse download session created_at: %w", err)
	}
	lastSeen, err := time.Parse(time.RFC3339, lastSeenAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse download session last_seen_at: %w", err)
	}

	// A foreign/expired token gets no oracle: treat it exactly like "not
	// found" so the caller falls back to a fresh, tokenless download.
	//
	// This cutoff check is deliberately Go-side (unlike ReapDownloadSessions'
	// DB-side datetime('now', ...) cutoffs): worst case under application/DB
	// clock skew is that a borderline-fresh token is rejected a little early
	// or a little late, which just falls back to (or delays falling back to)
	// a fresh reservation — it can never let a session be double-counted or
	// push download_count past max_downloads, so the skew risk that matters
	// for the reaper's cutoffs (bug-hunter M4) doesn't apply here.
	now := time.Now()
	if maxAge > 0 && now.Sub(created) > maxAge {
		return nil, nil
	}
	if idleTTL > 0 && now.Sub(lastSeen) > idleTTL {
		return nil, nil
	}

	return &repository.DownloadSession{
		FileID:        fileID,
		Committed:     committedAt.Valid,
		Completed:     completedAt.Valid,
		BytesServed:   bytesServed,
		BytesReserved: bytesReserved,
		CreatedAt:     created,
		LastSeenAt:    lastSeen,
	}, nil
}

// CommitDownloadSession implements repository.FileRepository.CommitDownloadSession.
// See ADR-014 for the three-outcome semantics.
func (r *FileRepository) CommitDownloadSession(ctx context.Context, fileID int64, token string) (repository.DownloadCommitResult, error) {
	if token == "" || token == repository.ReservationTokenUnlimited {
		// Not a real session token — nothing to commit. Reported as
		// "already committed" so a caller that forwards the sentinel by
		// mistake doesn't misread it as a lost slot.
		return repository.DownloadCommitAlreadyCommitted, nil
	}
	hash := hashDownloadSessionToken(token)

	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return 0, fmt.Errorf("failed to begin commit-session transaction: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			slog.Warn("failed to rollback commit-session transaction", "error", rbErr)
		}
	}()

	res, err := tx.ExecContext(ctx, `
		UPDATE download_sessions
		SET committed_at = CURRENT_TIMESTAMP, last_seen_at = CURRENT_TIMESTAMP
		WHERE token_hash = ? AND file_id = ? AND committed_at IS NULL
	`, hash, fileID)
	if err != nil {
		return 0, fmt.Errorf("failed to mark download session committed: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read commit-session rows affected: %w", err)
	}

	if rows == 1 {
		// Normal path: swap the uncommitted slot for a credited download, and
		// refund this session's entire probe grant — it's a real, credited
		// download now, not an uncounted probe (the UPDATE above didn't touch
		// probe_bytes_granted, so it's still the value ReserveDownload set).
		var granted int64
		if err := tx.QueryRowContext(ctx, `SELECT probe_bytes_granted FROM download_sessions WHERE token_hash = ? AND file_id = ?`, hash, fileID).Scan(&granted); err != nil {
			return 0, fmt.Errorf("failed to read probe grant for refund: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE files
			SET in_flight_reservations = CASE WHEN in_flight_reservations > 0 THEN in_flight_reservations - 1 ELSE 0 END,
			    download_count          = download_count + 1,
			    uncounted_bytes         = CASE WHEN uncounted_bytes > ? THEN uncounted_bytes - ? ELSE 0 END
			WHERE id = ?
		`, granted, granted, fileID); err != nil {
			return 0, fmt.Errorf("failed to finalise download-session counters: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("failed to commit download-session finalisation: %w", err)
		}
		return repository.DownloadCommitCredited, nil
	}

	// Either already committed, or the row is gone entirely (reaped mid-stream).
	var exists bool
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM download_sessions WHERE token_hash = ? AND file_id = ?`, hash, fileID).Scan(&exists)
	switch {
	case err == nil:
		if cErr := tx.Commit(); cErr != nil {
			return 0, fmt.Errorf("failed to commit no-op session commit: %w", cErr)
		}
		return repository.DownloadCommitAlreadyCommitted, nil
	case errors.Is(err, sql.ErrNoRows):
		// Reaped-mid-stream recovery: try to atomically take a slot now.
		// Guard MUST match ReserveDownload: (download_count + in_flight) < max_downloads.
		// Using `download_count < max_downloads` alone would let a late-committing
		// session jump past a still-live reservation and over-count past the cap
		// (bug-hunter C1: same-token replay or retry-race could double-credit).
		recover, err := tx.ExecContext(ctx, `
			UPDATE files
			SET download_count = download_count + 1
			WHERE id = ?
			  AND (max_downloads IS NULL OR max_downloads = 0
			       OR (download_count + in_flight_reservations) < max_downloads)
		`, fileID)
		if err != nil {
			return 0, fmt.Errorf("failed reaped-recovery increment: %w", err)
		}
		recovered, err := recover.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("failed to read reaped-recovery rows affected: %w", err)
		}
		if recovered == 0 {
			slog.Warn("download session committed after reaper cancelled it; cap already taken by another reader — not counting",
				"file_id", fileID,
			)
			if cErr := tx.Commit(); cErr != nil {
				return 0, fmt.Errorf("failed to commit slot-lost no-op: %w", cErr)
			}
			return repository.DownloadCommitSlotLost, nil
		}
		// Re-insert a committed row under the same hash so a later
		// CompleteDownloadSession call can still find it. probe_bytes_granted
		// is 0 (the default): the original row's grant was already refunded
		// by whatever swept it (ReapDownloadSessions' phase 1 refunds
		// probe_bytes_granted - bytes_served as it deletes the row), so there
		// is nothing left owed here — refunding again would over-credit the
		// file's uncounted-bytes budget.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO download_sessions (token_hash, file_id, committed_at, last_seen_at)
			VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		`, hash, fileID); err != nil {
			return 0, fmt.Errorf("failed to re-insert recovered download session: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("failed to commit reaped-recovery: %w", err)
		}
		return repository.DownloadCommitCredited, nil
	default:
		return 0, fmt.Errorf("failed to disambiguate commit-session failure: %w", err)
	}
}

// TouchDownloadSession implements repository.FileRepository.TouchDownloadSession.
func (r *FileRepository) TouchDownloadSession(ctx context.Context, fileID int64, token string, bytesDelta int64) error {
	if token == "" || token == repository.ReservationTokenUnlimited {
		return nil
	}
	hash := hashDownloadSessionToken(token)
	_, err := r.db.ExecContext(ctx, `
		UPDATE download_sessions
		SET last_seen_at = CURRENT_TIMESTAMP, bytes_served = bytes_served + ?
		WHERE token_hash = ? AND file_id = ?
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

	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return false, fmt.Errorf("failed to begin complete-session transaction: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			slog.Warn("failed to rollback complete-session transaction", "error", rbErr)
		}
	}()

	res, err := tx.ExecContext(ctx, `
		UPDATE download_sessions
		SET completed_at = CURRENT_TIMESTAMP
		WHERE token_hash = ? AND file_id = ? AND committed_at IS NOT NULL AND completed_at IS NULL
	`, hash, fileID)
	if err != nil {
		return false, fmt.Errorf("failed to mark download session complete: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read complete-session rows affected: %w", err)
	}
	if rows != 1 {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("failed to commit no-op session completion: %w", err)
		}
		return false, nil
	}

	if _, err := tx.ExecContext(ctx, `UPDATE files SET completed_downloads = completed_downloads + 1 WHERE id = ?`, fileID); err != nil {
		return false, fmt.Errorf("failed to increment completed_downloads: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("failed to commit session completion: %w", err)
	}
	return true, nil
}

// CommitDownload finalises a reservation/session and credits both
// download_count and completed_downloads in one call. See the interface doc
// for why this exists alongside CommitDownloadSession/CompleteDownloadSession.
func (r *FileRepository) CommitDownload(ctx context.Context, fileID int64, token string) error {
	if token == "" {
		return nil
	}
	if token == repository.ReservationTokenUnlimited {
		// No session row to update; just credit the counters.
		_, err := r.db.ExecContext(ctx, `
			UPDATE files
			SET download_count      = download_count + 1,
			    completed_downloads = completed_downloads + 1
			WHERE id = ?
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

	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return fmt.Errorf("failed to begin cancel transaction: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			slog.Warn("failed to rollback cancel transaction", "error", rbErr)
		}
	}()

	var bytesServed, probeGranted int64
	err = tx.QueryRowContext(ctx, `
		SELECT bytes_served, probe_bytes_granted FROM download_sessions
		WHERE token_hash = ? AND file_id = ? AND committed_at IS NULL
	`, hash, fileID).Scan(&bytesServed, &probeGranted)
	if errors.Is(err, sql.ErrNoRows) {
		// Missing, or already committed — nothing to cancel.
		return tx.Commit()
	}
	if err != nil {
		return fmt.Errorf("failed to read download session for cancel: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM download_sessions WHERE token_hash = ? AND file_id = ?`, hash, fileID); err != nil {
		return fmt.Errorf("failed to delete download session: %w", err)
	}
	// Refund only the unspent portion of the grant: it was charged in full at
	// Reserve time, and bytes the session actually served stay charged
	// against the file's probe budget even though this download itself was
	// never credited.
	refund := probeGranted - bytesServed
	if refund < 0 {
		refund = 0
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE files
		SET in_flight_reservations = CASE WHEN in_flight_reservations > 0 THEN in_flight_reservations - 1 ELSE 0 END,
		    uncounted_bytes         = CASE WHEN uncounted_bytes > ? THEN uncounted_bytes - ? ELSE 0 END
		WHERE id = ?
	`, refund, refund, fileID); err != nil {
		return fmt.Errorf("failed to decrement in_flight / refund uncounted_bytes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit cancel: %w", err)
	}
	return nil
}

// ReapDownloadSessions implements repository.FileRepository.ReapDownloadSessions.
// See the interface doc for the two independent sweep classes.
func (r *FileRepository) ReapDownloadSessions(ctx context.Context, leaseTTL, idleTTL, maxAge time.Duration) (int, int, error) {
	leaseModifier := sqliteAgoModifier(leaseTTL)
	idleModifier := sqliteAgoModifier(idleTTL)
	maxAgeModifier := sqliteAgoModifier(maxAge)

	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to begin reaper transaction: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			slog.Warn("failed to rollback reaper transaction", "error", rbErr)
		}
	}()

	// Resolve every cutoff to a concrete instant ONCE, inside this
	// transaction, and bind that same value to every statement that needs
	// it. Letting the SELECT and the DELETE below each independently
	// evaluate datetime('now', ?) meant a row whose last_seen_at fell in the
	// (real, if narrow) gap between the two statements' evaluations could be
	// swept by the DELETE's later "now" without ever appearing in the
	// SELECT's bucket — deleted but never refunded (bug-hunter finding).
	var leaseCutoff, idleCutoff, maxAgeCutoff string
	if err := tx.QueryRowContext(ctx, `SELECT datetime('now', ?), datetime('now', ?), datetime('now', ?)`,
		leaseModifier, idleModifier, maxAgeModifier).Scan(&leaseCutoff, &idleCutoff, &maxAgeCutoff); err != nil {
		return 0, 0, fmt.Errorf("failed to resolve reaper cutoffs: %w", err)
	}

	// Phase 1: uncommitted rows whose lease has lapsed — treated as abandoned
	// (crashed process, or a probe the client never resumed). Refunds
	// in_flight and, per row, MAX(0, probe_bytes_granted - bytes_served) —
	// computed per row inside SQL (not on the file's aggregated totals),
	// so one session that over-served its own grant can't cancel out the
	// refund genuinely owed by another session on the same file (matches the
	// mock's already-per-row behaviour) — before deleting.
	//
	// last_seen_at/created_at are compared as raw columns against the
	// pre-resolved cutoff, NOT wrapped in datetime(...) themselves: every
	// writer of these columns (the table defaults, ReserveDownload's INSERT,
	// CommitDownloadSession, TouchDownloadSession, and the reaped-recovery
	// re-INSERT) uses SQLite's own CURRENT_TIMESTAMP, which already produces
	// the same "YYYY-MM-DD HH:MM:SS" text datetime('now', ...) does — so a
	// raw lexical comparison is correct, and it lets SQLite use
	// idx_dl_sessions_committed_last_seen instead of evaluating datetime() per
	// row. (Contrast with files.expires_at, which IS written as a Go-formatted
	// RFC3339 string and genuinely needs datetime() normalisation to compare.)
	rows, err := tx.QueryContext(ctx, `
		SELECT file_id, COUNT(*), COALESCE(SUM(MAX(0, probe_bytes_granted - bytes_served)), 0)
		FROM download_sessions
		WHERE committed_at IS NULL AND last_seen_at < ?
		GROUP BY file_id
	`, leaseCutoff)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to query abandoned download sessions: %w", err)
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
			return 0, 0, fmt.Errorf("failed to scan reaper row: %w", err)
		}
		buckets = append(buckets, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("reaper row iteration error: %w", err)
	}

	cancelled := 0
	if len(buckets) > 0 {
		// Delete first, then adjust counters. Atomic together inside this
		// BEGIN IMMEDIATE transaction — outside readers never observe an
		// intermediate state. Same pre-resolved leaseCutoff as the SELECT
		// above, so this can never delete a row the SELECT didn't also see.
		delRes, err := tx.ExecContext(ctx, `DELETE FROM download_sessions WHERE committed_at IS NULL AND last_seen_at < ?`, leaseCutoff)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to delete abandoned download sessions: %w", err)
		}
		deleted, err := delRes.RowsAffected()
		if err != nil {
			return 0, 0, fmt.Errorf("failed to read abandoned-session delete rows: %w", err)
		}

		total := 0
		for _, b := range buckets {
			if _, err := tx.ExecContext(ctx, `
				UPDATE files
				SET in_flight_reservations = MAX(0, in_flight_reservations - ?),
				    uncounted_bytes         = CASE WHEN uncounted_bytes > ? THEN uncounted_bytes - ? ELSE 0 END
				WHERE id = ?
			`, b.n, b.refund, b.refund, b.fileID); err != nil {
				return 0, 0, fmt.Errorf("failed to clamp in_flight for file %d: %w", b.fileID, err)
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
	// The download was already credited at commit time, so this is pure
	// record cleanup — no counter change.
	expiredRes, err := tx.ExecContext(ctx, `
		DELETE FROM download_sessions
		WHERE committed_at IS NOT NULL
		  AND (last_seen_at < ? OR created_at < ?)
	`, idleCutoff, maxAgeCutoff)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to delete expired committed download sessions: %w", err)
	}
	expiredCount, err := expiredRes.RowsAffected()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read expired-session delete rows: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("failed to commit reaper tx: %w", err)
	}
	return cancelled, int(expiredCount), nil
}

// IncrementCompletedDownloads increments the completed downloads counter.
//
// Deprecated: see FileRepository.IncrementCompletedDownloads.
func (r *FileRepository) IncrementCompletedDownloads(ctx context.Context, id int64) error {
	query := `UPDATE files SET completed_downloads = completed_downloads + 1 WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to increment completed downloads: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// Delete removes a file record by ID.
func (r *FileRepository) Delete(ctx context.Context, id int64) error {
	query := `DELETE FROM files WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// DeleteByClaimCode removes a file record by claim code.
// Uses a transaction to prevent TOCTOU race conditions between SELECT and DELETE.
func (r *FileRepository) DeleteByClaimCode(ctx context.Context, claimCode string) (*models.File, error) {
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.Warn("failed to rollback transaction", "error", err)
		}
	}()

	// Get the file info within transaction
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads, download_count, completed_downloads,
			uploader_ip, password_hash, user_id, client_encrypted
		FROM files
		WHERE claim_code = ?
	`

	file := &models.File{}
	var createdAt, expiresAt string
	var passwordHash sql.NullString
	var maxDownloads sql.NullInt64
	var userID sql.NullInt64

	err = tx.QueryRowContext(ctx, query, claimCode).Scan(
		&file.ID,
		&file.ClaimCode,
		&file.OriginalFilename,
		&file.StoredFilename,
		&file.FileSize,
		&file.MimeType,
		&createdAt,
		&expiresAt,
		&maxDownloads,
		&file.DownloadCount,
		&file.CompletedDownloads,
		&file.UploaderIP,
		&passwordHash,
		&userID,
		&file.ClientEncrypted,
	)

	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query file: %w", err)
	}

	// Parse timestamps
	file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", err)
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
	deleteQuery := `DELETE FROM files WHERE claim_code = ?`
	result, err := tx.ExecContext(ctx, deleteQuery, claimCode)
	if err != nil {
		return nil, fmt.Errorf("failed to delete file from database: %w", err)
	}

	// Verify deletion occurred (defense against concurrent delete)
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return nil, repository.ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return file, nil
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
			WHERE claim_code = ?
		`

		file := &models.File{}
		var createdAt, expiresAt string
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userID sql.NullInt64

		err := r.db.QueryRowContext(ctx, query, claimCode).Scan(
			&file.ID,
			&file.ClaimCode,
			&file.OriginalFilename,
			&file.StoredFilename,
			&file.FileSize,
			&file.MimeType,
			&createdAt,
			&expiresAt,
			&maxDownloads,
			&file.DownloadCount,
			&file.CompletedDownloads,
			&file.UploaderIP,
			&passwordHash,
			&userID,
			&file.ClientEncrypted,
		)

		if err == sql.ErrNoRows {
			continue // Skip files that don't exist
		}
		if err != nil {
			return nil, fmt.Errorf("failed to query file %s: %w", claimCode, err)
		}

		// Parse timestamps
		file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse created_at: %w", err)
		}

		file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse expires_at: %w", err)
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
		placeholders := make([]string, len(files))
		args := make([]interface{}, len(files))
		for i, file := range files {
			placeholders[i] = "?"
			args[i] = file.ClaimCode
		}

		deleteQuery := fmt.Sprintf("DELETE FROM files WHERE claim_code IN (%s)", strings.Join(placeholders, ","))
		_, err := r.db.ExecContext(ctx, deleteQuery, args...)
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
		WHERE datetime(expires_at) <= datetime('now', '-1 hour')
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to query expired files: %w", err)
	}
	// Defensive defer — the explicit Close below normally fires first. A second
	// Close on an already-closed *sql.Rows is a no-op per database/sql.
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
		var expiresAtStr string
		var id int64
		var claimCode, originalFilename, storedFilename, mimeType string
		var fileSize int64

		if err := rows.Scan(&id, &claimCode, &originalFilename, &storedFilename, &fileSize, &mimeType, &expiresAtStr); err != nil {
			slog.Error("failed to scan expired file", "error", err)
			continue
		}

		expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
		if err != nil {
			slog.Error("failed to parse expires_at timestamp",
				"file_id", id,
				"error", err,
			)
			continue
		}

		expiredFiles = append(expiredFiles, expiredFileData{
			ID:               id,
			ClaimCode:        claimCode,
			OriginalFilename: originalFilename,
			StoredFilename:   storedFilename,
			FileSize:         fileSize,
			MimeType:         mimeType,
			ExpiresAt:        expiresAt,
		})
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("error iterating expired files: %w", err)
	}

	// SH-3.4: close the read cursor explicitly *before* doing filesystem
	// deletions and the subsequent batch DELETE. The original `defer rows.Close()`
	// kept the SQLite read transaction open across os.Remove + batchDeleteFiles
	// on every cleanup cycle, which can run for seconds on large sets. While the
	// read tx is open, WAL checkpointing is blocked and the WAL file grows
	// unbounded — causing a checkpoint stall when the cursor finally closes and
	// elevating read latency for concurrent requests in the meantime.
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("failed to close expired files cursor: %w", err)
	}

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

		if _, err := r.db.ExecContext(ctx, "ANALYZE files"); err != nil {
			slog.Warn("failed to analyze files table", "error", err)
		}
	}

	return deletedCount, nil
}

// batchDeleteFiles deletes multiple file records using batch DELETE operations.
func (r *FileRepository) batchDeleteFiles(ctx context.Context, fileIDs []int64) int {
	const batchSize = 500
	deletedCount := 0

	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		slog.Error("failed to begin transaction for batch delete", "error", err)
		return 0
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.Warn("failed to rollback transaction", "error", err)
		}
	}()

	// Process in chunks
	for i := 0; i < len(fileIDs); i += batchSize {
		end := i + batchSize
		if end > len(fileIDs) {
			end = len(fileIDs)
		}
		batch := fileIDs[i:end]

		placeholders := strings.Repeat("?,", len(batch))
		placeholders = placeholders[:len(placeholders)-1]
		deleteQuery := fmt.Sprintf("DELETE FROM files WHERE id IN (%s)", placeholders)

		args := make([]interface{}, len(batch))
		for j, id := range batch {
			args[j] = id
		}

		result, err := tx.ExecContext(ctx, deleteQuery, args...)
		if err != nil {
			slog.Error("failed to batch delete file records",
				"batch_size", len(batch),
				"error", err,
			)
			return 0
		}

		affected, err := result.RowsAffected()
		if err != nil {
			slog.Warn("failed to get rows affected for batch delete", "error", err)
			affected = int64(len(batch))
		}

		deletedCount += int(affected)
		slog.Debug("batch deleted file records",
			"batch_size", len(batch),
			"deleted", affected,
		)
	}

	if err := tx.Commit(); err != nil {
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
			COALESCE((SELECT SUM(total_size) FROM partial_uploads WHERE completed = 0), 0)
		FROM files
		WHERE datetime(expires_at) > datetime('now')
	`

	var totalUsage int64
	err := r.db.QueryRowContext(ctx, query).Scan(&totalUsage)
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
		WHERE datetime(expires_at) > datetime('now')
	`

	var totalFiles int
	var storageUsed int64
	err := r.db.QueryRowContext(ctx, query).Scan(&totalFiles, &storageUsed)
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

	rows, err := r.db.QueryContext(ctx, query)
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
		var scannedAt sql.NullString
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
			if t, err := time.Parse(time.RFC3339, scannedAt.String); err == nil {
				file.ScannedAt = &t
			}
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

	rows, err := r.db.QueryContext(ctx, query)
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
	// Validate pagination bounds (defense in depth)
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
	err := r.db.QueryRowContext(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count files: %w", err)
	}

	// Get paginated files with username via LEFT JOIN
	query := `SELECT f.id, f.claim_code, f.original_filename, f.stored_filename, f.file_size, f.mime_type,
		f.created_at, f.expires_at, f.max_downloads, f.download_count, f.completed_downloads, f.uploader_ip, f.password_hash, f.user_id,
		u.username, f.scan_status, f.scan_result, f.scanned_at, f.client_encrypted
		FROM files f
		LEFT JOIN users u ON f.user_id = u.id
		ORDER BY f.created_at DESC LIMIT ? OFFSET ?`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query files: %w", err)
	}
	defer rows.Close()

	var files []models.File
	for rows.Next() {
		var file models.File
		var createdAt, expiresAt string
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userID sql.NullInt64
		var username sql.NullString
		var scanStatus sql.NullString
		var scanResult sql.NullString
		var scannedAt sql.NullString

		err := rows.Scan(
			&file.ID,
			&file.ClaimCode,
			&file.OriginalFilename,
			&file.StoredFilename,
			&file.FileSize,
			&file.MimeType,
			&createdAt,
			&expiresAt,
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

		// Parse timestamps
		file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse created_at: %w", err)
		}

		file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse expires_at: %w", err)
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
			if t, err := time.Parse(time.RFC3339, scannedAt.String); err == nil {
				file.ScannedAt = &t
			}
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
	// Validate pagination bounds (defense in depth)
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
	countQuery := `SELECT COUNT(*) FROM files f
		LEFT JOIN users u ON f.user_id = u.id
		WHERE f.claim_code LIKE ? ESCAPE '\' OR f.original_filename LIKE ? ESCAPE '\' OR f.uploader_ip LIKE ? ESCAPE '\' OR u.username LIKE ? ESCAPE '\'`
	err := r.db.QueryRowContext(ctx, countQuery, searchPattern, searchPattern, searchPattern, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	// Get paginated results with username via LEFT JOIN
	query := `SELECT f.id, f.claim_code, f.original_filename, f.stored_filename, f.file_size, f.mime_type,
		f.created_at, f.expires_at, f.max_downloads, f.download_count, f.completed_downloads, f.uploader_ip, f.password_hash, f.user_id,
		u.username, f.scan_status, f.scan_result, f.scanned_at, f.client_encrypted
		FROM files f
		LEFT JOIN users u ON f.user_id = u.id
		WHERE f.claim_code LIKE ? ESCAPE '\' OR f.original_filename LIKE ? ESCAPE '\' OR f.uploader_ip LIKE ? ESCAPE '\' OR u.username LIKE ? ESCAPE '\'
		ORDER BY f.created_at DESC LIMIT ? OFFSET ?`

	rows, err := r.db.QueryContext(ctx, query, searchPattern, searchPattern, searchPattern, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search files: %w", err)
	}
	defer rows.Close()

	var files []models.File
	for rows.Next() {
		var file models.File
		var createdAt, expiresAt string
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userID sql.NullInt64
		var username sql.NullString
		var scanStatus sql.NullString
		var scanResult sql.NullString
		var scannedAt sql.NullString

		err := rows.Scan(
			&file.ID,
			&file.ClaimCode,
			&file.OriginalFilename,
			&file.StoredFilename,
			&file.FileSize,
			&file.MimeType,
			&createdAt,
			&expiresAt,
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

		// Parse timestamps
		file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse created_at: %w", err)
		}

		file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse expires_at: %w", err)
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
			if t, err := time.Parse(time.RFC3339, scannedAt.String); err == nil {
				file.ScannedAt = &t
			}
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
	query := `UPDATE files SET scan_status = ?, scan_result = ?, scanned_at = ? WHERE id = ?`
	now := time.Now().Format(time.RFC3339)
	res, err := r.db.ExecContext(ctx, query, status, result, now, id)
	if err != nil {
		return fmt.Errorf("failed to update scan status: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// Ensure FileRepository implements repository.FileRepository.
var _ repository.FileRepository = (*FileRepository)(nil)
