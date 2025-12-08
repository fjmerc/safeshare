// Package postgres provides PostgreSQL implementations of repository interfaces.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// UserRepository implements repository.UserRepository for PostgreSQL.
type UserRepository struct {
	pool *Pool
}

// NewUserRepository creates a new PostgreSQL user repository.
func NewUserRepository(pool *Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

// Input validation constants.
const (
	maxUsernameLen = 64
	maxEmailLen    = 255
)

// validRoles defines the allowed user roles.
var validRoles = map[string]bool{"user": true, "admin": true}

// Create inserts a new user record into the database.
func (r *UserRepository) Create(ctx context.Context, username, email, passwordHash, role string, requirePasswordChange bool) (*models.User, error) {
	// Validate role
	if !validRoles[role] {
		return nil, fmt.Errorf("invalid role: must be 'user' or 'admin'")
	}

	// Validate username
	if len(username) == 0 || len(username) > maxUsernameLen {
		return nil, fmt.Errorf("username must be 1-%d characters", maxUsernameLen)
	}

	// Validate email
	if len(email) == 0 || len(email) > maxEmailLen {
		return nil, fmt.Errorf("email must be 1-%d characters", maxEmailLen)
	}

	query := `
		INSERT INTO users (username, email, password_hash, role, require_password_change)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at
	`

	user := &models.User{
		Username:              username,
		Email:                 email,
		PasswordHash:          passwordHash,
		Role:                  role,
		IsApproved:            true,
		IsActive:              true,
		RequirePasswordChange: requirePasswordChange,
	}

	err := r.pool.QueryRow(ctx, query, username, email, passwordHash, role, requirePasswordChange).
		Scan(&user.ID, &user.CreatedAt)

	if err != nil {
		if isUniqueViolation(err) {
			return nil, repository.ErrDuplicateKey
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// GetByID retrieves a user by database ID.
func (r *UserRepository) GetByID(ctx context.Context, id int64) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, role, is_approved, is_active,
			require_password_change, created_at, last_login
		FROM users WHERE id = $1
	`

	var user models.User
	var lastLogin sql.NullTime

	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.IsApproved,
		&user.IsActive,
		&user.RequirePasswordChange,
		&user.CreatedAt,
		&lastLogin,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

// GetByUsername retrieves a user by username.
func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, role, is_approved, is_active,
			require_password_change, created_at, last_login
		FROM users WHERE username = $1
	`

	var user models.User
	var lastLogin sql.NullTime

	err := r.pool.QueryRow(ctx, query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.IsApproved,
		&user.IsActive,
		&user.RequirePasswordChange,
		&user.CreatedAt,
		&lastLogin,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

// UpdateLastLogin updates the last login timestamp for a user.
func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID int64) error {
	query := `UPDATE users SET last_login = NOW() WHERE id = $1`

	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// UpdatePassword updates a user's password hash.
func (r *UserRepository) UpdatePassword(ctx context.Context, userID int64, passwordHash string, clearPasswordChangeFlag bool) error {
	query := `UPDATE users SET password_hash = $1, require_password_change = $2 WHERE id = $3`

	requireChange := !clearPasswordChangeFlag

	_, err := r.pool.Exec(ctx, query, passwordHash, requireChange, userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// UpdatePasswordWithSessionInvalidation atomically updates password and invalidates all sessions.
func (r *UserRepository) UpdatePasswordWithSessionInvalidation(ctx context.Context, userID int64, passwordHash string, clearPasswordChangeFlag bool) error {
	return withRetryNoReturn(ctx, 3, func() error {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback(ctx)

		requireChange := !clearPasswordChangeFlag

		_, err = tx.Exec(ctx,
			`UPDATE users SET password_hash = $1, require_password_change = $2 WHERE id = $3`,
			passwordHash, requireChange, userID)
		if err != nil {
			return fmt.Errorf("failed to update password: %w", err)
		}

		_, err = tx.Exec(ctx, `DELETE FROM user_sessions WHERE user_id = $1`, userID)
		if err != nil {
			return fmt.Errorf("failed to invalidate sessions: %w", err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		slog.Info("password updated with session invalidation", "user_id", userID)
		return nil
	})
}

// Update updates user details (username, email, role).
func (r *UserRepository) Update(ctx context.Context, userID int64, username, email, role string) error {
	// Validate role
	if !validRoles[role] {
		return fmt.Errorf("invalid role: must be 'user' or 'admin'")
	}

	// Validate username
	if len(username) == 0 || len(username) > maxUsernameLen {
		return fmt.Errorf("username must be 1-%d characters", maxUsernameLen)
	}

	// Validate email
	if len(email) == 0 || len(email) > maxEmailLen {
		return fmt.Errorf("email must be 1-%d characters", maxEmailLen)
	}

	query := `UPDATE users SET username = $1, email = $2, role = $3 WHERE id = $4`

	_, err := r.pool.Exec(ctx, query, username, email, role, userID)
	if err != nil {
		if isUniqueViolation(err) {
			return repository.ErrDuplicateKey
		}
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// SetActive enables or disables a user account.
func (r *UserRepository) SetActive(ctx context.Context, userID int64, isActive bool) error {
	query := `UPDATE users SET is_active = $1 WHERE id = $2`

	_, err := r.pool.Exec(ctx, query, isActive, userID)
	if err != nil {
		return fmt.Errorf("failed to set user active status: %w", err)
	}

	return nil
}

// Delete removes a user from the database and cleans up their physical files.
func (r *UserRepository) Delete(ctx context.Context, userID int64, uploadDir string) error {
	// Validate uploadDir
	if uploadDir == "" {
		return fmt.Errorf("uploadDir cannot be empty")
	}

	return withRetryNoReturn(ctx, 3, func() error {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback(ctx)

		// Get all files owned by this user within the transaction
		var fileRecords []struct {
			ID             int64
			StoredFilename string
		}

		query := `SELECT id, stored_filename FROM files WHERE user_id = $1 LIMIT 10000`
		rows, err := tx.Query(ctx, query, userID)
		if err != nil {
			return fmt.Errorf("failed to query user files: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var rec struct {
				ID             int64
				StoredFilename string
			}
			if err := rows.Scan(&rec.ID, &rec.StoredFilename); err != nil {
				return fmt.Errorf("failed to scan file record: %w", err)
			}
			fileRecords = append(fileRecords, rec)
		}

		if err := rows.Err(); err != nil {
			return fmt.Errorf("error iterating user files: %w", err)
		}

		// Delete user from database FIRST within the transaction
		deleteQuery := `DELETE FROM users WHERE id = $1`
		result, err := tx.Exec(ctx, deleteQuery, userID)
		if err != nil {
			return fmt.Errorf("failed to delete user: %w", err)
		}

		if result.RowsAffected() == 0 {
			return repository.ErrNotFound
		}

		// Commit the transaction before deleting physical files
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		// Now delete physical files from disk (after DB commit)
		for _, rec := range fileRecords {
			if err := validateStoredFilename(rec.StoredFilename); err != nil {
				slog.Warn("skipping invalid stored filename during user deletion",
					"user_id", userID,
					"file_id", rec.ID,
					"filename", rec.StoredFilename,
					"error", err,
				)
				continue
			}

			filePath := filepath.Join(uploadDir, rec.StoredFilename)
			if err := os.Remove(filePath); err != nil {
				if !os.IsNotExist(err) {
					slog.Warn("failed to delete user file from disk",
						"user_id", userID,
						"file_id", rec.ID,
						"path", filePath,
						"error", err,
					)
				}
			} else {
				slog.Debug("deleted user file from disk",
					"user_id", userID,
					"file_id", rec.ID,
					"filename", rec.StoredFilename,
				)
			}
		}

		slog.Info("user deleted with file cleanup",
			"user_id", userID,
			"files_cleaned", len(fileRecords),
		)

		return nil
	})
}

// GetAll retrieves all users with pagination.
func (r *UserRepository) GetAll(ctx context.Context, limit, offset int) ([]models.UserListItem, int, error) {
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
	countQuery := `SELECT COUNT(*) FROM users`
	err := r.pool.QueryRow(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Get paginated users with file counts
	query := `
		SELECT u.id, u.username, u.email, u.role, u.is_active, u.created_at, u.last_login,
			COUNT(f.id) as file_count
		FROM users u
		LEFT JOIN files f ON u.id = f.user_id
		GROUP BY u.id, u.username, u.email, u.role, u.is_active, u.created_at, u.last_login
		ORDER BY u.created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var users []models.UserListItem
	for rows.Next() {
		var user models.UserListItem
		var lastLogin sql.NullTime

		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.Role,
			&user.IsActive,
			&user.CreatedAt,
			&lastLogin,
			&user.FileCount,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan user: %w", err)
		}

		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating users: %w", err)
	}

	return users, total, nil
}

// Session operations

// CreateSession creates a new user session.
func (r *UserRepository) CreateSession(ctx context.Context, userID int64, token string, expiresAt time.Time, ipAddress, userAgent string) error {
	query := `
		INSERT INTO user_sessions (user_id, session_token, expires_at, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.pool.Exec(ctx, query, userID, token, expiresAt, ipAddress, userAgent)
	if err != nil {
		return fmt.Errorf("failed to create user session: %w", err)
	}

	return nil
}

// GetSession retrieves a session by token.
func (r *UserRepository) GetSession(ctx context.Context, token string) (*models.UserSession, error) {
	query := `
		SELECT id, user_id, session_token, created_at, expires_at, last_activity, ip_address, user_agent
		FROM user_sessions WHERE session_token = $1 AND expires_at > NOW()
	`

	var session models.UserSession

	err := r.pool.QueryRow(ctx, query, token).Scan(
		&session.ID,
		&session.UserID,
		&session.SessionToken,
		&session.CreatedAt,
		&session.ExpiresAt,
		&session.LastActivity,
		&session.IPAddress,
		&session.UserAgent,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user session: %w", err)
	}

	return &session, nil
}

// UpdateSessionActivity updates the last activity timestamp for a session.
func (r *UserRepository) UpdateSessionActivity(ctx context.Context, token string) error {
	query := `UPDATE user_sessions SET last_activity = NOW() WHERE session_token = $1`

	_, err := r.pool.Exec(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to update session activity: %w", err)
	}

	return nil
}

// DeleteSession deletes a session (logout).
func (r *UserRepository) DeleteSession(ctx context.Context, token string) error {
	query := `DELETE FROM user_sessions WHERE session_token = $1`

	_, err := r.pool.Exec(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to delete user session: %w", err)
	}

	return nil
}

// DeleteSessionsByUserID deletes all sessions for a specific user.
func (r *UserRepository) DeleteSessionsByUserID(ctx context.Context, userID int64) error {
	query := `DELETE FROM user_sessions WHERE user_id = $1`

	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}

	return nil
}

// CleanupExpiredSessions removes expired user sessions.
func (r *UserRepository) CleanupExpiredSessions(ctx context.Context) error {
	query := `DELETE FROM user_sessions WHERE expires_at < NOW()`

	_, err := r.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired user sessions: %w", err)
	}

	return nil
}

// User file operations

// GetFiles retrieves all files uploaded by a specific user with pagination.
func (r *UserRepository) GetFiles(ctx context.Context, userID int64, limit, offset int) ([]models.File, int, error) {
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
	countQuery := `SELECT COUNT(*) FROM files WHERE user_id = $1`
	err := r.pool.QueryRow(ctx, countQuery, userID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count user files: %w", err)
	}

	// Get paginated files
	query := `
		SELECT id, claim_code, original_filename, stored_filename, file_size, mime_type,
			created_at, expires_at, max_downloads, download_count, completed_downloads, 
			uploader_ip, password_hash, user_id
		FROM files WHERE user_id = $1 
		ORDER BY created_at DESC 
		LIMIT $2 OFFSET $3
	`

	rows, err := r.pool.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query user files: %w", err)
	}
	defer rows.Close()

	var files []models.File
	for rows.Next() {
		var file models.File
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userIDVal sql.NullInt64

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
			&userIDVal,
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
		if userIDVal.Valid {
			file.UserID = &userIDVal.Int64
		}

		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating files: %w", err)
	}

	return files, total, nil
}

// DeleteFile deletes a file if it belongs to the specified user.
func (r *UserRepository) DeleteFile(ctx context.Context, fileID, userID int64) (*models.File, error) {
	return withRetry(ctx, 3, func() (*models.File, error) {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return nil, fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback(ctx)

		// Get the file to ensure it belongs to the user
		query := `
			SELECT id, claim_code, original_filename, stored_filename, file_size,
				mime_type, created_at, expires_at, max_downloads, download_count, 
				uploader_ip, password_hash, user_id
			FROM files
			WHERE id = $1 AND user_id = $2
			FOR UPDATE
		`

		file := &models.File{}
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userIDVal sql.NullInt64

		err = tx.QueryRow(ctx, query, fileID, userID).Scan(
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
			&file.UploaderIP,
			&passwordHash,
			&userIDVal,
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
		if userIDVal.Valid {
			file.UserID = &userIDVal.Int64
		}

		// Delete from database
		deleteQuery := `DELETE FROM files WHERE id = $1 AND user_id = $2`
		result, err := tx.Exec(ctx, deleteQuery, fileID, userID)
		if err != nil {
			return nil, fmt.Errorf("failed to delete file from database: %w", err)
		}

		if result.RowsAffected() == 0 {
			return nil, repository.ErrNotFound
		}

		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("failed to commit transaction: %w", err)
		}

		return file, nil
	})
}

// DeleteFileByClaimCode deletes a file by claim code if it belongs to the specified user.
func (r *UserRepository) DeleteFileByClaimCode(ctx context.Context, claimCode string, userID int64) (*models.File, error) {
	return withRetry(ctx, 3, func() (*models.File, error) {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return nil, fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback(ctx)

		// Get the file
		query := `
			SELECT id, claim_code, original_filename, stored_filename, file_size,
				mime_type, created_at, expires_at, max_downloads, download_count,
				completed_downloads, uploader_ip, password_hash, user_id
			FROM files
			WHERE claim_code = $1 AND user_id = $2
			FOR UPDATE
		`

		file := &models.File{}
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userIDVal sql.NullInt64

		err = tx.QueryRow(ctx, query, claimCode, userID).Scan(
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
			&userIDVal,
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
		if userIDVal.Valid {
			file.UserID = &userIDVal.Int64
		}

		// Delete from database
		deleteQuery := `DELETE FROM files WHERE claim_code = $1 AND user_id = $2`
		result, err := tx.Exec(ctx, deleteQuery, claimCode, userID)
		if err != nil {
			return nil, fmt.Errorf("failed to delete file from database: %w", err)
		}

		if result.RowsAffected() == 0 {
			return nil, repository.ErrNotFound
		}

		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("failed to commit transaction: %w", err)
		}

		return file, nil
	})
}

// UpdateFileName updates the original filename for a file owned by the specified user.
func (r *UserRepository) UpdateFileName(ctx context.Context, fileID, userID int64, newFilename string) error {
	query := `UPDATE files SET original_filename = $1 WHERE id = $2 AND user_id = $3`

	result, err := r.pool.Exec(ctx, query, newFilename, fileID, userID)
	if err != nil {
		return fmt.Errorf("failed to update filename: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// UpdateFileNameByClaimCode updates the original filename for a file identified by claim code.
func (r *UserRepository) UpdateFileNameByClaimCode(ctx context.Context, claimCode string, userID int64, newFilename string) error {
	query := `UPDATE files SET original_filename = $1 WHERE claim_code = $2 AND user_id = $3`

	result, err := r.pool.Exec(ctx, query, newFilename, claimCode, userID)
	if err != nil {
		return fmt.Errorf("failed to update filename: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// UpdateFileExpiration updates the expiration date for a file owned by the specified user.
func (r *UserRepository) UpdateFileExpiration(ctx context.Context, fileID, userID int64, newExpiration time.Time) error {
	query := `UPDATE files SET expires_at = $1 WHERE id = $2 AND user_id = $3`

	result, err := r.pool.Exec(ctx, query, newExpiration, fileID, userID)
	if err != nil {
		return fmt.Errorf("failed to update expiration: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// UpdateFileExpirationByClaimCode updates the expiration date for a file identified by claim code.
func (r *UserRepository) UpdateFileExpirationByClaimCode(ctx context.Context, claimCode string, userID int64, newExpiration time.Time) error {
	query := `UPDATE files SET expires_at = $1 WHERE claim_code = $2 AND user_id = $3`

	result, err := r.pool.Exec(ctx, query, newExpiration, claimCode, userID)
	if err != nil {
		return fmt.Errorf("failed to update expiration: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// GetFileByClaimCode retrieves a file by claim code if it belongs to the specified user.
func (r *UserRepository) GetFileByClaimCode(ctx context.Context, claimCode string, userID int64) (*models.File, error) {
	query := `
		SELECT id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads, download_count,
			completed_downloads, uploader_ip, password_hash, user_id
		FROM files
		WHERE claim_code = $1 AND user_id = $2
	`

	file := &models.File{}
	var passwordHash sql.NullString
	var maxDownloads sql.NullInt64
	var userIDVal sql.NullInt64

	err := r.pool.QueryRow(ctx, query, claimCode, userID).Scan(
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
		&userIDVal,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
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
	if userIDVal.Valid {
		file.UserID = &userIDVal.Int64
	}

	return file, nil
}

// RegenerateClaimCode generates a new unique claim code for a file owned by the specified user.
func (r *UserRepository) RegenerateClaimCode(ctx context.Context, fileID, userID int64) (*repository.ClaimCodeRegenerationResult, error) {
	return withRetry(ctx, 3, func() (*repository.ClaimCodeRegenerationResult, error) {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return nil, fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback(ctx)

		// Verify file exists and belongs to user
		var currentClaimCode string
		var filename string
		err = tx.QueryRow(ctx, `
			SELECT claim_code, original_filename
			FROM files
			WHERE id = $1 AND user_id = $2
			FOR UPDATE
		`, fileID, userID).Scan(&currentClaimCode, &filename)

		if err == pgx.ErrNoRows {
			return nil, repository.ErrNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("failed to query file: %w", err)
		}

		// Generate new unique claim code
		newClaimCode, err := generateUniqueClaimCodePg(ctx, tx, fileID)
		if err != nil {
			return nil, err
		}

		// Update database with new claim code
		result, err := tx.Exec(ctx, `
			UPDATE files
			SET claim_code = $1
			WHERE id = $2 AND user_id = $3
		`, newClaimCode, fileID, userID)

		if err != nil {
			return nil, fmt.Errorf("failed to update claim code: %w", err)
		}

		if result.RowsAffected() == 0 {
			return nil, repository.ErrNotFound
		}

		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("failed to commit transaction: %w", err)
		}

		slog.Info("claim code regenerated",
			"file_id", fileID,
			"old_claim_code", currentClaimCode,
			"new_claim_code", newClaimCode,
		)

		return &repository.ClaimCodeRegenerationResult{
			NewClaimCode:     newClaimCode,
			OldClaimCode:     currentClaimCode,
			FileID:           fileID,
			OriginalFilename: filename,
		}, nil
	})
}

// RegenerateClaimCodeByClaimCode generates a new unique claim code for a file identified by claim code.
func (r *UserRepository) RegenerateClaimCodeByClaimCode(ctx context.Context, oldClaimCode string, userID int64) (*repository.ClaimCodeRegenerationResult, error) {
	return withRetry(ctx, 3, func() (*repository.ClaimCodeRegenerationResult, error) {
		tx, err := r.pool.BeginTx(ctx, TxOptions())
		if err != nil {
			return nil, fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback(ctx)

		// Verify file exists and belongs to user
		var fileID int64
		var filename string
		err = tx.QueryRow(ctx, `
			SELECT id, original_filename
			FROM files
			WHERE claim_code = $1 AND user_id = $2
			FOR UPDATE
		`, oldClaimCode, userID).Scan(&fileID, &filename)

		if err == pgx.ErrNoRows {
			return nil, repository.ErrNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("failed to query file: %w", err)
		}

		// Generate new unique claim code
		newClaimCode, err := generateUniqueClaimCodePg(ctx, tx, fileID)
		if err != nil {
			return nil, err
		}

		// Update database with new claim code
		result, err := tx.Exec(ctx, `
			UPDATE files
			SET claim_code = $1
			WHERE claim_code = $2 AND user_id = $3
		`, newClaimCode, oldClaimCode, userID)

		if err != nil {
			return nil, fmt.Errorf("failed to update claim code: %w", err)
		}

		if result.RowsAffected() == 0 {
			return nil, repository.ErrNotFound
		}

		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("failed to commit transaction: %w", err)
		}

		slog.Info("claim code regenerated by claim code",
			"file_id", fileID,
			"old_claim_code", oldClaimCode,
			"new_claim_code", newClaimCode,
		)

		return &repository.ClaimCodeRegenerationResult{
			NewClaimCode:     newClaimCode,
			OldClaimCode:     oldClaimCode,
			FileID:           fileID,
			OriginalFilename: filename,
		}, nil
	})
}

// generateUniqueClaimCodePg generates a unique claim code with exponential backoff for PostgreSQL.
func generateUniqueClaimCodePg(ctx context.Context, tx pgx.Tx, fileID int64) (string, error) {
	var newClaimCode string
	maxAttempts := 10

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Add exponential backoff after first attempt (context-aware to avoid blocking)
		if attempt > 0 {
			backoff := time.Duration(10*(1<<uint(attempt-1))) * time.Millisecond
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(backoff):
			}
			slog.Debug("retrying claim code generation",
				"attempt", attempt,
				"backoff_ms", backoff.Milliseconds(),
			)
		}

		code, err := generateClaimCode()
		if err != nil {
			slog.Error("failed to generate claim code", "error", err)
			if attempt >= 2 {
				break
			}
			continue
		}

		// Check if code already exists
		var exists bool
		err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM files WHERE claim_code = $1)", code).Scan(&exists)
		if err != nil {
			slog.Error("failed to check claim code uniqueness", "error", err)
			continue
		}

		if !exists {
			newClaimCode = code
			break
		}

		slog.Warn("claim code collision detected",
			"attempt", attempt,
			"file_id", fileID,
		)
	}

	if newClaimCode == "" {
		slog.Error("failed to generate unique claim code after max attempts",
			"max_attempts", maxAttempts,
			"file_id", fileID,
		)
		return "", repository.ErrServiceUnavailable
	}

	return newClaimCode, nil
}

// Ensure UserRepository implements repository.UserRepository.
var _ repository.UserRepository = (*UserRepository)(nil)
