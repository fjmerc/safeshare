package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// UserRepository implements repository.UserRepository for SQLite.
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new SQLite user repository.
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
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

	query := `INSERT INTO users (username, email, password_hash, role, require_password_change)
		VALUES (?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(ctx, query, username, email, passwordHash, role, requirePasswordChange)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err)
	}

	user := &models.User{
		ID:                    id,
		Username:              username,
		Email:                 email,
		PasswordHash:          passwordHash,
		Role:                  role,
		IsApproved:            true,
		IsActive:              true,
		RequirePasswordChange: requirePasswordChange,
		CreatedAt:             time.Now(),
	}

	return user, nil
}

// GetByID retrieves a user by database ID.
func (r *UserRepository) GetByID(ctx context.Context, id int64) (*models.User, error) {
	query := `SELECT id, username, email, password_hash, role, is_approved, is_active,
		require_password_change, created_at, last_login
		FROM users WHERE id = ?`

	var user models.User
	var createdAt string
	var lastLogin sql.NullString

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.IsApproved,
		&user.IsActive,
		&user.RequirePasswordChange,
		&createdAt,
		&lastLogin,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Parse timestamps
	user.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	if lastLogin.Valid {
		t, err := time.Parse(time.RFC3339, lastLogin.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse last_login: %w", err)
		}
		user.LastLogin = &t
	}

	return &user, nil
}

// GetByUsername retrieves a user by username.
func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `SELECT id, username, email, password_hash, role, is_approved, is_active,
		require_password_change, created_at, last_login
		FROM users WHERE username = ?`

	var user models.User
	var createdAt string
	var lastLogin sql.NullString

	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.IsApproved,
		&user.IsActive,
		&user.RequirePasswordChange,
		&createdAt,
		&lastLogin,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Parse timestamps
	user.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	if lastLogin.Valid {
		t, err := time.Parse(time.RFC3339, lastLogin.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse last_login: %w", err)
		}
		user.LastLogin = &t
	}

	return &user, nil
}

// UpdateLastLogin updates the last login timestamp for a user.
func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID int64) error {
	query := `UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// UpdatePassword updates a user's password hash.
// NOTE: This method does NOT invalidate sessions. Use UpdatePasswordWithSessionInvalidation
// for security-critical password changes.
func (r *UserRepository) UpdatePassword(ctx context.Context, userID int64, passwordHash string, clearPasswordChangeFlag bool) error {
	query := `UPDATE users SET password_hash = ?, require_password_change = ? WHERE id = ?`

	requireChange := 0
	if !clearPasswordChangeFlag {
		requireChange = 1
	}

	_, err := r.db.ExecContext(ctx, query, passwordHash, requireChange, userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// UpdatePasswordWithSessionInvalidation atomically updates password and invalidates all sessions.
// This prevents session fixation attacks by ensuring old sessions cannot be used after password change.
func (r *UserRepository) UpdatePasswordWithSessionInvalidation(ctx context.Context, userID int64, passwordHash string, clearPasswordChangeFlag bool) error {
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.Warn("failed to rollback transaction", "error", err)
		}
	}()

	// Update password
	requireChange := 0
	if !clearPasswordChangeFlag {
		requireChange = 1
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, require_password_change = ? WHERE id = ?`,
		passwordHash, requireChange, userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Invalidate all sessions atomically
	_, err = tx.ExecContext(ctx, `DELETE FROM user_sessions WHERE user_id = ?`, userID)
	if err != nil {
		return fmt.Errorf("failed to invalidate sessions: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	slog.Info("password updated with session invalidation", "user_id", userID)
	return nil
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

	query := `UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?`

	_, err := r.db.ExecContext(ctx, query, username, email, role, userID)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// SetActive enables or disables a user account.
func (r *UserRepository) SetActive(ctx context.Context, userID int64, isActive bool) error {
	query := `UPDATE users SET is_active = ? WHERE id = ?`

	active := 0
	if isActive {
		active = 1
	}

	_, err := r.db.ExecContext(ctx, query, active, userID)
	if err != nil {
		return fmt.Errorf("failed to set user active status: %w", err)
	}

	return nil
}

// Delete removes a user from the database and cleans up their physical files.
// Uses a transaction to prevent TOCTOU race conditions.
func (r *UserRepository) Delete(ctx context.Context, userID int64, uploadDir string) error {
	// Validate uploadDir (defense in depth)
	if uploadDir == "" {
		return fmt.Errorf("uploadDir cannot be empty")
	}

	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.Warn("failed to rollback transaction", "error", err)
		}
	}()

	// Get all files owned by this user within the transaction
	var fileRecords []struct {
		ID             int64
		StoredFilename string
	}

	query := `SELECT id, stored_filename FROM files WHERE user_id = ? LIMIT 10000`
	rows, err := tx.QueryContext(ctx, query, userID)
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
	// This prevents new files from being associated with the user during deletion
	deleteQuery := `DELETE FROM users WHERE id = ?`
	result, err := tx.ExecContext(ctx, deleteQuery, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return repository.ErrNotFound
	}

	// Commit the transaction before deleting physical files
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Now delete physical files from disk (after DB commit)
	// Files are already detached from user, so orphaning is prevented
	for _, rec := range fileRecords {
		// Validate filename before deletion (defense-in-depth)
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
				// Log error but continue - DB deletion already happened
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
	err := r.db.QueryRowContext(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Get paginated users with file counts
	query := `SELECT u.id, u.username, u.email, u.role, u.is_active, u.created_at, u.last_login,
		COUNT(f.id) as file_count
		FROM users u
		LEFT JOIN files f ON u.id = f.user_id
		GROUP BY u.id
		ORDER BY u.created_at DESC
		LIMIT ? OFFSET ?`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var users []models.UserListItem
	for rows.Next() {
		var user models.UserListItem
		var createdAt string
		var lastLogin sql.NullString

		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.Role,
			&user.IsActive,
			&createdAt,
			&lastLogin,
			&user.FileCount,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan user: %w", err)
		}

		// Parse timestamps
		user.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse created_at: %w", err)
		}

		if lastLogin.Valid {
			t, err := time.Parse(time.RFC3339, lastLogin.String)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to parse last_login: %w", err)
			}
			user.LastLogin = &t
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
	query := `INSERT INTO user_sessions (user_id, session_token, expires_at, ip_address, user_agent)
		VALUES (?, ?, ?, ?, ?)`

	// Format as RFC3339 for consistent SQLite datetime parsing
	expiresAtRFC3339 := expiresAt.Format(time.RFC3339)

	_, err := r.db.ExecContext(ctx, query, userID, token, expiresAtRFC3339, ipAddress, userAgent)
	if err != nil {
		return fmt.Errorf("failed to create user session: %w", err)
	}

	return nil
}

// GetSession retrieves a session by token.
func (r *UserRepository) GetSession(ctx context.Context, token string) (*models.UserSession, error) {
	// Note: datetime(expires_at) normalizes RFC3339 format for proper comparison
	query := `SELECT id, user_id, session_token, created_at, expires_at, last_activity, ip_address, user_agent
		FROM user_sessions WHERE session_token = ? AND datetime(expires_at) > datetime('now')`

	var session models.UserSession
	var createdAt, expiresAt, lastActivity string

	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&session.ID,
		&session.UserID,
		&session.SessionToken,
		&createdAt,
		&expiresAt,
		&lastActivity,
		&session.IPAddress,
		&session.UserAgent,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user session: %w", err)
	}

	// Parse timestamps
	session.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	session.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", err)
	}

	session.LastActivity, err = time.Parse(time.RFC3339, lastActivity)
	if err != nil {
		return nil, fmt.Errorf("failed to parse last_activity: %w", err)
	}

	return &session, nil
}

// UpdateSessionActivity updates the last activity timestamp for a session.
func (r *UserRepository) UpdateSessionActivity(ctx context.Context, token string) error {
	query := `UPDATE user_sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_token = ?`

	_, err := r.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to update session activity: %w", err)
	}

	return nil
}

// DeleteSession deletes a session (logout).
func (r *UserRepository) DeleteSession(ctx context.Context, token string) error {
	query := `DELETE FROM user_sessions WHERE session_token = ?`

	_, err := r.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to delete user session: %w", err)
	}

	return nil
}

// DeleteSessionsByUserID deletes all sessions for a specific user.
func (r *UserRepository) DeleteSessionsByUserID(ctx context.Context, userID int64) error {
	query := `DELETE FROM user_sessions WHERE user_id = ?`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}

	return nil
}

// CleanupExpiredSessions removes expired user sessions.
func (r *UserRepository) CleanupExpiredSessions(ctx context.Context) error {
	// Note: datetime(expires_at) normalizes RFC3339 format for proper comparison
	query := `DELETE FROM user_sessions WHERE datetime(expires_at) < datetime('now')`

	_, err := r.db.ExecContext(ctx, query)
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
	countQuery := `SELECT COUNT(*) FROM files WHERE user_id = ?`
	err := r.db.QueryRowContext(ctx, countQuery, userID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count user files: %w", err)
	}

	// Get paginated files
	query := `SELECT id, claim_code, original_filename, stored_filename, file_size, mime_type,
		created_at, expires_at, max_downloads, download_count, completed_downloads, uploader_ip, password_hash, user_id
		FROM files WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`

	rows, err := r.db.QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query user files: %w", err)
	}
	defer rows.Close()

	var files []models.File
	for rows.Next() {
		var file models.File
		var createdAt, expiresAt string
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
			&createdAt,
			&expiresAt,
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
// Uses a transaction to prevent TOCTOU race conditions.
func (r *UserRepository) DeleteFile(ctx context.Context, fileID, userID int64) (*models.File, error) {
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.Warn("failed to rollback transaction", "error", err)
		}
	}()

	// Get the file to ensure it belongs to the user
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads, download_count, uploader_ip, password_hash, user_id
		FROM files
		WHERE id = ? AND user_id = ?
	`

	file := &models.File{}
	var createdAt, expiresAt string
	var passwordHash sql.NullString
	var maxDownloads sql.NullInt64
	var userIDVal sql.NullInt64

	err = tx.QueryRowContext(ctx, query, fileID, userID).Scan(
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
		&file.UploaderIP,
		&passwordHash,
		&userIDVal,
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
	if userIDVal.Valid {
		file.UserID = &userIDVal.Int64
	}

	// Delete from database
	deleteQuery := `DELETE FROM files WHERE id = ? AND user_id = ?`
	result, err := tx.ExecContext(ctx, deleteQuery, fileID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete file from database: %w", err)
	}

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

// DeleteFileByClaimCode deletes a file by claim code if it belongs to the specified user.
// Uses a transaction to prevent TOCTOU race conditions.
func (r *UserRepository) DeleteFileByClaimCode(ctx context.Context, claimCode string, userID int64) (*models.File, error) {
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.Warn("failed to rollback transaction", "error", err)
		}
	}()

	// Get the file
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads, download_count,
			completed_downloads, uploader_ip, password_hash, user_id
		FROM files
		WHERE claim_code = ? AND user_id = ?
	`

	file := &models.File{}
	var createdAt, expiresAt string
	var passwordHash sql.NullString
	var maxDownloads sql.NullInt64
	var userIDVal sql.NullInt64

	err = tx.QueryRowContext(ctx, query, claimCode, userID).Scan(
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
		&userIDVal,
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
	if userIDVal.Valid {
		file.UserID = &userIDVal.Int64
	}

	// Delete from database
	deleteQuery := `DELETE FROM files WHERE claim_code = ? AND user_id = ?`
	result, err := tx.ExecContext(ctx, deleteQuery, claimCode, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete file from database: %w", err)
	}

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

// UpdateFileName updates the original filename for a file owned by the specified user.
func (r *UserRepository) UpdateFileName(ctx context.Context, fileID, userID int64, newFilename string) error {
	query := `UPDATE files SET original_filename = ? WHERE id = ? AND user_id = ?`

	result, err := r.db.ExecContext(ctx, query, newFilename, fileID, userID)
	if err != nil {
		return fmt.Errorf("failed to update filename: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// UpdateFileNameByClaimCode updates the original filename for a file identified by claim code.
func (r *UserRepository) UpdateFileNameByClaimCode(ctx context.Context, claimCode string, userID int64, newFilename string) error {
	query := `UPDATE files SET original_filename = ? WHERE claim_code = ? AND user_id = ?`

	result, err := r.db.ExecContext(ctx, query, newFilename, claimCode, userID)
	if err != nil {
		return fmt.Errorf("failed to update filename: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// UpdateFileExpiration updates the expiration date for a file owned by the specified user.
func (r *UserRepository) UpdateFileExpiration(ctx context.Context, fileID, userID int64, newExpiration time.Time) error {
	query := `UPDATE files SET expires_at = ? WHERE id = ? AND user_id = ?`

	// Format as RFC3339 for consistent SQLite datetime() parsing
	expiresAtRFC3339 := newExpiration.Format(time.RFC3339)

	result, err := r.db.ExecContext(ctx, query, expiresAtRFC3339, fileID, userID)
	if err != nil {
		return fmt.Errorf("failed to update expiration: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// UpdateFileExpirationByClaimCode updates the expiration date for a file identified by claim code.
func (r *UserRepository) UpdateFileExpirationByClaimCode(ctx context.Context, claimCode string, userID int64, newExpiration time.Time) error {
	query := `UPDATE files SET expires_at = ? WHERE claim_code = ? AND user_id = ?`

	// Format as RFC3339 for consistent SQLite datetime() parsing
	expiresAtRFC3339 := newExpiration.Format(time.RFC3339)

	result, err := r.db.ExecContext(ctx, query, expiresAtRFC3339, claimCode, userID)
	if err != nil {
		return fmt.Errorf("failed to update expiration: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// GetFileByClaimCode retrieves a file by claim code if it belongs to the specified user.
func (r *UserRepository) GetFileByClaimCode(ctx context.Context, claimCode string, userID int64) (*models.File, error) {
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads, download_count,
			completed_downloads, uploader_ip, password_hash, user_id
		FROM files
		WHERE claim_code = ? AND user_id = ?
	`

	file := &models.File{}
	var createdAt, expiresAt string
	var passwordHash sql.NullString
	var maxDownloads sql.NullInt64
	var userIDVal sql.NullInt64

	err := r.db.QueryRowContext(ctx, query, claimCode, userID).Scan(
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
		&userIDVal,
	)

	if err == sql.ErrNoRows {
		return nil, nil
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
	if userIDVal.Valid {
		file.UserID = &userIDVal.Int64
	}

	return file, nil
}

// Ensure UserRepository implements repository.UserRepository.
var _ repository.UserRepository = (*UserRepository)(nil)
