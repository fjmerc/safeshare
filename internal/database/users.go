package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// CreateUser creates a new user in the database
func CreateUser(db *sql.DB, username, email, passwordHash, role string, requirePasswordChange bool) (*models.User, error) {
	query := `INSERT INTO users (username, email, password_hash, role, require_password_change)
		VALUES (?, ?, ?, ?, ?)`

	result, err := db.Exec(query, username, email, passwordHash, role, requirePasswordChange)
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

// GetUserByUsername retrieves a user by username
func GetUserByUsername(db *sql.DB, username string) (*models.User, error) {
	query := `SELECT id, username, email, password_hash, role, is_approved, is_active,
		require_password_change, created_at, last_login
		FROM users WHERE username = ?`

	var user models.User
	var createdAt string
	var lastLogin sql.NullString

	err := db.QueryRow(query, username).Scan(
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

// GetUserByID retrieves a user by ID
func GetUserByID(db *sql.DB, id int64) (*models.User, error) {
	query := `SELECT id, username, email, password_hash, role, is_approved, is_active,
		require_password_change, created_at, last_login
		FROM users WHERE id = ?`

	var user models.User
	var createdAt string
	var lastLogin sql.NullString

	err := db.QueryRow(query, id).Scan(
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

// UpdateUserLastLogin updates the last login timestamp for a user
func UpdateUserLastLogin(db *sql.DB, userID int64) error {
	query := `UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`

	_, err := db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// UpdateUserPassword updates a user's password
func UpdateUserPassword(db *sql.DB, userID int64, passwordHash string, clearPasswordChangeFlag bool) error {
	query := `UPDATE users SET password_hash = ?, require_password_change = ? WHERE id = ?`

	requireChange := 0
	if !clearPasswordChangeFlag {
		requireChange = 1
	}

	_, err := db.Exec(query, passwordHash, requireChange, userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// UpdateUser updates user details (username, email, role)
func UpdateUser(db *sql.DB, userID int64, username, email, role string) error {
	query := `UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?`

	_, err := db.Exec(query, username, email, role, userID)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// SetUserActive enables or disables a user account
func SetUserActive(db *sql.DB, userID int64, isActive bool) error {
	query := `UPDATE users SET is_active = ? WHERE id = ?`

	active := 0
	if isActive {
		active = 1
	}

	_, err := db.Exec(query, active, userID)
	if err != nil {
		return fmt.Errorf("failed to set user active status: %w", err)
	}

	return nil
}

// DeleteUser deletes a user from the database
func DeleteUser(db *sql.DB, userID int64) error {
	query := `DELETE FROM users WHERE id = ?`

	result, err := db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// GetAllUsers retrieves all users with pagination
func GetAllUsers(db *sql.DB, limit, offset int) ([]models.UserListItem, int, error) {
	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM users`
	err := db.QueryRow(countQuery).Scan(&total)
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

	rows, err := db.Query(query, limit, offset)
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

// CreateUserSession creates a new user session
func CreateUserSession(db *sql.DB, userID int64, token string, expiresAt time.Time, ipAddress, userAgent string) error {
	query := `INSERT INTO user_sessions (user_id, session_token, expires_at, ip_address, user_agent)
		VALUES (?, ?, ?, ?, ?)`

	_, err := db.Exec(query, userID, token, expiresAt, ipAddress, userAgent)
	if err != nil {
		return fmt.Errorf("failed to create user session: %w", err)
	}

	return nil
}

// GetUserSession retrieves a user session by token
func GetUserSession(db *sql.DB, token string) (*models.UserSession, error) {
	query := `SELECT id, user_id, session_token, created_at, expires_at, last_activity, ip_address, user_agent
		FROM user_sessions WHERE session_token = ? AND expires_at > CURRENT_TIMESTAMP`

	var session models.UserSession
	var createdAt, expiresAt, lastActivity string

	err := db.QueryRow(query, token).Scan(
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

// UpdateUserSessionActivity updates the last activity timestamp for a session
func UpdateUserSessionActivity(db *sql.DB, token string) error {
	query := `UPDATE user_sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_token = ?`

	_, err := db.Exec(query, token)
	if err != nil {
		return fmt.Errorf("failed to update session activity: %w", err)
	}

	return nil
}

// DeleteUserSession deletes a user session (logout)
func DeleteUserSession(db *sql.DB, token string) error {
	query := `DELETE FROM user_sessions WHERE session_token = ?`

	_, err := db.Exec(query, token)
	if err != nil {
		return fmt.Errorf("failed to delete user session: %w", err)
	}

	return nil
}

// CleanupExpiredUserSessions removes expired user sessions
func CleanupExpiredUserSessions(db *sql.DB) error {
	query := `DELETE FROM user_sessions WHERE expires_at < CURRENT_TIMESTAMP`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired user sessions: %w", err)
	}

	return nil
}

// GetFilesByUserID retrieves all files uploaded by a specific user
func GetFilesByUserID(db *sql.DB, userID int64, limit, offset int) ([]models.File, int, error) {
	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM files WHERE user_id = ?`
	err := db.QueryRow(countQuery, userID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count user files: %w", err)
	}

	// Get paginated files
	query := `SELECT id, claim_code, original_filename, stored_filename, file_size, mime_type,
		created_at, expires_at, max_downloads, download_count, completed_downloads, uploader_ip, password_hash, user_id
		FROM files WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`

	rows, err := db.Query(query, userID, limit, offset)
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

// DeleteFileByIDAndUserID deletes a file if it belongs to the specified user
func DeleteFileByIDAndUserID(db *sql.DB, fileID, userID int64) (*models.File, error) {
	// First get the file to ensure it belongs to the user
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

	err := db.QueryRow(query, fileID, userID).Scan(
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
		return nil, fmt.Errorf("file not found or does not belong to user")
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
	_, err = db.Exec(deleteQuery, fileID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete file from database: %w", err)
	}

	return file, nil
}

// UpdateFileNameByIDAndUserID updates the original filename for a file owned by the specified user
// Returns error if file not found or doesn't belong to the user
func UpdateFileNameByIDAndUserID(db *sql.DB, fileID, userID int64, newFilename string) error {
	query := `UPDATE files SET original_filename = ? WHERE id = ? AND user_id = ?`

	result, err := db.Exec(query, newFilename, fileID, userID)
	if err != nil {
		return fmt.Errorf("failed to update filename: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("file not found or does not belong to user")
	}

	return nil
}

// UpdateFileExpirationByIDAndUserID updates the expiration date for a file owned by the specified user
// Returns error if file not found or doesn't belong to the user
func UpdateFileExpirationByIDAndUserID(db *sql.DB, fileID, userID int64, newExpiration time.Time) error {
	query := `UPDATE files SET expires_at = ? WHERE id = ? AND user_id = ?`

	result, err := db.Exec(query, newExpiration, fileID, userID)
	if err != nil {
		return fmt.Errorf("failed to update expiration: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("file not found or does not belong to user")
	}

	return nil
}
