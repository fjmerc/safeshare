package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// BlockedIP represents a blocked IP address
type BlockedIP struct {
	ID        int64
	IPAddress string
	Reason    string
	BlockedAt time.Time
	BlockedBy string
}

// AdminSession represents an admin session
type AdminSession struct {
	ID           int64
	SessionToken string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastActivity time.Time
	IPAddress    string
	UserAgent    string
}

// ValidateAdminCredentials checks if the provided username and password are valid
func ValidateAdminCredentials(db *sql.DB, username, password string) (bool, error) {
	query := `SELECT password_hash FROM admin_credentials WHERE username = ?`

	var hashedPassword string
	err := db.QueryRow(query, username).Scan(&hashedPassword)

	if err == sql.ErrNoRows {
		return false, nil // User not found
	}
	if err != nil {
		return false, fmt.Errorf("failed to query admin credentials: %w", err)
	}

	// Compare password with hash
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false, nil // Invalid password
	}

	return true, nil
}

// InitializeAdminCredentials creates or updates admin credentials in the database
func InitializeAdminCredentials(db *sql.DB, username, password string) error {
	// Hash the password
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}
	hashedPassword := string(hashedBytes)

	// Check if admin credentials already exist
	var existingUsername string
	err = db.QueryRow("SELECT username FROM admin_credentials LIMIT 1").Scan(&existingUsername)

	if err == sql.ErrNoRows {
		// No admin exists, insert new credentials
		query := `INSERT INTO admin_credentials (username, password_hash) VALUES (?, ?)`
		_, err = db.Exec(query, username, hashedPassword)
		if err != nil {
			return fmt.Errorf("failed to insert admin credentials: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to check existing admin: %w", err)
	}

	// Admin exists, update if username or password changed
	query := `UPDATE admin_credentials SET username = ?, password_hash = ? WHERE id = 1`
	_, err = db.Exec(query, username, hashedPassword)
	if err != nil {
		return fmt.Errorf("failed to update admin credentials: %w", err)
	}

	return nil
}

// CreateSession creates a new admin session
func CreateSession(db *sql.DB, token string, expiresAt time.Time, ipAddress, userAgent string) error {
	query := `INSERT INTO admin_sessions (session_token, expires_at, ip_address, user_agent)
		VALUES (?, ?, ?, ?)`

	// Format as RFC3339 for consistent SQLite datetime parsing
	expiresAtRFC3339 := expiresAt.Format(time.RFC3339)

	_, err := db.Exec(query, token, expiresAtRFC3339, ipAddress, userAgent)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// GetSession retrieves a session by token
func GetSession(db *sql.DB, token string) (*AdminSession, error) {
	// Note: datetime(expires_at) normalizes RFC3339 format for proper comparison
	query := `SELECT id, session_token, created_at, expires_at, last_activity, ip_address, user_agent
		FROM admin_sessions WHERE session_token = ? AND datetime(expires_at) > datetime('now')`

	var session AdminSession
	err := db.QueryRow(query, token).Scan(
		&session.ID,
		&session.SessionToken,
		&session.CreatedAt,
		&session.ExpiresAt,
		&session.LastActivity,
		&session.IPAddress,
		&session.UserAgent,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

// UpdateSessionActivity updates the last activity timestamp for a session
func UpdateSessionActivity(db *sql.DB, token string) error {
	query := `UPDATE admin_sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_token = ?`

	_, err := db.Exec(query, token)
	if err != nil {
		return fmt.Errorf("failed to update session activity: %w", err)
	}

	return nil
}

// DeleteSession deletes a session (logout)
func DeleteSession(db *sql.DB, token string) error {
	query := `DELETE FROM admin_sessions WHERE session_token = ?`

	_, err := db.Exec(query, token)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

// CleanupExpiredSessions removes expired sessions
func CleanupExpiredSessions(db *sql.DB) error {
	// Note: datetime(expires_at) normalizes RFC3339 format for proper comparison
	query := `DELETE FROM admin_sessions WHERE datetime(expires_at) < datetime('now')`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	return nil
}

// BlockIP adds an IP address to the blocklist
func BlockIP(db *sql.DB, ipAddress, reason, blockedBy string) error {
	query := `INSERT INTO blocked_ips (ip_address, reason, blocked_by)
		VALUES (?, ?, ?)`

	_, err := db.Exec(query, ipAddress, reason, blockedBy)
	if err != nil {
		return fmt.Errorf("failed to block IP: %w", err)
	}

	return nil
}

// UnblockIP removes an IP address from the blocklist
func UnblockIP(db *sql.DB, ipAddress string) error {
	query := `DELETE FROM blocked_ips WHERE ip_address = ?`

	result, err := db.Exec(query, ipAddress)
	if err != nil {
		return fmt.Errorf("failed to unblock IP: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("IP address not found in blocklist")
	}

	return nil
}

// IsIPBlocked checks if an IP address is blocked
func IsIPBlocked(db *sql.DB, ipAddress string) (bool, error) {
	query := `SELECT COUNT(*) FROM blocked_ips WHERE ip_address = ?`

	var count int
	err := db.QueryRow(query, ipAddress).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check if IP is blocked: %w", err)
	}

	return count > 0, nil
}

// GetBlockedIPs retrieves all blocked IPs
func GetBlockedIPs(db *sql.DB) ([]BlockedIP, error) {
	query := `SELECT id, ip_address, reason, blocked_at, blocked_by
		FROM blocked_ips ORDER BY blocked_at DESC`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query blocked IPs: %w", err)
	}
	defer rows.Close()

	var blockedIPs []BlockedIP
	for rows.Next() {
		var ip BlockedIP
		err := rows.Scan(&ip.ID, &ip.IPAddress, &ip.Reason, &ip.BlockedAt, &ip.BlockedBy)
		if err != nil {
			return nil, fmt.Errorf("failed to scan blocked IP: %w", err)
		}
		blockedIPs = append(blockedIPs, ip)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating blocked IPs: %w", err)
	}

	return blockedIPs, nil
}

// GetAllFilesForAdmin retrieves all files with pagination for admin dashboard
func GetAllFilesForAdmin(db *sql.DB, limit, offset int) ([]models.File, int, error) {
	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM files`
	err := db.QueryRow(countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count files: %w", err)
	}

	// Get paginated files with username via LEFT JOIN
	query := `SELECT f.id, f.claim_code, f.original_filename, f.stored_filename, f.file_size, f.mime_type,
		f.created_at, f.expires_at, f.max_downloads, f.download_count, f.completed_downloads, f.uploader_ip, f.password_hash, f.user_id,
		u.username
		FROM files f
		LEFT JOIN users u ON f.user_id = u.id
		ORDER BY f.created_at DESC LIMIT ? OFFSET ?`

	rows, err := db.Query(query, limit, offset)
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

		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating files: %w", err)
	}

	return files, total, nil
}

// escapeLikePattern escapes SQL LIKE wildcard characters (% and _) to prevent LIKE injection
func escapeLikePattern(s string) string {
	// Replace \ with \\ first to avoid double-escaping
	s = strings.ReplaceAll(s, "\\", "\\\\")
	// Escape % and _ wildcards
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}

// SearchFilesForAdmin searches files by claim code or filename
func SearchFilesForAdmin(db *sql.DB, searchTerm string, limit, offset int) ([]models.File, int, error) {
	// Escape LIKE wildcards to prevent LIKE injection (P1 security fix)
	escapedTerm := escapeLikePattern(searchTerm)
	searchPattern := "%" + escapedTerm + "%"

	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM files f
		LEFT JOIN users u ON f.user_id = u.id
		WHERE f.claim_code LIKE ? ESCAPE '\' OR f.original_filename LIKE ? ESCAPE '\' OR f.uploader_ip LIKE ? ESCAPE '\' OR u.username LIKE ? ESCAPE '\'`
	err := db.QueryRow(countQuery, searchPattern, searchPattern, searchPattern, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	// Get paginated results with username via LEFT JOIN
	query := `SELECT f.id, f.claim_code, f.original_filename, f.stored_filename, f.file_size, f.mime_type,
		f.created_at, f.expires_at, f.max_downloads, f.download_count, f.completed_downloads, f.uploader_ip, f.password_hash, f.user_id,
		u.username
		FROM files f
		LEFT JOIN users u ON f.user_id = u.id
		WHERE f.claim_code LIKE ? ESCAPE '\' OR f.original_filename LIKE ? ESCAPE '\' OR f.uploader_ip LIKE ? ESCAPE '\' OR u.username LIKE ? ESCAPE '\'
		ORDER BY f.created_at DESC LIMIT ? OFFSET ?`

	rows, err := db.Query(query, searchPattern, searchPattern, searchPattern, searchPattern, limit, offset)
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

		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating search results: %w", err)
	}

	return files, total, nil
}

// DeleteFileByClaimCode deletes a file by claim code (admin operation)
func DeleteFileByClaimCode(db *sql.DB, claimCode string) (*models.File, error) {
	// First get the file info for cleanup - don't check expiration for admin operations
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads, download_count, completed_downloads, uploader_ip, password_hash, user_id
		FROM files
		WHERE claim_code = ?
	`

	file := &models.File{}
	var createdAt, expiresAt string
	var passwordHash sql.NullString
	var maxDownloads sql.NullInt64
	var userID sql.NullInt64

	err := db.QueryRow(query, claimCode).Scan(
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
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("file not found")
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

	// Delete from database
	deleteQuery := `DELETE FROM files WHERE claim_code = ?`
	_, err = db.Exec(deleteQuery, claimCode)
	if err != nil {
		return nil, fmt.Errorf("failed to delete file from database: %w", err)
	}

	return file, nil
}

// DeleteFilesByClaimCodes deletes multiple files by claim codes (bulk admin operation)
func DeleteFilesByClaimCodes(db *sql.DB, claimCodes []string) ([]*models.File, error) {
	if len(claimCodes) == 0 {
		return nil, fmt.Errorf("no claim codes provided")
	}

	// Get all files info first
	files := make([]*models.File, 0, len(claimCodes))

	for _, claimCode := range claimCodes {
		// Get file info
		query := `
			SELECT
				id, claim_code, original_filename, stored_filename, file_size,
				mime_type, created_at, expires_at, max_downloads, download_count, completed_downloads, uploader_ip, password_hash, user_id
			FROM files
			WHERE claim_code = ?
		`

		file := &models.File{}
		var createdAt, expiresAt string
		var passwordHash sql.NullString
		var maxDownloads sql.NullInt64
		var userID sql.NullInt64
		// Note: username not needed for bulk delete operation

		err := db.QueryRow(query, claimCode).Scan(
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
		)

		if err == sql.ErrNoRows {
			// Skip files that don't exist
			continue
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
		// username not queried in bulk delete - not needed

		files = append(files, file)
	}

	// Delete all files from database
	if len(files) > 0 {
		// Build placeholders for IN clause
		placeholders := make([]string, len(files))
		args := make([]interface{}, len(files))
		for i, file := range files {
			placeholders[i] = "?"
			args[i] = file.ClaimCode
		}

		deleteQuery := fmt.Sprintf("DELETE FROM files WHERE claim_code IN (%s)", joinStrings(placeholders, ","))
		_, err := db.Exec(deleteQuery, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to delete files from database: %w", err)
		}
	}

	return files, nil
}

// Helper function to join strings
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
