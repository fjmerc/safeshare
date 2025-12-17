package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// MFARepository implements repository.MFARepository for SQLite.
type MFARepository struct {
	db *sql.DB
}

// NewMFARepository creates a new SQLite MFA repository.
func NewMFARepository(db *sql.DB) *MFARepository {
	return &MFARepository{db: db}
}

// Input validation constants.
const (
	maxSecretLen       = 512  // Maximum length for encrypted TOTP secret
	maxCredentialIDLen = 1024 // Maximum length for WebAuthn credential ID
	maxNameLen         = 100  // Maximum length for credential name
	maxChallengeLen    = 256  // Maximum length for challenge
	maxCodeHashLen     = 256  // Maximum length for bcrypt hash
	maxRecoveryCodes   = 20   // Maximum number of recovery codes per user
)

// parseTimestampUTC parses a timestamp string trying multiple formats.
// SQLite may return timestamps in different formats depending on how they were stored
// and how the Go driver handles them.
func parseTimestampUTC(s string) (time.Time, error) {
	// Try common SQLite timestamp formats
	formats := []string{
		"2006-01-02 15:04:05",    // Standard SQLite format
		time.RFC3339,             // ISO 8601 / RFC 3339 (2006-01-02T15:04:05Z)
		"2006-01-02T15:04:05Z",   // Explicit UTC variant
		"2006-01-02T15:04:05",    // Without timezone
	}

	for _, format := range formats {
		if t, err := time.ParseInLocation(format, s, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", s)
}

// ===========================================================================
// TOTP Operations
// ===========================================================================

// SetupTOTP initializes TOTP for a user with an encrypted secret.
func (r *MFARepository) SetupTOTP(ctx context.Context, userID int64, encryptedSecret string) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}
	if len(encryptedSecret) == 0 || len(encryptedSecret) > maxSecretLen {
		return fmt.Errorf("invalid secret length")
	}

	// Check if TOTP is already enabled
	var totpEnabled bool
	err := r.db.QueryRowContext(ctx,
		"SELECT totp_enabled FROM user_mfa WHERE user_id = ?",
		userID,
	).Scan(&totpEnabled)

	if err == nil && totpEnabled {
		return repository.ErrMFAAlreadyEnabled
	}

	// Use UPSERT pattern: insert or update if exists
	query := `
		INSERT INTO user_mfa (user_id, totp_secret, totp_enabled, created_at, updated_at)
		VALUES (?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id) DO UPDATE SET
			totp_secret = excluded.totp_secret,
			totp_enabled = 0,
			totp_verified_at = NULL,
			updated_at = CURRENT_TIMESTAMP
		WHERE totp_enabled = 0`

	result, err := r.db.ExecContext(ctx, query, userID, encryptedSecret)
	if err != nil {
		return fmt.Errorf("failed to setup TOTP: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return repository.ErrMFAAlreadyEnabled
	}

	return nil
}

// GetTOTPSecret retrieves the encrypted TOTP secret for a user.
func (r *MFARepository) GetTOTPSecret(ctx context.Context, userID int64) (string, error) {
	if userID <= 0 {
		return "", fmt.Errorf("invalid user ID")
	}

	var secret sql.NullString
	err := r.db.QueryRowContext(ctx,
		"SELECT totp_secret FROM user_mfa WHERE user_id = ?",
		userID,
	).Scan(&secret)

	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	return secret.String, nil
}

// EnableTOTP marks TOTP as verified and enabled for a user.
func (r *MFARepository) EnableTOTP(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE user_mfa 
		SET totp_enabled = 1, totp_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE user_id = ? AND totp_secret IS NOT NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("failed to enable TOTP: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// DisableTOTP disables TOTP for a user.
func (r *MFARepository) DisableTOTP(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete recovery codes
	if _, err := tx.ExecContext(ctx, "DELETE FROM user_mfa_recovery_codes WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("failed to delete recovery codes: %w", err)
	}

	// Clear TOTP settings
	if _, err := tx.ExecContext(ctx, `
		UPDATE user_mfa 
		SET totp_secret = NULL, totp_enabled = 0, totp_verified_at = NULL, updated_at = CURRENT_TIMESTAMP
		WHERE user_id = ?`,
		userID,
	); err != nil {
		return fmt.Errorf("failed to disable TOTP: %w", err)
	}

	return tx.Commit()
}

// IsTOTPEnabled checks if TOTP is enabled and verified for a user.
func (r *MFARepository) IsTOTPEnabled(ctx context.Context, userID int64) (bool, error) {
	if userID <= 0 {
		return false, fmt.Errorf("invalid user ID")
	}

	var enabled bool
	err := r.db.QueryRowContext(ctx,
		"SELECT totp_enabled FROM user_mfa WHERE user_id = ?",
		userID,
	).Scan(&enabled)

	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check TOTP status: %w", err)
	}

	return enabled, nil
}

// GetMFAStatus retrieves the full MFA status for a user.
func (r *MFARepository) GetMFAStatus(ctx context.Context, userID int64) (*repository.MFAStatus, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("invalid user ID")
	}

	status := &repository.MFAStatus{}

	// Get TOTP status
	var totpVerifiedAt sql.NullString
	err := r.db.QueryRowContext(ctx,
		"SELECT totp_enabled, totp_verified_at FROM user_mfa WHERE user_id = ?",
		userID,
	).Scan(&status.TOTPEnabled, &totpVerifiedAt)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to get TOTP status: %w", err)
	}
	if totpVerifiedAt.Valid {
		status.TOTPVerifiedAt = totpVerifiedAt.String
	}

	// Get WebAuthn credential count
	err = r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM user_webauthn_credentials WHERE user_id = ?",
		userID,
	).Scan(&status.WebAuthnCredentials)
	if err != nil {
		return nil, fmt.Errorf("failed to count WebAuthn credentials: %w", err)
	}
	status.WebAuthnEnabled = status.WebAuthnCredentials > 0

	// Get remaining recovery codes
	err = r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM user_mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL",
		userID,
	).Scan(&status.RecoveryCodesRemaining)
	if err != nil {
		return nil, fmt.Errorf("failed to count recovery codes: %w", err)
	}

	return status, nil
}

// GetUserMFA retrieves the full MFA record for a user.
func (r *MFARepository) GetUserMFA(ctx context.Context, userID int64) (*repository.UserMFA, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("invalid user ID")
	}

	query := `SELECT id, user_id, totp_secret, totp_enabled, totp_verified_at, created_at, updated_at
		FROM user_mfa WHERE user_id = ?`

	var mfa repository.UserMFA
	var secret, verifiedAt sql.NullString
	var createdAt, updatedAt string

	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&mfa.ID,
		&mfa.UserID,
		&secret,
		&mfa.TOTPEnabled,
		&verifiedAt,
		&createdAt,
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get MFA record: %w", err)
	}

	mfa.TOTPSecret = secret.String
	if verifiedAt.Valid {
		t, _ := time.Parse("2006-01-02 15:04:05", verifiedAt.String)
		mfa.TOTPVerifiedAt = &t
	}
	mfa.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	mfa.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)

	return &mfa, nil
}

// ===========================================================================
// Recovery Code Operations
// ===========================================================================

// CreateRecoveryCodes stores hashed recovery codes for a user.
func (r *MFARepository) CreateRecoveryCodes(ctx context.Context, userID int64, codeHashes []string) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}
	if len(codeHashes) == 0 || len(codeHashes) > maxRecoveryCodes {
		return fmt.Errorf("invalid number of recovery codes: must be 1-%d", maxRecoveryCodes)
	}
	for _, hash := range codeHashes {
		if len(hash) == 0 || len(hash) > maxCodeHashLen {
			return fmt.Errorf("invalid code hash length")
		}
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete existing unused codes
	if _, err := tx.ExecContext(ctx, "DELETE FROM user_mfa_recovery_codes WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("failed to delete existing codes: %w", err)
	}

	// Insert new codes
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO user_mfa_recovery_codes (user_id, code_hash, created_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer func() { _ = stmt.Close() }() // Error not actionable in defer

	for _, hash := range codeHashes {
		if _, err := stmt.ExecContext(ctx, userID, hash); err != nil {
			return fmt.Errorf("failed to insert recovery code: %w", err)
		}
	}

	return tx.Commit()
}

// UseRecoveryCode attempts to use a recovery code.
func (r *MFARepository) UseRecoveryCode(ctx context.Context, userID int64, code string) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}
	if len(code) == 0 {
		return repository.ErrInvalidRecoveryCode
	}

	// Collect all unused codes first to avoid SQLite deadlock
	// (can't execute UPDATE while rows iterator is open)
	type codeCandidate struct {
		id   int64
		hash string
	}
	var candidates []codeCandidate

	rows, err := r.db.QueryContext(ctx,
		"SELECT id, code_hash FROM user_mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL",
		userID,
	)
	if err != nil {
		return fmt.Errorf("failed to query recovery codes: %w", err)
	}

	for rows.Next() {
		var c codeCandidate
		if err := rows.Scan(&c.id, &c.hash); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan recovery code: %w", err)
		}
		candidates = append(candidates, c)
	}
	rows.Close()

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating recovery codes: %w", err)
	}

	// Now check each code hash (rows is closed, safe to UPDATE)
	for _, c := range candidates {
		if err := bcrypt.CompareHashAndPassword([]byte(c.hash), []byte(code)); err == nil {
			// Match found - mark as used
			_, err := r.db.ExecContext(ctx,
				"UPDATE user_mfa_recovery_codes SET used_at = CURRENT_TIMESTAMP WHERE id = ?",
				c.id,
			)
			if err != nil {
				return fmt.Errorf("failed to mark code as used: %w", err)
			}
			return nil
		}
	}

	return repository.ErrInvalidRecoveryCode
}

// GetRecoveryCodeCount returns the count of remaining (unused) recovery codes.
func (r *MFARepository) GetRecoveryCodeCount(ctx context.Context, userID int64) (int, error) {
	if userID <= 0 {
		return 0, fmt.Errorf("invalid user ID")
	}

	var count int
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM user_mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL",
		userID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count recovery codes: %w", err)
	}

	return count, nil
}

// DeleteRecoveryCodes deletes all recovery codes for a user.
func (r *MFARepository) DeleteRecoveryCodes(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}

	_, err := r.db.ExecContext(ctx, "DELETE FROM user_mfa_recovery_codes WHERE user_id = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to delete recovery codes: %w", err)
	}

	return nil
}

// ===========================================================================
// WebAuthn Credential Operations
// ===========================================================================

// CreateWebAuthnCredential stores a new WebAuthn credential for a user.
func (r *MFARepository) CreateWebAuthnCredential(ctx context.Context, cred *repository.WebAuthnCredential) (*repository.WebAuthnCredential, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is nil")
	}
	if cred.UserID <= 0 {
		return nil, fmt.Errorf("invalid user ID")
	}
	if len(cred.Name) == 0 || len(cred.Name) > maxNameLen {
		return nil, fmt.Errorf("invalid credential name length")
	}
	if len(cred.CredentialID) == 0 || len(cred.CredentialID) > maxCredentialIDLen {
		return nil, fmt.Errorf("invalid credential ID length")
	}
	if len(cred.PublicKey) == 0 {
		return nil, fmt.Errorf("public key is required")
	}

	transports := strings.Join(cred.Transports, ",")

	query := `
		INSERT INTO user_webauthn_credentials 
		(user_id, name, credential_id, public_key, aaguid, sign_count, transports, 
		 user_verified, backup_eligible, backup_state, attestation_type, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`

	result, err := r.db.ExecContext(ctx, query,
		cred.UserID, cred.Name, cred.CredentialID, cred.PublicKey, cred.AAGUID,
		cred.SignCount, transports, cred.UserVerified, cred.BackupEligible,
		cred.BackupState, cred.AttestationType,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn credential: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get credential ID: %w", err)
	}

	cred.ID = id
	cred.CreatedAt = time.Now()

	return cred, nil
}

// GetWebAuthnCredentials retrieves all WebAuthn credentials for a user.
func (r *MFARepository) GetWebAuthnCredentials(ctx context.Context, userID int64) ([]repository.WebAuthnCredential, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("invalid user ID")
	}

	query := `
		SELECT id, user_id, name, credential_id, public_key, aaguid, sign_count, transports,
		       user_verified, backup_eligible, backup_state, attestation_type, created_at, last_used_at
		FROM user_webauthn_credentials
		WHERE user_id = ?
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query WebAuthn credentials: %w", err)
	}
	defer rows.Close()

	var credentials []repository.WebAuthnCredential
	for rows.Next() {
		var cred repository.WebAuthnCredential
		var transports, aaguid, attestationType sql.NullString
		var lastUsedAt sql.NullString
		var createdAt string

		err := rows.Scan(
			&cred.ID, &cred.UserID, &cred.Name, &cred.CredentialID, &cred.PublicKey,
			&aaguid, &cred.SignCount, &transports, &cred.UserVerified,
			&cred.BackupEligible, &cred.BackupState, &attestationType, &createdAt, &lastUsedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan WebAuthn credential: %w", err)
		}

		cred.AAGUID = aaguid.String
		cred.AttestationType = attestationType.String
		if transports.Valid && transports.String != "" {
			cred.Transports = strings.Split(transports.String, ",")
		}
		cred.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		if lastUsedAt.Valid {
			t, _ := time.Parse("2006-01-02 15:04:05", lastUsedAt.String)
			cred.LastUsedAt = &t
		}

		credentials = append(credentials, cred)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating WebAuthn credentials: %w", err)
	}

	return credentials, nil
}

// GetWebAuthnCredentialByID retrieves a specific credential by ID.
func (r *MFARepository) GetWebAuthnCredentialByID(ctx context.Context, credentialID int64, userID int64) (*repository.WebAuthnCredential, error) {
	if credentialID <= 0 || userID <= 0 {
		return nil, fmt.Errorf("invalid credential or user ID")
	}

	query := `
		SELECT id, user_id, name, credential_id, public_key, aaguid, sign_count, transports,
		       user_verified, backup_eligible, backup_state, attestation_type, created_at, last_used_at
		FROM user_webauthn_credentials
		WHERE id = ? AND user_id = ?`

	var cred repository.WebAuthnCredential
	var transports, aaguid, attestationType sql.NullString
	var lastUsedAt sql.NullString
	var createdAt string

	err := r.db.QueryRowContext(ctx, query, credentialID, userID).Scan(
		&cred.ID, &cred.UserID, &cred.Name, &cred.CredentialID, &cred.PublicKey,
		&aaguid, &cred.SignCount, &transports, &cred.UserVerified,
		&cred.BackupEligible, &cred.BackupState, &attestationType, &createdAt, &lastUsedAt,
	)

	if err == sql.ErrNoRows {
		return nil, repository.ErrWebAuthnCredentialNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get WebAuthn credential: %w", err)
	}

	cred.AAGUID = aaguid.String
	cred.AttestationType = attestationType.String
	if transports.Valid && transports.String != "" {
		cred.Transports = strings.Split(transports.String, ",")
	}
	cred.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	if lastUsedAt.Valid {
		t, _ := time.Parse("2006-01-02 15:04:05", lastUsedAt.String)
		cred.LastUsedAt = &t
	}

	return &cred, nil
}

// GetWebAuthnCredentialByCredentialID retrieves a credential by its credential ID.
func (r *MFARepository) GetWebAuthnCredentialByCredentialID(ctx context.Context, credentialID string) (*repository.WebAuthnCredential, error) {
	if len(credentialID) == 0 || len(credentialID) > maxCredentialIDLen {
		return nil, fmt.Errorf("invalid credential ID")
	}

	query := `
		SELECT id, user_id, name, credential_id, public_key, aaguid, sign_count, transports,
		       user_verified, backup_eligible, backup_state, attestation_type, created_at, last_used_at
		FROM user_webauthn_credentials
		WHERE credential_id = ?`

	var cred repository.WebAuthnCredential
	var transports, aaguid, attestationType sql.NullString
	var lastUsedAt sql.NullString
	var createdAt string

	err := r.db.QueryRowContext(ctx, query, credentialID).Scan(
		&cred.ID, &cred.UserID, &cred.Name, &cred.CredentialID, &cred.PublicKey,
		&aaguid, &cred.SignCount, &transports, &cred.UserVerified,
		&cred.BackupEligible, &cred.BackupState, &attestationType, &createdAt, &lastUsedAt,
	)

	if err == sql.ErrNoRows {
		return nil, repository.ErrWebAuthnCredentialNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get WebAuthn credential: %w", err)
	}

	cred.AAGUID = aaguid.String
	cred.AttestationType = attestationType.String
	if transports.Valid && transports.String != "" {
		cred.Transports = strings.Split(transports.String, ",")
	}
	cred.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	if lastUsedAt.Valid {
		t, _ := time.Parse("2006-01-02 15:04:05", lastUsedAt.String)
		cred.LastUsedAt = &t
	}

	return &cred, nil
}

// UpdateWebAuthnCredentialSignCount updates the sign count for a credential.
func (r *MFARepository) UpdateWebAuthnCredentialSignCount(ctx context.Context, credentialID int64, signCount uint32) error {
	if credentialID <= 0 {
		return fmt.Errorf("invalid credential ID")
	}

	result, err := r.db.ExecContext(ctx,
		"UPDATE user_webauthn_credentials SET sign_count = ?, last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
		signCount, credentialID,
	)
	if err != nil {
		return fmt.Errorf("failed to update sign count: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return repository.ErrWebAuthnCredentialNotFound
	}

	return nil
}

// UpdateWebAuthnCredentialName updates the user-friendly name of a credential.
func (r *MFARepository) UpdateWebAuthnCredentialName(ctx context.Context, credentialID int64, userID int64, name string) error {
	if credentialID <= 0 || userID <= 0 {
		return fmt.Errorf("invalid credential or user ID")
	}
	if len(name) == 0 || len(name) > maxNameLen {
		return fmt.Errorf("invalid name length")
	}

	result, err := r.db.ExecContext(ctx,
		"UPDATE user_webauthn_credentials SET name = ? WHERE id = ? AND user_id = ?",
		name, credentialID, userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update credential name: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return repository.ErrWebAuthnCredentialNotFound
	}

	return nil
}

// DeleteWebAuthnCredential removes a WebAuthn credential.
func (r *MFARepository) DeleteWebAuthnCredential(ctx context.Context, credentialID int64, userID int64) error {
	if credentialID <= 0 || userID <= 0 {
		return fmt.Errorf("invalid credential or user ID")
	}

	result, err := r.db.ExecContext(ctx,
		"DELETE FROM user_webauthn_credentials WHERE id = ? AND user_id = ?",
		credentialID, userID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete WebAuthn credential: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return repository.ErrWebAuthnCredentialNotFound
	}

	return nil
}

// CountWebAuthnCredentials returns the number of WebAuthn credentials for a user.
func (r *MFARepository) CountWebAuthnCredentials(ctx context.Context, userID int64) (int, error) {
	if userID <= 0 {
		return 0, fmt.Errorf("invalid user ID")
	}

	var count int
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM user_webauthn_credentials WHERE user_id = ?",
		userID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count WebAuthn credentials: %w", err)
	}

	return count, nil
}

// ===========================================================================
// MFA Challenge Operations
// ===========================================================================

// CreateChallenge creates a new WebAuthn challenge.
func (r *MFARepository) CreateChallenge(ctx context.Context, userID int64, challenge, challengeType string, expiresAt time.Time) (*repository.MFAChallenge, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("invalid user ID")
	}
	if len(challenge) == 0 || len(challenge) > maxChallengeLen {
		return nil, fmt.Errorf("invalid challenge length")
	}
	if challengeType != "registration" && challengeType != "authentication" && challengeType != "login_authentication" {
		return nil, fmt.Errorf("invalid challenge type: must be 'registration', 'authentication', or 'login_authentication'")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete any existing challenge of the same type for this user
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM mfa_challenges WHERE user_id = ? AND challenge_type = ?",
		userID, challengeType,
	); err != nil {
		return nil, fmt.Errorf("failed to delete existing challenge: %w", err)
	}

	// Insert new challenge (store times in UTC for consistency with SQLite CURRENT_TIMESTAMP)
	result, err := tx.ExecContext(ctx, `
		INSERT INTO mfa_challenges (user_id, challenge, challenge_type, expires_at, created_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		userID, challenge, challengeType, expiresAt.UTC().Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create challenge: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get challenge ID: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &repository.MFAChallenge{
		ID:            id,
		UserID:        userID,
		Challenge:     challenge,
		ChallengeType: challengeType,
		ExpiresAt:     expiresAt,
		CreatedAt:     time.Now(),
	}, nil
}

// GetChallenge retrieves a valid (non-expired) challenge.
func (r *MFARepository) GetChallenge(ctx context.Context, userID int64, challengeType string) (*repository.MFAChallenge, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("invalid user ID")
	}
	if challengeType != "registration" && challengeType != "authentication" && challengeType != "login_authentication" {
		return nil, fmt.Errorf("invalid challenge type")
	}

	query := `
		SELECT id, user_id, challenge, challenge_type, expires_at, created_at
		FROM mfa_challenges
		WHERE user_id = ? AND challenge_type = ?`

	var ch repository.MFAChallenge
	var expiresAt, createdAt string

	err := r.db.QueryRowContext(ctx, query, userID, challengeType).Scan(
		&ch.ID, &ch.UserID, &ch.Challenge, &ch.ChallengeType, &expiresAt, &createdAt,
	)

	if err == sql.ErrNoRows {
		return nil, repository.ErrChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get challenge: %w", err)
	}

	// Parse times as UTC using multi-format parser
	var parseErr error
	ch.ExpiresAt, parseErr = parseTimestampUTC(expiresAt)
	if parseErr != nil {
		slog.Error("failed to parse challenge expires_at", "raw_value", expiresAt, "error", parseErr)
		return nil, fmt.Errorf("failed to parse challenge timestamp: %w", parseErr)
	}
	ch.CreatedAt, _ = parseTimestampUTC(createdAt)

	// Debug logging to trace timezone issue (temporary - remove after fixing)
	slog.Info("challenge lookup result",
		"challenge_id", ch.ID,
		"raw_expires_at_string", expiresAt,
		"parsed_expires_at", ch.ExpiresAt.Format(time.RFC3339),
		"current_utc", time.Now().UTC().Format(time.RFC3339),
		"is_expired", time.Now().UTC().After(ch.ExpiresAt),
	)

	// Check if expired (compare in UTC)
	if time.Now().UTC().After(ch.ExpiresAt) {
		// Clean up expired challenge (best-effort, error not actionable)
		_, _ = r.db.ExecContext(ctx, "DELETE FROM mfa_challenges WHERE id = ?", ch.ID)
		return nil, repository.ErrChallengeExpired
	}

	return &ch, nil
}

// DeleteChallenge removes a challenge after use.
func (r *MFARepository) DeleteChallenge(ctx context.Context, userID int64, challengeType string) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}

	_, err := r.db.ExecContext(ctx,
		"DELETE FROM mfa_challenges WHERE user_id = ? AND challenge_type = ?",
		userID, challengeType,
	)
	if err != nil {
		return fmt.Errorf("failed to delete challenge: %w", err)
	}

	return nil
}

// CleanupExpiredChallenges removes all expired challenges.
func (r *MFARepository) CleanupExpiredChallenges(ctx context.Context) (int64, error) {
	result, err := r.db.ExecContext(ctx,
		"DELETE FROM mfa_challenges WHERE expires_at < CURRENT_TIMESTAMP",
	)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired challenges: %w", err)
	}

	affected, _ := result.RowsAffected()
	return affected, nil
}

// ===========================================================================
// Admin Operations
// ===========================================================================

// AdminDisableMFA disables all MFA methods for a user (admin operation).
func (r *MFARepository) AdminDisableMFA(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete recovery codes
	if _, err := tx.ExecContext(ctx, "DELETE FROM user_mfa_recovery_codes WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("failed to delete recovery codes: %w", err)
	}

	// Delete WebAuthn credentials
	if _, err := tx.ExecContext(ctx, "DELETE FROM user_webauthn_credentials WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("failed to delete WebAuthn credentials: %w", err)
	}

	// Delete challenges
	if _, err := tx.ExecContext(ctx, "DELETE FROM mfa_challenges WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("failed to delete MFA challenges: %w", err)
	}

	// Clear TOTP settings (or delete the record entirely)
	if _, err := tx.ExecContext(ctx, "DELETE FROM user_mfa WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("failed to delete MFA record: %w", err)
	}

	return tx.Commit()
}

// AdminGetMFAStatus retrieves MFA status for any user (admin operation).
func (r *MFARepository) AdminGetMFAStatus(ctx context.Context, userID int64) (*repository.MFAStatus, error) {
	// Same as GetMFAStatus - admin can view any user's status
	return r.GetMFAStatus(ctx, userID)
}
