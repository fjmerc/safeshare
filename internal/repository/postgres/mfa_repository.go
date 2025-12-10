// Package postgres provides PostgreSQL implementations of repository interfaces.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/fjmerc/safeshare/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// MFARepository implements repository.MFARepository for PostgreSQL.
type MFARepository struct {
	pool *Pool
}

// NewMFARepository creates a new PostgreSQL MFA repository.
func NewMFARepository(pool *Pool) *MFARepository {
	return &MFARepository{pool: pool}
}

// Input validation constants.
const (
	mfaMaxSecretLen       = 512  // Maximum length for encrypted TOTP secret
	mfaMaxCredentialIDLen = 1024 // Maximum length for WebAuthn credential ID
	mfaMaxNameLen         = 100  // Maximum length for credential name
	mfaMaxChallengeLen    = 256  // Maximum length for challenge
	mfaMaxCodeHashLen     = 256  // Maximum length for bcrypt hash
	mfaMaxRecoveryCodes   = 20   // Maximum number of recovery codes per user
)

// ===========================================================================
// TOTP Operations
// ===========================================================================

// SetupTOTP initializes TOTP for a user with an encrypted secret.
func (r *MFARepository) SetupTOTP(ctx context.Context, userID int64, encryptedSecret string) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}
	if len(encryptedSecret) == 0 || len(encryptedSecret) > mfaMaxSecretLen {
		return fmt.Errorf("invalid secret length")
	}

	// Check if TOTP is already enabled
	var totpEnabled bool
	err := r.pool.QueryRow(ctx,
		"SELECT totp_enabled FROM user_mfa WHERE user_id = $1",
		userID,
	).Scan(&totpEnabled)

	if err == nil && totpEnabled {
		return repository.ErrMFAAlreadyEnabled
	}

	// Use UPSERT pattern: insert or update if exists
	query := `
		INSERT INTO user_mfa (user_id, totp_secret, totp_enabled, created_at, updated_at)
		VALUES ($1, $2, FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id) DO UPDATE SET
			totp_secret = EXCLUDED.totp_secret,
			totp_enabled = FALSE,
			totp_verified_at = NULL,
			updated_at = CURRENT_TIMESTAMP
		WHERE user_mfa.totp_enabled = FALSE`

	result, err := r.pool.Exec(ctx, query, userID, encryptedSecret)
	if err != nil {
		return fmt.Errorf("failed to setup TOTP: %w", err)
	}

	if result.RowsAffected() == 0 {
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
	err := r.pool.QueryRow(ctx,
		"SELECT totp_secret FROM user_mfa WHERE user_id = $1",
		userID,
	).Scan(&secret)

	if err == pgx.ErrNoRows {
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

	result, err := r.pool.Exec(ctx, `
		UPDATE user_mfa 
		SET totp_enabled = TRUE, totp_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE user_id = $1 AND totp_secret IS NOT NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("failed to enable TOTP: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// DisableTOTP disables TOTP for a user.
func (r *MFARepository) DisableTOTP(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Delete recovery codes
	if _, err := tx.Exec(ctx, "DELETE FROM user_mfa_recovery_codes WHERE user_id = $1", userID); err != nil {
		return fmt.Errorf("failed to delete recovery codes: %w", err)
	}

	// Clear TOTP settings
	if _, err := tx.Exec(ctx, `
		UPDATE user_mfa 
		SET totp_secret = NULL, totp_enabled = FALSE, totp_verified_at = NULL, updated_at = CURRENT_TIMESTAMP
		WHERE user_id = $1`,
		userID,
	); err != nil {
		return fmt.Errorf("failed to disable TOTP: %w", err)
	}

	return tx.Commit(ctx)
}

// IsTOTPEnabled checks if TOTP is enabled and verified for a user.
func (r *MFARepository) IsTOTPEnabled(ctx context.Context, userID int64) (bool, error) {
	if userID <= 0 {
		return false, fmt.Errorf("invalid user ID")
	}

	var enabled bool
	err := r.pool.QueryRow(ctx,
		"SELECT totp_enabled FROM user_mfa WHERE user_id = $1",
		userID,
	).Scan(&enabled)

	if err == pgx.ErrNoRows {
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
	var totpVerifiedAt sql.NullTime
	err := r.pool.QueryRow(ctx,
		"SELECT totp_enabled, totp_verified_at FROM user_mfa WHERE user_id = $1",
		userID,
	).Scan(&status.TOTPEnabled, &totpVerifiedAt)
	if err != nil && err != pgx.ErrNoRows {
		return nil, fmt.Errorf("failed to get TOTP status: %w", err)
	}
	if totpVerifiedAt.Valid {
		status.TOTPVerifiedAt = totpVerifiedAt.Time.Format(time.RFC3339)
	}

	// Get WebAuthn credential count
	err = r.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM user_webauthn_credentials WHERE user_id = $1",
		userID,
	).Scan(&status.WebAuthnCredentials)
	if err != nil {
		return nil, fmt.Errorf("failed to count WebAuthn credentials: %w", err)
	}
	status.WebAuthnEnabled = status.WebAuthnCredentials > 0

	// Get remaining recovery codes
	err = r.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM user_mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
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
		FROM user_mfa WHERE user_id = $1`

	var mfa repository.UserMFA
	var secret sql.NullString
	var verifiedAt sql.NullTime

	err := r.pool.QueryRow(ctx, query, userID).Scan(
		&mfa.ID,
		&mfa.UserID,
		&secret,
		&mfa.TOTPEnabled,
		&verifiedAt,
		&mfa.CreatedAt,
		&mfa.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get MFA record: %w", err)
	}

	mfa.TOTPSecret = secret.String
	if verifiedAt.Valid {
		mfa.TOTPVerifiedAt = &verifiedAt.Time
	}

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
	if len(codeHashes) == 0 || len(codeHashes) > mfaMaxRecoveryCodes {
		return fmt.Errorf("invalid number of recovery codes: must be 1-%d", mfaMaxRecoveryCodes)
	}
	for _, hash := range codeHashes {
		if len(hash) == 0 || len(hash) > mfaMaxCodeHashLen {
			return fmt.Errorf("invalid code hash length")
		}
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Delete existing codes
	if _, err := tx.Exec(ctx, "DELETE FROM user_mfa_recovery_codes WHERE user_id = $1", userID); err != nil {
		return fmt.Errorf("failed to delete existing codes: %w", err)
	}

	// Insert new codes using batch
	batch := &pgx.Batch{}
	for _, hash := range codeHashes {
		batch.Queue(`
			INSERT INTO user_mfa_recovery_codes (user_id, code_hash, created_at)
			VALUES ($1, $2, CURRENT_TIMESTAMP)`,
			userID, hash,
		)
	}

	results := tx.SendBatch(ctx, batch)
	for range codeHashes {
		if _, err := results.Exec(); err != nil {
			results.Close()
			return fmt.Errorf("failed to insert recovery code: %w", err)
		}
	}
	results.Close()

	return tx.Commit(ctx)
}

// UseRecoveryCode attempts to use a recovery code.
func (r *MFARepository) UseRecoveryCode(ctx context.Context, userID int64, code string) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}
	if len(code) == 0 {
		return repository.ErrInvalidRecoveryCode
	}

	// Get all unused codes for the user
	rows, err := r.pool.Query(ctx,
		"SELECT id, code_hash FROM user_mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
		userID,
	)
	if err != nil {
		return fmt.Errorf("failed to query recovery codes: %w", err)
	}
	defer rows.Close()

	// Check each code hash
	for rows.Next() {
		var id int64
		var hash string
		if err := rows.Scan(&id, &hash); err != nil {
			return fmt.Errorf("failed to scan recovery code: %w", err)
		}

		// Compare using bcrypt
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(code)); err == nil {
			// Match found - mark as used
			_, err := r.pool.Exec(ctx,
				"UPDATE user_mfa_recovery_codes SET used_at = CURRENT_TIMESTAMP WHERE id = $1",
				id,
			)
			if err != nil {
				return fmt.Errorf("failed to mark code as used: %w", err)
			}
			return nil
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating recovery codes: %w", err)
	}

	return repository.ErrInvalidRecoveryCode
}

// GetRecoveryCodeCount returns the count of remaining (unused) recovery codes.
func (r *MFARepository) GetRecoveryCodeCount(ctx context.Context, userID int64) (int, error) {
	if userID <= 0 {
		return 0, fmt.Errorf("invalid user ID")
	}

	var count int
	err := r.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM user_mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
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

	_, err := r.pool.Exec(ctx, "DELETE FROM user_mfa_recovery_codes WHERE user_id = $1", userID)
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
	if len(cred.Name) == 0 || len(cred.Name) > mfaMaxNameLen {
		return nil, fmt.Errorf("invalid credential name length")
	}
	if len(cred.CredentialID) == 0 || len(cred.CredentialID) > mfaMaxCredentialIDLen {
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
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CURRENT_TIMESTAMP)
		RETURNING id, created_at`

	err := r.pool.QueryRow(ctx, query,
		cred.UserID, cred.Name, cred.CredentialID, cred.PublicKey, cred.AAGUID,
		cred.SignCount, transports, cred.UserVerified, cred.BackupEligible,
		cred.BackupState, cred.AttestationType,
	).Scan(&cred.ID, &cred.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn credential: %w", err)
	}

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
		WHERE user_id = $1
		ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query WebAuthn credentials: %w", err)
	}
	defer rows.Close()

	var credentials []repository.WebAuthnCredential
	for rows.Next() {
		var cred repository.WebAuthnCredential
		var transports, aaguid, attestationType sql.NullString
		var lastUsedAt sql.NullTime

		err := rows.Scan(
			&cred.ID, &cred.UserID, &cred.Name, &cred.CredentialID, &cred.PublicKey,
			&aaguid, &cred.SignCount, &transports, &cred.UserVerified,
			&cred.BackupEligible, &cred.BackupState, &attestationType, &cred.CreatedAt, &lastUsedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan WebAuthn credential: %w", err)
		}

		cred.AAGUID = aaguid.String
		cred.AttestationType = attestationType.String
		if transports.Valid && transports.String != "" {
			cred.Transports = strings.Split(transports.String, ",")
		}
		if lastUsedAt.Valid {
			cred.LastUsedAt = &lastUsedAt.Time
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
		WHERE id = $1 AND user_id = $2`

	var cred repository.WebAuthnCredential
	var transports, aaguid, attestationType sql.NullString
	var lastUsedAt sql.NullTime

	err := r.pool.QueryRow(ctx, query, credentialID, userID).Scan(
		&cred.ID, &cred.UserID, &cred.Name, &cred.CredentialID, &cred.PublicKey,
		&aaguid, &cred.SignCount, &transports, &cred.UserVerified,
		&cred.BackupEligible, &cred.BackupState, &attestationType, &cred.CreatedAt, &lastUsedAt,
	)

	if err == pgx.ErrNoRows {
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
	if lastUsedAt.Valid {
		cred.LastUsedAt = &lastUsedAt.Time
	}

	return &cred, nil
}

// GetWebAuthnCredentialByCredentialID retrieves a credential by its credential ID.
func (r *MFARepository) GetWebAuthnCredentialByCredentialID(ctx context.Context, credentialID string) (*repository.WebAuthnCredential, error) {
	if len(credentialID) == 0 || len(credentialID) > mfaMaxCredentialIDLen {
		return nil, fmt.Errorf("invalid credential ID")
	}

	query := `
		SELECT id, user_id, name, credential_id, public_key, aaguid, sign_count, transports,
		       user_verified, backup_eligible, backup_state, attestation_type, created_at, last_used_at
		FROM user_webauthn_credentials
		WHERE credential_id = $1`

	var cred repository.WebAuthnCredential
	var transports, aaguid, attestationType sql.NullString
	var lastUsedAt sql.NullTime

	err := r.pool.QueryRow(ctx, query, credentialID).Scan(
		&cred.ID, &cred.UserID, &cred.Name, &cred.CredentialID, &cred.PublicKey,
		&aaguid, &cred.SignCount, &transports, &cred.UserVerified,
		&cred.BackupEligible, &cred.BackupState, &attestationType, &cred.CreatedAt, &lastUsedAt,
	)

	if err == pgx.ErrNoRows {
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
	if lastUsedAt.Valid {
		cred.LastUsedAt = &lastUsedAt.Time
	}

	return &cred, nil
}

// UpdateWebAuthnCredentialSignCount updates the sign count for a credential.
func (r *MFARepository) UpdateWebAuthnCredentialSignCount(ctx context.Context, credentialID int64, signCount uint32) error {
	if credentialID <= 0 {
		return fmt.Errorf("invalid credential ID")
	}

	result, err := r.pool.Exec(ctx,
		"UPDATE user_webauthn_credentials SET sign_count = $1, last_used_at = CURRENT_TIMESTAMP WHERE id = $2",
		signCount, credentialID,
	)
	if err != nil {
		return fmt.Errorf("failed to update sign count: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrWebAuthnCredentialNotFound
	}

	return nil
}

// UpdateWebAuthnCredentialName updates the user-friendly name of a credential.
func (r *MFARepository) UpdateWebAuthnCredentialName(ctx context.Context, credentialID int64, userID int64, name string) error {
	if credentialID <= 0 || userID <= 0 {
		return fmt.Errorf("invalid credential or user ID")
	}
	if len(name) == 0 || len(name) > mfaMaxNameLen {
		return fmt.Errorf("invalid name length")
	}

	result, err := r.pool.Exec(ctx,
		"UPDATE user_webauthn_credentials SET name = $1 WHERE id = $2 AND user_id = $3",
		name, credentialID, userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update credential name: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrWebAuthnCredentialNotFound
	}

	return nil
}

// DeleteWebAuthnCredential removes a WebAuthn credential.
func (r *MFARepository) DeleteWebAuthnCredential(ctx context.Context, credentialID int64, userID int64) error {
	if credentialID <= 0 || userID <= 0 {
		return fmt.Errorf("invalid credential or user ID")
	}

	result, err := r.pool.Exec(ctx,
		"DELETE FROM user_webauthn_credentials WHERE id = $1 AND user_id = $2",
		credentialID, userID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete WebAuthn credential: %w", err)
	}

	if result.RowsAffected() == 0 {
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
	err := r.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM user_webauthn_credentials WHERE user_id = $1",
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
	if len(challenge) == 0 || len(challenge) > mfaMaxChallengeLen {
		return nil, fmt.Errorf("invalid challenge length")
	}
	if challengeType != "registration" && challengeType != "authentication" && challengeType != "login_authentication" {
		return nil, fmt.Errorf("invalid challenge type: must be 'registration', 'authentication', or 'login_authentication'")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Delete any existing challenge of the same type for this user
	if _, err := tx.Exec(ctx,
		"DELETE FROM mfa_challenges WHERE user_id = $1 AND challenge_type = $2",
		userID, challengeType,
	); err != nil {
		return nil, fmt.Errorf("failed to delete existing challenge: %w", err)
	}

	// Insert new challenge
	var id int64
	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO mfa_challenges (user_id, challenge, challenge_type, expires_at, created_at)
		VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
		RETURNING id, created_at`,
		userID, challenge, challengeType, expiresAt,
	).Scan(&id, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create challenge: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &repository.MFAChallenge{
		ID:            id,
		UserID:        userID,
		Challenge:     challenge,
		ChallengeType: challengeType,
		ExpiresAt:     expiresAt,
		CreatedAt:     createdAt,
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
		WHERE user_id = $1 AND challenge_type = $2`

	var ch repository.MFAChallenge
	err := r.pool.QueryRow(ctx, query, userID, challengeType).Scan(
		&ch.ID, &ch.UserID, &ch.Challenge, &ch.ChallengeType, &ch.ExpiresAt, &ch.CreatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, repository.ErrChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get challenge: %w", err)
	}

	// Check if expired
	if time.Now().After(ch.ExpiresAt) {
		// Clean up expired challenge
		r.pool.Exec(ctx, "DELETE FROM mfa_challenges WHERE id = $1", ch.ID)
		return nil, repository.ErrChallengeExpired
	}

	return &ch, nil
}

// DeleteChallenge removes a challenge after use.
func (r *MFARepository) DeleteChallenge(ctx context.Context, userID int64, challengeType string) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}

	_, err := r.pool.Exec(ctx,
		"DELETE FROM mfa_challenges WHERE user_id = $1 AND challenge_type = $2",
		userID, challengeType,
	)
	if err != nil {
		return fmt.Errorf("failed to delete challenge: %w", err)
	}

	return nil
}

// CleanupExpiredChallenges removes all expired challenges.
func (r *MFARepository) CleanupExpiredChallenges(ctx context.Context) (int64, error) {
	result, err := r.pool.Exec(ctx,
		"DELETE FROM mfa_challenges WHERE expires_at < CURRENT_TIMESTAMP",
	)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired challenges: %w", err)
	}

	return result.RowsAffected(), nil
}

// ===========================================================================
// Admin Operations
// ===========================================================================

// AdminDisableMFA disables all MFA methods for a user (admin operation).
func (r *MFARepository) AdminDisableMFA(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Delete recovery codes
	if _, err := tx.Exec(ctx, "DELETE FROM user_mfa_recovery_codes WHERE user_id = $1", userID); err != nil {
		return fmt.Errorf("failed to delete recovery codes: %w", err)
	}

	// Delete WebAuthn credentials
	if _, err := tx.Exec(ctx, "DELETE FROM user_webauthn_credentials WHERE user_id = $1", userID); err != nil {
		return fmt.Errorf("failed to delete WebAuthn credentials: %w", err)
	}

	// Delete challenges
	if _, err := tx.Exec(ctx, "DELETE FROM mfa_challenges WHERE user_id = $1", userID); err != nil {
		return fmt.Errorf("failed to delete MFA challenges: %w", err)
	}

	// Clear TOTP settings (or delete the record entirely)
	if _, err := tx.Exec(ctx, "DELETE FROM user_mfa WHERE user_id = $1", userID); err != nil {
		return fmt.Errorf("failed to delete MFA record: %w", err)
	}

	return tx.Commit(ctx)
}

// AdminGetMFAStatus retrieves MFA status for any user (admin operation).
func (r *MFARepository) AdminGetMFAStatus(ctx context.Context, userID int64) (*repository.MFAStatus, error) {
	// Same as GetMFAStatus - admin can view any user's status
	return r.GetMFAStatus(ctx, userID)
}
