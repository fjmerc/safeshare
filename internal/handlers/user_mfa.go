package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// totpVerificationMinTime is the minimum time for TOTP verification operations
// to prevent timing attacks. All TOTP validation attempts take at least this long.
const totpVerificationMinTime = 100 * time.Millisecond

// MFA-related request/response types

// TOTPSetupResponse is returned when setting up TOTP
type TOTPSetupResponse struct {
	Secret string `json:"secret"`  // Base32-encoded secret for manual entry
	URL    string `json:"url"`     // otpauth:// URL for QR code generation
	Issuer string `json:"issuer"`  // Issuer name (e.g., "SafeShare")
}

// TOTPVerifyRequest is the request body for verifying TOTP setup
type TOTPVerifyRequest struct {
	Code string `json:"code"` // 6-digit TOTP code
}

// TOTPVerifyResponse is returned after successful TOTP verification
type TOTPVerifyResponse struct {
	Success       bool     `json:"success"`
	RecoveryCodes []string `json:"recovery_codes"` // Plaintext codes for user to save
}

// TOTPDisableRequest is the request body for disabling TOTP
type TOTPDisableRequest struct {
	Code string `json:"code"` // Current valid TOTP code
}

// MFAStatusResponse represents the MFA status for a user
type MFAStatusResponse struct {
	Enabled                bool   `json:"enabled"`                   // Whether MFA feature is enabled globally
	TOTPEnabled            bool   `json:"totp_enabled"`              // Whether user has TOTP enabled
	TOTPVerifiedAt         string `json:"totp_verified_at,omitempty"` // When TOTP was verified
	WebAuthnEnabled        bool   `json:"webauthn_enabled"`          // Whether user has WebAuthn enabled
	WebAuthnCredentials    int    `json:"webauthn_credentials"`      // Number of WebAuthn credentials
	RecoveryCodesRemaining int    `json:"recovery_codes_remaining"`  // Remaining unused recovery codes
}

// MFATOTPSetupHandler handles POST /api/user/mfa/totp/setup
// Generates a new TOTP secret and returns QR code URL
func MFATOTPSetupHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		clientIP := getClientIP(r)

		// Check if MFA feature is enabled
		if cfg.MFA == nil || !cfg.MFA.Enabled {
			slog.Warn("TOTP setup attempted but MFA is disabled",
				"user_id", user.ID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "MFA is not enabled on this server",
			})
			return
		}

		// Check if TOTP method is enabled
		if !cfg.MFA.TOTPEnabled {
			slog.Warn("TOTP setup attempted but TOTP method is disabled",
				"user_id", user.ID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "TOTP authentication is not enabled on this server",
			})
			return
		}

		// Check if TOTP is already enabled for this user
		enabled, err := repos.MFA.IsTOTPEnabled(ctx, user.ID)
		if err != nil {
			slog.Error("failed to check TOTP status",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if enabled {
			slog.Warn("TOTP setup attempted but already enabled",
				"user_id", user.ID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "TOTP is already enabled for your account",
			})
			return
		}

		// Generate TOTP key
		accountName := user.Email
		if accountName == "" {
			accountName = user.Username
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      cfg.MFA.Issuer,
			AccountName: accountName,
		})
		if err != nil {
			slog.Error("failed to generate TOTP key",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get the base32 secret
		secret := key.Secret()

		// Encrypt secret if encryption is enabled
		var secretToStore string
		if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
			// Encrypt the secret
			encrypted, err := utils.EncryptFile([]byte(secret), cfg.EncryptionKey)
			if err != nil {
				slog.Error("failed to encrypt TOTP secret",
					"error", err,
					"user_id", user.ID,
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			// Store as base64-encoded encrypted data
			secretToStore = base64.StdEncoding.EncodeToString(encrypted)
		} else {
			// Store plaintext (not recommended for production)
			secretToStore = secret
		}

		// Store the TOTP setup (not yet verified)
		if err := repos.MFA.SetupTOTP(ctx, user.ID, secretToStore); err != nil {
			if err == repository.ErrMFAAlreadyEnabled {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "TOTP is already enabled for your account",
				})
				return
			}
			slog.Error("failed to store TOTP setup",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("TOTP setup initiated",
			"user_id", user.ID,
			"username", user.Username,
			"ip", clientIP,
		)

		// Return the setup information
		response := TOTPSetupResponse{
			Secret: secret,          // Base32 secret for manual entry
			URL:    key.URL(),       // otpauth:// URL for QR code
			Issuer: cfg.MFA.Issuer,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// MFATOTPVerifyHandler handles POST /api/user/mfa/totp/verify
// Verifies the TOTP code and enables TOTP for the user
func MFATOTPVerifyHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		clientIP := getClientIP(r)

		// Parse request body
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit
		var req TOTPVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate code format (exactly 6 digits)
		if !isValidTOTPCode(req.Code) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "TOTP code must be exactly 6 digits",
			})
			return
		}

		// Check if MFA is enabled
		if cfg.MFA == nil || !cfg.MFA.Enabled || !cfg.MFA.TOTPEnabled {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "TOTP is not enabled on this server",
			})
			return
		}

		// Check if TOTP is already enabled
		enabled, err := repos.MFA.IsTOTPEnabled(ctx, user.ID)
		if err != nil {
			slog.Error("failed to check TOTP status",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if enabled {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "TOTP is already enabled for your account",
			})
			return
		}

		// Get the stored TOTP secret
		storedSecret, err := repos.MFA.GetTOTPSecret(ctx, user.ID)
		if err != nil {
			slog.Error("failed to get TOTP secret",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if storedSecret == "" {
			slog.Warn("TOTP verification attempted without setup",
				"user_id", user.ID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "TOTP has not been set up. Please initiate setup first.",
			})
			return
		}

		// Decrypt secret if encryption is enabled
		var secret string
		if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
			// Decode from base64
			encrypted, err := base64.StdEncoding.DecodeString(storedSecret)
			if err != nil {
				slog.Error("failed to decode TOTP secret",
					"error", err,
					"user_id", user.ID,
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			// Decrypt
			decrypted, err := utils.DecryptFile(encrypted, cfg.EncryptionKey)
			if err != nil {
				slog.Error("failed to decrypt TOTP secret",
					"error", err,
					"user_id", user.ID,
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			secret = string(decrypted)
		} else {
			secret = storedSecret
		}

		// Validate the TOTP code with timing attack protection
		validationStart := time.Now()
		valid := totp.Validate(req.Code, secret)
		
		// Ensure minimum time to prevent timing attacks
		elapsed := time.Since(validationStart)
		if elapsed < totpVerificationMinTime {
			time.Sleep(totpVerificationMinTime - elapsed)
		}
		
		if !valid {
			slog.Warn("TOTP verification failed - invalid code",
				"user_id", user.ID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid TOTP code",
			})
			return
		}

		// Enable TOTP for the user
		if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
			slog.Error("failed to enable TOTP",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Generate recovery codes
		recoveryCodes, codeHashes, err := generateRecoveryCodes(cfg.MFA.RecoveryCodesCount)
		if err != nil {
			slog.Error("failed to generate recovery codes",
				"error", err,
				"user_id", user.ID,
			)
			// TOTP is enabled but recovery codes failed - log but don't fail
			slog.Warn("TOTP enabled without recovery codes due to generation failure",
				"user_id", user.ID,
			)
		} else {
			// Store recovery code hashes
			if err := repos.MFA.CreateRecoveryCodes(ctx, user.ID, codeHashes); err != nil {
				slog.Error("failed to store recovery codes",
					"error", err,
					"user_id", user.ID,
				)
				// TOTP is enabled but recovery codes failed
				slog.Warn("TOTP enabled without recovery codes due to storage failure",
					"user_id", user.ID,
				)
				recoveryCodes = nil // Don't return codes if storage failed
			}
		}

		slog.Info("TOTP enabled successfully",
			"user_id", user.ID,
			"username", user.Username,
			"ip", clientIP,
			"recovery_codes_generated", len(recoveryCodes),
		)

		response := TOTPVerifyResponse{
			Success:       true,
			RecoveryCodes: recoveryCodes,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// MFATOTPDisableHandler handles DELETE /api/user/mfa/totp
// Disables TOTP for the user (requires current valid code)
func MFATOTPDisableHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		clientIP := getClientIP(r)

		// Parse request body
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit
		var req TOTPDisableRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate code format (exactly 6 digits)
		if !isValidTOTPCode(req.Code) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "TOTP code must be exactly 6 digits",
			})
			return
		}

		// Check if TOTP is enabled
		enabled, err := repos.MFA.IsTOTPEnabled(ctx, user.ID)
		if err != nil {
			slog.Error("failed to check TOTP status",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if !enabled {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "TOTP is not enabled for your account",
			})
			return
		}

		// Get the stored TOTP secret
		storedSecret, err := repos.MFA.GetTOTPSecret(ctx, user.ID)
		if err != nil {
			slog.Error("failed to get TOTP secret",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Decrypt secret if encryption is enabled
		var secret string
		if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
			encrypted, err := base64.StdEncoding.DecodeString(storedSecret)
			if err != nil {
				slog.Error("failed to decode TOTP secret",
					"error", err,
					"user_id", user.ID,
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			decrypted, err := utils.DecryptFile(encrypted, cfg.EncryptionKey)
			if err != nil {
				slog.Error("failed to decrypt TOTP secret",
					"error", err,
					"user_id", user.ID,
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			secret = string(decrypted)
		} else {
			secret = storedSecret
		}

		// Validate the TOTP code with timing attack protection
		validationStart := time.Now()
		valid := totp.Validate(req.Code, secret)
		
		// Ensure minimum time to prevent timing attacks
		elapsed := time.Since(validationStart)
		if elapsed < totpVerificationMinTime {
			time.Sleep(totpVerificationMinTime - elapsed)
		}
		
		if !valid {
			slog.Warn("TOTP disable failed - invalid code",
				"user_id", user.ID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid TOTP code",
			})
			return
		}

		// Disable TOTP (this also deletes recovery codes)
		if err := repos.MFA.DisableTOTP(ctx, user.ID); err != nil {
			slog.Error("failed to disable TOTP",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("TOTP disabled successfully",
			"user_id", user.ID,
			"username", user.Username,
			"ip", clientIP,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "TOTP has been disabled",
		})
	}
}

// MFAStatusHandler handles GET /api/user/mfa/status
// Returns the MFA status for the current user
func MFAStatusHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if MFA feature is enabled globally
		mfaEnabled := cfg.MFA != nil && cfg.MFA.Enabled

		// Get MFA status from repository
		status, err := repos.MFA.GetMFAStatus(ctx, user.ID)
		if err != nil {
			slog.Error("failed to get MFA status",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := MFAStatusResponse{
			Enabled:                mfaEnabled,
			TOTPEnabled:            status.TOTPEnabled,
			TOTPVerifiedAt:         status.TOTPVerifiedAt,
			WebAuthnEnabled:        status.WebAuthnEnabled,
			WebAuthnCredentials:    status.WebAuthnCredentials,
			RecoveryCodesRemaining: status.RecoveryCodesRemaining,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// generateRecoveryCodes generates a set of recovery codes and their bcrypt hashes
// Returns: plaintext codes (for user), hashed codes (for storage), error
func generateRecoveryCodes(count int) ([]string, []string, error) {
	if count <= 0 {
		count = 10 // Default
	}

	codes := make([]string, count)
	hashes := make([]string, count)

	for i := 0; i < count; i++ {
		// Generate 16 random bytes (128 bits of entropy)
		randomBytes := make([]byte, 16)
		if _, err := rand.Read(randomBytes); err != nil {
			return nil, nil, err
		}

		// Format as hex string (32 characters)
		// Then format as XXXX-XXXX-XXXX-XXXX for readability
		hexCode := hex.EncodeToString(randomBytes)
		code := formatRecoveryCode(hexCode[:16]) // Use first 16 hex chars

		codes[i] = code

		// Hash the code (use a reasonable cost for bcrypt)
		// Note: We hash the formatted code, not the raw hex
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, err
		}
		hashes[i] = string(hash)
	}

	return codes, hashes, nil
}

// formatRecoveryCode formats a hex string as XXXX-XXXX-XXXX-XXXX
func formatRecoveryCode(hex string) string {
	if len(hex) < 16 {
		return hex
	}
	return hex[0:4] + "-" + hex[4:8] + "-" + hex[8:12] + "-" + hex[12:16]
}

// isValidTOTPCode validates that a TOTP code is exactly 6 numeric digits
func isValidTOTPCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
