package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webauthn"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// MFA login flow constants
const (
	// mfaChallengeExpiryMinutes is how long an MFA challenge is valid
	mfaChallengeExpiryMinutes = 5

	// mfaLoginVerificationMinTime prevents timing attacks on MFA verification
	// This covers ALL operations in the verification path
	mfaLoginVerificationMinTime = 200 * time.Millisecond

	// mfaMaxVerifyAttempts limits brute force attacks
	mfaMaxVerifyAttempts = 5

	// maxTotalChallenges prevents memory exhaustion (DoS protection)
	maxTotalChallenges = 10000

	// maxChallengesPerIP prevents single-IP DoS attacks
	maxChallengesPerIP = 10
)

// ErrTooManyChallenges is returned when the challenge store is at capacity
var ErrTooManyChallenges = errors.New("too many pending MFA challenges")

// MFALoginChallenge represents a pending MFA login challenge
type MFALoginChallenge struct {
	UserID      int64
	ChallengeID string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Attempts    int
	ClientIP    string
	UserAgent   string
}

// MFALoginStore provides thread-safe storage for pending MFA challenges
// In production, this should use Redis or database for multi-instance support
type MFALoginStore struct {
	mu         sync.Mutex // Use exclusive lock to prevent TOCTOU races
	challenges map[string]*MFALoginChallenge
}

// Global MFA challenge store (initialized in init)
var mfaLoginStore *MFALoginStore

func init() {
	mfaLoginStore = &MFALoginStore{
		challenges: make(map[string]*MFALoginChallenge),
	}
	// Start cleanup goroutine
	go mfaLoginStore.cleanupLoop()
}

// cleanupLoop periodically removes expired challenges
func (s *MFALoginStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.cleanup()
	}
}

// cleanup removes expired challenges
func (s *MFALoginStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, challenge := range s.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(s.challenges, id)
		}
	}
}

// Create creates a new MFA challenge and returns the challenge ID
// Returns ErrTooManyChallenges if limits are exceeded
func (s *MFALoginStore) Create(userID int64, clientIP, userAgent string, expiryMinutes int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check total limit to prevent memory exhaustion
	if len(s.challenges) >= maxTotalChallenges {
		return "", ErrTooManyChallenges
	}

	// Count challenges from this IP to prevent single-source DoS
	ipCount := 0
	for _, c := range s.challenges {
		if c.ClientIP == clientIP {
			ipCount++
		}
	}
	if ipCount >= maxChallengesPerIP {
		return "", ErrTooManyChallenges
	}

	// Generate a secure challenge ID
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	challengeID := hex.EncodeToString(idBytes)

	now := time.Now()
	challenge := &MFALoginChallenge{
		UserID:      userID,
		ChallengeID: challengeID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Duration(expiryMinutes) * time.Minute),
		Attempts:    0,
		ClientIP:    clientIP,
		UserAgent:   userAgent,
	}

	s.challenges[challengeID] = challenge

	return challengeID, nil
}

// Get retrieves a challenge by ID and validates it
// Uses exclusive lock to prevent TOCTOU race conditions
func (s *MFALoginStore) Get(challengeID string) (*MFALoginChallenge, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	challenge, exists := s.challenges[challengeID]
	if !exists {
		return nil, false
	}

	// Check expiry under the same lock
	if time.Now().After(challenge.ExpiresAt) {
		delete(s.challenges, challengeID)
		return nil, false
	}

	return challenge, true
}

// GetAndValidateIP retrieves a challenge and validates the client IP
// Returns (challenge, valid, ipMismatch) where:
// - valid indicates if the challenge exists and is not expired
// - ipMismatch indicates if the challenge exists but IP doesn't match
func (s *MFALoginStore) GetAndValidateIP(challengeID, clientIP string) (*MFALoginChallenge, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	challenge, exists := s.challenges[challengeID]
	if !exists {
		return nil, false, false
	}

	// Check expiry under the same lock
	if time.Now().After(challenge.ExpiresAt) {
		delete(s.challenges, challengeID)
		return nil, false, false
	}

	// Check IP binding
	if challenge.ClientIP != clientIP {
		return challenge, true, true // exists, valid, but IP mismatch
	}

	return challenge, true, false
}

// IncrementAttempts increments the attempt counter and returns true if still valid
func (s *MFALoginStore) IncrementAttempts(challengeID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	challenge, exists := s.challenges[challengeID]
	if !exists {
		return false
	}

	challenge.Attempts++
	return challenge.Attempts <= mfaMaxVerifyAttempts
}

// Delete removes a challenge
func (s *MFALoginStore) Delete(challengeID string) {
	s.mu.Lock()
	delete(s.challenges, challengeID)
	s.mu.Unlock()
}

// MFALoginResponse is the response when MFA is required
type MFALoginResponse struct {
	MFARequired      bool     `json:"mfa_required"`
	ChallengeID      string   `json:"challenge_id"`
	ChallengeType    string   `json:"challenge_type,omitempty"`    // Deprecated: use available_methods
	AvailableMethods []string `json:"available_methods,omitempty"` // ["totp", "webauthn", "recovery"]
	ExpiresIn        int      `json:"expires_in"`                  // Seconds until challenge expires
	Message          string   `json:"message"`
}

// MFAVerifyLoginRequest is the request body for MFA login verification
type MFAVerifyLoginRequest struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`        // TOTP code or recovery code
	IsRecovery  bool   `json:"is_recovery"` // If true, code is a recovery code
}

// UserLoginWithMFAHandler handles user login with MFA support
// This is a replacement for the regular login handler when MFA is enabled
func UserLoginWithMFAHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Parse JSON request
		var req models.UserLoginRequest
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error("failed to parse login request", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		clientIP := getClientIP(r)
		userAgent := getUserAgent(r)

		// Validate input
		if req.Username == "" || req.Password == "" {
			slog.Warn("user login failed - empty username or password",
				"username", req.Username,
				"ip", clientIP,
			)
			time.Sleep(500 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid username or password",
			})
			return
		}

		// Get user from repository
		user, err := repos.Users.GetByUsername(ctx, req.Username)
		if err != nil {
			slog.Error("failed to get user", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Check if user exists and password matches
		if user == nil || !utils.VerifyPassword(user.PasswordHash, req.Password) {
			slog.Warn("user login failed - invalid credentials",
				"username", req.Username,
				"ip", clientIP,
			)
			time.Sleep(500 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid username or password",
			})
			return
		}

		// Check if user is active - use same error message to prevent enumeration
		if !user.IsActive {
			slog.Warn("user login failed - account disabled",
				"username", req.Username,
				"ip", clientIP,
			)
			time.Sleep(500 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized) // Use 401, not 403 to prevent enumeration
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid username or password", // Same message as invalid credentials
			})
			return
		}

		// Check if MFA is enabled for this user
		mfaEnabled := false
		var availableMethods []string
		if cfg.MFA != nil && cfg.MFA.Enabled {
			// Check if user has TOTP enabled
			totpEnabled, err := repos.MFA.IsTOTPEnabled(ctx, user.ID)
			if err != nil {
				slog.Error("failed to check TOTP status", "error", err, "user_id", user.ID)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			// Check if user has WebAuthn credentials
			hasWebAuthn := false
			if cfg.MFA.WebAuthnEnabled {
				webauthnCreds, err := repos.MFA.GetWebAuthnCredentials(ctx, user.ID)
				if err != nil {
					slog.Error("failed to check WebAuthn credentials", "error", err, "user_id", user.ID)
					// Continue without WebAuthn - don't fail login
				} else {
					hasWebAuthn = len(webauthnCreds) > 0
				}
			}

			// Build available methods list
			if totpEnabled {
				availableMethods = append(availableMethods, "totp")
			}
			if hasWebAuthn {
				availableMethods = append(availableMethods, "webauthn")
			}

			// MFA is enabled if user has at least one method set up
			mfaEnabled = len(availableMethods) > 0

			// Recovery codes are always available if MFA is enabled
			if mfaEnabled {
				availableMethods = append(availableMethods, "recovery")
			}

			// Also check if MFA is required but user hasn't set it up
			if cfg.MFA.Required && !mfaEnabled {
				// User must set up MFA first - we'll create the session but flag this
				// The frontend can then prompt them to set up MFA
				slog.Info("user login - MFA required but not configured",
					"username", req.Username,
					"user_id", user.ID,
					"ip", clientIP,
				)
			}
		}

		if mfaEnabled {
			// MFA is required - create a challenge instead of a full session
			expiryMinutes := mfaChallengeExpiryMinutes
			if cfg.MFA.ChallengeExpiryMinutes > 0 {
				expiryMinutes = cfg.MFA.ChallengeExpiryMinutes
			}

			challengeID, err := mfaLoginStore.Create(user.ID, clientIP, userAgent, expiryMinutes)
			if err != nil {
				if err == ErrTooManyChallenges {
					slog.Warn("MFA challenge creation rate limited",
						"user_id", user.ID,
						"ip", clientIP,
					)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					json.NewEncoder(w).Encode(map[string]string{
						"error": "Too many login attempts. Please try again later.",
					})
					return
				}
				slog.Error("failed to create MFA challenge", "error", err, "user_id", user.ID)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			slog.Info("MFA challenge created for login",
				"username", req.Username,
				"user_id", user.ID,
				"available_methods", availableMethods,
				"ip", clientIP,
			)

			// Determine primary challenge type for backward compatibility
			challengeType := "totp"
			if len(availableMethods) > 0 && availableMethods[0] == "webauthn" {
				challengeType = "webauthn"
			}

			response := MFALoginResponse{
				MFARequired:      true,
				ChallengeID:      challengeID,
				ChallengeType:    challengeType,
				AvailableMethods: availableMethods,
				ExpiresIn:        expiryMinutes * 60,
				Message:          "Please verify your identity to complete login",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		// No MFA required - complete the login normally
		completeLogin(w, r, repos, cfg, user, clientIP, userAgent)
	}
}

// MFAVerifyLoginHandler handles MFA verification during login
func MFAVerifyLoginHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Start timing for constant-time responses (covers ALL operations)
		startTime := time.Now()
		defer func() {
			elapsed := time.Since(startTime)
			if elapsed < mfaLoginVerificationMinTime {
				time.Sleep(mfaLoginVerificationMinTime - elapsed)
			}
		}()

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Parse request body
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit
		var req MFAVerifyLoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		clientIP := getClientIP(r)

		// Validate challenge ID
		if req.ChallengeID == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Challenge ID is required",
			})
			return
		}

		// Validate code format
		if !req.IsRecovery && !isValidTOTPCode(req.Code) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "TOTP code must be exactly 6 digits",
			})
			return
		}

		// Recovery code format validation (XXXX-XXXX-XXXX-XXXX)
		if req.IsRecovery && !isValidRecoveryCodeFormat(req.Code) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid recovery code format",
			})
			return
		}

		// Get and validate the challenge with IP binding
		challenge, exists, ipMismatch := mfaLoginStore.GetAndValidateIP(req.ChallengeID, clientIP)
		if !exists {
			slog.Warn("MFA login verification failed - invalid or expired challenge",
				"challenge_id", req.ChallengeID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "MFA challenge has expired. Please log in again.",
			})
			return
		}

		// Check IP binding - reject if IP changed
		if ipMismatch {
			slog.Warn("MFA verification from different IP",
				"challenge_id", req.ChallengeID,
				"original_ip", challenge.ClientIP,
				"request_ip", clientIP,
				"user_id", challenge.UserID,
			)
			// Delete the challenge to prevent further attempts
			mfaLoginStore.Delete(req.ChallengeID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Session validation failed. Please log in again.",
			})
			return
		}

		// Check if too many attempts
		if !mfaLoginStore.IncrementAttempts(req.ChallengeID) {
			mfaLoginStore.Delete(req.ChallengeID)
			slog.Warn("MFA login verification failed - too many attempts",
				"challenge_id", req.ChallengeID,
				"user_id", challenge.UserID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Too many failed attempts. Please log in again.",
			})
			return
		}

		// Get user from database
		user, err := repos.Users.GetByID(ctx, challenge.UserID)
		if err != nil || user == nil {
			slog.Error("failed to get user for MFA verification", "error", err, "user_id", challenge.UserID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Verify the code
		var valid bool

		if req.IsRecovery {
			// Use recovery code
			err := repos.MFA.UseRecoveryCode(ctx, user.ID, req.Code)
			if err != nil {
				if err == repository.ErrInvalidRecoveryCode {
					valid = false
				} else {
					slog.Error("failed to verify recovery code", "error", err, "user_id", user.ID)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}
			} else {
				valid = true
				slog.Info("recovery code used for login",
					"user_id", user.ID,
					"ip", clientIP,
				)
			}
		} else {
			// Verify TOTP
			storedSecret, err := repos.MFA.GetTOTPSecret(ctx, user.ID)
			if err != nil {
				slog.Error("failed to get TOTP secret", "error", err, "user_id", user.ID)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			// Decrypt if needed
			var secret string
			if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
				encrypted, err := base64.StdEncoding.DecodeString(storedSecret)
				if err != nil {
					slog.Error("failed to decode TOTP secret", "error", err, "user_id", user.ID)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}
				decrypted, err := utils.DecryptFile(encrypted, cfg.EncryptionKey)
				if err != nil {
					slog.Error("failed to decrypt TOTP secret", "error", err, "user_id", user.ID)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}
				secret = string(decrypted)
			} else {
				secret = storedSecret
			}

			valid = totp.Validate(req.Code, secret)
		}

		if !valid {
			codeType := "TOTP"
			if req.IsRecovery {
				codeType = "recovery"
			}
			slog.Warn("MFA login verification failed - invalid code",
				"challenge_id", req.ChallengeID,
				"user_id", challenge.UserID,
				"code_type", codeType,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid code",
			})
			return
		}

		// MFA verified - delete the challenge and complete login
		mfaLoginStore.Delete(req.ChallengeID)

		slog.Info("MFA login verification successful",
			"user_id", user.ID,
			"username", user.Username,
			"is_recovery", req.IsRecovery,
			"ip", clientIP,
		)

		// Complete the login
		completeLogin(w, r, repos, cfg, user, challenge.ClientIP, challenge.UserAgent)
	}
}

// completeLogin creates the session and returns the login response
func completeLogin(w http.ResponseWriter, r *http.Request, repos *repository.Repositories, cfg *config.Config, user *models.User, clientIP, userAgent string) {
	ctx := r.Context()

	// Generate session token
	sessionToken, err := utils.GenerateSessionToken()
	if err != nil {
		slog.Error("failed to generate session token", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Calculate expiry time
	expiresAt := time.Now().Add(time.Duration(cfg.SessionExpiryHours) * time.Hour)

	// Store session in repository
	err = repos.Users.CreateSession(ctx, user.ID, sessionToken, expiresAt, clientIP, userAgent)
	if err != nil {
		slog.Error("failed to create user session", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Update last login timestamp
	if err := repos.Users.UpdateLastLogin(ctx, user.ID); err != nil {
		slog.Error("failed to update last login", "error", err)
		// Don't fail the request, just log
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "user_session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.HTTPSEnabled,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiresAt,
	})

	// Set user CSRF cookie for MFA and other protected user operations
	if _, err := setUserCSRFCookieForLogin(w, cfg); err != nil {
		slog.Error("failed to set user CSRF cookie", "error", err)
		// Continue anyway - not critical for login success
	}

	slog.Info("user login successful",
		"username", user.Username,
		"user_id", user.ID,
		"ip", clientIP,
	)

	// Check if MFA is required but not set up
	mfaSetupRequired := false
	if cfg.MFA != nil && cfg.MFA.Required {
		totpEnabled, err := repos.MFA.IsTOTPEnabled(ctx, user.ID)
		if err == nil && !totpEnabled {
			mfaSetupRequired = true
		}
	}

	// Return user info
	response := struct {
		models.UserLoginResponse
		MFASetupRequired bool `json:"mfa_setup_required,omitempty"`
	}{
		UserLoginResponse: models.UserLoginResponse{
			ID:                    user.ID,
			Username:              user.Username,
			Email:                 user.Email,
			Role:                  user.Role,
			RequirePasswordChange: user.RequirePasswordChange,
		},
		MFASetupRequired: mfaSetupRequired,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// setUserCSRFCookieForLogin sets the CSRF cookie for user login
// This is a local helper to avoid circular import with middleware package
func setUserCSRFCookieForLogin(w http.ResponseWriter, cfg *config.Config) (string, error) {
	token, err := utils.GenerateCSRFToken()
	if err != nil {
		return "", err
	}
	cookie := &http.Cookie{
		Name:     "user_csrf_token",
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   cfg.HTTPSEnabled,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	}
	http.SetCookie(w, cookie)
	return token, nil
}

// isValidRecoveryCodeFormat validates recovery code format (XXXX-XXXX-XXXX-XXXX)
func isValidRecoveryCodeFormat(code string) bool {
	if len(code) != 19 { // 16 hex chars + 3 dashes
		return false
	}
	// Check format: XXXX-XXXX-XXXX-XXXX
	for i, c := range code {
		if i == 4 || i == 9 || i == 14 {
			if c != '-' {
				return false
			}
		} else {
			// Must be hex digit (0-9, a-f)
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// VerifyRecoveryCodeHash checks if a plaintext code matches a bcrypt hash
func VerifyRecoveryCodeHash(code, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(code)) == nil
}

// ===========================================================================
// WebAuthn Login Flow Handlers
// ===========================================================================

// MFAWebAuthnLoginBeginRequest is the request body for starting WebAuthn login MFA
type MFAWebAuthnLoginBeginRequest struct {
	ChallengeID string `json:"challenge_id"`
}

// MFAWebAuthnLoginBeginResponse is returned when starting WebAuthn login MFA
type MFAWebAuthnLoginBeginResponse struct {
	Options         *protocol.CredentialAssertion `json:"options"`
	WebAuthnChallenge string                        `json:"webauthn_challenge"` // Base64-encoded WebAuthn challenge
}

// MFAWebAuthnLoginFinishRequest is the request body for completing WebAuthn login MFA
type MFAWebAuthnLoginFinishRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Credential  json.RawMessage `json:"credential"`
}

// MFAWebAuthnLoginBeginHandler handles POST /api/auth/mfa/webauthn/begin
// Starts the WebAuthn authentication ceremony during login
func MFAWebAuthnLoginBeginHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Parse request
		r.Body = http.MaxBytesReader(w, r.Body, 1024) // 1KB limit
		var req MFAWebAuthnLoginBeginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate challenge ID
		if req.ChallengeID == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Challenge ID is required",
			})
			return
		}

		// Check if WebAuthn is enabled
		if cfg.MFA == nil || !cfg.MFA.Enabled || !cfg.MFA.WebAuthnEnabled {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "WebAuthn is not enabled on this server",
			})
			return
		}

		// Get WebAuthn service (supports runtime reinitialization when MFA config changes)
		webauthnSvc := GetWebAuthnService()
		if webauthnSvc == nil {
			slog.Error("WebAuthn service not initialized for login",
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "WebAuthn is temporarily unavailable. Please contact your administrator.",
			})
			return
		}

		// Get and validate the MFA login challenge with IP binding
		challenge, exists, ipMismatch := mfaLoginStore.GetAndValidateIP(req.ChallengeID, clientIP)
		if !exists {
			slog.Warn("WebAuthn login begin failed - invalid or expired challenge",
				"challenge_id", req.ChallengeID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "MFA challenge has expired. Please log in again.",
			})
			return
		}

		// Check IP binding
		if ipMismatch {
			slog.Warn("WebAuthn login begin from different IP",
				"challenge_id", req.ChallengeID,
				"original_ip", challenge.ClientIP,
				"request_ip", clientIP,
				"user_id", challenge.UserID,
			)
			mfaLoginStore.Delete(req.ChallengeID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Session validation failed. Please log in again.",
			})
			return
		}

		// Get user's WebAuthn credentials
		existingCreds, err := repos.MFA.GetWebAuthnCredentials(ctx, challenge.UserID)
		if err != nil {
			slog.Error("failed to get WebAuthn credentials",
				"error", err,
				"user_id", challenge.UserID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if len(existingCreds) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "No WebAuthn credentials registered",
			})
			return
		}

		// Get user details
		user, err := repos.Users.GetByID(ctx, challenge.UserID)
		if err != nil || user == nil {
			slog.Error("failed to get user for WebAuthn login", "error", err, "user_id", challenge.UserID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Convert to gowebauthn.Credential format
		var credentials []gowebauthn.Credential
		for _, cred := range existingCreds {
			waCred, err := webauthn.CredentialToWebAuthn(&cred)
			if err != nil {
				slog.Warn("failed to convert credential",
					"error", err,
					"credential_id", cred.ID,
				)
				continue
			}
			credentials = append(credentials, *waCred)
		}

		// Create WebAuthn user
		waUser := &webauthn.WebAuthnUser{
			ID:          user.ID,
			Name:        user.Username,
			DisplayName: user.Username,
			Credentials: credentials,
		}

		// Begin WebAuthn authentication ceremony
		assertion, session, err := webauthnSvc.BeginLogin(waUser)
		if err != nil {
			slog.Error("failed to begin WebAuthn login authentication",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Store WebAuthn challenge in database (session.Challenge is already base64url encoded)
		expiresAt := time.Now().Add(time.Duration(cfg.MFA.ChallengeExpiryMinutes) * time.Minute)

		_, err = repos.MFA.CreateChallenge(ctx, user.ID, session.Challenge, "login_authentication", expiresAt)
		if err != nil {
			slog.Error("failed to store WebAuthn challenge",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("WebAuthn login authentication started",
			"user_id", user.ID,
			"username", user.Username,
			"ip", clientIP,
		)

		response := MFAWebAuthnLoginBeginResponse{
			Options:           assertion,
			WebAuthnChallenge: session.Challenge,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// MFAWebAuthnLoginFinishHandler handles POST /api/auth/mfa/webauthn/finish
// Completes the WebAuthn authentication ceremony during login
func MFAWebAuthnLoginFinishHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Apply timing attack protection
		startTime := time.Now()
		defer func() {
			elapsed := time.Since(startTime)
			if elapsed < mfaLoginVerificationMinTime {
				time.Sleep(mfaLoginVerificationMinTime - elapsed)
			}
		}()

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Parse request
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB limit
		var req MFAWebAuthnLoginFinishRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate challenge ID
		if req.ChallengeID == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Challenge ID is required",
			})
			return
		}

		// Check if WebAuthn is enabled
		if cfg.MFA == nil || !cfg.MFA.Enabled || !cfg.MFA.WebAuthnEnabled {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "WebAuthn is not enabled on this server",
			})
			return
		}

		// Get WebAuthn service (supports runtime reinitialization when MFA config changes)
		webauthnSvc := GetWebAuthnService()
		if webauthnSvc == nil {
			slog.Error("WebAuthn service not initialized for login finish",
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "WebAuthn is temporarily unavailable. Please contact your administrator.",
			})
			return
		}

		// Get and validate the MFA login challenge with IP binding
		challenge, exists, ipMismatch := mfaLoginStore.GetAndValidateIP(req.ChallengeID, clientIP)
		if !exists {
			slog.Warn("WebAuthn login finish failed - invalid or expired challenge",
				"challenge_id", req.ChallengeID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "MFA challenge has expired. Please log in again.",
			})
			return
		}

		// Check IP binding
		if ipMismatch {
			slog.Warn("WebAuthn login finish from different IP",
				"challenge_id", req.ChallengeID,
				"original_ip", challenge.ClientIP,
				"request_ip", clientIP,
				"user_id", challenge.UserID,
			)
			mfaLoginStore.Delete(req.ChallengeID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Session validation failed. Please log in again.",
			})
			return
		}

		// Check if too many attempts
		if !mfaLoginStore.IncrementAttempts(req.ChallengeID) {
			mfaLoginStore.Delete(req.ChallengeID)
			slog.Warn("WebAuthn login verification failed - too many attempts",
				"challenge_id", req.ChallengeID,
				"user_id", challenge.UserID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Too many failed attempts. Please log in again.",
			})
			return
		}

		// Get the stored WebAuthn challenge
		webAuthnChallenge, err := repos.MFA.GetChallenge(ctx, challenge.UserID, "login_authentication")
		if err != nil {
			if err == repository.ErrChallengeNotFound || err == repository.ErrChallengeExpired {
				slog.Warn("WebAuthn login finish failed - WebAuthn challenge not found or expired",
					"user_id", challenge.UserID,
					"ip", clientIP,
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "WebAuthn session expired. Please try again.",
				})
				return
			}
			slog.Error("failed to get WebAuthn challenge",
				"error", err,
				"user_id", challenge.UserID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get user details
		user, err := repos.Users.GetByID(ctx, challenge.UserID)
		if err != nil || user == nil {
			slog.Error("failed to get user for WebAuthn login", "error", err, "user_id", challenge.UserID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get user's WebAuthn credentials
		existingCreds, err := repos.MFA.GetWebAuthnCredentials(ctx, challenge.UserID)
		if err != nil {
			slog.Error("failed to get WebAuthn credentials",
				"error", err,
				"user_id", challenge.UserID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Convert to gowebauthn.Credential format
		var credentials []gowebauthn.Credential
		credentialMap := make(map[string]int64) // Map credential ID to database ID
		for _, cred := range existingCreds {
			waCred, err := webauthn.CredentialToWebAuthn(&cred)
			if err != nil {
				continue
			}
			credentials = append(credentials, *waCred)
			credentialMap[base64.StdEncoding.EncodeToString(waCred.ID)] = cred.ID
		}

		// Create WebAuthn user
		waUser := &webauthn.WebAuthnUser{
			ID:          user.ID,
			Name:        user.Username,
			DisplayName: user.Username,
			Credentials: credentials,
		}

		// Parse the credential assertion response
		parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(req.Credential)
		if err != nil {
			slog.Warn("failed to parse WebAuthn assertion response for login",
				"error", err,
				"user_id", user.ID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid authentication response",
			})
			return
		}

		// Create session data from stored challenge (already base64url encoded)
		sessionData := gowebauthn.SessionData{
			Challenge: webAuthnChallenge.Challenge,
			UserID:    waUser.WebAuthnID(),
		}

		// Finish WebAuthn authentication
		validatedCredential, err := webauthnSvc.FinishLogin(waUser, sessionData, parsedResponse)
		if err != nil {
			slog.Warn("WebAuthn login verification failed",
				"error", err,
				"user_id", user.ID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Authentication failed. Please try again.",
			})
			return
		}

		// Delete the WebAuthn challenge (single use)
		if err := repos.MFA.DeleteChallenge(ctx, user.ID, "login_authentication"); err != nil {
			slog.Warn("failed to delete WebAuthn challenge",
				"error", err,
				"user_id", user.ID,
			)
		}

		// Find and update the credential's sign count
		credIDBase64 := base64.StdEncoding.EncodeToString(validatedCredential.ID)
		if dbCredID, ok := credentialMap[credIDBase64]; ok {
			// Validate sign count to detect cloned authenticators
			for _, cred := range existingCreds {
				if cred.ID == dbCredID {
					if !webauthn.ValidateSignCount(cred.SignCount, validatedCredential.Authenticator.SignCount) {
						slog.Warn("SECURITY: Potential cloned authenticator detected during login",
							"user_id", user.ID,
							"credential_id", dbCredID,
							"stored_count", cred.SignCount,
							"new_count", validatedCredential.Authenticator.SignCount,
							"ip", clientIP,
						)
						// Allow authentication to continue but log the warning
					}
					break
				}
			}

			if err := repos.MFA.UpdateWebAuthnCredentialSignCount(ctx, dbCredID, validatedCredential.Authenticator.SignCount); err != nil {
				slog.Warn("failed to update WebAuthn sign count",
					"error", err,
					"credential_id", dbCredID,
				)
			}
		}

		// MFA verified - delete the login challenge and complete login
		mfaLoginStore.Delete(req.ChallengeID)

		slog.Info("WebAuthn login MFA verification successful",
			"user_id", user.ID,
			"username", user.Username,
			"ip", clientIP,
		)

		// Complete the login
		completeLogin(w, r, repos, cfg, user, challenge.ClientIP, challenge.UserAgent)
	}
}
