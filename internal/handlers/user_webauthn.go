package handlers

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/webauthn"
)

// webAuthnVerificationMinTime is the minimum time for WebAuthn verification operations
// to prevent timing attacks. All WebAuthn validation attempts take at least this long.
const webAuthnVerificationMinTime = 100 * time.Millisecond

// ===========================================================================
// Request/Response Types
// ===========================================================================

// WebAuthnRegisterBeginResponse is returned when starting credential registration
type WebAuthnRegisterBeginResponse struct {
	Options   *protocol.CredentialCreation `json:"options"`
	Challenge string                       `json:"challenge"` // Base64-encoded challenge for reference
}

// WebAuthnRegisterFinishRequest is the request body for completing registration
type WebAuthnRegisterFinishRequest struct {
	Name       string          `json:"name"`     // User-friendly name for the credential
	Credential json.RawMessage `json:"response"` // The credential response from the browser
}

// WebAuthnAuthBeginResponse is returned when starting authentication
type WebAuthnAuthBeginResponse struct {
	Options   *protocol.CredentialAssertion `json:"options"`
	Challenge string                        `json:"challenge"` // Base64-encoded challenge for reference
}

// WebAuthnCredentialResponse represents a credential in API responses
type WebAuthnCredentialResponse struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	CreatedAt   string   `json:"created_at"`
	LastUsedAt  string   `json:"last_used_at,omitempty"`
	Transports  []string `json:"transports,omitempty"`
	BackupState bool     `json:"backup_state"`
}

// WebAuthnCredentialUpdateRequest is the request body for updating a credential name
type WebAuthnCredentialUpdateRequest struct {
	Name string `json:"name"`
}

// ===========================================================================
// Registration Handlers
// ===========================================================================

// MFAWebAuthnRegisterBeginHandler handles POST /api/user/mfa/webauthn/register/begin
// Starts the WebAuthn credential registration ceremony
func MFAWebAuthnRegisterBeginHandler(repos *repository.Repositories, cfg *config.Config, webauthnSvc *webauthn.Service) http.HandlerFunc {
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

		// Check if WebAuthn is enabled
		if cfg.MFA == nil || !cfg.MFA.Enabled || !cfg.MFA.WebAuthnEnabled {
			slog.Warn("WebAuthn registration attempted but WebAuthn is disabled",
				"user_id", user.ID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "WebAuthn is not enabled on this server",
			})
			return
		}

		if webauthnSvc == nil {
			slog.Error("WebAuthn service not initialized",
				"user_id", user.ID,
				"ip", clientIP,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get existing credentials for exclusion list
		existingCreds, err := repos.MFA.GetWebAuthnCredentials(ctx, user.ID)
		if err != nil {
			slog.Error("failed to get existing WebAuthn credentials",
				"error", err,
				"user_id", user.ID,
			)
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

		// Begin registration ceremony
		creation, session, err := webauthnSvc.BeginRegistration(waUser)
		if err != nil {
			slog.Error("failed to begin WebAuthn registration",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Store challenge in database (session.Challenge is already base64url encoded)
		expiresAt := time.Now().Add(time.Duration(cfg.MFA.ChallengeExpiryMinutes) * time.Minute)

		_, err = repos.MFA.CreateChallenge(ctx, user.ID, session.Challenge, "registration", expiresAt)
		if err != nil {
			slog.Error("failed to store WebAuthn challenge",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("WebAuthn registration started",
			"user_id", user.ID,
			"username", user.Username,
			"ip", clientIP,
		)

		response := WebAuthnRegisterBeginResponse{
			Options:   creation,
			Challenge: session.Challenge,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// MFAWebAuthnRegisterFinishHandler handles POST /api/user/mfa/webauthn/register/finish
// Completes the WebAuthn credential registration ceremony
func MFAWebAuthnRegisterFinishHandler(repos *repository.Repositories, cfg *config.Config, webauthnSvc *webauthn.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Apply timing attack protection
		startTime := time.Now()
		defer func() {
			elapsed := time.Since(startTime)
			if elapsed < webAuthnVerificationMinTime {
				time.Sleep(webAuthnVerificationMinTime - elapsed)
			}
		}()

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
		userAgent := getUserAgent(r)

		// Check if WebAuthn is enabled
		if cfg.MFA == nil || !cfg.MFA.Enabled || !cfg.MFA.WebAuthnEnabled {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "WebAuthn is not enabled on this server",
			})
			return
		}

		if webauthnSvc == nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Parse request
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB limit for WebAuthn response
		var req WebAuthnRegisterFinishRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate credential name
		if req.Name == "" {
			req.Name = "Hardware Key"
		}
		if len(req.Name) > 100 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Credential name must be 100 characters or less",
			})
			return
		}

		// Get the stored challenge
		challenge, err := repos.MFA.GetChallenge(ctx, user.ID, "registration")
		if err != nil {
			if err == repository.ErrChallengeNotFound || err == repository.ErrChallengeExpired {
				slog.Warn("WebAuthn registration failed - challenge not found or expired",
					"user_id", user.ID,
					"ip", clientIP,
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Registration session expired. Please start again.",
				})
				return
			}
			slog.Error("failed to get WebAuthn challenge",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get existing credentials for the user
		existingCreds, err := repos.MFA.GetWebAuthnCredentials(ctx, user.ID)
		if err != nil {
			slog.Error("failed to get existing WebAuthn credentials",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Convert to gowebauthn.Credential format
		var credentials []gowebauthn.Credential
		for _, cred := range existingCreds {
			waCred, err := webauthn.CredentialToWebAuthn(&cred)
			if err != nil {
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

		// Parse the credential creation response
		parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
		if err != nil {
			slog.Warn("failed to parse WebAuthn credential response",
				"error", err,
				"user_id", user.ID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid credential response",
			})
			return
		}

		// Create session data from stored challenge (already base64url encoded)
		sessionData := gowebauthn.SessionData{
			Challenge: challenge.Challenge,
			UserID:    waUser.WebAuthnID(),
		}

		// Finish registration
		credential, err := webauthnSvc.FinishRegistration(waUser, sessionData, parsedResponse)
		if err != nil {
			slog.Warn("WebAuthn registration verification failed",
				"error", err,
				"user_id", user.ID,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to verify credential. Please try again.",
			})
			return
		}

		// Delete the challenge (single use)
		if err := repos.MFA.DeleteChallenge(ctx, user.ID, "registration"); err != nil {
			slog.Warn("failed to delete WebAuthn challenge",
				"error", err,
				"user_id", user.ID,
			)
			// Don't fail the registration for this
		}

		// Convert and store the credential
		repoCred := webauthn.WebAuthnToCredential(user.ID, req.Name, credential)
		storedCred, err := repos.MFA.CreateWebAuthnCredential(ctx, repoCred)
		if err != nil {
			slog.Error("failed to store WebAuthn credential",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("WebAuthn credential registered",
			"user_id", user.ID,
			"username", user.Username,
			"credential_id", storedCred.ID,
			"credential_name", req.Name,
			"ip", clientIP,
			"user_agent", userAgent,
		)

		// Return the new credential info
		response := WebAuthnCredentialResponse{
			ID:          storedCred.ID,
			Name:        storedCred.Name,
			CreatedAt:   storedCred.CreatedAt.Format(time.RFC3339),
			Transports:  storedCred.Transports,
			BackupState: storedCred.BackupState,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// ===========================================================================
// Authentication Handlers
// ===========================================================================

// MFAWebAuthnAuthBeginHandler handles POST /api/user/mfa/webauthn/auth/begin
// Starts the WebAuthn authentication ceremony (for MFA verification)
func MFAWebAuthnAuthBeginHandler(repos *repository.Repositories, cfg *config.Config, webauthnSvc *webauthn.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context - user must be authenticated (but not MFA verified yet for login flow)
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		clientIP := getClientIP(r)

		// Check if WebAuthn is enabled
		if cfg.MFA == nil || !cfg.MFA.Enabled || !cfg.MFA.WebAuthnEnabled {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "WebAuthn is not enabled on this server",
			})
			return
		}

		if webauthnSvc == nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get user's WebAuthn credentials
		existingCreds, err := repos.MFA.GetWebAuthnCredentials(ctx, user.ID)
		if err != nil {
			slog.Error("failed to get WebAuthn credentials",
				"error", err,
				"user_id", user.ID,
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

		// Begin authentication ceremony
		assertion, session, err := webauthnSvc.BeginLogin(waUser)
		if err != nil {
			slog.Error("failed to begin WebAuthn authentication",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Store challenge in database (session.Challenge is already base64url encoded)
		expiresAt := time.Now().Add(time.Duration(cfg.MFA.ChallengeExpiryMinutes) * time.Minute)

		_, err = repos.MFA.CreateChallenge(ctx, user.ID, session.Challenge, "authentication", expiresAt)
		if err != nil {
			slog.Error("failed to store WebAuthn challenge",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("WebAuthn authentication started",
			"user_id", user.ID,
			"username", user.Username,
			"ip", clientIP,
		)

		response := WebAuthnAuthBeginResponse{
			Options:   assertion,
			Challenge: session.Challenge,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// MFAWebAuthnAuthFinishHandler handles POST /api/user/mfa/webauthn/auth/finish
// Completes the WebAuthn authentication ceremony
func MFAWebAuthnAuthFinishHandler(repos *repository.Repositories, cfg *config.Config, webauthnSvc *webauthn.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Apply timing attack protection
		startTime := time.Now()
		defer func() {
			elapsed := time.Since(startTime)
			if elapsed < webAuthnVerificationMinTime {
				time.Sleep(webAuthnVerificationMinTime - elapsed)
			}
		}()

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

		// Check if WebAuthn is enabled
		if cfg.MFA == nil || !cfg.MFA.Enabled || !cfg.MFA.WebAuthnEnabled {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "WebAuthn is not enabled on this server",
			})
			return
		}

		if webauthnSvc == nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Parse the raw request body
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB limit

		// Get the stored challenge
		challenge, err := repos.MFA.GetChallenge(ctx, user.ID, "authentication")
		if err != nil {
			if err == repository.ErrChallengeNotFound || err == repository.ErrChallengeExpired {
				slog.Warn("WebAuthn authentication failed - challenge not found or expired",
					"user_id", user.ID,
					"ip", clientIP,
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Authentication session expired. Please try again.",
				})
				return
			}
			slog.Error("failed to get WebAuthn challenge",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get user's WebAuthn credentials
		existingCreds, err := repos.MFA.GetWebAuthnCredentials(ctx, user.ID)
		if err != nil {
			slog.Error("failed to get WebAuthn credentials",
				"error", err,
				"user_id", user.ID,
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
		parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
		if err != nil {
			slog.Warn("failed to parse WebAuthn assertion response",
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
			Challenge: challenge.Challenge,
			UserID:    waUser.WebAuthnID(),
		}

		// Finish authentication
		validatedCredential, err := webauthnSvc.FinishLogin(waUser, sessionData, parsedResponse)
		if err != nil {
			slog.Warn("WebAuthn authentication verification failed",
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

		// Delete the challenge (single use)
		if err := repos.MFA.DeleteChallenge(ctx, user.ID, "authentication"); err != nil {
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
						slog.Warn("SECURITY: Potential cloned authenticator detected",
							"user_id", user.ID,
							"credential_id", dbCredID,
							"stored_count", cred.SignCount,
							"new_count", validatedCredential.Authenticator.SignCount,
							"ip", clientIP,
						)
						// Allow authentication to continue but log the warning
						// In a stricter implementation, you might want to reject the login
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

		slog.Info("WebAuthn authentication successful",
			"user_id", user.ID,
			"username", user.Username,
			"ip", clientIP,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Authentication successful",
		})
	}
}

// ===========================================================================
// Credential Management Handlers
// ===========================================================================

// MFAWebAuthnCredentialsHandler handles GET /api/user/mfa/webauthn/credentials
// Returns list of user's WebAuthn credentials
func MFAWebAuthnCredentialsHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
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

		// Get user's WebAuthn credentials
		credentials, err := repos.MFA.GetWebAuthnCredentials(ctx, user.ID)
		if err != nil {
			slog.Error("failed to get WebAuthn credentials",
				"error", err,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Convert to response format
		var response []WebAuthnCredentialResponse
		for _, cred := range credentials {
			resp := WebAuthnCredentialResponse{
				ID:          cred.ID,
				Name:        cred.Name,
				CreatedAt:   cred.CreatedAt.Format(time.RFC3339),
				Transports:  cred.Transports,
				BackupState: cred.BackupState,
			}
			if cred.LastUsedAt != nil {
				resp.LastUsedAt = cred.LastUsedAt.Format(time.RFC3339)
			}
			response = append(response, resp)
		}

		// Return empty array instead of null
		if response == nil {
			response = []WebAuthnCredentialResponse{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// webauthnCredentialPathRegex matches paths like /api/user/mfa/webauthn/credentials/{id}
var webauthnCredentialPathRegex = regexp.MustCompile(`^/api/user/mfa/webauthn/credentials/(\d+)$`)

// MFAWebAuthnCredentialDeleteHandler handles DELETE /api/user/mfa/webauthn/credentials/{id}
// Deletes a specific WebAuthn credential
func MFAWebAuthnCredentialDeleteHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
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

		// Parse credential ID from path
		matches := webauthnCredentialPathRegex.FindStringSubmatch(r.URL.Path)
		if len(matches) < 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid credential ID",
			})
			return
		}

		credentialID, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil || credentialID <= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid credential ID",
			})
			return
		}

		// Delete the credential (repository validates ownership)
		err = repos.MFA.DeleteWebAuthnCredential(ctx, credentialID, user.ID)
		if err != nil {
			if err == repository.ErrWebAuthnCredentialNotFound {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Credential not found",
				})
				return
			}
			slog.Error("failed to delete WebAuthn credential",
				"error", err,
				"user_id", user.ID,
				"credential_id", credentialID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("WebAuthn credential deleted",
			"user_id", user.ID,
			"username", user.Username,
			"credential_id", credentialID,
			"ip", clientIP,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Credential deleted successfully",
		})
	}
}

// MFAWebAuthnCredentialUpdateHandler handles PATCH /api/user/mfa/webauthn/credentials/{id}
// Updates a WebAuthn credential's name
func MFAWebAuthnCredentialUpdateHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
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

		// Parse credential ID from path
		matches := webauthnCredentialPathRegex.FindStringSubmatch(r.URL.Path)
		if len(matches) < 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid credential ID",
			})
			return
		}

		credentialID, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil || credentialID <= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid credential ID",
			})
			return
		}

		// Parse request body
		r.Body = http.MaxBytesReader(w, r.Body, 1024) // 1KB limit
		var req WebAuthnCredentialUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate name
		if req.Name == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Name is required",
			})
			return
		}
		if len(req.Name) > 100 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Name must be 100 characters or less",
			})
			return
		}

		// Update the credential name (repository validates ownership)
		err = repos.MFA.UpdateWebAuthnCredentialName(ctx, credentialID, user.ID, req.Name)
		if err != nil {
			if err == repository.ErrWebAuthnCredentialNotFound {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Credential not found",
				})
				return
			}
			slog.Error("failed to update WebAuthn credential name",
				"error", err,
				"user_id", user.ID,
				"credential_id", credentialID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("WebAuthn credential renamed",
			"user_id", user.ID,
			"username", user.Username,
			"credential_id", credentialID,
			"new_name", req.Name,
			"ip", clientIP,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Credential updated successfully",
		})
	}
}
