package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/webauthn"
)

// EnterpriseConfigResponse represents the combined enterprise configuration.
type EnterpriseConfigResponse struct {
	FeatureFlags *config.FeatureFlagsData `json:"feature_flags"`
	MFA          *MFAConfigResponse       `json:"mfa"`
	SSO          *SSOConfigResponse       `json:"sso"`
}

// MFAConfigResponse represents MFA configuration for API responses.
type MFAConfigResponse struct {
	Enabled                bool   `json:"enabled"`
	Required               bool   `json:"required"`
	Issuer                 string `json:"issuer"`
	TOTPEnabled            bool   `json:"totp_enabled"`
	WebAuthnEnabled        bool   `json:"webauthn_enabled"`
	RecoveryCodesCount     int    `json:"recovery_codes_count"`
	ChallengeExpiryMinutes int    `json:"challenge_expiry_minutes"`
}

// SSOConfigResponse represents SSO configuration for API responses.
type SSOConfigResponse struct {
	Enabled            bool   `json:"enabled"`
	AutoProvision      bool   `json:"auto_provision"`
	DefaultRole        string `json:"default_role"`
	SessionLifetime    int    `json:"session_lifetime"`
	StateExpiryMinutes int    `json:"state_expiry_minutes"`
}

// MFAConfigRequest represents the JSON request body for updating MFA configuration.
type MFAConfigRequest struct {
	Enabled                *bool   `json:"enabled,omitempty"`
	Required               *bool   `json:"required,omitempty"`
	Issuer                 *string `json:"issuer,omitempty"`
	TOTPEnabled            *bool   `json:"totp_enabled,omitempty"`
	WebAuthnEnabled        *bool   `json:"webauthn_enabled,omitempty"`
	RecoveryCodesCount     *int    `json:"recovery_codes_count,omitempty"`
	ChallengeExpiryMinutes *int    `json:"challenge_expiry_minutes,omitempty"`
}

// SSOConfigRequest represents the JSON request body for updating SSO configuration.
type SSOConfigRequest struct {
	Enabled            *bool   `json:"enabled,omitempty"`
	AutoProvision      *bool   `json:"auto_provision,omitempty"`
	DefaultRole        *string `json:"default_role,omitempty"`
	SessionLifetime    *int    `json:"session_lifetime,omitempty"`
	StateExpiryMinutes *int    `json:"state_expiry_minutes,omitempty"`
}

// AdminGetEnterpriseConfigHandler returns the combined enterprise configuration.
// GET /api/admin/config/enterprise
func AdminGetEnterpriseConfigHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get feature flags from in-memory config
		flags := cfg.Features.GetAll()

		// Get MFA config
		mfaCfg := cfg.GetMFAConfig()
		var mfaResp *MFAConfigResponse
		if mfaCfg != nil {
			mfaResp = &MFAConfigResponse{
				Enabled:                mfaCfg.Enabled,
				Required:               mfaCfg.Required,
				Issuer:                 mfaCfg.Issuer,
				TOTPEnabled:            mfaCfg.TOTPEnabled,
				WebAuthnEnabled:        mfaCfg.WebAuthnEnabled,
				RecoveryCodesCount:     mfaCfg.RecoveryCodesCount,
				ChallengeExpiryMinutes: mfaCfg.ChallengeExpiryMinutes,
			}
		}

		// Get SSO config
		ssoCfg := cfg.GetSSOConfig()
		var ssoResp *SSOConfigResponse
		if ssoCfg != nil {
			ssoResp = &SSOConfigResponse{
				Enabled:            ssoCfg.Enabled,
				AutoProvision:      ssoCfg.AutoProvision,
				DefaultRole:        ssoCfg.DefaultRole,
				SessionLifetime:    ssoCfg.SessionLifetime,
				StateExpiryMinutes: ssoCfg.StateExpiryMinutes,
			}
		}

		response := EnterpriseConfigResponse{
			FeatureFlags: &flags,
			MFA:          mfaResp,
			SSO:          ssoResp,
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		json.NewEncoder(w).Encode(response)
	}
}

// AdminUpdateMFAConfigHandler updates MFA configuration.
// PUT /api/admin/config/mfa
//
// Updates both the database and in-memory config.
// When MFA is enabled/disabled, also syncs the feature flag.
func AdminUpdateMFAConfigHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Limit request body size
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

		var req MFAConfigRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			slog.Error("failed to parse MFA config request", "error", err, "ip", clientIP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Invalid request format",
				"code":  "INVALID_REQUEST",
			})
			return
		}

		// Get current MFA config from database
		currentCfg, err := repos.Settings.GetMFAConfig(ctx)
		if err != nil {
			slog.Error("failed to get current MFA config", "error", err, "ip", clientIP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Failed to retrieve current MFA configuration",
				"code":  "DATABASE_ERROR",
			})
			return
		}

		// Apply updates only for provided fields
		if req.Enabled != nil {
			currentCfg.Enabled = *req.Enabled
		}
		if req.Required != nil {
			currentCfg.Required = *req.Required
		}
		if req.Issuer != nil {
			currentCfg.Issuer = *req.Issuer
		}
		if req.TOTPEnabled != nil {
			currentCfg.TOTPEnabled = *req.TOTPEnabled
		}
		if req.WebAuthnEnabled != nil {
			currentCfg.WebAuthnEnabled = *req.WebAuthnEnabled
		}
		if req.RecoveryCodesCount != nil {
			currentCfg.RecoveryCodesCount = *req.RecoveryCodesCount
		}
		if req.ChallengeExpiryMinutes != nil {
			currentCfg.ChallengeExpiryMinutes = *req.ChallengeExpiryMinutes
		}

		// Persist to database
		if err := repos.Settings.UpdateMFAConfig(ctx, currentCfg); err != nil {
			slog.Error("failed to update MFA config in database", "error", err, "ip", clientIP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": err.Error(),
				"code":  "VALIDATION_ERROR",
			})
			return
		}

		// Update in-memory config
		cfg.SetMFAEnabled(currentCfg.Enabled)
		cfg.SetMFARequired(currentCfg.Required)
		if err := cfg.SetMFAIssuer(currentCfg.Issuer); err != nil {
			slog.Error("failed to set MFA issuer in config", "error", err)
		}
		cfg.SetMFATOTPEnabled(currentCfg.TOTPEnabled)
		cfg.SetMFAWebAuthnEnabled(currentCfg.WebAuthnEnabled)
		if err := cfg.SetMFARecoveryCodesCount(currentCfg.RecoveryCodesCount); err != nil {
			slog.Error("failed to set MFA recovery codes count in config", "error", err)
		}
		if err := cfg.SetMFAChallengeExpiryMinutes(currentCfg.ChallengeExpiryMinutes); err != nil {
			slog.Error("failed to set MFA challenge expiry in config", "error", err)
		}

		// Sync feature flag with enabled state
		cfg.Features.SetMFAEnabled(currentCfg.Enabled)

		// Reinitialize WebAuthn service if MFA + WebAuthn is now enabled
		if currentCfg.Enabled && currentCfg.WebAuthnEnabled {
			newSvc, err := webauthn.NewService(cfg)
			if err != nil {
				slog.Error("failed to reinitialize WebAuthn service", "error", err, "ip", clientIP)
				// Continue anyway - log warning but don't fail the MFA config update
			} else {
				SetWebAuthnService(newSvc)
				slog.Info("WebAuthn service reinitialized",
					"rpid", newSvc.GetRPID(),
					"origins", newSvc.GetRPOrigins(),
				)
			}
		}

		slog.Info("MFA configuration updated",
			"ip", clientIP,
			"enabled", currentCfg.Enabled,
			"required", currentCfg.Required,
			"issuer", currentCfg.Issuer,
			"totp_enabled", currentCfg.TOTPEnabled,
			"webauthn_enabled", currentCfg.WebAuthnEnabled,
		)

		// Return updated config
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"mfa": MFAConfigResponse{
				Enabled:                currentCfg.Enabled,
				Required:               currentCfg.Required,
				Issuer:                 currentCfg.Issuer,
				TOTPEnabled:            currentCfg.TOTPEnabled,
				WebAuthnEnabled:        currentCfg.WebAuthnEnabled,
				RecoveryCodesCount:     currentCfg.RecoveryCodesCount,
				ChallengeExpiryMinutes: currentCfg.ChallengeExpiryMinutes,
			},
		})
	}
}

// AdminUpdateSSOConfigHandler updates SSO configuration.
// PUT /api/admin/config/sso
//
// Updates both the database and in-memory config.
// When SSO is enabled/disabled, also syncs the feature flag.
func AdminUpdateSSOConfigHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Limit request body size
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

		var req SSOConfigRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			slog.Error("failed to parse SSO config request", "error", err, "ip", clientIP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Invalid request format",
				"code":  "INVALID_REQUEST",
			})
			return
		}

		// Get current SSO config from database
		currentCfg, err := repos.Settings.GetSSOConfig(ctx)
		if err != nil {
			slog.Error("failed to get current SSO config", "error", err, "ip", clientIP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Failed to retrieve current SSO configuration",
				"code":  "DATABASE_ERROR",
			})
			return
		}

		// Apply updates only for provided fields
		if req.Enabled != nil {
			currentCfg.Enabled = *req.Enabled
		}
		if req.AutoProvision != nil {
			currentCfg.AutoProvision = *req.AutoProvision
		}
		if req.DefaultRole != nil {
			currentCfg.DefaultRole = *req.DefaultRole
		}
		if req.SessionLifetime != nil {
			currentCfg.SessionLifetime = *req.SessionLifetime
		}
		if req.StateExpiryMinutes != nil {
			currentCfg.StateExpiryMinutes = *req.StateExpiryMinutes
		}

		// Persist to database
		if err := repos.Settings.UpdateSSOConfig(ctx, currentCfg); err != nil {
			slog.Error("failed to update SSO config in database", "error", err, "ip", clientIP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": err.Error(),
				"code":  "VALIDATION_ERROR",
			})
			return
		}

		// Update in-memory config
		cfg.SetSSOEnabled(currentCfg.Enabled)
		cfg.SetSSOAutoProvision(currentCfg.AutoProvision)
		if err := cfg.SetSSODefaultRole(currentCfg.DefaultRole); err != nil {
			slog.Error("failed to set SSO default role in config", "error", err)
		}
		if err := cfg.SetSSOSessionLifetime(currentCfg.SessionLifetime); err != nil {
			slog.Error("failed to set SSO session lifetime in config", "error", err)
		}
		if err := cfg.SetSSOStateExpiryMinutes(currentCfg.StateExpiryMinutes); err != nil {
			slog.Error("failed to set SSO state expiry in config", "error", err)
		}

		// Sync feature flag with enabled state
		cfg.Features.SetSSOEnabled(currentCfg.Enabled)

		slog.Info("SSO configuration updated",
			"ip", clientIP,
			"enabled", currentCfg.Enabled,
			"auto_provision", currentCfg.AutoProvision,
			"default_role", currentCfg.DefaultRole,
			"session_lifetime", currentCfg.SessionLifetime,
		)

		// Return updated config
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"sso": SSOConfigResponse{
				Enabled:            currentCfg.Enabled,
				AutoProvision:      currentCfg.AutoProvision,
				DefaultRole:        currentCfg.DefaultRole,
				SessionLifetime:    currentCfg.SessionLifetime,
				StateExpiryMinutes: currentCfg.StateExpiryMinutes,
			},
		})
	}
}
