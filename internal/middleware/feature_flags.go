package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/fjmerc/safeshare/internal/config"
)

// FeatureFlagCheck is a middleware factory that checks if a feature is enabled.
// If the feature is disabled, it returns a 403 Forbidden response.
// This allows enterprise features to be disabled at runtime.
type FeatureFlagChecker func() bool

// FeatureFlagRequired creates a middleware that requires a specific feature to be enabled.
// Usage:
//
//	FeatureFlagRequired(cfg.Features.IsWebhooksEnabled, "webhooks")(handler)
func FeatureFlagRequired(checker FeatureFlagChecker, featureName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !checker() {
				// Truncate path for logging to prevent log spam from long URLs
				path := r.URL.Path
				if len(path) > 200 {
					path = path[:200] + "..."
				}
				slog.Warn("feature flag check failed",
					"feature", featureName,
					"path", path,
					"method", r.Method,
				)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "Feature disabled",
					"feature": featureName,
					"message": "This feature is currently disabled. Contact your administrator to enable it.",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WebhooksEnabled creates a middleware that requires webhooks feature to be enabled.
func WebhooksEnabled(cfg *config.Config) func(http.Handler) http.Handler {
	return FeatureFlagRequired(cfg.Features.IsWebhooksEnabled, "webhooks")
}

// APITokensEnabled creates a middleware that requires API tokens feature to be enabled.
func APITokensEnabled(cfg *config.Config) func(http.Handler) http.Handler {
	return FeatureFlagRequired(cfg.Features.IsAPITokensEnabled, "api_tokens")
}

// BackupsEnabled creates a middleware that requires backups feature to be enabled.
func BackupsEnabled(cfg *config.Config) func(http.Handler) http.Handler {
	return FeatureFlagRequired(cfg.Features.IsBackupsEnabled, "backups")
}

// MFAEnabled creates a middleware that requires MFA feature to be enabled.
func MFAEnabled(cfg *config.Config) func(http.Handler) http.Handler {
	return FeatureFlagRequired(cfg.Features.IsMFAEnabled, "mfa")
}

// SSOEnabled creates a middleware that requires SSO feature to be enabled.
func SSOEnabled(cfg *config.Config) func(http.Handler) http.Handler {
	return FeatureFlagRequired(cfg.Features.IsSSOEnabled, "sso")
}

// MalwareScanEnabled creates a middleware that requires malware scan feature to be enabled.
func MalwareScanEnabled(cfg *config.Config) func(http.Handler) http.Handler {
	return FeatureFlagRequired(cfg.Features.IsMalwareScanEnabled, "malware_scan")
}
