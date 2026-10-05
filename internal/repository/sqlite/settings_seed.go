package sqlite

import (
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
)

// SettingsFromConfig builds a full settings row from the live configuration.
// It seeds the settings table the first time an admin saves anything, so the
// partial UPSERTs never create the row with schema defaults that would
// override the operator's environment config on the next restart. Until that
// first save no row exists and the environment stays authoritative.
func SettingsFromConfig(cfg *config.Config) *repository.Settings {
	s := &repository.Settings{
		QuotaLimitGB:           cfg.GetQuotaLimitGB(),
		MaxFileSizeBytes:       cfg.GetMaxFileSize(),
		DefaultExpirationHours: cfg.GetDefaultExpirationHours(),
		MaxExpirationHours:     cfg.GetMaxExpirationHours(),
		RateLimitUpload:        cfg.GetRateLimitUpload(),
		RateLimitDownload:      cfg.GetRateLimitDownload(),
		BlockedExtensions:      cfg.GetBlockedExtensions(),

		FeaturePostgreSQL:  cfg.Features.IsPostgreSQLEnabled(),
		FeatureS3Storage:   cfg.Features.IsS3StorageEnabled(),
		FeatureSSO:         cfg.Features.IsSSOEnabled(),
		FeatureMFA:         cfg.Features.IsMFAEnabled(),
		FeatureWebhooks:    cfg.Features.IsWebhooksEnabled(),
		FeatureAPITokens:   cfg.Features.IsAPITokensEnabled(),
		FeatureMalwareScan: cfg.Features.IsMalwareScanEnabled(),
		FeatureBackups:     cfg.Features.IsBackupsEnabled(),

		// Schema defaults, overridden below from env-derived config.
		MFAIssuer:                 repository.DefaultMFAIssuer,
		MFATOTPEnabled:            true,
		MFAWebAuthnEnabled:        true,
		MFARecoveryCodesCount:     repository.DefaultMFARecoveryCodesCount,
		MFAChallengeExpiryMinutes: repository.DefaultMFAChallengeExpiryMinutes,
		SSODefaultRole:            repository.DefaultSSORole,
		SSOSessionLifetime:        repository.DefaultSSOSessionLifetime,
		SSOStateExpiryMinutes:     repository.DefaultSSOStateExpiryMinutes,
	}
	if m := cfg.MFA; m != nil {
		s.MFARequired = m.Required
		if m.Issuer != "" {
			s.MFAIssuer = m.Issuer
		}
		s.MFATOTPEnabled = m.TOTPEnabled
		s.MFAWebAuthnEnabled = m.WebAuthnEnabled
		if m.RecoveryCodesCount > 0 {
			s.MFARecoveryCodesCount = m.RecoveryCodesCount
		}
		if m.ChallengeExpiryMinutes > 0 {
			s.MFAChallengeExpiryMinutes = m.ChallengeExpiryMinutes
		}
	}
	if o := cfg.SSO; o != nil {
		s.SSOAutoProvision = o.AutoProvision
		if o.DefaultRole != "" {
			s.SSODefaultRole = o.DefaultRole
		}
		if o.SessionLifetime > 0 {
			s.SSOSessionLifetime = o.SessionLifetime
		}
		if o.StateExpiryMinutes > 0 {
			s.SSOStateExpiryMinutes = o.StateExpiryMinutes
		}
	}
	return s
}
