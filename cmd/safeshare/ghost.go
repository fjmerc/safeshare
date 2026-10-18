package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/fjmerc/safeshare/internal/claimcode"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
)

// enforceAnonymousModeEgress forces the Webhooks and SSO feature flags off
// when anonymous mode is on: both make outbound connections to third parties
// (webhook targets, OIDC providers), which anonymous mode must not do. It
// returns the names of the features it turned off. When settings is non-nil
// the new flags are persisted so the admin UI (which reads the database)
// agrees with what is actually running; a persistence failure is logged only.
func enforceAnonymousModeEgress(ctx context.Context, cfg *config.Config, settings repository.SettingsRepository) []string {
	if !cfg.IsAnonymousMode() {
		return nil
	}
	var disabled []string
	if cfg.Features.IsWebhooksEnabled() {
		cfg.Features.SetWebhooksEnabled(false)
		disabled = append(disabled, "webhooks")
	}
	if cfg.Features.IsSSOEnabled() || (cfg.SSO != nil && cfg.SSO.Enabled) {
		cfg.Features.SetSSOEnabled(false)
		cfg.SetSSOEnabled(false)
		disabled = append(disabled, "sso")
	}
	if len(disabled) == 0 {
		return nil
	}
	slog.Warn("anonymous mode: forcing outbound-connecting features off",
		"disabled", strings.Join(disabled, ","),
		"reason", "webhooks and SSO contact third parties and are not allowed with ANONYMOUS_MODE")
	// Only correct an existing row; never create one just for this (with no
	// row, the in-memory force-off above is all that is needed).
	if settings == nil {
		return disabled
	}
	if row, err := settings.Get(ctx); err == nil && row != nil {
		f := cfg.Features.GetAll()
		if err := settings.UpdateFeatureFlags(ctx, &repository.FeatureFlags{
			EnablePostgreSQL:  f.EnablePostgreSQL,
			EnableS3Storage:   f.EnableS3Storage,
			EnableSSO:         f.EnableSSO,
			EnableMFA:         f.EnableMFA,
			EnableWebhooks:    f.EnableWebhooks,
			EnableAPITokens:   f.EnableAPITokens,
			EnableMalwareScan: f.EnableMalwareScan,
			EnableBackups:     f.EnableBackups,
		}); err != nil {
			slog.Error("failed to persist anonymous-mode feature flag override", "error", err)
		}
	}
	return disabled
}

// clientEncryptionScanConflict reports whether the configuration makes every
// upload fail: client-side encryption is mandatory (so every upload is E2E
// ciphertext) while malware scanning rejects unscannable (E2E) uploads. It
// logs a loud error when so.
func clientEncryptionScanConflict(cfg *config.Config) bool {
	if cfg.IsClientEncryptionRequired() && cfg.Features.IsMalwareScanEnabled() && cfg.ClamAV != nil && cfg.ClamAV.RejectUnscannable {
		slog.Error("CONFIGURATION CONFLICT: REQUIRE_CLIENT_ENCRYPTION (default on in anonymous mode) requires every upload to be encrypted in the browser, " +
			"but malware scanning is enabled with MALWARE_SCAN_REJECT_UNSCANNABLE=true, which rejects every end-to-end encrypted upload. " +
			"EVERY UPLOAD WILL BE REJECTED. Disable the malware-scan feature or set MALWARE_SCAN_REJECT_UNSCANNABLE=false.")
		return true
	}
	return false
}

// metricsEndpointEnabled reports whether the unauthenticated /metrics
// endpoint should be mounted. In anonymous mode it is off unless the operator
// opts in with METRICS_IN_ANONYMOUS_MODE=true.
func metricsEndpointEnabled(cfg *config.Config) bool {
	return !cfg.IsAnonymousMode() || cfg.MetricsInAnonymousMode
}

// remoteAddrPattern matches IPv4:port and [IPv6]:port tokens in net/http's
// internal error messages ("http: TLS handshake error from 1.2.3.4:5678: ...").
var remoteAddrPattern = regexp.MustCompile(`(\[[0-9a-fA-F:.%]+\]|\b\d{1,3}(?:\.\d{1,3}){3}):\d+`)

// claimPathPattern matches claim-code URL paths that can appear in panic
// messages ("http: panic serving ...: GET /api/claim/<code> ...").
var claimPathPattern = regexp.MustCompile(`/(api/claim|claim|c)/[^\s/?"]+`)

// requestLinePattern matches "GET /path" / "HEAD /path" request lines in
// net/http's error messages, capturing the whole path (up to whitespace or a
// query string) so claimcode.ShortPath can judge it exactly, including codes
// that end in '-' or '_' and the reserved-route exemptions.
var requestLinePattern = regexp.MustCompile(`\b(GET|HEAD) (/[^\s?]*)`)

// redactShortClaimPaths masks the code in request lines for short claim links
// ("GET /<code>"). Paths that are not short claim links are left untouched.
func redactShortClaimPaths(msg string) string {
	return requestLinePattern.ReplaceAllStringFunc(msg, func(m string) string {
		sub := requestLinePattern.FindStringSubmatch(m)
		if _, ok := claimcode.ShortPath(sub[2]); !ok {
			return m
		}
		return sub[1] + " /[redacted]"
	})
}

// slogWriter forwards net/http's own error log lines to slog. In anonymous
// mode it masks remote addresses, which the stdlib otherwise writes raw.
type slogWriter struct{ anonymous bool }

func (w slogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	if w.anonymous {
		msg = remoteAddrPattern.ReplaceAllString(msg, "[redacted]")
		msg = claimPathPattern.ReplaceAllString(msg, "/$1/[redacted]")
		msg = redactShortClaimPaths(msg)
	}
	slog.Warn("http server", "message", msg)
	return len(p), nil
}

// newServerErrorLog returns the http.Server.ErrorLog logger.
func newServerErrorLog(anonymous bool) *log.Logger {
	return log.New(slogWriter{anonymous: anonymous}, "", 0)
}

// killSwitchServiceWorker is the file /service-worker.js returns in anonymous
// mode. Visitors who loaded the site before it was switched to anonymous mode
// still have the real worker installed and controlling their pages; browsers
// check the worker script on navigation, so this stub replaces it, deletes
// every cache and unregisters itself. It has no handler for network requests,
// so it never intercepts anything while it is running. It is an embedded file,
// not a Go string, so it is covered by the published web asset hashes.
const killSwitchServiceWorker = "service-worker-anonymous.js"

// manifestHandler serves the web app manifest from assets, except in anonymous
// mode, where it answers 404 so no browser offers to install the app.
func manifestHandler(cfg *config.Config, assets http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.IsAnonymousMode() {
			http.NotFound(w, r)
			return
		}
		http.StripPrefix("/", assets).ServeHTTP(w, r)
	})
}
