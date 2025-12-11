package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fjmerc/safeshare/internal/backup"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/handlers"
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/static"
	"github.com/fjmerc/safeshare/internal/storage"
	"github.com/fjmerc/safeshare/internal/storage/filesystem"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webauthn"
	"github.com/fjmerc/safeshare/internal/webhooks"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

// run is the main application entry point that can be tested
func run() error {
	// Setup structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	slog.Info("starting safeshare",
		"port", cfg.Port,
		"max_file_size", cfg.GetMaxFileSize(),
		"default_expiration_hours", cfg.GetDefaultExpirationHours(),
		"admin_enabled", cfg.AdminUsername != "" && cfg.GetAdminPassword() != "",
	)

	// Initialize database
	db, err := database.Initialize(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	slog.Info("database initialized", "path", cfg.DBPath)

	// Initialize repositories
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		return fmt.Errorf("failed to create repositories: %w", err)
	}

	slog.Info("repositories initialized")

	// Initialize admin credentials if admin is enabled
	if cfg.AdminUsername != "" && cfg.GetAdminPassword() != "" {
		err = repos.Admin.InitializeCredentials(context.Background(), cfg.AdminUsername, cfg.GetAdminPassword())
		if err != nil {
			return fmt.Errorf("failed to initialize admin credentials: %w", err)
		}
		slog.Info("admin credentials initialized", "username", cfg.AdminUsername)
	}

	// Load all settings from database (overrides environment variables if set)
	if dbSettings, err := repos.Settings.Get(context.Background()); err != nil {
		slog.Error("failed to load settings from database", "error", err)
	} else if dbSettings != nil {
		// Database has settings - use them instead of env vars
		cfg.SetQuotaLimitGB(dbSettings.QuotaLimitGB)
		cfg.SetMaxFileSize(dbSettings.MaxFileSizeBytes)
		cfg.SetDefaultExpirationHours(dbSettings.DefaultExpirationHours)
		cfg.SetMaxExpirationHours(dbSettings.MaxExpirationHours)
		cfg.SetRateLimitUpload(dbSettings.RateLimitUpload)
		cfg.SetRateLimitDownload(dbSettings.RateLimitDownload)
		cfg.SetBlockedExtensions(dbSettings.BlockedExtensions)

		// Load feature flags from database
		cfg.Features.SetAll(config.FeatureFlagsData{
			EnablePostgreSQL:  dbSettings.FeaturePostgreSQL,
			EnableS3Storage:   dbSettings.FeatureS3Storage,
			EnableSSO:         dbSettings.FeatureSSO,
			EnableMFA:         dbSettings.FeatureMFA,
			EnableWebhooks:    dbSettings.FeatureWebhooks,
			EnableAPITokens:   dbSettings.FeatureAPITokens,
			EnableMalwareScan: dbSettings.FeatureMalwareScan,
			EnableBackups:     dbSettings.FeatureBackups,
		})

		// Load MFA configuration from database (syncs with feature flag)
		if dbSettings.FeatureMFA {
			cfg.SetMFAEnabled(true)
			cfg.SetMFARequired(dbSettings.MFARequired)
			if dbSettings.MFAIssuer != "" {
				cfg.SetMFAIssuer(dbSettings.MFAIssuer)
			}
			cfg.SetMFATOTPEnabled(dbSettings.MFATOTPEnabled)
			cfg.SetMFAWebAuthnEnabled(dbSettings.MFAWebAuthnEnabled)
			if dbSettings.MFARecoveryCodesCount > 0 {
				cfg.SetMFARecoveryCodesCount(dbSettings.MFARecoveryCodesCount)
			}
			if dbSettings.MFAChallengeExpiryMinutes > 0 {
				cfg.SetMFAChallengeExpiryMinutes(dbSettings.MFAChallengeExpiryMinutes)
			}
			slog.Info("loaded MFA config from database",
				"enabled", true,
				"required", dbSettings.MFARequired,
				"issuer", dbSettings.MFAIssuer,
			)
		}

		// Load SSO configuration from database (syncs with feature flag)
		if dbSettings.FeatureSSO {
			cfg.SetSSOEnabled(true)
			cfg.SetSSOAutoProvision(dbSettings.SSOAutoProvision)
			if dbSettings.SSODefaultRole != "" {
				cfg.SetSSODefaultRole(dbSettings.SSODefaultRole)
			}
			if dbSettings.SSOSessionLifetime > 0 {
				cfg.SetSSOSessionLifetime(dbSettings.SSOSessionLifetime)
			}
			if dbSettings.SSOStateExpiryMinutes > 0 {
				cfg.SetSSOStateExpiryMinutes(dbSettings.SSOStateExpiryMinutes)
			}
			slog.Info("loaded SSO config from database",
				"enabled", true,
				"auto_provision", dbSettings.SSOAutoProvision,
				"default_role", dbSettings.SSODefaultRole,
			)
		}

		slog.Info("loaded settings from database",
			"quota_limit_gb", dbSettings.QuotaLimitGB,
			"max_file_size_bytes", dbSettings.MaxFileSizeBytes,
			"default_expiration_hours", dbSettings.DefaultExpirationHours,
			"max_expiration_hours", dbSettings.MaxExpirationHours,
			"rate_limit_upload", dbSettings.RateLimitUpload,
			"rate_limit_download", dbSettings.RateLimitDownload,
			"blocked_extensions", dbSettings.BlockedExtensions,
		)
	}

	// Create upload directory if it doesn't exist
	if err := os.MkdirAll(cfg.UploadDir, 0755); err != nil {
		return fmt.Errorf("failed to create upload directory: %w", err)
	}

	slog.Info("upload directory ready", "path", cfg.UploadDir)

	// Initialize storage backend
	fsStorage, err := filesystem.NewFilesystemStorage(cfg.UploadDir)
	if err != nil {
		return fmt.Errorf("failed to initialize filesystem storage: %w", err)
	}

	// Wrap with encryption if encryption is enabled
	var storageBackend storage.StorageBackend
	if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
		encStorage, err := storage.NewEncryptedStorage(fsStorage, cfg.EncryptionKey)
		if err != nil {
			return fmt.Errorf("failed to initialize encrypted storage: %w", err)
		}
		storageBackend = encStorage
		slog.Info("storage initialized with encryption")
	} else {
		storageBackend = fsStorage
		slog.Info("storage initialized without encryption")
	}

	// Make storage backend available to handlers
	handlers.SetStorageBackend(storageBackend)

	// Initialize webhook dispatcher
	webhookMetrics := webhooks.NewPrometheusMetrics()
	webhookDB := database.NewWebhookDBAdapter(db)
	webhookDispatcher := webhooks.NewDispatcher(webhookDB, 5, 1000, webhookMetrics)
	webhookDispatcher.Start()
	defer webhookDispatcher.Shutdown()
	slog.Info("webhook dispatcher started", "workers", 5, "buffer_size", 1000)

	// Make webhook dispatcher available to handlers
	handlers.SetWebhookDispatcher(webhookDispatcher)

	// Initialize WebAuthn service if MFA + WebAuthn is enabled
	var webauthnSvc *webauthn.Service
	if cfg.MFA != nil && cfg.MFA.Enabled && cfg.MFA.WebAuthnEnabled {
		var err error
		webauthnSvc, err = webauthn.NewService(cfg)
		if err != nil {
			slog.Error("failed to initialize WebAuthn service", "error", err)
			// Don't fail startup - WebAuthn is optional, TOTP can still work
		} else {
			slog.Info("WebAuthn service initialized",
				"rpid", webauthnSvc.GetRPID(),
				"origins", webauthnSvc.GetRPOrigins(),
			)
		}
	}

	// Initialize backup scheduler
	backupScheduler := backup.NewScheduler(cfg, repos)
	if cfg.AutoBackup != nil && cfg.AutoBackup.Enabled {
		if err := backupScheduler.Start(context.Background()); err != nil {
			slog.Error("failed to start backup scheduler", "error", err)
		} else {
			slog.Info("backup scheduler started",
				"schedule", cfg.AutoBackup.Schedule,
				"mode", cfg.AutoBackup.Mode,
				"retention_days", cfg.AutoBackup.RetentionDays,
			)
		}
	} else {
		slog.Info("automatic backups disabled (set AUTO_BACKUP_ENABLED=true to enable)")
	}
	defer backupScheduler.Stop()

	// Record start time for health checks
	startTime := time.Now()

	// Setup HTTP router
	mux := http.NewServeMux()

	// Register public API routes (with IP blocking middleware and conditional user auth)
	ipBlockMw := middleware.IPBlockCheck(repos, cfg)
	optionalUserAuth := middleware.OptionalUserAuth(repos)
	userAuth := middleware.UserAuth(repos)
	tokenAudit := middleware.APITokenAuditLog(repos)
	totpRateLimit := middleware.RateLimitTOTPVerify() // Rate limit for TOTP verification

	// Select authentication middleware for uploads based on configuration
	var uploadAuthMw func(http.Handler) http.Handler
	if cfg.RequireAuthForUpload {
		uploadAuthMw = userAuth // Require authentication
		slog.Info("upload authentication required", "require_auth_for_upload", true)
	} else {
		uploadAuthMw = optionalUserAuth // Allow anonymous uploads
		slog.Info("anonymous uploads enabled", "require_auth_for_upload", false)
	}

	// Upload endpoint with conditional authentication and token audit logging
	mux.HandleFunc("/api/upload", func(w http.ResponseWriter, r *http.Request) {
		ipBlockMw(uploadAuthMw(tokenAudit(http.HandlerFunc(handlers.UploadHandler(repos, cfg))))).ServeHTTP(w, r)
	})

	// Chunked upload endpoints with conditional authentication and token audit logging
	mux.HandleFunc("/api/upload/init", func(w http.ResponseWriter, r *http.Request) {
		ipBlockMw(uploadAuthMw(tokenAudit(http.HandlerFunc(handlers.UploadInitHandler(repos, cfg))))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/upload/chunk/", func(w http.ResponseWriter, r *http.Request) {
		ipBlockMw(uploadAuthMw(tokenAudit(http.HandlerFunc(handlers.UploadChunkHandler(repos, cfg))))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/upload/complete/", func(w http.ResponseWriter, r *http.Request) {
		ipBlockMw(uploadAuthMw(tokenAudit(http.HandlerFunc(handlers.UploadCompleteHandler(repos, cfg))))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/upload/status/", func(w http.ResponseWriter, r *http.Request) {
		ipBlockMw(uploadAuthMw(tokenAudit(http.HandlerFunc(handlers.UploadStatusHandler(repos, cfg))))).ServeHTTP(w, r)
	})

	// Note: Order matters - info endpoint must be registered before catch-all claim handler
	mux.HandleFunc("/api/claim/", func(w http.ResponseWriter, r *http.Request) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/info") {
				handlers.ClaimInfoHandler(repos, cfg)(w, r)
			} else {
				handlers.ClaimHandler(repos, cfg)(w, r)
			}
		}
		ipBlockMw(http.HandlerFunc(handler)).ServeHTTP(w, r)
	})
	// Health check endpoints (no auth required for monitoring)
	// Note: Health handlers still use *sql.DB - use repos.DB for backward compatibility
	mux.HandleFunc("/health", handlers.HealthHandler(repos.DB, cfg, startTime))
	mux.HandleFunc("/health/live", handlers.HealthLivenessHandler(repos.DB))
	mux.HandleFunc("/health/ready", handlers.HealthReadinessHandler(repos.DB, cfg, startTime))

	// Prometheus metrics endpoint (no auth required for Prometheus scraper)
	// Note: Metrics handler still uses *sql.DB - use repos.DB for backward compatibility
	mux.Handle("/metrics", handlers.MetricsHandler(repos.DB, cfg))

	// Public configuration endpoint (no auth required)
	mux.HandleFunc("/api/config", handlers.PublicConfigHandler(cfg))

	// User authentication routes (public - no auth required)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Check if user is already authenticated
		cookie, err := r.Cookie("user_session")
		if err == nil {
			// Has cookie, verify it's valid
			session, _ := repos.Users.GetSession(r.Context(), cookie.Value)
			if session != nil {
				// Valid session, redirect to dashboard
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
		}
		// Not authenticated, serve login page
		serveUserPage("login.html")(w, r)
	})
	// Login endpoint with MFA support
	// If MFA is enabled globally, uses the MFA-aware handler
	// Otherwise, falls back to standard login handler
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if cfg.MFA != nil && cfg.MFA.Enabled {
			middleware.RateLimitUserLogin()(http.HandlerFunc(handlers.UserLoginWithMFAHandler(repos, cfg))).ServeHTTP(w, r)
		} else {
			middleware.RateLimitUserLogin()(http.HandlerFunc(handlers.UserLoginHandler(repos, cfg))).ServeHTTP(w, r)
		}
	})

	// MFA login verification endpoint (no auth required - uses challenge token)
	// Rate limited to prevent brute-force attacks on TOTP codes
	mux.HandleFunc("/api/auth/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
		totpRateLimit(http.HandlerFunc(handlers.MFAVerifyLoginHandler(repos, cfg))).ServeHTTP(w, r)
	})

	// User dashboard routes (auth required)
	// Note: userAuth already defined above for conditional upload middleware

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(serveUserPage("dashboard.html"))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.UserLogoutHandler(repos, cfg))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/auth/user", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.UserGetCurrentHandler(repos))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/auth/change-password", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.UserChangePasswordHandler(repos))).ServeHTTP(w, r)
	})

	// User file management routes (with token audit logging)
	mux.HandleFunc("/api/user/files", func(w http.ResponseWriter, r *http.Request) {
		userAuth(tokenAudit(http.HandlerFunc(handlers.UserDashboardDataHandler(repos, cfg)))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/files/delete", func(w http.ResponseWriter, r *http.Request) {
		userAuth(tokenAudit(http.HandlerFunc(handlers.UserDeleteFileHandler(repos, cfg)))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/files/rename", func(w http.ResponseWriter, r *http.Request) {
		userAuth(tokenAudit(http.HandlerFunc(handlers.UserRenameFileHandler(repos, cfg)))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/files/update-expiration", func(w http.ResponseWriter, r *http.Request) {
		userAuth(tokenAudit(http.HandlerFunc(handlers.UserEditExpirationHandler(repos, cfg)))).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/user/files/regenerate-claim-code", func(w http.ResponseWriter, r *http.Request) {
		userAuth(tokenAudit(http.HandlerFunc(handlers.UserRegenerateClaimCodeHandler(repos, cfg)))).ServeHTTP(w, r)
	})

	// SDK-compatible user file management routes (claim code in URL path)
	// These routes support: DELETE /api/user/files/{claimCode}
	//                       PUT /api/user/files/{claimCode}/rename
	//                       PUT /api/user/files/{claimCode}/expiration
	//                       POST /api/user/files/{claimCode}/regenerate
	mux.HandleFunc("/api/user/files/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Route based on path suffix and method (with token audit logging)
		switch {
		case strings.HasSuffix(path, "/rename") && r.Method == http.MethodPut:
			userAuth(tokenAudit(http.HandlerFunc(handlers.UserRenameFileByClaimCodeHandler(repos, cfg)))).ServeHTTP(w, r)
		case strings.HasSuffix(path, "/expiration") && r.Method == http.MethodPut:
			userAuth(tokenAudit(http.HandlerFunc(handlers.UserEditExpirationByClaimCodeHandler(repos, cfg)))).ServeHTTP(w, r)
		case strings.HasSuffix(path, "/regenerate") && r.Method == http.MethodPost:
			userAuth(tokenAudit(http.HandlerFunc(handlers.UserRegenerateClaimCodeByClaimCodeHandler(repos, cfg)))).ServeHTTP(w, r)
		case r.Method == http.MethodDelete:
			// DELETE /api/user/files/{claimCode}
			userAuth(tokenAudit(http.HandlerFunc(handlers.UserDeleteFileByClaimCodeHandler(repos, cfg)))).ServeHTTP(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// API Token management routes
	// Note: Token creation requires session auth (cannot create tokens using tokens)
	mux.HandleFunc("/api/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Create token - requires session auth only (no token audit needed for session-only ops)
			userAuth(http.HandlerFunc(handlers.CreateAPITokenHandler(repos, cfg))).ServeHTTP(w, r)
		} else if r.Method == http.MethodGet {
			// List tokens with usage stats - allows both session and token auth (with token audit logging)
			userAuth(tokenAudit(http.HandlerFunc(handlers.ListAPITokensWithStatsHandler(repos)))).ServeHTTP(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// User CSRF protection for sensitive token operations
	userCSRF := middleware.CSRFProtection(repos)

	mux.HandleFunc("/api/tokens/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Route based on path suffix and method
		switch {
		case strings.HasSuffix(path, "/rotate") && r.Method == http.MethodPost:
			// Rotate token - requires session auth + CSRF protection
			userAuth(userCSRF(http.HandlerFunc(handlers.RotateTokenHandler(repos, cfg)))).ServeHTTP(w, r)
		case r.Method == http.MethodDelete:
			// Revoke token - requires session auth + CSRF protection
			userAuth(userCSRF(http.HandlerFunc(handlers.RevokeAPITokenHandler(repos.DB)))).ServeHTTP(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// MFA routes (TOTP enrollment and status)
	// Note: MFA routes require user authentication and user-specific CSRF protection
	mfaCSRF := middleware.UserCSRFProtection(repos)
	// Note: totpRateLimit already defined above with other middleware

	mux.HandleFunc("/api/user/mfa/status", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.MFAStatusHandler(repos, cfg))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/mfa/totp/setup", func(w http.ResponseWriter, r *http.Request) {
		userAuth(mfaCSRF(http.HandlerFunc(handlers.MFATOTPSetupHandler(repos, cfg)))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/mfa/totp/verify", func(w http.ResponseWriter, r *http.Request) {
		// Rate limit TOTP verification to prevent brute-force attacks
		userAuth(mfaCSRF(totpRateLimit(http.HandlerFunc(handlers.MFATOTPVerifyHandler(repos, cfg))))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/mfa/totp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			// Rate limit TOTP disable to prevent brute-force attacks
			userAuth(mfaCSRF(totpRateLimit(http.HandlerFunc(handlers.MFATOTPDisableHandler(repos, cfg))))).ServeHTTP(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// WebAuthn MFA routes (credential management - requires user auth + CSRF)
	mux.HandleFunc("/api/user/mfa/webauthn/register/begin", func(w http.ResponseWriter, r *http.Request) {
		userAuth(mfaCSRF(http.HandlerFunc(handlers.MFAWebAuthnRegisterBeginHandler(repos, cfg, webauthnSvc)))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/mfa/webauthn/register/finish", func(w http.ResponseWriter, r *http.Request) {
		userAuth(mfaCSRF(http.HandlerFunc(handlers.MFAWebAuthnRegisterFinishHandler(repos, cfg, webauthnSvc)))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/mfa/webauthn/auth/begin", func(w http.ResponseWriter, r *http.Request) {
		userAuth(mfaCSRF(http.HandlerFunc(handlers.MFAWebAuthnAuthBeginHandler(repos, cfg, webauthnSvc)))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/mfa/webauthn/auth/finish", func(w http.ResponseWriter, r *http.Request) {
		userAuth(mfaCSRF(http.HandlerFunc(handlers.MFAWebAuthnAuthFinishHandler(repos, cfg, webauthnSvc)))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/mfa/webauthn/credentials", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.MFAWebAuthnCredentialsHandler(repos, cfg))).ServeHTTP(w, r)
	})

	// WebAuthn credential management (DELETE/PATCH with ID in path)
	mux.HandleFunc("/api/user/mfa/webauthn/credentials/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			userAuth(mfaCSRF(http.HandlerFunc(handlers.MFAWebAuthnCredentialDeleteHandler(repos, cfg)))).ServeHTTP(w, r)
		} else if r.Method == http.MethodPatch {
			userAuth(mfaCSRF(http.HandlerFunc(handlers.MFAWebAuthnCredentialUpdateHandler(repos, cfg)))).ServeHTTP(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// WebAuthn login flow routes (no auth required - uses challenge token)
	mux.HandleFunc("/api/auth/mfa/webauthn/begin", func(w http.ResponseWriter, r *http.Request) {
		totpRateLimit(http.HandlerFunc(handlers.MFAWebAuthnLoginBeginHandler(repos, cfg, webauthnSvc))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/auth/mfa/webauthn/finish", func(w http.ResponseWriter, r *http.Request) {
		totpRateLimit(http.HandlerFunc(handlers.MFAWebAuthnLoginFinishHandler(repos, cfg, webauthnSvc))).ServeHTTP(w, r)
	})

	// SSO authentication routes
	// Public routes: providers list, login initiation, callback
	// Protected routes: link/unlink account, get linked providers
	// Rate limited to prevent state exhaustion and provider enumeration
	ssoRateLimit := middleware.RateLimitUserLogin() // Reuse user login rate limiting

	// GET /api/auth/sso/providers - List enabled SSO providers (public)
	mux.HandleFunc("/api/auth/sso/providers", handlers.ListSSOProvidersHandler(repos, cfg))

	// GET /api/auth/sso/{provider}/login - Initiate SSO login (public, rate limited)
	// GET /api/auth/sso/{provider}/callback - Handle IdP callback (public, rate limited)
	mux.HandleFunc("/api/auth/sso/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Route based on path suffix
		switch {
		case strings.HasSuffix(path, "/login"):
			ssoRateLimit(http.HandlerFunc(handlers.SSOLoginHandler(repos, cfg))).ServeHTTP(w, r)
		case strings.HasSuffix(path, "/callback"):
			ssoRateLimit(http.HandlerFunc(handlers.SSOCallbackHandler(repos, cfg))).ServeHTTP(w, r)
		default:
			http.Error(w, "Not found", http.StatusNotFound)
		}
	})

	// POST /api/auth/sso/link - Initiate SSO account linking (auth + CSRF required)
	// Note: mfaCSRF already defined above for MFA routes
	mux.HandleFunc("/api/auth/sso/link", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			userAuth(mfaCSRF(http.HandlerFunc(handlers.SSOLinkAccountHandler(repos, cfg)))).ServeHTTP(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// DELETE /api/auth/sso/link/{provider} - Unlink SSO account (auth + CSRF required)
	mux.HandleFunc("/api/auth/sso/link/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			userAuth(mfaCSRF(http.HandlerFunc(handlers.SSOUnlinkAccountHandler(repos, cfg)))).ServeHTTP(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// GET /api/auth/sso/linked - Get linked SSO providers for current user (auth required)
	mux.HandleFunc("/api/auth/sso/linked", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.SSOGetLinkedProvidersHandler(repos, cfg))).ServeHTTP(w, r)
	})

	// POST /api/auth/sso/refresh - Refresh SSO OAuth2 tokens (auth + CSRF required)
	mux.HandleFunc("/api/auth/sso/refresh", func(w http.ResponseWriter, r *http.Request) {
		userAuth(mfaCSRF(http.HandlerFunc(handlers.SSORefreshTokenHandler(repos, cfg)))).ServeHTTP(w, r)
	})

	// POST /api/auth/sso/logout - SSO logout with optional IdP redirect (auth + CSRF required)
	mux.HandleFunc("/api/auth/sso/logout", func(w http.ResponseWriter, r *http.Request) {
		userAuth(mfaCSRF(http.HandlerFunc(handlers.SSOLogoutHandler(repos, cfg)))).ServeHTTP(w, r)
	})

	// Admin routes (only enabled if admin credentials are configured)
	if cfg.AdminUsername != "" && cfg.GetAdminPassword() != "" {
		slog.Info("admin dashboard enabled", "username", cfg.AdminUsername)

		// Admin authentication routes (no auth required)
		mux.HandleFunc("/admin/login", func(w http.ResponseWriter, r *http.Request) {
			// Check if admin is already authenticated (admin_session or user with admin role)
			adminCookie, adminErr := r.Cookie("admin_session")
			if adminErr == nil {
				// Has admin cookie, verify it's valid
				session, _ := repos.Admin.GetSession(r.Context(), adminCookie.Value)
				if session != nil {
					// Valid admin session, redirect to admin dashboard
					http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
					return
				}
			}

			// Check for user_session with admin role
			userCookie, userErr := r.Cookie("user_session")
			if userErr == nil {
				session, _ := repos.Users.GetSession(r.Context(), userCookie.Value)
				if session != nil {
					user, _ := repos.Users.GetByID(r.Context(), session.UserID)
					if user != nil && user.Role == "admin" {
						// User has admin role, redirect to admin dashboard
						http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
						return
					}
				}
			}

			// Not authenticated as admin, serve login page
			serveAdminPage("admin/login.html")(w, r)
		})
		mux.HandleFunc("/admin/api/login", func(w http.ResponseWriter, r *http.Request) {
			middleware.RateLimitAdminLogin()(http.HandlerFunc(handlers.AdminLoginHandler(repos, cfg))).ServeHTTP(w, r)
		})

		// Admin dashboard routes (auth required)
		adminAuth := middleware.AdminAuth(repos)
		csrfProtection := middleware.CSRFProtection(repos)

		mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
			// Redirect to dashboard
			http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
		})

		mux.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(serveAdminDashboard(cfg)).ServeHTTP(w, r)
		})

		// Admin API routes (auth + CSRF protection required)
		mux.HandleFunc("/admin/api/logout", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.AdminLogoutHandler(repos, cfg))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/dashboard", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.AdminDashboardDataHandler(repos, cfg))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/files/delete", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminDeleteFileHandler(repos, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/files/delete/bulk", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminBulkDeleteFilesHandler(repos, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/ip/block", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminBlockIPHandler(repos)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/ip/unblock", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUnblockIPHandler(repos)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/quota/update", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUpdateQuotaHandler(repos, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/settings/storage", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUpdateStorageSettingsHandler(repos, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/settings/security", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUpdateSecuritySettingsHandler(repos, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/settings/password", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminChangePasswordHandler(cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/partial-uploads/cleanup", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminCleanupPartialUploadsHandler(repos, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/config", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.AdminGetConfigHandler(cfg))).ServeHTTP(w, r)
		})

		// Feature flags management
		mux.HandleFunc("/admin/api/features", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				adminAuth(http.HandlerFunc(handlers.AdminGetFeatureFlagsHandler(repos, cfg))).ServeHTTP(w, r)
			} else if r.Method == http.MethodPut {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUpdateFeatureFlagsHandler(repos, cfg)))).ServeHTTP(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		// Enterprise configuration management (MFA, SSO config details)
		mux.HandleFunc("/admin/api/config/enterprise", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				adminAuth(http.HandlerFunc(handlers.AdminGetEnterpriseConfigHandler(repos, cfg))).ServeHTTP(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		mux.HandleFunc("/admin/api/config/mfa", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUpdateMFAConfigHandler(repos, cfg)))).ServeHTTP(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		mux.HandleFunc("/admin/api/config/sso", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUpdateSSOConfigHandler(repos, cfg)))).ServeHTTP(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		mux.HandleFunc("/admin/api/config-assistant/analyze", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminConfigAssistantHandler(cfg)))).ServeHTTP(w, r)
		})

		// Admin user management routes
		mux.HandleFunc("/admin/api/users/create", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminCreateUserHandler(repos)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/users", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.AdminListUsersHandler(repos))).ServeHTTP(w, r)
		})

		// Match patterns for user-specific operations
		mux.HandleFunc("/admin/api/users/", func(w http.ResponseWriter, r *http.Request) {
			// Route to appropriate handler based on HTTP method and path
			path := r.URL.Path

			// Admin MFA management routes
			// GET /admin/api/users/{id}/mfa/status - Get user's MFA status
			// POST /admin/api/users/{id}/mfa/reset - Disable MFA for user
			// Note: Use HasSuffix for strict path matching to prevent path traversal
			if strings.HasSuffix(path, "/mfa/status") && r.Method == "GET" {
				adminAuth(http.HandlerFunc(handlers.AdminGetUserMFAStatusHandler(repos))).ServeHTTP(w, r)
				return
			} else if strings.HasSuffix(path, "/mfa/reset") && r.Method == "POST" {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminResetUserMFAHandler(repos, cfg)))).ServeHTTP(w, r)
				return
			}

			if r.Method == "PUT" || r.Method == "PATCH" {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUpdateUserHandler(repos)))).ServeHTTP(w, r)
			} else if r.Method == "DELETE" {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminDeleteUserHandler(repos, cfg)))).ServeHTTP(w, r)
			} else if r.Method == "POST" {
				// Check which action: enable, disable, or reset-password
				if strings.Contains(path, "/enable") || strings.Contains(path, "/disable") {
					adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminToggleUserActiveHandler(repos)))).ServeHTTP(w, r)
				} else if strings.Contains(path, "/reset-password") {
					adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminResetUserPasswordHandler(repos)))).ServeHTTP(w, r)
				} else {
					http.Error(w, "Not found", http.StatusNotFound)
				}
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		// Webhook management routes
		// Note: Webhook handlers still use *sql.DB - use repos.DB for backward compatibility
		mux.HandleFunc("/admin/api/webhooks", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				adminAuth(http.HandlerFunc(handlers.ListWebhookConfigsHandler(repos.DB))).ServeHTTP(w, r)
			} else if r.Method == "POST" {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.CreateWebhookConfigHandler(repos.DB)))).ServeHTTP(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		mux.HandleFunc("/admin/api/webhooks/update", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.UpdateWebhookConfigHandler(repos.DB)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/webhooks/delete", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.DeleteWebhookConfigHandler(repos.DB)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/webhooks/test", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.TestWebhookConfigHandler(repos.DB)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/webhook-deliveries", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.ListWebhookDeliveriesHandler(repos.DB))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/webhook-deliveries/detail", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.GetWebhookDeliveryHandler(repos.DB))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/webhook-deliveries/clear", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.ClearWebhookDeliveriesHandler(repos.DB)))).ServeHTTP(w, r)
		})

		// Admin API Token management routes
		mux.HandleFunc("/admin/api/tokens", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				// List all tokens with usage stats
				adminAuth(http.HandlerFunc(handlers.AdminListAPITokensWithStatsHandler(repos))).ServeHTTP(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		mux.HandleFunc("/admin/api/tokens/revoke", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminRevokeAPITokenHandler(repos.DB)))).ServeHTTP(w, r)
		})

		// Bulk token revocation - revoke multiple tokens by IDs
		mux.HandleFunc("/admin/api/tokens/bulk-revoke", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminBulkRevokeTokensHandler(repos, cfg)))).ServeHTTP(w, r)
		})

		// Revoke all tokens for a specific user
		mux.HandleFunc("/admin/api/tokens/revoke-user/", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminRevokeUserTokensHandler(repos, cfg)))).ServeHTTP(w, r)
		})

		// Token usage audit logs
		mux.HandleFunc("/admin/api/tokens/", func(w http.ResponseWriter, r *http.Request) {
			// Only handle /admin/api/tokens/{id}/usage pattern
			if !handlers.IsTokenUsagePath(r.URL.Path) {
				http.NotFound(w, r)
				return
			}
			if r.Method == http.MethodGet {
				adminAuth(http.HandlerFunc(handlers.AdminGetTokenUsageHandler(repos))).ServeHTTP(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		// Backup management routes
		// Note: Backup handlers still use *sql.DB - use repos.DB for backward compatibility
		mux.HandleFunc("/admin/api/backups", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				adminAuth(http.HandlerFunc(handlers.AdminListBackupsHandler(repos.DB, cfg))).ServeHTTP(w, r)
			} else if r.Method == http.MethodPost {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminCreateBackupHandler(repos.DB, cfg)))).ServeHTTP(w, r)
			} else if r.Method == http.MethodDelete {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminDeleteBackupHandler(repos.DB, cfg)))).ServeHTTP(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		mux.HandleFunc("/admin/api/backups/verify", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminVerifyBackupHandler(repos.DB, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/backups/restore", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminRestoreBackupHandler(repos.DB, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/backups/download", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminDownloadBackupHandler(repos.DB, cfg)))).ServeHTTP(w, r)
		})

		// Backup scheduler management routes
		backupSchedulerHandler := handlers.NewBackupSchedulerHandler(repos, cfg, backupScheduler)

		mux.HandleFunc("/admin/api/backup-schedules", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(backupSchedulerHandler.ListSchedules())).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/backup-schedules/{id}", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				adminAuth(http.HandlerFunc(backupSchedulerHandler.GetSchedule())).ServeHTTP(w, r)
			} else if r.Method == http.MethodPut {
				adminAuth(csrfProtection(http.HandlerFunc(backupSchedulerHandler.UpdateSchedule()))).ServeHTTP(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		mux.HandleFunc("/admin/api/backup-runs", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(backupSchedulerHandler.ListRuns())).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/backup-runs/{id}", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(backupSchedulerHandler.GetRun())).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/backup-stats", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(backupSchedulerHandler.GetStats())).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/backup-trigger", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(backupSchedulerHandler.TriggerBackup()))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/backup-running", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(backupSchedulerHandler.GetRunningBackup())).ServeHTTP(w, r)
		})

		// Admin SSO Management endpoints
		// GET /admin/api/sso/providers - List all SSO providers with stats
		mux.HandleFunc("/admin/api/sso/providers", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				adminAuth(http.HandlerFunc(handlers.AdminListSSOProvidersHandler(repos, cfg))).ServeHTTP(w, r)
			case http.MethodPost:
				// POST /admin/api/sso/providers - Create new SSO provider
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminCreateSSOProviderHandler(repos, cfg)))).ServeHTTP(w, r)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		// GET/PUT/DELETE /admin/api/sso/providers/{id} - CRUD operations on specific provider
		// POST /admin/api/sso/providers/{id}/test - Test OIDC connection
		mux.HandleFunc("/admin/api/sso/providers/", func(w http.ResponseWriter, r *http.Request) {
			// Check if this is a /test endpoint
			if strings.HasSuffix(r.URL.Path, "/test") {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminTestSSOProviderHandler(repos, cfg)))).ServeHTTP(w, r)
				return
			}

			switch r.Method {
			case http.MethodGet:
				adminAuth(http.HandlerFunc(handlers.AdminGetSSOProviderHandler(repos, cfg))).ServeHTTP(w, r)
			case http.MethodPut:
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUpdateSSOProviderHandler(repos, cfg)))).ServeHTTP(w, r)
			case http.MethodDelete:
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminDeleteSSOProviderHandler(repos, cfg)))).ServeHTTP(w, r)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		// GET /admin/api/sso/links - List all SSO links with pagination
		mux.HandleFunc("/admin/api/sso/links", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.AdminListSSOLinksHandler(repos, cfg))).ServeHTTP(w, r)
		})

		// DELETE /admin/api/sso/links/{id} - Admin unlink user's SSO
		mux.HandleFunc("/admin/api/sso/links/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminDeleteSSOLinkHandler(repos, cfg)))).ServeHTTP(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		// Admin static assets
		mux.Handle("/admin/assets/", http.StripPrefix("/", static.Handler()))
	} else {
		slog.Info("admin dashboard disabled - set ADMIN_USERNAME and ADMIN_PASSWORD to enable")
	}

	// Register static file routes (embedded frontend)
	mux.Handle("/assets/", http.StripPrefix("/", static.Handler()))

	// Service worker route (must be at root scope for PWA)
	mux.HandleFunc("/service-worker.js", serveServiceWorker())

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Serve index.html for root path only
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		// Use embedded file system
		fs := static.FileSystem()
		file, err := fs.Open("index.html")
		if err != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		defer file.Close()

		stat, err := file.Stat()
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		http.ServeContent(w, r, "index.html", stat.ModTime(), file.(io.ReadSeeker))
	})

	// Create rate limiter (pass config pointer for runtime updates)
	rateLimiter := middleware.NewRateLimiter(cfg)
	defer rateLimiter.Stop()

	// Wrap with middleware (order: Recovery -> Logging -> Metrics -> Security -> RateLimit -> handlers)
	handler := middleware.RecoveryMiddleware(
		middleware.LoggingMiddleware(
			metrics.Middleware(
				middleware.SecurityHeadersMiddleware(
					middleware.RateLimitMiddleware(rateLimiter)(mux),
				),
			),
		),
	)

	// Enable HTTP/2 support (with h2c for non-TLS environments)
	h2Server := &http2.Server{
		MaxConcurrentStreams: 250, // Allow many parallel chunk uploads
	}

	// Wrap handler with h2c for HTTP/2 over cleartext (dev/testing)
	// If HTTPS is enabled, Go automatically uses HTTP/2 via TLS ALPN
	handlerWithH2C := h2c.NewHandler(handler, h2Server)

	// Setup HTTP server
	server := &http.Server{
		Addr:           ":" + cfg.Port,
		Handler:        handlerWithH2C,
		ReadTimeout:    time.Duration(cfg.ReadTimeoutSeconds) * time.Second,
		WriteTimeout:   time.Duration(cfg.WriteTimeoutSeconds) * time.Second,
		IdleTimeout:    120 * time.Second, // Increased from 60s for HTTP/2 connection reuse
		MaxHeaderBytes: 1 << 20,           // 1MB header limit
	}

	// Start cleanup workers with WaitGroup for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var workerWg sync.WaitGroup

	// Start file cleanup worker
	workerWg.Add(1)
	go func() {
		defer workerWg.Done()
		utils.StartCleanupWorker(ctx, repos, cfg.UploadDir, cfg.CleanupIntervalMinutes, handlers.EmitWebhookEvent)
	}()

	// Start partial upload cleanup worker (runs every 6 hours)
	workerWg.Add(1)
	go func() {
		defer workerWg.Done()
		utils.StartPartialUploadCleanupWorker(ctx, repos, cfg.UploadDir, cfg.PartialUploadExpiryHours, 6*time.Hour)
	}()

	// Start assembly recovery worker (recovers interrupted assemblies on startup, runs every 10 minutes)
	workerWg.Add(1)
	go func() {
		defer workerWg.Done()
		utils.StartAssemblyRecoveryWorker(ctx, repos, cfg, handlers.AssembleUploadAsync)
	}()

	// Start session cleanup worker (clean expired admin and user sessions every 30 minutes)
	workerWg.Add(1)
	go func() {
		defer workerWg.Done()
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Add panic recovery to prevent goroutine death
				func() {
					defer func() {
						if r := recover(); r != nil {
							slog.Error("session cleanup worker panic recovered", "panic", r)
						}
					}()

					cleanupCtx := context.Background()

					if err := repos.Admin.CleanupExpiredSessions(cleanupCtx); err != nil {
						slog.Error("failed to cleanup expired admin sessions", "error", err)
					} else {
						slog.Debug("cleaned up expired admin sessions")
					}

					if err := repos.Users.CleanupExpiredSessions(cleanupCtx); err != nil {
						slog.Error("failed to cleanup expired user sessions", "error", err)
					} else {
						slog.Debug("cleaned up expired user sessions")
					}

					// Cleanup expired API tokens
					if count, err := repos.APITokens.CleanupExpired(cleanupCtx); err != nil {
						slog.Error("failed to cleanup expired API tokens", "error", err)
					} else if count > 0 {
						slog.Info("cleaned up expired API tokens", "count", count)
					}
				}()
			}
		}
	}()

	// Start HTTP server in a goroutine
	serverErrors := make(chan error, 1)
	go func() {
		slog.Info("http server listening", "address", server.Addr)
		serverErrors <- server.ListenAndServe()
	}()

	// Setup graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Wait for shutdown signal or server error
	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)

	case sig := <-shutdown:
		slog.Info("shutdown signal received", "signal", sig)

		// Get upload tracker to manage in-progress uploads
		uploadTracker := utils.GetUploadTracker()

		// Phase 1: Stop accepting new uploads (but allow existing ones to finish)
		slog.Info("phase 1: stopping new uploads",
			"active_uploads", uploadTracker.GetActiveCount(),
		)
		uploadTracker.BeginShutdown()

		// Cancel context to signal workers to stop
		cancel()

		// Phase 2: Wait for in-progress uploads to complete (up to 30 seconds)
		// This is separate from HTTP server shutdown to give uploads more time
		uploadTimeout := 30 * time.Second
		if uploadTracker.GetActiveCount() > 0 {
			slog.Info("phase 2: waiting for in-progress uploads to complete",
				"timeout_seconds", uploadTimeout.Seconds(),
				"active_uploads", uploadTracker.GetActiveCount(),
			)
			uploadTracker.WaitForUploads(uploadTimeout)
		}

		// Phase 3: Gracefully shutdown HTTP server (give remaining requests 10 seconds)
		slog.Info("phase 3: shutting down HTTP server")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful shutdown failed", "error", err)
			if err := server.Close(); err != nil {
				return fmt.Errorf("server close failed: %w", err)
			}
			return fmt.Errorf("graceful shutdown failed: %w", err)
		}

		slog.Info("HTTP server shutdown complete")

		// Phase 4: Wait for all background workers to finish (with 5 second timeout)
		slog.Info("phase 4: waiting for background workers to finish")
		workerDone := make(chan struct{})
		go func() {
			workerWg.Wait()
			close(workerDone)
		}()

		select {
		case <-workerDone:
			slog.Info("all background workers stopped gracefully")
		case <-time.After(5 * time.Second):
			slog.Warn("background workers did not finish within timeout, forcing exit")
		}

		slog.Info("graceful shutdown complete")
		return nil
	}
}

// serveAdminPage returns a handler that serves an admin HTML page from embedded files
func serveAdminPage(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fs := static.FileSystem()
		file, err := fs.Open(path)
		if err != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		defer file.Close()

		stat, err := file.Stat()
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, path, stat.ModTime(), file.(io.ReadSeeker))
	}
}

// serveAdminDashboard serves the admin dashboard and ensures CSRF token is set
func serveAdminDashboard(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CSRF token for all admin dashboard access
		// This ensures users who login via user login also get the token
		_, err := middleware.SetCSRFCookie(w, cfg)
		if err != nil {
			slog.Error("failed to set CSRF cookie for dashboard", "error", err)
			// Continue anyway - token might already be set
		}

		// Serve the dashboard page
		serveAdminPage("admin/dashboard.html")(w, r)
	}
}

func serveUserPage(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fs := static.FileSystem()
		file, err := fs.Open(path)
		if err != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		defer file.Close()

		stat, err := file.Stat()
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, path, stat.ModTime(), file.(io.ReadSeeker))
	}
}

// serveServiceWorker serves the service worker file with proper headers for PWA
func serveServiceWorker() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fs := static.FileSystem()
		file, err := fs.Open("service-worker.js")
		if err != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		defer file.Close()

		stat, err := file.Stat()
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		// Set proper MIME type and cache headers for service worker
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, "service-worker.js", stat.ModTime(), file.(io.ReadSeeker))
	}
}
