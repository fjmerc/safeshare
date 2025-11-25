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

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/handlers"
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/static"
	"github.com/fjmerc/safeshare/internal/utils"
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

	// Initialize admin credentials if admin is enabled
	if cfg.AdminUsername != "" && cfg.GetAdminPassword() != "" {
		err = database.InitializeAdminCredentials(db, cfg.AdminUsername, cfg.GetAdminPassword())
		if err != nil {
			return fmt.Errorf("failed to initialize admin credentials: %w", err)
		}
		slog.Info("admin credentials initialized", "username", cfg.AdminUsername)
	}

	// Load all settings from database (overrides environment variables if set)
	if dbSettings, err := database.GetSettings(db); err != nil {
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

	// Initialize webhook dispatcher
	webhookMetrics := webhooks.NewPrometheusMetrics()
	webhookDB := database.NewWebhookDBAdapter(db)
	webhookDispatcher := webhooks.NewDispatcher(webhookDB, 5, 1000, webhookMetrics)
	webhookDispatcher.Start()
	defer webhookDispatcher.Shutdown()
	slog.Info("webhook dispatcher started", "workers", 5, "buffer_size", 1000)

	// Make webhook dispatcher available to handlers
	handlers.SetWebhookDispatcher(webhookDispatcher)

	// Record start time for health checks
	startTime := time.Now()

	// Setup HTTP router
	mux := http.NewServeMux()

	// Register public API routes (with IP blocking middleware and conditional user auth)
	ipBlockMw := middleware.IPBlockCheck(db, cfg)
	optionalUserAuth := middleware.OptionalUserAuth(db)
	userAuth := middleware.UserAuth(db)

	// Select authentication middleware for uploads based on configuration
	var uploadAuthMw func(http.Handler) http.Handler
	if cfg.RequireAuthForUpload {
		uploadAuthMw = userAuth // Require authentication
		slog.Info("upload authentication required", "require_auth_for_upload", true)
	} else {
		uploadAuthMw = optionalUserAuth // Allow anonymous uploads
		slog.Info("anonymous uploads enabled", "require_auth_for_upload", false)
	}

	// Upload endpoint with conditional authentication
	mux.HandleFunc("/api/upload", func(w http.ResponseWriter, r *http.Request) {
		ipBlockMw(uploadAuthMw(http.HandlerFunc(handlers.UploadHandler(db, cfg)))).ServeHTTP(w, r)
	})

	// Chunked upload endpoints with conditional authentication
	mux.HandleFunc("/api/upload/init", func(w http.ResponseWriter, r *http.Request) {
		ipBlockMw(uploadAuthMw(http.HandlerFunc(handlers.UploadInitHandler(db, cfg)))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/upload/chunk/", func(w http.ResponseWriter, r *http.Request) {
		ipBlockMw(uploadAuthMw(http.HandlerFunc(handlers.UploadChunkHandler(db, cfg)))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/upload/complete/", func(w http.ResponseWriter, r *http.Request) {
		ipBlockMw(uploadAuthMw(http.HandlerFunc(handlers.UploadCompleteHandler(db, cfg)))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/upload/status/", func(w http.ResponseWriter, r *http.Request) {
		ipBlockMw(uploadAuthMw(http.HandlerFunc(handlers.UploadStatusHandler(db, cfg)))).ServeHTTP(w, r)
	})

	// Note: Order matters - info endpoint must be registered before catch-all claim handler
	mux.HandleFunc("/api/claim/", func(w http.ResponseWriter, r *http.Request) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/info") {
				handlers.ClaimInfoHandler(db, cfg)(w, r)
			} else {
				handlers.ClaimHandler(db, cfg)(w, r)
			}
		}
		ipBlockMw(http.HandlerFunc(handler)).ServeHTTP(w, r)
	})
	// Health check endpoints (no auth required for monitoring)
	mux.HandleFunc("/health", handlers.HealthHandler(db, cfg, startTime))
	mux.HandleFunc("/health/live", handlers.HealthLivenessHandler(db))
	mux.HandleFunc("/health/ready", handlers.HealthReadinessHandler(db, cfg, startTime))

	// Prometheus metrics endpoint (no auth required for Prometheus scraper)
	mux.Handle("/metrics", handlers.MetricsHandler(db, cfg))

	// Public configuration endpoint (no auth required)
	mux.HandleFunc("/api/config", handlers.PublicConfigHandler(cfg))

	// User authentication routes (public - no auth required)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Check if user is already authenticated
		cookie, err := r.Cookie("user_session")
		if err == nil {
			// Has cookie, verify it's valid
			session, _ := database.GetUserSession(db, cookie.Value)
			if session != nil {
				// Valid session, redirect to dashboard
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
		}
		// Not authenticated, serve login page
		serveUserPage("login.html")(w, r)
	})
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		middleware.RateLimitUserLogin()(http.HandlerFunc(handlers.UserLoginHandler(db, cfg))).ServeHTTP(w, r)
	})

	// User dashboard routes (auth required)
	// Note: userAuth already defined above for conditional upload middleware

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(serveUserPage("dashboard.html"))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.UserLogoutHandler(db, cfg))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/auth/user", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.UserGetCurrentHandler(db))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/auth/change-password", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.UserChangePasswordHandler(db))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/files", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.UserDashboardDataHandler(db, cfg))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/files/delete", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.UserDeleteFileHandler(db, cfg))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/files/rename", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.UserRenameFileHandler(db, cfg))).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/user/files/update-expiration", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.UserEditExpirationHandler(db, cfg))).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/user/files/regenerate-claim-code", func(w http.ResponseWriter, r *http.Request) {
		userAuth(http.HandlerFunc(handlers.UserRegenerateClaimCodeHandler(db, cfg))).ServeHTTP(w, r)
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
				session, _ := database.GetSession(db, adminCookie.Value)
				if session != nil {
					// Valid admin session, redirect to admin dashboard
					http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
					return
				}
			}

			// Check for user_session with admin role
			userCookie, userErr := r.Cookie("user_session")
			if userErr == nil {
				session, _ := database.GetUserSession(db, userCookie.Value)
				if session != nil {
					user, _ := database.GetUserByID(db, session.UserID)
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
			middleware.RateLimitAdminLogin()(http.HandlerFunc(handlers.AdminLoginHandler(db, cfg))).ServeHTTP(w, r)
		})

		// Admin dashboard routes (auth required)
		adminAuth := middleware.AdminAuth(db)
		csrfProtection := middleware.CSRFProtection(db)

		mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
			// Redirect to dashboard
			http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
		})

		mux.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(serveAdminDashboard(cfg)).ServeHTTP(w, r)
		})

		// Admin API routes (auth + CSRF protection required)
		mux.HandleFunc("/admin/api/logout", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.AdminLogoutHandler(db, cfg))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/dashboard", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.AdminDashboardDataHandler(db, cfg))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/files/delete", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminDeleteFileHandler(db, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/files/delete/bulk", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminBulkDeleteFilesHandler(db, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/ip/block", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminBlockIPHandler(db)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/ip/unblock", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUnblockIPHandler(db)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/quota/update", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUpdateQuotaHandler(db, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/settings/storage", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUpdateStorageSettingsHandler(db, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/settings/security", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUpdateSecuritySettingsHandler(db, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/settings/password", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminChangePasswordHandler(cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/partial-uploads/cleanup", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminCleanupPartialUploadsHandler(db, cfg)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/config", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.AdminGetConfigHandler(cfg))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/config-assistant/analyze", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminConfigAssistantHandler(cfg)))).ServeHTTP(w, r)
		})

		// Admin user management routes
		mux.HandleFunc("/admin/api/users/create", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminCreateUserHandler(db)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/users", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.AdminListUsersHandler(db))).ServeHTTP(w, r)
		})

		// Match patterns for user-specific operations
		mux.HandleFunc("/admin/api/users/", func(w http.ResponseWriter, r *http.Request) {
			// Route to appropriate handler based on HTTP method and path
			path := r.URL.Path

			if r.Method == "PUT" || r.Method == "PATCH" {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminUpdateUserHandler(db)))).ServeHTTP(w, r)
			} else if r.Method == "DELETE" {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminDeleteUserHandler(db, cfg)))).ServeHTTP(w, r)
			} else if r.Method == "POST" {
				// Check which action: enable, disable, or reset-password
				if strings.Contains(path, "/enable") || strings.Contains(path, "/disable") {
					adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminToggleUserActiveHandler(db)))).ServeHTTP(w, r)
				} else if strings.Contains(path, "/reset-password") {
					adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminResetUserPasswordHandler(db)))).ServeHTTP(w, r)
				} else {
					http.Error(w, "Not found", http.StatusNotFound)
				}
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		// Webhook management routes
		mux.HandleFunc("/admin/api/webhooks", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				adminAuth(http.HandlerFunc(handlers.ListWebhookConfigsHandler(db))).ServeHTTP(w, r)
			} else if r.Method == "POST" {
				adminAuth(csrfProtection(http.HandlerFunc(handlers.CreateWebhookConfigHandler(db)))).ServeHTTP(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		mux.HandleFunc("/admin/api/webhooks/update", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.UpdateWebhookConfigHandler(db)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/webhooks/delete", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.DeleteWebhookConfigHandler(db)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/webhooks/test", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.TestWebhookConfigHandler(db)))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/webhook-deliveries", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.ListWebhookDeliveriesHandler(db))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/webhook-deliveries/detail", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.GetWebhookDeliveryHandler(db))).ServeHTTP(w, r)
		})

		mux.HandleFunc("/admin/api/webhook-deliveries/clear", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(csrfProtection(http.HandlerFunc(handlers.ClearWebhookDeliveriesHandler(db)))).ServeHTTP(w, r)
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
		utils.StartCleanupWorker(ctx, db, cfg.UploadDir, cfg.CleanupIntervalMinutes, handlers.EmitWebhookEvent)
	}()

	// Start partial upload cleanup worker (runs every 6 hours)
	workerWg.Add(1)
	go func() {
		defer workerWg.Done()
		utils.StartPartialUploadCleanupWorker(ctx, db, cfg.UploadDir, cfg.PartialUploadExpiryHours, 6*time.Hour)
	}()

	// Start assembly recovery worker (recovers interrupted assemblies on startup, runs every 10 minutes)
	workerWg.Add(1)
	go func() {
		defer workerWg.Done()
		utils.StartAssemblyRecoveryWorker(ctx, db, cfg, handlers.AssembleUploadAsync)
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

					if err := database.CleanupExpiredSessions(db); err != nil {
						slog.Error("failed to cleanup expired admin sessions", "error", err)
					} else {
						slog.Debug("cleaned up expired admin sessions")
					}

					if err := database.CleanupExpiredUserSessions(db); err != nil {
						slog.Error("failed to cleanup expired user sessions", "error", err)
					} else {
						slog.Debug("cleaned up expired user sessions")
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

		// Cancel context to signal workers to stop
		cancel()

		// Give outstanding requests 10 seconds to complete
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful shutdown failed", "error", err)
			if err := server.Close(); err != nil {
				return fmt.Errorf("server close failed: %w", err)
			}
			return fmt.Errorf("graceful shutdown failed: %w", err)
		}

		slog.Info("server shutdown complete")

		// Wait for all background workers to finish (with 5 second timeout)
		slog.Info("waiting for background workers to finish")
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
