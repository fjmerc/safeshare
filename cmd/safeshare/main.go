package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/handlers"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/static"
	"github.com/fjmerc/safeshare/internal/utils"
)

func main() {
	// Setup structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
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
		slog.Error("failed to initialize database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	slog.Info("database initialized", "path", cfg.DBPath)

	// Initialize admin credentials if admin is enabled
	if cfg.AdminUsername != "" && cfg.GetAdminPassword() != "" {
		err = database.InitializeAdminCredentials(db, cfg.AdminUsername, cfg.GetAdminPassword())
		if err != nil {
			slog.Error("failed to initialize admin credentials", "error", err)
			os.Exit(1)
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
		slog.Error("failed to create upload directory", "error", err)
		os.Exit(1)
	}

	slog.Info("upload directory ready", "path", cfg.UploadDir)

	// Record start time for health checks
	startTime := time.Now()

	// Setup HTTP router
	mux := http.NewServeMux()

	// Register public API routes (with IP blocking middleware and conditional user auth)
	ipBlockMw := middleware.IPBlockCheck(db)
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
	mux.HandleFunc("/health", handlers.HealthHandler(db, cfg, startTime))

	// Public configuration endpoint (no auth required)
	mux.HandleFunc("/api/config", handlers.PublicConfigHandler(cfg))

	// User authentication routes (public - no auth required)
	mux.HandleFunc("/login", serveUserPage("login.html"))
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

	// Admin routes (only enabled if admin credentials are configured)
	if cfg.AdminUsername != "" && cfg.GetAdminPassword() != "" {
		slog.Info("admin dashboard enabled", "username", cfg.AdminUsername)

		// Admin authentication routes (no auth required)
		mux.HandleFunc("/admin/login", serveAdminPage("admin/login.html"))
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

		mux.HandleFunc("/admin/api/config", func(w http.ResponseWriter, r *http.Request) {
			adminAuth(http.HandlerFunc(handlers.AdminGetConfigHandler(cfg))).ServeHTTP(w, r)
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
				adminAuth(csrfProtection(http.HandlerFunc(handlers.AdminDeleteUserHandler(db)))).ServeHTTP(w, r)
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

		// Admin static assets
		mux.Handle("/admin/assets/", http.StripPrefix("/", static.Handler()))
	} else {
		slog.Info("admin dashboard disabled - set ADMIN_USERNAME and ADMIN_PASSWORD to enable")
	}

	// Register static file routes (embedded frontend)
	mux.Handle("/assets/", http.StripPrefix("/", static.Handler()))
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

	// Create rate limiter
	rateLimiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
		UploadLimit:   cfg.GetRateLimitUpload(),
		DownloadLimit: cfg.GetRateLimitDownload(),
	})
	defer rateLimiter.Stop()

	// Wrap with middleware (order: Recovery -> Logging -> Security -> RateLimit -> handlers)
	handler := middleware.RecoveryMiddleware(
		middleware.LoggingMiddleware(
			middleware.SecurityHeadersMiddleware(
				middleware.RateLimitMiddleware(rateLimiter)(mux),
			),
		),
	)

	// Setup HTTP server
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start cleanup workers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go utils.StartCleanupWorker(ctx, db, cfg.UploadDir, cfg.CleanupIntervalMinutes)

	// Start partial upload cleanup worker (runs every 6 hours)
	go utils.StartPartialUploadCleanupWorker(ctx, db, cfg.UploadDir, cfg.PartialUploadExpiryHours, 6*time.Hour)

	// Start session cleanup worker (clean expired admin and user sessions every 30 minutes)
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
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
		slog.Error("server error", "error", err)
		os.Exit(1)

	case sig := <-shutdown:
		slog.Info("shutdown signal received", "signal", sig)

		// Cancel cleanup worker
		cancel()

		// Give outstanding requests 10 seconds to complete
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			slog.Error("graceful shutdown failed", "error", err)
			if err := server.Close(); err != nil {
				slog.Error("server close failed", "error", err)
			}
			os.Exit(1)
		}

		slog.Info("server shutdown complete")
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
