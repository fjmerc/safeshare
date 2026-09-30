package main

import (
	"net/http"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/handlers"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/repository"
)

// registerUserLoginRoute wires the /api/auth/login endpoint.
//
// The rate limiter is constructed exactly once, outside the per-request
// handler closure, and shared by both the MFA and non-MFA branches. A
// limiter built inside the closure would allocate a fresh, empty attempts
// map on every request, so the lockout could never trigger regardless of
// how many failed logins came from the same IP (see hotfix v1.7.1).
func registerUserLoginRoute(mux *http.ServeMux, repos *repository.Repositories, cfg *config.Config, anonMode bool) {
	userLoginRL := middleware.RateLimitUserLogin(anonMode)

	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if cfg.MFA != nil && cfg.MFA.Enabled {
			userLoginRL(http.HandlerFunc(handlers.UserLoginWithMFAHandler(repos, cfg))).ServeHTTP(w, r)
		} else {
			userLoginRL(http.HandlerFunc(handlers.UserLoginHandler(repos, cfg))).ServeHTTP(w, r)
		}
	})
}

// registerAdminLoginRoute wires the /admin/api/login endpoint with a single
// shared rate limiter instance (see registerUserLoginRoute for why this
// matters).
func registerAdminLoginRoute(mux *http.ServeMux, repos *repository.Repositories, cfg *config.Config, anonMode bool) {
	adminLoginRL := middleware.RateLimitAdminLogin(anonMode)

	mux.HandleFunc("/admin/api/login", func(w http.ResponseWriter, r *http.Request) {
		adminLoginRL(http.HandlerFunc(handlers.AdminLoginHandler(repos, cfg))).ServeHTTP(w, r)
	})
}
