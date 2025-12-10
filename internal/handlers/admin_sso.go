// Package handlers provides HTTP request handlers for the SafeShare application.
package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/auth/sso"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
)

// AdminSSOProviderResponse represents an SSO provider in admin responses.
type AdminSSOProviderResponse struct {
	ID                int64                      `json:"id"`
	Name              string                     `json:"name"`
	Slug              string                     `json:"slug"`
	Type              repository.SSOProviderType `json:"type"`
	Enabled           bool                       `json:"enabled"`
	IssuerURL         string                     `json:"issuer_url,omitempty"`
	ClientID          string                     `json:"client_id,omitempty"`
	AuthorizationURL  string                     `json:"authorization_url,omitempty"`
	TokenURL          string                     `json:"token_url,omitempty"`
	UserinfoURL       string                     `json:"userinfo_url,omitempty"`
	JWKSURL           string                     `json:"jwks_url,omitempty"`
	Scopes            string                     `json:"scopes,omitempty"`
	RedirectURL       string                     `json:"redirect_url,omitempty"`
	AutoProvision     bool                       `json:"auto_provision"`
	DefaultRole       string                     `json:"default_role,omitempty"`
	DomainAllowlist   string                     `json:"domain_allowlist,omitempty"`
	IconURL           string                     `json:"icon_url,omitempty"`
	ButtonColor       string                     `json:"button_color,omitempty"`
	ButtonTextColor   string                     `json:"button_text_color,omitempty"`
	DisplayOrder      int                        `json:"display_order"`
	LinkedUsersCount  int                        `json:"linked_users_count,omitempty"`
	LoginCount24h     int                        `json:"login_count_24h,omitempty"`
	CreatedAt         time.Time                  `json:"created_at"`
	UpdatedAt         time.Time                  `json:"updated_at"`
}

// AdminSSOLinkResponse represents an SSO link in admin responses.
type AdminSSOLinkResponse struct {
	ID            int64      `json:"id"`
	UserID        int64      `json:"user_id"`
	Username      string     `json:"username"`
	Email         string     `json:"email"`
	ProviderID    int64      `json:"provider_id"`
	ProviderSlug  string     `json:"provider_slug"`
	ProviderName  string     `json:"provider_name"`
	ExternalID    string     `json:"external_id"`
	ExternalEmail string     `json:"external_email,omitempty"`
	ExternalName  string     `json:"external_name,omitempty"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// AdminListSSOProvidersHandler returns a handler that lists all SSO providers with stats.
// GET /admin/api/sso/providers
// Requires admin authentication.
func AdminListSSOProvidersHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Get all providers with stats
		providersWithStats, err := repos.SSO.ListProvidersWithStats(ctx)
		if err != nil {
			slog.Error("admin failed to list SSO providers",
				"error", err,
				"ip", clientIP,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Convert to response format
		providers := make([]AdminSSOProviderResponse, 0, len(providersWithStats))
		for _, p := range providersWithStats {
			providers = append(providers, AdminSSOProviderResponse{
				ID:               p.ID,
				Name:             p.Name,
				Slug:             p.Slug,
				Type:             p.Type,
				Enabled:          p.Enabled,
				IssuerURL:        p.IssuerURL,
				ClientID:         p.ClientID,
				AuthorizationURL: p.AuthorizationURL,
				TokenURL:         p.TokenURL,
				UserinfoURL:      p.UserinfoURL,
				JWKSURL:          p.JWKSURL,
				Scopes:           p.Scopes,
				RedirectURL:      p.RedirectURL,
				AutoProvision:    p.AutoProvision,
				DefaultRole:      p.DefaultRole,
				DomainAllowlist:  p.DomainAllowlist,
				IconURL:          p.IconURL,
				ButtonColor:      p.ButtonColor,
				ButtonTextColor:  p.ButtonTextColor,
				DisplayOrder:     p.DisplayOrder,
				LinkedUsersCount: p.LinkedUsersCount,
				LoginCount24h:    p.LoginCount24h,
				CreatedAt:        p.CreatedAt,
				UpdatedAt:        p.UpdatedAt,
			})
		}

		slog.Info("admin listed SSO providers",
			"count", len(providers),
			"ip", clientIP,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"providers":   providers,
			"total_count": len(providers),
		})
	}
}

// AdminCreateSSOProviderHandler returns a handler that creates a new SSO provider.
// POST /admin/api/sso/providers
// Requires admin authentication + CSRF.
func AdminCreateSSOProviderHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Limit request body size
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

		var input repository.CreateSSOProviderInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			slog.Error("admin failed to parse SSO provider create request",
				"error", err,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate required fields
		if input.Name == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Name is required",
			})
			return
		}

		if input.Slug == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Slug is required",
			})
			return
		}

		// Validate slug format
		if !providerSlugRegex.MatchString(input.Slug) || len(input.Slug) > 64 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Slug must be lowercase alphanumeric with hyphens, 1-64 characters",
			})
			return
		}

		if input.IssuerURL == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Issuer URL is required",
			})
			return
		}

		if input.ClientID == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Client ID is required",
			})
			return
		}

		// Set defaults
		if input.Type == "" {
			input.Type = repository.SSOProviderTypeOIDC
		}

		if input.DefaultRole == "" {
			input.DefaultRole = "user"
		}

		// Create the provider
		provider, err := repos.SSO.CreateProvider(ctx, &input)
		if err != nil {
			if errors.Is(err, repository.ErrSSOProviderSlugExists) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "A provider with this slug already exists",
				})
				return
			}

			slog.Error("admin failed to create SSO provider",
				"name", input.Name,
				"slug", input.Slug,
				"error", err,
				"ip", clientIP,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("admin created SSO provider",
			"provider_id", provider.ID,
			"name", provider.Name,
			"slug", provider.Slug,
			"ip", clientIP,
		)

		// Return created provider
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(AdminSSOProviderResponse{
			ID:               provider.ID,
			Name:             provider.Name,
			Slug:             provider.Slug,
			Type:             provider.Type,
			Enabled:          provider.Enabled,
			IssuerURL:        provider.IssuerURL,
			ClientID:         provider.ClientID,
			AuthorizationURL: provider.AuthorizationURL,
			TokenURL:         provider.TokenURL,
			UserinfoURL:      provider.UserinfoURL,
			JWKSURL:          provider.JWKSURL,
			Scopes:           provider.Scopes,
			RedirectURL:      provider.RedirectURL,
			AutoProvision:    provider.AutoProvision,
			DefaultRole:      provider.DefaultRole,
			DomainAllowlist:  provider.DomainAllowlist,
			IconURL:          provider.IconURL,
			ButtonColor:      provider.ButtonColor,
			ButtonTextColor:  provider.ButtonTextColor,
			DisplayOrder:     provider.DisplayOrder,
			CreatedAt:        provider.CreatedAt,
			UpdatedAt:        provider.UpdatedAt,
		})
	}
}

// AdminGetSSOProviderHandler returns a handler that gets a specific SSO provider.
// GET /admin/api/sso/providers/{id}
// Requires admin authentication.
func AdminGetSSOProviderHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Extract provider ID from path
		providerID, err := extractProviderIDFromPath(r.URL.Path, "/admin/api/sso/providers/")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid provider ID",
			})
			return
		}

		// Get the provider
		provider, err := repos.SSO.GetProvider(ctx, providerID)
		if err != nil {
			if errors.Is(err, repository.ErrSSOProviderNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Provider not found",
				})
				return
			}
			slog.Error("admin failed to get SSO provider",
				"provider_id", providerID,
				"error", err,
				"ip", clientIP,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get linked users count
		linkedCount, err := repos.SSO.CountLinksByProviderID(ctx, providerID)
		if err != nil {
			slog.Error("failed to count SSO links",
				"provider_id", providerID,
				"error", err,
			)
			linkedCount = 0
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AdminSSOProviderResponse{
			ID:               provider.ID,
			Name:             provider.Name,
			Slug:             provider.Slug,
			Type:             provider.Type,
			Enabled:          provider.Enabled,
			IssuerURL:        provider.IssuerURL,
			ClientID:         provider.ClientID,
			AuthorizationURL: provider.AuthorizationURL,
			TokenURL:         provider.TokenURL,
			UserinfoURL:      provider.UserinfoURL,
			JWKSURL:          provider.JWKSURL,
			Scopes:           provider.Scopes,
			RedirectURL:      provider.RedirectURL,
			AutoProvision:    provider.AutoProvision,
			DefaultRole:      provider.DefaultRole,
			DomainAllowlist:  provider.DomainAllowlist,
			IconURL:          provider.IconURL,
			ButtonColor:      provider.ButtonColor,
			ButtonTextColor:  provider.ButtonTextColor,
			DisplayOrder:     provider.DisplayOrder,
			LinkedUsersCount: int(linkedCount),
			CreatedAt:        provider.CreatedAt,
			UpdatedAt:        provider.UpdatedAt,
		})
	}
}

// AdminUpdateSSOProviderHandler returns a handler that updates an SSO provider.
// PUT /admin/api/sso/providers/{id}
// Requires admin authentication + CSRF.
func AdminUpdateSSOProviderHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Extract provider ID from path
		providerID, err := extractProviderIDFromPath(r.URL.Path, "/admin/api/sso/providers/")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid provider ID",
			})
			return
		}

		// Limit request body size
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

		var input repository.UpdateSSOProviderInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			slog.Error("admin failed to parse SSO provider update request",
				"error", err,
				"ip", clientIP,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Update the provider
		provider, err := repos.SSO.UpdateProvider(ctx, providerID, &input)
		if err != nil {
			if errors.Is(err, repository.ErrSSOProviderNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Provider not found",
				})
				return
			}
			slog.Error("admin failed to update SSO provider",
				"provider_id", providerID,
				"error", err,
				"ip", clientIP,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("admin updated SSO provider",
			"provider_id", providerID,
			"name", provider.Name,
			"ip", clientIP,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AdminSSOProviderResponse{
			ID:               provider.ID,
			Name:             provider.Name,
			Slug:             provider.Slug,
			Type:             provider.Type,
			Enabled:          provider.Enabled,
			IssuerURL:        provider.IssuerURL,
			ClientID:         provider.ClientID,
			AuthorizationURL: provider.AuthorizationURL,
			TokenURL:         provider.TokenURL,
			UserinfoURL:      provider.UserinfoURL,
			JWKSURL:          provider.JWKSURL,
			Scopes:           provider.Scopes,
			RedirectURL:      provider.RedirectURL,
			AutoProvision:    provider.AutoProvision,
			DefaultRole:      provider.DefaultRole,
			DomainAllowlist:  provider.DomainAllowlist,
			IconURL:          provider.IconURL,
			ButtonColor:      provider.ButtonColor,
			ButtonTextColor:  provider.ButtonTextColor,
			DisplayOrder:     provider.DisplayOrder,
			CreatedAt:        provider.CreatedAt,
			UpdatedAt:        provider.UpdatedAt,
		})
	}
}

// AdminDeleteSSOProviderHandler returns a handler that deletes an SSO provider.
// DELETE /admin/api/sso/providers/{id}
// Requires admin authentication + CSRF.
func AdminDeleteSSOProviderHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Extract provider ID from path
		providerID, err := extractProviderIDFromPath(r.URL.Path, "/admin/api/sso/providers/")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid provider ID",
			})
			return
		}

		// Get provider info for logging
		provider, err := repos.SSO.GetProvider(ctx, providerID)
		if err != nil {
			if errors.Is(err, repository.ErrSSOProviderNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Provider not found",
				})
				return
			}
			slog.Error("admin failed to get SSO provider for deletion",
				"provider_id", providerID,
				"error", err,
				"ip", clientIP,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Delete the provider (cascades to links)
		if err := repos.SSO.DeleteProvider(ctx, providerID); err != nil {
			if errors.Is(err, repository.ErrSSOProviderNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Provider not found",
				})
				return
			}
			slog.Error("admin failed to delete SSO provider",
				"provider_id", providerID,
				"error", err,
				"ip", clientIP,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("admin deleted SSO provider",
			"provider_id", providerID,
			"name", provider.Name,
			"slug", provider.Slug,
			"ip", clientIP,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Provider deleted successfully",
		})
	}
}

// AdminTestSSOProviderHandler returns a handler that tests an SSO provider's OIDC connection.
// POST /admin/api/sso/providers/{id}/test
// Requires admin authentication + CSRF.
func AdminTestSSOProviderHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Extract provider ID from path (remove /test suffix)
		path := strings.TrimSuffix(r.URL.Path, "/test")
		providerID, err := extractProviderIDFromPath(path, "/admin/api/sso/providers/")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid provider ID",
			})
			return
		}

		// Get the provider
		provider, err := repos.SSO.GetProvider(ctx, providerID)
		if err != nil {
			if errors.Is(err, repository.ErrSSOProviderNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Provider not found",
				})
				return
			}
			slog.Error("admin failed to get SSO provider for test",
				"provider_id", providerID,
				"error", err,
				"ip", clientIP,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Test the OIDC connection by creating provider instance
		startTime := time.Now()
		_, err = sso.NewOIDCProvider(ctx, provider, repos.SSO)
		testDuration := time.Since(startTime)

		testResult := map[string]interface{}{
			"provider_id":   providerID,
			"provider_name": provider.Name,
			"issuer_url":    provider.IssuerURL,
			"test_duration": testDuration.String(),
		}

		if err != nil {
			slog.Warn("admin SSO provider test failed",
				"provider_id", providerID,
				"name", provider.Name,
				"error", err,
				"ip", clientIP,
			)

			testResult["success"] = false
			testResult["error"] = err.Error()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK) // Return 200 but with success=false
			json.NewEncoder(w).Encode(testResult)
			return
		}

		slog.Info("admin SSO provider test successful",
			"provider_id", providerID,
			"name", provider.Name,
			"duration", testDuration,
			"ip", clientIP,
		)

		testResult["success"] = true
		testResult["message"] = "OIDC discovery successful"

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testResult)
	}
}

// AdminListSSOLinksHandler returns a handler that lists all SSO links with pagination.
// GET /admin/api/sso/links?page=1&per_page=50&provider_id=1
// Requires admin authentication.
func AdminListSSOLinksHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Parse pagination parameters
		page := 1
		perPage := 50
		var providerID int64

		if pageStr := r.URL.Query().Get("page"); pageStr != "" {
			if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
				page = p
			}
		}

		if perPageStr := r.URL.Query().Get("per_page"); perPageStr != "" {
			if pp, err := strconv.Atoi(perPageStr); err == nil && pp > 0 && pp <= 100 {
				perPage = pp
			}
		}

		if providerIDStr := r.URL.Query().Get("provider_id"); providerIDStr != "" {
			if pid, err := strconv.ParseInt(providerIDStr, 10, 64); err == nil && pid > 0 {
				providerID = pid
			}
		}

		// Get all links (we'll filter and paginate in memory for now)
		// In a production system, you'd want proper SQL pagination
		var allLinks []repository.UserSSOLink
		var err error

		if providerID > 0 {
			allLinks, err = repos.SSO.GetLinksByProviderID(ctx, providerID)
		} else {
			// Get all links by iterating through providers
			providers, pErr := repos.SSO.ListProviders(ctx, false)
			if pErr != nil {
				slog.Error("admin failed to list providers for SSO links",
					"error", pErr,
					"ip", clientIP,
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			allLinks = []repository.UserSSOLink{}
			for _, provider := range providers {
				links, lErr := repos.SSO.GetLinksByProviderID(ctx, provider.ID)
				if lErr != nil {
					continue
				}
				allLinks = append(allLinks, links...)
			}
		}

		if err != nil {
			slog.Error("admin failed to list SSO links",
				"error", err,
				"ip", clientIP,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Calculate pagination
		totalCount := len(allLinks)
		start := (page - 1) * perPage
		end := start + perPage
		if start > totalCount {
			start = totalCount
		}
		if end > totalCount {
			end = totalCount
		}

		pagedLinks := allLinks[start:end]

		// Build response with user and provider info
		linkResponses := make([]AdminSSOLinkResponse, 0, len(pagedLinks))
		for _, link := range pagedLinks {
			// Get user info
			user, err := repos.Users.GetByID(ctx, link.UserID)
			username := "unknown"
			email := ""
			if err == nil && user != nil {
				username = user.Username
				email = user.Email
			}

			// Get provider info
			provider, err := repos.SSO.GetProvider(ctx, link.ProviderID)
			providerSlug := "unknown"
			providerName := "Unknown Provider"
			if err == nil && provider != nil {
				providerSlug = provider.Slug
				providerName = provider.Name
			}

			linkResponses = append(linkResponses, AdminSSOLinkResponse{
				ID:            link.ID,
				UserID:        link.UserID,
				Username:      username,
				Email:         email,
				ProviderID:    link.ProviderID,
				ProviderSlug:  providerSlug,
				ProviderName:  providerName,
				ExternalID:    link.ExternalID,
				ExternalEmail: link.ExternalEmail,
				ExternalName:  link.ExternalName,
				LastLoginAt:   link.LastLoginAt,
				CreatedAt:     link.CreatedAt,
			})
		}

		slog.Info("admin listed SSO links",
			"count", len(linkResponses),
			"page", page,
			"ip", clientIP,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"links":       linkResponses,
			"page":        page,
			"per_page":    perPage,
			"total_count": totalCount,
			"total_pages": (totalCount + perPage - 1) / perPage,
		})
	}
}

// AdminDeleteSSOLinkHandler returns a handler that deletes an SSO link (admin unlink).
// DELETE /admin/api/sso/links/{id}
// Requires admin authentication + CSRF.
func AdminDeleteSSOLinkHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Extract link ID from path
		linkID, err := extractLinkIDFromPath(r.URL.Path, "/admin/api/sso/links/")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid link ID",
			})
			return
		}

		// Get link info for logging
		link, err := repos.SSO.GetLink(ctx, linkID)
		if err != nil {
			if errors.Is(err, repository.ErrSSOLinkNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "SSO link not found",
				})
				return
			}
			slog.Error("admin failed to get SSO link for deletion",
				"link_id", linkID,
				"error", err,
				"ip", clientIP,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Delete the link
		if err := repos.SSO.DeleteLink(ctx, linkID); err != nil {
			if errors.Is(err, repository.ErrSSOLinkNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "SSO link not found",
				})
				return
			}
			slog.Error("admin failed to delete SSO link",
				"link_id", linkID,
				"error", err,
				"ip", clientIP,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("admin deleted SSO link",
			"link_id", linkID,
			"user_id", link.UserID,
			"provider_id", link.ProviderID,
			"external_id", link.ExternalID,
			"ip", clientIP,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "SSO link deleted successfully",
		})
	}
}

// extractProviderIDFromPath extracts the provider ID from a URL path.
func extractProviderIDFromPath(path, prefix string) (int64, error) {
	if !strings.HasPrefix(path, prefix) {
		return 0, errors.New("invalid path")
	}

	idStr := strings.TrimPrefix(path, prefix)
	// Remove any trailing path segments
	if idx := strings.Index(idStr, "/"); idx >= 0 {
		idStr = idStr[:idx]
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid ID")
	}

	return id, nil
}

// extractLinkIDFromPath extracts the link ID from a URL path.
func extractLinkIDFromPath(path, prefix string) (int64, error) {
	return extractProviderIDFromPath(path, prefix)
}
