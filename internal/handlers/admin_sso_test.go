package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestExtractProviderIDFromPath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		prefix    string
		wantID    int64
		wantError bool
	}{
		{
			name:      "valid ID",
			path:      "/admin/api/sso/providers/123",
			prefix:    "/admin/api/sso/providers/",
			wantID:    123,
			wantError: false,
		},
		{
			name:      "valid ID with trailing segment",
			path:      "/admin/api/sso/providers/456/test",
			prefix:    "/admin/api/sso/providers/",
			wantID:    456,
			wantError: false,
		},
		{
			name:      "invalid path prefix",
			path:      "/wrong/prefix/123",
			prefix:    "/admin/api/sso/providers/",
			wantID:    0,
			wantError: true,
		},
		{
			name:      "invalid ID format",
			path:      "/admin/api/sso/providers/abc",
			prefix:    "/admin/api/sso/providers/",
			wantID:    0,
			wantError: true,
		},
		{
			name:      "zero ID",
			path:      "/admin/api/sso/providers/0",
			prefix:    "/admin/api/sso/providers/",
			wantID:    0,
			wantError: true,
		},
		{
			name:      "negative ID",
			path:      "/admin/api/sso/providers/-1",
			prefix:    "/admin/api/sso/providers/",
			wantID:    0,
			wantError: true,
		},
		{
			name:      "empty ID",
			path:      "/admin/api/sso/providers/",
			prefix:    "/admin/api/sso/providers/",
			wantID:    0,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := extractProviderIDFromPath(tt.path, tt.prefix)
			if (err != nil) != tt.wantError {
				t.Errorf("extractProviderIDFromPath() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if id != tt.wantID {
				t.Errorf("extractProviderIDFromPath() = %v, want %v", id, tt.wantID)
			}
		})
	}
}

func TestExtractLinkIDFromPath(t *testing.T) {
	// Since extractLinkIDFromPath is an alias for extractProviderIDFromPath,
	// we just test a basic case
	id, err := extractLinkIDFromPath("/admin/api/sso/links/789", "/admin/api/sso/links/")
	if err != nil {
		t.Errorf("extractLinkIDFromPath() error = %v", err)
	}
	if id != 789 {
		t.Errorf("extractLinkIDFromPath() = %v, want 789", id)
	}
}

// =============================================================================
// AdminListSSOProvidersHandler Tests
// =============================================================================

func TestAdminListSSOProvidersHandler_Success(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create test providers
	_, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	_, err = repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "GitHub",
		Slug:      "github",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   false,
		ClientID:  "test-client-id-2",
		IssuerURL: "https://github.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	handler := AdminListSSOProvidersHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/sso/providers", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	totalCount := int(resp["total_count"].(float64))
	if totalCount != 2 {
		t.Errorf("total_count = %d, want 2", totalCount)
	}

	providers := resp["providers"].([]interface{})
	if len(providers) != 2 {
		t.Errorf("providers count = %d, want 2", len(providers))
	}
}

func TestAdminListSSOProvidersHandler_Empty(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminListSSOProvidersHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/sso/providers", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if int(resp["total_count"].(float64)) != 0 {
		t.Error("expected 0 providers")
	}
}

func TestAdminListSSOProvidersHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := AdminListSSOProvidersHandler(repos, cfg)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/sso/providers", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// AdminCreateSSOProviderHandler Tests
// =============================================================================

func TestAdminCreateSSOProviderHandler_Success(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminCreateSSOProviderHandler(repos, cfg)

	input := repository.CreateSSOProviderInput{
		Name:        "Google",
		Slug:        "google",
		Type:        repository.SSOProviderTypeOIDC,
		Enabled:     true,
		ClientID:    "test-client-id",
		IssuerURL:   "https://accounts.google.com",
		DefaultRole: "user",
	}

	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/sso/providers", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusCreated)

	var resp AdminSSOProviderResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Name != "Google" {
		t.Errorf("provider name = %q, want Google", resp.Name)
	}
	if resp.Slug != "google" {
		t.Errorf("provider slug = %q, want google", resp.Slug)
	}
}

func TestAdminCreateSSOProviderHandler_ValidationErrors(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminCreateSSOProviderHandler(repos, cfg)

	tests := []struct {
		name       string
		input      repository.CreateSSOProviderInput
		wantStatus int
		wantError  string
	}{
		{
			name:       "missing name",
			input:      repository.CreateSSOProviderInput{Slug: "google", ClientID: "id", IssuerURL: "https://google.com"},
			wantStatus: http.StatusBadRequest,
			wantError:  "Name is required",
		},
		{
			name:       "missing slug",
			input:      repository.CreateSSOProviderInput{Name: "Google", ClientID: "id", IssuerURL: "https://google.com"},
			wantStatus: http.StatusBadRequest,
			wantError:  "Slug is required",
		},
		{
			name:       "invalid slug format",
			input:      repository.CreateSSOProviderInput{Name: "Google", Slug: "GOOGLE", ClientID: "id", IssuerURL: "https://google.com"},
			wantStatus: http.StatusBadRequest,
			wantError:  "Slug must be lowercase",
		},
		{
			name:       "missing issuer URL",
			input:      repository.CreateSSOProviderInput{Name: "Google", Slug: "google", ClientID: "id"},
			wantStatus: http.StatusBadRequest,
			wantError:  "Issuer URL is required",
		},
		{
			name:       "missing client ID",
			input:      repository.CreateSSOProviderInput{Name: "Google", Slug: "google", IssuerURL: "https://google.com"},
			wantStatus: http.StatusBadRequest,
			wantError:  "Client ID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.input)
			req := httptest.NewRequest(http.MethodPost, "/admin/api/sso/providers", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, tt.wantStatus)
			testutil.AssertContains(t, rr.Body.String(), tt.wantError)
		})
	}
}

func TestAdminCreateSSOProviderHandler_DuplicateSlug(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create existing provider
	_, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "existing-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create existing provider: %v", err)
	}

	handler := AdminCreateSSOProviderHandler(repos, cfg)

	input := repository.CreateSSOProviderInput{
		Name:      "Another Google",
		Slug:      "google", // Duplicate
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "new-client-id",
		IssuerURL: "https://accounts.google.com",
	}

	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/sso/providers", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusConflict)
	testutil.AssertContains(t, rr.Body.String(), "slug already exists")
}

func TestAdminCreateSSOProviderHandler_InvalidJSON(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminCreateSSOProviderHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/sso/providers", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

func TestAdminCreateSSOProviderHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := AdminCreateSSOProviderHandler(repos, cfg)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/sso/providers", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// AdminGetSSOProviderHandler Tests
// =============================================================================

func TestAdminGetSSOProviderHandler_Success(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	provider, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	handler := AdminGetSSOProviderHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/sso/providers/"+strconv.FormatInt(provider.ID, 10), nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp AdminSSOProviderResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.ID != provider.ID {
		t.Errorf("provider ID = %d, want %d", resp.ID, provider.ID)
	}
	if resp.Name != "Google" {
		t.Errorf("provider name = %q, want Google", resp.Name)
	}
}

func TestAdminGetSSOProviderHandler_NotFound(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminGetSSOProviderHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/sso/providers/99999", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

func TestAdminGetSSOProviderHandler_InvalidID(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminGetSSOProviderHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/sso/providers/invalid", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

func TestAdminGetSSOProviderHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := AdminGetSSOProviderHandler(repos, cfg)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/sso/providers/1", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// AdminUpdateSSOProviderHandler Tests
// =============================================================================

func TestAdminUpdateSSOProviderHandler_Success(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	provider, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	handler := AdminUpdateSSOProviderHandler(repos, cfg)

	newName := "Updated Google"
	enabled := false
	input := repository.UpdateSSOProviderInput{
		Name:    &newName,
		Enabled: &enabled,
	}

	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPut, "/admin/api/sso/providers/"+strconv.FormatInt(provider.ID, 10), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp AdminSSOProviderResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Name != "Updated Google" {
		t.Errorf("provider name = %q, want Updated Google", resp.Name)
	}
	if resp.Enabled {
		t.Error("provider should be disabled")
	}
}

func TestAdminUpdateSSOProviderHandler_NotFound(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminUpdateSSOProviderHandler(repos, cfg)

	newName := "Updated"
	input := repository.UpdateSSOProviderInput{Name: &newName}

	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPut, "/admin/api/sso/providers/99999", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

func TestAdminUpdateSSOProviderHandler_InvalidJSON(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	provider, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	handler := AdminUpdateSSOProviderHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPut, "/admin/api/sso/providers/"+strconv.FormatInt(provider.ID, 10), bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

func TestAdminUpdateSSOProviderHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := AdminUpdateSSOProviderHandler(repos, cfg)

	methods := []string{http.MethodGet, http.MethodPost, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/sso/providers/1", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// AdminDeleteSSOProviderHandler Tests
// =============================================================================

func TestAdminDeleteSSOProviderHandler_Success(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	provider, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	handler := AdminDeleteSSOProviderHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/sso/providers/"+strconv.FormatInt(provider.ID, 10), nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Verify provider is deleted
	_, err = repos.SSO.GetProvider(ctx, provider.ID)
	if err == nil {
		t.Error("expected provider to be deleted")
	}
}

func TestAdminDeleteSSOProviderHandler_NotFound(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminDeleteSSOProviderHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/sso/providers/99999", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

func TestAdminDeleteSSOProviderHandler_CascadeDeletesLinks(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create provider
	provider, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create link
	_, err = repos.SSO.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:        user.ID,
		ProviderID:    provider.ID,
		ExternalID:    "google-user-123",
		ExternalEmail: "test@gmail.com",
	})
	if err != nil {
		t.Fatalf("failed to create link: %v", err)
	}

	handler := AdminDeleteSSOProviderHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/sso/providers/"+strconv.FormatInt(provider.ID, 10), nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Verify links are deleted
	links, err := repos.SSO.GetLinksByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to get links: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("expected 0 links after cascade delete, got %d", len(links))
	}
}

func TestAdminDeleteSSOProviderHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := AdminDeleteSSOProviderHandler(repos, cfg)

	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/sso/providers/1", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// AdminTestSSOProviderHandler Tests
// =============================================================================

func TestAdminTestSSOProviderHandler_NotFound(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminTestSSOProviderHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/sso/providers/99999/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

func TestAdminTestSSOProviderHandler_InvalidID(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminTestSSOProviderHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/sso/providers/invalid/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

func TestAdminTestSSOProviderHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := AdminTestSSOProviderHandler(repos, cfg)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/sso/providers/1/test", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// AdminListSSOLinksHandler Tests
// =============================================================================

func TestAdminListSSOLinksHandler_Empty(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminListSSOLinksHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/sso/links", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if int(resp["total_count"].(float64)) != 0 {
		t.Error("expected 0 links")
	}
}

func TestAdminListSSOLinksHandler_WithLinks(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create provider
	provider, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Create users
	passwordHash, _ := utils.HashPassword("password123")
	user1, err := repos.Users.Create(ctx, "user1", "user1@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user1: %v", err)
	}
	user2, err := repos.Users.Create(ctx, "user2", "user2@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user2: %v", err)
	}

	// Create links
	_, err = repos.SSO.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:        user1.ID,
		ProviderID:    provider.ID,
		ExternalID:    "google-user-1",
		ExternalEmail: "user1@gmail.com",
	})
	if err != nil {
		t.Fatalf("failed to create link 1: %v", err)
	}

	_, err = repos.SSO.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:        user2.ID,
		ProviderID:    provider.ID,
		ExternalID:    "google-user-2",
		ExternalEmail: "user2@gmail.com",
	})
	if err != nil {
		t.Fatalf("failed to create link 2: %v", err)
	}

	handler := AdminListSSOLinksHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/sso/links", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if int(resp["total_count"].(float64)) != 2 {
		t.Errorf("total_count = %v, want 2", resp["total_count"])
	}
}

func TestAdminListSSOLinksHandler_Pagination(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminListSSOLinksHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/sso/links?page=2&per_page=10", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if int(resp["page"].(float64)) != 2 {
		t.Errorf("page = %v, want 2", resp["page"])
	}
	if int(resp["per_page"].(float64)) != 10 {
		t.Errorf("per_page = %v, want 10", resp["per_page"])
	}
}

func TestAdminListSSOLinksHandler_FilterByProvider(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create providers
	provider1, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id-1",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider1: %v", err)
	}

	provider2, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "GitHub",
		Slug:      "github",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id-2",
		IssuerURL: "https://github.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider2: %v", err)
	}

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create links to both providers
	_, err = repos.SSO.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:        user.ID,
		ProviderID:    provider1.ID,
		ExternalID:    "google-user-123",
		ExternalEmail: "test@gmail.com",
	})
	if err != nil {
		t.Fatalf("failed to create google link: %v", err)
	}

	_, err = repos.SSO.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:        user.ID,
		ProviderID:    provider2.ID,
		ExternalID:    "github-user-123",
		ExternalEmail: "test@github.com",
	})
	if err != nil {
		t.Fatalf("failed to create github link: %v", err)
	}

	handler := AdminListSSOLinksHandler(repos, cfg)

	// Filter by provider1 ID
	req := httptest.NewRequest(http.MethodGet, "/admin/api/sso/links?provider_id="+strconv.FormatInt(provider1.ID, 10), nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if int(resp["total_count"].(float64)) != 1 {
		t.Errorf("total_count = %v, want 1 (filtered by provider)", resp["total_count"])
	}
}

func TestAdminListSSOLinksHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := AdminListSSOLinksHandler(repos, cfg)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/sso/links", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// AdminDeleteSSOLinkHandler Tests
// =============================================================================

func TestAdminDeleteSSOLinkHandler_Success(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create provider
	provider, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Create user
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create link
	link, err := repos.SSO.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:        user.ID,
		ProviderID:    provider.ID,
		ExternalID:    "google-user-123",
		ExternalEmail: "test@gmail.com",
	})
	if err != nil {
		t.Fatalf("failed to create link: %v", err)
	}

	handler := AdminDeleteSSOLinkHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/sso/links/"+strconv.FormatInt(link.ID, 10), nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	// Verify link is deleted
	_, err = repos.SSO.GetLink(ctx, link.ID)
	if err == nil {
		t.Error("expected link to be deleted")
	}
}

func TestAdminDeleteSSOLinkHandler_NotFound(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminDeleteSSOLinkHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/sso/links/99999", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotFound)
}

func TestAdminDeleteSSOLinkHandler_InvalidID(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminDeleteSSOLinkHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/sso/links/invalid", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusBadRequest)
}

func TestAdminDeleteSSOLinkHandler_MethodNotAllowed(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	handler := AdminDeleteSSOLinkHandler(repos, cfg)

	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/sso/links/1", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusMethodNotAllowed)
		})
	}
}

// =============================================================================
// AdminSSOProviderResponse Tests
// =============================================================================

func TestAdminSSOProviderResponse_JSONSerialization(t *testing.T) {
	resp := AdminSSOProviderResponse{
		ID:           1,
		Name:         "Test Provider",
		Slug:         "test",
		Type:         repository.SSOProviderTypeOIDC,
		Enabled:      true,
		IssuerURL:    "https://example.com",
		ClientID:     "client-id",
		DefaultRole:  "user",
		DisplayOrder: 1,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var decoded AdminSSOProviderResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if decoded.ID != resp.ID {
		t.Errorf("ID mismatch: got %d, want %d", decoded.ID, resp.ID)
	}
	if decoded.Name != resp.Name {
		t.Errorf("Name mismatch: got %q, want %q", decoded.Name, resp.Name)
	}
	if decoded.Slug != resp.Slug {
		t.Errorf("Slug mismatch: got %q, want %q", decoded.Slug, resp.Slug)
	}
}

func TestAdminSSOLinkResponse_JSONSerialization(t *testing.T) {
	resp := AdminSSOLinkResponse{
		ID:            1,
		UserID:        2,
		Username:      "testuser",
		Email:         "test@example.com",
		ProviderID:    3,
		ProviderSlug:  "google",
		ProviderName:  "Google",
		ExternalID:    "ext-123",
		ExternalEmail: "test@gmail.com",
		ExternalName:  "Test User",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var decoded AdminSSOLinkResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if decoded.ID != resp.ID {
		t.Errorf("ID mismatch: got %d, want %d", decoded.ID, resp.ID)
	}
	if decoded.Username != resp.Username {
		t.Errorf("Username mismatch: got %q, want %q", decoded.Username, resp.Username)
	}
	if decoded.ExternalEmail != resp.ExternalEmail {
		t.Errorf("ExternalEmail mismatch: got %q, want %q", decoded.ExternalEmail, resp.ExternalEmail)
	}
}

// =============================================================================
// Test Provider Response includes stats
// =============================================================================

func TestAdminListSSOProvidersHandler_IncludesStats(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create provider
	provider, err := repos.SSO.CreateProvider(ctx, &repository.CreateSSOProviderInput{
		Name:      "Google",
		Slug:      "google",
		Type:      repository.SSOProviderTypeOIDC,
		Enabled:   true,
		ClientID:  "test-client-id",
		IssuerURL: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Create user and link
	passwordHash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "testuser", "test@example.com", passwordHash, "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	_, err = repos.SSO.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:        user.ID,
		ProviderID:    provider.ID,
		ExternalID:    "google-user-123",
		ExternalEmail: "test@gmail.com",
	})
	if err != nil {
		t.Fatalf("failed to create link: %v", err)
	}

	handler := AdminListSSOProvidersHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/sso/providers", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	providers := resp["providers"].([]interface{})
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}

	providerData := providers[0].(map[string]interface{})
	linkedUsersCount := int(providerData["linked_users_count"].(float64))
	if linkedUsersCount != 1 {
		t.Errorf("linked_users_count = %d, want 1", linkedUsersCount)
	}
}

// =============================================================================
// Slug Validation in Create Handler
// =============================================================================

func TestAdminCreateSSOProviderHandler_SlugValidation(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	handler := AdminCreateSSOProviderHandler(repos, cfg)

	tests := []struct {
		name       string
		slug       string
		wantStatus int
	}{
		{"valid slug", "google", http.StatusCreated},
		{"valid slug with hyphen", "my-provider", http.StatusCreated},
		{"valid slug with numbers", "provider123", http.StatusCreated},
		{"uppercase rejected", "Google", http.StatusBadRequest},
		{"spaces rejected", "my provider", http.StatusBadRequest},
		{"special chars rejected", "my_provider", http.StatusBadRequest},
		{"empty slug rejected", "", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use unique name to avoid "provider name already exists" errors
			uniqueName := "Test Provider " + tt.slug
			if tt.slug == "" {
				uniqueName = "Test Provider Empty Slug"
			}
			input := repository.CreateSSOProviderInput{
				Name:      uniqueName,
				Slug:      tt.slug,
				Type:      repository.SSOProviderTypeOIDC,
				Enabled:   true,
				ClientID:  "test-client-id-" + tt.slug,
				IssuerURL: "https://example.com",
			}

			body, _ := json.Marshal(input)
			req := httptest.NewRequest(http.MethodPost, "/admin/api/sso/providers", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("slug %q: status = %d, want %d. Body: %s", tt.slug, rr.Code, tt.wantStatus, rr.Body.String())
			}
		})
	}
}
