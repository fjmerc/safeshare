package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

func TestTokenRequirement(t *testing.T) {
	cases := []struct {
		method, path string
		scope        string
		allowed      bool
	}{
		{"POST", "/api/upload", "upload", true},
		{"POST", "/api/upload/init", "upload", true},
		{"POST", "/api/upload/chunk/abc/0", "upload", true},
		{"POST", "/api/upload/complete/abc", "upload", true},
		{"GET", "/api/upload/status/abc", "upload", true},
		{"GET", "/api/user/files", "manage", true},
		{"DELETE", "/api/user/files/Xk3pQ9aB", "manage", true},
		{"PUT", "/api/user/files/rename", "manage", true},
		{"GET", "/api/tokens", "manage", true},
		{"GET", "/api/auth/user", "", true},
		{"HEAD", "/api/auth/user", "", true}, // HEAD is a GET without a body
		{"HEAD", "/api/tokens", "manage", true},
		// Bundles (several files under one link): creating, publishing and
		// discarding a draft is part of uploading; the owner routes manage.
		{"POST", "/api/bundles", "upload", true},
		{"POST", "/api/bundles/42/publish", "upload", true},
		{"DELETE", "/api/bundles/42", "upload", true},
		{"GET", "/api/user/bundles", "manage", true},
		{"PUT", "/api/user/bundles/42/expiration", "manage", true},
		{"DELETE", "/api/user/bundles/42", "manage", true},
		{"GET", "/api/bundlesx", "", false},
		// Owner downloads read file contents: the download scope, not manage.
		{"GET", "/api/user/files/Xk3pQ9aB/download", "download", true},
		{"HEAD", "/api/user/files/Xk3pQ9aB/download", "download", true},
		{"GET", "/api/user/bundles/42/files/0/download", "download", true},
		{"POST", "/api/user/files/Xk3pQ9aB/download", "manage", true}, // not a download (the handler answers 405)
		{"GET", "/api/user/files/download", "manage", true},            // no file in the path
		{"PUT", "/api/user/files/Xk3pQ9aB/rename", "manage", true},
		// Account security needs a signed-in browser session.
		{"POST", "/api/tokens", "", false},
		{"DELETE", "/api/tokens/5", "", false},
		{"POST", "/api/auth/change-password", "", false},
		{"POST", "/api/auth/logout", "", false},
		{"GET", "/api/user/mfa/status", "", false},
		{"DELETE", "/api/user/mfa/totp", "", false},
		{"POST", "/api/auth/sso/link", "", false},
		{"GET", "/dashboard", "", false},
		// Anything not listed is refused (fail closed), including look-alikes.
		{"POST", "/api/uploadx", "", false},
		{"GET", "/api/user/filesx", "", false},
		{"GET", "/api/something-new", "", false},
	}
	for _, c := range cases {
		scope, allowed := tokenRequirement(c.method, c.path)
		if scope != c.scope || allowed != c.allowed {
			t.Errorf("tokenRequirement(%s %s) = %q, %v; want %q, %v", c.method, c.path, scope, allowed, c.scope, c.allowed)
		}
	}
}

type tokenPolicyEnv struct {
	repos  *repository.Repositories
	tokens map[string]string // scopes -> plaintext token
}

func newTokenPolicyEnv(t *testing.T) *tokenPolicyEnv {
	t.Helper()
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	user, err := repos.Users.Create(ctx, "scopeuser", "scope@example.com", hash, "user", false)
	if err != nil {
		t.Fatal(err)
	}
	env := &tokenPolicyEnv{repos: repos, tokens: map[string]string{}}
	expires := time.Now().Add(24 * time.Hour)
	for _, scopes := range []string{"upload", "manage", "download", "upload,manage", "admin"} {
		plain, prefix, err := utils.GenerateAPIToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repos.APITokens.Create(ctx, user.ID, "t-"+scopes, utils.HashAPIToken(plain), prefix, scopes, "127.0.0.1", &expires); err != nil {
			t.Fatal(err)
		}
		env.tokens[scopes] = plain
	}
	return env
}

// call runs method path through mw with the given bearer token and returns
// the status and, for a refusal, the error code. A refusal must be a JSON
// error with a message.
func (e *tokenPolicyEnv) call(t *testing.T, mw func(http.Handler) http.Handler, method, path, token string) (int, string) {
	t.Helper()
	reached := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	mw(reached).ServeHTTP(rr, req)
	var body struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code == http.StatusForbidden {
		if ct := rr.Header().Get("Content-Type"); ct != "application/json" || body.Error == "" {
			t.Errorf("%s %s: refusal is not a JSON error (Content-Type %q, body %q)", method, path, ct, rr.Body.String())
		}
		// The Go SDK masks messages that mention tokens; keep the useful part visible.
		if strings.Contains(strings.ToLower(body.Error), "token") {
			t.Errorf("%s %s: refusal message %q would be masked by the SDK", method, path, body.Error)
		}
	}
	return rr.Code, body.Code
}

func TestTokenPolicy_Enforced(t *testing.T) {
	e := newTokenPolicyEnv(t)
	required := UserAuth(e.repos, false)
	optional := OptionalUserAuth(e.repos, false)

	cases := []struct {
		name         string
		mw           func(http.Handler) http.Handler
		method, path string
		scopes       string
		status       int
		code         string
	}{
		{"upload token uploads", optional, "POST", "/api/upload", "upload", 200, ""},
		{"manage token can't upload", optional, "POST", "/api/upload", "manage", 403, "INSUFFICIENT_SCOPE"},
		{"download token can't upload", optional, "POST", "/api/upload/init", "download", 403, "INSUFFICIENT_SCOPE"},
		{"manage token lists files", required, "GET", "/api/user/files", "manage", 200, ""},
		{"upload token can't list files", required, "GET", "/api/user/files", "upload", 403, "INSUFFICIENT_SCOPE"},
		{"upload token can't delete files", required, "DELETE", "/api/user/files/Xk3pQ9aB", "upload", 403, "INSUFFICIENT_SCOPE"},
		{"any token reads who it is", required, "GET", "/api/auth/user", "download", 200, ""},
		{"no token changes the password", required, "POST", "/api/auth/change-password", "upload,manage", 403, "SESSION_REQUIRED"},
		{"no token touches MFA", required, "DELETE", "/api/user/mfa/totp", "upload,manage", 403, "SESSION_REQUIRED"},
		{"no token links SSO", required, "POST", "/api/auth/sso/link", "upload,manage", 403, "SESSION_REQUIRED"},
		{"admin scope implies the others", required, "GET", "/api/user/files", "admin", 200, ""},
		{"admin scope still can't change the password", required, "POST", "/api/auth/change-password", "admin", 403, "SESSION_REQUIRED"},
	}
	for _, c := range cases {
		status, code := e.call(t, c.mw, c.method, c.path, e.tokens[c.scopes])
		if status != c.status || code != c.code {
			t.Errorf("%s: got %d %q, want %d %q", c.name, status, code, c.status, c.code)
		}
	}

	// Without a token nothing changes: anonymous uploads still pass where
	// the route allows them.
	if status, _ := e.call(t, optional, "POST", "/api/upload", ""); status != 200 {
		t.Errorf("anonymous upload: %d, want 200", status)
	}
}

// TestTokenPolicy_OptOutRelaxesScopesOnly: ENFORCE_API_TOKEN_SCOPES=false
// lets tokens use routes regardless of scope, but account security
// (password, MFA, SSO, token management) stays browser-session only.
// (This flips a package-level switch: tests here must not run in parallel.)
func TestTokenPolicy_OptOutRelaxesScopesOnly(t *testing.T) {
	SetTokenScopeEnforcement(false)
	t.Cleanup(func() { SetTokenScopeEnforcement(true) })
	e := newTokenPolicyEnv(t)
	if status, _ := e.call(t, UserAuth(e.repos, false), "GET", "/api/user/files", e.tokens["upload"]); status != 200 {
		t.Errorf("scope check with enforcement off: %d, want 200", status)
	}
	if status, code := e.call(t, UserAuth(e.repos, false), "GET", "/api/user/mfa/status", e.tokens["upload,manage"]); status != 403 || code != "SESSION_REQUIRED" {
		t.Errorf("session-only route with enforcement off: %d %q, want 403 SESSION_REQUIRED", status, code)
	}
}
