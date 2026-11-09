package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		scope, allowed := TokenRequirement(c.method, c.path)
		if scope != c.scope || allowed != c.allowed {
			t.Errorf("TokenRequirement(%s %s) = %q, %v; want %q, %v", c.method, c.path, scope, allowed, c.scope, c.allowed)
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
	hash, _ := utils.HashPassword("password123")
	user, err := repos.Users.Create(ctx, "scopeuser", "scope@example.com", hash, "user", false)
	if err != nil {
		t.Fatal(err)
	}
	env := &tokenPolicyEnv{repos: repos, tokens: map[string]string{}}
	expires := time.Now().Add(24 * time.Hour)
	for _, scopes := range []string{"upload", "manage", "download", "upload,manage"} {
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
// the status and, for a refusal, the error code.
func (e *tokenPolicyEnv) call(mw func(http.Handler) http.Handler, method, path, token string) (int, string) {
	reached := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	mw(reached).ServeHTTP(rr, req)
	var body struct {
		Code string `json:"code"`
	}
	json.Unmarshal(rr.Body.Bytes(), &body)
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
	}
	for _, c := range cases {
		status, code := e.call(c.mw, c.method, c.path, e.tokens[c.scopes])
		if status != c.status || code != c.code {
			t.Errorf("%s: got %d %q, want %d %q", c.name, status, code, c.status, c.code)
		}
	}

	// Without a token nothing changes: anonymous uploads still pass where
	// the route allows them.
	if status, _ := e.call(optional, "POST", "/api/upload", ""); status != 200 {
		t.Errorf("anonymous upload: %d, want 200", status)
	}
}

func TestTokenPolicy_CanBeTurnedOff(t *testing.T) {
	SetTokenScopeEnforcement(false)
	t.Cleanup(func() { SetTokenScopeEnforcement(true) })
	e := newTokenPolicyEnv(t)
	if status, _ := e.call(UserAuth(e.repos, false), "GET", "/api/user/files", e.tokens["upload"]); status != 200 {
		t.Errorf("with enforcement off: %d, want 200", status)
	}
}
