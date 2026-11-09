package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/fjmerc/safeshare/internal/utils"
)

// API token scopes are enforced here, once, right after a Bearer token is
// recognised - not per route - so a route added later can't become reachable
// by tokens by accident. The policy table below lists every path a token may
// use and the scope it needs; any other path (account security: password,
// MFA, SSO, token management, logout, pages) needs a signed-in browser
// session. Browser sessions and anonymous requests are not affected.

// tokenScopesEnforced is on unless ENFORCE_API_TOKEN_SCOPES=false (fail closed).
var tokenScopesEnforced atomic.Bool

func init() { tokenScopesEnforced.Store(true) }

// SetTokenScopeEnforcement turns API token scope enforcement on or off
// (ENFORCE_API_TOKEN_SCOPES). Off restores the old behavior, in which any
// valid token could use any route its user could.
func SetTokenScopeEnforcement(enforce bool) { tokenScopesEnforced.Store(enforce) }

// tokenRule is one entry of the token policy: a path (exact, or a prefix
// ending in "/"), optionally limited to one method, and the scope it needs
// ("" = any valid token).
type tokenRule struct {
	method string // "" = any method
	path   string // ends in "/" for a prefix
	scope  string
}

var tokenPolicy = []tokenRule{
	{"", "/api/upload", utils.ScopeUpload},
	{"", "/api/upload/init", utils.ScopeUpload},
	{"", "/api/upload/chunk/", utils.ScopeUpload},
	{"", "/api/upload/complete/", utils.ScopeUpload},
	{"", "/api/upload/status/", utils.ScopeUpload},
	{"", "/api/upload/cancel/", utils.ScopeUpload},
	{"", "/api/user/files", utils.ScopeManage},
	{"", "/api/user/files/", utils.ScopeManage},
	{http.MethodGet, "/api/tokens", utils.ScopeManage},
	{http.MethodGet, "/api/auth/user", ""},
}

// TokenRequirement reports what an API token needs to make this request:
// allowed is false when only a browser session may, and otherwise scope is
// the scope the token must hold ("" = any valid token).
func TokenRequirement(method, path string) (scope string, allowed bool) {
	for _, rule := range tokenPolicy {
		if rule.method != "" && rule.method != method {
			continue
		}
		if path == rule.path || (strings.HasSuffix(rule.path, "/") && strings.HasPrefix(path, rule.path)) {
			return rule.scope, true
		}
	}
	return "", false
}

func writeTokenRefusal(w http.ResponseWriter, status int, message, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message, "code": code})
}

// tokenPolicyAllows checks a request authenticated by API token (ctx holds
// its scopes) against the policy. It writes a 403 and returns false when the
// token may not make this request.
func tokenPolicyAllows(w http.ResponseWriter, r *http.Request, ctx context.Context) bool {
	if !tokenScopesEnforced.Load() {
		return true
	}
	scope, allowed := TokenRequirement(r.Method, r.URL.Path)
	if !allowed {
		slog.Warn("API token refused: route needs a browser session", "method", r.Method, "path", logPath(r.URL.Path))
		writeTokenRefusal(w, http.StatusForbidden, "This needs a signed-in browser session; API tokens can't do it", "SESSION_REQUIRED")
		return false
	}
	if scope == "" {
		return true
	}
	scopes, _ := ctx.Value(ContextKeyTokenScopes).(string)
	if !utils.HasScope(scopes, scope) {
		slog.Warn("API token refused: missing scope", "required", scope, "method", r.Method, "path", logPath(r.URL.Path))
		writeTokenRefusal(w, http.StatusForbidden, "This API token doesn't have the \""+scope+"\" scope", "INSUFFICIENT_SCOPE")
		return false
	}
	return true
}
