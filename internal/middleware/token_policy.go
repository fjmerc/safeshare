package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/privacy"
	"github.com/fjmerc/safeshare/internal/utils"
)

// API token scopes are enforced here, once, right after a Bearer token is
// recognised - not per route - so a route added later can't become reachable
// by tokens by accident. The policy table below lists every path a token may
// use and the scope it needs; any other path (account security: password,
// MFA, SSO, token management, logout, pages) needs a signed-in browser
// session. Browser sessions and anonymous requests are not affected.
//
// When adding a route a script should be able to call with an API token, add
// it to tokenPolicy; until then tokens get 403 SESSION_REQUIRED there.
//
// The admin scope implies every other scope (utils.HasScope), but admin
// dashboard routes use their own admin session and never accept tokens.

// tokenScopesEnforced is on unless ENFORCE_API_TOKEN_SCOPES=false (fail closed).
var tokenScopesEnforced atomic.Bool

func init() { tokenScopesEnforced.Store(true) }

// SetTokenScopeEnforcement turns API token scope checks on or off
// (ENFORCE_API_TOKEN_SCOPES). Off lets a token use any route in the policy
// whatever its scopes; routes outside the policy (account security) stay
// browser-session only either way.
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
	{"", "/api/user/files", utils.ScopeManage},
	{"", "/api/user/files/", utils.ScopeManage},
	// Bundles: a draft is created, published or discarded (only while a
	// draft, with its own upload token) as part of uploading.
	{"", "/api/bundles", utils.ScopeUpload},
	{"", "/api/bundles/", utils.ScopeUpload},
	{"", "/api/user/bundles", utils.ScopeManage},
	{"", "/api/user/bundles/", utils.ScopeManage},
	{http.MethodGet, "/api/tokens", utils.ScopeManage},
	{http.MethodGet, "/api/auth/user", ""},
}

// Routes under a tokenPolicy prefix that need a different scope, told apart
// by their last segment; checked before tokenPolicy. Owner downloads read a
// file's contents (with no password and no download limit), which manage
// (list, rename, delete) does not grant.
var tokenSuffixPolicy = []struct{ method, prefix, suffix, scope string }{
	{http.MethodGet, "/api/user/files/", "/download", utils.ScopeDownload},
	{http.MethodGet, "/api/user/bundles/", "/download", utils.ScopeDownload},
}

// methodMatches: "" matches any method, and a GET rule also covers HEAD.
func methodMatches(rule, method string) bool {
	return rule == "" || rule == method || (rule == http.MethodGet && method == http.MethodHead)
}

// tokenRequirement reports what an API token needs to make this request:
// allowed is false when only a browser session may, and otherwise scope is
// the scope the token must hold ("" = any valid token).
func tokenRequirement(method, path string) (scope string, allowed bool) {
	for _, rule := range tokenSuffixPolicy {
		if !methodMatches(rule.method, method) || !strings.HasPrefix(path, rule.prefix) {
			continue
		}
		// Something must sit between the prefix and the suffix (the file).
		if rest := path[len(rule.prefix):]; len(rest) > len(rule.suffix) && strings.HasSuffix(rest, rule.suffix) {
			return rule.scope, true
		}
	}
	for _, rule := range tokenPolicy {
		if !methodMatches(rule.method, method) {
			continue
		}
		if path == rule.path || (strings.HasSuffix(rule.path, "/") && strings.HasPrefix(path, rule.path)) {
			return rule.scope, true
		}
	}
	return "", false
}

// The messages avoid the word "token": the Go SDK masks server messages
// that mention credentials, and these are the useful part of the error.
func writeTokenRefusal(w http.ResponseWriter, message, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(models.ErrorResponse{Error: message, Code: code})
}

// tokenPolicyAllows checks a request authenticated by API token (ctx is the
// authenticated context) against the policy. It writes a 403 and returns
// false when the token may not make this request.
func tokenPolicyAllows(ctx context.Context, w http.ResponseWriter, r *http.Request, anonymousMode bool) bool {
	refused := func(reason, required, message, code string) bool {
		var userID int64
		if u, ok := ctx.Value(ContextKeyUser).(*models.User); ok && u != nil {
			userID = u.ID
		}
		slog.Warn("API token refused",
			"reason", reason,
			"required_scope", required,
			"method", r.Method,
			"path", logPath(r.URL.Path),
			"token_id", ctx.Value(ContextKeyTokenID),
			"user_id", userID,
			"ip", privacy.RedactIP(getClientIP(r), anonymousMode),
		)
		writeTokenRefusal(w, message, code)
		return false
	}

	scope, allowed := tokenRequirement(r.Method, r.URL.Path)
	if !allowed {
		return refused("session_required", "", "This needs a signed-in browser session", "SESSION_REQUIRED")
	}
	if scope == "" || !tokenScopesEnforced.Load() {
		return true
	}
	scopes, _ := ctx.Value(ContextKeyTokenScopes).(string)
	if !utils.HasScope(scopes, scope) {
		return refused("missing_scope", scope, "This request needs the \""+scope+"\" scope", "INSUFFICIENT_SCOPE")
	}
	return true
}
