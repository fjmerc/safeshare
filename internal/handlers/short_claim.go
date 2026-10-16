package handlers

import (
	"net/http"

	"github.com/fjmerc/safeshare/internal/claimcode"
	"github.com/fjmerc/safeshare/internal/config"
)

// TryShortClaimRedirect serves the opt-in short claim link form "/<code>".
// When SHORT_CLAIM_LINKS is enabled and the request is a GET/HEAD for a
// single-segment path that is a well-formed claim code (and not a reserved
// application route), it answers with an unconditional 302 to the canonical
// download URL (a relative /api/claim/<code>, or on DOWNLOAD_URL when that is set) and returns true. The raw query string is preserved.
//
// There is deliberately no database lookup: every well-formed code redirects,
// so this path is not an existence oracle, and the real download request hits
// the claim rate limiter, which keys on the /api/claim/ prefix. The target is
// always the API form, so the redirect can never loop back to a short link.
//
// It returns false (response not written) when the request is not a short
// claim link, letting the caller fall through to its normal 404 handling.
func TryShortClaimRedirect(w http.ResponseWriter, r *http.Request, cfg *config.Config) bool {
	if !cfg.ShortClaimLinks {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	code, ok := claimcode.ShortPath(r.URL.Path)
	if !ok {
		return false
	}

	// Without DOWNLOAD_URL the target is a relative Location: the client
	// resolves it against the URL it used, which cannot be downgraded to http
	// behind an untrusted TLS-terminating proxy or poisoned via the Host header.
	target := "/api/claim/" + code
	if cfg.DownloadURL != "" {
		target = buildDownloadURL(r, cfg, code)
	}
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}

	// The Location header carries the bearer secret; keep it out of caches.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
	return true
}
