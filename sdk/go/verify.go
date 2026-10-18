package safeshare

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Web asset verification: checks that the web app a server sends to browsers
// is byte-for-byte the one published with a SafeShare release. Each release
// attaches web-assets.sha256 (made by scripts/web-asset-hashes.sh), the
// SHA-256 of every file the server embeds under internal/static/web.

const (
	// DefaultReleaseRepo is the GitHub repository whose releases publish the
	// web asset hashes.
	DefaultReleaseRepo = "fjmerc/safeshare"
	// WebAssetManifestName is the release file holding the web asset hashes.
	WebAssetManifestName = "web-assets.sha256"

	maxManifestSize = 1 << 20
	maxAssetSize    = 32 << 20
)

// AssetStatus is the outcome of checking one web asset.
type AssetStatus int

const (
	// AssetMatch: the server sent exactly the released file.
	AssetMatch AssetStatus = iota
	// AssetMismatch: the server sent something else. The file was changed on
	// the server or on the way (a CDN that rewrites pages counts).
	AssetMismatch
	// AssetMissing: the server answered 404 for a file every server serves.
	AssetMissing
	// AssetNotServed: the server answered 404 for a file it serves only with
	// some settings (the admin pages, the app manifest).
	AssetNotServed
	// AssetFetchFailed: no definite answer (network error, redirect, an
	// unexpected status, a challenge page).
	AssetFetchFailed
	// AssetNotChecked: not compared, because it needs a login or is filled in
	// for each request.
	AssetNotChecked
	// AssetUnknown: the release has a file this version of the SDK doesn't
	// know the URL of (a newer release). It can't be checked, so the report
	// isn't verified.
	AssetUnknown
)

func (s AssetStatus) String() string {
	switch s {
	case AssetMatch:
		return "match"
	case AssetMismatch:
		return "MISMATCH"
	case AssetMissing:
		return "missing"
	case AssetNotServed:
		return "not served"
	case AssetFetchFailed:
		return "fetch failed"
	case AssetNotChecked:
		return "not checked"
	case AssetUnknown:
		return "unknown file"
	}
	return "unknown"
}

// AssetResult is the check of one file from the manifest.
type AssetResult struct {
	// File is the manifest path, relative to internal/static/web.
	File string
	// URLPath is the path requested from the server; empty if not checked.
	URLPath string
	Status  AssetStatus
	// Expected is the published SHA-256 (hex).
	Expected string
	// Got is the SHA-256 of what the server sent, when it sent something.
	Got string
	// Detail explains a status other than AssetMatch.
	Detail string
}

// WebAssetReport is the result of VerifyWebAssets.
type WebAssetReport struct {
	Results []AssetResult
	// PageCSP is the Content-Security-Policy header sent with "/", "" if none.
	PageCSP string
}

// LooseScriptPolicy returns the script sources the page's Content Security
// Policy allows beyond the released "script-src 'self'", for script elements,
// inline handlers and workers (or "missing" when the page has no policy
// limiting scripts). Only the first policy header is read. Extra sources mean injected or
// third-party scripts can run in the page; they aren't covered by the hashes.
func (r *WebAssetReport) LooseScriptPolicy() []string {
	directives := map[string][]string{}
	for _, d := range strings.Split(r.PageCSP, ";") {
		f := strings.Fields(d)
		if len(f) > 0 {
			name := strings.ToLower(f[0])
			if _, seen := directives[name]; !seen { // the first one counts
				directives[name] = f[1:]
			}
		}
	}
	// Each kind of script falls back to script-src, then default-src.
	effective := func(names ...string) []string {
		for _, n := range append(names, "script-src", "default-src") {
			if v, ok := directives[n]; ok {
				return v
			}
		}
		return nil
	}
	var extra []string
	seen := map[string]bool{}
	for _, kind := range [][]string{{"script-src-elem"}, {"script-src-attr"}, {"worker-src", "child-src"}} {
		src := effective(kind...)
		if src == nil {
			return []string{"missing"}
		}
		for _, v := range src {
			if lv := strings.ToLower(v); lv != "'self'" && lv != "'none'" && !seen[v] {
				seen[v] = true
				extra = append(extra, v)
			}
		}
	}
	return extra
}

// Tampered reports whether any file differs from the release.
func (r *WebAssetReport) Tampered() bool {
	for _, a := range r.Results {
		if a.Status == AssetMismatch {
			return true
		}
	}
	return false
}

// coreFiles must match for a report to be verified: the page and the
// scripts that do the encryption.
var coreFiles = []string{"index.html", "assets/app.js", "assets/crypto.js"}

// Verified reports whether every file the server must serve matched,
// including the main page and the encryption scripts, and nothing differed,
// failed to load or was unknown.
func (r *WebAssetReport) Verified() bool {
	matched := map[string]bool{}
	for _, a := range r.Results {
		switch a.Status {
		case AssetMismatch, AssetMissing, AssetFetchFailed, AssetUnknown:
			return false
		case AssetMatch:
			matched[a.File] = true
		}
	}
	for _, f := range coreFiles {
		if !matched[f] {
			return false
		}
	}
	return true
}

// Count returns how many files have status s.
func (r *WebAssetReport) Count(s AssetStatus) int {
	n := 0
	for _, a := range r.Results {
		if a.Status == s {
			n++
		}
	}
	return n
}

var (
	manifestLine  = regexp.MustCompile(`^([0-9a-f]{64}) [ *]([A-Za-z0-9._/-]+)$`)
	versionRe     = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)
	repoRe        = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$`)
	errNoManifest = errors.New("release has no " + WebAssetManifestName)
)

// ParseWebAssetManifest parses a web-assets.sha256 file (sha256sum format) into
// a map from file path to hex SHA-256.
func ParseWebAssetManifest(data []byte) (map[string]string, error) {
	if len(data) > maxManifestSize {
		return nil, fmt.Errorf("manifest is larger than %d bytes", maxManifestSize)
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if line == "" {
			continue
		}
		m := manifestLine.FindStringSubmatch(line)
		if m == nil || !validManifestPath(m[2]) {
			return nil, fmt.Errorf("manifest line %d is not \"<sha256>  <path>\"", n)
		}
		if _, dup := out[m[2]]; dup {
			return nil, fmt.Errorf("manifest lists %s twice", m[2])
		}
		out[m[2]] = m[1]
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	if _, ok := out["index.html"]; !ok {
		return nil, errors.New("manifest has no index.html; is it a SafeShare " + WebAssetManifestName + "?")
	}
	return out, nil
}

func validManifestPath(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// assetRoute maps a manifest path to the URL the server serves it at. It
// mirrors the routes in cmd/safeshare/main.go; sdk/go's tests check every
// embedded file is mapped. A file it doesn't know (from a newer release)
// makes the report unverified rather than being skipped.
func assetRoute(file string) (urlPath string, optional bool, skip string) {
	switch {
	case file == "index.html":
		return "/", false, ""
	case file == "login.html":
		return "/login", false, ""
	case file == "service-worker.js", file == "service-worker-anonymous.js":
		return "/service-worker.js", false, "" // checked together, see VerifyWebAssets
	case file == "assets/manifest.json":
		return "/assets/manifest.json", true, "" // not served in Ghost mode
	case strings.HasPrefix(file, "assets/"):
		return "/" + file, false, ""
	case file == "admin/login.html":
		return "/admin/login", true, "" // admin dashboard disabled
	case strings.HasPrefix(file, "admin/assets/"):
		return "/" + file, true, ""
	case file == "dashboard.html", file == "admin/dashboard.html":
		return "", false, "needs a login"
	case file == "error.html":
		return "", false, "filled in for each error, so it never matches"
	}
	return "", false, unknownRoute
}

// unknownRoute is assetRoute's skip reason for a file it has no URL for.
const unknownRoute = "no known URL"

// VerifyWebAssets fetches every web file listed in manifest (from
// ParseWebAssetManifest) from the server and compares it with the published
// hash. Requests carry no API token or cookies.
//
// It only checks what the server sends to this client: a server that can tell
// a verifier from a visitor can still send visitors something else.
//
// The server must use https, unless it is a .onion or loopback address: over
// plain http anyone on the path could change the files.
func (c *Client) VerifyWebAssets(ctx context.Context, manifest map[string]string) (*WebAssetReport, error) {
	origin, err := verifyOrigin(c.baseURL)
	if err != nil {
		return nil, err
	}
	if t, ok := c.httpClient.Transport.(*http.Transport); ok && t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
		return nil, &ValidationError{Field: "InsecureSkipVerify", Message: "must be off to verify: without certificate checks anyone on the path can change the files"}
	}

	hc := *c.httpClient
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	files := make([]string, 0, len(manifest))
	for f := range manifest {
		files = append(files, f)
	}
	sort.Strings(files)

	report := &WebAssetReport{}
	swDone := false
	for _, file := range files {
		urlPath, optional, skip := assetRoute(file)
		res := AssetResult{File: file, Expected: manifest[file]}
		if skip == unknownRoute {
			res.Status, res.Detail = AssetUnknown, "not known to this version of the SDK/CLI; update it"
			report.Results = append(report.Results, res)
			continue
		}
		if skip != "" {
			res.Status, res.Detail = AssetNotChecked, skip
			report.Results = append(report.Results, res)
			continue
		}
		if urlPath == "/service-worker.js" {
			// The real worker, or in Ghost mode the stub that removes it.
			if swDone {
				continue
			}
			swDone = true
			res = checkServiceWorker(ctx, &hc, origin, manifest)
			report.Results = append(report.Results, res)
			continue
		}
		res.URLPath = urlPath
		sum, status, hdr, detail := fetchHash(ctx, &hc, origin+urlPath, isPage(file))
		res.Got, res.Detail = sum, detail
		if file == "index.html" && hdr != nil {
			report.PageCSP = hdr.Get("Content-Security-Policy")
		}
		switch {
		case status == http.StatusNotFound && optional:
			res.Status, res.Detail = AssetNotServed, "404, normal when this feature is off"
		case status == http.StatusNotFound:
			res.Status, res.Detail = AssetMissing, "404"
		case sum == "":
			res.Status = AssetFetchFailed
		case sum == res.Expected:
			res.Status = AssetMatch
		default:
			res.Status = AssetMismatch
		}
		report.Results = append(report.Results, res)
	}
	return report, nil
}

func checkServiceWorker(ctx context.Context, hc *http.Client, origin string, manifest map[string]string) AssetResult {
	res := AssetResult{File: "service-worker.js", URLPath: "/service-worker.js"}
	names := []string{"service-worker.js", "service-worker-anonymous.js"}
	var accept []string
	for _, f := range names {
		if h, ok := manifest[f]; ok {
			accept = append(accept, h)
		}
	}
	res.Expected = strings.Join(accept, " or ")
	sum, status, _, detail := fetchHash(ctx, hc, origin+res.URLPath, false)
	res.Got, res.Detail = sum, detail
	switch {
	case status == http.StatusNotFound:
		res.Status, res.Detail = AssetMissing, "404"
	case sum == "":
		res.Status = AssetFetchFailed
	default:
		res.Status = AssetMismatch
		for _, f := range names {
			if h, ok := manifest[f]; ok && sum == h {
				res.Status, res.File, res.Expected = AssetMatch, f, h
				break
			}
		}
	}
	return res
}

// isPage reports whether a browser loads file as a page (navigation).
func isPage(file string) bool {
	return strings.HasSuffix(file, ".html")
}

// browserPageAccept is the Accept header browsers send when opening a page.
// Some CDNs only rewrite pages for requests that look like this (Cloudflare
// injects its analytics script for "text/html" but not for "*/*"), so the
// check asks the way a browser does.
const browserPageAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

// fetchHash GETs u and returns the SHA-256 of a 200 response body. sum is ""
// unless the status was 200 and the whole body was read; detail says why.
func fetchHash(ctx context.Context, hc *http.Client, u string, page bool) (sum string, status int, hdr http.Header, detail string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", 0, nil, err.Error()
	}
	if page {
		req.Header.Set("Accept", browserPageAccept)
	} else {
		req.Header.Set("Accept", "*/*")
	}
	// Ask for the bytes as stored and past caches; hash what a browser would
	// end up with if something compresses anyway.
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := hc.Do(req)
	if err != nil {
		return "", 0, nil, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
		if loc := resp.Header.Get("Location"); loc != "" {
			detail += " redirect to " + loc
		}
		return "", resp.StatusCode, resp.Header, detail
	}
	if page && resp.Header.Get("Refresh") != "" {
		// A genuine page with a Refresh header sends the browser elsewhere.
		return "", resp.StatusCode, resp.Header, "the page has a Refresh header, which sends browsers to another page"
	}
	if len(resp.Header.Values("Content-Encoding")) > 1 {
		return "", resp.StatusCode, resp.Header, "more than one Content-Encoding header"
	}
	var body io.Reader = resp.Body
	switch enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))); enc {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return "", resp.StatusCode, resp.Header, "bad gzip body: " + err.Error()
		}
		defer zr.Close()
		body = zr
	default:
		return "", resp.StatusCode, resp.Header, "unsupported Content-Encoding " + enc
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(body, maxAssetSize+1))
	if err != nil {
		return "", resp.StatusCode, resp.Header, "reading body: " + err.Error()
	}
	if n > maxAssetSize {
		return "", resp.StatusCode, resp.Header, fmt.Sprintf("larger than %d bytes", maxAssetSize)
	}
	return hex.EncodeToString(h.Sum(nil)), resp.StatusCode, resp.Header, ""
}

// CheckVerifyURL reports whether raw is a server address VerifyWebAssets
// accepts: https (or http for .onion and loopback), and only scheme, host and
// port. SafeShare's pages load their scripts from the site root (/assets/...),
// so a path or query would check files browsers never load.
func CheckVerifyURL(raw string) error {
	_, err := verifyOrigin(raw)
	return err
}

func verifyOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", &ValidationError{Field: "BaseURL", Message: "must be a URL such as https://share.example.com"}
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || u.User != nil || u.Opaque != "" {
		return "", &ValidationError{Field: "BaseURL", Message: "must be just scheme://host[:port] to verify, with no path, query or user name (SafeShare runs at the site root)"}
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && onionOrLoopback(u.Hostname())) {
		return "", &ValidationError{Field: "BaseURL", Message: "must use https to verify (http is only accepted for .onion and loopback addresses)"}
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String(), nil
}

func onionOrLoopback(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if strings.HasSuffix(host, ".onion") || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// githubClient talks to GitHub through the same proxy as c, without the API
// token, with certificate checks on, following redirects only to GitHub's own https hosts (release files
// are served from *.githubusercontent.com).
func (c *Client) githubClient(follow bool) *http.Client {
	hc := *c.httpClient
	if t, ok := hc.Transport.(*http.Transport); ok {
		// Always check GitHub's certificate, even if the client was made
		// with InsecureSkipVerify for a self-signed SafeShare server.
		t = t.Clone()
		t.TLSClientConfig = nil
		hc.Transport = t
	}
	hc.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if !follow {
			return http.ErrUseLastResponse
		}
		host := strings.ToLower(r.URL.Hostname())
		if r.URL.Scheme != "https" || (host != "github.com" && !strings.HasSuffix(host, ".githubusercontent.com")) {
			return fmt.Errorf("refusing redirect to %s://%s", r.URL.Scheme, r.URL.Host)
		}
		if len(via) >= 5 {
			return errors.New("stopped after 5 redirects")
		}
		return nil
	}
	return &hc
}

// FetchReleaseManifest downloads web-assets.sha256 for a release (version
// without the "v", e.g. "1.17.0") from GitHub, through the client's proxy. repo
// is "owner/name"; empty means DefaultReleaseRepo.
func (c *Client) FetchReleaseManifest(ctx context.Context, repo, version string) ([]byte, error) {
	repo, err := checkRepo(repo)
	if err != nil {
		return nil, err
	}
	if !versionRe.MatchString(version) {
		return nil, &ValidationError{Field: "version", Message: "must look like 1.2.3"}
	}
	u := "https://github.com/" + repo + "/releases/download/v" + version + "/" + WebAssetManifestName
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.githubClient(true).Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("v%s: %w", version, errNoManifest)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading %s: HTTP %d", u, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize+1))
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", u, err)
	}
	if len(data) > maxManifestSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", u, maxManifestSize)
	}
	return data, nil
}

// IsNoManifest reports whether err from FetchReleaseManifest means the release
// exists but publishes no web asset hashes (releases before they were added),
// or doesn't exist.
func IsNoManifest(err error) bool {
	return errors.Is(err, errNoManifest)
}

// LatestReleaseVersion returns the newest release's version (without the "v")
// from GitHub, through the client's proxy. repo is "owner/name"; empty means
// DefaultReleaseRepo.
func (c *Client) LatestReleaseVersion(ctx context.Context, repo string) (string, error) {
	repo, err := checkRepo(repo)
	if err != nil {
		return "", err
	}
	u := "https://github.com/" + repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	// GitHub answers with a redirect to /releases/tag/vX.Y.Z. Reading it
	// avoids the rate-limited API, which shared Tor exits often hit.
	resp, err := c.githubClient(false).Do(req)
	if err != nil {
		return "", fmt.Errorf("checking the latest release: %w", err)
	}
	resp.Body.Close()
	loc, err := resp.Location()
	if err != nil || resp.StatusCode/100 != 3 {
		return "", fmt.Errorf("checking the latest release: unexpected HTTP %d", resp.StatusCode)
	}
	prefix := "/" + repo + "/releases/tag/v"
	if loc.Host != "github.com" || !strings.HasPrefix(loc.Path, prefix) || !versionRe.MatchString(strings.TrimPrefix(loc.Path, prefix)) {
		return "", errors.New("checking the latest release: unexpected redirect")
	}
	return strings.TrimPrefix(loc.Path, prefix), nil
}

func checkRepo(repo string) (string, error) {
	if repo == "" {
		return DefaultReleaseRepo, nil
	}
	if !repoRe.MatchString(repo) || strings.Contains(repo, "..") {
		return "", &ValidationError{Field: "repo", Message: "must look like owner/name"}
	}
	return repo, nil
}
