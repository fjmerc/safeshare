package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	safeshare "github.com/fjmerc/safeshare/sdk/go"
)

func hexSum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestRunVerifyExitStatus(t *testing.T) {
	const page, script = "<html>page</html>", "console.log(1)"
	const strict = "default-src 'self'; script-src 'self'"
	dir := t.TempDir()
	manifest := filepath.Join(dir, "web-assets.sha256")
	content := fmt.Sprintf("%s  assets/app.js\n%s  assets/crypto.js\n%s  index.html\n", hexSum(script), hexSum(script), hexSum(page))
	if err := os.WriteFile(manifest, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		script     string
		status     int
		csp        string
		wantCode   int // 0: no error
		wantOutput string
		wantResult string // --json "result"
	}{
		"verified":  {script, 200, strict, 0, "VERIFIED", "verified"},
		"tampered":  {script + "evil()", 200, strict, 2, "MISMATCH", "tampered"},
		"blocked":   {script, 403, strict, 1, "fetch failed", "could_not_verify"},
		"loose csp": {script, 200, "default-src 'self'; script-src 'self' 'unsafe-inline'", 1, "allow-loose-csp", "could_not_verify"},
		"no csp":    {script, 200, "", 1, "missing", "could_not_verify"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/config":
					_, _ = io.WriteString(w, `{"version":"1.17.0"}`)
				case "/":
					w.Header().Set("Content-Security-Policy", tc.csp)
					_, _ = io.WriteString(w, page)
				case "/assets/crypto.js":
					_, _ = io.WriteString(w, script)
				case "/assets/app.js":
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.script)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			client, err := safeshare.NewClient(safeshare.ClientConfig{BaseURL: srv.URL, DisableProxy: true})
			if err != nil {
				t.Fatal(err)
			}
			var out, doc bytes.Buffer
			err = runVerify(context.Background(), &out, client, verifyOptions{manifestFile: manifest, jsonTo: &doc})
			var ee *exitError
			switch {
			case tc.wantCode == 0 && err != nil:
				t.Fatalf("error: %v\n%s", err, out.String())
			case tc.wantCode != 0 && (!errors.As(err, &ee) || ee.code != tc.wantCode):
				t.Fatalf("got %v, want exit %d\n%s", err, tc.wantCode, out.String())
			}
			if !strings.Contains(out.String()+fmt.Sprint(err), tc.wantOutput) {
				t.Errorf("output lacks %q:\n%s", tc.wantOutput, out.String())
			}
			if !strings.Contains(out.String(), "Server reports version 1.17.0") {
				t.Errorf("version not shown:\n%s", out.String())
			}
			var report verifyJSON
			if err := json.Unmarshal(doc.Bytes(), &report); err != nil {
				t.Fatalf("--json report: %v: %q", err, doc.String())
			}
			if report.Result != tc.wantResult || report.ServerVersion != "1.17.0" || report.Version != "" || len(report.Files) != 3 {
				t.Errorf("--json report: %s", doc.String())
			}
			if tc.wantResult == "tampered" && !strings.Contains(doc.String(), `"status":"mismatch"`) {
				t.Errorf("--json report lacks the mismatch: %s", doc.String())
			}
		})
	}
}

func TestVerifyRefusesURLWithPath(t *testing.T) {
	for _, u := range []string{"https://h.example/share", "https://h.example/?x=", "https://h.example/#", "https://u@h.example"} {
		cmd := verifyCmd()
		cmd.SetArgs([]string{u})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "scheme://host") {
			t.Errorf("%s: %v", u, err)
		}
	}
}
