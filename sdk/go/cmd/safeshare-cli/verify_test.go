package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	dir := t.TempDir()
	manifest := filepath.Join(dir, "web-assets.sha256")
	content := fmt.Sprintf("%s  assets/app.js\n%s  index.html\n", hexSum(script), hexSum(page))
	if err := os.WriteFile(manifest, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		script     string
		status     int
		wantCode   int // 0: no error
		wantOutput string
	}{
		"verified": {script, 200, 0, "VERIFIED"},
		"tampered": {script + "evil()", 200, 2, "MISMATCH"},
		"blocked":  {script, 403, 1, "fetch failed"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/config":
					_, _ = io.WriteString(w, `{"version":"1.17.0"}`)
				case "/":
					_, _ = io.WriteString(w, page)
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
			var out bytes.Buffer
			err = runVerify(context.Background(), &out, client, verifyOptions{manifestFile: manifest})
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
		})
	}
}
