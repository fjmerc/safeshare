package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/privacy"
)

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestLoggingMiddleware_AnonymousModeRedactsPathAndUserAgent(t *testing.T) {
	const code = "AbCdEfGhIjKlMnOp"
	for _, anon := range []bool{true, false} {
		buf := captureLogs(t)
		h := LoggingMiddleware(anon)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		req := httptest.NewRequest(http.MethodGet, "/claim/"+code, nil)
		req.Header.Set("User-Agent", "SecretAgent/1.0")
		h.ServeHTTP(httptest.NewRecorder(), req)
		out := buf.String()
		if anon {
			if strings.Contains(out, code) || strings.Contains(out, "SecretAgent") {
				t.Errorf("anonymous log leaks path/user agent: %s", out)
			}
		} else if !strings.Contains(out, "SecretAgent") || !strings.Contains(out, code) {
			t.Errorf("normal mode log should keep path and user agent: %s", out)
		}
	}
}

func TestNewRecoveryMiddleware_AnonymousModeRedactsPath(t *testing.T) {
	const code = "AbCdEfGhIjKlMnOp"
	for _, anon := range []bool{true, false} {
		buf := captureLogs(t)
		h := NewRecoveryMiddleware(anon)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("boom") }))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/claim/"+code+"/info", nil))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", rr.Code)
		}
		logged := strings.Contains(buf.String(), `"path":"/api/claim/`+code)
		if anon && strings.Contains(buf.String(), code) {
			t.Errorf("anonymous panic log leaks claim code: %s", buf.String())
		}
		if !anon && !logged {
			t.Errorf("normal mode should log the full path: %s", buf.String())
		}
	}
}

func TestRateLimitLog_AnonymousModeRedactsClaimPath(t *testing.T) {
	const code = "AbCdEfGhIjKlMnOp"
	for _, anon := range []bool{true, false} {
		buf := captureLogs(t)
		privacy.SetAnonymousMode(anon)
		t.Cleanup(func() { privacy.SetAnonymousMode(false) })

		rl := NewRateLimiter(&mockConfigProvider{uploadLimit: 10, downloadLimit: 1, anonymousMode: anon})
		defer rl.Stop()
		h := RateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		var last int
		for i := 0; i < 3; i++ {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil)
			req.RemoteAddr = "203.0.113.9:1234"
			h.ServeHTTP(rr, req)
			last = rr.Code
		}
		if last != http.StatusTooManyRequests {
			t.Fatalf("expected a 429, got %d", last)
		}
		if strings.Contains(buf.String(), code) {
			t.Errorf("anon=%v: rate-limit log contains the full claim code: %s", anon, buf.String())
		}
		if anon && strings.Contains(buf.String(), "claim/") {
			t.Errorf("anonymous rate-limit log keeps more than the route prefix: %s", buf.String())
		}
	}
}

func TestDisabledInAnonymousMode(t *testing.T) {
	for _, anon := range []bool{true, false} {
		t.Setenv("ANONYMOUS_MODE", map[bool]string{true: "true", false: "false"}[anon])
		cfg, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		h := DisabledInAnonymousMode(cfg, "webhooks")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/x", nil))
		want := http.StatusOK
		if anon {
			want = http.StatusConflict
		}
		if rr.Code != want {
			t.Errorf("anon=%v status = %d, want %d", anon, rr.Code, want)
		}
	}
}
