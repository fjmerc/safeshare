package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/config"
)

func TestTryShortClaimRedirect(t *testing.T) {
	const code = "Xy9kLm8pQz4vDwE_"

	tests := []struct {
		name         string
		cfg          *config.Config
		method       string
		target       string
		wantHandled  bool
		wantLocation string
	}{
		{
			name:         "enabled, valid code, request host",
			cfg:          &config.Config{ShortClaimLinks: true},
			method:       http.MethodGet,
			target:       "http://share.test/" + code,
			wantHandled:  true,
			wantLocation: "/api/claim/" + code,
		},
		{
			name:         "HEAD redirects too",
			cfg:          &config.Config{ShortClaimLinks: true},
			method:       http.MethodHead,
			target:       "http://share.test/" + code,
			wantHandled:  true,
			wantLocation: "/api/claim/" + code,
		},
		{
			name:         "PUBLIC_URL ignored, relative target",
			cfg:          &config.Config{ShortClaimLinks: true, PublicURL: "https://public.example.com/"},
			method:       http.MethodGet,
			target:       "http://internal/" + code,
			wantHandled:  true,
			wantLocation: "/api/claim/" + code,
		},
		{
			name:         "DOWNLOAD_URL wins over PUBLIC_URL",
			cfg:          &config.Config{ShortClaimLinks: true, PublicURL: "https://public.example.com", DownloadURL: "https://dl.example.com"},
			method:       http.MethodGet,
			target:       "http://internal/" + code,
			wantHandled:  true,
			wantLocation: "https://dl.example.com/api/claim/" + code,
		},
		{
			name:         "query string preserved",
			cfg:          &config.Config{ShortClaimLinks: true, PublicURL: "https://public.example.com"},
			method:       http.MethodGet,
			target:       "http://internal/" + code + "?password=hunter2&x=1",
			wantHandled:  true,
			wantLocation: "/api/claim/" + code + "?password=hunter2&x=1",
		},
		{name: "disabled", cfg: &config.Config{}, method: http.MethodGet, target: "http://share.test/" + code},
		{name: "POST not handled", cfg: &config.Config{ShortClaimLinks: true}, method: http.MethodPost, target: "http://share.test/" + code},
		{name: "reserved dashboard", cfg: &config.Config{ShortClaimLinks: true}, method: http.MethodGet, target: "http://share.test/dashboard"},
		{name: "7 chars", cfg: &config.Config{ShortClaimLinks: true}, method: http.MethodGet, target: "http://share.test/abcdefg"},
		{name: "33 chars", cfg: &config.Config{ShortClaimLinks: true}, method: http.MethodGet, target: "http://share.test/" + strings.Repeat("a", 33)},
		{name: "bad chars", cfg: &config.Config{ShortClaimLinks: true}, method: http.MethodGet, target: "http://share.test/abcdef!!"},
		{name: "nested path", cfg: &config.Config{ShortClaimLinks: true}, method: http.MethodGet, target: "http://share.test/abcdefgh/ijklmnop"},
		{name: "root", cfg: &config.Config{ShortClaimLinks: true}, method: http.MethodGet, target: "http://share.test/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, nil)
			rr := httptest.NewRecorder()

			handled := TryShortClaimRedirect(rr, req, tt.cfg)
			if handled != tt.wantHandled {
				t.Fatalf("handled = %v, want %v", handled, tt.wantHandled)
			}
			if !tt.wantHandled {
				if rr.Code != http.StatusOK || rr.Header().Get("Location") != "" {
					t.Errorf("unhandled request wrote a response: code=%d location=%q", rr.Code, rr.Header().Get("Location"))
				}
				return
			}
			if rr.Code != http.StatusFound {
				t.Errorf("status = %d, want 302", rr.Code)
			}
			if got := rr.Header().Get("Location"); got != tt.wantLocation {
				t.Errorf("Location = %q, want %q", got, tt.wantLocation)
			}
			if got := rr.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}

// The redirect target must always be the API form, even with short links
// enabled, so a short link can never redirect to itself.
func TestTryShortClaimRedirect_NeverTargetsShortForm(t *testing.T) {
	cfg := &config.Config{ShortClaimLinks: true, PublicURL: "https://public.example.com"}
	req := httptest.NewRequest(http.MethodGet, "http://internal/abcdefgh", nil)
	rr := httptest.NewRecorder()
	if !TryShortClaimRedirect(rr, req, cfg) {
		t.Fatal("expected redirect")
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/api/claim/") {
		t.Errorf("Location %q is not the API form", loc)
	}
}
