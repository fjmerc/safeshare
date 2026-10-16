package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/config"
)

func loadCfg(t *testing.T, env map[string]string) *config.Config {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func TestEnforceAnonymousModeEgress(t *testing.T) {
	cfg := loadCfg(t, map[string]string{"ANONYMOUS_MODE": "true"})
	cfg.Features.SetWebhooksEnabled(true)
	cfg.Features.SetSSOEnabled(true)
	cfg.Features.SetAPITokensEnabled(true)

	got := enforceAnonymousModeEgress(context.Background(), cfg, nil)
	if len(got) != 2 {
		t.Fatalf("disabled = %v, want webhooks and sso", got)
	}
	if cfg.Features.IsWebhooksEnabled() || cfg.Features.IsSSOEnabled() || cfg.SSO.Enabled {
		t.Error("webhooks/SSO still enabled")
	}
	if !cfg.Features.IsAPITokensEnabled() {
		t.Error("unrelated feature was disabled")
	}

	normal := loadCfg(t, map[string]string{"ANONYMOUS_MODE": "false"})
	normal.Features.SetWebhooksEnabled(true)
	if got := enforceAnonymousModeEgress(context.Background(), normal, nil); got != nil || !normal.Features.IsWebhooksEnabled() {
		t.Error("normal mode must be untouched")
	}
}

func TestClientEncryptionScanConflict(t *testing.T) {
	cfg := loadCfg(t, map[string]string{"ANONYMOUS_MODE": "true", "MALWARE_SCAN_REJECT_UNSCANNABLE": "true"})
	if clientEncryptionScanConflict(cfg) {
		t.Error("no conflict expected while malware scanning is off")
	}
	cfg.Features.SetMalwareScanEnabled(true)
	if !clientEncryptionScanConflict(cfg) {
		t.Error("conflict expected: E2E required + scan enabled + reject unscannable")
	}
	cfg.ClamAV.RejectUnscannable = false
	if clientEncryptionScanConflict(cfg) {
		t.Error("no conflict expected without RejectUnscannable")
	}
}

func TestMetricsEndpointEnabled(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"normal mode", map[string]string{"ANONYMOUS_MODE": "false"}, true},
		{"anonymous mode default", map[string]string{"ANONYMOUS_MODE": "true"}, false},
		{"anonymous mode opt-in", map[string]string{"ANONYMOUS_MODE": "true", "METRICS_IN_ANONYMOUS_MODE": "true"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := metricsEndpointEnabled(loadCfg(t, tt.env)); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServerErrorLogRedactsRemoteAddrInAnonymousMode(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	msg := "http: TLS handshake error from 203.0.113.7:51234: EOF; also [2001:db8::1]:443 dropped; GET /api/claim/Ab3dEf9h/info\n"
	newServerErrorLog(true).Print(msg)
	if out := buf.String(); strings.Contains(out, "203.0.113.7") || strings.Contains(out, "2001:db8") || strings.Contains(out, "Ab3dEf9h") {
		t.Errorf("anonymous server error log leaks a remote address or claim code: %s", out)
	}
	buf.Reset()
	newServerErrorLog(false).Print(msg)
	if !strings.Contains(buf.String(), "203.0.113.7:51234") {
		t.Errorf("normal mode should keep the address: %s", buf.String())
	}
}

func TestSlogWriter_RedactsShortClaimPathInAnonymousMode(t *testing.T) {
	tests := []struct {
		name, msg, want string
	}{
		{"plain", "http: panic serving: GET /Xy9kLm8pQz4vDwE_ boom", "http: panic serving: GET /[redacted] boom"},
		{"ends with underscore", "GET /abcdefg_ x", "GET /[redacted] x"},
		{"ends with hyphen", "GET /abcdefg- x", "GET /[redacted] x"},
		{"HEAD", "HEAD /abcdefgh x", "HEAD /[redacted] x"},
		{"with query", "GET /abcdefgh?a=b x", "GET /[redacted]?a=b x"},
		{"reserved short name untouched", "GET /health x", "GET /health x"},
		{"reserved long name untouched", "GET /dashboard x", "GET /dashboard x"},
		{"nested untouched", "GET /abcdefgh/ijklmnop x", "GET /abcdefgh/ijklmnop x"},
		{"dotted untouched", "GET /service-worker.js x", "GET /service-worker.js x"},
		{"too short untouched", "GET /abcdefg x", "GET /abcdefg x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redactShortClaimPaths(tt.msg); got != tt.want {
				t.Errorf("redactShortClaimPaths(%q) = %q, want %q", tt.msg, got, tt.want)
			}
		})
	}
}
