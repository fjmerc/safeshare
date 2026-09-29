package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
)

// mockProxyConfig implements ProxyConfigProvider for testing
type mockProxyConfig struct {
	// trustedProxyIPs overrides the default RFC1918 trust list when
	// non-empty. Left unset, existing tests keep their original behavior.
	trustedProxyIPs string
}

func (m *mockProxyConfig) GetTrustProxyHeaders() string {
	return "auto"
}

func (m *mockProxyConfig) GetTrustedProxyIPs() string {
	if m.trustedProxyIPs != "" {
		return m.trustedProxyIPs
	}
	return "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
}

func (m *mockProxyConfig) IsAnonymousMode() bool {
	return false
}

func TestIPBlockCheck_BlockedIP(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Block an IP
	if err := repos.Admin.BlockIP(ctx, "192.168.1.100", "test block", "test"); err != nil {
		t.Fatalf("failed to block IP: %v", err)
	}

	middleware := IPBlockCheck(repos, &mockProxyConfig{})
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/upload", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Blocked IP should get 403
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestIPBlockCheck_AllowedIP(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	middleware := IPBlockCheck(repos, &mockProxyConfig{})
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/upload", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Non-blocked IP should succeed
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestIPBlockCheck_XForwardedFor(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Block the real client IP (from X-Forwarded-For)
	if err := repos.Admin.BlockIP(ctx, "203.0.113.1", "test block", "test"); err != nil {
		t.Fatalf("failed to block IP: %v", err)
	}

	middleware := IPBlockCheck(repos, &mockProxyConfig{})
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/upload", nil)
	req.RemoteAddr = "10.0.0.1:12345"                // Proxy IP
	req.Header.Set("X-Forwarded-For", "203.0.113.1") // Real client IP

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should block based on X-Forwarded-For
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestIPBlockCheck_UnblockIP(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Block then unblock
	repos.Admin.BlockIP(ctx, "192.168.1.100", "test block", "test")
	repos.Admin.UnblockIP(ctx, "192.168.1.100")

	middleware := IPBlockCheck(repos, &mockProxyConfig{})
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/upload", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Unblocked IP should succeed
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestIPBlockCheck_MultipleBlockedIPs(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Block multiple IPs
	blockedIPs := []string{
		"192.168.1.100",
		"192.168.1.101",
		"192.168.1.102",
	}

	for _, ip := range blockedIPs {
		if err := repos.Admin.BlockIP(ctx, ip, "test block", "test"); err != nil {
			t.Fatalf("failed to block IP %s: %v", ip, err)
		}
	}

	middleware := IPBlockCheck(repos, &mockProxyConfig{})
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// All blocked IPs should get 403
	for _, ip := range blockedIPs {
		req := httptest.NewRequest(http.MethodGet, "/api/upload", nil)
		req.RemoteAddr = ip + ":12345"
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("IP %s: status = %d, want %d", ip, rr.Code, http.StatusForbidden)
		}
	}

	// Non-blocked IP should succeed
	req := httptest.NewRequest(http.MethodGet, "/api/upload", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("allowed IP: status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestIPBlockCheck_IPv6(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	// Block IPv6 address (without brackets - ExtractIP removes them)
	if err := repos.Admin.BlockIP(ctx, "2001:db8::1", "test block", "test"); err != nil {
		t.Fatalf("failed to block IPv6: %v", err)
	}

	middleware := IPBlockCheck(repos, &mockProxyConfig{})
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/upload", nil)
	req.RemoteAddr = "[2001:db8::1]:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Blocked IPv6 should get 403
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// TestIPBlockCheck_ProductionChainSpoofResistant proves the T41 fix at this
// call site, mirroring the production chain: client -> Cloudflare ->
// Traefik -> SafeShare. A blocked client must not be able to evade the
// block by prepending an arbitrary spoofed IP to X-Forwarded-For, and an
// unrelated client must not inherit someone else's block just because they
// share the same spoofable leftmost entry.
func TestIPBlockCheck_ProductionChainSpoofResistant(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	const realClient = "203.0.113.42"
	const cfEdge = "172.64.1.1" // within Cloudflare's published ranges

	if err := repos.Admin.BlockIP(ctx, realClient, "test block", "test"); err != nil {
		t.Fatalf("failed to block IP: %v", err)
	}

	proxyCfg := &mockProxyConfig{
		trustedProxyIPs: "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,cloudflare",
	}
	middleware := IPBlockCheck(repos, proxyCfg)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// A blocked client cannot evade the block by claiming to be a different
	// IP via a spoofed leftmost XFF entry. A Cloudflare hop is consumed
	// here, so the CF-Connecting-IP veto applies -- set it to what the real
	// edge would, confirming this really is realClient (see
	// TestGetClientIPWithTrust_CFConnectingIPVeto in internal/utils for the
	// fail-closed cases without it).
	req := httptest.NewRequest(http.MethodGet, "/api/upload", nil)
	req.RemoteAddr = "172.20.0.5:54321" // Traefik peer, within trusted range
	req.Header.Set("X-Forwarded-For", "6.6.6.6, "+realClient+", "+cfEdge)
	req.Header.Set("CF-Connecting-IP", realClient)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("blocked client via spoofed XFF: status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	// A different, non-blocked real client is unaffected even when it
	// reuses the exact same spoofed leftmost entry.
	const otherClient = "198.51.100.9"
	req2 := httptest.NewRequest(http.MethodGet, "/api/upload", nil)
	req2.RemoteAddr = "172.20.0.5:54321"
	req2.Header.Set("X-Forwarded-For", "6.6.6.6, "+otherClient+", "+cfEdge)
	req2.Header.Set("CF-Connecting-IP", otherClient)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Errorf("unrelated client with same spoofed leftmost entry: status = %d, want %d", rr2.Code, http.StatusOK)
	}
}
