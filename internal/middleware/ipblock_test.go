package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/testutil"
)

// mockProxyConfig implements ProxyConfigProvider for testing
type mockProxyConfig struct{}

func (m *mockProxyConfig) GetTrustProxyHeaders() string {
	return "auto"
}

func (m *mockProxyConfig) GetTrustedProxyIPs() string {
	return "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
}

func TestIPBlockCheck_BlockedIP(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Block an IP
	if err := database.BlockIP(db, "192.168.1.100", "test block", "test"); err != nil {
		t.Fatalf("failed to block IP: %v", err)
	}

	middleware := IPBlockCheck(db, &mockProxyConfig{})
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

	middleware := IPBlockCheck(db, &mockProxyConfig{})
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

	// Block the real client IP (from X-Forwarded-For)
	if err := database.BlockIP(db, "203.0.113.1", "test block", "test"); err != nil {
		t.Fatalf("failed to block IP: %v", err)
	}

	middleware := IPBlockCheck(db, &mockProxyConfig{})
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/upload", nil)
	req.RemoteAddr = "10.0.0.1:12345" // Proxy IP
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

	// Block then unblock
	database.BlockIP(db, "192.168.1.100", "test block", "test")
	database.UnblockIP(db, "192.168.1.100")

	middleware := IPBlockCheck(db, &mockProxyConfig{})
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

	// Block multiple IPs
	blockedIPs := []string{
		"192.168.1.100",
		"192.168.1.101",
		"192.168.1.102",
	}

	for _, ip := range blockedIPs {
		if err := database.BlockIP(db, ip, "test block", "test"); err != nil {
			t.Fatalf("failed to block IP %s: %v", ip, err)
		}
	}

	middleware := IPBlockCheck(db, &mockProxyConfig{})
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

	// Block IPv6 address (without brackets - ExtractIP removes them)
	if err := database.BlockIP(db, "2001:db8::1", "test block", "test"); err != nil {
		t.Fatalf("failed to block IPv6: %v", err)
	}

	middleware := IPBlockCheck(db, &mockProxyConfig{})
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
