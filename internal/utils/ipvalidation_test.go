package utils

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsTrustedProxyIP(t *testing.T) {
	tests := []struct {
		name           string
		ipStr          string
		trustedProxies string
		want           bool
	}{
		{
			name:           "exact match single IP",
			ipStr:          "192.168.1.1",
			trustedProxies: "192.168.1.1",
			want:           true,
		},
		{
			name:           "no match single IP",
			ipStr:          "192.168.1.2",
			trustedProxies: "192.168.1.1",
			want:           false,
		},
		{
			name:           "CIDR match",
			ipStr:          "192.168.1.50",
			trustedProxies: "192.168.1.0/24",
			want:           true,
		},
		{
			name:           "CIDR no match",
			ipStr:          "192.168.2.50",
			trustedProxies: "192.168.1.0/24",
			want:           false,
		},
		{
			name:           "multiple proxies - match first",
			ipStr:          "10.0.0.1",
			trustedProxies: "10.0.0.1,192.168.1.0/24",
			want:           true,
		},
		{
			name:           "multiple proxies - match second CIDR",
			ipStr:          "192.168.1.100",
			trustedProxies: "10.0.0.1,192.168.1.0/24",
			want:           true,
		},
		{
			name:           "localhost IPv4",
			ipStr:          "127.0.0.1",
			trustedProxies: "127.0.0.1",
			want:           true,
		},
		{
			name:           "empty trusted proxies",
			ipStr:          "192.168.1.1",
			trustedProxies: "",
			want:           false,
		},
		{
			name:           "invalid IP",
			ipStr:          "not-an-ip",
			trustedProxies: "192.168.1.0/24",
			want:           false,
		},
		{
			name:           "whitespace in trusted proxies",
			ipStr:          "192.168.1.1",
			trustedProxies: " 192.168.1.1 , 10.0.0.1 ",
			want:           true,
		},
		{
			name:           "invalid CIDR ignored at runtime (rejected at config load instead)",
			ipStr:          "192.168.1.1",
			trustedProxies: "192.168.1.0/invalid-marker-1",
			want:           false,
		},
		{
			name:           "IPv6 address",
			ipStr:          "::1",
			trustedProxies: "::1",
			want:           true,
		},
		{
			name:           "IPv6 CIDR",
			ipStr:          "2001:db8::1",
			trustedProxies: "2001:db8::/32",
			want:           true,
		},
		{
			name:           "IPv4-mapped IPv6 address matches IPv4 CIDR",
			ipStr:          "::ffff:192.168.1.50",
			trustedProxies: "192.168.1.0/24",
			want:           true,
		},
		{
			name:           "cloudflare keyword trusts published edge range",
			ipStr:          "173.245.48.1",
			trustedProxies: "cloudflare",
			want:           true,
		},
		{
			name:           "cloudflare keyword is case-insensitive",
			ipStr:          "173.245.48.1",
			trustedProxies: "CloudFlare",
			want:           true,
		},
		{
			name:           "cloudflare keyword ipv6 range",
			ipStr:          "2400:cb00::1",
			trustedProxies: "cloudflare",
			want:           true,
		},
		{
			name:           "cloudflare keyword does not trust arbitrary public IP",
			ipStr:          "8.8.8.8",
			trustedProxies: "cloudflare",
			want:           false,
		},
		{
			name:           "cloudflare keyword combined with RFC1918 list",
			ipStr:          "10.0.0.5",
			trustedProxies: "10.0.0.0/8,cloudflare",
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTrustedProxyIP(tt.ipStr, tt.trustedProxies)
			if got != tt.want {
				t.Errorf("IsTrustedProxyIP(%q, %q) = %v, want %v", tt.ipStr, tt.trustedProxies, got, tt.want)
			}
		})
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{
			name: "IPv4 with port",
			addr: "192.168.1.1:8080",
			want: "192.168.1.1",
		},
		{
			name: "IPv4 without port",
			addr: "192.168.1.1",
			want: "192.168.1.1",
		},
		{
			name: "IPv6 with brackets and port",
			addr: "[::1]:8080",
			want: "::1",
		},
		{
			name: "IPv6 with brackets no port",
			addr: "[::1]",
			want: "::1",
		},
		{
			name: "IPv6 without brackets",
			addr: "::1",
			want: "::1",
		},
		{
			name: "full IPv6 without port",
			addr: "2001:db8::1",
			want: "2001:db8::1",
		},
		{
			name: "full IPv6 with brackets and port",
			addr: "[2001:db8::1]:443",
			want: "2001:db8::1",
		},
		{
			name: "localhost with port",
			addr: "127.0.0.1:3000",
			want: "127.0.0.1",
		},
		{
			name: "empty string",
			addr: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractIP(tt.addr)
			if got != tt.want {
				t.Errorf("ExtractIP(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

// TestGetClientIPWithTrust_ProductionChain covers the T41 production chain:
// client -> Cloudflare -> Traefik -> SafeShare. Traefik keeps whatever XFF
// the client sent and appends the Cloudflare edge address; Cloudflare
// appends the real client IP to whatever XFF the client sent. So the header
// SafeShare sees is "<client-controlled...>, <real client>, <cf edge>".
func TestGetClientIPWithTrust_ProductionChain(t *testing.T) {
	const defaultTrustedProxies = "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
	const withCloudflare = defaultTrustedProxies + ",cloudflare"

	// Traefik runs on the docker network and connects to SafeShare from a
	// private address; that's the immediate peer (RemoteAddr).
	const traefikPeer = "172.20.0.5:54321"
	// A Cloudflare edge IP (within the published ranges).
	const cfEdge = "172.64.1.1"
	const realClient = "203.0.113.42"
	const spoofedLeftmost = "6.6.6.6"

	xff := spoofedLeftmost + ", " + realClient + ", " + cfEdge

	t.Run("without cloudflare keyword: CF edge IP is returned (documented misconfiguration symptom)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", xff)

		got := GetClientIPWithTrust(req, "auto", defaultTrustedProxies, false)
		if got != cfEdge {
			t.Errorf("got %q, want %q (operator must add the Cloudflare hop to TRUSTED_PROXY_IPS)", got, cfEdge)
		}
	})

	t.Run("with cloudflare keyword: real client IP is returned, spoofed leftmost entry ignored", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", xff)
		// A Cloudflare hop is consumed here, so the CF-Connecting-IP veto
		// (see TestGetClientIPWithTrust_CFConnectingIPVeto) applies: the
		// real edge would set this to the real client's IP.
		req.Header.Set("CF-Connecting-IP", realClient)

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		if got != realClient {
			t.Errorf("got %q, want %q", got, realClient)
		}
	})

	t.Run("TRUST_PROXY_HEADERS=true still uses rightmost-untrusted walk, not leftmost", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "8.8.8.8:12345" // untrusted peer, but "true" trusts headers unconditionally
		req.Header.Set("X-Forwarded-For", xff)
		req.Header.Set("CF-Connecting-IP", realClient)

		got := GetClientIPWithTrust(req, "true", withCloudflare, false)
		if got != realClient {
			t.Errorf("got %q, want %q", got, realClient)
		}
	})
}

// TestGetClientIPWithTrust_CloudflareWorkerLaundering is a bug-hunter
// follow-up on T41: a Cloudflare Worker (or any Cloudflare product) can
// itself originate a request from inside Cloudflare's published IP ranges.
// If the walk kept skipping every *consecutive* trusted entry once the
// "cloudflare" keyword is configured, an attacker-controlled Worker could
// launder an arbitrary leftmost X-Forwarded-For entry past two
// Cloudflare-range hops (its own egress IP, then the edge IP Cloudflare
// presents to our reverse proxy) and have it accepted as the client. The
// fix allows at most one Cloudflare-range entry to ever be skipped as a
// hop; the entry immediately to its left is always the client, even if it
// also happens to fall inside a Cloudflare or local trusted range.
//
// Every case here that resolves to something other than the consumed
// Cloudflare hop / RemoteAddr also depends on trusting Cloudflare (see
// GetClientIPWithTrust's cfConsumed/dependsOnCF tracking), so each now also
// sets a matching CF-Connecting-IP header -- the value the real Cloudflare
// edge would set for that topology -- to satisfy the CF-Connecting-IP veto
// added as a second bug-hunter follow-up. See
// TestGetClientIPWithTrust_CFConnectingIPVeto for what happens when that
// header is absent, mismatched, or a Worker bypasses Cloudflare entirely.
func TestGetClientIPWithTrust_CloudflareWorkerLaundering(t *testing.T) {
	const defaultTrustedProxies = "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
	const withCloudflare = defaultTrustedProxies + ",cloudflare"
	const traefikPeer = "172.18.0.5:54321"

	t.Run("Worker's own CF-range egress IP is attributed as the client, not the attacker's forged leftmost entry", func(t *testing.T) {
		// 6.6.6.6 is attacker-forged; 2a06:98c0:3600::103 is the Worker's own
		// egress (inside 2a06:98c0::/29, a published Cloudflare v6 range);
		// 162.158.1.1 is the Cloudflare edge IP as seen by Traefik (inside
		// 162.158.0.0/15). Cloudflare's real edge sets CF-Connecting-IP to
		// the Worker's own egress IP -- the same value it appended to XFF.
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", "6.6.6.6, 2a06:98c0:3600::103, 162.158.1.1")
		req.Header.Set("CF-Connecting-IP", "2a06:98c0:3600::103")

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		const wantWorkerEgress = "2a06:98c0:3600::103"
		if got != wantWorkerEgress {
			t.Errorf("got %q, want %q (the attacker-forged leftmost entry 6.6.6.6 must never be returned)", got, wantWorkerEgress)
		}
	})

	t.Run("all-Cloudflare-range chain does not fall back to a spoofable loopback leftmost entry", func(t *testing.T) {
		// A chain where every entry -- including the attacker-supplied
		// leftmost one -- happens to look like a trusted address (loopback
		// here) must not resolve to that leftmost entry once a Cloudflare
		// hop has been consumed: the entry immediately after the consumed
		// Cloudflare hop wins unconditionally, and only then if
		// CF-Connecting-IP confirms it.
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", "127.0.0.1, 162.158.2.2, 162.158.1.1")
		req.Header.Set("CF-Connecting-IP", "162.158.2.2")

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		const wantSecondCFHop = "162.158.2.2"
		if got != wantSecondCFHop {
			t.Errorf("got %q, want %q (must not resolve to the spoofable leftmost loopback entry 127.0.0.1)", got, wantSecondCFHop)
		}
	})

	t.Run("direct Cloudflare connection, no local reverse proxy: RemoteAddr itself consumes the one Cloudflare hop", func(t *testing.T) {
		// SafeShare sits directly behind Cloudflare with no Traefik/nginx in
		// between: RemoteAddr is itself a Cloudflare edge address. A
		// Worker's own (Cloudflare-range) egress IP in X-Forwarded-For must
		// NOT additionally be skipped as "the Cloudflare hop" -- that budget
		// was already spent by the direct connection. This now also
		// requires a matching CF-Connecting-IP (this exact shape -- a
		// forged XFF with a direct Cloudflare-range RemoteAddr -- is the
		// scenario TestGetClientIPWithTrust_CFConnectingIPVeto's "Worker
		// connecting directly as RemoteAddr" case shows fails closed
		// without it).
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "162.158.1.1:443" // Cloudflare edge connecting directly
		req.Header.Set("X-Forwarded-For", "6.6.6.6, 2a06:98c0:3600::103")
		req.Header.Set("CF-Connecting-IP", "2a06:98c0:3600::103")

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		const wantWorkerEgress = "2a06:98c0:3600::103"
		if got != wantWorkerEgress {
			t.Errorf("got %q, want %q", got, wantWorkerEgress)
		}
	})

	t.Run("direct Cloudflare connection, ordinary (non-Worker) visitor resolves correctly", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "162.158.1.1:443"
		req.Header.Set("X-Forwarded-For", "203.0.113.42")
		req.Header.Set("CF-Connecting-IP", "203.0.113.42")

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		const wantRealClient = "203.0.113.42"
		if got != wantRealClient {
			t.Errorf("got %q, want %q", got, wantRealClient)
		}
	})

	t.Run("CF -> Traefik -> SafeShare without the keyword: still stops at the CF edge IP (unaffected by the budget fix)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", "6.6.6.6, 2a06:98c0:3600::103, 162.158.1.1")

		got := GetClientIPWithTrust(req, "auto", defaultTrustedProxies, false)
		const wantCFEdge = "162.158.1.1"
		if got != wantCFEdge {
			t.Errorf("got %q, want %q", got, wantCFEdge)
		}
	})
}

// TestGetClientIPWithTrust_CFConnectingIPVeto is a third-pass bug-hunter
// follow-up on T41: the one-Cloudflare-hop budget closes the
// Worker->edge->Traefik path, but two further topologies still let a Worker
// launder its own chosen IP:
//
//   - Cloudflare Tunnel: the entry SafeShare's own reverse proxy appends
//     represents the tunnel daemon's own local address, not a published
//     Cloudflare range, so the walk still treats it as a local hop and can
//     land on an attacker-forged entry past the Worker's own egress hop.
//   - A Worker connecting to the origin directly, bypassing Cloudflare's
//     actual edge/proxy layer: RemoteAddr itself is a Cloudflare-range
//     address with no local reverse proxy in front, so the one-hop budget
//     is pre-spent and anything in X-Forwarded-For or X-Real-IP is
//     attacker-supplied with nothing vouching for it at all.
//
// The fix: whenever the result depends on trusting Cloudflare, it's only
// accepted if it matches the CF-Connecting-IP header Cloudflare's real
// edge/proxy layer sets (see applyCFConnectingIPVeto). The header is only
// ever a veto -- a missing, malformed, or mismatched header falls back to
// the Cloudflare hop (or RemoteAddr) instead, never to the header's value.
func TestGetClientIPWithTrust_CFConnectingIPVeto(t *testing.T) {
	const defaultTrustedProxies = "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
	const withCloudflare = defaultTrustedProxies + ",cloudflare"
	// Traefik's own docker-network peer address, itself within
	// 172.16.0.0/12 (the default local trust list).
	const traefikPeer = "172.18.0.2:54321"

	t.Run("production path: legit visitor is accepted when CF-Connecting-IP confirms the walk's candidate", func(t *testing.T) {
		const realClient = "203.0.113.42"
		const cfEdge = "162.158.1.1"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", "6.6.6.6, "+realClient+", "+cfEdge)
		req.Header.Set("CF-Connecting-IP", realClient)

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		if got != realClient {
			t.Errorf("got %q, want %q", got, realClient)
		}
	})

	t.Run("Worker via edge: candidate equals CF-Connecting-IP, accepted as the Worker's own egress IP", func(t *testing.T) {
		const workerEgress = "2a06:98c0:3600::103"
		const cfEdge = "162.158.1.1"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", "6.6.6.6, "+workerEgress+", "+cfEdge)
		req.Header.Set("CF-Connecting-IP", workerEgress)

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		if got != workerEgress {
			t.Errorf("got %q, want %q", got, workerEgress)
		}
	})

	t.Run("Cloudflare Tunnel: appended hop is the tunnel daemon's local address, not a CF range; forged leftmost is vetoed onto the consumed Cloudflare hop", func(t *testing.T) {
		// cloudflared (running the Tunnel) forwards what Cloudflare's edge
		// already set, and Traefik then appends ITS OWN peer -- cloudflared's
		// local container address -- as the rightmost XFF entry. That local
		// address is trusted as an ordinary local hop (correctly -- it IS
		// our own trusted infrastructure), so the walk continues left and
		// consumes the Worker's own Cloudflare-range egress IP as the one
		// Cloudflare hop, landing the naive candidate on the attacker-forged
		// leftmost entry. No CF-Connecting-IP is presented here (simulating
		// either it being absent or simply not matching); either way the
		// veto must not accept the forged candidate.
		const workerEgress = "2a06:98c0:3600::103"
		const cloudflaredLocal = "172.18.0.5"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", "6.6.6.6, "+workerEgress+", "+cloudflaredLocal)

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		if got != workerEgress {
			t.Errorf("got %q, want %q (fail-closed onto the consumed Cloudflare hop, never the forged 6.6.6.6)", got, workerEgress)
		}
	})

	t.Run("Cloudflare Tunnel: a genuine CF-Connecting-IP for the Worker's own egress still doesn't let the forged entry through", func(t *testing.T) {
		const workerEgress = "2a06:98c0:3600::103"
		const cloudflaredLocal = "172.18.0.5"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", "6.6.6.6, "+workerEgress+", "+cloudflaredLocal)
		req.Header.Set("CF-Connecting-IP", workerEgress) // matches the real CF hop, not the forged leftmost

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		if got != workerEgress {
			t.Errorf("got %q, want %q", got, workerEgress)
		}
	})

	t.Run("Worker bypassing Cloudflare via Traefik with no CF-Connecting-IP: vetoed onto the Worker's own egress hop", func(t *testing.T) {
		const workerEgress = "2a06:98c0:3600::103"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", "6.6.6.6, "+workerEgress)

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		if got != workerEgress {
			t.Errorf("got %q, want %q", got, workerEgress)
		}
	})

	t.Run("Worker connecting directly as RemoteAddr with a forged X-Forwarded-For: vetoed onto the peer IP", func(t *testing.T) {
		const workerEgress = "162.158.1.1"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = workerEgress + ":443"
		req.Header.Set("X-Forwarded-For", "6.6.6.6")

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		if got != workerEgress {
			t.Errorf("got %q, want %q", got, workerEgress)
		}
	})

	t.Run("Worker connecting directly as RemoteAddr with a forged X-Real-IP: vetoed onto the peer IP", func(t *testing.T) {
		const workerEgress = "162.158.1.1"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = workerEgress + ":443"
		req.Header.Set("X-Real-IP", "6.6.6.6")

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		if got != workerEgress {
			t.Errorf("got %q, want %q", got, workerEgress)
		}
	})

	t.Run("missing CF-Connecting-IP header always fails closed, even for an otherwise-plausible candidate", func(t *testing.T) {
		const cfEdge = "162.158.1.1"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", "203.0.113.42, "+cfEdge)

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		if got != cfEdge {
			t.Errorf("got %q, want %q (fail closed onto the Cloudflare hop without the header)", got, cfEdge)
		}
	})

	t.Run("malformed CF-Connecting-IP header fails closed", func(t *testing.T) {
		const realClient = "203.0.113.42"
		const cfEdge = "162.158.1.1"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", realClient+", "+cfEdge)
		req.Header.Set("CF-Connecting-IP", "not-an-ip")

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		if got != cfEdge {
			t.Errorf("got %q, want %q", got, cfEdge)
		}
	})

	t.Run("Pseudo-IPv4 add-header mode: CF-Connecting-IP stays IPv6 and matches the candidate directly", func(t *testing.T) {
		const realClientV6 = "2001:db8::42"
		const cfEdge = "162.158.1.1"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", realClientV6+", "+cfEdge)
		req.Header.Set("CF-Connecting-IP", realClientV6)
		req.Header.Set("Cf-Pseudo-IPv4", "192.0.2.1") // present, not needed for this match

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		if got != realClientV6 {
			t.Errorf("got %q, want %q", got, realClientV6)
		}
	})

	t.Run("Pseudo-IPv4 overwrite mode: both CF-Connecting-IP and the XFF entry become the pseudo IPv4, accepted via direct match", func(t *testing.T) {
		const pseudoV4 = "192.0.2.1"
		const cfEdge = "162.158.1.1"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", pseudoV4+", "+cfEdge)
		req.Header.Set("CF-Connecting-IP", pseudoV4)

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		if got != pseudoV4 {
			t.Errorf("got %q, want %q", got, pseudoV4)
		}
	})

	t.Run("Cf-Pseudo-IPv4 is ignored: a Worker cannot use it to launder a spoofed entry past the veto", func(t *testing.T) {
		// Tunnel + Worker: the only Cloudflare-range entry is the Worker's own
		// egress IP, so the walk lands on the attacker-written entry. The real
		// edge sets CF-Connecting-IP to the Worker's IP; the Worker sets
		// Cf-Pseudo-IPv4 to match its spoof. The veto must still fire.
		const worker = "2a06:98c0:3600::103"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.2:4242"
		req.Header.Set("X-Forwarded-For", "6.6.6.6, "+worker+", 172.18.0.5")
		req.Header.Set("CF-Connecting-IP", worker)
		req.Header.Set("Cf-Pseudo-IPv4", "6.6.6.6")

		got := GetClientIPWithTrust(req, "auto", withCloudflare, false)
		if got != worker {
			t.Errorf("got %q, want %q (veto must ignore Cf-Pseudo-IPv4)", got, worker)
		}
	})

	t.Run("no cloudflare keyword configured: veto never applies even with a Cloudflare-range hop and no header", func(t *testing.T) {
		const cfEdge = "162.158.1.1"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = traefikPeer
		req.Header.Set("X-Forwarded-For", "6.6.6.6, "+cfEdge)

		got := GetClientIPWithTrust(req, "auto", defaultTrustedProxies, false)
		if got != cfEdge {
			t.Errorf("got %q, want %q", got, cfEdge)
		}
	})
}

func TestGetClientIPWithTrust(t *testing.T) {
	tests := []struct {
		name              string
		remoteAddr        string
		xForwardedFor     []string // one entry per X-Forwarded-For header line
		xRealIP           string
		trustProxyHeaders string
		trustedProxyIPs   string
		anonymousMode     bool
		want              string
	}{
		{
			name:              "trust=false returns RemoteAddr even with XFF present",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"10.0.0.1"},
			trustProxyHeaders: "false",
			trustedProxyIPs:   "",
			want:              "192.168.1.1",
		},
		{
			name:              "trust=true single XFF entry (no trusted list to skip) returns that entry",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"10.0.0.1"},
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "10.0.0.1",
		},
		{
			name:              "spoofed leftmost entry is ignored: rightmost untrusted entry wins",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"10.0.0.1, 172.16.0.1, 192.168.1.1"},
			trustProxyHeaders: "true",
			trustedProxyIPs:   "172.16.0.1,192.168.1.1", // both rightmost hops are trusted proxies
			want:              "10.0.0.1",               // first untrusted entry walking from the right
		},
		{
			name:              "no trusted list configured: rightmost entry is returned even though it's a proxy",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"10.0.0.1, 172.16.0.1, 192.168.1.1"},
			trustProxyHeaders: "true",
			trustedProxyIPs:   "", // nothing is trusted, so nothing is skipped
			want:              "192.168.1.1",
		},
		{
			name:              "trust=true prefers X-Forwarded-For over X-Real-IP",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"10.0.0.1"},
			xRealIP:           "172.16.0.1",
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "10.0.0.1",
		},
		{
			name:              "trust=true uses X-Real-IP when X-Forwarded-For absent",
			remoteAddr:        "192.168.1.1:8080",
			xRealIP:           "172.16.0.1",
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "172.16.0.1",
		},
		{
			name:              "trust=auto with trusted proxy uses X-Forwarded-For",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"10.0.0.1"},
			trustProxyHeaders: "auto",
			trustedProxyIPs:   "192.168.1.1",
			want:              "10.0.0.1",
		},
		{
			name:              "trust=auto with untrusted proxy returns RemoteAddr, ignores XFF entirely",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"10.0.0.1"},
			trustProxyHeaders: "auto",
			trustedProxyIPs:   "10.0.0.0/8",
			want:              "192.168.1.1",
		},
		{
			name:              "trust=true falls back to RemoteAddr when no headers at all",
			remoteAddr:        "192.168.1.1:8080",
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "192.168.1.1",
		},
		{
			name:              "unknown trust mode defaults to auto behavior",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"10.0.0.1"},
			trustProxyHeaders: "unknown",
			trustedProxyIPs:   "192.168.1.1",
			want:              "10.0.0.1",
		},
		{
			name:              "multiple X-Forwarded-For header lines concatenate in order",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"203.0.113.9", "192.168.1.1"},
			trustProxyHeaders: "true",
			trustedProxyIPs:   "192.168.1.1", // only the last line's entry is trusted
			want:              "203.0.113.9",
		},
		{
			name:              "garbage rightmost entry with no trusted hop walked: XFF unusable, fall back to RemoteAddr (not X-Real-IP)",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"203.0.113.9, garbage-not-an-ip"},
			xRealIP:           "198.51.100.1",
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "192.168.1.1",
		},
		{
			name:              "garbage entry after a trusted hop: falls back to the last trusted hop, not RemoteAddr",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"garbage-not-an-ip, 10.0.0.1"},
			trustProxyHeaders: "true",
			trustedProxyIPs:   "10.0.0.1",
			want:              "10.0.0.1",
		},
		{
			name:              "unknown literal entry treated as garbage",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"unknown"},
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "192.168.1.1",
		},
		{
			name:              "entry with port is normalized rather than rejected",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"203.0.113.9:4433"},
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "203.0.113.9",
		},
		{
			name:              "bracketed IPv6 entry with port is normalized",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"[2001:db8::9]:4433"},
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "2001:db8::9",
		},
		{
			name:              "all entries trusted: leftmost entry is returned",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"10.0.0.1, 10.0.0.2, 10.0.0.3"},
			trustProxyHeaders: "true",
			trustedProxyIPs:   "10.0.0.0/8",
			want:              "10.0.0.1",
		},
		{
			name:              "IPv4-mapped IPv6 XFF entry is unmapped",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{"::ffff:203.0.113.9"},
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "203.0.113.9",
		},
		{
			name:              "untrusted peer ignores headers entirely under auto",
			remoteAddr:        "203.0.113.5:8080",
			xForwardedFor:     []string{"6.6.6.6"},
			xRealIP:           "7.7.7.7",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1",
			want:              "203.0.113.5",
		},
		{
			name:              "X-Real-IP invalid value is ignored, falls back to RemoteAddr",
			remoteAddr:        "192.168.1.1:8080",
			xRealIP:           "not-an-ip",
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "192.168.1.1",
		},
		{
			name:              "empty XFF header value is treated as unusable, not absent",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     []string{""},
			xRealIP:           "198.51.100.1",
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for _, v := range tt.xForwardedFor {
				req.Header.Add("X-Forwarded-For", v)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			got := GetClientIPWithTrust(req, tt.trustProxyHeaders, tt.trustedProxyIPs, tt.anonymousMode)
			if got != tt.want {
				t.Errorf("GetClientIPWithTrust() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIpInCIDR(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		cidr string
		want bool
	}{
		{
			name: "IP in CIDR",
			ip:   "192.168.1.100",
			cidr: "192.168.1.0/24",
			want: true,
		},
		{
			name: "IP not in CIDR",
			ip:   "192.168.2.1",
			cidr: "192.168.1.0/24",
			want: false,
		},
		{
			name: "invalid CIDR",
			ip:   "192.168.1.1",
			cidr: "invalid-marker-2",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use IsTrustedProxyIP to test CIDR matching indirectly
			got := IsTrustedProxyIP(tt.ip, tt.cidr)
			if got != tt.want {
				t.Errorf("IsTrustedProxyIP(%q, %q) = %v, want %v", tt.ip, tt.cidr, got, tt.want)
			}
		})
	}
}

func TestParseTrustedProxyList(t *testing.T) {
	t.Run("valid mixed list", func(t *testing.T) {
		prefixes, err := ParseTrustedProxyList("127.0.0.1,10.0.0.0/8, 192.168.1.10 ,cloudflare")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// 1 (127.0.0.1) + 1 (10.0.0.0/8) + 1 (192.168.1.10) + 15 (CF v4) + 7 (CF v6) = 25
		if want := 25; len(prefixes) != want {
			t.Errorf("len(prefixes) = %d, want %d", len(prefixes), want)
		}
	})

	t.Run("rejects unknown keyword", func(t *testing.T) {
		_, err := ParseTrustedProxyList("10.0.0.0/8,not-a-real-keyword")
		if err == nil {
			t.Fatal("expected error for unknown keyword, got nil")
		}
	})

	t.Run("rejects malformed CIDR", func(t *testing.T) {
		_, err := ParseTrustedProxyList("10.0.0.0/99")
		if err == nil {
			t.Fatal("expected error for malformed CIDR, got nil")
		}
	})

	t.Run("empty string yields no prefixes and no error", func(t *testing.T) {
		prefixes, err := ParseTrustedProxyList("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(prefixes) != 0 {
			t.Errorf("len(prefixes) = %d, want 0", len(prefixes))
		}
	})

	t.Run("cloudflare keyword is case-insensitive", func(t *testing.T) {
		_, err := ParseTrustedProxyList("CLOUDFLARE")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// TestGetClientIPWithTrust_HopCap is a bug-hunter follow-up on T41: an
// unbounded X-Forwarded-For chain must not be walked indefinitely. Beyond
// maxForwardedForHops the walk stops and applies the same safe fallback as
// a malformed entry: the last trusted hop already walked, or RemoteAddr if
// none was.
func TestGetClientIPWithTrust_HopCap(t *testing.T) {
	t.Run("an untrusted rightmost entry resolves immediately without needing the cap, even in a long chain", func(t *testing.T) {
		// The cap only ever matters while hops are being *skipped* (trusted
		// local/Cloudflare entries); the first untrusted, well-formed entry
		// walking from the right always ends the walk immediately. So a
		// hop-cap "no trusted hop walked" fallback to RemoteAddr can only
		// happen via a malformed rightmost entry (see the "garbage
		// rightmost entry" and "unknown literal entry" cases in
		// TestGetClientIPWithTrust), never via merely exceeding the cap.
		entries := make([]string, 40)
		for i := range entries {
			entries[i] = "203.0.113.1" // never trusted under any config used here
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:8080"
		req.Header.Set("X-Forwarded-For", strings.Join(entries, ", "))

		got := GetClientIPWithTrust(req, "true", "", false)
		if got != "203.0.113.1" {
			t.Errorf("got %q, want %q", got, "203.0.113.1")
		}
	})

	t.Run("a trusted hop walked before the cap is returned instead of continuing indefinitely", func(t *testing.T) {
		entries := make([]string, 35)
		for i := range entries {
			entries[i] = "10.0.0.1"
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:8080"
		req.Header.Set("X-Forwarded-For", strings.Join(entries, ", "))

		got := GetClientIPWithTrust(req, "true", "10.0.0.0/8", false)
		if got != "10.0.0.1" {
			t.Errorf("got %q, want %q (last trusted hop before the cap)", got, "10.0.0.1")
		}
	})

	t.Run("a chain of exactly the cap length is walked in full", func(t *testing.T) {
		entries := make([]string, maxForwardedForHops)
		entries[0] = "203.0.113.9" // leftmost: real client
		for i := 1; i < len(entries); i++ {
			entries[i] = "10.0.0.1" // remaining (rightmost) hops: trusted proxy
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:8080"
		req.Header.Set("X-Forwarded-For", strings.Join(entries, ", "))

		got := GetClientIPWithTrust(req, "true", "10.0.0.0/8", false)
		if got != "203.0.113.9" {
			t.Errorf("got %q, want %q", got, "203.0.113.9")
		}
	})
}

// TestGetClientIPWithTrust_LargeXFFBoundedAllocation is a bug-hunter
// follow-up on T41: a large X-Forwarded-For header (an attacker can send
// megabytes of comma-separated entries) used to be split into a slice
// holding every hop, allocating memory proportional to the header size on
// every call -- and this function is called 3-4 times per request. The
// cursor-based walk must do a small, constant number of allocations
// regardless of header size, and the hop cap must stop it from ever
// processing more than maxForwardedForHops entries.
func TestGetClientIPWithTrust_LargeXFFBoundedAllocation(t *testing.T) {
	const hopCount = 100000
	var sb strings.Builder
	for i := 0; i < hopCount; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString("10.0.0.1")
	}
	xff := sb.String() // every one of 100,000 entries is a trusted local proxy

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:8080"
	req.Header.Set("X-Forwarded-For", xff)

	var got string
	allocs := testing.AllocsPerRun(50, func() {
		got = GetClientIPWithTrust(req, "true", "10.0.0.0/8", false)
	})

	if got != "10.0.0.1" {
		t.Errorf("got %q, want %q (hop cap fallback to the last trusted hop)", got, "10.0.0.1")
	}
	if allocs > 20 {
		t.Errorf("GetClientIPWithTrust with a %d-hop XFF allocated %.1f times per call, want a small constant (<=20)", hopCount, allocs)
	}
}

// BenchmarkGetClientIPWithTrust_LargeXFF reports the time and allocation
// cost of resolving the client IP behind a very large X-Forwarded-For
// header. Run with -bench=LargeXFF -benchmem.
func BenchmarkGetClientIPWithTrust_LargeXFF(b *testing.B) {
	const hopCount = 100000
	var sb strings.Builder
	for i := 0; i < hopCount; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString("10.0.0.1")
	}
	xff := sb.String()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:8080"
	req.Header.Set("X-Forwarded-For", xff)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetClientIPWithTrust(req, "true", "10.0.0.0/8", false)
	}
}
