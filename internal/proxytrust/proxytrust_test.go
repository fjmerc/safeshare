package proxytrust

import (
	"net/netip"
	"testing"
)

func TestParseList(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{"empty string", "", 0, false},
		{"only whitespace/commas", " , , ", 0, false},
		{"single IP", "127.0.0.1", 1, false},
		{"single CIDR", "10.0.0.0/8", 1, false},
		{"mixed with whitespace", " 127.0.0.1 , 10.0.0.0/8 ", 2, false},
		{"cloudflare keyword expands", "cloudflare", len(CloudflareIPv4Ranges) + len(CloudflareIPv6Ranges), false},
		{"cloudflare keyword case-insensitive", "CLOUDFLARE", len(CloudflareIPv4Ranges) + len(CloudflareIPv6Ranges), false},
		{"cloudflare combined with a CIDR", "10.0.0.0/8,cloudflare", 1 + len(CloudflareIPv4Ranges) + len(CloudflareIPv6Ranges), false},
		{"malformed CIDR", "10.0.0.0/99", 0, true},
		{"malformed IP", "not-an-ip", 0, true},
		{"unknown keyword", "aws", 0, true},
		{"IPv6 address", "::1", 1, false},
		{"IPv6 CIDR", "2001:db8::/32", 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes, err := ParseList(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseList(%q) succeeded, want error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseList(%q) failed: %v", tt.input, err)
			}
			if len(prefixes) != tt.wantLen {
				t.Errorf("ParseList(%q): len = %d, want %d", tt.input, len(prefixes), tt.wantLen)
			}
		})
	}
}

func TestParseList_MappedIPv4CIDR(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantErr    bool
		wantPrefix string // expected String() of the single resulting prefix
	}{
		{
			name:       "mapped /104 unmaps to equivalent plain IPv4 /8",
			input:      "::ffff:10.0.0.0/104",
			wantPrefix: "10.0.0.0/8",
		},
		{
			name:       "mapped /96 unmaps to plain IPv4 /0",
			input:      "::ffff:0.0.0.0/96",
			wantPrefix: "0.0.0.0/0",
		},
		{
			name:       "mapped /128 (single host) unmaps to plain IPv4 /32",
			input:      "::ffff:192.168.1.1/128",
			wantPrefix: "192.168.1.1/32",
		},
		{
			name:    "mapped prefix shorter than /96 is rejected",
			input:   "::ffff:10.0.0.0/64",
			wantErr: true,
		},
		{
			name:    "mapped prefix at /0 is rejected",
			input:   "::ffff:0.0.0.0/0",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes, err := ParseList(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseList(%q) succeeded, want error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseList(%q) failed: %v", tt.input, err)
			}
			if len(prefixes) != 1 {
				t.Fatalf("ParseList(%q): len = %d, want 1", tt.input, len(prefixes))
			}
			if got := prefixes[0].String(); got != tt.wantPrefix {
				t.Errorf("ParseList(%q): prefix = %q, want %q", tt.input, got, tt.wantPrefix)
			}
			// The normalized prefix must actually match what it claims to:
			// a mapped IPv4 address falling in range should be trusted.
			if !tt.wantErr {
				want := netip.MustParsePrefix(tt.wantPrefix)
				if want.Addr().Is4() {
					if !Trusted(want.Addr(), prefixes) {
						t.Errorf("ParseList(%q): resulting prefix %v does not contain its own base address", tt.input, prefixes[0])
					}
				}
			}
		})
	}
}

func TestParseListSplit(t *testing.T) {
	t.Run("local and cloudflare entries are kept separate", func(t *testing.T) {
		local, cf, err := ParseListSplit("10.0.0.0/8,192.168.1.10,cloudflare,172.16.0.0/12")
		if err != nil {
			t.Fatalf("ParseListSplit failed: %v", err)
		}
		if len(local) != 3 {
			t.Errorf("len(local) = %d, want 3", len(local))
		}
		if len(cf) != len(CloudflareIPv4Ranges)+len(CloudflareIPv6Ranges) {
			t.Errorf("len(cloudflare) = %d, want %d", len(cf), len(CloudflareIPv4Ranges)+len(CloudflareIPv6Ranges))
		}
	})

	t.Run("no cloudflare keyword yields empty cloudflare set", func(t *testing.T) {
		local, cf, err := ParseListSplit("10.0.0.0/8")
		if err != nil {
			t.Fatalf("ParseListSplit failed: %v", err)
		}
		if len(local) != 1 {
			t.Errorf("len(local) = %d, want 1", len(local))
		}
		if len(cf) != 0 {
			t.Errorf("len(cloudflare) = %d, want 0", len(cf))
		}
	})

	t.Run("error propagates from either set", func(t *testing.T) {
		if _, _, err := ParseListSplit("10.0.0.0/99"); err == nil {
			t.Error("expected error for malformed CIDR")
		}
		if _, _, err := ParseListSplit("not-a-real-keyword"); err == nil {
			t.Error("expected error for unknown keyword")
		}
	})

	t.Run("ParseList returns the combination of ParseListSplit", func(t *testing.T) {
		local, cf, err := ParseListSplit("10.0.0.0/8,cloudflare")
		if err != nil {
			t.Fatalf("ParseListSplit failed: %v", err)
		}
		combined, err := ParseList("10.0.0.0/8,cloudflare")
		if err != nil {
			t.Fatalf("ParseList failed: %v", err)
		}
		if len(combined) != len(local)+len(cf) {
			t.Errorf("len(combined) = %d, want %d", len(combined), len(local)+len(cf))
		}
	})
}

func TestTrusted(t *testing.T) {
	prefixes, err := ParseList("10.0.0.0/8,192.168.1.10,cloudflare")
	if err != nil {
		t.Fatalf("ParseList failed: %v", err)
	}

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"in CIDR", "10.1.2.3", true},
		{"exact IP match", "192.168.1.10", true},
		{"not matching", "192.168.1.11", false},
		{"cloudflare v4 range", "173.245.48.1", true},
		{"cloudflare v6 range", "2400:cb00::1", true},
		{"public IP not in any range", "8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.ip)
			got := Trusted(NormalizeAddr(addr), prefixes)
			if got != tt.want {
				t.Errorf("Trusted(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestNormalizeAddr(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"IPv4-mapped IPv6 is unmapped", "::ffff:192.168.1.1", "192.168.1.1"},
		{"plain IPv4 unchanged", "192.168.1.1", "192.168.1.1"},
		{"plain IPv6 unchanged", "2001:db8::1", "2001:db8::1"},
		{"zone is dropped", "fe80::1%eth0", "fe80::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.in)
			got := NormalizeAddr(addr).String()
			if got != tt.want {
				t.Errorf("NormalizeAddr(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
