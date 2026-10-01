package ipcanon

import (
	"errors"
	"testing"
)

func TestCanonicalizePrefix_TooBroadErrorIsErrPrefixTooBroad(t *testing.T) {
	cases := []string{"10.0.0.0/7", "0.0.0.0/0", "2001:db8::/16", "::/0"}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			_, err := CanonicalizePrefix(in)
			if !errors.Is(err, ErrPrefixTooBroad) {
				t.Errorf("CanonicalizePrefix(%q) error = %v, want errors.Is(..., ErrPrefixTooBroad)", in, err)
			}
		})
	}
}

func TestCanonicalizePrefix_GarbageIsNotErrPrefixTooBroad(t *testing.T) {
	_, err := CanonicalizePrefix("not-a-cidr")
	if errors.Is(err, ErrPrefixTooBroad) {
		t.Errorf("CanonicalizePrefix(garbage) unexpectedly matched ErrPrefixTooBroad: %v", err)
	}
	if err == nil {
		t.Fatal("CanonicalizePrefix(garbage) succeeded, want error")
	}
}

func TestCanonicalize(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"uppercase IPv6", "2001:DB8::1", "2001:db8::1", false},
		{"leading zeros IPv6", "2001:0db8::0001", "2001:db8::1", false},
		{"IPv4-mapped IPv6", "::ffff:1.2.3.4", "1.2.3.4", false},
		{"zoned link-local", "fe80::1%eth0", "fe80::1", false},
		{"bare IPv4", "203.0.113.5", "203.0.113.5", false},
		{"whitespace padded", "  203.0.113.5  ", "203.0.113.5", false},
		{"empty", "", "", true},
		{"garbage", "not-an-ip", "", true},
		{"CIDR rejected by Canonicalize", "203.0.113.0/24", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonicalize(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Canonicalize(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("Canonicalize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCanonicalizePrefix(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"v4 /24", "203.0.113.0/24", "203.0.113.0/24", false},
		{"v4 unmasks host bits", "203.0.113.77/24", "203.0.113.0/24", false},
		{"v6 /64", "2001:db8:1:2::/64", "2001:db8:1:2::/64", false},
		{"v6 uppercase", "2001:DB8:1:2::/64", "2001:db8:1:2::/64", false},
		{"v4-mapped v6 prefix", "::ffff:10.0.0.0/104", "10.0.0.0/8", false},
		{"v4 exactly /8 allowed", "10.0.0.0/8", "10.0.0.0/8", false},
		{"v4 broader than /8 rejected", "10.0.0.0/7", "", true},
		{"v4 unspecified rejected", "0.0.0.0/0", "", true},
		{"v6 exactly /32 allowed", "2001:db8::/32", "2001:db8::/32", false},
		{"v6 broader than /32 rejected", "2001:db8::/16", "", true},
		{"v6 unspecified rejected", "::/0", "", true},
		{"garbage", "not-a-cidr", "", true},
		{"bare IP rejected", "203.0.113.5", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalizePrefix(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CanonicalizePrefix(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if err == nil && got.String() != tc.want {
				t.Errorf("CanonicalizePrefix(%q) = %q, want %q", tc.in, got.String(), tc.want)
			}
		})
	}
}

func TestCanonicalizeEntry(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		want         string
		wantIsPrefix bool
		wantErr      bool
	}{
		{"bare v4", "203.0.113.5", "203.0.113.5", false, false},
		{"bare v6 uppercase", "2001:DB8::1", "2001:db8::1", false, false},
		{"mapped v4", "::ffff:1.2.3.4", "1.2.3.4", false, false},
		{"v4 CIDR", "203.0.113.0/24", "203.0.113.0/24", true, false},
		{"v6 CIDR", "2001:db8:1:2::/64", "2001:db8:1:2::/64", true, false},
		{"too-broad CIDR rejected", "10.0.0.0/4", "", true, true},
		{"empty rejected", "", "", false, true},
		{"whitespace only rejected", "   ", "", false, true},
		{"garbage rejected", "definitely-not-an-ip", "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, isPrefix, err := CanonicalizeEntry(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CanonicalizeEntry(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if got != tc.want {
				t.Errorf("CanonicalizeEntry(%q) value = %q, want %q", tc.in, got, tc.want)
			}
			if isPrefix != tc.wantIsPrefix {
				t.Errorf("CanonicalizeEntry(%q) isPrefix = %v, want %v", tc.in, isPrefix, tc.wantIsPrefix)
			}
		})
	}
}
