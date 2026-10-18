package config

import (
	"strings"
	"testing"

	"filippo.io/age"
)

func clearDropEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"DROP_RECIPIENT", "DROP_MAX_SIZE", "DROP_MAX_CONCURRENT", "DROP_EXPIRATION_HOURS"} {
		t.Setenv(k, "")
	}
}

func TestLoadDropConfig_OffByDefault(t *testing.T) {
	clearDropEnv(t)
	d, err := loadDropConfig()
	if err != nil {
		t.Fatal(err)
	}
	if d.Enabled() {
		t.Error("drop page on without DROP_RECIPIENT")
	}
	if d.MaxSize != defaultDropMaxSize || d.MaxConcurrent != defaultDropMaxConcurrent || d.ExpirationHours != defaultDropExpirationHours {
		t.Errorf("defaults = %+v", d)
	}
}

func TestLoadDropConfig_Recipients(t *testing.T) {
	x, _ := age.GenerateX25519Identity()
	pq, _ := age.GenerateHybridIdentity()
	for _, key := range []string{x.Recipient().String(), pq.Recipient().String(), "  " + x.Recipient().String() + "\n"} {
		clearDropEnv(t)
		t.Setenv("DROP_RECIPIENT", key)
		d, err := loadDropConfig()
		if err != nil {
			t.Fatalf("%.20s…: %v", key, err)
		}
		if !d.Enabled() || d.RecipientKey != strings.TrimSpace(key) {
			t.Errorf("%.20s…: enabled=%v key=%q", key, d.Enabled(), d.RecipientKey)
		}
	}
}

func TestLoadDropConfig_RejectsBadRecipients(t *testing.T) {
	x, _ := age.GenerateX25519Identity()
	y, _ := age.GenerateX25519Identity()
	secret := x.String()
	cases := map[string]string{
		"private key":       secret,
		"lowercase private": strings.ToLower(secret),
		"two keys":          x.Recipient().String() + "," + y.Recipient().String(),
		"two keys spaced":   x.Recipient().String() + " " + y.Recipient().String(),
		"garbage":           "not-a-key",
		"broken checksum":   x.Recipient().String()[:len(x.Recipient().String())-1] + "q",
		"ssh key":           "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		"plugin":            "age1yubikey1qwerty",
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			clearDropEnv(t)
			t.Setenv("DROP_RECIPIENT", key)
			_, err := loadDropConfig()
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), secret[15:]) || strings.Contains(strings.ToUpper(err.Error()), secret[15:]) {
				t.Errorf("error echoes the private key: %v", err)
			}
		})
	}
}

func TestLoadDropConfig_Numbers(t *testing.T) {
	good := map[string]string{"DROP_MAX_SIZE": "1048576", "DROP_MAX_CONCURRENT": "4", "DROP_EXPIRATION_HOURS": "72"}
	clearDropEnv(t)
	for k, v := range good {
		t.Setenv(k, v)
	}
	d, err := loadDropConfig()
	if err != nil {
		t.Fatal(err)
	}
	if d.MaxSize != 1048576 || d.MaxConcurrent != 4 || d.ExpirationHours != 72 {
		t.Errorf("got %+v", d)
	}

	for _, bad := range []struct{ k, v string }{
		{"DROP_MAX_SIZE", "0"}, {"DROP_MAX_SIZE", "-5"}, {"DROP_MAX_SIZE", "50MB"},
		{"DROP_MAX_CONCURRENT", "0"}, {"DROP_MAX_CONCURRENT", "65"},
		{"DROP_EXPIRATION_HOURS", "x"}, {"DROP_EXPIRATION_HOURS", "99999999"},
	} {
		clearDropEnv(t)
		t.Setenv(bad.k, bad.v)
		if _, err := loadDropConfig(); err == nil {
			t.Errorf("%s=%s accepted", bad.k, bad.v)
		}
	}
}

func TestLoad_FailsOnBadDropRecipient(t *testing.T) {
	clearDropEnv(t)
	t.Setenv("DROP_RECIPIENT", "nope")
	if _, err := Load(); err == nil {
		t.Error("Load accepted an invalid DROP_RECIPIENT")
	}
}
