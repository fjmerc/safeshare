package safeshare

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestBundleVectorsFromWebApp(t *testing.T) {
	v := loadVectors(t)
	if len(v.BundleURL) == 0 || len(v.ManifestRejects) == 0 || v.Manifest.Sealed == "" {
		t.Fatal("vectors have no bundle cases; regenerate them")
	}
	for _, c := range v.BundleURL {
		if got := BuildBundleURL(c.Base, c.BundleCode, c.Key); got != c.URL {
			t.Errorf("BuildBundleURL(%q, %q, %q) = %q, want %q", c.Base, c.BundleCode, c.Key, got, c.URL)
		}
		l, err := ParseBundleURL(c.URL)
		if err != nil || l.BundleCode != c.BundleCode || l.Key != c.Key || l.BaseURL != strings.TrimRight(c.Base, "/") {
			t.Errorf("ParseBundleURL(%q) = %+v, %v", c.URL, l, err)
		}
	}
	for _, hash := range v.BundleFragmentRejects {
		if _, err := ParseBundleURL("https://h.example/" + hash); err == nil {
			t.Errorf("ParseBundleURL accepted fragment %q", hash)
		}
	}

	m, err := OpenManifest(v.Key, unhex(t, v.Manifest.Sealed))
	if err != nil {
		t.Fatalf("OpenManifest(web app manifest): %v", err)
	}
	if !reflect.DeepEqual(*m, v.Manifest.Manifest) {
		t.Fatalf("manifest = %+v, want %+v", *m, v.Manifest.Manifest)
	}
	for _, c := range v.ManifestRejects {
		if _, err := OpenManifest(v.Key, unhex(t, c.Sealed)); err == nil {
			t.Errorf("OpenManifest accepted %s", c.ID)
		}
	}
}

func TestParseBundleURLRejects(t *testing.T) {
	good := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	for _, link := range []string{
		"",
		"ftp://h.example/#/bundle/abcdefgh",
		"https://h.example/bundle/abcdefgh",
		"https://h.example/#/claim/abcdefgh/key/" + good,
		"https://h.example/#/bundle/abc",
		"https://h.example/#/bundle/abcdefgh/key/short",
		"https:///#/bundle/abcdefgh",
		"https://share.example.com@evil.example/#/bundle/abcdefgh",
		"https://good.example\\@evil.example/#/bundle/abcdefgh",
	} {
		if _, err := ParseBundleURL(link); err == nil {
			t.Errorf("ParseBundleURL(%q) accepted", link)
		}
	}
	l, err := ParseBundleURL("  https://h.example:8443/base/#/bundle/abcdefgh/key/" + good + "  ")
	if err != nil || l.BaseURL != "https://h.example:8443/base" || l.BundleCode != "abcdefgh" || l.Key != good {
		t.Fatalf("got %+v, %v", l, err)
	}
	l, err = ParseBundleURL("https://h.example/#/bundle/abcdefgh")
	if err != nil || l.Key != "" {
		t.Fatalf("plain bundle link: %+v, %v", l, err)
	}
}

func TestManifestRoundTrip(t *testing.T) {
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	in := &BundleManifest{V: 1, Files: []ManifestFile{
		{Position: 0, Name: "a <b> & c.png", Size: 3, SHA256: strings.Repeat("ab", 32)},
		{Position: 1, Name: "z", Size: 0, SHA256: strings.Repeat("0f", 32)},
	}}
	sealed, err := SealManifest(key, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) < 4096 {
		t.Fatalf("sealed manifest is %d bytes; it should be padded like a file", len(sealed))
	}
	out, err := OpenManifest(key, sealed)
	if err != nil || !reflect.DeepEqual(out, in) {
		t.Fatalf("round trip: %+v, %v", out, err)
	}
	other, _ := GenerateEncryptionKey()
	if _, err := OpenManifest(other, sealed); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := SealManifest(key, &BundleManifest{V: 1, Files: []ManifestFile{{Position: 1, SHA256: strings.Repeat("ab", 32)}}}); err == nil {
		t.Fatal("SealManifest accepted a manifest whose positions don't start at 0")
	}
}
