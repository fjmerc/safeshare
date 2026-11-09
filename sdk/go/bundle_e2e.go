package safeshare

// Bundle links and encrypted bundle manifests, compatible with the web app
// (internal/static/web/assets/crypto.js: buildBundleUrl, parseBundleFragment,
// sealManifest, openManifest).
//
// A bundle is several files behind one link: {base}/#/bundle/{code}, or for
// an end-to-end encrypted bundle {base}/#/bundle/{code}/key/{key}. Every file
// in an encrypted bundle is encrypted under the one bundle key, exactly as a
// single encrypted file is, and the bundle also carries a manifest — its
// file list, encrypted under the same key — so a recipient can show real
// names before downloading and can tell if the server dropped, swapped or
// reordered a file.

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	// ErrManifestMismatch means the files a server returned for an encrypted
	// bundle do not match the bundle's own encrypted file list.
	ErrManifestMismatch = errors.New("bundle contents do not match its manifest")

	bundleFragmentPattern = regexp.MustCompile(`^/bundle/([A-Za-z0-9_-]{8,32})(?:/key/([A-Za-z0-9_-]{43}))?$`)
	sha256HexPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// BuildBundleURL returns a bundle link. key is the bundle key for an
// encrypted bundle, or "" for a plain one.
func BuildBundleURL(baseURL, bundleCode, key string) string {
	u := strings.TrimRight(baseURL, "/") + "/#/bundle/" + bundleCode
	if key != "" {
		u += "/key/" + key
	}
	return u
}

// BundleLink is a parsed bundle link.
type BundleLink struct {
	// BaseURL is the server the bundle is on, e.g. "https://share.example.com".
	BaseURL string
	// BundleCode identifies the bundle.
	BundleCode string
	// Key is the base64url bundle key, or "" for a bundle that is not end-to-end encrypted.
	Key string
}

// ParseBundleURL parses a bundle link made by the web app or by
// BuildBundleURL, with the same hardening as ParseShareURL: links with a
// backslash or user info are refused.
func ParseBundleURL(link string) (*BundleLink, error) {
	if before, _, _ := strings.Cut(link, "#"); strings.Contains(link, "\\") || strings.Contains(before, "@") {
		return nil, &ValidationError{Field: "link", Message: "must not contain a backslash or user info"}
	}
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, &ValidationError{Field: "link", Message: "must be an http(s) bundle link"}
	}
	m := bundleFragmentPattern.FindStringSubmatch(u.Fragment)
	if m == nil {
		return nil, &ValidationError{Field: "link", Message: "has no #/bundle/<code> part; it is not a bundle link"}
	}
	if m[2] != "" {
		if _, err := decodeKey(m[2]); err != nil {
			return nil, &ValidationError{Field: "link", Message: "has an invalid key: it must be 32 bytes of base64url"}
		}
	}
	base := url.URL{Scheme: u.Scheme, Host: u.Host, Path: strings.TrimRight(u.Path, "/")}
	return &BundleLink{BaseURL: base.String(), BundleCode: m[1], Key: m[2]}, nil
}

// BundleManifest is the file list of an encrypted bundle.
type BundleManifest struct {
	V     int            `json:"v"`
	Files []ManifestFile `json:"files"`
}

// ManifestFile describes one file of an encrypted bundle. Size and SHA256
// are of the plaintext file (lowercase hex).
type ManifestFile struct {
	Position int    `json:"position"`
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

func (m *BundleManifest) validate() error {
	if m == nil || m.V != 1 || len(m.Files) == 0 {
		return fmt.Errorf("%w: bundle file list is malformed", ErrInvalidPayload)
	}
	for i, f := range m.Files {
		if f.Position != i || f.Size < 0 || !sha256HexPattern.MatchString(f.SHA256) {
			return fmt.Errorf("%w: bundle file list is malformed", ErrInvalidPayload)
		}
	}
	return nil
}

// SealManifest encrypts m under the bundle key: JSON in an SF02 payload with
// no name, padded like a file, then [IV][ciphertext][tag].
func SealManifest(key string, m *BundleManifest) ([]byte, error) {
	k, err := decodeKey(key)
	if err != nil {
		return nil, err
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // match JSON.stringify
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	payload, err := wrapPayload("", bytes.TrimRight(buf.Bytes(), "\n"), true, 0)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, e2eIVLength+len(payload), e2eIVLength+len(payload)+e2eTagLength)
	copy(blob[e2eIVLength:], payload)
	iv := make([]byte, e2eIVLength)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return sealInPlace(k, iv, blob)
}

// OpenManifest decrypts and validates an encrypted bundle's file list.
func OpenManifest(key string, sealed []byte) (*BundleManifest, error) {
	k, err := decodeKey(key)
	if err != nil {
		return nil, err
	}
	pt, err := decryptBlob(k, append([]byte(nil), sealed...))
	if err != nil {
		return nil, err
	}
	u, err := unwrapPayload(pt)
	if err != nil {
		return nil, err
	}
	var m BundleManifest
	dec := json.NewDecoder(bytes.NewReader(u.data))
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: bundle file list is malformed", ErrInvalidPayload)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}
