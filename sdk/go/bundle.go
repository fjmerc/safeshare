package safeshare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// bundleUploadTokenHeader carries the token that lets this client add files
// to, publish, or delete the draft bundle it created.
const bundleUploadTokenHeader = "X-Bundle-Upload-Token"

// bundleMember marks an upload as a file joining a draft bundle.
type bundleMember struct {
	id       int64
	position int
	token    string
}

// withHeader returns h plus the bundle token header (h unchanged for a nil member).
func (m *bundleMember) withHeader(h http.Header) http.Header {
	if m == nil {
		return h
	}
	out := http.Header{}
	for k, v := range h {
		out[k] = v
	}
	out.Set(bundleUploadTokenHeader, m.token)
	return out
}

// BundleFile describes one file of an uploaded bundle.
type BundleFile struct {
	// Position is the file's place in the bundle, from 0.
	Position int `json:"position"`
	// Name is the local file name.
	Name string `json:"name"`
	// Size is the local (plaintext) size in bytes.
	Size int64 `json:"size"`
}

// BundleResult is the result of UploadBundle.
type BundleResult struct {
	BundleCode string `json:"bundle_code"`
	// BundleURL is the link to the bundle. For an encrypted bundle it
	// contains the key: treat it as a secret.
	BundleURL         string       `json:"-"`
	ExpiresAt         *time.Time   `json:"expires_at"`
	DownloadLimit     *int         `json:"download_limit"` // per file; nil = unlimited
	PasswordProtected bool         `json:"password_protected"`
	Encrypted         bool         `json:"encrypted"`
	EncryptionKey     string       `json:"-"`
	Files             []BundleFile `json:"files"`
}

// BundleUploadError reports which file stopped a bundle upload. The draft
// bundle is deleted, so no link to a partial bundle exists.
type BundleUploadError struct {
	Path     string
	Position int
	Err      error
}

func (e *BundleUploadError) Error() string {
	return fmt.Sprintf("uploading %s: %v", e.Path, e.Err)
}

func (e *BundleUploadError) Unwrap() error { return e.Err }

type apiBundleCreateResponse struct {
	BundleID    int64     `json:"bundle_id"`
	BundleCode  string    `json:"bundle_code"`
	UploadToken string    `json:"upload_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type apiBundleResponse struct {
	BundleCode   string    `json:"bundle_code"`
	ExpiresAt    time.Time `json:"expires_at"`
	MaxDownloads *int      `json:"max_downloads"`
}

// UploadBundle uploads several files as one bundle: one code and one link
// for all of them. opts applies to the whole bundle (expiry, per-file
// download limit, password, encryption); opts.OnProgress reports each file
// in turn. If any file fails, the draft is deleted and a *BundleUploadError
// says which file; no link is returned.
func (c *Client) UploadBundle(ctx context.Context, paths []string, opts *UploadOptions) (*BundleResult, error) {
	if opts == nil {
		opts = &UploadOptions{}
	}
	if len(paths) == 0 {
		return nil, &ValidationError{Field: "paths", Message: "at least one file is required"}
	}

	type localFile struct {
		path, name string
		size       int64
	}
	files := make([]localFile, 0, len(paths))
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("resolving path: %w", err)
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf("getting file info: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, &ValidationError{Field: "paths", Message: p + " is not a regular file"}
		}
		name := filepath.Base(abs)
		if err := validateFilename(name); err != nil {
			return nil, err
		}
		files = append(files, localFile{path: abs, name: name, size: info.Size()})
	}

	cfg, err := c.GetConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting config: %w", err)
	}
	encrypt, err := shouldEncrypt(opts.Encrypt, cfg)
	if err != nil {
		return nil, err
	}
	var key string
	if encrypt {
		if key, err = GenerateEncryptionKey(); err != nil {
			return nil, err
		}
	}

	createBody := map[string]any{"file_count": len(files), "client_encrypted": encrypt}
	if opts.ExpiresInHours != nil {
		createBody["expires_in_hours"] = *opts.ExpiresInHours
	}
	if opts.DownloadLimit != nil {
		createBody["max_downloads"] = *opts.DownloadLimit
	}
	if opts.Password != "" {
		createBody["password"] = opts.Password
	}
	raw, _ := json.Marshal(createBody)
	resp, err := c.doRequest(ctx, http.MethodPost, "/api/bundles", bytes.NewReader(raw), "application/json", "", clientEncryptedHeader(encrypt))
	if err != nil {
		return nil, err
	}
	var draft apiBundleCreateResponse
	if err := handleResponse(resp, &draft); err != nil {
		return nil, err
	}
	if err := checkServerClaimCode(draft.BundleCode); err != nil {
		return nil, err
	}
	member := &bundleMember{id: draft.BundleID, token: draft.UploadToken}

	fail := func(i int, err error) (*BundleResult, error) {
		c.deleteDraftBundle(ctx, member)
		return nil, &BundleUploadError{Path: paths[i], Position: i, Err: err}
	}

	manifest := &BundleManifest{V: 1}
	result := &BundleResult{BundleCode: draft.BundleCode, Encrypted: encrypt, EncryptionKey: key, PasswordProtected: opts.Password != ""}
	for i, f := range files {
		m := *member
		m.position = i
		fileOpts := *opts
		fileOpts.member, fileOpts.bundleKey = &m, key

		if encrypt {
			sum, err := hashFile(f.path)
			if err != nil {
				return fail(i, err)
			}
			manifest.Files = append(manifest.Files, ManifestFile{Position: i, Name: f.name, Size: f.size, SHA256: sum})
			_, err = c.uploadEncrypted(ctx, f.path, f.name, f.size, cfg, &fileOpts)
			if err != nil {
				return fail(i, err)
			}
		} else {
			src := fileSource(f.path, f.name, f.size)
			if f.size >= cfg.ChunkUploadThreshold {
				_, err = c.uploadChunked(ctx, src, &fileOpts, false)
			} else {
				_, err = c.uploadSimple(ctx, src, &fileOpts, false)
			}
			if err != nil {
				return fail(i, err)
			}
		}
		if err := ctx.Err(); err != nil {
			return fail(i, err)
		}
		result.Files = append(result.Files, BundleFile{Position: i, Name: f.name, Size: f.size})
	}

	publishBody := map[string]string{}
	if encrypt {
		sealed, err := SealManifest(key, manifest)
		if err != nil {
			return fail(len(files)-1, err)
		}
		publishBody["encrypted_manifest"] = base64.StdEncoding.EncodeToString(sealed)
	}
	raw, _ = json.Marshal(publishBody)
	resp, err = c.doRequest(ctx, http.MethodPost, "/api/bundles/"+strconv.FormatInt(draft.BundleID, 10)+"/publish",
		bytes.NewReader(raw), "application/json", "", member.withHeader(nil))
	if err != nil {
		return fail(len(files)-1, err)
	}
	var published apiBundleResponse
	if err := handleResponse(resp, &published); err != nil {
		return fail(len(files)-1, err)
	}

	result.ExpiresAt = &published.ExpiresAt
	result.DownloadLimit = published.MaxDownloads
	result.BundleURL = BuildBundleURL(c.baseURL, draft.BundleCode, key)
	return result, nil
}

// deleteDraftBundle discards a draft after a failed upload, best effort,
// even if ctx was cancelled.
func (c *Client) deleteDraftBundle(ctx context.Context, m *bundleMember) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	resp, err := c.doRequest(dctx, http.MethodDelete, "/api/bundles/"+strconv.FormatInt(m.id, 10), nil, "", "", m.withHeader(nil))
	if err == nil {
		resp.Body.Close()
	}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// BundleInfoFile describes one file of a bundle as the server reports it.
type BundleInfoFile struct {
	Position          int    `json:"position"`
	Name              string `json:"original_filename"` // "encrypted.bin" when the real name is inside an encrypted file
	Size              int64  `json:"file_size"`         // stored size (ciphertext for encrypted bundles)
	MimeType          string `json:"mime_type"`
	SHA256            string `json:"sha256_hash,omitempty"`
	DownloadAvailable bool   `json:"download_available"`
}

// BundleInfo is what GetBundleInfo returns.
type BundleInfo struct {
	BundleCode        string           `json:"bundle_code"`
	ExpiresAt         time.Time        `json:"expires_at"`
	FileCount         int              `json:"file_count"`
	MaxDownloads      *int             `json:"max_downloads"`
	PasswordRequired  bool             `json:"password_required"`
	ClientEncrypted   bool             `json:"client_encrypted"`
	EncryptedManifest []byte           `json:"encrypted_manifest,omitempty"`
	Files             []BundleInfoFile `json:"files"`
}

// GetBundleInfo returns a bundle's settings and file list. It needs no password.
func (c *Client) GetBundleInfo(ctx context.Context, bundleCode string) (*BundleInfo, error) {
	if err := validateClaimCode(bundleCode); err != nil {
		return nil, err
	}
	resp, err := c.request(ctx, http.MethodGet, "/api/bundle/"+bundleCode+"/info", nil, "")
	if err != nil {
		return nil, err
	}
	var info BundleInfo
	if err := handleResponse(resp, &info); err != nil {
		return nil, err
	}
	if info.FileCount != len(info.Files) {
		return nil, fmt.Errorf("%w: the server listed %d of %d files", ErrManifestMismatch, len(info.Files), info.FileCount)
	}
	for i, f := range info.Files {
		if f.Position != i || f.Size < 0 {
			return nil, fmt.Errorf("%w: the server's file list is malformed", ErrManifestMismatch)
		}
	}
	return &info, nil
}

// DownloadBundle downloads every file of a bundle into dir (created if
// needed, mode 0700) and returns the saved paths in bundle order. For an
// encrypted bundle (link.Key set) each file is decrypted and checked
// against the bundle's encrypted manifest — count, order, name, size and
// SHA-256 — and if anything differs nothing is saved and the error wraps
// ErrManifestMismatch. Existing files are not overwritten unless
// opts.Overwrite; a " (n)" suffix is added instead.
func (c *Client) DownloadBundle(ctx context.Context, link *BundleLink, dir string, opts *DownloadOptions) ([]string, error) {
	if opts == nil {
		opts = &DownloadOptions{}
	}
	if link == nil {
		return nil, &ValidationError{Field: "link", Message: "is required"}
	}
	info, err := c.GetBundleInfo(ctx, link.BundleCode)
	if err != nil {
		return nil, err
	}

	var rawKey []byte
	var manifest *BundleManifest
	if link.Key != "" && !info.ClientEncrypted {
		// The link's key says the sender encrypted this bundle; a server that
		// claims otherwise would have its files saved unchecked.
		return nil, fmt.Errorf("%w: the link has a key but the server says the bundle is not encrypted", ErrManifestMismatch)
	}
	if info.ClientEncrypted {
		if link.Key == "" {
			return nil, &ValidationError{Field: "link", Message: "is for an end-to-end encrypted bundle but has no key"}
		}
		if rawKey, err = decodeKey(link.Key); err != nil {
			return nil, err
		}
		defer clear(rawKey)
		if manifest, err = OpenManifest(link.Key, info.EncryptedManifest); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrManifestMismatch, err)
		}
		if len(manifest.Files) != len(info.Files) {
			return nil, fmt.Errorf("%w: the bundle should hold %d files but the server lists %d", ErrManifestMismatch, len(manifest.Files), len(info.Files))
		}
	}

	// Check the destination before fetching anything: a fetch may spend a
	// download. Files are written to a staging directory inside dir as they
	// arrive and moved into place only once every file is here and checked.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	staging, err := os.MkdirTemp(dir, ".safeshare-bundle-")
	if err != nil {
		return nil, fmt.Errorf("preparing %s: %w", dir, err)
	}
	defer os.RemoveAll(staging)

	type fetched struct {
		name, path string
	}
	got := make([]fetched, 0, len(info.Files))
	for i, f := range info.Files {
		limit := f.Size
		if manifest != nil && limit > maxEncryptedPayload+CiphertextOverhead {
			return nil, fmt.Errorf("%w: file %d is %d bytes; decrypting holds each file in memory", ErrFileTooLarge, i, f.Size)
		}
		resp, err := c.requestWithPassword(ctx, http.MethodGet, "/api/bundle/"+link.BundleCode+"/files/"+strconv.Itoa(i), nil, "", opts.Password)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 400 {
			return nil, handleResponse(resp, nil)
		}
		stagePath := filepath.Join(staging, strconv.Itoa(i))

		if manifest == nil {
			// Plain file: stream it to disk, never more than the reported size.
			n, err := writeLimited(stagePath, resp.Body, limit)
			resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("downloading file %d: %w", i, err)
			}
			if n != limit {
				return nil, fmt.Errorf("%w: file %d is %d bytes but the server reported %d", ErrManifestMismatch, i, n, limit)
			}
			got = append(got, fetched{name: f.Name, path: stagePath})
			continue
		}

		blob, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("downloading file %d: %w", i, err)
		}
		if int64(len(blob)) != limit {
			return nil, fmt.Errorf("%w: file %d is %d bytes but the server reported %d", ErrManifestMismatch, i, len(blob), limit)
		}
		pt, err := decryptBlob(rawKey, blob)
		if err != nil {
			return nil, fmt.Errorf("%w: file %d does not decrypt with the bundle key", ErrManifestMismatch, i)
		}
		// The name is checked only when it travelled inside the encrypted
		// payload; a name left visible was cleaned up by the server, and the
		// manifest (encrypted, authenticated) holds the real one. Content is
		// always checked by size and SHA-256.
		data, payloadName := pt, ""
		if f.Name == EncryptedFilename || hasPaddedPayloadMagic(pt) {
			p, err := unwrapPayload(pt)
			if err != nil {
				return nil, fmt.Errorf("%w: file %d: %v", ErrManifestMismatch, i, err)
			}
			data, payloadName = p.data, p.filename
		}
		want := manifest.Files[i]
		sum := sha256.Sum256(data)
		if (payloadName != "" && payloadName != want.Name) || int64(len(data)) != want.Size || hex.EncodeToString(sum[:]) != want.SHA256 {
			return nil, fmt.Errorf("%w: file %d is not the file the sender put there", ErrManifestMismatch, i)
		}
		if err := writeNewFile(stagePath, data, false); err != nil {
			return nil, fmt.Errorf("saving file %d: %w", i, err)
		}
		got = append(got, fetched{name: want.Name, path: stagePath})
	}

	used := map[string]bool{}
	saved := make([]string, 0, len(got))
	for i, f := range got {
		name := SafeFilename(f.name, "file-"+strconv.Itoa(i+1))
		path := filepath.Join(dir, name)
		if !opts.Overwrite || used[name] {
			path = freeBundleName(dir, name, used)
		}
		used[filepath.Base(path)] = true
		if err := CheckDestination(path, opts.Overwrite); err != nil {
			return saved, err
		}
		if err := os.Rename(f.path, path); err != nil {
			return saved, fmt.Errorf("saving %s: %w", path, err)
		}
		saved = append(saved, path)
	}
	return saved, nil
}

// writeLimited copies at most limit+1 bytes of r to a new file at path
// (mode 0600) and returns how many bytes it wrote.
func writeLimited(path string, r io.Reader, limit int64) (int64, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, io.LimitReader(r, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return n, err
}

// freeBundleName returns dir/name, or dir/"name (n).ext" for the first n
// that is neither on disk nor already used by this download.
func freeBundleName(dir, name string, used map[string]bool) string {
	ext := filepath.Ext(name)
	stem := name[:len(name)-len(ext)]
	candidate := name
	for n := 2; ; n++ {
		if !used[candidate] {
			if _, err := os.Lstat(filepath.Join(dir, candidate)); os.IsNotExist(err) {
				return filepath.Join(dir, candidate)
			}
		}
		candidate = fmt.Sprintf("%s (%d)%s", stem, n, ext)
	}
}

// UserBundleFile is one file of a bundle in ListBundles.
type UserBundleFile struct {
	Position           int    `json:"position"`
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	CompletedDownloads int    `json:"completed_downloads"`
}

// UserBundle is one of the signed-in user's bundles.
type UserBundle struct {
	ID                int64            `json:"id"`
	BundleCode        string           `json:"bundle_code"`
	CreatedAt         time.Time        `json:"created_at"`
	ExpiresAt         time.Time        `json:"expires_at"`
	DownloadLimit     *int             `json:"max_downloads"` // per file; nil = unlimited
	PasswordProtected bool             `json:"password_protected"`
	Encrypted         bool             `json:"client_encrypted"`
	FileCount         int              `json:"file_count"`
	TotalSize         int64            `json:"total_size"`
	Files             []UserBundleFile `json:"files"`
}

// UserBundlesResponse is a page of the signed-in user's bundles.
type UserBundlesResponse struct {
	Bundles []UserBundle `json:"bundles"`
	Total   int          `json:"total"`
	Limit   int          `json:"limit"`
	Offset  int          `json:"offset"`
}

// ListBundles returns the signed-in user's bundles, newest first. Requires
// an API token. limit is clamped to 1..100 (default 50).
func (c *Client) ListBundles(ctx context.Context, limit, offset int) (*UserBundlesResponse, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	resp, err := c.request(ctx, http.MethodGet, fmt.Sprintf("/api/user/bundles?limit=%d&offset=%d", limit, offset), nil, "")
	if err != nil {
		return nil, err
	}
	var out UserBundlesResponse
	if err := handleResponse(resp, &out); err != nil {
		return nil, err
	}
	if out.Bundles == nil {
		out.Bundles = []UserBundle{}
	}
	for _, b := range out.Bundles {
		if err := checkServerClaimCode(b.BundleCode); err != nil {
			return nil, err
		}
	}
	return &out, nil
}
