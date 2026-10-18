package safeshare

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxEncryptedPayload caps what an encrypted upload holds in memory, so an
// unlimited server cannot turn a huge file into an allocation panic.
const maxEncryptedPayload = 16 << 30

// WillEncrypt reports whether Upload with this EncryptMode encrypts on this
// server; it fails like Upload for EncryptNever on a server that requires
// encryption.
func (c *Client) WillEncrypt(ctx context.Context, mode EncryptMode) (bool, error) {
	cfg, err := c.GetConfig(ctx)
	if err != nil {
		return false, fmt.Errorf("getting config: %w", err)
	}
	return shouldEncrypt(mode, cfg)
}

// shouldEncrypt resolves an EncryptMode against the server configuration.
func shouldEncrypt(mode EncryptMode, cfg *PublicConfig) (bool, error) {
	switch mode {
	case EncryptAlways:
		return true, nil
	case EncryptNever:
		if cfg.ClientEncryptionRequired {
			return false, fmt.Errorf("%w: this server only accepts encrypted uploads", ErrClientEncryptionRequired)
		}
		return false, nil
	default:
		return cfg.AnonymousMode || cfg.ClientEncryptionRequired, nil
	}
}

// uploadEncrypted reads the file into memory, frames and encrypts it in the
// web app's format, and uploads the ciphertext. Nothing is written to disk.
func (c *Client) uploadEncrypted(ctx context.Context, path, filename string, size int64, cfg *PublicConfig, opts *UploadOptions) (*UploadResult, error) {
	payloadName := filename
	if opts.ShowFilename {
		payloadName = "" // the server sees the real name instead
	}
	// Always pad (SF02): the padding is inside the encryption, so the server
	// sees only the size bucket. The browser pads only in Ghost mode, but that
	// is the server's claim; costing at most ~12%, padding regardless means a
	// lying server can't turn it off. Every client decrypts SF02.
	layout, err := framePayload(payloadName, size, true, cfg.MaxFileSize)
	if err != nil {
		return nil, err
	}

	if layout.total > maxEncryptedPayload {
		return nil, fmt.Errorf("%w: encrypting holds the whole file in memory, and the limit is %d bytes",
			ErrPayloadTooLarge, int64(maxEncryptedPayload))
	}

	// [IV][header][file][zero padding] + room for the tag, sealed in place.
	buf := make([]byte, e2eIVLength+layout.total, e2eIVLength+layout.total+e2eTagLength)
	copy(buf[e2eIVLength:], layout.header)
	dataStart := int64(e2eIVLength + len(layout.header))
	data := buf[dataStart : dataStart+size]
	if err := readExactly(path, data); err != nil {
		return nil, err
	}

	metadataKind := metadataFileType(data)
	if metadataKind != "" && cfg.AnonymousMode && cfg.StripMetadata && !opts.KeepMetadata {
		return nil, fmt.Errorf("%w: this %s may contain metadata (author, location, dates) and the server cannot remove it from an encrypted file; scrub it first, for example with mat2, or allow it explicitly",
			ErrMetadataNotRemoved, metadataKind)
	}

	encodedKey, err := GenerateEncryptionKey()
	if err != nil {
		return nil, err
	}
	key, _ := decodeKey(encodedKey)
	defer clear(key)
	iv := make([]byte, e2eIVLength)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("generating IV: %w", err)
	}
	blob, err := sealInPlace(key, iv, buf)
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}

	uploadName := EncryptedFilename
	if opts.ShowFilename {
		uploadName = filename
	}
	src := memorySource(uploadName, blob)

	var result *UploadResult
	if src.size >= cfg.ChunkUploadThreshold {
		result, err = c.uploadChunked(ctx, src, opts, true)
	} else {
		result, err = c.uploadSimple(ctx, src, opts, true)
	}
	if err != nil {
		return nil, err
	}
	result.Encrypted = true
	result.Filename = filename // the server stored "encrypted.bin" when it was hidden
	result.EncryptionKey = encodedKey
	result.ShareURL = BuildShareURL(c.baseURL, result.ClaimCode, encodedKey)
	if metadataKind != "" && cfg.StripMetadata {
		result.MetadataKept = metadataKind
	}
	return result, nil
}

// readExactly fills dst from the file at path and fails if the file is not
// exactly len(dst) bytes (it changed since it was measured).
func readExactly(path string, dst []byte) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()
	if _, err := io.ReadFull(f, dst); err != nil {
		return fmt.Errorf("reading file (did it change while uploading?): %w", err)
	}
	var one [1]byte
	if n, _ := f.Read(one[:]); n != 0 {
		return errors.New("reading file: it grew while uploading")
	}
	return nil
}

var (
	pngSignature    = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}
	zipSignature    = []byte{'P', 'K', 0x03, 0x04}
	contentTypesTag = []byte("[content_types].xml")
)

// metadataFileType names the file's type when it is one the web app removes
// metadata from before encrypting (detected by content, as the web app does),
// and returns "" otherwise.
func metadataFileType(b []byte) string {
	switch {
	case len(b) >= 4 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF:
		return "JPEG image"
	case bytes.HasPrefix(b, pngSignature):
		return "PNG image"
	case bytes.HasPrefix(b, zipSignature) && mentionsContentTypes(b):
		return "Office document"
	case isPDF(b):
		return "PDF"
	}
	return ""
}

// mentionsContentTypes reports whether "[Content_Types].xml" (any case)
// appears anywhere, as it does in every Office file's zip directory.
func mentionsContentTypes(b []byte) bool {
	n := len(contentTypesTag)
	for i := bytes.IndexByte(b, '['); i != -1 && i+n <= len(b); {
		j := 1
		for j < n && lowerASCII(b[i+j]) == contentTypesTag[j] {
			j++
		}
		if j == n {
			return true
		}
		next := bytes.IndexByte(b[i+1:], '[')
		if next == -1 {
			break
		}
		i += 1 + next
	}
	return false
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// isPDF matches the web app: a PDF header in the first megabyte, or a PDF
// trailer in the last 2 KB.
func isPDF(b []byte) bool {
	head := b[:min(len(b), 1024*1024)]
	tail := b[max(0, len(b)-2048):]
	return bytes.Contains(head, []byte("%PDF-")) ||
		(bytes.Contains(tail, []byte("startxref")) && bytes.Contains(tail, []byte("%%EOF")))
}

// DecryptedFile is an end-to-end encrypted file after download and decryption.
type DecryptedFile struct {
	// Filename is the original name: from inside the encrypted payload when
	// the uploader hid it, otherwise the name stored on the server. It comes
	// from the uploader, so sanitise it before using it as a path (Download
	// does this with SafeFilename).
	Filename string
	// Data is the decrypted file content.
	Data []byte
}

// DownloadDecrypted downloads an end-to-end encrypted file into memory and
// decrypts it with key (base64url, from the share link). It handles every
// format the web app writes. opts.Password is used for password-protected
// files; opts.OnProgress reports the encrypted download.
func (c *Client) DownloadDecrypted(ctx context.Context, claimCode, key string, opts *DownloadOptions) (*DecryptedFile, error) {
	if err := validateClaimCode(claimCode); err != nil {
		return nil, err
	}
	rawKey, err := decodeKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(rawKey)
	if opts == nil {
		opts = &DownloadOptions{}
	}

	info, err := c.GetFileInfo(ctx, claimCode)
	if err != nil {
		return nil, fmt.Errorf("getting file info: %w", err)
	}

	if info.Size > maxEncryptedPayload+CiphertextOverhead {
		return nil, fmt.Errorf("%w: the server reports %d bytes; decrypting holds the whole file in memory, and the limit is %d bytes",
			ErrFileTooLarge, info.Size, int64(maxEncryptedPayload+CiphertextOverhead))
	}

	resp, err := c.requestWithPassword(ctx, http.MethodGet, "/api/claim/"+claimCode, nil, "", opts.Password)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, handleResponse(resp, nil)
	}

	// Bound the read by the size the server reported, itself capped, so a
	// misbehaving server cannot make the client buffer without limit.
	limit := info.Size
	if limit < 0 || limit > maxEncryptedPayload+CiphertextOverhead {
		return nil, fmt.Errorf("%w: the server reports %d bytes; decrypting holds the whole file in memory, and the limit is %d bytes",
			ErrFileTooLarge, info.Size, int64(maxEncryptedPayload+CiphertextOverhead))
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("downloading file: the server sent %d bytes but reported %d", resp.ContentLength, limit)
	}
	var reader io.Reader = resp.Body
	if opts.OnProgress != nil {
		reader = &progressDownloadReader{reader: resp.Body, totalBytes: limit, onProgress: opts.OnProgress}
	}
	blob, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("downloading file: %w", err)
	}
	if int64(len(blob)) > limit {
		return nil, fmt.Errorf("downloading file: the server sent more than the %d bytes it reported", limit)
	}

	plaintext, err := decryptBlob(rawKey, blob)
	if err != nil {
		return nil, err
	}
	return unwrapDownload(plaintext, info.Filename)
}

// unwrapDownload removes payload framing the way the web app does. Files
// stored as "encrypted.bin" are framed (SF01 or SF02) and carry the name.
// A padded (SF02) file stored under its real name is unwrapped only if its
// header is valid, keeping the server's name; anything else is raw data.
func unwrapDownload(plaintext []byte, storedName string) (*DecryptedFile, error) {
	if storedName == EncryptedFilename {
		p, err := unwrapPayload(plaintext)
		if err != nil {
			return nil, err
		}
		name := p.filename
		if name == "" {
			name = storedName
		}
		return &DecryptedFile{Filename: name, Data: p.data}, nil
	}
	if hasPaddedPayloadMagic(plaintext) {
		if p, err := unwrapPayload(plaintext); err == nil {
			return &DecryptedFile{Filename: storedName, Data: p.data}, nil
		}
	}
	return &DecryptedFile{Filename: storedName, Data: plaintext}, nil
}

// downloadDecryptedTo is Download for an encrypted file: decrypt in memory,
// then write the plaintext to destPath (mode 0600). The destination is
// checked first, so a limited download is not used up for nothing.
func (c *Client) downloadDecryptedTo(ctx context.Context, claimCode, destPath string, opts *DownloadOptions) error {
	if err := CheckDestination(destPath, opts.Overwrite); err != nil {
		return err
	}
	f, err := c.DownloadDecrypted(ctx, claimCode, opts.DecryptionKey, opts)
	if err != nil {
		return err
	}
	return f.Save(destPath, opts.Overwrite)
}

// CheckDestination returns an error if path cannot be written by Save: it is
// a symbolic link, or it exists and overwrite is false. Call it before
// downloading, since a download may count against the file's limit.
func CheckDestination(path string, overwrite bool) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("destination is a symbolic link, refusing to overwrite for security")
		}
		if !overwrite {
			return fmt.Errorf("%w: %s", ErrDestinationExists, path)
		}
	}
	return nil
}

// Save writes the decrypted data to path with mode 0600, creating parent
// directories. Without overwrite the file must not exist; a symbolic link is
// always refused.
func (f *DecryptedFile) Save(path string, overwrite bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating destination directory: %w", err)
	}
	return writeNewFile(path, f.Data, overwrite)
}

// writeNewFile writes data to path with mode 0600 (see Save).
func writeNewFile(path string, data []byte, overwrite bool) error {
	if err := CheckDestination(path, overwrite); err != nil {
		return err
	}
	if overwrite {
		return replaceFile(path, data)
	}
	// O_EXCL also refuses a symbolic link created after the check.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrDestinationExists, path)
		}
		return fmt.Errorf("creating destination file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("writing file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return fmt.Errorf("writing file: %w", err)
	}
	return nil
}

// replaceFile writes data to a new temporary file next to path and renames
// it over path, so a symbolic link swapped in after the check is replaced
// rather than followed.
func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".safeshare-*.tmp")
	if err != nil {
		return fmt.Errorf("creating destination file: %w", err)
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("writing file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("writing file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return fmt.Errorf("writing file: %w", err)
	}
	return nil
}

// SafeFilename turns an uploader-supplied filename into a plain file name
// that is safe to create in the current directory: no directories, no
// control or invisible formatting characters (such as right-to-left
// overrides), no leading dots (so no hidden files like .bashrc), no
// characters or device names Windows reserves, at most 255 bytes. It returns
// fallback if nothing usable is left.
func SafeFilename(name, fallback string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = name[strings.LastIndex(name, "/")+1:]
	name = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == unicode.ReplacementChar:
			return -1
		case strings.ContainsRune(`<>:"|?*`, r):
			return '_'
		}
		return r
	}, name)
	name = strings.Trim(name, " .") // as the server's sanitizer does
	if len(name) > 255 {
		// Keep a short extension; trim the stem on a rune boundary.
		ext := filepath.Ext(name)
		if len(ext) > 16 {
			ext = ""
		}
		stem := name[:len(name)-len(ext)]
		for len(stem)+len(ext) > 255 {
			_, size := utf8.DecodeLastRuneInString(stem)
			stem = stem[:len(stem)-size]
		}
		name = strings.Trim(stem, " .") + ext
	}
	if name == "" || filepath.Base(name) != name {
		return fallback
	}
	if isWindowsReserved(name) {
		name = "_" + name
	}
	return name
}

// isWindowsReserved reports whether name's stem is a Windows device name.
func isWindowsReserved(name string) bool {
	stem := strings.ToUpper(strings.TrimRight(strings.SplitN(name, ".", 2)[0], " "))
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '0' && stem[3] <= '9' {
		return true
	}
	return false
}
