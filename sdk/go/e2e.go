package safeshare

// End-to-end encryption compatible with the SafeShare web app
// (internal/static/web/assets/crypto.js). A file encrypted here can be
// decrypted by the browser from its share link, and the other way round.
//
// Stored blob: [12-byte random IV][AES-256-GCM ciphertext + 16-byte tag].
// The key never reaches the server: it travels in the share link's fragment,
// {base}/#/claim/{code}/key/{base64url key}.
//
// The plaintext is one of:
//
//	SF02 (padded):  [SF02][u32 LE name length][u64 LE data length][name][data][zero padding]
//	SF01:           [SF01][u32 LE name length][name][data]
//	raw:            the file bytes (legacy browser uploads with the name visible)
//
// SF02 is padded to a PADME bucket so the stored size reveals only a size
// range; it is what the browser writes when the server is in Ghost
// (anonymous) mode. The name length may be 0, meaning the name is left
// visible to the server as the upload name.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	e2eIVLength  = 12
	e2eTagLength = 16
	e2eKeyLength = 32

	// CiphertextOverhead is what encryption adds to the payload: IV + GCM tag.
	CiphertextOverhead = e2eIVLength + e2eTagLength

	// EncryptedFilename is the upload name used when the real filename is
	// hidden inside the encrypted payload.
	EncryptedFilename = "encrypted.bin"

	// padMinBytes is the smallest padded payload, so all tiny files share one bucket.
	padMinBytes = 4096
	// uploadEnvelopeSlack is room kept below the server size limit for the
	// multipart form around the file.
	uploadEnvelopeSlack = 4096
	maxFilenameBytes    = 1024
	v2FixedHeader       = 16 // magic(4) + name length(4) + data length(8)
)

var (
	payloadMagicV1 = []byte("SF01")
	payloadMagicV2 = []byte("SF02")

	// ErrDecryptionFailed means the key is wrong or the file was changed.
	ErrDecryptionFailed = errors.New("file data is corrupted or the key is wrong")
	// ErrInvalidKey means the encryption key is not 32 bytes of base64url.
	// (ParseShareURL reports a bad key in a link as a ValidationError.)
	ErrInvalidKey = errors.New("invalid encryption key")
	// ErrInvalidPayload means a decrypted payload has a malformed header.
	ErrInvalidPayload = errors.New("encrypted payload is malformed")
	// ErrPayloadTooLarge means the file does not fit under the server's size
	// limit once encryption overhead is added.
	ErrPayloadTooLarge = errors.New("file is too large to upload encrypted")

	shareFragmentPattern = regexp.MustCompile(`^/claim/([^/]+)/key/(.+)$`)
)

// padmeLength rounds n up so only its top bits are significant: at most ~12%
// overhead, and the bucket reveals O(log log n) bits about n (Nikitin et al.,
// "Reducing Metadata Leakage from Encrypted Files and Communication with
// PURBs", PETS 2019).
func padmeLength(n int64) int64 {
	if n < 2 {
		return n
	}
	e := int64(bits.Len64(uint64(n)) - 1) // floor(log2 n)
	s := int64(bits.Len64(uint64(e)))     // floor(log2 e) + 1
	lastBits := e - s
	if lastBits <= 0 {
		return n
	}
	mask := int64(1)<<lastBits - 1
	return (n + mask) &^ mask
}

// paddedPayloadLength is the padded size for an unpadded framed payload of n
// bytes. maxStored is the server's file size limit, which applies to the
// stored size (payload + CiphertextOverhead); padding is capped so it never
// pushes a file over the limit. maxStored <= 0 means no limit.
func paddedPayloadLength(n, maxStored int64) (int64, error) {
	target := padmeLength(n)
	if target < padMinBytes {
		target = padMinBytes
	}
	if maxStored > 0 {
		hardCap := maxStored - CiphertextOverhead
		if n > hardCap {
			return 0, fmt.Errorf("%w: the server limit is %d bytes including %d bytes of encryption overhead",
				ErrPayloadTooLarge, maxStored, CiphertextOverhead)
		}
		// The server applies its limit to the whole request, so leave room for
		// the form; a file in the last few KB below the limit stays unpadded.
		limit := hardCap - uploadEnvelopeSlack
		if limit < n {
			limit = n
		}
		if target > limit {
			target = limit
		}
	}
	return target, nil
}

// encodeFilename returns the UTF-8 bytes of name, cut to maxFilenameBytes
// (by bytes, as the browser does).
func encodeFilename(name string) []byte {
	b := []byte(name)
	if len(b) > maxFilenameBytes {
		b = b[:maxFilenameBytes]
	}
	return b
}

// payloadLayout describes where the file data goes in a framed payload.
type payloadLayout struct {
	header   []byte // magic + lengths + name
	total    int64  // whole payload length, padding included
	dataSize int64
}

// framePayload computes the payload header and size for a file of dataSize
// bytes. pad selects SF02; otherwise a non-empty name selects SF01 and an empty
// name the raw format.
func framePayload(name string, dataSize int64, pad bool, maxStored int64) (payloadLayout, error) {
	nameBytes := encodeFilename(name)
	if pad {
		used := v2FixedHeader + int64(len(nameBytes)) + dataSize
		total, err := paddedPayloadLength(used, maxStored)
		if err != nil {
			return payloadLayout{}, err
		}
		h := make([]byte, v2FixedHeader+len(nameBytes))
		copy(h, payloadMagicV2)
		binary.LittleEndian.PutUint32(h[4:], uint32(len(nameBytes)))
		binary.LittleEndian.PutUint64(h[8:], uint64(dataSize))
		copy(h[v2FixedHeader:], nameBytes)
		return payloadLayout{header: h, total: total, dataSize: dataSize}, nil
	}
	var h []byte
	if len(nameBytes) > 0 {
		h = make([]byte, 8+len(nameBytes))
		copy(h, payloadMagicV1)
		binary.LittleEndian.PutUint32(h[4:], uint32(len(nameBytes)))
		copy(h[8:], nameBytes)
	}
	total := int64(len(h)) + dataSize
	if maxStored > 0 && total > maxStored-CiphertextOverhead {
		return payloadLayout{}, fmt.Errorf("%w: the server limit is %d bytes including %d bytes of encryption overhead",
			ErrPayloadTooLarge, maxStored, CiphertextOverhead)
	}
	return payloadLayout{header: h, total: total, dataSize: dataSize}, nil
}

// wrapPayload frames data in memory (see framePayload).
func wrapPayload(name string, data []byte, pad bool, maxStored int64) ([]byte, error) {
	l, err := framePayload(name, int64(len(data)), pad, maxStored)
	if err != nil {
		return nil, err
	}
	out := make([]byte, l.total) // zero-filled: the padding
	copy(out, l.header)
	copy(out[len(l.header):], data)
	return out, nil
}

// unwrappedPayload is a decrypted payload with its framing removed.
type unwrappedPayload struct {
	filename string // "" when the payload carries no name
	data     []byte
	version  int // 2 for SF02, 1 for SF01 and raw
}

// unwrapPayload removes SF02/SF01 framing. An SF02 payload whose lengths do
// not fit, or whose padding is not all zero, is an error; data without either
// magic, or with a corrupt SF01 header, is returned unchanged.
func unwrapPayload(b []byte) (unwrappedPayload, error) {
	if bytes.HasPrefix(b, payloadMagicV2) {
		if len(b) < v2FixedHeader {
			return unwrappedPayload{}, fmt.Errorf("%w: header is truncated", ErrInvalidPayload)
		}
		nameLen := uint64(binary.LittleEndian.Uint32(b[4:]))
		dataLen := binary.LittleEndian.Uint64(b[8:])
		if nameLen > maxFilenameBytes {
			return unwrappedPayload{}, fmt.Errorf("%w: filename length is invalid", ErrInvalidPayload)
		}
		dataStart := v2FixedHeader + nameLen
		if dataLen > uint64(len(b)) || dataStart+dataLen > uint64(len(b)) {
			return unwrappedPayload{}, fmt.Errorf("%w: length exceeds the decrypted size", ErrInvalidPayload)
		}
		end := dataStart + dataLen
		for _, c := range b[end:] {
			if c != 0 {
				return unwrappedPayload{}, fmt.Errorf("%w: padding is invalid", ErrInvalidPayload)
			}
		}
		return unwrappedPayload{
			filename: decodeFilename(b[v2FixedHeader:dataStart]),
			data:     b[dataStart:end],
			version:  2,
		}, nil
	}
	if len(b) < 8 || !bytes.HasPrefix(b, payloadMagicV1) {
		return unwrappedPayload{data: b, version: 1}, nil
	}
	nameLen := uint64(binary.LittleEndian.Uint32(b[4:]))
	if nameLen == 0 || nameLen > maxFilenameBytes || nameLen+8 > uint64(len(b)) {
		return unwrappedPayload{data: b, version: 1}, nil // corrupt header: legacy raw data
	}
	return unwrappedPayload{
		filename: decodeFilename(b[8 : 8+nameLen]),
		data:     b[8+nameLen:],
		version:  1,
	}, nil
}

func decodeFilename(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "�")
}

// hasPaddedPayloadMagic reports whether decrypted data starts with SF02.
func hasPaddedPayloadMagic(b []byte) bool {
	return bytes.HasPrefix(b, payloadMagicV2)
}

// GenerateEncryptionKey returns a new random 256-bit key, base64url-encoded
// without padding as in share links.
func GenerateEncryptionKey() (string, error) {
	key := make([]byte, e2eKeyLength)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generating key: %w", err)
	}
	return encodeKey(key), nil
}

func encodeKey(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

// decodeKey parses a base64url key (padding optional) and checks its length.
func decodeKey(s string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(s), "="))
	if err != nil || len(key) != e2eKeyLength {
		return nil, ErrInvalidKey
	}
	return key, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealInPlace encrypts buf[e2eIVLength:] in place with the given IV and
// returns [IV][ciphertext][tag]. buf must have e2eTagLength bytes of spare
// capacity so the tag is appended without a copy.
func sealInPlace(key, iv, buf []byte) ([]byte, error) {
	if len(iv) != e2eIVLength || len(buf) < e2eIVLength || cap(buf)-len(buf) < e2eTagLength {
		return nil, errors.New("invalid IV or buffer")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	copy(buf, iv)
	plaintext := buf[e2eIVLength:]
	ct := gcm.Seal(plaintext[:0], iv, plaintext, nil)
	return buf[:e2eIVLength+len(ct)], nil
}

// decryptBlob decrypts [IV][ciphertext][tag] in place.
func decryptBlob(key, blob []byte) ([]byte, error) {
	if len(blob) <= e2eIVLength {
		return nil, ErrDecryptionFailed
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ct := blob[e2eIVLength:]
	pt, err := gcm.Open(ct[:0], blob[:e2eIVLength], ct, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return pt, nil
}

// BuildShareURL returns the link the web app opens to download and decrypt a
// file: {baseURL}/#/claim/{claimCode}/key/{key}.
func BuildShareURL(baseURL, claimCode, key string) string {
	return strings.TrimRight(baseURL, "/") + "/#/claim/" + claimCode + "/key/" + key
}

// ShareLink is a parsed encrypted share link.
type ShareLink struct {
	// BaseURL is the server the file is on, e.g. "https://share.example.com".
	BaseURL string
	// ClaimCode identifies the file.
	ClaimCode string
	// Key is the base64url decryption key from the link fragment.
	Key string
}

// ParseShareURL parses an encrypted share link made by the web app or by
// BuildShareURL. The base URL keeps any path prefix the server is served under.
func ParseShareURL(link string) (*ShareLink, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, &ValidationError{Field: "link", Message: "must be an http(s) share link"}
	}
	m := shareFragmentPattern.FindStringSubmatch(u.Fragment)
	if m == nil {
		return nil, &ValidationError{Field: "link", Message: "has no #/claim/<code>/key/<key> part; it is not an encrypted share link"}
	}
	if err := validateClaimCode(m[1]); err != nil {
		return nil, err
	}
	if _, err := decodeKey(m[2]); err != nil {
		return nil, &ValidationError{Field: "link", Message: "has an invalid key: it must be 32 bytes of base64url"}
	}
	base := url.URL{Scheme: u.Scheme, Host: u.Host, Path: strings.TrimRight(u.Path, "/")}
	return &ShareLink{BaseURL: base.String(), ClaimCode: m[1], Key: m[2]}, nil
}
