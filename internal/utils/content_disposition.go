package utils

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// rfc5987AttrChars are the RFC 5987 attr-char set: bytes that may appear
// unescaped in an ext-value (the value after filename*=UTF-8”). Everything
// else is percent-encoded.
const rfc5987AttrChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$&+-.^_`|~"

// maxContentDispositionNameBytes caps the sanitized filename before either
// encoding — well under common filesystem/header-line limits, and small
// enough that a pathological name can't be used to inflate the response
// header.
const maxContentDispositionNameBytes = 255

// ContentDisposition builds an `attachment` Content-Disposition header
// value for name, following RFC 6266: a legacy ASCII `filename=` fallback
// for clients that don't understand the extended form, plus an RFC 5987
// `filename*=UTF-8”...` value carrying the (sanitized) name for clients
// that do.
//
// Before either encoding, name is sanitized (see sanitizeFilename): this is
// what stops a name like "invoice<U+202E>fdp.exe" — which a browser renders
// as "invoice...exe.pdf" via the right-to-left override — from spoofing its
// real extension through either the ASCII fallback or the UTF-8 ext-value.
//
// ASCII fallback rules (applied to the sanitized name): '"' and '\' are
// backslash-escaped (they're quoted-string special characters), and any
// remaining non-ASCII rune is replaced with a single '_'.
func ContentDisposition(name string) string {
	name = sanitizeFilename(name)
	return fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, asciiFallbackFilename(name), rfc5987Encode(name))
}

// sanitizeFilename strips characters a browser can use to visually spoof a
// filename's real extension or otherwise misrender it, then caps the
// result to a sane byte length:
//
//   - invalid UTF-8 byte sequences are replaced with U+FFFD, which is then
//     dropped along with the rest of the disallowed runes below;
//   - Unicode format characters (category Cf) — bidi overrides/embeddings
//     (U+202E RIGHT-TO-LEFT OVERRIDE and friends), directional isolates
//     (U+2066-U+2069), zero-width joiners/marks (U+200E, U+200B, ...);
//   - line/paragraph separators (Zl/Zp: U+2028, U+2029), which some clients
//     treat as a header line break;
//   - control characters (Cc: C0, DEL, C1), which also covers what the
//     ASCII fallback used to strip on its own.
//
// The result is capped at maxContentDispositionNameBytes bytes, cut on a
// rune boundary; a short trailing extension (".ext", <= 32 bytes) is kept
// intact where present rather than getting truncated away. If nothing
// survives sanitization, "download" is used instead of an empty filename.
func sanitizeFilename(name string) string {
	name = strings.ToValidUTF8(name, string(utf8.RuneError))

	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if r == utf8.RuneError || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) || unicode.Is(unicode.Cc, r) {
			continue
		}
		b.WriteRune(r)
	}

	sanitized := capFilenameBytes(b.String(), maxContentDispositionNameBytes)
	if sanitized == "" {
		return "download"
	}
	return sanitized
}

// capFilenameBytes truncates name to at most maxBytes bytes, cutting on a
// UTF-8 rune boundary. When name has a short (<= 32 byte) trailing
// extension, the extension is preserved and only the base name is
// shortened.
func capFilenameBytes(name string, maxBytes int) string {
	if len(name) <= maxBytes {
		return name
	}
	ext := ""
	base := name
	if dot := strings.LastIndexByte(name, '.'); dot > 0 && len(name)-dot <= 32 {
		ext = name[dot:]
		base = name[:dot]
	}
	limit := maxBytes - len(ext)
	if limit < 0 {
		limit = 0
	}
	if limit > len(base) {
		limit = len(base)
	}
	for limit > 0 && limit < len(base) && !utf8.RuneStart(base[limit]) {
		limit--
	}
	return base[:limit] + ext
}

func asciiFallbackFilename(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20 || r == 0x7f:
			// Control characters are dropped entirely rather than escaped —
			// they have no legitimate place in a filename and quoting them
			// would just relocate the header-injection risk. Redundant with
			// sanitizeFilename's Cc filtering above (kept as defense in
			// depth in case this function is ever called on its own).
		case r > 0x7e:
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func rfc5987Encode(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if strings.IndexByte(rfc5987AttrChars, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
