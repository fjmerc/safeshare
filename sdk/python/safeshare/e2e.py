"""
End-to-end encryption compatible with the SafeShare web app
(internal/static/web/assets/crypto.js). A file encrypted here opens from its
share link in a browser, and a browser upload decrypts here.

Stored blob: [12-byte random IV][AES-256-GCM ciphertext + 16-byte tag]. The
key never reaches the server: it travels in the share link's fragment,
``{base}/#/claim/{code}/key/{base64url key}``.

The plaintext is one of:

* SF02 (padded): [SF02][u32 LE name length][u64 LE data length][name][data][zero padding]
* SF01:          [SF01][u32 LE name length][name][data]
* raw:           the file bytes (legacy browser uploads with the name visible)

This SDK always writes SF02, padded to a PADME bucket, so the stored size
reveals only a size range whatever the server claims about its mode.
"""

from __future__ import annotations

import base64
import os
import re
import secrets
import struct
import unicodedata
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from safeshare.exceptions import SafeShareError, ValidationError

IV_LENGTH = 12
TAG_LENGTH = 16
KEY_LENGTH = 32
CIPHERTEXT_OVERHEAD = IV_LENGTH + TAG_LENGTH
ENCRYPTED_FILENAME = "encrypted.bin"
PAD_MIN_BYTES = 4096
UPLOAD_ENVELOPE_SLACK = 4096
MAX_FILENAME_BYTES = 1024
V2_FIXED_HEADER = 16
# What an encrypted upload or download may hold in memory.
MAX_ENCRYPTED_PAYLOAD = 16 << 30

MAGIC_V1 = b"SF01"
MAGIC_V2 = b"SF02"

_CLAIM_CODE = re.compile(r"^[A-Za-z0-9_-]{8,32}$")
_FRAGMENT = re.compile(r"^/claim/([^/]+)/key/(.+)$")


class DecryptionError(SafeShareError):
    """The key is wrong or the file was changed."""


class InvalidPayloadError(SafeShareError):
    """A decrypted payload has a malformed header."""


class PayloadTooLargeError(SafeShareError):
    """The file doesn't fit under the server's limit once encrypted."""


class MetadataNotRemovedError(SafeShareError):
    """An encrypted upload to a Ghost server was refused: the file may contain
    metadata that neither this SDK nor the server can remove."""


class ClientEncryptionRequiredError(SafeShareError):
    """The server only accepts files encrypted before upload."""


def padme_length(n: int) -> int:
    """PADME padded length (Nikitin et al., PETS 2019): at most ~12% overhead."""
    if n < 0:
        raise ValueError("length must be non-negative")
    if n < 2:
        return n
    e = n.bit_length() - 1
    s = e.bit_length()
    last_bits = e - s
    if last_bits <= 0:
        return n
    mask = (1 << last_bits) - 1
    return (n + mask) & ~mask


def padded_payload_length(n: int, max_stored: int = 0) -> int:
    """Padded payload size for an unpadded payload of n bytes, capped so the
    stored size (payload + overhead) stays under max_stored (0 = no limit)."""
    target = max(padme_length(n), PAD_MIN_BYTES)
    if max_stored > 0:
        hard_cap = max_stored - CIPHERTEXT_OVERHEAD
        if n > hard_cap:
            raise PayloadTooLargeError(
                f"File is too large to upload encrypted: the server limit is {max_stored} bytes "
                f"including {CIPHERTEXT_OVERHEAD} bytes of encryption overhead"
            )
        target = min(target, max(hard_cap - UPLOAD_ENVELOPE_SLACK, n))
    return target


def _name_bytes(name: str) -> bytes:
    return name.encode("utf-8")[:MAX_FILENAME_BYTES]


def wrap_payload(name: str, data: bytes, pad: bool = True, max_stored: int = 0) -> bytes:
    """Frame data as SF02 (pad) or, without padding, SF01 (name) / raw (no name)."""
    nb = _name_bytes(name)
    if pad:
        used = V2_FIXED_HEADER + len(nb) + len(data)
        total = padded_payload_length(used, max_stored)
        header = MAGIC_V2 + struct.pack("<IQ", len(nb), len(data)) + nb
        return header + data + bytes(total - used)
    out = (MAGIC_V1 + struct.pack("<I", len(nb)) + nb + data) if nb else bytes(data)
    if max_stored > 0 and len(out) > max_stored - CIPHERTEXT_OVERHEAD:
        raise PayloadTooLargeError(f"File is too large to upload encrypted: the server limit is {max_stored} bytes")
    return out


@dataclass
class UnwrappedPayload:
    filename: Optional[str]
    data: bytes
    version: int


def unwrap_payload(b: bytes) -> UnwrappedPayload:
    """Remove SF02/SF01 framing. Malformed SF02 raises InvalidPayloadError;
    data without a magic, or with a corrupt SF01 header, is returned as is."""
    if b[:4] == MAGIC_V2:
        if len(b) < V2_FIXED_HEADER:
            raise InvalidPayloadError("Payload header is truncated")
        name_len, data_len = struct.unpack_from("<IQ", b, 4)
        if name_len > MAX_FILENAME_BYTES:
            raise InvalidPayloadError("Payload filename length is invalid")
        start = V2_FIXED_HEADER + name_len
        end = start + data_len
        if end > len(b):
            raise InvalidPayloadError("Payload length exceeds the decrypted size")
        if any(b[end:]):
            raise InvalidPayloadError("Payload padding is invalid")
        name = b[V2_FIXED_HEADER:start].decode("utf-8", errors="replace") if name_len else None
        return UnwrappedPayload(name, b[start:end], 2)
    if len(b) < 8 or b[:4] != MAGIC_V1:
        return UnwrappedPayload(None, b, 1)
    (name_len,) = struct.unpack_from("<I", b, 4)
    if name_len == 0 or name_len > MAX_FILENAME_BYTES or name_len + 8 > len(b):
        return UnwrappedPayload(None, b, 1)
    return UnwrappedPayload(b[8 : 8 + name_len].decode("utf-8", errors="replace"), b[8 + name_len :], 1)


def unwrap_download(plaintext: bytes, stored_name: str) -> "DecryptedFile":
    """Unframe a downloaded file the way the web app does: files stored as
    encrypted.bin are framed; a padded file stored under its real name is
    unwrapped only if valid, keeping the server's name."""
    if stored_name == ENCRYPTED_FILENAME:
        p = unwrap_payload(plaintext)
        return DecryptedFile(p.filename or stored_name, p.data)
    if plaintext[:4] == MAGIC_V2:
        try:
            return DecryptedFile(stored_name, unwrap_payload(plaintext).data)
        except InvalidPayloadError:
            pass
    return DecryptedFile(stored_name, plaintext)


@dataclass
class DecryptedFile:
    """A downloaded end-to-end encrypted file after decryption. ``filename``
    comes from the uploader: pass it through safe_filename() before saving."""

    filename: str
    data: bytes


def generate_key() -> str:
    """A new random 256-bit key, base64url without padding."""
    return encode_key(secrets.token_bytes(KEY_LENGTH))


def encode_key(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")


def decode_key(key: str) -> bytes:
    s = key.strip().rstrip("=")
    if not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise ValidationError("Invalid encryption key")
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        raise ValidationError("Invalid encryption key") from None
    if len(raw) != KEY_LENGTH:
        raise ValidationError("Invalid encryption key")
    return raw


def encrypt_blob(key: bytes, payload: bytes, iv: Optional[bytes] = None) -> bytes:
    """[IV][AES-256-GCM(payload)][tag]; a fresh random IV unless given (tests)."""
    iv = iv if iv is not None else secrets.token_bytes(IV_LENGTH)
    if len(iv) != IV_LENGTH:
        raise ValueError("IV must be 12 bytes")
    return iv + AESGCM(key).encrypt(iv, payload, None)


def decrypt_blob(key: bytes, blob: bytes) -> bytes:
    if len(blob) <= IV_LENGTH:
        raise DecryptionError("File data is corrupted or the key is wrong")
    try:
        return AESGCM(key).decrypt(blob[:IV_LENGTH], blob[IV_LENGTH:], None)
    except InvalidTag:
        raise DecryptionError("File data is corrupted or the key is wrong") from None


def build_share_url(base_url: str, claim_code: str, key: str) -> str:
    """The link the web app opens to download and decrypt a file."""
    return f"{base_url.rstrip('/')}/#/claim/{claim_code}/key/{key}"


@dataclass
class ShareLink:
    base_url: str
    claim_code: str
    key: str


def parse_share_url(link: str) -> ShareLink:
    """Parse an encrypted share link (keeps any path prefix of the server)."""
    parts = urlsplit(link.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValidationError("The link must be an http(s) share link")
    m = _FRAGMENT.match(parts.fragment)
    if not m:
        raise ValidationError("The link has no #/claim/<code>/key/<key> part; it is not an encrypted share link")
    code, key = m.group(1), m.group(2)
    if not _CLAIM_CODE.match(code):
        raise ValidationError("The link's claim code is invalid")
    decode_key(key)
    netloc = parts.hostname if parts.port is None else f"{parts.hostname}:{parts.port}"
    if ":" in parts.hostname:  # IPv6 literal
        netloc = f"[{parts.hostname}]" + ("" if parts.port is None else f":{parts.port}")
    base = urlunsplit((parts.scheme, netloc, parts.path.rstrip("/"), "", ""))
    return ShareLink(base, code, key)


_PNG = b"\x89PNG\r\n\x1a\n"
_CONTENT_TYPES = b"[content_types].xml"


def metadata_file_type(b: bytes) -> Optional[str]:
    """Name of the file type when it is one the web app cleans of metadata
    before encrypting (detected by content, as the web app does)."""
    if len(b) >= 4 and b[:3] == b"\xff\xd8\xff":
        return "JPEG image"
    if b[:8] == _PNG:
        return "PNG image"
    if b[:4] == b"PK\x03\x04" and _CONTENT_TYPES in b.lower():
        return "Office document"
    head, tail = b[: 1024 * 1024], b[-2048:]
    if b"%PDF-" in head or (b"startxref" in tail and b"%%EOF" in tail):
        return "PDF"
    return None


_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    f"{p}{d}" for p in ("COM", "LPT") for d in "0123456789"
}


def safe_filename(name: str, fallback: str = "download.bin") -> str:
    """Turn an uploader-supplied filename into a plain name that is safe to
    create in the current directory: no directories, control or invisible
    formatting characters, leading dots (hidden files), Windows-reserved
    characters or device names; at most 255 bytes."""
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    out = []
    for ch in name:
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf") or ch == "�":
            continue
        out.append("_" if ch in '<>:"|?*' else ch)
    name = "".join(out).strip(" .")
    if len(name.encode("utf-8")) > 255:
        stem, ext = os.path.splitext(name)
        if len(ext.encode("utf-8")) > 16:
            stem, ext = name, ""
        while len((stem + ext).encode("utf-8")) > 255:
            stem = stem[:-1]
        name = stem.rstrip(" .") + ext
    if not name or name in (".", ".."):
        return fallback
    if name.split(".", 1)[0].rstrip(" ").upper() in _WINDOWS_RESERVED:
        name = "_" + name
    return name
