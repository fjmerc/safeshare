# Client-Side End-to-End Encryption

SafeShare supports optional end-to-end encryption (E2EE) where the file is encrypted in the browser before upload. The server receives and stores an opaque encrypted blob and never has access to the plaintext or the decryption key.

## How It Works

### Upload Flow

1. The user selects a file and toggles **End-to-End Encryption** on the upload form.
2. The browser generates a random 256-bit AES key using the Web Crypto API (`crypto.subtle.generateKey`).
3. A random 12-byte initialization vector (IV) is generated.
4. The file is encrypted in the browser using **AES-256-GCM** before any data is sent over the network.
5. The encrypted payload — `[12-byte IV][AES-256-GCM ciphertext + 16-byte authentication tag]` — is uploaded to the server as a binary blob.
6. The server stores the encrypted blob with no knowledge of the original content.
7. After a successful upload, the share URL is generated with the decryption key embedded in the **URL fragment**:

   ```
   https://host/#/claim/CLAIM_CODE/key/BASE64URL_ENCODED_KEY
   ```

### Download Flow

1. The recipient opens the share URL. The browser parses the URL fragment to extract the claim code and the decryption key.
2. Because URL fragments are never transmitted to the server (RFC 3986 §3.5), the server does not see the key at any point.
3. The browser downloads the encrypted blob from the server using the claim code.
4. The browser decrypts the blob in memory using the extracted AES-256-GCM key and IV.
5. The GCM authentication tag is verified automatically. If the ciphertext has been tampered with, decryption fails and the file is not saved.
6. The browser triggers a file save dialog with the decrypted content using the original filename.

## When to Use E2EE

End-to-end encryption protects files from anyone who has access to the server but not the share URL. This includes:

- **Server compromise**: An attacker who gains access to disk storage or the database cannot read E2EE files without the decryption key.
- **Untrusted operators**: When the server is operated by a third party, E2EE ensures they cannot inspect file contents even if they wanted to.
- **Encryption at rest disabled**: E2EE provides file-level confidentiality regardless of whether the `ENCRYPTION_KEY` environment variable is configured.

E2EE does **not** protect against:

- An attacker who obtains the full share URL (which contains the key in the fragment).
- Malicious JavaScript served by a compromised server — if the server is compromised at the application level, it could serve modified JavaScript that exfiltrates keys before encryption.
- Metadata leakage: the server still knows the file size (of the ciphertext), the upload time, the claim code, and the uploader's IP address.

## Limitations

### Browser Memory

The entire file must fit in browser memory twice — once as the original content and once as the encrypted output. For large files this can cause the browser tab to run out of memory or become unresponsive.

- A warning is shown in the UI for files larger than **500 MB**.
- For files that do not fit in memory, use server-side encryption at rest (`ENCRYPTION_KEY`) instead.

### URL Fragment Handling

The decryption key lives in the URL fragment. If the fragment is lost, the file cannot be decrypted:

- Copying only the base URL (without the `#...` portion) produces a broken link.
- Some messaging applications and link-preview systems strip or truncate URL fragments.
- When a recipient opens the link, SafeShare removes the fragment from the address bar and the browser's history entry as soon as it has read the key, so the key doesn't stay in history on the recipient's device. Anywhere the link itself was pasted (chat logs, email, notes) still holds the key, so treat the link as the secret it is.

Always share the complete URL, including everything after and including the `#` character.

### Requires a Secure Context

The Web Crypto API is only available in [secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts). This means E2EE requires:

- **HTTPS** in production,
- **a `.onion` address opened in Tor Browser**, which treats onion services as secure contexts even over `http://` (Tor itself provides the end-to-end encryption and authentication), or
- **localhost** for local development.

SafeShare checks for Web Crypto itself rather than for `https:`, so the toggle appears wherever the browser provides it. Browsers that don't treat `.onion` as a secure context (for example a regular Chromium routed through a Tor proxy) don't provide Web Crypto on `http://` onion pages.

On insecure HTTP connections the E2EE toggle is hidden. If the server requires client-side encryption (see below), uploading is disabled on those connections with a message explaining why, instead of sending the file unencrypted.

## Requiring Client-Side Encryption

Set `REQUIRE_CLIENT_ENCRYPTION=true` to make the server refuse any upload that wasn't encrypted in the browser. It defaults to the value of `ANONYMOUS_MODE`, so anonymous (Ghost) deployments require it unless you set `REQUIRE_CLIENT_ENCRYPTION=false`.

When it's on:

- The E2EE toggle is checked and locked, and **Hide filename** starts checked (it can still be turned off).
- `POST /api/upload` must carry the header `X-SafeShare-Client-Encrypted: true`; without it the request is rejected with `400 CLIENT_ENCRYPTION_REQUIRED` before the body is read, so no plaintext reaches the server's disk. The `client_encrypted=true` form field is still required as well.
- `POST /api/upload/init` must have `client_encrypted: true`, and chunks or completion for a session opened without it are rejected the same way.
- `GET /api/config` reports `client_encryption_required: true` so clients and SDKs can tell up front.

The server can't verify that a file really is ciphertext; `client_encrypted` is the client's own claim. The requirement protects honest uploaders from sending plaintext by mistake (an old bookmarked page, a browser without Web Crypto, a script that forgot the flag). It does not stop someone who deliberately sends plaintext with the flag set, and it doesn't need to: the only person that hurts is that uploader.

The requirement can't be combined with `MALWARE_SCAN_REJECT_UNSCANNABLE=true`, which rejects every E2EE upload because ciphertext can't be scanned. The server logs an error at startup when both are set.

The SDKs and the CLI import tool don't encrypt client-side, so they can't upload to a server that requires it.

### Metadata Stripping and E2EE

The server can't strip metadata from ciphertext. When `STRIP_METADATA=true`, the browser strips metadata itself before encrypting:

- **JPEG**: APP1–APP15 segments (EXIF, GPS, XMP, IPTC, maker notes, ICC profiles) and comments are removed, including any between progressive scans. The JFIF header keeps no embedded thumbnail, and anything after the end-of-image marker (secondary images, vendor trailers) is dropped. The Adobe APP14 colour-transform marker is kept so CMYK images still decode. Removing EXIF also removes the orientation flag, so the page warns when a photo may display rotated.
- **PNG**: only image-rendering chunks are kept (`IHDR`, `PLTE`, `IDAT`, `IEND`, `tRNS`, `cHRM`, `gAMA`, `iCCP`, `sBIT`, `sRGB`, `bKGD`, `pHYs` and the APNG animation chunks). Text, EXIF, timestamps, private chunks and anything after `IEND` are removed.
- **Anything else** (PDF, Office documents, video, audio) is uploaded as is, with a warning. Scrub those files before uploading, for example with [mat2](https://0xacab.org/jvoisin/mat2).

In anonymous mode, if the browser can't parse a JPEG or PNG to strip it, the upload is stopped instead of sending the original.

## Technical Details

### Encryption Algorithm

| Property | Value |
|----------|-------|
| Algorithm | AES-256-GCM |
| Key size | 256 bits (32 bytes) |
| IV size | 12 bytes (random, per file) |
| Authentication tag | 16 bytes (appended by GCM) |
| API | Web Crypto API (`crypto.subtle`) |

### Ciphertext Format

```
[ 12 bytes: random IV ][ N bytes: AES-256-GCM ciphertext ][ 16 bytes: GCM auth tag ]
```

The IV is prepended to the ciphertext so the download path can extract it without any additional metadata stored on the server.

### Key Transport

The AES key is encoded as **base64url** (URL-safe base64, no padding) and placed in the URL fragment:

```
https://host/#/claim/ABC123/key/dGhpcyBpcyBhIHRlc3Qga2V5ZXhhbXBsZQ
```

The fragment is parsed entirely in the browser. It is not included in HTTP requests, server logs, or `Referer` headers.

### Key Generation

Keys are generated using `crypto.subtle.generateKey` with `{name: "AES-GCM", length: 256}` and `extractable: true`. The generated `CryptoKey` is exported via `crypto.subtle.exportKey("raw", key)` to obtain the raw 32-byte key material for embedding in the URL.

## Compatibility with Other Features

| Feature | Compatibility | Notes |
|---------|--------------|-------|
| Password protection | Compatible | Password is verified by the server before the encrypted blob is served. The browser then decrypts the blob client-side. The password prompt appears first. |
| QR codes | Compatible | The QR code encodes the full share URL including the key fragment. The recipient must scan the full URL. |
| Chunked uploads | Compatible | Each chunk is part of the encrypted payload. The entire file is encrypted before chunking begins. |
| Server-side encryption at rest (`ENCRYPTION_KEY`) | Compatible | The two encryption layers are independent. The server encrypts the E2EE ciphertext blob with its own key. Provides defense in depth. |
| Download limits | Compatible | The server enforces download limits on the encrypted blob as normal. |
| File expiration | Compatible | Expiration is enforced by the server as normal. |
| Admin file inspection | Not applicable | Admins can see file metadata (size, upload time, claim code) but cannot read E2EE file contents. |
| Import tool (`cmd/import-file`) | Not supported | The CLI import tool does not perform client-side encryption. Use standard server-side encryption at rest for imported files. |
| Metadata stripping (`STRIP_METADATA`) | Browser-side only | The server can't strip ciphertext; the browser strips JPEG and PNG metadata before encrypting. See [Metadata Stripping and E2EE](#metadata-stripping-and-e2ee). |
| Malware scanning | Not compatible | Ciphertext can't be scanned. With `MALWARE_SCAN_REJECT_UNSCANNABLE=true`, E2EE uploads are rejected and the toggle is hidden. |

## Security Properties

- **Zero server knowledge**: The server stores only the encrypted blob. It never receives the plaintext or the key.
- **Authenticated encryption**: AES-256-GCM provides both confidentiality and integrity. A tampered ciphertext will fail to decrypt.
- **Unique IV per file**: Each upload uses a freshly generated random IV, preventing IV reuse attacks.
- **No additional endpoints**: E2EE is implemented entirely in the browser. It requires no new API endpoints and no new database fields.
- **What the server still sees**: the ciphertext size, upload and expiry times, download counts, and the filename unless **Hide filename** is checked. In anonymous mode the server does not record a hash of the upload.

## Setup

E2EE requires no server configuration. It is available to all users on any SafeShare deployment served over HTTPS, or over a `.onion` address in Tor Browser. To make it mandatory, set `REQUIRE_CLIENT_ENCRYPTION=true` (the default in anonymous mode).

To ensure the feature is accessible:

1. Deploy SafeShare behind a TLS-terminating reverse proxy (see `docs/REVERSE_PROXY.md`).
2. Set `PUBLIC_URL` to your HTTPS domain so generated share URLs use `https://`.

For maximum protection, combine E2EE with server-side encryption at rest:

```bash
docker run -d \
  -p 8080:8080 \
  -e PUBLIC_URL=https://share.yourdomain.com \
  -e ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  safeshare:latest
```

With both layers active, E2EE files are doubly encrypted: client-side AES-256-GCM (key held only by the user) wrapped by server-side AES-256-GCM (key held only by the operator).
