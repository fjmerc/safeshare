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
- Metadata leakage: the server still knows the size bucket of the ciphertext (see [Size Padding](#size-padding-anonymous-mode)), the upload time, the claim code, and the uploader's IP address.

## Limitations

### Browser Memory

The entire file must fit in browser memory twice — once as the original content and once as the encrypted output. For large files this can cause the browser tab to run out of memory or become unresponsive.

- A warning is shown in the UI for files larger than **500 MB**.
- In anonymous mode the padded copy is up to about 12% larger than the file, so peak memory grows by the same amount. On download, unwrapping copies the file once more.
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

The command-line tool, `safeshare-cli`, and the Go, Python and TypeScript SDKs encrypt client-side in the same format as the browser (see [Command-Line Tool and SDKs](#command-line-tool-and-sdks)). The import tool (`cmd/import-file`) doesn't, so it can't be used for these uploads.

### Metadata Stripping and E2EE

The server can't strip metadata from ciphertext. When `STRIP_METADATA=true`, the browser strips metadata itself before encrypting:

- **JPEG**: APP1–APP15 segments (EXIF, GPS, XMP, IPTC, maker notes, ICC profiles) and comments are removed, including any between progressive scans. The JFIF header keeps no embedded thumbnail, and anything after the end-of-image marker (secondary images, vendor trailers) is dropped. The Adobe APP14 colour-transform marker is kept so CMYK images still decode. Removing EXIF also removes the orientation flag, so the page warns when a photo may display rotated.
- **PNG**: only image-rendering chunks are kept (`IHDR`, `PLTE`, `IDAT`, `IEND`, `tRNS`, `cHRM`, `gAMA`, `iCCP`, `sBIT`, `sRGB`, `bKGD`, `pHYs` and the APNG animation chunks). Text, EXIF, timestamps, private chunks and anything after `IEND` are removed.
- **Office documents** (Word, Excel and PowerPoint: `.docx`, `.xlsx`, `.pptx` and their macro-enabled versions). Cleared:
  - The document properties (author, last editor, company, manager, title, template, timestamps, custom properties) and the custom XML data stores, including their schema lists (SharePoint names its own schemas by IDs that identify the site). Word bibliography sources and content-control bindings live in those stores and are lost too; bound content controls keep their current text.
  - Comment and tracked-change authors, initials and dates; the people and persons lists; PowerPoint co-authoring change records; shared-workbook user names; pivot-table "refreshed by" names; editing-permission editors; worksheet-protection account IDs; ink timestamps; and the account IDs and e-mail addresses Office stores with them.
  - Word revision-session IDs (`rsid`), document IDs, document variables and mail-merge sources; Excel's save path, revision ID, data-connection paths, connection strings and query sources, shared-workbook personal view names and OneDrive IDs of linked workbooks; PowerPoint's client ID and slide-library sync times; Microsoft 365 sensitivity labels (which name the organisation); and leftover data from earlier saves (`[trash]` entries).
  - Links that point at the author's files: the attached template, external workbook links, linked objects and mail-merge sources, whatever their address (including OneDrive and SharePoint URLs), and hyperlinks to local, network or relative paths, and the source path Word keeps for pictures pasted from a web page. Web hyperlinks and online video and audio (except from personal OneDrive or SharePoint storage) are kept; linked pictures are not.
  - Printer names and printer-driver data, metadata in embedded JPEG and PNG images and in the document thumbnail, metadata, comments and editor data (Inkscape paths) in embedded SVG images, and every zip entry's timestamp, comment and extra fields, plus the archive comment.
  - Embedded Office files (a chart's workbook, a pasted document) are cleaned the same way.
  - Each part is handled by its content type and root element, not its file name, and a part where a local file path is left in an attribute is reported as not cleaned.

  **Limits.** Office cleaning removes a known list of fields and keeps the rest. It's built and tested for files saved by Microsoft Office and LibreOffice, and checked with Microsoft's Open XML SDK so cleaned files still open; it has been tested with real Word, Excel and PowerPoint files, but not opened in Office itself. It isn't a guarantee against a document crafted to defeat it: someone who sends you a document could hide tracking data in a place this cleaner doesn't know about. If that's part of your threat model, don't upload the original: convert it to PDF or plain text, or use a dedicated tool such as [mat2](https://0xacab.org/jvoisin/mat2), and check the result.

  Kept: the text, formatting, comments and tracked changes themselves (a name typed into the text, or shown by an Author field, stays), web hyperlinks, embedded fonts and EMF, WMF and BMP images. Only parts known to be safe are copied unchanged; anything else is reported as not cleaned. That includes VBA macro projects, ActiveX controls, embedded OLE objects, data models, digital signatures, add-in data (including PowerPoint tags), Excel XML maps and macro sheets, document tasks, mail-merge recipient lists, parts of types it doesn't know (including newer ones and files saved in the "Strict Open XML" format), Word fields that link to files (Paste Link, linked pictures, `INCLUDETEXT`, fields naming a local path), SVG images that embed raster images, and media other than JPEG, PNG and SVG (video, audio, GIF, TIFF, HEIC, WebP). In anonymous mode a file containing them is refused; in other modes it's uploaded with the rest cleaned and a warning. Visio, XPS and other Office-style packages aren't supported. This needs the browser's built-in compression streams (any current browser, including Tor Browser).
- **PDF**: the document information (author, creator, producer, title, subject, keywords, dates and any custom entries) is cleared in every revision of the file, including earlier revisions left behind by incremental saves and entries stored in compressed object streams. All XMP metadata streams (for the document, pages and images) are replaced with an empty packet, the file identifier (`/ID`) is zeroed, comment annotations lose their author and dates, digital signatures lose the signer's name, location, reason, contact details, time and certificate (editing a signed PDF breaks the signature anyway), application-private data (`/PieceInfo`, left by Illustrator, InDesign or Acrobat) is emptied, and EXIF and other APP segments are removed from embedded JPEG images. Metadata is overwritten in place, so the file keeps its size and structure (including linearization). Kept: the text, images, comments' text, form fields and bookmarks. Reported as not cleaned: attached files, JPEG 2000 images, inline JPEG images in page content, XMP found in other streams, streams whose encoding can't be decoded to check them, unreadable trailers, objects the cross-reference data lists that can't be found, signs of hidden objects in a file whose cross-reference data is damaged, and anything that can't be rewritten in place, such as a compressed object stream holding the document information that no longer fits once the browser recompresses it (in testing, object streams written at maximum compression still fit). Encrypted or password-protected PDFs can't be cleaned.
- **Anything else** (OpenDocument, older `.doc`/`.xls`/`.ppt` files, password-protected Office files, Visio, video, audio) is uploaded as is, with a warning. Scrub those files before uploading, for example with [mat2](https://0xacab.org/jvoisin/mat2).

In anonymous mode the upload is stopped instead of sending the original when a JPEG, PNG, Office file or PDF can't be stripped: it can't be parsed, it's encrypted (PDF), an Office file or PDF is over 100 MB or contains parts that can't be cleaned, or the browser lacks compression streams.

## Command-Line Tool and SDKs

`safeshare-cli` (attached to each release from v1.17.1, or built from `sdk/go/cmd/safeshare-cli`; see [installing it](../sdk/go/README.md#installing-the-cli)) and the Go SDK encrypt and decrypt on your own machine, in exactly the browser's format: a file uploaded from the command line opens from its share link in a browser, and a browser upload downloads and decrypts with the CLI. Because no JavaScript from the server is involved, you don't have to trust the server to send you honest code. That is the main reason to use it on a Ghost server. You do have to trust the CLI binary, so build it from source or check it against the release.

**Upload.** Files are encrypted automatically on a server in Ghost mode or with `REQUIRE_CLIENT_ENCRYPTION=true`, and always when you use a proxy or an `.onion` address. In those cases the server's own settings aren't trusted, because a seized server could claim it isn't in Ghost mode. `--encrypt` encrypts on any server. The CLI says before uploading whether it will encrypt. The filename is hidden inside the encrypted file (stored as `encrypted.bin`) unless you pass `--show-filename`. Encrypted uploads are always padded, like Ghost-mode browser uploads. The CLI prints a share link with the key after the `#`; treat it as a secret. With `--json`, the link is the `url` field, so the whole JSON output is a secret too, and with `--qr` the QR code drawn on screen holds the key.

```bash
export SAFESHARE_URL=https://share.example.com
safeshare-cli upload report.pdf --expires 24
```

**Download.** Pass the share link, or `-` to read it from standard input so the key stays out of your shell history and the process list. The API token is only sent if the link points at your configured server. Filenames chosen by the uploader are cleaned before saving: no folders, hidden dot-files or special characters, and an existing file is never overwritten unless you pass `--overwrite`.

```bash
safeshare-cli download - < link.txt
```

You can also give the claim code and put the key in the `SAFESHARE_KEY` environment variable. Without the key, the file is saved still encrypted.

**Metadata.** The CLI can't remove metadata. On a Ghost server, it refuses JPEG, PNG, PDF and Office files (the ones the browser would have cleaned) unless you pass `--keep-metadata`. Scrub them first, for example with [mat2](https://0xacab.org/jvoisin/mat2). Other file types are uploaded as they are, the same as in the browser.

**Tor.** Give the CLI a SOCKS proxy with `--proxy` (or `SAFESHARE_PROXY`). Every request then goes through it, including the host name lookup, so `.onion` addresses work and DNS doesn't leak:

```bash
export SAFESHARE_PROXY=socks5h://127.0.0.1:9050
SAFESHARE_URL=http://xyz.onion safeshare-cli upload notes.txt
```

`ALL_PROXY`, `HTTPS_PROXY` or `HTTP_PROXY` work too. When only one of them is set, it is used for every request. When both `HTTPS_PROXY` and `HTTP_PROXY` are set, the usual per-scheme and `NO_PROXY` rules apply, so prefer `--proxy` for Tor. The CLI refuses redirects to another host or scheme, so a server can't send it to an address outside the proxy.

**Memory.** As in the browser, the whole file is encrypted in memory, so you need free memory of about its size. The CLI warns above 500 MB.

In Go code, `client.Upload` uses `UploadOptions.Encrypt` (`EncryptAuto` by default, which follows the server's settings, or `EncryptAlways`/`EncryptNever`); the result's `ShareURL` and `EncryptionKey` carry the key (they are left out of JSON encodings). `ClientConfig.Proxy` sets a proxy for every request. `client.DownloadDecrypted` (or `DownloadOptions.DecryptionKey`) decrypts, and `ParseShareURL` splits a share link. The Python and TypeScript SDKs work the same way (`encrypt="always"`, `download_decrypted`/`downloadDecrypted`, `parse_share_url`/`parseShareUrl`); see their READMEs. Test vectors generated from the browser's `crypto.js` (`sdk/testdata/e2e-vectors.json`, checked in CI by `tests/js/e2e-vectors.test.js`) keep all of them byte-for-byte the same as the browser.

## Checking the Web App

In the browser, the encryption code comes from the server, so you trust it to send the released code. From v1.17.0, each release publishes the SHA-256 of every page and script, and `safeshare-cli verify <url>` checks a running server against them. It shows whether the server (or a CDN in front of it) changed the web app, but only for what the server sent to you at the time. See [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md).

## Technical Details

### Payload Format and Versions

The bytes that go into AES-GCM are one of three layouts. The browser tells them apart by the first four bytes, and **decryption always understands all three, whatever mode the server is in**, so old share links keep working.

| Version | Magic | Layout | Written when |
|---------|-------|--------|--------------|
| v1 | none | `[file]` | E2EE with the filename visible, in non-anonymous mode (and every file from before filename hiding) |
| v2 (`SF01`) | `SF01` | `[SF01][u32 LE name length][name UTF-8][file]` | **Hide filename** on, non-anonymous mode |
| v3 (`SF02`) | `SF02` | `[SF02][u32 LE name length][u64 LE file length][name UTF-8][file][zero padding]` | Anonymous mode, always |

The magic is `SF` plus a two-digit format number, so the next format uses `SF03`. For `SF02`, a name length of 0 means the filename stays visible to the server (Hide filename off) and is not in the payload. The download page unwraps files the server stored as `encrypted.bin` (these are always framed) and any file whose decrypted data begins with `SF02` and has a valid header (for a file stored under its real name, the server-visible name wins over any embedded one); a plain legacy file that merely starts with `SF01` is not touched.

An `SF02` payload is rejected (the download shows an error and nothing is saved) if the file length plus header does not fit in the decrypted size, the name length is over 1024 bytes, or any padding byte is not zero. Because the length is inside the authenticated plaintext, only the key holder can write a bad one. The exception is a file stored under its real name (not `encrypted.bin`): if its data starts with `SF02` but the header is invalid, it is saved as is, because a legacy plain file could begin with those bytes.

### Size Padding (Anonymous Mode)

The server stores ciphertext, so the stored size would otherwise be the file size plus 28 bytes. When `GET /api/config` reports `anonymous_mode: true`, the browser pads the framed payload to a bucket **before encryption**, so the padding is authenticated by GCM and indistinguishable from the rest of the ciphertext. Other modes are unchanged: no padding, same formats as before. If the browser can't load `/api/config`, it pads anyway, because the mode is unknown and padding is the safe default.

- **Scheme: PADME** (Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs", PETS 2019). The padded length keeps only the top bits of the length significant. Overhead is at most about 12% and shrinks as files grow, and the bucket leaks O(log log n) bits about the length. Power-of-two buckets would add up to 100% (a 300 MB file would become 512 MB in browser memory).
- **Floor:** payloads smaller than 4096 bytes are padded to 4096, so notes and keys are not in fine-grained buckets of their own.
- **Padding bytes are zeros.** They sit inside the AES-GCM plaintext, so the ciphertext is indistinguishable from random, and zeros are free to generate for hundreds of MB. The decryptor requires them to be zero, which keeps the format canonical and gives a malicious writer no covert channel.
- **Examples** (file size, stored size): 10 KiB, 10.5 KiB; 1 MiB, 1.03 MiB; 100 MiB, 102 MiB; 500 MiB, 504 MiB.
- **What is still visible:** the bucket, hence the size to within about 12%. Files of similar size share a bucket. The upload and expiry times, the claim code and the download count are unaffected.

#### Size limits and quota

The server cannot see inside the ciphertext, so `MAX_FILE_SIZE`, the quota and the disk check apply to the **stored (padded) size**, as with any upload. To avoid refusing files that would have fit, the browser caps the bucket 4 KB below `MAX_FILE_SIZE` (the server applies the limit to the whole upload request, form fields included). A file that would fit unpadded is never rejected because of padding: files that PADME would round past the cap land in that top bucket, and a file in the last 4 KB below the limit is simply left unpadded. A file that exceeds the limit even unpadded (the 28 bytes of IV and tag, plus a header of 16 bytes and the filename if hidden) is refused in the browser before upload with "This file is too large to upload encrypted...". Padding does count toward the quota, so a quota that is nearly full can refuse an upload the unpadded file would have fit.

The pickup page and the download page show the stored (padded) size, since the real size is only known after decrypting. The upload result page shows the real size.

#### Chunked uploads

The file is padded and encrypted before chunking, so chunked uploads (`CHUNKED_UPLOAD_THRESHOLD`) work on the padded size and the server sees the padded total, as for any other upload. The threshold decision uses the padded size.

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

The plaintext inside is one of the payload layouts above.

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
| Chunked uploads | Compatible | Each chunk is part of the encrypted payload. The entire file is padded (anonymous mode) and encrypted before chunking begins. |
| Server-side encryption at rest (`ENCRYPTION_KEY`) | Compatible | The two encryption layers are independent. The server encrypts the E2EE ciphertext blob with its own key. Provides defense in depth. |
| Download limits | Compatible | The server enforces download limits on the encrypted blob as normal. |
| File expiration | Compatible | Expiration is enforced by the server as normal. |
| Admin file inspection | Not applicable | Admins can see file metadata (size, upload time, claim code) but cannot read E2EE file contents. |
| Go SDK and `safeshare-cli` | Compatible | Encrypt and decrypt on the user's machine in the browser's format. See [Command-Line Tool and SDKs](#command-line-tool-and-sdks). |
| Python and TypeScript SDKs | Compatible | Same format and defaults: `upload(..., encrypt="auto"/"always"/"never")`, `download_decrypted` / `downloadDecrypted`. The Python SDK takes a `proxy` for Tor; the TypeScript SDK needs a proxy-aware `fetch`. |
| Import tool (`cmd/import-file`) | Not supported | The CLI import tool does not perform client-side encryption. Use standard server-side encryption at rest for imported files. |
| Metadata stripping (`STRIP_METADATA`) | Browser-side only | The server can't strip ciphertext; the browser strips JPEG, PNG, Office (docx/xlsx/pptx) and PDF metadata before encrypting. See [Metadata Stripping and E2EE](#metadata-stripping-and-e2ee). |
| Malware scanning | Not compatible | Ciphertext can't be scanned. With `MALWARE_SCAN_REJECT_UNSCANNABLE=true`, E2EE uploads are rejected and the toggle is hidden. |

## Security Properties

- **Zero server knowledge**: The server stores only the encrypted blob. It never receives the plaintext or the key.
- **Authenticated encryption**: AES-256-GCM provides both confidentiality and integrity. A tampered ciphertext will fail to decrypt.
- **Unique IV per file**: Each upload uses a freshly generated random IV, preventing IV reuse attacks.
- **No additional endpoints**: E2EE is implemented entirely in the browser. It requires no new API endpoints and no new database fields.
- **What the server still sees**: the ciphertext size bucket (exact size in non-anonymous mode), upload and expiry times, download counts, and the filename unless **Hide filename** is checked. In anonymous mode the server does not record a hash of the upload.

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
