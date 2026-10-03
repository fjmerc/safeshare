# HTTP Range Request Support

SafeShare implements RFC 9110-compliant HTTP Range and conditional-request support for claim downloads, enabling resumable downloads, partial content delivery, and client-side caching for large files. As of ADR-017, all of this is implemented via Go's standard `http.ServeContent`, layered on top of SafeShare's own encrypted-format decryption and download-accounting policy.

## Overview

HTTP Range requests allow clients to request specific byte ranges of a file instead of downloading the entire file at once. This enables:

- **Resumable Downloads**: If a download is interrupted, it can be resumed from where it stopped
- **Partial Content Delivery**: Download only specific portions of a file
- **Parallel Downloads**: Some download managers can request multiple ranges in parallel
- **Streaming Optimization**: Media players can seek to specific positions without downloading the entire file

Conditional requests (`If-None-Match`, `If-Modified-Since`, `If-Range`) let a client that already has an up-to-date copy of a file avoid re-downloading it, and let a resumed download safely fall back to a full re-download if the underlying file changed since the client's last request.

## Features

### Supported Range Formats

| Format | Description | Example |
|--------|-------------|---------|
| `bytes=start-end` | Specific byte range | `bytes=0-1048575` (first 1MB) |
| `bytes=start-` | From offset to end | `bytes=1048576-` (skip first 1MB) |
| `bytes=-suffix` | Last N bytes | `bytes=-1048576` (last 1MB) |

### HTTP Status Codes

| Status Code | Description | When Returned |
|-------------|-------------|---------------|
| **200 OK** | Full file | No Range header, or the Range header is unsupported/malformed (see below) |
| **206 Partial Content** | Byte range | A well-formed, satisfiable single-range Range header |
| **304 Not Modified** | Client's cached copy is current | `If-None-Match`/`If-Modified-Since` matches; empty body, headers only |
| **416 Range Not Satisfiable** | Range describes bytes the file doesn't have | Start >= file size, or a range against a zero-byte file |
| **500 Internal Server Error** | The file could not be safely served | See "Fail-closed error handling" below |

**A malformed, unsupported, or multi-range `Range` header is treated as if it were absent (200 full content), not rejected.** SafeShare has never supported multipart/byteranges responses (`Range: bytes=0-100,200-300`) — each additional part of a multipart response would cost its own decrypt pass for an encrypted file — so a client that sends one gets the whole file instead of an error. Likewise `bytes=abc-def` or `bytes=500-100` (start > end) are simply ignored, per RFC 9110 §14.2's guidance that a server unable to satisfy exactly what a Range header asks for may serve the full representation instead of rejecting the request.

### Response Headers

**All responses** (200, 206, 304, 416, and `HEAD`):
- `Accept-Ranges: bytes` — advertises Range support
- `Cache-Control: private, no-store` — every claim response depends on per-recipient state (password gate result, scan status, download-limit outcome) and must never be cached by a browser or CDN
- `ETag` — a strong (quoted, no `W/` prefix) validator derived from the file's stored filename, size, and creation time — see "Conditional Requests" below
- `Last-Modified` — the file's creation time (files are immutable after upload, so this is the only meaningful "last modified")

**200/206 responses additionally carry**:
- `Content-Type` — the file's original MIME type
- `Content-Disposition` — `attachment`, with both a legacy ASCII `filename=` fallback and an RFC 6266 `filename*=UTF-8''...` extended value carrying the full (sanitized) Unicode filename

**206 Partial Content responses**:
- `Content-Range: bytes start-end/total`
- `Content-Length` — size of the range (end − start + 1)

**416 Range Not Satisfiable responses**:
- `Content-Range: bytes */total`

**Capped-download responses** (`max_downloads` set; see ADR-014):
- `X-Download-Session` — opaque bearer token identifying this download's session. A resumable download client should send this back as an `X-Download-Session` request header on any follow-up Range request for the same file, so a pause/resume is recognised as the same download instead of a separate, independently-counted request. Not present on files with no download cap, and never set on a `HEAD` request (see below).

### `HEAD` Requests

A `HEAD` request to a claim download URL returns exactly the headers a `GET` to the same URL would (`Content-Length`, `ETag`, `Accept-Ranges`, `Content-Type`, `Content-Disposition`, ...) with no body, and goes through every access check a `GET` does (claim-code validity, expiry, scan status, password, **and the download-limit check** — a `HEAD` on a file that has already reached `max_downloads` gets the same `410 Gone` a `GET` would). It never:

- counts against `max_downloads`,
- reserves or spends a download-session slot, or
- mints an `X-Download-Session` token.

Because it never reserves anything, the download-limit check above is a best-effort read (the same one `/api/claim/:code/info` uses) rather than the atomic, DB-enforced guard a capped `GET` goes through — in a narrow race, a `HEAD` might report a file as available a moment after its last slot was actually claimed by a concurrent `GET`. The following `GET` still enforces the limit atomically and correctly either way.

**One further, narrower exception**: a `HEAD` against a file stored in the old, pre-streaming (legacy) encrypted format does not actually attempt decryption (this is what lets it skip the memory/CPU cost a `GET` would pay — see "Legacy Encrypted Files" below), so it cannot detect a corrupt ciphertext or a wrong encryption key the way a `GET` (or a `HEAD` against a newer-format file, which does validate its first chunk) would. Such a file would pass `HEAD` but fail the subsequent `GET`. Run `migrate-encryption --verify --verify-decrypt` to audit legacy files' decryptability outside the request path.

Use `HEAD` to check a file's size or availability before starting a real download — SafeShare's own web UI does this to check a password before it starts a password-protected download.

### Conditional Requests

`If-None-Match` (checked against `ETag`) and `If-Modified-Since` (checked against `Last-Modified`) are fully supported: a match returns `304 Not Modified` with no body. `If-Match` and `If-Unmodified-Since` are also supported, returning `412 Precondition Failed` when they fail. Like `HEAD`, a `304`/`412` response never counts against `max_downloads` or spends a download-session slot — it's handled entirely before any file content is read.

`If-Range` is also supported for resuming a paused download safely: if the file has changed since the client's `If-Range` validator was captured, the server serves the full file (200) instead of a now-incorrect byte range.

These conditional headers take precedence over Range entirely, per RFC 9110: if a request combines a Range header describing bytes the file doesn't have (which would otherwise get `416 Range Not Satisfiable`) with a conditional header that resolves to `304`/`412`, the conditional result wins — the client gets `304`/`412`, not `416`.

## Implementation Details

### Architecture

SafeShare handles Range requests uniformly across storage formats by presenting each one as an `io.ReadSeeker` to `http.ServeContent`, which does the actual Range/conditional-request/`HEAD` work. What differs per format is how that `io.ReadSeeker` is produced:

#### Unencrypted (Plaintext) Files
- The on-disk file is opened and passed directly to `http.ServeContent` — no intermediate buffering.
- This also lets a full, non-Range GET reach the kernel's `sendfile(2)` fast path all the way through SafeShare's logging/metrics middleware. As of the 3c-3 hardening pass, `sessionWriter.ReadFrom` (`internal/handlers/session_writer.go`) extends the same `io.ReaderFrom` chain to a file with a download limit set (`max_downloads`) too — provably equivalent to the ordinary buffered-write path for the ADR-014 commit-threshold/session bookkeeping (see that file's tests), and confirmed to actually reach `sendfile(2)`: measured on a real container, a 512MB capped plaintext download now costs ~200ms CPU instead of ~1060ms.

#### Streaming Encrypted Files (SFSE1 / SFSE2)
- A pooled, seekable decrypting reader (`SFSEReader`) is opened over the file. Opening it validates the header and confirms the on-disk ciphertext size exactly matches what the database-recorded plaintext length implies — a truncated or corrupted file is rejected here, before any response header is written, rather than surfacing mid-stream.
- The reader's first chunk is decrypted immediately (before headers are written) to catch a wrong key or a corrupt first chunk the same way.
- Only the chunks actually touched by the requested range are decrypted — for a small range deep inside a large file, this means one or two chunks, not the whole file.
- Both SFSE1 and SFSE2 downloads verify the file's recorded SHA-256 checksum for a genuinely full, sequential download (this check silently doesn't apply to a partial/ranged read, which can't validate a whole-file digest).

#### Legacy Encrypted Files (pre-SFSE, AES-256-GCM, all-at-once)
- The entire file is decrypted into memory before being served — this format predates chunked/streaming encryption and has no way to seek within it.
- Capped by `LEGACY_DECRYPT_MAX_BYTES` (default 128MB): a legacy file larger than this is refused (500) rather than risking excessive memory use. Re-encrypt it with `migrate-encryption` to move it to the streaming SFSE format, which has no such limit.
- A `HEAD` request against a legacy file does **not** decrypt it: the file's size is already known from the database and was already confirmed consistent with the on-disk ciphertext size during format classification, so `HEAD` answers from that without doing (or budgeting for) any decrypt work. The size cap above is still enforced for `HEAD` — a legacy file too large to ever serve reports the same failure either way.

### Fail-Closed Error Handling

- **A file whose on-disk size doesn't match any recognized format for its database record** (plaintext-size match, or a structurally valid SFSE1/SFSE2/legacy ciphertext for that plaintext length) fails with `500` rather than being served — this can only happen from disk-level corruption or tampering, not normal operation.
- **An encrypted file with no `ENCRYPTION_KEY` configured** fails with `500` rather than streaming raw ciphertext to the client with an incorrect `Content-Length`.
- **A plaintext file is always served as plaintext**, regardless of whether `ENCRYPTION_KEY` happens to be configured — classification is based on the file's actual on-disk shape, never on server configuration.

### Encrypted-Download Admission Control

Decrypting a file (SFSE chunk buffers, or a legacy file's full-memory decrypt) costs server memory for the duration of the download. Three independent limits bound this:

- `DOWNLOAD_DECRYPT_MEMORY_BUDGET` (default 256MB) — a process-wide ceiling on how much decrypt memory may be in use across every concurrent encrypted download at once. A download that can't get a share of this budget within a few seconds receives `503 Service Unavailable` with `Retry-After`. Requests wait for a share of this budget in strict arrival order (first-come, first-served) — a large request is never skipped over by smaller ones that arrive after it and happen to fit in whatever's currently free, so it can't be starved indefinitely by a steady stream of small requests. The tradeoff is that once the request at the front of the line doesn't fit yet, nothing behind it is admitted either, even if it would otherwise fit.
- **A per-client share of that budget**, capped at a quarter of it: a single client can't claim more than 25% of `DOWNLOAD_DECRYPT_MEMORY_BUDGET` across their own concurrent encrypted downloads, even though the FIFO ordering above is otherwise fair. A lone download is never rejected by this — only a *second* concurrent one from the same client that would push their combined share over the limit. Tracked per client, grouped by full address for IPv4 or by /64 prefix for IPv6 (so briefly rotating addresses within one IPv6 allocation doesn't dodge the limit).
- `MAX_ENCRYPTED_DOWNLOADS_PER_IP` (default 8, `0` disables) — a limit on how many encrypted downloads a single client may have running at once, independent of which file(s) are targeted, guarding against a client flooding many cheap tiny-Range requests against one file, each of which would otherwise cost a full chunk decrypt. Grouped the same way as the per-client budget share above. See `docs/TOR_DEPLOYMENT.md` for why this needs raising (or disabling) on a hidden service or any deployment where every visitor shares one apparent address. **Setting this to `0` disables the per-client memory-budget share above too** — `0` means no per-client limits of either kind, only the global `DOWNLOAD_DECRYPT_MEMORY_BUDGET` ceiling.

Unencrypted downloads are not subject to any of these.

**A stalled reader — or one that merely reads too slowly — can't hold its share of the budget indefinitely.** The write deadline for an encrypted download is continuously the *shortest* of three bounds: the full multi-hour transfer deadline a healthy download gets; a short idle window (60 seconds by default) re-armed after every successful write, including — critically — before the very first one, so a connection that blocks immediately (a client that never acknowledges anything at all) is caught exactly as fast as one that blocks after a few writes; and an **average-progress floor** that requires the whole transfer to sustain at least a minimum rate (16 KiB/s by default) since it started, not just "some progress every 60 seconds." That last bound specifically closes a "slow-drip" gap: without it, a client reading just often enough to keep resetting the 60-second idle window — regardless of how little data actually moved — could stretch a single download out to the full multi-hour deadline. Once any of the three bounds elapses with insufficient progress, the connection is torn down and its share of the decrypt-memory budget is released.

**`LEGACY_DECRYPT_MAX_BYTES` is deliberately kept well under `DOWNLOAD_DECRYPT_MEMORY_BUDGET`** (128MB vs. 256MB by default): a legacy download holds its *entire* weight for the whole time it's decrypting, so if the per-file cap were allowed to approach or exceed the total budget, a single max-size legacy decrypt could by itself consume the whole budget and serialize every other concurrent encrypted download (SFSE or legacy) behind it in the FIFO queue above. Keeping the cap well below the budget bounds how much of it any one legacy download can claim. `HEAD` requests against a legacy file don't acquire any of this budget at all (see "Legacy Encrypted Files" above) — they answer from the already-verified database size instead of decrypting.

### Key Components

| File | Purpose |
|------|---------|
| `internal/utils/range_policy.go` | `ResolveRange` — Range/If-Range decision policy |
| `internal/utils/sfse_readseeker.go` | `SFSEReader` — seekable decrypting reader for SFSE1/SFSE2 |
| `internal/utils/classify.go` | `ClassifyStoredFile` — on-disk format detection |
| `internal/utils/content_disposition.go` | `ContentDisposition` — RFC 6266 header construction |
| `internal/utils/etag.go` | `ComputeClaimETag` — strong ETag derivation |
| `internal/utils/decrypt_admission.go` | `DecryptAdmission` — decrypt-memory admission control |
| `internal/handlers/claim_range.go` | `serveFileWithRangeSupport` — ties the above together via `http.ServeContent` |
| `internal/handlers/claim.go` | `ClaimHandler` — integration point, `HEAD` short-circuit |
| `internal/handlers/claim_session.go` | ADR-014 download-session/commit-threshold policy for capped files |
| `internal/handlers/session_writer.go` | `sessionWriter` — commit-threshold gating for capped downloads, including the `ReadFrom` path that reaches the same sendfile mechanism uncapped downloads use |

See ADR-017 for the full design rationale.

### Performance

**Unencrypted Files**:
- Near-instant response for any range; a full download can use `sendfile`.

**Streaming Encrypted Files (SFSE1/SFSE2)**:
- Only processes chunks within the requested range.
- For a 1MB range in a 10GB file: processes one or two 10MB chunks, not the entire 10GB.
- Memory usage per stream: roughly one chunk's size, regardless of file size (bounded further, in aggregate across all concurrent downloads, by `DOWNLOAD_DECRYPT_MEMORY_BUDGET`).

**Legacy Encrypted Files**:
- Decrypts the entire file into memory, capped by `LEGACY_DECRYPT_MAX_BYTES`.
- Recommended: re-encrypt large legacy files to SFSE with `migrate-encryption`.

## Usage Examples

### curl

```bash
# Download first 1MB
curl -r 0-1048575 "https://share.example.com/api/claim/ABC123" -o chunk1.bin

# Download from 1MB to end
curl -r 1048576- "https://share.example.com/api/claim/ABC123" -o remainder.bin

# Download last 1MB
curl -r -1048576 "https://share.example.com/api/claim/ABC123" -o last-mb.bin

# Resume interrupted download
curl -C - "https://share.example.com/api/claim/ABC123" -o file.bin

# Check size/availability without downloading
curl -I "https://share.example.com/api/claim/ABC123"
```

### wget

```bash
# Resume interrupted download
wget -c "https://share.example.com/api/claim/ABC123" -O file.bin
```

### Browser

Modern browsers automatically use Range requests for:
- HTML5 video/audio seeking
- PDF viewer seeking
- Download manager resume functionality

### Download Managers

Download managers like aria2, axel, and IDM automatically utilize Range requests for:
- Parallel chunk downloads
- Resume after network interruption
- Bandwidth optimization

## Testing

### Basic Test

```bash
# Create test file
dd if=/dev/urandom of=test.bin bs=1M count=10

# Upload to SafeShare
RESPONSE=$(curl -s -F "file=@test.bin" -F "expires_in_hours=24" \
  http://localhost:8080/api/upload)
CLAIM_CODE=$(echo $RESPONSE | jq -r '.claim_code')

# Test range request
curl -v -r 0-1048575 "http://localhost:8080/api/claim/$CLAIM_CODE" \
  -o chunk.bin
```

**Expected Response**:
```
HTTP/1.1 206 Partial Content
Accept-Ranges: bytes
Cache-Control: private, no-store
ETag: "a1b2c3d4e5f6..."
Content-Range: bytes 0-1048575/10485760
Content-Length: 1048576
```

### Conditional Request Test

```bash
ETAG=$(curl -sI "http://localhost:8080/api/claim/$CLAIM_CODE" | grep -i '^etag:' | tr -d '\r')
curl -v -H "If-None-Match: ${ETAG#etag: }" "http://localhost:8080/api/claim/$CLAIM_CODE"
# Expected: HTTP/1.1 304 Not Modified, empty body
```

### Resume Test

```bash
# Download first half
curl -r 0-5242879 "http://localhost:8080/api/claim/$CLAIM_CODE" -o part1.bin

# Download second half
curl -r 5242880- "http://localhost:8080/api/claim/$CLAIM_CODE" -o part2.bin

# Combine and verify
cat part1.bin part2.bin > resumed.bin
md5sum test.bin resumed.bin  # Should match
```

### Invalid Range Test

```bash
# Start beyond file size
curl -v -r 999999999- "http://localhost:8080/api/claim/$CLAIM_CODE"
# Expected: HTTP/1.1 416 Range Not Satisfiable

# Malformed Range header (treated as absent)
curl -v -H "Range: bytes=abc-def" "http://localhost:8080/api/claim/$CLAIM_CODE"
# Expected: HTTP/1.1 200 OK, full file body
```

## Backward Compatibility

- **100% backward compatible**: Clients without Range support still work
- No Range header = HTTP 200 OK with full file (existing behavior)
- All existing download links continue to work unchanged
- Claim codes, expiration, download limits, password protection all work identically

## Security Considerations

### No Authentication Bypass

- Range and conditional requests respect all existing security controls:
  - Claim code validation
  - Password protection
  - Download limits (see "Download Counting" below)
  - Expiration enforcement
  - Malware-scan status gating (ADR-015)

### Download Counting

**As of ADR-014**, a download only counts against `max_downloads` when the
recipient has actually received the file, not on every individual HTTP
request:

- Full download (no Range): 1 download counted, immediately.
- Resume across several Range requests, presenting the returned
  `X-Download-Session` token on each follow-up request: 1 download counted
  total, regardless of how many requests it took.
- A small "probe" Range request (e.g. a link-preview crawler fetching a few
  bytes) below a per-file threshold: free, and does not consume a slot.
  Repeated small probes are bounded by a per-file budget — once enough
  uncounted probe bytes accumulate, subsequent probes start counting.
- A `HEAD` request or a `304 Not Modified` response: always free, never
  counted, regardless of `max_downloads`.
- A parallel download manager fetching several ranges *without* reusing the
  session token: only the request(s) that push past the probe threshold (or
  cover the whole file) count; once the file's `max_downloads` cap is
  reached, further requests are denied with `410 Gone` rather than being
  served and separately counted.

**Recommendation**: resumable download clients should always capture and
resend `X-Download-Session` (SafeShare's own web UI already does this) so a
paused/resumed download reliably counts once. See ADR-014 for the full
threshold/budget design and the SafeShare SDKs for reference client behavior.

### Rate Limiting

Range requests are subject to the same rate limits as regular downloads:
- `RATE_LIMIT_DOWNLOAD` applies per IP (default: 50 requests/hour)
- Encrypted-content downloads (SFSE or legacy) are additionally bounded by the decrypt-memory admission budget and a small per-IP concurrency limit — see "Encrypted-Download Admission Control" above.

## Limitations

### Not Supported

- **Multi-range requests**: `Range: bytes=0-100,200-300` (returns full file with 200 OK, not a multipart/byteranges response)
- **Content-Encoding with Range**: Gzip/compression not used with Range responses

### File Size Limits

- Maximum file size: Controlled by `MAX_FILE_SIZE` config (default: 100MB, configurable up to 8GB)
- Legacy-format encrypted files larger than `LEGACY_DECRYPT_MAX_BYTES` (default 128MB) cannot be downloaded until re-encrypted with `migrate-encryption`
- SFSE-format (streaming) encrypted files have no such limit

## Troubleshooting

### Range Requests Not Working

**Check headers**:
```bash
curl -I "http://localhost:8080/api/claim/ABC123"
```

**Expected**:
```
HTTP/1.1 200 OK
Accept-Ranges: bytes
Cache-Control: private, no-store
ETag: "..."
```

If `Accept-Ranges` is missing, the file may not support Range requests (rare).

### Download Counts Increasing Rapidly

**Cause**: A download manager or client using multiple parallel connections
*without* reusing the `X-Download-Session` token — each range that pushes
past the free-probe threshold on its own is treated as a separate download
attempt.

**Solution**:
- Use a client that captures and resends `X-Download-Session` (SafeShare's
  own web UI does this automatically)
- Increase `max_downloads` when uploading
- Or use `max_downloads: null` for unlimited downloads

### Resume Not Working

**Possible Causes**:
1. **File expired**: Check `expires_at` timestamp
2. **Download limit reached**: Check `download_count` vs `max_downloads`
3. **Reverse proxy timeout**: Check proxy configuration

**Verify**:
```bash
curl "http://localhost:8080/api/claim/ABC123/info" | jq .
```

### "Server Busy" (503, `SERVER_BUSY`) on Encrypted Downloads

**Cause**: `DOWNLOAD_DECRYPT_MEMORY_BUDGET` is exhausted by other concurrent encrypted downloads and this request couldn't reach the front of the admission queue within a few seconds.

**Solution**: retry after the `Retry-After` header's delay; if this happens routinely under normal load, raise `DOWNLOAD_DECRYPT_MEMORY_BUDGET`.

### "Too Many Concurrent Downloads" (429, `TOO_MANY_INFLIGHT`) on Encrypted Downloads

**Cause**: either the per-IP concurrent-encrypted-download limit (`MAX_ENCRYPTED_DOWNLOADS_PER_IP`) was hit — a single client has too many SFSE/legacy claim downloads in flight at once, across every file — or that client's share of `DOWNLOAD_DECRYPT_MEMORY_BUDGET` (a quarter of it) is already fully committed to another concurrent download of theirs.

**Solution**: retry after the `Retry-After` header's delay, or reduce the number of parallel encrypted downloads the client opens at once. If this happens routinely for legitimate traffic — most commonly behind a proxy where many real visitors share one apparent address, such as a Tor hidden service — raise or disable `MAX_ENCRYPTED_DOWNLOADS_PER_IP` (see `docs/TOR_DEPLOYMENT.md`). The per-client budget share is not separately configurable.

## Configuration

Range support and conditional requests are enabled automatically for all downloads; no configuration is required for the basic feature.

### Relevant Settings

| Setting | Default | Impact on Range Requests |
|---------|---------|---------------------------|
| `ENCRYPTION_KEY` | (unset) | Enables streaming encrypted format (SFSE) for new uploads |
| `MAX_FILE_SIZE` | 100MB | Maximum size for Range-capable files |
| `RATE_LIMIT_DOWNLOAD` | 50/hour | Applies to each Range request, per IP |
| `LEGACY_DECRYPT_MAX_BYTES` | 128MB | Max size of a legacy-format encrypted file the server will decrypt into memory |
| `DOWNLOAD_DECRYPT_MEMORY_BUDGET` | 256MB | Process-wide ceiling on concurrent encrypted-download decrypt memory |
| `MAX_ENCRYPTED_DOWNLOADS_PER_IP` | 8 | Max concurrent encrypted downloads per client; `0` disables. Raise/disable behind a proxy where visitors share one apparent address (Tor, etc.) |

## Logging

Every claim download (full or partial, GET or HEAD) logs a single `"claim download served"` line at INFO level with the resolved range kind, bytes sent, status code, whether it counted toward `max_downloads`, and any stream error encountered:

```json
{
  "level": "INFO",
  "msg": "claim download served",
  "claim_code": "ABC...123",
  "filename": "file.bin",
  "method": "GET",
  "status": 206,
  "range_kind": "partial",
  "bytes_sent": 1048576,
  "whole_file": false,
  "commitable": false,
  "error": null,
  "client_ip": "192.168.1.100"
}
```

A mid-stream decrypt/integrity failure (a chunk failing to authenticate, or a whole-file hash mismatch discovered on the last chunk of a multi-chunk file) additionally logs a dedicated `ERROR`-level line and increments `DownloadsTotal{status="integrity_failed"}` — distinct from an ordinary client disconnect mid-stream, which logs at `WARN` and isn't counted:

```json
{
  "level": "ERROR",
  "msg": "SFSE decrypt/integrity failure after headers were sent",
  "claim_code": "ABC...123",
  "error": "SFSE2 integrity check failed: SHA-256 mismatch",
  "bytes_sent": 10485760
}
```

**Invalid (unsatisfiable) Range (416)**:
```json
{
  "level": "WARN",
  "msg": "range not satisfiable",
  "claim_code": "ABC...123",
  "range_header": "bytes=999999999-",
  "file_size": 10485760
}
```

## References

- [RFC 9110 - HTTP Semantics (Range, Conditional Requests)](https://www.rfc-editor.org/rfc/rfc9110)
- [MDN - HTTP Range Requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests)
- [SafeShare Encryption Documentation](./ENCRYPTION.md)
- ADR-017 (`SafeShare-Planning/06-Architecture-Decisions/ADR-017-serve-content-downloads.md`) — full design rationale
