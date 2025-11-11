# HTTP Range Request Support

SafeShare implements RFC 7233-compliant HTTP Range request support, enabling resumable downloads and partial content delivery for large files.

## Overview

HTTP Range requests allow clients to request specific byte ranges of a file instead of downloading the entire file at once. This enables:

- **Resumable Downloads**: If a download is interrupted, it can be resumed from where it stopped
- **Partial Content Delivery**: Download only specific portions of a file
- **Parallel Downloads**: Some download managers can request multiple ranges in parallel
- **Streaming Optimization**: Media players can seek to specific positions without downloading the entire file

## Features

### Supported Range Formats

SafeShare supports all RFC 7233 range formats:

| Format | Description | Example |
|--------|-------------|---------|
| `bytes=start-end` | Specific byte range | `bytes=0-1048575` (first 1MB) |
| `bytes=start-` | From offset to end | `bytes=1048576-` (skip first 1MB) |
| `bytes=-suffix` | Last N bytes | `bytes=-1048576` (last 1MB) |

### HTTP Status Codes

| Status Code | Description | When Returned |
|-------------|-------------|---------------|
| **200 OK** | Full file | No Range header present |
| **206 Partial Content** | Byte range | Valid Range header |
| **416 Range Not Satisfiable** | Invalid range | Start >= file size, or start > end |

### Response Headers

**All responses** (both 200 and 206):
- `Accept-Ranges: bytes` - Advertises Range support
- `Content-Type` - Original file MIME type
- `Content-Disposition` - Attachment with sanitized filename

**206 Partial Content responses**:
- `Content-Range: bytes start-end/total` - Indicates range being served
- `Content-Length` - Size of the range (end - start + 1)

**416 Range Not Satisfiable responses**:
- `Content-Range: bytes */total` - Indicates available file size

## Implementation Details

### Architecture

SafeShare handles Range requests differently based on file encryption status:

#### Unencrypted Files
- Direct byte-range serving from disk
- Efficient seeking with minimal memory usage

#### Legacy Encrypted Files (AES-256-GCM, all-at-once)
- File decrypted into memory
- Requested range extracted from decrypted data
- Less efficient for large files, but maintains backward compatibility

#### Streaming Encrypted Files (SFSE1 format)
- **Optimized chunked decryption**: Only decrypts the chunks needed for the requested range
- Calculates which 64MB chunks contain the range
- Decrypts only those chunks
- Extracts the exact bytes requested
- **Highly efficient** for large files - doesn't process unnecessary data

### Key Components

| File | Purpose |
|------|---------|
| `internal/utils/range.go` | Range header parsing and validation |
| `internal/handlers/claim_range.go` | Range-aware file serving logic |
| `internal/utils/encryption.go` | `DecryptFileStreamingRange()` function |
| `internal/handlers/claim.go` | Integration point |

### Performance

**Unencrypted Files**:
- Near-instant response for any range
- Minimal memory usage (streams directly)

**Streaming Encrypted Files (SFSE1)**:
- Only processes chunks within the requested range
- For a 1MB range in a 10GB file: Processes ~1-2 chunks (64-128MB) instead of entire 10GB
- Memory usage: ~64-128MB regardless of file size

**Legacy Encrypted Files**:
- Must decrypt entire file to memory first
- Performance degrades for files >1GB
- Recommended to re-upload large files to use SFSE1 format

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
Content-Range: bytes 0-1048575/10485760
Content-Length: 1048576
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

# Start > end
curl -v -r 5000-1000 "http://localhost:8080/api/claim/$CLAIM_CODE"
# Expected: HTTP/1.1 416 Range Not Satisfiable
```

## Backward Compatibility

- **100% backward compatible**: Clients without Range support still work
- No Range header = HTTP 200 OK with full file (existing behavior)
- All existing download links continue to work unchanged
- Claim codes, expiration, download limits, password protection all work identically

## Security Considerations

### No Authentication Bypass

- Range requests respect all existing security controls:
  - Claim code validation
  - Password protection
  - Download limits (each range request counts as a download)
  - Expiration enforcement

### Download Counting

**Important**: Each HTTP request (including range requests) increments the download counter. This means:

- Full download (no Range): 1 download counted
- Resume (2 range requests): 2 downloads counted
- Parallel download manager (10 ranges): 10 downloads counted

**Recommendation**: For files with strict download limits, inform users that resume/parallel downloads may consume multiple download credits.

### Rate Limiting

Range requests are subject to the same rate limits as regular downloads:
- `RATE_LIMIT_DOWNLOAD` applies per IP (default: 100 requests/hour)

## Limitations

### Not Supported

- **Multi-range requests**: `Range: bytes=0-100,200-300` (returns full file with 200 OK)
- **If-Range conditional requests**: Not implemented (always processes Range header)
- **Content-Encoding with Range**: Gzip/compression not used with Range responses

### File Size Limits

- Maximum file size: Controlled by `MAX_FILE_SIZE` config (default: 100MB, configurable up to 8GB)
- For files >1GB with legacy encryption: Performance may degrade
- Recommendation: Files >1GB should use streaming encryption (SFSE1 format)

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
```

If `Accept-Ranges` is missing, the file may not support Range requests (rare).

### Download Counts Increasing Rapidly

**Cause**: Download manager using multiple parallel connections

**Solution**:
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

## Configuration

No additional configuration required. Range support is enabled automatically for all downloads.

### Relevant Settings

| Setting | Impact on Range Requests |
|---------|--------------------------|
| `ENCRYPTION_KEY` | Enables streaming encrypted format (SFSE1) for new uploads |
| `MAX_FILE_SIZE` | Maximum size for Range-capable files |
| `RATE_LIMIT_DOWNLOAD` | Applies to each Range request |

## Logging

Range requests are logged with additional context:

**Full Download (200 OK)**:
```json
{
  "level": "INFO",
  "msg": "file downloaded (full)",
  "claim_code": "ABC...123",
  "filename": "file.bin",
  "size": 10485760,
  "client_ip": "192.168.1.100"
}
```

**Partial Download (206)**:
```json
{
  "level": "INFO",
  "msg": "file downloaded (partial)",
  "claim_code": "ABC...123",
  "filename": "file.bin",
  "range_start": 0,
  "range_end": 1048575,
  "bytes_sent": 1048576,
  "client_ip": "192.168.1.100"
}
```

**Invalid Range (416)**:
```json
{
  "level": "WARN",
  "msg": "invalid range request",
  "claim_code": "ABC...123",
  "range_header": "bytes=999999999-",
  "file_size": 10485760,
  "error": "range not satisfiable: start position 999999999 >= file size 10485760"
}
```

## References

- [RFC 7233 - Range Requests](https://tools.ietf.org/html/rfc7233)
- [MDN - HTTP Range Requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests)
- [SafeShare Encryption Documentation](./ENCRYPTION.md)
