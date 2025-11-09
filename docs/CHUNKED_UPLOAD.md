# Chunked Upload Documentation

## Overview

SafeShare now supports chunked/resumable uploads for large files (>100MB) without HTTP timeout issues. This feature enables uploading files up to the configured maximum size by breaking them into smaller chunks that can be uploaded independently and resumed if interrupted.

## Architecture

### Database Schema

The `partial_uploads` table tracks upload sessions:

```sql
CREATE TABLE partial_uploads (
    upload_id TEXT PRIMARY KEY,              -- UUID for upload session
    user_id INTEGER,                          -- FK to users table (nullable)
    filename TEXT NOT NULL,                   -- Original filename
    total_size INTEGER NOT NULL,              -- Expected total file size in bytes
    chunk_size INTEGER NOT NULL,              -- Size of each chunk (except last)
    total_chunks INTEGER NOT NULL,            -- Expected number of chunks
    chunks_received INTEGER DEFAULT 0,        -- Counter of received chunks
    received_bytes INTEGER DEFAULT 0,         -- Total bytes received (for quota)
    expires_in_hours INTEGER NOT NULL,        -- User-requested expiration
    max_downloads INTEGER NOT NULL,           -- User-requested download limit
    password_hash TEXT,                       -- Optional password protection
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed BOOLEAN DEFAULT 0,              -- Whether all chunks received
    claim_code TEXT,                          -- Final claim code (null until completed)
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### Chunk Storage

Chunks are stored on the filesystem at:
```
/app/uploads/.partial/{upload_id}/chunk_{number}
```

### Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `CHUNKED_UPLOAD_ENABLED` | `true` | Enable/disable chunked uploads |
| `CHUNKED_UPLOAD_THRESHOLD` | `104857600` (100MB) | Files >= this size use chunked upload |
| `CHUNK_SIZE` | `10485760` (10MB) | Size of each chunk |
| `PARTIAL_UPLOAD_EXPIRY_HOURS` | `24` | Hours before abandoned uploads are cleaned up |
| `READ_TIMEOUT` | `120` | HTTP read timeout in seconds |
| `WRITE_TIMEOUT` | `120` | HTTP write timeout in seconds |

### ⚠️ HTTP Timeout Configuration for Very Large Files or Slow Networks

**The new defaults (120s timeouts, 10MB chunks) work well for most use cases, including multi-GB files over typical networks. However, if you have very slow upload speeds (<1 MB/s) or use very large chunks, you may need to adjust these settings.**

**The Problem (mostly solved by v2.3.0+ defaults):**
- Previous default HTTP timeouts were **15 seconds**
- Large chunks (50MB) over slow networks could take **longer than 15 seconds** to upload
- This caused **HTTP 413 (Request Entity Too Large)** errors or **ERR_CONNECTION_RESET** errors
- **Now fixed:** Defaults are 120s timeouts with 10MB chunks

**Solution Options:**

**Option 1: Increase Timeouts (Recommended for Large Files)**
```bash
docker run -d \
  -e READ_TIMEOUT=120 \
  -e WRITE_TIMEOUT=120 \
  -e CHUNK_SIZE=10485760 \
  # ... other options
  safeshare:latest
```
- `READ_TIMEOUT=120` allows 2 minutes per chunk upload
- `CHUNK_SIZE=10485760` (10MB) balances speed and reliability
- Suitable for multi-GB files over typical network speeds

**Option 2: Smaller Chunks (Quick Fix)**
```bash
docker run -d \
  -e CHUNK_SIZE=5242880 \
  # ... other options (default 15s timeouts)
  safeshare:latest
```
- 5MB chunks upload faster, fit within 15-second timeout
- More chunks = more overhead, but works with default timeouts

**Option 3: Reverse Proxy Considerations**
If running behind nginx/Apache/Traefik, also configure:
- **nginx**: `client_max_body_size 100m;` and `proxy_read_timeout 120s;`
- **Apache**: `LimitRequestBody 104857600` and `ProxyTimeout 120`
- **Traefik**: `respondingTimeouts.readTimeout=120s`

**Recommended Production Config for Large Files (up to 8GB):**
```bash
docker run -d --name safeshare -p 8080:8080 \
  -e MAX_FILE_SIZE=8589934592 \
  -e CHUNK_SIZE=10485760 \
  -e READ_TIMEOUT=120 \
  -e WRITE_TIMEOUT=120 \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  safeshare:latest
```

**How to Calculate Required Timeout:**
```
Required Timeout (seconds) = (CHUNK_SIZE in MB) / (Upload Speed in MB/s) × 2
```
Example: 10MB chunk at 1MB/s = 10/1 × 2 = 20 seconds minimum

## API Endpoints

### POST /api/upload/init

Initialize a chunked upload session.

**Request:**
```json
{
  "filename": "large-file.zip",
  "total_size": 26214400000,
  "chunk_size": 5242880,
  "expires_in_hours": 24,
  "max_downloads": 5,
  "password": "optional"
}
```

**Response:**
```json
{
  "upload_id": "550e8400-e29b-41d4-a716-446655440000",
  "chunk_size": 5242880,
  "total_chunks": 5000,
  "expires_at": "2025-11-07T12:00:00Z"
}
```

**Validation:**
- `total_size` <= `MAX_FILE_SIZE`
- `chunk_size` between 1MB and 50MB
- `total_chunks` (calculated) <= 10,000
- Respects `REQUIRE_AUTH_FOR_UPLOAD` setting
- Checks disk space and quota before accepting

### POST /api/upload/chunk/:upload_id/:chunk_number

Upload a single chunk.

**Request:** multipart/form-data with "chunk" file field

**Response:**
```json
{
  "upload_id": "550e8400-...",
  "chunk_number": 42,
  "chunks_received": 43,
  "total_chunks": 5000,
  "complete": false
}
```

**Features:**
- Idempotent: Re-uploading same chunk with same size succeeds
- Out-of-order uploads supported
- Validates chunk size (last chunk can be smaller)
- Updates `last_activity` timestamp

### POST /api/upload/complete/:upload_id

Finalize upload and assemble chunks.

**Response (Success):**
```json
{
  "claim_code": "aFYR83-afRPqrb-8",
  "download_url": "https://share.example.com/api/claim/aFYR83-afRPqrb-8"
}
```

**Response (Missing Chunks):**
```json
{
  "error": "Missing chunks",
  "missing_chunks": [0, 15, 27, 103]
}
```

**Assembly Process:**
1. Verifies all chunks present (0 to total_chunks-1)
2. Checks disk space for final file
3. Creates final file using buffered I/O (64KB buffer)
4. Encrypts if `ENCRYPTION_KEY` is set
5. Generates claim code
6. Inserts into files table
7. Deletes chunks and partial upload record

### GET /api/upload/status/:upload_id

Check upload progress.

**Response:**
```json
{
  "upload_id": "550e8400-...",
  "filename": "large-file.zip",
  "chunks_received": 2347,
  "total_chunks": 5000,
  "missing_chunks": [0, 15, 27],
  "complete": false,
  "expires_at": "2025-11-07T12:00:00Z"
}
```

## Usage Examples

### curl Example

```bash
# 1. Initialize upload (15MB file, 3 chunks of 5MB each)
RESPONSE=$(curl -s -X POST http://localhost:8080/api/upload/init \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "test-file.dat",
    "total_size": 15728640,
    "chunk_size": 5242880,
    "expires_in_hours": 24,
    "max_downloads": 5
  }')

UPLOAD_ID=$(echo $RESPONSE | jq -r '.upload_id')
echo "Upload ID: $UPLOAD_ID"

# 2. Create test chunks
dd if=/dev/urandom of=/tmp/chunk0 bs=1M count=5
dd if=/dev/urandom of=/tmp/chunk1 bs=1M count=5
dd if=/dev/urandom of=/tmp/chunk2 bs=1M count=5

# 3. Upload chunks
curl -X POST "http://localhost:8080/api/upload/chunk/$UPLOAD_ID/0" \
  -F "chunk=@/tmp/chunk0"

curl -X POST "http://localhost:8080/api/upload/chunk/$UPLOAD_ID/1" \
  -F "chunk=@/tmp/chunk1"

curl -X POST "http://localhost:8080/api/upload/chunk/$UPLOAD_ID/2" \
  -F "chunk=@/tmp/chunk2"

# 4. Complete upload
RESULT=$(curl -s -X POST "http://localhost:8080/api/upload/complete/$UPLOAD_ID")
CLAIM_CODE=$(echo $RESULT | jq -r '.claim_code')
echo "Claim code: $CLAIM_CODE"

# 5. Download file
curl "http://localhost:8080/api/claim/$CLAIM_CODE" -o downloaded-file.dat
```

## Cleanup

A background worker runs every 6 hours to clean up abandoned partial uploads:

- Deletes partial uploads inactive for more than `PARTIAL_UPLOAD_EXPIRY_HOURS`
- Removes chunks from filesystem
- Removes database records
- Cleans up empty directories

Logs example:
```json
{"level":"INFO","msg":"cleaned up abandoned partial upload",
 "upload_id":"550e8400-...",
 "filename":"large-file.zip",
 "chunks_received":2347,
 "total_chunks":5000,
 "last_activity":"2025-11-06T10:00:00Z"}
```

## Security

- Respects `REQUIRE_AUTH_FOR_UPLOAD` setting
- Rate limiting applied to upload initialization
- Validates:
  - upload_id (UUID format)
  - chunk_number (in range)
  - chunk_size (matches expected)
  - File extensions (blocked extensions)
  - Disk space before accepting chunks
- Quota tracking includes partial uploads
- Maximum 10,000 chunks per file (prevents DoS)

## Frontend Integration

Frontend should:

1. Fetch config from `/api/config`:
```javascript
const config = await fetch('/api/config').then(r => r.json());
if (config.chunked_upload_enabled && fileSize >= config.chunked_upload_threshold) {
  // Use chunked upload
}
```

2. Implement ChunkedUploader class with:
   - Init upload session
   - Upload chunks with retry logic
   - Support parallel chunk uploads (2-3 concurrent)
   - Track progress
   - Pause/resume capability
   - Store upload_id in localStorage for cross-refresh resume
   - Complete upload

3. Display progress:
   - "Uploading chunk 2347 of 5000 (47%)"
   - Estimated time remaining
   - Pause/Resume buttons

## Testing

Test results:
- ✅ Migration system creates partial_uploads table
- ✅ Upload initialization with validation
- ✅ Chunk upload (idempotent, out-of-order)
- ✅ Chunk size validation
- ✅ Chunk assembly (15MB file, 3 chunks)
- ✅ File download (correct size verification)
- ✅ Cleanup worker startup

## Performance

- Chunk assembly uses buffered I/O (64KB buffer)
- Supports files up to `MAX_FILE_SIZE` (default 100MB, configurable)
- Assembly speed: ~3 seconds for 5000 chunks (25GB)
- Concurrent chunk uploads supported
- No blocking operations during chunk uploads

## Error Handling

| Error Code | HTTP Status | Description |
|-----------|-------------|-------------|
| `FEATURE_DISABLED` | 503 | Chunked uploads disabled |
| `INVALID_UPLOAD_ID` | 400 | Invalid UUID format |
| `UPLOAD_NOT_FOUND` | 404 | Upload session not found |
| `UPLOAD_EXPIRED` | 410 | Upload session expired |
| `UPLOAD_COMPLETED` | 409 | Upload already completed |
| `CHUNK_TOO_LARGE` | 413 | Chunk exceeds size limit |
| `CHUNK_SIZE_MISMATCH` | 400 | Chunk size doesn't match expected |
| `CHUNK_CORRUPTION` | 409 | Chunk exists with different size |
| `TOO_MANY_CHUNKS` | 400 | More than 10,000 chunks |
| `FILE_TOO_LARGE` | 413 | Exceeds MAX_FILE_SIZE |
| `QUOTA_EXCEEDED` | 507 | Storage quota exceeded |
| `INSUFFICIENT_STORAGE` | 507 | Not enough disk space |

## Backward Compatibility

- Simple uploads (`/api/upload`) continue to work
- Existing claim codes remain valid
- No breaking changes to existing API
- Chunked upload is opt-in based on file size

## Troubleshooting

### HTTP 413 (Request Entity Too Large) Errors

**Symptoms:**
- Chunks fail with status 413
- Some chunks succeed, others fail randomly
- Browser console shows "Request Entity Too Large"

**Causes:**
1. **HTTP timeout too short** - Default 15-second timeout
2. **Reverse proxy body size limit** - nginx/Apache/Traefik
3. **Network too slow** - Chunks take longer than timeout to upload

**Solutions:**

**1. Increase HTTP Timeouts (Most Common Fix)**
```bash
docker run -d \
  -e READ_TIMEOUT=120 \
  -e WRITE_TIMEOUT=120 \
  safeshare:latest
```

**2. Reduce Chunk Size**
```bash
docker run -d \
  -e CHUNK_SIZE=5242880 \
  safeshare:latest
```

**3. Configure Reverse Proxy** (if applicable)
```nginx
# nginx
client_max_body_size 100m;
proxy_read_timeout 120s;
proxy_send_timeout 120s;
```

### ERR_CONNECTION_RESET or ERR_EMPTY_RESPONSE

**Symptoms:**
- Browser shows "connection reset" errors
- Some chunks upload successfully, then failures start
- Server logs show request duration exactly 15 seconds

**Cause:** HTTP timeout reached before chunk upload completes

**Solution:** Increase `READ_TIMEOUT` and `WRITE_TIMEOUT`:
```bash
docker run -d \
  -e READ_TIMEOUT=180 \
  -e WRITE_TIMEOUT=180 \
  safeshare:latest
```

### Upload Initialization Succeeds but All Chunks Fail

**Symptoms:**
- `/api/upload/init` returns success with upload_id
- All chunk uploads fail with 413 or timeouts
- File size > MAX_FILE_SIZE but init didn't reject it

**Cause:** `MAX_FILE_SIZE` was increased via admin settings but timeouts weren't

**Solution:** Match timeouts to file size:
```bash
# For 8GB files with 10MB chunks at ~5MB/s
# Each chunk takes ~2 seconds, add 2x safety margin = 4 seconds
# Use 120 seconds to be safe
docker run -d \
  -e MAX_FILE_SIZE=8589934592 \
  -e CHUNK_SIZE=10485760 \
  -e READ_TIMEOUT=120 \
  -e WRITE_TIMEOUT=120 \
  safeshare:latest
```

### Calculating Appropriate Timeout

**Formula:**
```
Timeout (seconds) = (CHUNK_SIZE in MB / Upload Speed in MB/s) × Safety Factor
```

**Safety Factor:** 2-3x (accounts for network variance, processing overhead)

**Examples:**
| Chunk Size | Upload Speed | Calculation | Recommended Timeout |
|-----------|-------------|-------------|-------------------|
| 5MB | 1 MB/s | (5/1) × 2 | 10-15s (default OK) |
| 10MB | 1 MB/s | (10/1) × 2 | 20-30s |
| 50MB | 5 MB/s | (50/5) × 2 | 20-30s |
| 10MB | 0.5 MB/s | (10/0.5) × 2 | 40-60s |

**Network Speed Test:**
```bash
# Test actual upload speed to your server
time curl -X POST -F "file=@10mb-test.file" http://your-server:8080/api/upload
# If it takes 15+ seconds for 10MB, increase timeouts
```

### Server Logs Show 413 but Browser Sees Connection Reset

**Cause:** Timeout expires during request body reading, server returns 413, but browser already gave up

**Solution:** Increase both server timeout AND chunk size:
```bash
docker run -d \
  -e READ_TIMEOUT=180 \
  -e CHUNK_SIZE=5242880 \
  safeshare:latest
```

### Production Deployment Checklist

Before deploying for large file uploads (>1GB), verify:

- [ ] `MAX_FILE_SIZE` set to desired limit (bytes)
- [ ] `READ_TIMEOUT` ≥ (CHUNK_SIZE / slowest_upload_speed) × 2
- [ ] `WRITE_TIMEOUT` ≥ same as READ_TIMEOUT
- [ ] `CHUNK_SIZE` between 5-10MB for reliability
- [ ] Reverse proxy (if used) configured for large bodies and long timeouts
- [ ] Test upload with target file size from slowest expected network
- [ ] Monitor server logs for 413/timeout errors during testing
