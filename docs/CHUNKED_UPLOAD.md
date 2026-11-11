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
| `PARTIAL_UPLOAD_EXPIRY_HOURS` | `24` | Hours before abandoned uploads are cleaned up |
| `READ_TIMEOUT` | `120` | HTTP read timeout in seconds for ordinary requests. Also the minimum deadline for chunk uploads and downloads |
| `WRITE_TIMEOUT` | `120` | HTTP write timeout in seconds for ordinary requests. Also the minimum deadline for chunk uploads and downloads |

`CHUNK_SIZE` is retired. The server picks the chunk size for each upload from the file size: 5 MiB for files under 100 MiB, 10 MiB under 1 GiB, and 20 MiB above that. If `CHUNK_SIZE` is still set, the server starts normally, ignores it, and logs a warning. You can remove it.
| `ASSEMBLY_WORKERS_MAX` | `10` | Max concurrent assembly workers (SH-1.4); `/complete` returns `503 ASSEMBLY_BUSY` beyond this |
| `ASSEMBLY_LEASE_TTL` | `2m` | How long an assembly worker's lease is valid before it must renew (heartbeat) or be eligible for takeover by recovery (ADR-016). Bounds: 30s–30m. |
| `ASSEMBLY_MAX_ATTEMPTS` | `5` | Max times a single chunked upload will be (re)attempted — via retry after a transient failure, or takeover after a crashed/stalled worker — before it's marked terminally failed with `ASSEMBLY_RETRIES_EXHAUSTED` (ADR-016). Bounds: 1–20. |
| `ASSEMBLY_SHUTDOWN_GRACE` | `30s` | How long graceful shutdown waits for in-progress assembly workers to finish (or yield their lease) before asking them to abandon their current step (ADR-016). Bounds: 5s–5m. |

### Chunk Size and Timeouts for Large Files or Slow Networks

You don't need to tune chunk size or timeouts for large files or slow networks.

- **Chunk size is automatic.** The server picks it per upload from the file size (5 MiB under 100 MiB, 10 MiB under 1 GiB, 20 MiB above) and returns it as `chunk_size` in the `/api/upload/init` response. Clients must split the file by that value.
- **Each chunk request gets its own deadline** based on its size, assuming at least 64 KiB/s plus 60 seconds, capped at 6 hours. `READ_TIMEOUT` and `WRITE_TIMEOUT` act only as a minimum for this deadline and as the limit for ordinary requests.
- **A stalled upload is still cut off.** A request body that sends nothing for 60 seconds, or averages under 4 KiB/s, is rejected with `408 UPLOAD_TIMEOUT`.

**Reverse proxy:** The proxy in front of SafeShare must accept request bodies at least as large as one chunk (20 MiB) and let each chunk request run for as long as SafeShare allows it: about 6 minutes for a 20 MiB chunk at the 64 KiB/s floor. Downloads and single-request uploads of large files can run up to 6 hours, so give those routes the longer timeout. Examples:
- **nginx**: `client_max_body_size 100m;`, `proxy_read_timeout 6h;` and `proxy_send_timeout 6h;`
- **Apache**: `LimitRequestBody 104857600` and `ProxyTimeout 21600`
- **Traefik**: `respondingTimeouts.readTimeout=0` (no limit) on the entrypoint

See `docs/REVERSE_PROXY.md` for full configurations.

**Example production config for large files (up to 8GB):**
```bash
docker run -d --name safeshare -p 8080:8080 \
  -e MAX_FILE_SIZE=8589934592 \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  safeshare:latest
```

## API Endpoints

### POST /api/upload/init

Initialize a chunked upload session.

**Request:**
```json
{
  "filename": "large-file.zip",
  "total_size": 26214400000,
  "expires_in_hours": 24,
  "max_downloads": 5,
  "password": "optional"
}
```

The server chooses the chunk size. A `chunk_size` in the request is ignored.

**Response:**
```json
{
  "upload_id": "550e8400-e29b-41d4-a716-446655440000",
  "chunk_size": 20971520,
  "total_chunks": 1250,
  "expires_at": "2025-11-07T12:00:00Z"
}
```

Split the file by the `chunk_size` in this response. Every chunk except the last must be exactly that size. The last chunk holds the remainder.

**Validation:**
- `total_size` <= `MAX_FILE_SIZE`
- `total_chunks` (calculated from the chosen chunk size) <= 10,000
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

Finalize upload and assemble chunks. Assembly runs asynchronously off the request path (a background worker), guarded by a fenced lease (see [Assembly State Machine (ADR-016)](#assembly-state-machine-adr-016) below) so at most one attempt can ever finish a given upload.

**Response (202 Accepted — assembly started/still running):**
```json
{
  "status": "processing",
  "upload_id": "550e8400-...",
  "message": "File is being assembled. Please poll /api/upload/status/550e8400-... for completion."
}
```

**Response (200 OK — already completed):**
```json
{
  "claim_code": "aFYR83-afRPqrb-8",
  "download_url": "https://share.example.com/api/claim/aFYR83-afRPqrb-8",
  "original_filename": "large-file.zip",
  "file_size": 5368709120,
  "expires_at": "2025-11-07T12:00:00Z",
  "max_downloads": 0,
  "completed_downloads": 0
}
```

**Response (400 — Missing Chunks):**
```json
{
  "error": "Missing 4 chunks",
  "code": "MISSING_CHUNKS",
  "missing_chunks": [0, 15, 27, 103]
}
```

**Response (409 — terminal failure, not retryable, or attempt budget exhausted):**
```json
{
  "error": "Upload could not be verified and was rejected",
  "code": "INTEGRITY_ERROR"
}
```

**Assembly process** (runs in the background after a `202`):
1. Verifies all chunks present (0 to total_chunks-1) and their integrity
2. Checks disk space for the final file
3. Scans the assembled content synchronously (ADR-015), before any encryption/storage
4. Creates the final file using buffered streaming I/O
5. Encrypts if `ENCRYPTION_KEY` is set
6. Generates a claim code and inserts the `files` row, atomically with marking the upload `completed` (ADR-016)
7. Deletes chunks and (eventually) the partial upload record

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
  "status": "processing",
  "retryable": false,
  "attempts": 1,
  "expires_at": "2025-11-07T12:00:00Z"
}
```

`status` is one of `uploading`, `processing`, `completed`, `failed`. When `status` is `failed`, `retryable` indicates whether POSTing `/api/upload/complete/:upload_id` again will retry assembly (see below), and `attempts` is how many assembly attempts have been made so far (capped at `ASSEMBLY_MAX_ATTEMPTS`).

## Assembly State Machine (ADR-016)

Every chunked upload moves through `uploading → processing → completed` or `uploading → processing → failed`, but `processing` and `failed` are not dead ends: assembly is fenced with a lease (owner token + TTL), so a failed-but-retryable upload, or one whose worker crashed/stalled, can be recovered without losing the already-uploaded chunks. See [ADR-016](../../SafeShare-Planning/06-Architecture-Decisions/ADR-016-assembly-state-machine.md) for the full design and rationale.

**`POST /complete` behavior by current state:**

| Current state | Response | Notes |
|---|---|---|
| `completed`, has claim code | `200` with claim code | Idempotent — safe to call repeatedly |
| `completed`, no claim code | `500 INTERNAL_ERROR` | Should be unreachable; publish sets both atomically |
| `processing`, lease live | `202` | Another attempt (or this one) is actively working |
| `processing`, lease expired | `202` | An inline takeover attempt is made first, so an actively-polling client doesn't wait for the next recovery sweep |
| `failed`, retryable, attempts < max | Reopens and retries assembly, then `202` | Chunks are re-verified; missing ones must be re-uploaded first (`400 MISSING_CHUNKS`) |
| `failed`, not retryable or attempts exhausted | `409` with `code` = the failure's `error_code` | Not retryable — a fresh `/api/upload/init` is required |

**Error codes** (`error_code` on `/status`, `code` on a `409` from `/complete`):

| Code | Retryable | Meaning |
|---|---|---|
| `SCAN_UNAVAILABLE` | Yes | Malware scanner unreachable after retries |
| `ASSEMBLY_FAILED` | Yes | A transient IO/DB/encryption/claim-code error |
| `MALWARE_DETECTED` | No | The scanned content matched a malware signature |
| `INTEGRITY_ERROR` | No | Assembled content didn't match what was scanned (TOCTOU), or a size mismatch — re-upload from scratch |
| `ASSEMBLY_RETRIES_EXHAUSTED` | No | `ASSEMBLY_MAX_ATTEMPTS` reached without success |

The official Go, TypeScript, and Python SDKs, and the bundled web client, automatically retry a `retryable: true` failure (POSTing `/complete` again) a bounded number of times while polling `/status`, before reporting a terminal error.

## Usage Examples

### curl Example

```bash
# 1. Initialize upload (15MB file; the server chooses the chunk size)
RESPONSE=$(curl -s -X POST http://localhost:8080/api/upload/init \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "test-file.dat",
    "total_size": 15728640,
    "expires_in_hours": 24,
    "max_downloads": 5
  }')

UPLOAD_ID=$(echo $RESPONSE | jq -r '.upload_id')
CHUNK_SIZE=$(echo $RESPONSE | jq -r '.chunk_size')   # 5242880 for a 15MB file
echo "Upload ID: $UPLOAD_ID, chunk size: $CHUNK_SIZE"

# 2. Create test chunks (3 chunks of 5MB, matching chunk_size above)
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
- Rate limiting per client IP (per hour, based on `RATE_LIMIT_UPLOAD`): `/init` at the upload limit, `/chunk` at enough chunks for that many `MAX_FILE_SIZE` uploads plus a quarter and 10 more for retries (never under 10× the upload limit), `/complete` at 10× it, and `/status` at 600× it (6,000/hour by default - well above the ~1,800/hour a client polling every 2 seconds sends)
- A request body that stops arriving for 60 seconds, or averages under 4 KiB/s, is cut off with `408 UPLOAD_TIMEOUT` rather than held open until the full transfer deadline
- Validates:
  - upload_id (UUID format)
  - chunk_number (in range)
  - chunk_size (matches expected)
  - File extensions (blocked extensions)
  - Disk space before accepting chunks
- Quota tracking includes partial uploads: `/init` reserves the upload's full size against `QUOTA_LIMIT_GB` (507 `QUOTA_EXCEEDED` if it doesn't fit). The reservation is held while the upload makes progress; once it has stored no new chunk for an hour, it counts only the bytes received so far, so an upload that's started and abandoned can't keep the quota tied up until cleanup. Its next new chunk (or `/complete`) re-reserves the rest, or gets 507 `QUOTA_EXCEEDED` if the quota has filled in the meantime (the web client stops and reports the error). A client so slow that a single chunk takes over an hour can hit this mid-upload when the quota is nearly full. Re-sending an already-stored chunk doesn't renew the reservation.
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

## Complete End-to-End Examples

This section provides complete, production-ready code examples for implementing chunked uploads in various languages and frameworks.

### JavaScript/Browser Example

```javascript
/**
 * ChunkedUploader - Production-ready chunked file uploader
 * Supports: progress tracking, pause/resume, retry logic, parallel uploads
 */
class ChunkedUploader {
  constructor(baseUrl, options = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.concurrency = options.concurrency || 3;
    this.retries = options.retries || 3;
    this.retryDelay = options.retryDelay || 1000;
    this.apiToken = options.apiToken;
    this.onProgress = options.onProgress || (() => {});
    this.onError = options.onError || (() => {});
    this.onComplete = options.onComplete || (() => {});
    
    this.uploadId = null;
    this.totalChunks = 0;
    this.chunksUploaded = new Set();
    this.isPaused = false;
    this.isCancelled = false;
    this.activeUploads = 0;
  }

  async upload(file, options = {}) {
    const { expiresInHours = 24, maxDownloads = 0, password = null } = options;

    // Initialize upload. The server chooses the chunk size.
    const initResponse = await this.initUpload(file, expiresInHours, maxDownloads, password);
    this.uploadId = initResponse.upload_id;
    this.totalChunks = initResponse.total_chunks;
    this.chunkSize = initResponse.chunk_size;

    // Persist for resume capability
    this.saveProgress(file.name);

    // Upload chunks with concurrency control, split by the server's chunk_size
    const chunks = this.createChunks(file, this.chunkSize);
    await this.uploadChunksWithConcurrency(chunks);

    if (this.isCancelled) {
      return null;
    }

    // Complete upload
    const result = await this.completeUpload();
    this.clearProgress(file.name);
    this.onComplete(result);
    return result;
  }

  async initUpload(file, expiresInHours, maxDownloads, password) {
    const body = {
      filename: file.name,
      total_size: file.size,
      expires_in_hours: expiresInHours,
      max_downloads: maxDownloads,
    };
    if (password) body.password = password;

    const response = await fetch(`${this.baseUrl}/api/upload/init`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(this.apiToken && { 'Authorization': `Bearer ${this.apiToken}` }),
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to initialize upload');
    }

    return response.json();
  }

  createChunks(file, chunkSize) {
    const chunks = [];
    let offset = 0;
    let index = 0;

    while (offset < file.size) {
      const end = Math.min(offset + chunkSize, file.size);
      chunks.push({
        index,
        blob: file.slice(offset, end),
        size: end - offset,
      });
      offset = end;
      index++;
    }

    return chunks;
  }

  async uploadChunksWithConcurrency(chunks) {
    const pending = chunks.filter(c => !this.chunksUploaded.has(c.index));
    const queue = [...pending];

    const uploadNext = async () => {
      while (queue.length > 0 && !this.isCancelled) {
        if (this.isPaused) {
          await this.waitForResume();
        }

        const chunk = queue.shift();
        if (!chunk || this.chunksUploaded.has(chunk.index)) continue;

        this.activeUploads++;
        try {
          await this.uploadChunkWithRetry(chunk);
          this.chunksUploaded.add(chunk.index);
          this.reportProgress();
          this.saveProgress();
        } catch (error) {
          this.onError({ chunk: chunk.index, error });
          queue.push(chunk); // Re-queue failed chunk
        } finally {
          this.activeUploads--;
        }
      }
    };

    // Start concurrent workers
    const workers = Array(this.concurrency).fill(null).map(() => uploadNext());
    await Promise.all(workers);
  }

  async uploadChunkWithRetry(chunk, attempt = 0) {
    try {
      const formData = new FormData();
      formData.append('chunk', chunk.blob);

      const response = await fetch(
        `${this.baseUrl}/api/upload/chunk/${this.uploadId}/${chunk.index}`,
        {
          method: 'POST',
          headers: this.apiToken ? { 'Authorization': `Bearer ${this.apiToken}` } : {},
          body: formData,
        }
      );

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || `Chunk ${chunk.index} failed`);
      }

      return response.json();
    } catch (error) {
      if (attempt < this.retries) {
        const delay = this.retryDelay * Math.pow(2, attempt);
        await new Promise(resolve => setTimeout(resolve, delay));
        return this.uploadChunkWithRetry(chunk, attempt + 1);
      }
      throw error;
    }
  }

  async completeUpload() {
    const response = await fetch(
      `${this.baseUrl}/api/upload/complete/${this.uploadId}`,
      {
        method: 'POST',
        headers: this.apiToken ? { 'Authorization': `Bearer ${this.apiToken}` } : {},
      }
    );

    if (!response.ok) {
      const error = await response.json();
      if (error.missing_chunks) {
        throw new Error(`Missing chunks: ${error.missing_chunks.join(', ')}`);
      }
      throw new Error(error.error || 'Failed to complete upload');
    }

    return response.json();
  }

  reportProgress() {
    const percentage = Math.round((this.chunksUploaded.size / this.totalChunks) * 100);
    this.onProgress({
      percentage,
      chunksUploaded: this.chunksUploaded.size,
      totalChunks: this.totalChunks,
      uploadId: this.uploadId,
    });
  }

  pause() {
    this.isPaused = true;
  }

  resume() {
    this.isPaused = false;
    if (this.resumeResolve) {
      this.resumeResolve();
      this.resumeResolve = null;
    }
  }

  cancel() {
    this.isCancelled = true;
    this.resume(); // Unblock any paused uploads
  }

  waitForResume() {
    return new Promise(resolve => {
      this.resumeResolve = resolve;
    });
  }

  saveProgress(filename) {
    const key = `chunked_upload_${filename || 'current'}`;
    localStorage.setItem(key, JSON.stringify({
      uploadId: this.uploadId,
      totalChunks: this.totalChunks,
      chunksUploaded: Array.from(this.chunksUploaded),
      timestamp: Date.now(),
    }));
  }

  loadProgress(filename) {
    const key = `chunked_upload_${filename}`;
    const data = localStorage.getItem(key);
    if (!data) return null;

    const parsed = JSON.parse(data);
    // Check if upload is still valid (not expired)
    if (Date.now() - parsed.timestamp > 23 * 60 * 60 * 1000) {
      localStorage.removeItem(key);
      return null;
    }

    return parsed;
  }

  clearProgress(filename) {
    const key = `chunked_upload_${filename || 'current'}`;
    localStorage.removeItem(key);
  }

  // Resume a previously started upload
  async resumeUpload(file, savedProgress) {
    this.uploadId = savedProgress.uploadId;
    this.totalChunks = savedProgress.totalChunks;
    this.chunksUploaded = new Set(savedProgress.chunksUploaded);

    // Verify upload still exists on server and read its chunk size
    let status;
    try {
      const response = await fetch(
        `${this.baseUrl}/api/upload/status/${this.uploadId}`,
        { headers: this.apiToken ? { 'Authorization': `Bearer ${this.apiToken}` } : {} }
      );
      if (!response.ok) {
        throw new Error('Upload expired');
      }
      status = await response.json();
    } catch {
      // Upload expired, start fresh
      this.clearProgress(file.name);
      return this.upload(file);
    }

    // Split by the chunk_size the server chose for this upload
    this.chunkSize = status.chunk_size;
    const chunks = this.createChunks(file, this.chunkSize);

    await this.uploadChunksWithConcurrency(chunks);

    if (this.isCancelled) return null;

    const result = await this.completeUpload();
    this.clearProgress(file.name);
    this.onComplete(result);
    return result;
  }
}

// Usage Example
/*
const uploader = new ChunkedUploader('https://share.example.com', {
  apiToken: 'safeshare_abc123...',
  concurrency: 3,
  onProgress: (progress) => {
    console.log(`${progress.percentage}% - ${progress.chunksUploaded}/${progress.totalChunks}`);
    document.getElementById('progress').style.width = `${progress.percentage}%`;
  },
  onError: (error) => {
    console.error(`Chunk ${error.chunk} failed:`, error.error);
  },
  onComplete: (result) => {
    console.log('Upload complete!', result.claim_code);
  },
});

// Check for resumable upload
const savedProgress = uploader.loadProgress(file.name);
if (savedProgress) {
  await uploader.resumeUpload(file, savedProgress);
} else {
  await uploader.upload(file, { expiresInHours: 24 });
}

// Pause/Resume controls
document.getElementById('pause').onclick = () => uploader.pause();
document.getElementById('resume').onclick = () => uploader.resume();
document.getElementById('cancel').onclick = () => uploader.cancel();
*/
```

### Python End-to-End Example

```python
#!/usr/bin/env python3
"""
Chunked upload implementation for SafeShare
Supports: progress, retry, resume, parallel uploads
"""

import os
import json
import hashlib
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Callable
from dataclasses import dataclass


@dataclass
class UploadProgress:
    percentage: int
    chunks_uploaded: int
    total_chunks: int
    bytes_uploaded: int
    total_bytes: int


class ChunkedUploader:
    def __init__(
        self,
        base_url: str,
        api_token: Optional[str] = None,
        concurrency: int = 3,
        max_retries: int = 3,
        on_progress: Optional[Callable[[UploadProgress], None]] = None,
    ):
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.concurrency = concurrency
        self.max_retries = max_retries
        self.on_progress = on_progress
        self.session = requests.Session()
        
        if api_token:
            self.session.headers['Authorization'] = f'Bearer {api_token}'

    def upload(
        self,
        file_path: str,
        expires_in_hours: int = 24,
        max_downloads: int = 0,
        password: Optional[str] = None,
    ) -> dict:
        """Upload a file using chunked upload protocol."""
        file_path = Path(file_path)
        file_size = file_path.stat().st_size
        filename = file_path.name

        # Initialize upload. The server chooses the chunk size.
        init_data = self._init_upload(
            filename, file_size,
            expires_in_hours, max_downloads, password
        )
        upload_id = init_data['upload_id']
        total_chunks = init_data['total_chunks']
        chunk_size = init_data['chunk_size']

        # Create chunk list, split by the server's chunk_size
        chunks = self._create_chunks(file_path, chunk_size)
        chunks_uploaded = set()

        # Upload chunks with concurrency
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {
                executor.submit(
                    self._upload_chunk_with_retry,
                    upload_id, chunk_num, chunk_data
                ): chunk_num
                for chunk_num, chunk_data in chunks
            }

            for future in as_completed(futures):
                chunk_num = futures[future]
                try:
                    future.result()
                    chunks_uploaded.add(chunk_num)
                    
                    if self.on_progress:
                        bytes_uploaded = sum(
                            len(c[1]) for c in chunks if c[0] in chunks_uploaded
                        )
                        self.on_progress(UploadProgress(
                            percentage=int(len(chunks_uploaded) / total_chunks * 100),
                            chunks_uploaded=len(chunks_uploaded),
                            total_chunks=total_chunks,
                            bytes_uploaded=bytes_uploaded,
                            total_bytes=file_size,
                        ))
                except Exception as e:
                    raise RuntimeError(f"Chunk {chunk_num} failed: {e}")

        # Complete upload
        result = self._complete_upload(upload_id)
        return result

    def _init_upload(
        self,
        filename: str,
        total_size: int,
        expires_in_hours: int,
        max_downloads: int,
        password: Optional[str],
    ) -> dict:
        data = {
            'filename': filename,
            'total_size': total_size,
            'expires_in_hours': expires_in_hours,
            'max_downloads': max_downloads,
        }
        if password:
            data['password'] = password

        resp = self.session.post(
            f"{self.base_url}/api/upload/init",
            json=data,
        )
        resp.raise_for_status()
        return resp.json()

    def _create_chunks(self, file_path: Path, chunk_size: int):
        """Generator yielding (chunk_number, chunk_data) tuples."""
        chunks = []
        with open(file_path, 'rb') as f:
            chunk_num = 0
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                chunks.append((chunk_num, data))
                chunk_num += 1
        return chunks

    def _upload_chunk_with_retry(self, upload_id: str, chunk_num: int, data: bytes) -> dict:
        for attempt in range(self.max_retries):
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/upload/chunk/{upload_id}/{chunk_num}",
                    files={'chunk': ('chunk', data)},
                    timeout=120,
                )
                resp.raise_for_status()
                return resp.json()
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise
                import time
                time.sleep(2 ** attempt)  # Exponential backoff

    def _complete_upload(self, upload_id: str) -> dict:
        resp = self.session.post(f"{self.base_url}/api/upload/complete/{upload_id}")
        resp.raise_for_status()
        return resp.json()


# Usage example
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python chunked_upload.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    base_url = os.environ.get('SAFESHARE_URL', 'http://localhost:8080')
    api_token = os.environ.get('SAFESHARE_TOKEN')

    def progress_callback(progress: UploadProgress):
        bar_width = 40
        filled = int(bar_width * progress.percentage / 100)
        bar = '█' * filled + '░' * (bar_width - filled)
        print(
            f"\r[{bar}] {progress.percentage}% "
            f"({progress.chunks_uploaded}/{progress.total_chunks} chunks)",
            end='', flush=True
        )

    uploader = ChunkedUploader(
        base_url=base_url,
        api_token=api_token,
        concurrency=3,
        on_progress=progress_callback,
    )

    try:
        result = uploader.upload(file_path, expires_in_hours=24)
        print(f"\n\nUpload complete!")
        print(f"Claim code: {result['claim_code']}")
        print(f"Download URL: {base_url}/claim/{result['claim_code']}")
    except Exception as e:
        print(f"\nUpload failed: {e}")
        sys.exit(1)
```

### Go End-to-End Example

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type ChunkedUploader struct {
	BaseURL     string
	APIToken    string
	Concurrency int
	MaxRetries  int
	OnProgress  func(UploadProgress)
	Client      *http.Client
}

type UploadProgress struct {
	Percentage     int
	ChunksUploaded int
	TotalChunks    int
	BytesUploaded  int64
	TotalBytes     int64
}

type InitResponse struct {
	UploadID    string `json:"upload_id"`
	ChunkSize   int64  `json:"chunk_size"`
	TotalChunks int    `json:"total_chunks"`
	ExpiresAt   string `json:"expires_at"`
}

type CompleteResponse struct {
	ClaimCode   string `json:"claim_code"`
	DownloadURL string `json:"download_url"`
}

func NewChunkedUploader(baseURL, apiToken string) *ChunkedUploader {
	return &ChunkedUploader{
		BaseURL:     baseURL,
		APIToken:    apiToken,
		Concurrency: 3,
		MaxRetries:  3,
		Client: &http.Client{
			Timeout: 2 * time.Minute,
		},
	}
}

func (u *ChunkedUploader) Upload(filePath string, expiresInHours int) (*CompleteResponse, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	totalSize := stat.Size()
	filename := filepath.Base(filePath)

	// Initialize upload. The server chooses the chunk size.
	initResp, err := u.initUpload(filename, totalSize, expiresInHours)
	if err != nil {
		return nil, fmt.Errorf("init upload: %w", err)
	}

	// Upload chunks with concurrency, split by the server's chunk_size
	err = u.uploadChunks(file, initResp.UploadID, initResp.TotalChunks, initResp.ChunkSize, totalSize)
	if err != nil {
		return nil, fmt.Errorf("upload chunks: %w", err)
	}

	// Complete upload
	result, err := u.completeUpload(initResp.UploadID)
	if err != nil {
		return nil, fmt.Errorf("complete upload: %w", err)
	}

	return result, nil
}

func (u *ChunkedUploader) initUpload(filename string, totalSize int64, expiresInHours int) (*InitResponse, error) {
	body := map[string]interface{}{
		"filename":         filename,
		"total_size":       totalSize,
		"expires_in_hours": expiresInHours,
		"max_downloads":    0,
	}

	jsonBody, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", u.BaseURL+"/api/upload/init", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	if u.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+u.APIToken)
	}

	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("init failed: %s", body)
	}

	var initResp InitResponse
	if err := json.NewDecoder(resp.Body).Decode(&initResp); err != nil {
		return nil, err
	}
	return &initResp, nil
}

func (u *ChunkedUploader) uploadChunks(file *os.File, uploadID string, totalChunks int, chunkSize, totalSize int64) error {
	sem := make(chan struct{}, u.Concurrency)
	var wg sync.WaitGroup
	var uploadErr error
	var errOnce sync.Once
	var chunksUploaded int32

	for i := 0; i < totalChunks; i++ {
		wg.Add(1)
		go func(chunkNum int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Read chunk
			offset := int64(chunkNum) * chunkSize
			size := chunkSize
			if offset+size > totalSize {
				size = totalSize - offset
			}

			chunkData := make([]byte, size)
			_, err := file.ReadAt(chunkData, offset)
			if err != nil && err != io.EOF {
				errOnce.Do(func() { uploadErr = err })
				return
			}

			// Upload with retry
			if err := u.uploadChunkWithRetry(uploadID, chunkNum, chunkData); err != nil {
				errOnce.Do(func() { uploadErr = err })
				return
			}

			uploaded := atomic.AddInt32(&chunksUploaded, 1)
			if u.OnProgress != nil {
				u.OnProgress(UploadProgress{
					Percentage:     int(float64(uploaded) / float64(totalChunks) * 100),
					ChunksUploaded: int(uploaded),
					TotalChunks:    totalChunks,
					BytesUploaded:  int64(uploaded) * chunkSize,
					TotalBytes:     totalSize,
				})
			}
		}(i)
	}

	wg.Wait()
	return uploadErr
}

func (u *ChunkedUploader) uploadChunkWithRetry(uploadID string, chunkNum int, data []byte) error {
	var lastErr error
	for attempt := 0; attempt < u.MaxRetries; attempt++ {
		err := u.uploadChunk(uploadID, chunkNum, data)
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(1<<attempt) * time.Second)
	}
	return lastErr
}

func (u *ChunkedUploader) uploadChunk(uploadID string, chunkNum int, data []byte) error {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("chunk", "chunk")
	part.Write(data)
	writer.Close()

	url := fmt.Sprintf("%s/api/upload/chunk/%s/%d", u.BaseURL, uploadID, chunkNum)
	req, _ := http.NewRequest("POST", url, &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if u.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+u.APIToken)
	}

	resp, err := u.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("chunk %d failed: %s", chunkNum, body)
	}
	return nil
}

func (u *ChunkedUploader) completeUpload(uploadID string) (*CompleteResponse, error) {
	url := fmt.Sprintf("%s/api/upload/complete/%s", u.BaseURL, uploadID)
	req, _ := http.NewRequest("POST", url, nil)
	if u.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+u.APIToken)
	}

	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("complete failed: %s", body)
	}

	var result CompleteResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Usage example
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run chunked_upload.go <file_path>")
		os.Exit(1)
	}

	uploader := NewChunkedUploader(
		os.Getenv("SAFESHARE_URL"),
		os.Getenv("SAFESHARE_TOKEN"),
	)
	uploader.OnProgress = func(p UploadProgress) {
		fmt.Printf("\r[%3d%%] %d/%d chunks", p.Percentage, p.ChunksUploaded, p.TotalChunks)
	}

	result, err := uploader.Upload(os.Args[1], 24)
	if err != nil {
		fmt.Printf("\nUpload failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n\nUpload complete!\n")
	fmt.Printf("Claim code: %s\n", result.ClaimCode)
	fmt.Printf("Download URL: %s\n", result.DownloadURL)
}
```

### Bash/Shell Script Example

```bash
#!/bin/bash
# Chunked upload script for SafeShare
# Usage: ./chunked_upload.sh <file_path> [expires_in_hours]

set -e

FILE_PATH="$1"
EXPIRES_IN_HOURS="${2:-24}"
BASE_URL="${SAFESHARE_URL:-http://localhost:8080}"
API_TOKEN="${SAFESHARE_TOKEN}"

if [ -z "$FILE_PATH" ]; then
    echo "Usage: $0 <file_path> [expires_in_hours]"
    exit 1
fi

if [ ! -f "$FILE_PATH" ]; then
    echo "Error: File not found: $FILE_PATH"
    exit 1
fi

# Get file info
FILENAME=$(basename "$FILE_PATH")
FILE_SIZE=$(stat -f%z "$FILE_PATH" 2>/dev/null || stat -c%s "$FILE_PATH" 2>/dev/null)

echo "File: $FILENAME ($FILE_SIZE bytes)"

# Initialize upload. The server chooses the chunk size and returns it.
echo "Initializing upload..."

INIT_RESPONSE=$(curl -s -X POST "$BASE_URL/api/upload/init" \
    -H "Content-Type: application/json" \
    ${API_TOKEN:+-H "Authorization: Bearer $API_TOKEN"} \
    -d "{
        \"filename\": \"$FILENAME\",
        \"total_size\": $FILE_SIZE,
        \"expires_in_hours\": $EXPIRES_IN_HOURS,
        \"max_downloads\": 0
    }")

UPLOAD_ID=$(echo "$INIT_RESPONSE" | jq -r '.upload_id')
TOTAL_CHUNKS=$(echo "$INIT_RESPONSE" | jq -r '.total_chunks')
CHUNK_SIZE=$(echo "$INIT_RESPONSE" | jq -r '.chunk_size')

if [ "$UPLOAD_ID" = "null" ] || [ -z "$UPLOAD_ID" ]; then
    echo "Error: Failed to initialize upload"
    echo "$INIT_RESPONSE"
    exit 1
fi

echo "Upload ID: $UPLOAD_ID"
echo "Total chunks: $TOTAL_CHUNKS"
echo "Chunk size: $CHUNK_SIZE bytes"

# Create temporary directory for chunks
CHUNK_DIR=$(mktemp -d)
trap 'rm -rf "$CHUNK_DIR"' EXIT

# Split file into chunks
echo "Splitting file into chunks..."
split -b "$CHUNK_SIZE" "$FILE_PATH" "$CHUNK_DIR/chunk_"

# Upload chunks with progress
echo "Uploading chunks..."

upload_chunk() {
    local chunk_file=$1
    local chunk_num=$2
    
    for attempt in 1 2 3; do
        result=$(curl -s -w "\n%{http_code}" -X POST \
            "$BASE_URL/api/upload/chunk/$UPLOAD_ID/$chunk_num" \
            ${API_TOKEN:+-H "Authorization: Bearer $API_TOKEN"} \
            -F "chunk=@$chunk_file")
        
        http_code=$(echo "$result" | tail -n1)
        
        if [ "$http_code" = "200" ]; then
            return 0
        fi
        
        echo "Chunk $chunk_num: attempt $attempt failed (HTTP $http_code), retrying..."
        sleep $((2 ** attempt))
    done
    
    return 1
}

# Upload chunks (sequential for shell script simplicity)
chunk_num=0
for chunk_file in "$CHUNK_DIR"/chunk_*; do
    upload_chunk "$chunk_file" $chunk_num
    
    # Show progress
    percent=$((chunk_num * 100 / TOTAL_CHUNKS))
    printf "\rProgress: [%-50s] %d%% (%d/%d)" \
        "$(printf '%*s' $((percent / 2)) '' | tr ' ' '#')" \
        $percent $chunk_num $TOTAL_CHUNKS
    
    chunk_num=$((chunk_num + 1))
done

echo
echo "Completing upload..."

# Complete upload
COMPLETE_RESPONSE=$(curl -s -X POST \
    "$BASE_URL/api/upload/complete/$UPLOAD_ID" \
    ${API_TOKEN:+-H "Authorization: Bearer $API_TOKEN"})

CLAIM_CODE=$(echo "$COMPLETE_RESPONSE" | jq -r '.claim_code')

if [ "$CLAIM_CODE" = "null" ] || [ -z "$CLAIM_CODE" ]; then
    echo "Error: Failed to complete upload"
    echo "$COMPLETE_RESPONSE"
    exit 1
fi

echo
echo "========================================"
echo "Upload complete!"
echo "Claim code: $CLAIM_CODE"
echo "Download URL: $BASE_URL/claim/$CLAIM_CODE"
echo "========================================"
```

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
| `UPLOAD_TIMEOUT` | 408 | The chunk's body stopped arriving (no data for 60 seconds, or under 4 KiB/s on average); retry the chunk |
| `INSUFFICIENT_STORAGE` | 507 | Not enough disk space to store the chunk |
| `CHUNK_SIZE_MISMATCH` | 400 | Chunk size doesn't match the `chunk_size` returned by `/init` (the last chunk must be the exact remainder) |
| `UPLOAD_NOT_ACCEPTING` | 409 | Upload is being assembled (or assembly failed); chunks can no longer be written |
| `CHUNK_CONFLICT` | 409 | Chunk was already uploaded with different content |
| `MISSING_CHUNKS` | 400 | `/complete` called before all chunks arrived (`missing_chunks` lists them) |
| `TOO_MANY_CHUNKS` | 400 | More than 10,000 chunks |
| `FILE_TOO_LARGE` | 413 | Exceeds MAX_FILE_SIZE |
| `QUOTA_EXCEEDED` | 507 | Storage quota exceeded |
| `INSUFFICIENT_STORAGE` | 507 | Not enough disk space |
| `UNSCANNABLE_UPLOAD` | 422 | (`POST /api/upload/init`, ADR-015) File cannot be scanned (E2E encrypted or exceeds the scan size limit) and this server requires scannable uploads |

### Assembly failure (`status: "failed"`)

When `FEATURE_MALWARE_SCAN=true`, chunk assembly (`GET /api/upload/status/:upload_id`) now includes a synchronous malware scan of the reassembled content before encryption/storage (ADR-015). A failed assembly's `error_code` field gives the machine-readable reason, in addition to the human-readable `error_message`; `retryable` says whether re-submitting `/complete` will retry assembly (see [Assembly State Machine (ADR-016)](#assembly-state-machine-adr-016)):

| `error_code` | `retryable` | Meaning |
|---|---|---|
| `MALWARE_DETECTED` | No | The file was scanned and found infected. No claim code is ever issued. |
| `SCAN_UNAVAILABLE` | Yes | The malware scanner could not be reached after 3 retries (5s/15s/45s backoff). Re-submit `/complete` once the scanner recovers, or set `MALWARE_SCAN_ALLOW_UNVERIFIED=true` to proceed unverified instead of failing. |
| `INTEGRITY_ERROR` | No | The assembled content didn't match what was scanned (TOCTOU), or its size changed underneath it. Start a fresh upload. |
| `ASSEMBLY_RETRIES_EXHAUSTED` | No | The upload was retried (or recovered after a crash) `ASSEMBLY_MAX_ATTEMPTS` times without success. |
| `ASSEMBLY_FAILED` | Yes | A transient IO/DB/encryption/claim-code error. |

`error_code` may be absent (`null`/omitted) for legacy rows predating ADR-016, in which case treat the failure as not retryable.

The official SDKs and the bundled web client automatically retry a `retryable: true` failure a bounded number of times before reporting it to the caller/UI as terminal.

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
1. **Reverse proxy body size limit** - nginx/Apache/Traefik rejects the chunk before it reaches SafeShare
2. **Reverse proxy timeout** - the proxy gives up on a slow chunk
3. **Client not splitting by `chunk_size`** - a chunk larger than the `chunk_size` from `/init` is rejected

**Solutions:**

**1. Split by the `chunk_size` from `/init`.** The server picks 5, 10 or 20 MiB depending on file size. Don't use a fixed size or the value from `/api/config`.

**2. Configure the reverse proxy** (if applicable). It must accept bodies of at least 20 MiB, let a chunk request run for several minutes, and let downloads and single-request uploads run for up to 6 hours:
```nginx
# nginx
client_max_body_size 100m;
proxy_read_timeout 6h;
proxy_send_timeout 6h;
```

You don't need to raise `READ_TIMEOUT` or `WRITE_TIMEOUT` for large chunks. SafeShare gives each chunk request a deadline based on its size.

### ERR_CONNECTION_RESET or ERR_EMPTY_RESPONSE

**Symptoms:**
- Browser shows "connection reset" errors
- Some chunks upload successfully, then failures start

**Cause:** Usually a reverse proxy or load balancer closing the connection before the chunk finishes. SafeShare itself allows at least 64 KiB/s plus 60 seconds per chunk request, capped at 6 hours.

**Solution:** Raise the proxy's read, send and idle timeouts (see above). If the connection stalls completely (no data for 60 seconds), SafeShare returns `408 UPLOAD_TIMEOUT`; retry the chunk.

### Upload Initialization Succeeds but All Chunks Fail

**Symptoms:**
- `/api/upload/init` returns success with upload_id
- All chunk uploads fail with 413 or timeouts

**Cause:** Almost always the reverse proxy: its body size limit or timeout is lower than one chunk needs.

**Solution:** Check the proxy limits above. Test with a direct request to SafeShare (bypassing the proxy) to confirm.

### Checking Your Upload Speed

```bash
# Test actual upload speed to your server
time curl -X POST -F "file=@10mb-test.file" http://your-server:8080/api/upload
```
SafeShare needs no timeout changes for any speed above 64 KiB/s. Slower than that, large chunks may exceed their deadline.

### Production Deployment Checklist

Before deploying for large file uploads (>1GB), verify:

- [ ] `MAX_FILE_SIZE` set to desired limit (bytes)
- [ ] `CHUNK_SIZE` removed from your config (it is ignored)
- [ ] Reverse proxy (if used) allows request bodies of at least 20 MiB, chunk requests of several minutes, and downloads and single-request uploads of up to 6 hours
- [ ] Test upload with target file size from slowest expected network
- [ ] Monitor server logs for 413/timeout errors during testing
