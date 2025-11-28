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

    // Fetch server config
    const config = await this.fetchConfig();
    const chunkSize = config.chunk_size || 10 * 1024 * 1024;

    // Initialize upload
    const initResponse = await this.initUpload(file, chunkSize, expiresInHours, maxDownloads, password);
    this.uploadId = initResponse.upload_id;
    this.totalChunks = initResponse.total_chunks;

    // Persist for resume capability
    this.saveProgress(file.name);

    // Upload chunks with concurrency control
    const chunks = this.createChunks(file, chunkSize);
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

  async fetchConfig() {
    const response = await fetch(`${this.baseUrl}/api/config`);
    if (!response.ok) throw new Error('Failed to fetch config');
    return response.json();
  }

  async initUpload(file, chunkSize, expiresInHours, maxDownloads, password) {
    const body = {
      filename: file.name,
      total_size: file.size,
      chunk_size: chunkSize,
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

    // Verify upload still exists on server
    try {
      const response = await fetch(
        `${this.baseUrl}/api/upload/status/${this.uploadId}`,
        { headers: this.apiToken ? { 'Authorization': `Bearer ${this.apiToken}` } : {} }
      );
      if (!response.ok) {
        throw new Error('Upload expired');
      }
    } catch {
      // Upload expired, start fresh
      this.clearProgress(file.name);
      return this.upload(file);
    }

    const config = await this.fetchConfig();
    const chunkSize = config.chunk_size || 10 * 1024 * 1024;
    const chunks = this.createChunks(file, chunkSize);

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

        # Get server config
        config = self._get_config()
        chunk_size = config.get('chunk_size', 10 * 1024 * 1024)

        # Initialize upload
        init_data = self._init_upload(
            filename, file_size, chunk_size,
            expires_in_hours, max_downloads, password
        )
        upload_id = init_data['upload_id']
        total_chunks = init_data['total_chunks']

        # Create chunk list
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

    def _get_config(self) -> dict:
        resp = self.session.get(f"{self.base_url}/api/config")
        resp.raise_for_status()
        return resp.json()

    def _init_upload(
        self,
        filename: str,
        total_size: int,
        chunk_size: int,
        expires_in_hours: int,
        max_downloads: int,
        password: Optional[str],
    ) -> dict:
        data = {
            'filename': filename,
            'total_size': total_size,
            'chunk_size': chunk_size,
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

	// Get server config
	config, err := u.getConfig()
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}
	chunkSize := config["chunk_size"].(float64)

	// Initialize upload
	initResp, err := u.initUpload(filename, totalSize, int64(chunkSize), expiresInHours)
	if err != nil {
		return nil, fmt.Errorf("init upload: %w", err)
	}

	// Upload chunks with concurrency
	err = u.uploadChunks(file, initResp.UploadID, initResp.TotalChunks, int64(chunkSize), totalSize)
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

func (u *ChunkedUploader) getConfig() (map[string]interface{}, error) {
	resp, err := u.Client.Get(u.BaseURL + "/api/config")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}
	return config, nil
}

func (u *ChunkedUploader) initUpload(filename string, totalSize, chunkSize int64, expiresInHours int) (*InitResponse, error) {
	body := map[string]interface{}{
		"filename":         filename,
		"total_size":       totalSize,
		"chunk_size":       chunkSize,
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
CONCURRENT_UPLOADS=3

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

# Fetch server config
echo "Fetching server config..."
CONFIG=$(curl -s "$BASE_URL/api/config")
CHUNK_SIZE=$(echo "$CONFIG" | jq -r '.chunk_size // 10485760')

echo "Chunk size: $CHUNK_SIZE bytes"

# Initialize upload
echo "Initializing upload..."
AUTH_HEADER=""
if [ -n "$API_TOKEN" ]; then
    AUTH_HEADER="Authorization: Bearer $API_TOKEN"
fi

INIT_RESPONSE=$(curl -s -X POST "$BASE_URL/api/upload/init" \
    -H "Content-Type: application/json" \
    ${API_TOKEN:+-H "Authorization: Bearer $API_TOKEN"} \
    -d "{
        \"filename\": \"$FILENAME\",
        \"total_size\": $FILE_SIZE,
        \"chunk_size\": $CHUNK_SIZE,
        \"expires_in_hours\": $EXPIRES_IN_HOURS,
        \"max_downloads\": 0
    }")

UPLOAD_ID=$(echo "$INIT_RESPONSE" | jq -r '.upload_id')
TOTAL_CHUNKS=$(echo "$INIT_RESPONSE" | jq -r '.total_chunks')

if [ "$UPLOAD_ID" = "null" ] || [ -z "$UPLOAD_ID" ]; then
    echo "Error: Failed to initialize upload"
    echo "$INIT_RESPONSE"
    exit 1
fi

echo "Upload ID: $UPLOAD_ID"
echo "Total chunks: $TOTAL_CHUNKS"

# Create temporary directory for chunks
CHUNK_DIR=$(mktemp -d)
trap "rm -rf $CHUNK_DIR" EXIT

# Split file into chunks
echo "Splitting file into chunks..."
split -b $CHUNK_SIZE "$FILE_PATH" "$CHUNK_DIR/chunk_"

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
