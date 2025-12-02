# SafeShare TypeScript/JavaScript SDK

Official TypeScript/JavaScript SDK for the [SafeShare](https://github.com/fjmerc/safeshare) file sharing service.

## Requirements

- Node.js 18.0.0 or later (uses native `fetch`)
- TypeScript 5.0+ (for TypeScript users)

## Installation

```bash
# From npm (when published)
npm install safeshare-sdk

# From local source
cd sdk/typescript
npm install
npm run build
```

## Quick Start

```typescript
import { SafeShareClient } from "safeshare-sdk";

// Create a client with API token authentication
const client = new SafeShareClient({
  baseUrl: "https://share.example.com",
  apiToken: "safeshare_abc123...", // Get from SafeShare web UI
});

// Upload a file
const result = await client.upload("./document.pdf", {
  expiresInHours: 24,
  downloadLimit: 10,
  onProgress: (progress) => {
    console.log(`Upload: ${progress.percentage}%`);
  },
});

console.log(`Share this link: ${client.baseUrl}/claim/${result.claimCode}`);

// Download a file
await client.download("abc12345", "./downloaded-file.pdf", {
  onProgress: (progress) => {
    console.log(`Download: ${progress.percentage}%`);
  },
});
```

## Features

- **File Upload** - Simple and chunked uploads with progress tracking
- **File Download** - Stream downloads with progress callbacks
- **File Management** - List, rename, delete, update expiration
- **API Token Management** - Create, list, and revoke API tokens
- **Strong Typing** - Full TypeScript support with comprehensive types
- **Error Handling** - Typed error classes for different error scenarios
- **Security** - Input validation, token redaction in logs

## API Reference

### Creating a Client

```typescript
import { SafeShareClient } from "safeshare-sdk";

const client = new SafeShareClient({
  baseUrl: "https://share.example.com", // Required: SafeShare server URL
  apiToken: "safeshare_...",            // Optional: API token for auth
  timeout: 300000,                       // Optional: Request timeout (default: 5 min)
});
```

### Uploading Files

#### Simple Upload

```typescript
const result = await client.upload("./myfile.txt", {
  expiresInHours: 24,        // Optional: Hours until expiration
  downloadLimit: 10,          // Optional: Max downloads allowed
  password: "secret123",      // Optional: Password protection
  onProgress: (progress) => { // Optional: Progress callback
    console.log(`${progress.percentage}%`);
  },
});

console.log(result.claimCode);  // Use this to download
console.log(result.filename);   // Original filename
console.log(result.size);       // File size in bytes
console.log(result.expiresAt);  // ISO 8601 expiration time
```

The SDK automatically uses chunked upload for large files based on server configuration.

#### Chunked Upload Progress

For large files, the progress callback includes chunk information:

```typescript
const result = await client.upload("./large-file.zip", {
  onProgress: (progress) => {
    console.log(`Chunk ${progress.currentChunk}/${progress.totalChunks}`);
    console.log(`Overall: ${progress.percentage}%`);
  },
});
```

### Downloading Files

#### Download to File

```typescript
const savedPath = await client.download("abc12345", "./output.pdf", {
  password: "secret123",      // Optional: If file is password-protected
  onProgress: (progress) => {
    console.log(`${progress.bytesDownloaded} / ${progress.totalBytes}`);
  },
});
```

#### Download to Buffer

```typescript
const buffer = await client.downloadToBuffer("abc12345", {
  password: "secret123",
});
// Use buffer directly
```

### Getting File Information

```typescript
const info = await client.getFileInfo("abc12345");

console.log(info.filename);           // Original filename
console.log(info.size);               // Size in bytes
console.log(info.mimeType);           // MIME type
console.log(info.expiresAt);          // Expiration time or null
console.log(info.passwordProtected);  // Boolean
console.log(info.downloadsRemaining); // Number or null (unlimited)
```

### Managing Your Files

These operations require authentication (API token).

#### List Files

```typescript
const response = await client.listFiles(1, 20); // page, perPage

for (const file of response.files) {
  console.log(`${file.filename} (${file.claimCode})`);
  console.log(`  Downloads: ${file.completedDownloads}/${file.downloadLimit || "∞"}`);
}

console.log(`Total: ${response.total}`);
```

#### Delete a File

```typescript
await client.deleteFile("abc12345");
```

#### Rename a File

```typescript
const updated = await client.renameFile("abc12345", "new-name.pdf");
console.log(updated.filename); // "new-name.pdf"
```

#### Update Expiration

```typescript
const updated = await client.updateExpiration("abc12345", {
  expiresInHours: 48, // null to remove expiration
});
console.log(updated.expiresAt);
```

#### Regenerate Claim Code

```typescript
const updated = await client.regenerateClaimCode("abc12345");
console.log(`New code: ${updated.claimCode}`);
```

### API Token Management

#### List Tokens

```typescript
const tokens = await client.listTokens();

for (const token of tokens) {
  console.log(`${token.name}: ${token.scopes.join(", ")}`);
  console.log(`  Last used: ${token.lastUsedAt || "Never"}`);
}
```

#### Create Token (requires session auth)

```typescript
const newToken = await client.createToken({
  name: "Automation Token",
  scopes: ["upload", "download", "manage"],
  expiresInDays: 90,
});

// Save this - it's only shown once!
console.log(`Token: ${newToken.token}`);
```

#### Revoke Token (requires session auth)

```typescript
await client.revokeToken(tokenId);
```

### Server Configuration

```typescript
const config = await client.getConfig();

console.log(`Max file size: ${config.maxFileSize}`);
console.log(`Chunk threshold: ${config.chunkUploadThreshold}`);
console.log(`Chunk size: ${config.chunkSize}`);
console.log(`Max expiration: ${config.maxExpirationHours} hours`);
```

## Error Handling

The SDK provides typed error classes for different error scenarios:

```typescript
import {
  SafeShareError,
  AuthenticationError,
  NotFoundError,
  ValidationError,
  RateLimitError,
  UploadError,
  DownloadError,
  PasswordRequiredError,
  DownloadLimitReachedError,
  FileTooLargeError,
  QuotaExceededError,
  ChunkedUploadError,
} from "safeshare-sdk";

try {
  await client.download("abc12345", "./output.pdf");
} catch (error) {
  if (error instanceof NotFoundError) {
    console.log("File not found or expired");
  } else if (error instanceof PasswordRequiredError) {
    console.log("Password is required");
  } else if (error instanceof DownloadLimitReachedError) {
    console.log("Download limit exceeded");
  } else if (error instanceof RateLimitError) {
    console.log(`Rate limited. Retry after ${error.retryAfter} seconds`);
  } else if (error instanceof SafeShareError) {
    console.log(`Error ${error.statusCode}: ${error.message}`);
  }
}
```

## TypeScript Types

All types are exported for use in your TypeScript projects:

```typescript
import type {
  UploadResult,
  UploadOptions,
  UploadProgress,
  FileInfo,
  UserFile,
  UserFilesResponse,
  DownloadOptions,
  DownloadProgress,
  PublicConfig,
  TokenInfo,
  CreateTokenRequest,
  TokenCreatedResponse,
} from "safeshare-sdk";
```

## Examples

See the `examples/` directory for complete working examples:

- `upload.ts` - Upload files with progress
- `download.ts` - Download files with progress
- `file-management.ts` - List, rename, delete files
- `token-management.ts` - API token operations

Run examples with:

```bash
npx tsx examples/upload.ts ./myfile.txt
npx tsx examples/download.ts abc12345 ./output.txt
```

## Environment Variables

The examples use these environment variables:

- `SAFESHARE_URL` - SafeShare server URL (default: `http://localhost:8080`)
- `SAFESHARE_TOKEN` - API token for authentication

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Type check
npm run typecheck

# Lint
npm run lint
```

## Security

- API tokens are redacted in `toString()` output to prevent accidental logging
- Input validation prevents path traversal and injection attacks
- Claim codes, upload IDs, and filenames are validated before use

## Advanced Usage

### React Integration

```tsx
import { useState, useCallback } from 'react';
import { SafeShareClient, UploadProgress } from 'safeshare-sdk';

const client = new SafeShareClient({
  baseUrl: process.env.REACT_APP_SAFESHARE_URL!,
  apiToken: process.env.REACT_APP_SAFESHARE_TOKEN,
});

function FileUploader() {
  const [progress, setProgress] = useState<number>(0);
  const [uploading, setUploading] = useState(false);
  const [shareLink, setShareLink] = useState<string | null>(null);

  const handleUpload = useCallback(async (file: File) => {
    setUploading(true);
    setProgress(0);

    try {
      // Convert File to path or use FormData approach
      const result = await client.upload(file.name, {
        expiresInHours: 24,
        onProgress: (p: UploadProgress) => setProgress(p.percentage),
      });

      setShareLink(`${client.baseUrl}/claim/${result.claimCode}`);
    } catch (error) {
      console.error('Upload failed:', error);
    } finally {
      setUploading(false);
    }
  }, []);

  return (
    <div>
      <input
        type="file"
        onChange={(e) => e.target.files?.[0] && handleUpload(e.target.files[0])}
        disabled={uploading}
      />
      {uploading && <progress value={progress} max={100} />}
      {shareLink && <a href={shareLink}>Share Link</a>}
    </div>
  );
}
```

### Vue.js Composable

```typescript
// composables/useSafeShare.ts
import { ref, computed } from 'vue';
import { SafeShareClient, UploadProgress, UploadResult } from 'safeshare-sdk';

export function useSafeShare(baseUrl: string, apiToken?: string) {
  const client = new SafeShareClient({ baseUrl, apiToken });

  const progress = ref(0);
  const isUploading = ref(false);
  const lastResult = ref<UploadResult | null>(null);
  const error = ref<Error | null>(null);

  const shareLink = computed(() =>
    lastResult.value ? `${baseUrl}/claim/${lastResult.value.claimCode}` : null
  );

  async function upload(filePath: string, options?: { expiresInHours?: number }) {
    isUploading.value = true;
    progress.value = 0;
    error.value = null;

    try {
      lastResult.value = await client.upload(filePath, {
        ...options,
        onProgress: (p: UploadProgress) => {
          progress.value = p.percentage;
        },
      });
      return lastResult.value;
    } catch (e) {
      error.value = e as Error;
      throw e;
    } finally {
      isUploading.value = false;
    }
  }

  return {
    progress,
    isUploading,
    lastResult,
    shareLink,
    error,
    upload,
    client,
  };
}
```

### Retry Logic with Exponential Backoff

```typescript
import { SafeShareClient, RateLimitError, SafeShareError } from 'safeshare-sdk';

interface RetryOptions {
  maxRetries?: number;
  baseDelay?: number;
  maxDelay?: number;
}

async function withRetry<T>(
  operation: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const { maxRetries = 3, baseDelay = 1000, maxDelay = 30000 } = options;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      if (attempt === maxRetries) throw error;

      let delay: number;

      if (error instanceof RateLimitError && error.retryAfter) {
        // Use server-provided retry-after
        delay = error.retryAfter * 1000;
      } else if (error instanceof SafeShareError && error.statusCode >= 500) {
        // Server error - retry with exponential backoff
        delay = Math.min(baseDelay * Math.pow(2, attempt), maxDelay);
      } else {
        // Client error - don't retry
        throw error;
      }

      console.log(`Attempt ${attempt + 1} failed, retrying in ${delay}ms...`);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  throw new Error('Unreachable');
}

// Usage
const client = new SafeShareClient({ baseUrl: 'https://share.example.com' });

const result = await withRetry(
  () => client.upload('./large-file.zip', { expiresInHours: 24 }),
  { maxRetries: 5, baseDelay: 2000 }
);
```

### Custom Fetch Implementation

```typescript
import { SafeShareClient } from 'safeshare-sdk';
import { HttpsProxyAgent } from 'https-proxy-agent';
import fetch, { RequestInit } from 'node-fetch';

// Custom fetch with proxy support
const proxyAgent = new HttpsProxyAgent('http://proxy.example.com:8080');

const customFetch = (url: string, init?: RequestInit) => {
  return fetch(url, {
    ...init,
    agent: proxyAgent,
  });
};

// Note: You may need to patch the client or use a custom wrapper
// depending on your specific proxy requirements
```

### Batch Operations

```typescript
import { SafeShareClient } from 'safeshare-sdk';

const client = new SafeShareClient({
  baseUrl: 'https://share.example.com',
  apiToken: 'safeshare_...',
});

async function batchUpload(
  files: string[],
  options: { expiresInHours?: number; concurrency?: number } = {}
) {
  const { concurrency = 3 } = options;
  const results: Array<{ file: string; claimCode?: string; error?: Error }> = [];

  // Process files in batches
  for (let i = 0; i < files.length; i += concurrency) {
    const batch = files.slice(i, i + concurrency);

    const batchResults = await Promise.allSettled(
      batch.map((file) =>
        client.upload(file, { expiresInHours: options.expiresInHours })
      )
    );

    batchResults.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        results.push({ file: batch[index], claimCode: result.value.claimCode });
      } else {
        results.push({ file: batch[index], error: result.reason });
      }
    });
  }

  return results;
}

// Upload 10 files, 3 at a time
const files = ['file1.pdf', 'file2.pdf', /* ... */ 'file10.pdf'];
const results = await batchUpload(files, { expiresInHours: 24, concurrency: 3 });

for (const result of results) {
  if (result.claimCode) {
    console.log(`${result.file}: ${result.claimCode}`);
  } else {
    console.error(`${result.file}: ${result.error?.message}`);
  }
}
```

### Express.js Middleware

```typescript
import express, { Request, Response, NextFunction } from 'express';
import { SafeShareClient } from 'safeshare-sdk';
import multer from 'multer';

const upload = multer({ dest: 'uploads/' });
const client = new SafeShareClient({
  baseUrl: process.env.SAFESHARE_URL!,
  apiToken: process.env.SAFESHARE_TOKEN!,
});

const app = express();

// Upload endpoint with SafeShare integration
app.post(
  '/api/share',
  upload.single('file'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No file provided' });
      }

      const result = await client.upload(req.file.path, {
        expiresInHours: parseInt(req.body.expires) || 24,
        password: req.body.password,
      });

      res.json({
        shareLink: `${client.baseUrl}/claim/${result.claimCode}`,
        claimCode: result.claimCode,
        expiresAt: result.expiresAt,
      });
    } catch (error) {
      next(error);
    }
  }
);
```

### Testing with Jest

```typescript
import { SafeShareClient, NotFoundError, UploadResult } from 'safeshare-sdk';

// Mock the client
jest.mock('safeshare-sdk', () => {
  return {
    SafeShareClient: jest.fn().mockImplementation(() => ({
      upload: jest.fn(),
      download: jest.fn(),
      getFileInfo: jest.fn(),
    })),
    NotFoundError: class extends Error {
      statusCode = 404;
    },
  };
});

describe('FileService', () => {
  let client: jest.Mocked<SafeShareClient>;

  beforeEach(() => {
    client = new SafeShareClient({ baseUrl: 'http://test' }) as jest.Mocked<SafeShareClient>;
  });

  it('should upload a file and return share link', async () => {
    const mockResult: UploadResult = {
      claimCode: 'abc12345',
      filename: 'test.txt',
      size: 1024,
      expiresAt: '2024-12-31T23:59:59Z',
    };

    (client.upload as jest.Mock).mockResolvedValue(mockResult);

    const result = await client.upload('./test.txt', { expiresInHours: 24 });

    expect(result.claimCode).toBe('abc12345');
    expect(client.upload).toHaveBeenCalledWith('./test.txt', { expiresInHours: 24 });
  });

  it('should handle file not found', async () => {
    (client.getFileInfo as jest.Mock).mockRejectedValue(
      new NotFoundError('File not found')
    );

    await expect(client.getFileInfo('invalid')).rejects.toThrow(NotFoundError);
  });
});
```

### Event Emitter Wrapper

```typescript
import { EventEmitter } from 'events';
import { SafeShareClient, UploadProgress, UploadResult } from 'safeshare-sdk';

class SafeShareEmitter extends EventEmitter {
  private client: SafeShareClient;

  constructor(options: { baseUrl: string; apiToken?: string }) {
    super();
    this.client = new SafeShareClient(options);
  }

  async upload(filePath: string, options?: { expiresInHours?: number }): Promise<UploadResult> {
    this.emit('upload:start', { filePath });

    try {
      const result = await this.client.upload(filePath, {
        ...options,
        onProgress: (progress: UploadProgress) => {
          this.emit('upload:progress', { filePath, progress });
        },
      });

      this.emit('upload:complete', { filePath, result });
      return result;
    } catch (error) {
      this.emit('upload:error', { filePath, error });
      throw error;
    }
  }
}

// Usage with event listeners
const emitter = new SafeShareEmitter({ baseUrl: 'https://share.example.com' });

emitter.on('upload:start', ({ filePath }) => console.log(`Starting: ${filePath}`));
emitter.on('upload:progress', ({ progress }) => console.log(`Progress: ${progress.percentage}%`));
emitter.on('upload:complete', ({ result }) => console.log(`Done: ${result.claimCode}`));
emitter.on('upload:error', ({ error }) => console.error(`Error: ${error.message}`));

await emitter.upload('./document.pdf', { expiresInHours: 24 });
```

### Troubleshooting

#### Connection Timeouts

```typescript
// Increase timeout for large files or slow connections
const client = new SafeShareClient({
  baseUrl: 'https://share.example.com',
  timeout: 600000, // 10 minutes
});
```

#### CORS Issues (Browser)

```typescript
// Ensure your SafeShare server allows your origin
// Check server CORS configuration or use a proxy
```

#### Upload Progress Not Updating

```typescript
// Progress updates for chunked uploads happen per-chunk
// For small files, you may only see 0% -> 100%
// Chunked uploads provide more granular progress
```

#### Memory Issues with Large Downloads

```typescript
// Use download() instead of downloadToBuffer() for large files
// download() streams to disk instead of loading into memory
await client.download('abc12345', './large-file.zip');
```

## License

MIT
