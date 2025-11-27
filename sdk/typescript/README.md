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
  console.log(`  Downloads: ${file.downloadCount}/${file.downloadLimit || "∞"}`);
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

## License

MIT
