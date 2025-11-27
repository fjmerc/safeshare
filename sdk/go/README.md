# SafeShare Go SDK

Official Go SDK for the [SafeShare](https://github.com/fjmerc/safeshare) file sharing service.

## Requirements

- Go 1.21 or later

## Installation

```bash
go get github.com/fjmerc/safeshare/sdk/go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    safeshare "github.com/fjmerc/safeshare/sdk/go"
)

func main() {
    // Create a client with API token authentication
    client, err := safeshare.NewClient(safeshare.ClientConfig{
        BaseURL:  "https://share.example.com",
        APIToken: "safeshare_abc123...", // Get from SafeShare web UI
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Upload a file
    hours := 24
    result, err := client.Upload(ctx, "./document.pdf", &safeshare.UploadOptions{
        ExpiresInHours: &hours,
        OnProgress: func(p safeshare.UploadProgress) {
            fmt.Printf("Upload: %d%%\n", p.Percentage)
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Share this link: %s/claim/%s\n", client.BaseURL(), result.ClaimCode)

    // Download a file
    err = client.Download(ctx, "abc12345", "./downloaded-file.pdf", &safeshare.DownloadOptions{
        OnProgress: func(p safeshare.DownloadProgress) {
            fmt.Printf("Download: %d%%\n", p.Percentage)
        },
    })
    if err != nil {
        log.Fatal(err)
    }
}
```

## Features

- **File Upload** - Simple and chunked uploads with progress tracking
- **File Download** - Stream downloads with progress callbacks
- **File Management** - List, rename, delete, update expiration
- **API Token Management** - Create, list, and revoke API tokens
- **Strong Typing** - Full Go type definitions
- **Error Handling** - Typed errors with `errors.Is()` support
- **Security** - Input validation, token redaction, path traversal prevention

## API Reference

### Creating a Client

```go
client, err := safeshare.NewClient(safeshare.ClientConfig{
    BaseURL:            "https://share.example.com", // Required
    APIToken:           "safeshare_...",             // Optional for auth
    Timeout:            5 * time.Minute,             // Optional (default: 5 min)
    InsecureSkipVerify: false,                       // Skip TLS verification (dangerous!)
})
```

### Uploading Files

#### Simple Upload

```go
hours := 24
limit := 10
result, err := client.Upload(ctx, "./myfile.txt", &safeshare.UploadOptions{
    ExpiresInHours: &hours,        // Optional: Hours until expiration
    DownloadLimit:  &limit,        // Optional: Max downloads allowed
    Password:       "secret123",   // Optional: Password protection
    OnProgress: func(p safeshare.UploadProgress) {
        fmt.Printf("%d%%\n", p.Percentage)
    },
})

fmt.Println(result.ClaimCode)  // Use this to download
fmt.Println(result.Filename)   // Original filename
fmt.Println(result.Size)       // File size in bytes
fmt.Println(result.ExpiresAt)  // Expiration time (nil if none)
```

The SDK automatically uses chunked upload for large files based on server configuration.

#### Chunked Upload Progress

For large files, the progress callback includes chunk information:

```go
result, err := client.Upload(ctx, "./large-file.zip", &safeshare.UploadOptions{
    OnProgress: func(p safeshare.UploadProgress) {
        fmt.Printf("Chunk %d/%d - Overall: %d%%\n", 
            p.CurrentChunk, p.TotalChunks, p.Percentage)
    },
})
```

### Downloading Files

#### Download to File

```go
err := client.Download(ctx, "abc12345", "./output.pdf", &safeshare.DownloadOptions{
    Password:  "secret123",  // Optional: If file is password-protected
    Overwrite: true,         // Optional: Allow overwriting existing files
    OnProgress: func(p safeshare.DownloadProgress) {
        fmt.Printf("%d / %d bytes\n", p.BytesDownloaded, p.TotalBytes)
    },
})
```

#### Download to Writer

```go
var buf bytes.Buffer
err := client.DownloadToWriter(ctx, "abc12345", &buf, &safeshare.DownloadOptions{
    Password: "secret123",
})
// Use buf.Bytes() directly
```

### Getting File Information

```go
info, err := client.GetFileInfo(ctx, "abc12345")

fmt.Println(info.Filename)           // Original filename
fmt.Println(info.Size)               // Size in bytes
fmt.Println(info.MimeType)           // MIME type
fmt.Println(info.ExpiresAt)          // Expiration time or nil
fmt.Println(info.PasswordProtected)  // Boolean
fmt.Println(info.DownloadsRemaining) // Number or nil (unlimited)
```

### Managing Your Files

These operations require authentication (API token).

#### List Files

```go
response, err := client.ListFiles(ctx, 1, 20) // page, perPage

for _, file := range response.Files {
    fmt.Printf("%s (%s)\n", file.Filename, file.ClaimCode)
    limit := "∞"
    if file.DownloadLimit != nil {
        limit = fmt.Sprintf("%d", *file.DownloadLimit)
    }
    fmt.Printf("  Downloads: %d/%s\n", file.DownloadCount, limit)
}

fmt.Printf("Total: %d\n", response.Total)
```

#### Delete a File

```go
err := client.DeleteFile(ctx, "abc12345")
```

#### Rename a File

```go
updated, err := client.RenameFile(ctx, "abc12345", "new-name.pdf")
fmt.Println(updated.Filename) // "new-name.pdf"
```

#### Update Expiration

```go
hours := 48
updated, err := client.UpdateExpiration(ctx, "abc12345", &safeshare.UpdateExpirationOptions{
    ExpiresInHours: &hours, // nil to remove expiration
})
fmt.Println(updated.ExpiresAt)
```

#### Regenerate Claim Code

```go
updated, err := client.RegenerateClaimCode(ctx, "abc12345")
fmt.Printf("New code: %s\n", updated.ClaimCode)
```

### API Token Management

#### List Tokens

```go
tokens, err := client.ListTokens(ctx)

for _, token := range tokens {
    fmt.Printf("%s: %v\n", token.Name, token.Scopes)
    if token.LastUsedAt != nil {
        fmt.Printf("  Last used: %s\n", token.LastUsedAt)
    }
}
```

#### Create Token (requires session auth)

```go
days := 90
newToken, err := client.CreateToken(ctx, safeshare.CreateTokenRequest{
    Name:          "Automation Token",
    Scopes:        []string{"upload", "download", "manage"},
    ExpiresInDays: &days,
})

// Save this - it's only shown once!
fmt.Printf("Token: %s\n", newToken.Token)
```

#### Revoke Token (requires session auth)

```go
err := client.RevokeToken(ctx, tokenID)
```

### Server Configuration

```go
config, err := client.GetConfig(ctx)

fmt.Printf("Max file size: %d\n", config.MaxFileSize)
fmt.Printf("Chunk threshold: %d\n", config.ChunkUploadThreshold)
fmt.Printf("Chunk size: %d\n", config.ChunkSize)
fmt.Printf("Max expiration: %d hours\n", config.MaxExpirationHours)
```

## Error Handling

The SDK provides typed errors that work with `errors.Is()`:

```go
import (
    "errors"
    safeshare "github.com/fjmerc/safeshare/sdk/go"
)

err := client.Download(ctx, "abc12345", "./output.pdf", nil)

if errors.Is(err, safeshare.ErrNotFound) {
    fmt.Println("File not found or expired")
} else if errors.Is(err, safeshare.ErrAuthentication) {
    fmt.Println("Authentication failed")
} else if errors.Is(err, safeshare.ErrPasswordRequired) {
    fmt.Println("Password is required")
} else if errors.Is(err, safeshare.ErrDownloadLimitReached) {
    fmt.Println("Download limit exceeded")
} else if errors.Is(err, safeshare.ErrRateLimit) {
    fmt.Println("Rate limited")
} else if errors.Is(err, safeshare.ErrValidation) {
    fmt.Println("Invalid input")
} else if err != nil {
    fmt.Printf("Error: %v\n", err)
}

// For API errors, you can get more details:
var apiErr *safeshare.APIError
if errors.As(err, &apiErr) {
    fmt.Printf("Status %d: %s\n", apiErr.StatusCode, apiErr.Message)
}
```

### Error Types

| Error | Description |
|-------|-------------|
| `ErrValidation` | Input validation failed |
| `ErrAuthentication` | Invalid or missing API token |
| `ErrNotFound` | Resource not found |
| `ErrRateLimit` | Too many requests |
| `ErrPasswordRequired` | Password needed for download |
| `ErrDownloadLimitReached` | Download limit exceeded |
| `ErrFileTooLarge` | File exceeds size limit |
| `ErrQuotaExceeded` | User quota exceeded |

## CLI Tool

The SDK includes a command-line interface tool.

### Building the CLI

```bash
cd sdk/go
go build -o safeshare-cli ./cmd/safeshare-cli
```

### Configuration

Set environment variables:

```bash
export SAFESHARE_URL="https://share.example.com"
export SAFESHARE_TOKEN="safeshare_abc123..."
```

Or use flags:

```bash
safeshare-cli --url https://share.example.com --token safeshare_... upload file.txt
```

### Commands

#### Upload

```bash
# Simple upload
safeshare-cli upload ./myfile.txt

# With options
safeshare-cli upload ./myfile.txt --expires 24 --limit 10 --password secret
```

#### Download

```bash
# Download a file
safeshare-cli download abc12345 ./output.pdf

# With password
safeshare-cli download abc12345 ./output.pdf --password secret

# Overwrite existing file
safeshare-cli download abc12345 ./output.pdf --overwrite
```

#### File Info

```bash
safeshare-cli info abc12345
```

#### List Files

```bash
# List your files
safeshare-cli list

# With pagination
safeshare-cli list --page 2 --per-page 50
```

#### Delete File

```bash
safeshare-cli delete abc12345
```

#### Rename File

```bash
safeshare-cli rename abc12345 "new-name.pdf"
```

#### Server Config

```bash
safeshare-cli config
```

## Security

- **Token Redaction**: API tokens are redacted in `String()` output to prevent accidental logging
- **Input Validation**: Claim codes, upload IDs, and filenames are validated to prevent injection attacks
- **Path Traversal Prevention**: Filenames containing `..`, `/`, or `\` are rejected
- **Symlink Protection**: Downloads refuse to overwrite symbolic links
- **File Overwrite Protection**: By default, downloading to an existing file returns an error
- **CLI Token Warning**: Warning displayed when token is passed via command line (visible in process list)

## Development

```bash
# Run tests (requires Docker)
docker run --rm -v "$PWD":/app -w /app/sdk/go golang:1.24 go test -v ./...

# Build CLI
docker run --rm -v "$PWD":/app -w /app/sdk/go golang:1.24 go build -o safeshare-cli ./cmd/safeshare-cli
```

## License

MIT
