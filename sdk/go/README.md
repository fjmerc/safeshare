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

## Advanced Usage

### Retry Logic with Exponential Backoff

```go
package main

import (
    "context"
    "errors"
    "math"
    "time"

    safeshare "github.com/fjmerc/safeshare/sdk/go"
)

type RetryConfig struct {
    MaxRetries int
    BaseDelay  time.Duration
    MaxDelay   time.Duration
}

func DefaultRetryConfig() RetryConfig {
    return RetryConfig{
        MaxRetries: 3,
        BaseDelay:  1 * time.Second,
        MaxDelay:   30 * time.Second,
    }
}

func WithRetry[T any](ctx context.Context, cfg RetryConfig, operation func() (T, error)) (T, error) {
    var result T
    var lastErr error

    for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
        result, lastErr = operation()
        if lastErr == nil {
            return result, nil
        }

        // Don't retry on validation or auth errors
        if errors.Is(lastErr, safeshare.ErrValidation) ||
            errors.Is(lastErr, safeshare.ErrAuthentication) ||
            errors.Is(lastErr, safeshare.ErrNotFound) {
            return result, lastErr
        }

        if attempt == cfg.MaxRetries {
            break
        }

        // Calculate delay with exponential backoff
        delay := time.Duration(float64(cfg.BaseDelay) * math.Pow(2, float64(attempt)))
        if delay > cfg.MaxDelay {
            delay = cfg.MaxDelay
        }

        // Check for rate limit with Retry-After
        var apiErr *safeshare.APIError
        if errors.As(lastErr, &apiErr) && apiErr.RetryAfter > 0 {
            delay = time.Duration(apiErr.RetryAfter) * time.Second
        }

        select {
        case <-ctx.Done():
            return result, ctx.Err()
        case <-time.After(delay):
            // Continue to next attempt
        }
    }

    return result, lastErr
}

// Usage example
func uploadWithRetry(ctx context.Context, client *safeshare.Client, path string) (*safeshare.UploadResult, error) {
    return WithRetry(ctx, DefaultRetryConfig(), func() (*safeshare.UploadResult, error) {
        hours := 24
        return client.Upload(ctx, path, &safeshare.UploadOptions{
            ExpiresInHours: &hours,
        })
    })
}
```

### Concurrent Batch Uploads

```go
package main

import (
    "context"
    "fmt"
    "sync"

    safeshare "github.com/fjmerc/safeshare/sdk/go"
)

type BatchResult struct {
    Path      string
    ClaimCode string
    Error     error
}

func BatchUpload(ctx context.Context, client *safeshare.Client, paths []string, concurrency int) []BatchResult {
    results := make([]BatchResult, len(paths))
    sem := make(chan struct{}, concurrency)
    var wg sync.WaitGroup

    for i, path := range paths {
        wg.Add(1)
        go func(idx int, filePath string) {
            defer wg.Done()

            // Acquire semaphore
            sem <- struct{}{}
            defer func() { <-sem }()

            hours := 24
            result, err := client.Upload(ctx, filePath, &safeshare.UploadOptions{
                ExpiresInHours: &hours,
            })

            results[idx] = BatchResult{
                Path:  filePath,
                Error: err,
            }
            if result != nil {
                results[idx].ClaimCode = result.ClaimCode
            }
        }(i, path)
    }

    wg.Wait()
    return results
}

// Usage
func main() {
    client, _ := safeshare.NewClient(safeshare.ClientConfig{
        BaseURL:  "https://share.example.com",
        APIToken: "safeshare_...",
    })

    files := []string{"file1.pdf", "file2.pdf", "file3.pdf", "file4.pdf", "file5.pdf"}
    results := BatchUpload(context.Background(), client, files, 3) // 3 concurrent uploads

    for _, r := range results {
        if r.Error != nil {
            fmt.Printf("%s: ERROR - %v\n", r.Path, r.Error)
        } else {
            fmt.Printf("%s: %s\n", r.Path, r.ClaimCode)
        }
    }
}
```

### Custom HTTP Transport

```go
package main

import (
    "crypto/tls"
    "net"
    "net/http"
    "time"

    safeshare "github.com/fjmerc/safeshare/sdk/go"
)

func NewClientWithProxy(baseURL, token, proxyURL string) (*safeshare.Client, error) {
    // Create custom transport
    transport := &http.Transport{
        Proxy: http.ProxyFromEnvironment, // Or use explicit proxy
        DialContext: (&net.Dialer{
            Timeout:   30 * time.Second,
            KeepAlive: 30 * time.Second,
        }).DialContext,
        ForceAttemptHTTP2:     true,
        MaxIdleConns:          100,
        IdleConnTimeout:       90 * time.Second,
        TLSHandshakeTimeout:   10 * time.Second,
        ExpectContinueTimeout: 1 * time.Second,
        TLSClientConfig: &tls.Config{
            MinVersion: tls.VersionTLS12,
        },
    }

    // If using explicit proxy:
    // proxyParsed, _ := url.Parse(proxyURL)
    // transport.Proxy = http.ProxyURL(proxyParsed)

    return safeshare.NewClient(safeshare.ClientConfig{
        BaseURL:   baseURL,
        APIToken:  token,
        Transport: transport,
        Timeout:   10 * time.Minute,
    })
}
```

### HTTP Handler Integration

```go
package main

import (
    "encoding/json"
    "io"
    "net/http"
    "os"
    "path/filepath"

    safeshare "github.com/fjmerc/safeshare/sdk/go"
)

type ShareHandler struct {
    client    *safeshare.Client
    uploadDir string
}

func NewShareHandler(client *safeshare.Client, uploadDir string) *ShareHandler {
    return &ShareHandler{client: client, uploadDir: uploadDir}
}

func (h *ShareHandler) HandleUpload(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Parse multipart form (32 MB max)
    if err := r.ParseMultipartForm(32 << 20); err != nil {
        http.Error(w, "Failed to parse form", http.StatusBadRequest)
        return
    }

    file, header, err := r.FormFile("file")
    if err != nil {
        http.Error(w, "No file provided", http.StatusBadRequest)
        return
    }
    defer file.Close()

    // Save file temporarily
    tempPath := filepath.Join(h.uploadDir, header.Filename)
    out, err := os.Create(tempPath)
    if err != nil {
        http.Error(w, "Failed to save file", http.StatusInternalServerError)
        return
    }
    defer os.Remove(tempPath)
    defer out.Close()

    if _, err := io.Copy(out, file); err != nil {
        http.Error(w, "Failed to save file", http.StatusInternalServerError)
        return
    }
    out.Close()

    // Upload to SafeShare
    hours := 24
    result, err := h.client.Upload(r.Context(), tempPath, &safeshare.UploadOptions{
        ExpiresInHours: &hours,
    })
    if err != nil {
        http.Error(w, "Upload failed: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "claimCode": result.ClaimCode,
        "shareLink": h.client.BaseURL() + "/claim/" + result.ClaimCode,
    })
}

func (h *ShareHandler) HandleProxy(w http.ResponseWriter, r *http.Request) {
    claimCode := r.URL.Query().Get("code")
    if claimCode == "" {
        http.Error(w, "Missing claim code", http.StatusBadRequest)
        return
    }

    info, err := h.client.GetFileInfo(r.Context(), claimCode)
    if err != nil {
        http.Error(w, "File not found", http.StatusNotFound)
        return
    }

    // Set headers for download
    w.Header().Set("Content-Type", info.MimeType)
    w.Header().Set("Content-Disposition", "attachment; filename=\""+info.Filename+"\"")

    // Stream download to response
    err = h.client.DownloadToWriter(r.Context(), claimCode, w, nil)
    if err != nil {
        // Headers already sent, can't change status
        return
    }
}
```

### Context Cancellation and Timeouts

```go
package main

import (
    "context"
    "fmt"
    "time"

    safeshare "github.com/fjmerc/safeshare/sdk/go"
)

func uploadWithTimeout(client *safeshare.Client, path string) error {
    // Create context with 5-minute timeout
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    result, err := client.Upload(ctx, path, nil)
    if err != nil {
        if ctx.Err() == context.DeadlineExceeded {
            return fmt.Errorf("upload timed out after 5 minutes")
        }
        return err
    }

    fmt.Printf("Uploaded: %s\n", result.ClaimCode)
    return nil
}

func uploadWithCancellation(client *safeshare.Client, path string, done <-chan struct{}) error {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Watch for cancellation signal
    go func() {
        select {
        case <-done:
            cancel()
        case <-ctx.Done():
        }
    }()

    hours := 24
    _, err := client.Upload(ctx, path, &safeshare.UploadOptions{
        ExpiresInHours: &hours,
        OnProgress: func(p safeshare.UploadProgress) {
            fmt.Printf("Progress: %d%%\n", p.Percentage)
        },
    })
    return err
}
```

### Worker Pool Pattern

```go
package main

import (
    "context"
    "log"

    safeshare "github.com/fjmerc/safeshare/sdk/go"
)

type UploadJob struct {
    Path     string
    ResultCh chan<- *safeshare.UploadResult
    ErrorCh  chan<- error
}

func StartWorkerPool(ctx context.Context, client *safeshare.Client, workers int) chan<- UploadJob {
    jobs := make(chan UploadJob, 100)

    for i := 0; i < workers; i++ {
        go func(workerID int) {
            for {
                select {
                case <-ctx.Done():
                    return
                case job, ok := <-jobs:
                    if !ok {
                        return
                    }
                    hours := 24
                    result, err := client.Upload(ctx, job.Path, &safeshare.UploadOptions{
                        ExpiresInHours: &hours,
                    })
                    if err != nil {
                        job.ErrorCh <- err
                    } else {
                        job.ResultCh <- result
                    }
                }
            }
        }(i)
    }

    return jobs
}

// Usage
func main() {
    client, _ := safeshare.NewClient(safeshare.ClientConfig{
        BaseURL:  "https://share.example.com",
        APIToken: "safeshare_...",
    })

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    jobs := StartWorkerPool(ctx, client, 5)

    resultCh := make(chan *safeshare.UploadResult, 10)
    errorCh := make(chan error, 10)

    // Submit jobs
    files := []string{"file1.pdf", "file2.pdf", "file3.pdf"}
    for _, f := range files {
        jobs <- UploadJob{Path: f, ResultCh: resultCh, ErrorCh: errorCh}
    }

    // Collect results
    for i := 0; i < len(files); i++ {
        select {
        case result := <-resultCh:
            log.Printf("Uploaded: %s\n", result.ClaimCode)
        case err := <-errorCh:
            log.Printf("Error: %v\n", err)
        }
    }
}
```

### Testing with Mock Client

```go
package myapp_test

import (
    "context"
    "testing"

    safeshare "github.com/fjmerc/safeshare/sdk/go"
)

// MockClient implements the same interface as safeshare.Client
type MockClient struct {
    UploadFunc      func(ctx context.Context, path string, opts *safeshare.UploadOptions) (*safeshare.UploadResult, error)
    DownloadFunc    func(ctx context.Context, claimCode, destPath string, opts *safeshare.DownloadOptions) error
    GetFileInfoFunc func(ctx context.Context, claimCode string) (*safeshare.FileInfo, error)
}

func (m *MockClient) Upload(ctx context.Context, path string, opts *safeshare.UploadOptions) (*safeshare.UploadResult, error) {
    if m.UploadFunc != nil {
        return m.UploadFunc(ctx, path, opts)
    }
    return &safeshare.UploadResult{ClaimCode: "test123"}, nil
}

func (m *MockClient) Download(ctx context.Context, claimCode, destPath string, opts *safeshare.DownloadOptions) error {
    if m.DownloadFunc != nil {
        return m.DownloadFunc(ctx, claimCode, destPath, opts)
    }
    return nil
}

func (m *MockClient) GetFileInfo(ctx context.Context, claimCode string) (*safeshare.FileInfo, error) {
    if m.GetFileInfoFunc != nil {
        return m.GetFileInfoFunc(ctx, claimCode)
    }
    return &safeshare.FileInfo{Filename: "test.txt", Size: 1024}, nil
}

func TestFileService(t *testing.T) {
    mock := &MockClient{
        UploadFunc: func(ctx context.Context, path string, opts *safeshare.UploadOptions) (*safeshare.UploadResult, error) {
            return &safeshare.UploadResult{
                ClaimCode: "abc12345",
                Filename:  "test.txt",
                Size:      1024,
            }, nil
        },
    }

    result, err := mock.Upload(context.Background(), "test.txt", nil)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if result.ClaimCode != "abc12345" {
        t.Errorf("expected claim code abc12345, got %s", result.ClaimCode)
    }
}
```

### Graceful Shutdown

```go
package main

import (
    "context"
    "fmt"
    "os"
    "os/signal"
    "sync"
    "syscall"

    safeshare "github.com/fjmerc/safeshare/sdk/go"
)

func main() {
    client, _ := safeshare.NewClient(safeshare.ClientConfig{
        BaseURL:  "https://share.example.com",
        APIToken: "safeshare_...",
    })

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Handle shutdown signals
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sigCh
        fmt.Println("\nShutting down gracefully...")
        cancel()
    }()

    var wg sync.WaitGroup

    // Start uploads
    files := []string{"file1.pdf", "file2.pdf", "file3.pdf"}
    for _, f := range files {
        wg.Add(1)
        go func(path string) {
            defer wg.Done()
            hours := 24
            result, err := client.Upload(ctx, path, &safeshare.UploadOptions{
                ExpiresInHours: &hours,
            })
            if err != nil {
                if ctx.Err() != nil {
                    fmt.Printf("%s: cancelled\n", path)
                } else {
                    fmt.Printf("%s: error - %v\n", path, err)
                }
                return
            }
            fmt.Printf("%s: %s\n", path, result.ClaimCode)
        }(f)
    }

    wg.Wait()
    fmt.Println("Done")
}
```

### Troubleshooting

#### Connection Timeouts

```go
// Increase timeout for large files
client, _ := safeshare.NewClient(safeshare.ClientConfig{
    BaseURL: "https://share.example.com",
    Timeout: 30 * time.Minute,
})
```

#### Certificate Errors (Development Only)

```go
// WARNING: Only use for local development with self-signed certs
client, _ := safeshare.NewClient(safeshare.ClientConfig{
    BaseURL:            "https://localhost:8080",
    InsecureSkipVerify: true, // DO NOT use in production!
})
```

#### Memory Usage with Large Files

```go
// The SDK streams files automatically, but ensure you're not
// loading the entire file into memory elsewhere in your code

// DON'T do this for large files:
// data, _ := os.ReadFile("huge-file.zip")

// DO use the SDK's streaming upload:
client.Upload(ctx, "huge-file.zip", nil)
```

#### Progress Callback Not Firing

```go
// Progress callbacks fire per-chunk for chunked uploads
// For small files (< chunk threshold), you may only see 0% -> 100%
// Check server config for chunk threshold:
config, _ := client.GetConfig(ctx)
fmt.Printf("Chunk threshold: %d bytes\n", config.ChunkUploadThreshold)
```

## License

MIT
