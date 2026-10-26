# SafeShare Go SDK

Official Go SDK for the [SafeShare](https://github.com/fjmerc/safeshare) file sharing service.

## Requirements

- Go 1.26 or later

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

#### End-to-End Encrypted Upload

On servers in Ghost (anonymous) mode or that require client-side encryption, `Upload` encrypts the file before it leaves your machine, in the web app's format; set `Encrypt: safeshare.EncryptAlways` to encrypt on any server. The share link carries the key in its fragment and opens in a browser.

```go
result, err := client.Upload(ctx, "./report.pdf", &safeshare.UploadOptions{
    Encrypt: safeshare.EncryptAlways, // default EncryptAuto: only when the server needs it
})
fmt.Println(result.ShareURL) // https://host/#/claim/CODE/key/KEY - keep it secret
```

The filename is hidden inside the encrypted payload unless `ShowFilename` is set, and encrypted uploads are always padded to a size bucket. `EncryptAuto` follows the server's settings; use `EncryptAlways` if the server itself isn't trusted to report them. The SDK cannot remove metadata: on Ghost servers, JPEG, PNG, PDF and Office files fail with `ErrMetadataNotRemoved` unless `KeepMetadata` is set. Encrypted files are held in memory whole.

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

#### Download and Decrypt

```go
link, err := safeshare.ParseShareURL(shareURL)
client, _ := safeshare.NewClient(safeshare.ClientConfig{BaseURL: link.BaseURL})
file, err := client.DownloadDecrypted(ctx, link.ClaimCode, link.Key, nil)
// file.Filename comes from the uploader: use safeshare.SafeFilename before saving
```

Or set `DownloadOptions.DecryptionKey` with `Download`/`DownloadToWriter`.

#### Download a Drop-Page Submission

Files sent with a server's no-JavaScript drop page (`/drop`) are encrypted with [age](https://age-encryption.org) to the recipient's key. `DownloadDrop` decrypts the download as it streams and extracts it into a new directory: the sender's file, and `message.txt` if they wrote one.

```go
import "filippo.io/age"

f, err := os.Open("drop-key.txt") // from age-keygen; keep it private
if err != nil {
    return err
}
identities, err := age.ParseIdentities(f)
f.Close()
if err != nil {
    return err
}
files, err := client.DownloadDrop(ctx, "abc12345", "./drop-abc12345", identities, nil)
if err != nil {
    return err
}
for _, file := range files {
    fmt.Println(file.Name, file.Size)
}
```

The directory must not exist yet (its parent must). Only plain files are written, with mode 0600 and safe names; an archive with anything else, or a download that fails to decrypt to the last byte, is refused and the directory removed. `ExtractDrop` does the same for a drop already downloaded (`safeshare-drop.tar.age`).

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

### Installing the CLI

Each [release](https://github.com/fjmerc/safeshare/releases) (from v1.17.1) has `safeshare-cli` for Linux, macOS and Windows, on `amd64` (Intel/AMD) and `arm64` (ARM, including Apple silicon). Download yours and `safeshare-cli.sha256`, then check and install it:

```bash
sha256sum --ignore-missing -c safeshare-cli.sha256   # macOS: shasum -a 256 --ignore-missing -c safeshare-cli.sha256
chmod +x safeshare-cli-linux-amd64
sudo mv safeshare-cli-linux-amd64 /usr/local/bin/safeshare-cli
```

The binaries rebuild byte-for-byte from the release's source: see [VERIFYING_RELEASES.md](../../docs/VERIFYING_RELEASES.md#checking-safeshare-cli).

Or build it with Go 1.26 or later:

```bash
go install github.com/fjmerc/safeshare/sdk/go/cmd/safeshare-cli@main   # installs to ~/go/bin
# or, from a checkout:
cd sdk/go
go build -o safeshare-cli ./cmd/safeshare-cli
```

`safeshare-cli --version` shows which release a binary was built from (`version` also shows the Go version and platform). Other builds report what Go recorded instead: for a build from a git checkout, a pseudo-version with the commit (`v0.0.0-20261026133635-d82927633a6a`, `+dirty` with uncommitted changes), or `dev` when there is nothing to go on. The server's version is in `safeshare-cli config`.

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

# Encrypt on this machine (automatic on Ghost servers); prints a share link with the key
safeshare-cli upload ./myfile.txt --encrypt

# Over Tor (always encrypts; every request goes through the proxy)
safeshare-cli --proxy socks5h://127.0.0.1:9050 upload ./myfile.txt

# Several files: same options for each, one claim code and link per file
safeshare-cli upload video.mp4 cover.png caption.txt --expires 24
```

With several files, every path is checked before anything is uploaded. If an upload fails, the others still go (`--fail-fast` stops at the first failure), the summary says which failed, and the exit status is 1. Ctrl-C aborts the file being uploaded, skips the rest and still prints the links of the files already uploaded (a second Ctrl-C exits at once). The server can tell that files uploaded in one call came from the same person (by their order and timing); upload them separately, some time apart, if that matters.

To open a link on a phone, add `--qr`: each link is also drawn as a QR code in the terminal, to scan with the phone's camera. It is drawn for a terminal with a dark background. `safeshare-cli info CODE --qr` does the same for a file you uploaded earlier (not for end-to-end encrypted files: their link needs the key). `--qr` can't be combined with `--json`.

> **Warning:** for an encrypted upload, the QR code holds the share link with its key. Anyone who can see your screen, a screen recording or a shared terminal log can read the file. The CLI warns on stderr when this is the case.

Flags for encrypted uploads: `--encrypt`, `--no-encrypt`, `--show-filename` (let the server see the name), `--keep-metadata` (allow JPEG/PNG/PDF/Office files on Ghost servers; the CLI can't remove their metadata).

#### Download

```bash
# Download a file
safeshare-cli download abc12345 ./output.pdf

# With password
safeshare-cli download abc12345 ./output.pdf --password secret

# Overwrite existing file
safeshare-cli download abc12345 ./output.pdf --overwrite

# Encrypted file: read the share link from stdin (keeps the key out of shell history)
safeshare-cli download - < link.txt

# Drop-page submission: decrypt with your age key into a new directory (default drop-CODE)
safeshare-cli download abc12345 --identity drop-key.txt
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
safeshare-cli list --limit 50 --offset 50
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

#### Verify a Server's Web App

```bash
# Compare every page and script with the hashes published for the server's release
safeshare-cli verify https://share.example.com

# Over Tor, or against a hash list you made from a checkout
safeshare-cli verify --proxy socks5://127.0.0.1:9050 http://example.onion
safeshare-cli verify https://share.example.com --manifest web-assets.sha256
```

Exit status: 0 verified, 2 a file differs, 1 could not verify. See [docs/VERIFYING_RELEASES.md](../../docs/VERIFYING_RELEASES.md) for what it can and can't show. From Go: `ParseWebAssetManifest`, `Client.FetchReleaseManifest` and `Client.VerifyWebAssets`.

### Scripting with `--json`

With `--json`, any command prints one line of JSON on stdout and nothing else (no progress bar, no banners). Notes and warnings still go to stderr. When a command fails, the exit status is non-zero and stderr gets `{"error": "...", "code": "...", "status": 404}`; `code` (the server's error code) and `status` (HTTP) are there only for errors from the server.

```bash
url=$(safeshare-cli upload video.mp4 --expires 24 --json | jq -r .url)
```

`upload` prints:

```json
{"schema":1,"file":"video.mp4","claim_code":"Xk3pQ9aB","filename":"video.mp4","size":1048576,"mime_type":"video/mp4","expires_at":"2026-10-27T12:00:00Z","download_limit":null,"password_protected":false,"encrypted":false,"url":"https://share.example.com/claim/Xk3pQ9aB"}
```

`url` is the link to open: the claim page, or for an encrypted upload, the share link. With several files, `upload` prints an array with one object per file, in the order given (with one file, the object on its own; a script that passes a varying number of files can use `jq 'if type == "array" then .[] else . end'`). A file that wasn't uploaded has `file`, `error` and possibly `code`/`status` instead of the upload's fields:

```bash
safeshare-cli upload a.mp4 b.txt --json | jq -r '.[] | .url // "FAILED \(.file): \(.error)"'
```

> **Warning: the JSON of an encrypted upload is a secret.** Its `url` holds the decryption key after the `#`, and anyone who sees it can read the file. Don't write it to logs, CI output, shared files or anywhere else you wouldn't put a password. (The Go SDK leaves the key and the link out of `UploadResult`'s JSON for this reason; the CLI adds the link because it is what the command is for.)

The other commands print:

| Command | Fields |
|---|---|
| `info` | `claim_code` and the file's details: `filename`, `size`, `mime_type`, `expires_at`, `password_protected`, `downloads_remaining`, `client_encrypted`, `download_available`, `scan_status` |
| `list` | `files` (each with `claim_code`, `filename`, `size`, `uploaded_at`, `expires_at`, `completed_downloads`, `download_limit`, ...), `total`, `page`, `per_page` |
| `config` | `url` and the server's settings, including `version` |
| `download` | `claim_code`, `filename`, `size`, `path` (where it was saved), `decrypted`; for a drop, `path` (the directory) and `files` |
| `delete` | `claim_code`, `deleted`. Needs `--force`, since it can't ask |
| `rename` | `claim_code`, `filename` |
| `version` | `version`, `go`, `os`, `arch` |
| `verify` | `result` (`verified`, `tampered` or `could_not_verify`), `server_version`, `version`, `compared_against`, `files` (each with `file`, `url_path`, `status`, `expected`, `got`, `detail`), `loose_csp`. Printed whenever the comparison ran; the exit status still says the result |

The `--version` flag always prints text; use the `version` command for JSON. An error in the command line itself (an unknown flag or command) is also reported as JSON when `--json` is among the arguments.

Every document has `"schema": 1`. Within a schema, fields may be added but are never renamed or removed. Times are RFC 3339; a missing limit or expiry is `null`. Strings are as the server sent them: unlike the text output, control characters in names are not escaped for the terminal, so take care when printing them.

## Security

- **Token Redaction**: API tokens are redacted in `String()` output to prevent accidental logging
- **Input Validation**: Claim codes, upload IDs, and filenames are validated to prevent injection attacks
- **Path Traversal Prevention**: Filenames containing `..`, `/`, or `\` are rejected
- **Symlink Protection**: Downloads refuse to overwrite symbolic links
- **File Overwrite Protection**: By default, downloading to an existing file returns an error
- **CLI Token Warning**: Warning displayed when token is passed via command line (visible in process list)
- **End-to-End Encryption**: AES-256-GCM in the web app's format; keys never sent to the server; decrypted files written with mode 0600
- **Proxy Support**: `ClientConfig.Proxy` (CLI `--proxy`) sends every request through a proxy, including `socks5://` with remote DNS (Tor); `ALL_PROXY`/`HTTPS_PROXY`/`HTTP_PROXY` are honoured too
- **Redirects**: redirects to another host or scheme are refused, so the token and file passwords stay with the server

## Development

```bash
# Run tests (requires Docker)
docker run --rm -v "$PWD":/app -w /app/sdk/go golang:1.26 go test -v ./...

# Build CLI
docker run --rm -v "$PWD":/app -w /app/sdk/go golang:1.26 go build -o safeshare-cli ./cmd/safeshare-cli
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
