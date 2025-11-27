# SafeShare Python SDK

A Python client library for the SafeShare file sharing service.

## Installation

```bash
pip install safeshare
```

Or install from source:

```bash
cd sdk/python
pip install -e .
```

## Quick Start

```python
from safeshare import SafeShareClient

# Initialize client with API token
client = SafeShareClient(
    base_url="https://share.example.com",
    api_token="safeshare_your_token_here"
)

# Upload a file
result = client.upload("document.pdf", expires_in_hours=48)
print(f"Download URL: {result.download_url}")

# Download a file
client.download("claim_code_here", "downloaded_file.pdf")

# Close client when done
client.close()
```

### Using as Context Manager

```python
with SafeShareClient(base_url="https://share.example.com") as client:
    result = client.upload("file.txt")
    print(f"Claim code: {result.claim_code}")
```

## Features

- Simple and chunked file uploads
- Progress callbacks for uploads and downloads
- Automatic chunked upload for large files
- File management (list, rename, delete)
- API token authentication
- Password-protected file support
- Comprehensive error handling

## Authentication

SafeShare supports API token authentication for programmatic access:

```python
client = SafeShareClient(
    base_url="https://share.example.com",
    api_token="safeshare_<your_token>"
)
```

To create an API token:
1. Log in to the SafeShare web interface
2. Go to Settings > API Tokens
3. Create a token with the required scopes

### Available Scopes

| Scope | Description |
|-------|-------------|
| `upload` | Upload files |
| `download` | Download files |
| `manage` | List, rename, delete own files |
| `admin` | Admin operations (admin users only) |

## Upload Files

### Simple Upload

```python
result = client.upload(
    "document.pdf",
    expires_in_hours=24,     # Optional: expires in 24 hours
    max_downloads=5,         # Optional: limit to 5 downloads
    password="secret123",    # Optional: password protect
)

print(f"Claim code: {result.claim_code}")
print(f"Download URL: {result.download_url}")
```

### Upload with Progress

```python
from safeshare import UploadProgress

def on_progress(progress: UploadProgress):
    print(f"Uploaded: {progress.percentage:.1f}%")
    if progress.total_chunks > 1:
        print(f"Chunks: {progress.chunks_completed}/{progress.total_chunks}")

result = client.upload("large_file.zip", progress_callback=on_progress)
```

### Upload from File Object

```python
with open("document.pdf", "rb") as f:
    result = client.upload(f, filename="custom_name.pdf")
```

## Download Files

### Simple Download

```python
# Download by claim code
client.download("ABC123", "downloaded_file.pdf")

# Download password-protected file
client.download("ABC123", "downloaded_file.pdf", password="secret123")
```

### Download with Progress

```python
from safeshare.models import DownloadProgress

def on_progress(progress: DownloadProgress):
    if progress.percentage:
        print(f"Downloaded: {progress.percentage:.1f}%")

client.download("ABC123", "file.pdf", progress_callback=on_progress)
```

### Get File Info Without Downloading

```python
info = client.get_file_info("ABC123")
print(f"Filename: {info.original_filename}")
print(f"Size: {info.file_size} bytes")
print(f"Downloads remaining: {info.downloads_remaining}")
```

## File Management

Requires an API token with `manage` scope.

### List Files

```python
result = client.list_files(limit=50, offset=0)
for f in result.files:
    print(f"{f.id}: {f.original_filename} ({f.claim_code})")
```

### Delete File

```python
client.delete_file(file_id=123)
```

### Rename File

```python
client.rename_file(file_id=123, new_filename="new_name.pdf")
```

### Update Expiration

```python
# Extend expiration by 72 hours from now
client.update_expiration(file_id=123, expires_in_hours=72)
```

### Regenerate Claim Code

```python
new_code = client.regenerate_claim_code(file_id=123)
print(f"New claim code: {new_code}")
# Old claim code is now invalid
```

## Error Handling

```python
from safeshare import SafeShareClient
from safeshare.exceptions import (
    SafeShareError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    UploadError,
    DownloadError,
    PasswordRequiredError,
    FileTooLargeError,
    QuotaExceededError,
)

try:
    result = client.upload("file.txt")
except AuthenticationError:
    print("Invalid API token")
except FileTooLargeError:
    print("File exceeds maximum size limit")
except QuotaExceededError:
    print("Storage quota exceeded")
except RateLimitError as e:
    print(f"Rate limit exceeded. Retry after: {e.retry_after}")
except UploadError as e:
    print(f"Upload failed: {e}")

try:
    client.download("ABC123", "file.pdf")
except NotFoundError:
    print("File not found or expired")
except PasswordRequiredError:
    print("Password required for this file")
except DownloadError as e:
    print(f"Download failed: {e}")
```

## Server Configuration

Get server configuration to check limits:

```python
config = client.get_config()
print(f"Max file size: {config.max_file_size} bytes")
print(f"Chunked upload threshold: {config.chunked_upload_threshold} bytes")
print(f"Auth required for upload: {config.require_auth_for_upload}")
```

## Advanced Configuration

```python
client = SafeShareClient(
    base_url="https://share.example.com",
    api_token="safeshare_...",
    timeout=600.0,      # Request timeout in seconds (default: 300)
    verify_ssl=True,    # SSL certificate verification (default: True)
)
```

## Examples

See the `examples/` directory for complete examples:

- `simple_upload.py` - Basic file upload
- `chunked_upload.py` - Large file upload with progress
- `download_file.py` - Download with progress tracking
- `file_management.py` - List, rename, delete files

Run examples:

```bash
# Set environment variables
export SAFESHARE_URL="http://localhost:8080"
export SAFESHARE_TOKEN="safeshare_your_token"

# Upload a file
python examples/simple_upload.py myfile.pdf

# Download a file
python examples/download_file.py ABC123

# List your files
python examples/file_management.py list
```

## Development

### Setup Development Environment

```bash
cd sdk/python
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest
```

### Code Quality

```bash
# Lint
ruff check .

# Type check
mypy safeshare
```

## API Reference

See the [OpenAPI specification](../../docs/openapi.yaml) for complete API documentation.

## License

MIT License - see [LICENSE](../../LICENSE) for details.
