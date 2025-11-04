# SafeShare - Secure Temporary File Sharing

DoD SAFE-like file sharing service with claim codes and automatic expiration.

## Features

### Backend
- ✅ Upload files and receive unique claim codes
- ✅ Download files using claim codes
- ✅ Automatic file expiration
- ✅ Optional download limits
- ✅ Configurable expiration times
- ✅ RESTful API
- ✅ Single binary deployment
- ✅ Docker container (~26MB)
- ✅ SQLite database (no external dependencies)
- ✅ Graceful shutdown
- ✅ Health check endpoint
- ✅ Structured JSON logging

### Enterprise Security 🔒
- ✅ **Encryption at rest** (AES-256-GCM)
- ✅ **File extension blacklist** (blocks executables)
- ✅ **Enhanced audit logging** (compliance-ready)
- ✅ **Rate limiting** (IP-based DoS protection)
- ✅ **Filename sanitization** (prevents header injection)
- ✅ **Security headers** (CSP, X-Frame-Options, etc.)
- ✅ **MIME type detection** (server-side validation)
- ✅ **Disk space monitoring** (prevents exhaustion)
- ✅ **Maximum expiration limits** (prevents abuse)

### Frontend (Web UI)
- ✅ Modern, responsive web interface
- ✅ Drag & drop file upload
- ✅ QR code generation for mobile sharing
- ✅ Dark/Light mode toggle
- ✅ One-click copy to clipboard
- ✅ Real-time upload progress
- ✅ Embedded in binary (no separate deployment)

## Screenshots

![SafeShare Web UI](https://via.placeholder.com/800x400/3b82f6/ffffff?text=SafeShare+Web+UI)

*Modern web interface with drag-drop upload, QR codes, and dark mode support*

## Quick Start

### Web UI

Simply visit the root URL after starting the server:

```
http://localhost:8080/
```

Features drag-drop upload, QR code generation, and one-click sharing!

### Docker

```bash
# Run with default settings
docker run -d \
  -p 8080:8080 \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  --name safeshare \
  safeshare:latest

# Run with custom configuration
docker run -d \
  -p 8080:8080 \
  -e MAX_FILE_SIZE=209715200 \
  -e DEFAULT_EXPIRATION_HOURS=48 \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  --name safeshare \
  safeshare:latest
```

### Binary

```bash
# Set environment variables (optional)
export PORT=8080
export MAX_FILE_SIZE=104857600
export DEFAULT_EXPIRATION_HOURS=24

# Run the binary
./safeshare
```

## API Documentation

### Upload File

Upload a file and receive a unique claim code for sharing.

**Endpoint:** `POST /api/upload`

**Request:**
```bash
curl -X POST \
  -F "file=@document.pdf" \
  -F "expires_in_hours=48" \
  -F "max_downloads=5" \
  http://localhost:8080/api/upload
```

**Parameters:**
- `file` (required): The file to upload
- `expires_in_hours` (optional): Hours until expiration (default: 24)
- `max_downloads` (optional): Maximum number of downloads (default: unlimited)

**Response (201 Created):**
```json
{
  "claim_code": "Xy9kLm8pQz4vDwE",
  "expires_at": "2025-11-06T14:30:00Z",
  "download_url": "http://localhost:8080/api/claim/Xy9kLm8pQz4vDwE",
  "max_downloads": 5,
  "file_size": 1048576,
  "original_filename": "document.pdf"
}
```

**Error Responses:**
- `400 Bad Request`: No file provided or invalid parameters
- `413 Payload Too Large`: File exceeds maximum size
- `500 Internal Server Error`: Server error

### Download File

Download a file using its claim code.

**Endpoint:** `GET /api/claim/:code`

**Request:**
```bash
curl -O http://localhost:8080/api/claim/Xy9kLm8pQz4vDwE
```

**Response (200 OK):**
- File binary data with appropriate headers
- `Content-Type`: Original file MIME type
- `Content-Disposition`: Includes original filename
- `Content-Length`: File size

**Error Responses:**
- `404 Not Found`: Claim code doesn't exist or file expired
- `410 Gone`: Download limit reached
- `500 Internal Server Error`: Server error

### Health Check

Check service health and statistics.

**Endpoint:** `GET /health`

**Request:**
```bash
curl http://localhost:8080/health
```

**Response (200 OK):**
```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "total_files": 42,
  "storage_used_bytes": 104857600,
  "disk_total_bytes": 1000000000000,
  "disk_free_bytes": 500000000000,
  "disk_available_bytes": 500000000000,
  "disk_used_percent": 50.0
}
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `DB_PATH` | `./safeshare.db` | SQLite database path |
| `UPLOAD_DIR` | `./uploads` | File storage directory |
| `MAX_FILE_SIZE` | `104857600` | Max file size in bytes (100MB) |
| `DEFAULT_EXPIRATION_HOURS` | `24` | Default expiration time in hours |
| `CLEANUP_INTERVAL_MINUTES` | `60` | Cleanup job frequency in minutes |
| `PUBLIC_URL` | (empty) | Public URL for download links (e.g., `https://share.domain.com`) - **Required for reverse proxies** |
| `ENCRYPTION_KEY` | (empty) | AES-256 encryption key (64 hex chars) - **Optional, enables encryption at rest** |
| `BLOCKED_EXTENSIONS` | `.exe,.bat,...` | Comma-separated list of blocked file extensions |
| `MAX_EXPIRATION_HOURS` | `168` | Maximum allowed expiration time in hours (default: 7 days) |
| `RATE_LIMIT_UPLOAD` | `10` | Maximum upload requests per hour per IP |
| `RATE_LIMIT_DOWNLOAD` | `100` | Maximum download requests per hour per IP |

### Reverse Proxy Support

SafeShare works seamlessly behind reverse proxies (Traefik, nginx, Caddy, Apache).

**Quick setup:**
```bash
docker run -d \
  -e PUBLIC_URL=https://share.yourdomain.com \
  -p 8080:8080 \
  safeshare:latest
```

**Auto-detection:** If `PUBLIC_URL` is not set, SafeShare auto-detects from `X-Forwarded-Proto` and `X-Forwarded-Host` headers.

**Full documentation:** See [REVERSE_PROXY.md](REVERSE_PROXY.md) for complete configuration examples with Traefik, nginx, Caddy, and Apache.

## Building from Source

### Prerequisites

- Go 1.21 or later
- Docker (for containerized builds)

### Build Binary

```bash
# Clone repository
git clone https://github.com/yourusername/safeshare
cd safeshare

# Build (requires Go installed locally)
go build -o safeshare ./cmd/safeshare

# Run
./safeshare
```

### Build Docker Image

```bash
# Build image
docker build -t safeshare:latest .

# Check image size
docker images safeshare

# Run container
docker run -d -p 8080:8080 --name safeshare safeshare:latest
```

## Architecture

```
SafeShare Application
├── HTTP Server (net/http)
│   ├── Upload Handler
│   ├── Claim Handler
│   └── Health Handler
├── SQLite Database (modernc.org/sqlite)
│   └── Pure Go implementation (no CGO)
├── File Storage
│   └── UUID-based filenames
└── Background Cleanup Worker
    └── Periodic expired file deletion
```

### Security Features

#### Data Protection
- **Encryption at rest**: AES-256-GCM encryption for stored files (optional)
- **MIME type detection**: Server-side validation prevents malware masquerading
- **File extension blacklist**: Blocks dangerous file types (executables, scripts)
- **Automatic expiration**: Files automatically deleted after expiration
- **Maximum expiration limits**: Prevents disk abuse (default: 7 days max)

#### Attack Prevention
- **Rate limiting**: IP-based protection against DoS attacks (10 uploads/hour, 100 downloads/hour)
- **Filename sanitization**: Prevents HTTP header injection and path traversal
- **Security headers**: CSP, X-Frame-Options, X-Content-Type-Options prevent XSS/clickjacking
- **Disk space monitoring**: Pre-upload checks prevent disk exhaustion
- **Input validation**: All user inputs validated and sanitized
- **Parameterized SQL queries**: Prevents SQL injection attacks
- **Timeout enforcement**: HTTP timeouts prevent slowloris attacks

#### Operational Security
- **Enhanced audit logging**: Comprehensive security event logging for compliance
- **Cryptographically secure claim codes**: Uses `crypto/rand` for code generation
- **Non-root container user**: Container runs as user ID 1000
- **File size limits**: Enforced at application and HTTP levels

**📖 For detailed security configuration, see [SECURITY.md](SECURITY.md)**

## Example Workflows

### Basic File Sharing

```bash
# Upload a file
RESPONSE=$(curl -s -X POST -F "file=@report.pdf" http://localhost:8080/api/upload)
echo $RESPONSE | jq .

# Extract claim code
CLAIM_CODE=$(echo $RESPONSE | jq -r '.claim_code')

# Share the claim code with recipient
echo "Share this code: $CLAIM_CODE"

# Recipient downloads the file
curl -O http://localhost:8080/api/claim/$CLAIM_CODE
```

### Temporary One-Time Share

```bash
# Upload with 1-hour expiration and 1 download limit
curl -X POST \
  -F "file=@sensitive-doc.pdf" \
  -F "expires_in_hours=1" \
  -F "max_downloads=1" \
  http://localhost:8080/api/upload | jq .
```

### Quick Share (Minutes)

```bash
# Upload with 30-minute expiration
curl -X POST \
  -F "file=@quick-share.txt" \
  -F "expires_in_hours=0.5" \
  http://localhost:8080/api/upload | jq .
```

## Development

### Project Structure

```
safeshare/
├── cmd/safeshare/          # Application entry point
│   └── main.go
├── internal/
│   ├── config/             # Configuration management
│   ├── database/           # Database operations
│   ├── handlers/           # HTTP request handlers
│   ├── middleware/         # HTTP middleware
│   ├── models/             # Data models
│   └── utils/              # Utility functions
├── go.mod                  # Go module definition
├── go.sum                  # Dependency checksums
├── Dockerfile              # Container build instructions
└── README.md               # This file
```

### Running Tests

```bash
# Create test file
echo "Test content" > test.txt

# Test upload
curl -X POST -F "file=@test.txt" http://localhost:8080/api/upload

# Test health
curl http://localhost:8080/health

# Test error handling
curl -X POST http://localhost:8080/api/upload
curl http://localhost:8080/api/claim/INVALID_CODE
```

## Troubleshooting

### Container won't start

Check logs:
```bash
docker logs safeshare
```

Common issues:
- Port 8080 already in use
- Insufficient permissions for data directories
- Invalid environment variable values

### Database errors

The SQLite database is created automatically. If you encounter issues:
```bash
# Remove and recreate volumes
docker stop safeshare
docker rm safeshare
docker volume rm safeshare-data
docker run -d -p 8080:8080 -v safeshare-data:/app/data -v safeshare-uploads:/app/uploads safeshare:latest
```

### File upload fails

Check:
- File size is within `MAX_FILE_SIZE` limit
- Disk space available for uploads
- Permissions on upload directory

## Performance

- **Startup time**: < 1 second
- **Memory usage**: ~10-20 MB baseline
- **Disk usage**: File size + ~1KB per file record
- **Concurrent requests**: Handles 1000+ concurrent connections
- **SQLite WAL mode**: Improved concurrency for reads/writes

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Developer Documentation

For developers working on SafeShare:
- **[CLAUDE.md](CLAUDE.md)**: Architecture overview, build commands, and development guidelines
- **[FRONTEND.md](FRONTEND.md)**: Frontend customization guide
- **[REVERSE_PROXY.md](REVERSE_PROXY.md)**: Reverse proxy configuration examples
- **[SECURITY.md](SECURITY.md)**: Enterprise security features and best practices

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourusername/safeshare/issues
- Documentation: See this README and developer docs above

## Changelog

### v1.0.0
- Initial release
- File upload with claim codes
- Automatic expiration
- Download limits
- Health check endpoint
- Docker support
- Pure Go SQLite driver (no CGO)
