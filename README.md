# SafeShare - Secure Temporary File Sharing

[![Tests](https://github.com/fjmerc/safeshare/actions/workflows/build-and-push.yml/badge.svg)](https://github.com/fjmerc/safeshare/actions/workflows/build-and-push.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/fjmerc/safeshare)](https://goreportcard.com/report/github.com/fjmerc/safeshare)

A self-hosted secure file sharing service for temporary transfers with automatic expiration, cryptographically secure claim codes, and enterprise-grade security features.

**Version**: 1.4.1

## Screenshots

### Main Interface
![SafeShare Main Interface](docs/screenshots/main.png)
*Modern web interface with drag-drop upload, QR codes, dark mode, and PWA support*

### Admin Dashboard
![Admin Dashboard](docs/screenshots/admin-dashboard.png)
*Comprehensive admin dashboard for file management, user administration, and system configuration*

### User Dashboard
![User Dashboard](docs/screenshots/user-dashboard.png)
*User dashboard for viewing upload history, managing files, and sharing with advanced features*

### Admin Login (Dark Theme)
![Admin Login Dark Theme](docs/screenshots/admin-login-dark.png)
*Beautiful dark mode with gradient background for admin authentication*

---

## Key Features

###  Core Capabilities
- **Chunked/Resumable Uploads** - Large file support (>100MB) with pause/resume
- **Resumable Downloads** - Browser-based download resume with progress tracking
- **HTTP/2 Support** - Optimized performance with 250 concurrent streams
- **Progressive Web App (PWA)** - Installable app with offline support
- **Automatic Expiration** - Files auto-delete after configurable time
- **Download Limits** - Optional max downloads per file
- **Password Protection** - Optional bcrypt-hashed passwords for files
- **Claim Codes** - Cryptographically secure, URL-safe identifiers
- **QR Code Generation** - One-click QR codes for mobile sharing
- **File Checksums** - SHA256 hashes for integrity verification

### 🔒 Security Features
- **Encryption at Rest** - AES-256-GCM authenticated encryption
- **User Authentication** - Invite-only registration with role-based access
- **Admin Dashboard** - Web-based administration with CSRF protection
- **IP Blocking** - Block malicious IPs from uploads/downloads
- **Rate Limiting** - IP-based DoS protection (configurable limits)
- **File Extension Blacklist** - Blocks dangerous file types (executables, scripts)
- **Trusted Proxy Validation** - Smart proxy header validation (anti-spoofing)
- **Security Headers** - CSP, X-Frame-Options, X-Content-Type-Options
- **MIME Type Detection** - Server-side content validation
- **Storage Quotas** - Configurable per-application limits
- **Audit Logging** - Comprehensive JSON-structured logs

### 👥 User Management
- **Invite-Only Registration** - Admin-managed user accounts
- **User Dashboard** - View uploads, manage files, share with advanced features
- **File Management** - Rename files, edit expiration, regenerate claim codes
- **Session Management** - Secure httpOnly cookies with configurable expiry
- **Temporary Passwords** - Forced password change on first login
- **Role-Based Access** - User and admin roles with different permissions
- **Anonymous Uploads** - Configurable (enabled by default, can require authentication)

### 🎛️ Admin Dashboard
- **File Management** - View all files, search, bulk delete, download statistics
- **User Administration** - Create, edit, enable/disable, reset passwords
- **IP Blocking** - Block/unblock IPs with reason tracking
- **Dynamic Settings** - Adjust quotas, limits, security settings without restart
- **Configuration Assistant** - Intelligent config recommendations based on environment
- **Real-Time Statistics** - Storage usage, file counts, user counts, quota metrics
- **Partial Upload Management** - Monitor and cleanup abandoned chunked uploads

### 📊 Monitoring & Operations
- **Health Check Endpoints** - Comprehensive, liveness, and readiness probes
- **Prometheus Metrics** - Full metrics export for monitoring and alerting
- **Structured Logging** - JSON logs for aggregation tools (ELK, Splunk, Datadog)
- **Graceful Shutdown** - Safe container stop with request completion
- **Background Workers** - Auto-cleanup of expired files and abandoned uploads
- **Database Migrations** - Automatic schema versioning and upgrades

### 🚀 Deployment
- **Single Binary** - No external dependencies (pure Go, embedded SQLite)
- **Docker Container** - Minimal ~26MB Alpine-based image
- **Reverse Proxy Ready** - Works with Traefik, nginx, Caddy, Apache
- **CDN Compatible** - Supports Cloudflare and other CDNs
- **No CGO Required** - Portable across architectures (amd64, arm64)

---

## Quick Start

### Web UI

Simply visit the root URL after starting the server:

```
http://localhost:8080/              # Main upload interface
http://localhost:8080/admin/login   # Admin dashboard (if configured)
http://localhost:8080/login         # User login
```

Features drag-drop upload, QR code generation, PWA installation, and one-click sharing!

### Docker

```bash
# Basic deployment (anonymous uploads)
docker run -d \
  -p 8080:8080 \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  --name safeshare \
  fjmerc/safeshare:latest

# Production deployment with encryption and admin dashboard
docker run -d \
  -p 8080:8080 \
  -e ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD="YourSecurePassword123!" \
  -e QUOTA_LIMIT_GB=100 \
  -e TZ=Europe/Berlin \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  --name safeshare \
  fjmerc/safeshare:latest

# Visit http://localhost:8080/admin/login
```

### Binary

```bash
# Download latest release
wget https://github.com/fjmerc/safeshare/releases/latest/download/safeshare-linux-amd64

# Make executable
chmod +x safeshare-linux-amd64

# Run (uses default settings)
./safeshare-linux-amd64

# Or with custom configuration
export MAX_FILE_SIZE=209715200  # 200MB
export DEFAULT_EXPIRATION_HOURS=48
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=admin123
./safeshare-linux-amd64
```

---

## API Quick Start

### Simple Upload & Download

```bash
# Upload a file
curl -X POST -F "file=@document.pdf" \
  http://localhost:8080/api/upload | jq .

# Response includes claim code
{
  "claim_code": "Xy9kLm8pQz4vDwE",
  "download_url": "http://localhost:8080/api/claim/Xy9kLm8pQz4vDwE",
  "expires_at": "2025-11-22T10:00:00Z",
  "file_size": 1048576
}

# Download the file
curl -O http://localhost:8080/api/claim/Xy9kLm8pQz4vDwE
```

### With Options

```bash
# Upload with expiration, download limit, and password
curl -X POST \
  -F "file=@sensitive.pdf" \
  -F "expires_in_hours=24" \
  -F "max_downloads=1" \
  -F "password=secret123" \
  http://localhost:8080/api/upload | jq .

# Download with password
curl -O "http://localhost:8080/api/claim/Xy9kLm8pQz4vDwE?password=secret123"
```

### Get File Info (Without Downloading)

```bash
# Check file metadata
curl "http://localhost:8080/api/claim/Xy9kLm8pQz4vDwE/info" | jq .

# Response
{
  "claim_code": "Xy9kLm8pQz4vDwE",
  "original_filename": "document.pdf",
  "file_size": 1048576,
  "downloads_remaining": 4,
  "expires_at": "2025-11-22T10:00:00Z",
  "password_protected": false,
  "sha256_hash": "a3b2c1d4..."
}
```

**📖 Full API Documentation**: See [docs/API_REFERENCE.md](docs/API_REFERENCE.md) for complete endpoint details, authentication, user management, admin operations, health checks, and Prometheus metrics.

---

## Configuration

SafeShare is configured via environment variables. Common settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `MAX_FILE_SIZE` | `104857600` | Max file size in bytes (100MB) |
| `DEFAULT_EXPIRATION_HOURS` | `24` | Default file expiration |
| `ENCRYPTION_KEY` | (empty) | AES-256 key (64 hex chars) - enables encryption |
| `ADMIN_USERNAME` | (empty) | Admin username - enables dashboard |
| `ADMIN_PASSWORD` | (empty) | Admin password (min 8 chars) |
| `REQUIRE_AUTH_FOR_UPLOAD` | `false` | Require user authentication for uploads |
| `QUOTA_LIMIT_GB` | `0` | Storage quota in GB (0 = unlimited) |
| `RATE_LIMIT_UPLOAD` | `10` | Uploads per hour per IP |
| `RATE_LIMIT_DOWNLOAD` | `50` | Downloads per hour per IP |
| `PUBLIC_URL` | (empty) | Public URL for download links (e.g., `https://share.domain.com`) |
| `DOWNLOAD_URL` | (empty) | Separate URL for downloads (bypasses CDN timeouts) |
| `CHUNKED_UPLOAD_ENABLED` | `true` | Enable chunked uploads |
| `CHUNK_SIZE` | `10485760` | Chunk size in bytes (10MB) |
| `READ_TIMEOUT` | `120` | HTTP read timeout (seconds) |
| `WRITE_TIMEOUT` | `120` | HTTP write timeout (seconds) |
| `TZ` | `UTC` | Timezone for container |

**Advanced Configuration**:
- `TRUST_PROXY_HEADERS` - Proxy header validation (`auto`, `true`, `false`)
- `TRUSTED_PROXY_IPS` - Comma-separated trusted proxy IPs/CIDR ranges
- `MAX_EXPIRATION_HOURS` - Maximum allowed expiration (default: 168 hours / 7 days)
- `BLOCKED_EXTENSIONS` - Comma-separated blocked file extensions
- `DB_PATH`, `UPLOAD_DIR`, `CLEANUP_INTERVAL_MINUTES`, `SESSION_EXPIRY_HOURS`
- `CHUNKED_UPLOAD_THRESHOLD`, `PARTIAL_UPLOAD_EXPIRY_HOURS`, `HTTPS_ENABLED`

**💡 Configuration Assistant**: The admin dashboard includes an intelligent configuration assistant that analyzes your deployment environment and provides optimized settings recommendations.

---

## Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

| Document | Description |
|----------|-------------|
| **[API_REFERENCE.md](docs/API_REFERENCE.md)** | Complete API documentation with all endpoints, authentication, and examples |
| **[SECURITY.md](docs/SECURITY.md)** | Enterprise security features, encryption, admin dashboard security, best practices |
| **[CHUNKED_UPLOAD.md](docs/CHUNKED_UPLOAD.md)** | Chunked/resumable upload API, architecture, client implementation guide |
| **[REVERSE_PROXY.md](docs/REVERSE_PROXY.md)** | Reverse proxy configuration (Traefik, nginx, Caddy, Apache) |
| **[PROMETHEUS.md](docs/PROMETHEUS.md)** | Prometheus metrics, Grafana dashboards, alerting rules |
| **[HTTP_RANGE_SUPPORT.md](docs/HTTP_RANGE_SUPPORT.md)** | Resumable downloads, HTTP Range requests (RFC 7233) |
| **[PRODUCTION.md](docs/PRODUCTION.md)** | Production deployment guide with security hardening |
| **[INFRASTRUCTURE_PLANNING.md](docs/INFRASTRUCTURE_PLANNING.md)** | CDN timeouts, upload speed testing, configuration planning |
| **[FRONTEND.md](docs/FRONTEND.md)** | Web UI features, customization guide, browser compatibility |
| **[TESTING.md](docs/TESTING.md)** | Testing guide, test suite, coverage requirements |
| **[VERSION_STRATEGY.md](docs/VERSION_STRATEGY.md)** | Semantic versioning, Git Flow, release process |
| **[CHANGELOG.md](docs/CHANGELOG.md)** | Complete version history with all changes |
| **[CLAUDE.md](CLAUDE.md)** | Developer guide, architecture overview, build commands |

**Quick Links**:
- 🔐 [Encryption Setup](docs/SECURITY.md#encryption-at-rest)
- 🎛️ [Admin Dashboard](docs/SECURITY.md#admin-dashboard-security)
- 📊 [Monitoring Setup](docs/PROMETHEUS.md)
- 🔧 [Reverse Proxy Config](docs/REVERSE_PROXY.md)
- 📱 [PWA Features](docs/FRONTEND.md#progressive-web-app-pwa)

---

## Architecture

```
SafeShare Application
├── HTTP Server (net/http) with HTTP/2 support
│   ├── Public API: Upload, Download, Claim Info, Health, Metrics
│   ├── Chunked Upload: Init, Chunk, Complete, Status
│   ├── User Auth: Login, Logout, Dashboard, File Management
│   └── Admin Dashboard: Files, Users, IPs, Settings, Config Assistant
├── SQLite Database (modernc.org/sqlite - pure Go, no CGO)
│   ├── Tables: files, users, sessions, partial_uploads, blocked_ips, settings
│   └── Migrations: Automatic schema versioning (6 migrations)
├── File Storage
│   ├── Completed files: UUID filenames (encrypted if ENCRYPTION_KEY set)
│   └── Partial uploads: .partial/{upload_id}/chunk_{number}
├── Middleware
│   ├── Authentication (user & admin), IP Blocking, Rate Limiting
│   ├── CSRF Protection, Security Headers, Logging, Metrics Collection
│   └── Proxy Header Validation (anti-spoofing)
└── Background Workers
    ├── Expired File Cleanup (configurable interval)
    ├── Partial Upload Cleanup (abandoned uploads)
    ├── Assembly Recovery (interrupted chunked uploads)
    └── Session Cleanup (expired auth sessions)
```

**Key Technologies**:
- **Go 1.21+** - Single binary, no external dependencies
- **SQLite** - Embedded database with WAL mode (modernc.org/sqlite)
- **HTTP/2** - Concurrent stream multiplexing (h2c support)
- **Embedded Frontend** - HTML/CSS/JS bundled in binary (27KB total)
- **Service Worker** - PWA with offline support

---

## Building from Source

### Prerequisites
- Go 1.21 or later
- Docker (optional, for containerized builds)

### Build Binary

```bash
# Clone repository
git clone https://github.com/fjmerc/safeshare
cd safeshare

# Build
go build -o safeshare ./cmd/safeshare

# Run
./safeshare
```

### Build Docker Image

```bash
# Build image
docker build -t safeshare:latest .

# Check image size (~26MB)
docker images safeshare

# Run container
docker run -d -p 8080:8080 --name safeshare safeshare:latest
```

---

## Performance

- **Startup time**: < 1 second
- **Memory usage**: ~10-20 MB baseline
- **Disk usage**: File size + ~2KB per file record
- **Concurrent requests**: 1000+ concurrent connections
- **SQLite optimizations**: WAL mode, performance indexes, temp_store=MEMORY
- **Chunked upload**: 250 concurrent streams (HTTP/2)
- **Encryption throughput**: ~50-60 MB/s (tested on ARM VPS)

---

## Security Best Practices

🔒 **Production Deployments**:
1. **Always use encryption**: Set `ENCRYPTION_KEY` (64 hex chars)
2. **Enable admin authentication**: Set `ADMIN_USERNAME` and `ADMIN_PASSWORD`
3. **Use HTTPS**: Configure reverse proxy with TLS certificates
4. **Set storage quota**: Use `QUOTA_LIMIT_GB` to prevent disk abuse
5. **Configure rate limits**: Adjust `RATE_LIMIT_UPLOAD` and `RATE_LIMIT_DOWNLOAD`
6. **Block dangerous extensions**: Customize `BLOCKED_EXTENSIONS`
7. **Use trusted proxies only**: Configure `TRUST_PROXY_HEADERS=auto` (default)
8. **Enable audit logging**: Forward logs to SIEM/log aggregation
9. **Monitor metrics**: Set up Prometheus + Grafana dashboards
10. **Regular backups**: Backup database and encryption key securely

**📖 Security Guide**: See [docs/SECURITY.md](docs/SECURITY.md) for complete security documentation, compliance mapping (HIPAA, SOC 2, GDPR, PCI-DSS), and security audit checklist.

---

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker logs safeshare

# Common issues:
# - Port 8080 already in use
# - Insufficient volume permissions
# - Invalid environment variables
```

### Upload Fails

Check:
- File size is within `MAX_FILE_SIZE` limit
- Disk space available (requires >1GB free)
- Storage quota not exceeded
- File extension not in `BLOCKED_EXTENSIONS`
- Rate limit not exceeded

### Large Files Timeout

For files >100MB:
- Ensure `CHUNKED_UPLOAD_ENABLED=true` (default)
- Increase `READ_TIMEOUT` and `WRITE_TIMEOUT` if needed
- Configure `DOWNLOAD_URL` to bypass CDN timeouts
- See [docs/INFRASTRUCTURE_PLANNING.md](docs/INFRASTRUCTURE_PLANNING.md)

### Database Issues

```bash
# Reset database (CAUTION: deletes all data)
docker stop safeshare
docker rm safeshare
docker volume rm safeshare-data
docker run -d -p 8080:8080 \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  safeshare:latest
```

---

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following Git Flow ([docs/VERSION_STRATEGY.md](docs/VERSION_STRATEGY.md))
4. Add tests if applicable (minimum 60% coverage)
5. Update documentation (README, CHANGELOG, API docs)
6. Submit a pull request to `develop` branch

**Development Guide**: See [CLAUDE.md](CLAUDE.md) for architecture overview, build commands, testing procedures, and Git Flow workflow.

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

## Changelog

See [docs/CHANGELOG.md](docs/CHANGELOG.md) for complete version history.

**Latest Release (v1.4.0)**:
- Code quality improvements: reduced cyclomatic complexity in key functions
- Applied gofmt -s simplifications across 57 Go files
- All features from previous versions preserved (see CHANGELOG for version reset notice)

---

## Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/fjmerc/safeshare/issues)
- **Documentation**: See [docs/](docs/) directory
- **Security Issues**: See [SECURITY.md](docs/SECURITY.md) for responsible disclosure

---

**Built with ❤️ using Go**
