# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Local Development
```bash
# Build binary
go build -o safeshare ./cmd/safeshare

# Run locally
./safeshare

# Or run directly
go run ./cmd/safeshare
```

### Docker Development
```bash
# Build Docker image
docker build -t safeshare:latest .

# Run container (basic)
docker run -d -p 8080:8080 --name safeshare safeshare:latest

# Run with enterprise security features
docker run -d -p 8080:8080 \
  -e ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  -e BLOCKED_EXTENSIONS=".exe,.bat,.cmd,.sh,.ps1,.dll,.so,.msi,.scr,.vbs,.jar" \
  -e TZ=Europe/Berlin \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  --name safeshare \
  safeshare:latest

# Rebuild and restart after changes
docker stop safeshare && docker rm safeshare
docker build -t safeshare:latest . && docker run -d -p 8080:8080 --name safeshare safeshare:latest

# View logs
docker logs -f safeshare

# View audit logs (JSON formatted)
docker logs safeshare 2>&1 | jq .
```

### Testing Endpoints
```bash
# Test upload
curl -X POST -F "file=@test.txt" -F "expires_in_hours=24" -F "max_downloads=5" \
  http://localhost:8080/api/upload

# Test file info (retrieve metadata without downloading)
curl http://localhost:8080/api/claim/<CLAIM_CODE>/info

# Test download
curl -O http://localhost:8080/api/claim/<CLAIM_CODE>

# Test health
curl http://localhost:8080/health
```

## Admin Dashboard Architecture

### Overview
The admin dashboard provides web-based administration for SafeShare. It's a fully-featured management interface with secure authentication, CSRF protection, and comprehensive file and IP management capabilities.

### Components

**Database Schema** (`internal/database/db.go`, `internal/database/admin.go`):
- `admin_sessions` table: Stores active admin sessions with expiration tracking
- `blocked_ips` table: IP blocklist with reason and timestamp tracking
- Session cleanup worker: Automatically removes expired sessions every 30 minutes

**Authentication & Security** (`internal/middleware/admin.go`):
- `AdminAuth` middleware: Validates session cookies, auto-refreshes activity timestamps
- `CSRFProtection` middleware: Validates CSRF tokens for state-changing operations
- `RateLimitAdminLogin` middleware: Limits login attempts to 5 per 15 minutes per IP
- Session management: Secure tokens generated with crypto/rand (32 bytes, base64-encoded)
- CSRF tokens: Independent tokens stored in cookies, validated on POST/PUT/DELETE/PATCH

**IP Blocking** (`internal/middleware/ipblock.go`):
- `IPBlockCheck` middleware: Applied to upload and download routes
- Checks incoming IP against blocked_ips table
- Returns HTTP 403 (Forbidden) for blocked IPs
- Logs all blocked access attempts with IP, path, method, and user agent

**Handlers** (`internal/handlers/admin.go`):
- `AdminLoginHandler`: Validates credentials, creates session, sets cookies (session + CSRF)
- `AdminLogoutHandler`: Deletes session from database and clears cookies
- `AdminDashboardDataHandler`: Returns paginated files, stats, and blocked IPs
- `AdminDeleteFileHandler`: Deletes file from database and filesystem (requires CSRF)
- `AdminBlockIPHandler`: Adds IP to blocklist (requires CSRF)
- `AdminUnblockIPHandler`: Removes IP from blocklist (requires CSRF)
- `AdminUpdateQuotaHandler`: Dynamically updates storage quota without restart (requires CSRF)

**Frontend** (`internal/static/web/admin/`):
- `login.html`: Login page with username/password form
- `dashboard.html`: Three-tab interface (Files, Blocked IPs, Settings)
- `admin.css`: Responsive design with light theme, tables, forms, modals
- `admin.js`: Handles API calls, pagination, search, confirmations, CSRF token management

### Admin Routes
All admin routes require both `ADMIN_USERNAME` and `ADMIN_PASSWORD` to be configured. Routes are conditionally registered in `main.go`:

**Public routes** (no auth):
- `GET /admin/login` - Login page
- `POST /admin/api/login` - Login endpoint (rate-limited: 5 attempts per 15 minutes)

**Protected routes** (require session):
- `GET /admin` - Redirects to /admin/dashboard
- `GET /admin/dashboard` - Dashboard page (requires AdminAuth middleware)
- `GET /admin/api/dashboard` - Dashboard data API (requires AdminAuth)
- `POST /admin/api/logout` - Logout (requires AdminAuth)

**Protected routes with CSRF** (require session + CSRF token):
- `POST /admin/api/files/delete` - Delete file (requires AdminAuth + CSRFProtection)
- `POST /admin/api/ip/block` - Block IP (requires AdminAuth + CSRFProtection)
- `POST /admin/api/ip/unblock` - Unblock IP (requires AdminAuth + CSRFProtection)
- `POST /admin/api/quota/update` - Update quota (requires AdminAuth + CSRFProtection)

**Static assets**:
- `GET /admin/assets/*` - Admin CSS/JS files (served from embedded filesystem)

### Security Features

1. **Session Management**:
   - Secure 32-byte random tokens (base64-encoded)
   - HttpOnly cookies (prevents XSS)
   - SameSite=Strict (prevents CSRF on cookies)
   - Automatic expiration based on SESSION_EXPIRY_HOURS
   - Activity tracking (last_activity updated on each request)
   - Background cleanup removes expired sessions every 30 minutes

2. **CSRF Protection**:
   - Separate CSRF tokens (not derived from session)
   - Token validation on all state-changing operations
   - Tokens stored in cookies (JavaScript-readable for inclusion in requests)
   - Tokens included in X-CSRF-Token header or csrf_token form field
   - 24-hour token lifetime

3. **Rate Limiting**:
   - Login endpoint: 5 attempts per 15 minutes per IP
   - In-memory tracking with automatic cleanup
   - Returns HTTP 429 when limit exceeded

4. **Audit Logging**:
   - All admin actions logged with structured JSON logging (slog)
   - Logged events: login, logout, file deletion, IP blocking/unblocking, quota changes
   - Each log includes: timestamp, admin IP, user agent, claim code (redacted), file details
   - Example: `{"time":"...","level":"INFO","msg":"admin deleted file","claim_code":"Jsi...ue","filename":"test.txt","size":18,"admin_ip":"172.17.0.1"}`

### Dashboard Features

**Files Tab**:
- Table view: claim code, filename, size, uploader IP, created date, expires date, downloads, password protected status
- Search: Filter by claim code, filename, or uploader IP (live search with 500ms debounce)
- Pagination: 20 items per page with page navigation
- Delete: Remove files before expiration (requires confirmation modal)

**Blocked IPs Tab**:
- Table view: IP address, reason, blocked date, blocked by
- Add: Block new IP with optional reason
- Unblock: Remove IP from blocklist (requires confirmation)

**Settings Tab**:
- Quota management: Update QUOTA_LIMIT_GB dynamically without restart
- System info: Display database path, upload directory

**Real-time Stats** (top cards):
- Total Files: Active file count
- Storage Used: Total bytes used (formatted as B/KB/MB/GB/TB)
- Quota Usage: Percentage used (or "Unlimited" if quota = 0)
- Blocked IPs: Count of blocked IPs

## Architecture Overview

### Request Flow
1. **HTTP Server** (`cmd/safeshare/main.go`): Entry point with graceful shutdown, middleware chain
2. **Middleware Chain** (`internal/middleware/`): Recovery → Logging → SecurityHeaders → RateLimit → Handler
3. **Handlers** (`internal/handlers/`): Upload, Claim (download), ClaimInfo, Health
4. **Database** (`internal/database/`): Pure Go SQLite (modernc.org/sqlite, no CGO)
5. **Storage**: Files stored with UUID filenames, optionally encrypted at rest

**Middleware Order**:
The middleware chain order is critical for security and proper logging:
```
Recovery (outermost - catches panics)
  → Logging (logs all requests with status/duration)
    → SecurityHeaders (adds CSP, X-Frame-Options, etc.)
      → RateLimit (enforces upload/download limits)
        → Handler (route-specific logic)
```

### Critical Architecture Decisions

**Route Registration Order Matters**
In `main.go`, the `/api/claim/` routes MUST be registered with logic to differentiate:
- `/api/claim/:code/info` → ClaimInfoHandler (metadata only)
- `/api/claim/:code` → ClaimHandler (download)

The handler checks `strings.HasSuffix(r.URL.Path, "/info")` to route correctly.

**Embedded Frontend**
The web UI is embedded in the binary using `//go:embed` in `internal/static/static.go`:
- Files in `internal/static/web/` are embedded at compile time
- No separate deployment needed for frontend
- Assets served via `/assets/*` route
- Frontend changes require rebuild

**Database Schema**
SQLite with WAL mode for concurrency:
- `files` table tracks metadata (claim_code, filenames, size, expiration, download limits)
- Indexes on `claim_code` (lookups) and `expires_at` (cleanup worker)
- Physical files stored separately in `UPLOAD_DIR` with UUID-based names

**Background Cleanup Worker**
Goroutine launched in `main.go` using context for cancellation:
- Runs every `CLEANUP_INTERVAL_MINUTES` (default: 60)
- Deletes expired files from both database and disk
- Gracefully cancelled on shutdown

**Enterprise Security Features**

1. **Password Protection** (`internal/utils/password.go`):
   - Optional bcrypt-hashed passwords for file downloads
   - Bcrypt cost factor: 10 (industry standard)
   - Password required at download time (claim code + password)
   - Failed attempts logged with client IP and user agent
   - Frontend automatically shows password prompt when needed
   - API: password passed as query parameter (`?password=...`)
   - Database: `password_hash TEXT` column in files table

2. **Encryption at Rest** (`internal/utils/encryption.go`):
   - AES-256-GCM authenticated encryption
   - Requires 64-character hex `ENCRYPTION_KEY` (32 bytes)
   - Nonce stored with ciphertext: `[nonce(12)][ciphertext][tag(16)]`
   - Backward compatible: encrypted and plain files coexist
   - Detection via `IsEncrypted()` checks file header

3. **File Extension Blacklist** (`internal/utils/validation.go`):
   - Blocks dangerous file types (executables, scripts)
   - Configured via `BLOCKED_EXTENSIONS` env var (comma-separated)
   - Checks both simple extensions and double extensions (e.g., `.tar.exe`)
   - Default blocks: `.exe,.bat,.cmd,.sh,.ps1,.dll,.so,.msi,.scr,.vbs,.jar,.com,.app,.deb,.rpm`

4. **Enhanced Audit Logging**:
   - JSON-structured logs via `log/slog`
   - All events include: timestamp, level, message, claim_code, filename, client_ip, user_agent
   - Security events: upload, download, blocked_extension, access_denied (with reason), incorrect_password
   - Password-protected uploads logged with `password_protected: true`
   - Client IP extracted from `X-Forwarded-For`, `X-Real-IP`, or `RemoteAddr`
   - Designed for log aggregation tools (Splunk, ELK, Datadog)

**Production Security Features** (P0 - Required for Production):

5. **Rate Limiting** (`internal/middleware/ratelimit.go`):
   - IP-based rate limiting with sliding window algorithm
   - Separate limits for uploads (default: 10/hour) and downloads (default: 100/hour)
   - Automatic cleanup of old tracking records
   - Returns HTTP 429 when limit exceeded
   - Configured via `RATE_LIMIT_UPLOAD` and `RATE_LIMIT_DOWNLOAD` env vars

6. **Filename Sanitization** (`internal/utils/sanitize.go`):
   - Prevents HTTP header injection attacks
   - Removes control characters, newlines, path separators
   - Applied to both upload handler and Content-Disposition headers
   - Limits filename length to 255 characters

7. **Security Headers** (`internal/middleware/security.go`):
   - Adds CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection
   - Prevents clickjacking, XSS, MIME sniffing attacks
   - Configured for compatibility with jsDelivr CDN (QR code library)

8. **MIME Type Detection** (`internal/handlers/upload.go`):
   - Server-side content detection using magic bytes
   - Uses `github.com/gabriel-vasile/mimetype` library
   - Ignores user-provided Content-Type header
   - Prevents malware from masquerading as safe file types

9. **Disk Space Monitoring** (`internal/utils/disk.go`):
   - Pre-upload disk space validation
   - Rejects uploads if < 1GB free or > 80% capacity
   - Health endpoint includes disk space metrics
   - Uses syscall.Statfs for Unix/Linux systems

10. **Maximum Expiration Validation** (`internal/handlers/upload.go`):
   - Enforces maximum expiration time (default: 168 hours / 7 days)
   - Prevents disk space abuse from files that never expire
   - Configured via `MAX_EXPIRATION_HOURS` env var

11. **Storage Quota Management** (`internal/database/files.go`, `internal/handlers/upload.go`):
   - Configurable per-application storage quota (default: 0 / unlimited)
   - Tracks total usage via database query: `SELECT SUM(file_size) FROM files`
   - Pre-upload validation: rejects if `current_usage + file_size > quota`
   - Returns HTTP 507 (Insufficient Storage) with usage details when quota exceeded
   - Automatic quota reclamation via cleanup worker (deletes expired files)
   - Health endpoint exposes quota metrics: `quota_limit_bytes`, `quota_used_percent`
   - Configured via `QUOTA_LIMIT_GB` env var (0 = unlimited)
   - Prevents runaway disk usage and enables multi-tenant deployments

### Configuration

All configuration via environment variables (see `internal/config/config.go`):

**Basic Configuration**:
- `PORT`: HTTP server port (default: 8080)
- `DB_PATH`: SQLite database file location (default: ./safeshare.db)
- `UPLOAD_DIR`: Directory for storing uploaded files (default: ./uploads)
- `MAX_FILE_SIZE`: Maximum file size in bytes (default: 104857600 / 100MB)
- `DEFAULT_EXPIRATION_HOURS`: Default file expiration (default: 24)
- `CLEANUP_INTERVAL_MINUTES`: How often to run cleanup worker (default: 60)
- `PUBLIC_URL`: Public-facing URL for download links (for reverse proxies, e.g., `https://share.example.com`)

**Enterprise Security**:
- `ENCRYPTION_KEY`: Optional 64-character hex key for AES-256-GCM encryption
- `BLOCKED_EXTENSIONS`: Comma-separated file extensions to block (default: `.exe,.bat,.cmd,...`)

**Production Security (P0)**:
- `MAX_EXPIRATION_HOURS`: Maximum allowed expiration time (default: 168 / 7 days)
- `RATE_LIMIT_UPLOAD`: Upload requests per hour per IP (default: 10)
- `RATE_LIMIT_DOWNLOAD`: Download requests per hour per IP (default: 100)
- `QUOTA_LIMIT_GB`: Maximum total storage quota in GB (default: 0 / unlimited)

**Admin Dashboard** (Optional):
- `ADMIN_USERNAME`: Admin username (required to enable dashboard, minimum 3 characters)
- `ADMIN_PASSWORD`: Admin password (required to enable dashboard, minimum 8 characters)
- `SESSION_EXPIRY_HOURS`: Admin session expiration time (default: 24 hours)

**Note on Timestamps**: Logs use UTC timestamps (RFC3339 with `Z` suffix) regardless of TZ setting. This is industry standard for server applications and makes log correlation across timezones easier.

**Validation**:
The config validates encryption key format (64 hex chars), normalizes blocked extensions (adds `.` prefix, lowercases), and ensures rate limits and expiration values are positive.

### Frontend Architecture

**Tab-Based UI** (`internal/static/web/`):
- **Dropoff Tab**: File upload with drag-drop, QR code generation, expiration/download limit controls
- **Pickup Tab**: Claim code input → retrieve file info → download button

**Two-Step Download Flow**:
1. User enters claim code → API call to `/api/claim/:code/info`
2. Display file metadata (name, size, downloads remaining, expiration)
3. User clicks download → `window.open(download_url, '_blank')` to trigger browser save dialog

This gives users control over download location (no automatic download).

**Theme Toggle**: Dark/light mode with localStorage persistence (reduced size: 2rem, opacity: 0.7 for less intrusiveness).

### Key Dependencies

- **modernc.org/sqlite**: Pure Go SQLite implementation (no CGO required)
- **github.com/google/uuid**: UUID generation for stored filenames
- **github.com/gabriel-vasile/mimetype**: Server-side MIME type detection from file content
- **Standard library**: HTTP server, crypto (AES-256-GCM), logging (slog), file I/O

No external web frameworks or ORMs. Minimal dependencies for security and portability.

## Common Development Tasks

### Adding New API Endpoints

1. Create handler function in `internal/handlers/` (signature: `func(db *sql.DB, cfg *config.Config) http.HandlerFunc`)
2. Register route in `cmd/safeshare/main.go` (before middleware wrapping)
3. If modifying frontend, update `internal/static/web/` files
4. Rebuild Docker image to embed frontend changes

### Modifying Database Schema

1. Update schema in `internal/database/db.go`
2. Update model structs in `internal/models/`
3. Update query functions in `internal/database/files.go`
4. Consider migration strategy for existing deployments (SQLite doesn't support all ALTER operations)

### Frontend Changes

**Important**: Frontend is embedded at compile time. Changes require:
1. Edit files in `internal/static/web/`
2. Rebuild Go binary or Docker image
3. Restart application

Files are NOT read from disk at runtime.

### Security Considerations

When adding features:
- **Always** validate user input (see `internal/utils/validation.go`)
- Use parameterized SQL queries (no string concatenation)
- Log security events with client IP and user agent (use `getClientIP()` and `getUserAgent()` from `internal/handlers/helpers.go`)
- For file operations, read into memory first (safe within MAX_FILE_SIZE), then encrypt before writing
- Check file extensions against blacklist before processing uploads
- Return appropriate HTTP status codes (404 for not found, 410 for download limit reached, 413 for file too large)

### Reverse Proxy Configuration

SafeShare is designed to run behind reverse proxies (Traefik, nginx, Caddy, Apache):
- Set `PUBLIC_URL` environment variable to public-facing URL
- Proxy should set `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` headers
- SafeShare auto-detects protocol/host from these headers if `PUBLIC_URL` not set
- Client IP extraction prioritizes: `X-Forwarded-For` → `X-Real-IP` → `RemoteAddr`

See `REVERSE_PROXY.md` for detailed proxy configurations.

## Troubleshooting

### Encryption Issues
- Key must be exactly 64 hexadecimal characters (32 bytes for AES-256)
- Generate key: `openssl rand -hex 32`
- Lost key = lost files (no recovery possible)
- Check logs for "failed to decrypt file" errors (indicates wrong key or corrupted data)

### Container Issues
- Check logs: `docker logs safeshare`
- Verify health: `docker inspect safeshare | jq '.[0].State.Health'`
- Common issues: port conflicts, volume permissions, invalid env vars

### Frontend Not Updating
- Frontend is embedded at compile time
- Must rebuild Docker image after frontend changes
- Clear browser cache if seeing old UI
