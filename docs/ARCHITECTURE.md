# SafeShare Architecture Documentation

This document provides detailed technical documentation about SafeShare's architecture, components, and implementation details.

## Table of Contents
- [User Authentication Architecture](#user-authentication-architecture)
- [Admin Dashboard Architecture](#admin-dashboard-architecture)
- [Core Architecture Overview](#core-architecture-overview)
- [Configuration](#configuration)
- [Settings Persistence](#settings-persistence)
- [Frontend Architecture](#frontend-architecture)
- [Chunked Upload Architecture](#chunked-upload-architecture)
- [Webhook Architecture](#webhook-architecture)
- [Key Dependencies](#key-dependencies)

---

## User Authentication Architecture

### Overview
SafeShare implements a comprehensive user authentication system with invite-only registration, role-based access control, and secure session management. Users can track their uploads, manage their files, and admins can manage user accounts.

### Components

**Database Schema** (`internal/database/db.go`, `internal/database/users.go`):
- `users` table: Stores user accounts with username, email, password_hash, role, is_active, require_password_change
- `user_sessions` table: Stores active user sessions with expiration tracking
- `files.user_id`: Foreign key linking files to users (nullable for anonymous uploads)
- Session cleanup worker: Automatically removes expired user sessions

**Authentication & Security** (`internal/middleware/user_auth.go`):
- `UserAuth` middleware: Validates user session cookies, requires authentication
- `OptionalUserAuth` middleware: Adds user to context if authenticated, allows anonymous access
- Session management: Secure tokens generated with crypto/rand (32 bytes, base64-encoded)
- Password security: Bcrypt hashing with cost factor 10
- Temporary passwords: New users forced to change password on first login

**Handlers** (`internal/handlers/user_auth.go`, `internal/handlers/user_dashboard.go`, `internal/handlers/admin_users.go`):

*User Authentication:*
- `UserLoginHandler`: Validates credentials, creates session, sets cookies, returns user info
- `UserLogoutHandler`: Deletes session from database and clears cookies
- `UserGetCurrentHandler`: Returns current authenticated user info
- `UserChangePasswordHandler`: Allows users to change their password (validates old password)

*User Dashboard:*
- `UserDashboardDataHandler`: Returns paginated list of user's uploaded files
- `UserDeleteFileHandler`: Allows users to delete their own files (ownership validation)

*Admin User Management:*
- `AdminCreateUserHandler`: Creates new user with optional or auto-generated temporary password
- `AdminListUsersHandler`: Returns paginated list of all users with file counts
- `AdminUpdateUserHandler`: Updates user profile (username, email, role)
- `AdminToggleUserActiveHandler`: Enable/disable user accounts
- `AdminResetUserPasswordHandler`: Generates new temporary password for user
- `AdminDeleteUserHandler`: Permanently deletes user account

**Frontend** (`internal/static/web/`):
- `login.html`: User login page with username/password form, auto-redirect if logged in
- `dashboard.html`: User dashboard with file listing, delete functionality, password change modal
- `index.html`: Homepage with user status bar showing login/logout state
- `admin/dashboard.html`: Added Users tab for admin user management

### User Routes

**Public routes** (no auth):
- `GET /login` - User login page
- `POST /api/auth/login` - User login endpoint (JSON: {username, password})

**Protected routes** (require user session):
- `GET /dashboard` - User dashboard page (requires UserAuth middleware)
- `GET /api/auth/user` - Get current user info (requires UserAuth)
- `POST /api/auth/logout` - User logout (requires UserAuth)
- `POST /api/auth/change-password` - Change password (requires UserAuth)
- `GET /api/user/files` - Get user's uploaded files (requires UserAuth)
- `DELETE /api/user/files/delete` - Delete user's own file (requires UserAuth)

**Upload route** (optional auth):
- `POST /api/upload` - Upload file (uses OptionalUserAuth - tracks user_id if authenticated)

**Admin user management routes** (require admin session + CSRF):
- `POST /admin/api/users/create` - Create new user
- `GET /admin/api/users` - List all users with pagination
- `PUT /admin/api/users/:id` - Update user profile
- `POST /admin/api/users/:id/enable` - Enable user account
- `POST /admin/api/users/:id/disable` - Disable user account
- `POST /admin/api/users/:id/reset-password` - Reset user password
- `DELETE /admin/api/users/:id` - Delete user account

### User Authentication Features

1. **Invite-Only Registration**: No public registration endpoint, only admins can create accounts
2. **Temporary Password Flow**: Auto-generated passwords with forced change on first login
3. **Session Management**: Separate session tables, HttpOnly cookies, SameSite=Strict
4. **File Ownership**: Authenticated uploads tracked by user_id
5. **Role-Based Access**: User role (limited) vs Admin role (full access)
6. **Audit Logging**: All authentication events logged with IP and user agent

### User Dashboard Features

**File Management**:
- Table view with claim code, filename, size, dates, download counts
- Copy download link with one-click clipboard support
- Delete file with confirmation modal
- Empty state messaging

**Password Change**:
- Modal dialog requiring current password
- New password confirmation
- Clears require_password_change flag

**UI/UX Enhancements**:
- Responsive header layout with four action buttons
- Compact button styling optimized for horizontal space
- Cross-browser clipboard support with fallback
- Enhanced date formatting (compact display)
- Comprehensive mobile responsiveness

---

## Admin Dashboard Architecture

### Overview
The admin dashboard provides web-based administration for SafeShare with secure authentication, CSRF protection, comprehensive file/IP management, and full user account management.

### Components

**Database Schema** (`internal/database/db.go`, `internal/database/admin.go`):
- `admin_credentials` table: Stores admin username and bcrypt-hashed password (single row with id=1)
- `admin_sessions` table: Stores active admin sessions with expiration tracking
- `blocked_ips` table: IP blocklist with reason and timestamp tracking
- Session cleanup worker: Automatically removes expired admin sessions every 30 minutes

**Authentication & Security** (`internal/middleware/admin.go`):
- `AdminAuth` middleware: Validates session cookies, supports both admin_session and user_session (with admin role)
- `CSRFProtection` middleware: Validates CSRF tokens for state-changing operations
- `RateLimitAdminLogin` middleware: Limits login attempts to 5 per 15 minutes per IP
- Dual authentication: Admin dashboard accessible via admin credentials OR user accounts with admin role

**IP Blocking** (`internal/middleware/ipblock.go`):
- `IPBlockCheck` middleware: Applied to upload and download routes
- Checks incoming IP against blocked_ips table
- Returns HTTP 403 (Forbidden) for blocked IPs

**Handlers** (`internal/handlers/admin.go`, `internal/handlers/admin_users.go`):

*Admin Authentication:*
- `AdminLoginHandler`: Validates credentials, falls back to users table with admin role check
- `AdminLogoutHandler`: Deletes session and clears cookies

*Admin Dashboard:*
- `AdminDashboardDataHandler`: Returns paginated files, stats, blocked IPs, user counts

*Admin File Management:*
- `AdminDeleteFileHandler`: Deletes file from database and filesystem (requires CSRF)

*Admin IP Management:*
- `AdminBlockIPHandler`: Adds IP to blocklist (requires CSRF)
- `AdminUnblockIPHandler`: Removes IP from blocklist (requires CSRF)

*Admin Settings:*
- `AdminUpdateQuotaHandler`: Dynamically updates storage quota without restart (requires CSRF)
- `AdminChangePasswordHandler`: Changes admin password without restart (requires CSRF)

*Admin User Management:*
- `AdminCreateUserHandler`: Creates new user with optional or auto-generated temporary password
- `AdminListUsersHandler`: Returns paginated list of all users with file counts
- `AdminUpdateUserHandler`: Updates user profile (username, email, role)
- `AdminToggleUserActiveHandler`: Enable/disable user accounts
- `AdminResetUserPasswordHandler`: Generates new temporary password for user
- `AdminDeleteUserHandler`: Permanently deletes user account

**Frontend** (`internal/static/web/admin/`):
- `login.html`: Login page with username/password form
- `dashboard.html`: Four-tab interface (Files, Users, Blocked IPs, Settings)
- `admin.css`: Responsive design with light theme
- `admin.js`: Handles API calls, pagination, search, confirmations

### Admin Routes

**Public routes** (no auth):
- `GET /admin/login` - Login page
- `POST /admin/api/login` - Login endpoint (rate-limited: 5 attempts per 15 minutes)

**Protected routes** (require session):
- `GET /admin/dashboard` - Dashboard page
- `GET /admin/api/dashboard` - Dashboard data API
- `POST /admin/api/logout` - Logout

**Protected routes with CSRF** (require session + CSRF token):
- File management: `POST /admin/api/files/delete`
- IP management: `POST /admin/api/ip/block`, `POST /admin/api/ip/unblock`
- Settings: `POST /admin/api/quota/update`, `POST /admin/api/settings/password`
- User management: `POST /admin/api/users/create`, `PUT /admin/api/users/:id`, `DELETE /admin/api/users/:id`, etc.

### Security Features

1. **Session Management**: Secure 32-byte random tokens, HttpOnly cookies, SameSite=Strict
2. **CSRF Protection**: Separate CSRF tokens, token validation on all state-changing operations
3. **Rate Limiting**: 5 login attempts per 15 minutes per IP
4. **Audit Logging**: All admin actions logged with structured JSON logging

### Dashboard Features

**Files Tab**: Table view with search, pagination, delete functionality
**Users Tab**: User management with create, edit, enable/disable, reset password, delete
**Blocked IPs Tab**: IP blocklist with add/unblock functionality
**Settings Tab**: Dynamic settings updates (storage, security, password, system info)
**Real-time Stats**: Total files, storage used, quota usage, blocked IPs, total users

---

## Core Architecture Overview

### Request Flow
1. **HTTP Server** (`cmd/safeshare/main.go`): Entry point with graceful shutdown
2. **Middleware Chain**: Recovery → Logging → SecurityHeaders → RateLimit → Handler
3. **Handlers** (`internal/handlers/`): Upload, Claim, ClaimInfo, Health
4. **Database** (`internal/database/`): Pure Go SQLite (modernc.org/sqlite, no CGO)
5. **Storage**: Files stored with UUID filenames, optionally encrypted at rest

**Middleware Order**:
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
- `files` table: Tracks metadata (claim_code, filenames, size, expiration, download limits, user_id)
- `partial_uploads` table: Tracks chunked upload sessions
- `migrations` table: Tracks applied database schema migrations
- `users` table: Stores user accounts
- `user_sessions` / `admin_sessions` tables: Store active sessions
- `admin_credentials` table: Stores admin credentials (single row with id=1)
- `blocked_ips` table: IP blocklist
- Indexes on `claim_code`, `expires_at`, `username`, `email`
- Foreign keys for user relationships

**Background Cleanup Workers**
Goroutines launched in `main.go` using context for cancellation:

*File Cleanup Worker:* Runs every `CLEANUP_INTERVAL_MINUTES` (default: 60), deletes expired files
*Partial Upload Cleanup Worker:* Runs every 6 hours, deletes abandoned partial uploads
*Session Cleanup Worker:* Runs every 30 minutes, removes expired sessions

**Enterprise Security Features**

1. **Password Protection**: Optional bcrypt-hashed passwords for file downloads
2. **Encryption at Rest**: AES-256-GCM authenticated encryption
3. **File Extension Blacklist**: Blocks dangerous file types
4. **Enhanced Audit Logging**: JSON-structured logs via `log/slog`

**Production Security Features** (P0 - Required for Production):

5. **Rate Limiting**: IP-based rate limiting with sliding window algorithm
6. **Filename Sanitization**: Prevents HTTP header injection attacks
7. **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection
8. **MIME Type Detection**: Server-side content detection using magic bytes
9. **Disk Space Monitoring**: Pre-upload disk space validation
10. **Maximum Expiration Validation**: Enforces maximum expiration time
11. **Storage Quota Management**: Configurable per-application storage quota
12. **HTTP Range Request Support**: Enables resumable downloads and partial content delivery

---

## Configuration

All configuration via environment variables (see `internal/config/config.go`):

### Basic Configuration
- `PORT`: HTTP server port (default: 8080)
- `DB_PATH`: SQLite database file location (default: ./safeshare.db)
- `UPLOAD_DIR`: Directory for storing uploaded files (default: ./uploads)
- `MAX_FILE_SIZE`: Maximum file size in bytes (default: 104857600 / 100MB)
- `DEFAULT_EXPIRATION_HOURS`: Default file expiration (default: 24)
- `CLEANUP_INTERVAL_MINUTES`: How often to run cleanup worker (default: 60)
- `PUBLIC_URL`: Public-facing URL for download links (e.g., `https://share.example.com`)
- `DOWNLOAD_URL`: Optional separate URL for download links to bypass CDN timeouts

### Enterprise Security
- `ENCRYPTION_KEY`: Optional 64-character hex key for AES-256-GCM encryption
- `BLOCKED_EXTENSIONS`: Comma-separated file extensions to block

### Production Security (P0)
- `MAX_EXPIRATION_HOURS`: Maximum allowed expiration time (default: 168 / 7 days)
- `RATE_LIMIT_UPLOAD`: Upload requests per hour per IP (default: 10)
- `RATE_LIMIT_DOWNLOAD`: Download requests per hour per IP (default: 100)
- `QUOTA_LIMIT_GB`: Maximum total storage quota in GB (default: 0 / unlimited)

### Trusted Proxy Security
- `TRUST_PROXY_HEADERS`: Controls whether to trust X-Forwarded-For and X-Real-IP headers (default: "auto")
  - "auto" - Only trust headers from RFC1918 + localhost IPs (recommended)
  - "true" - Always trust proxy headers (use only behind trusted reverse proxy)
  - "false" - Never trust proxy headers (use for direct internet exposure)
- `TRUSTED_PROXY_IPS`: Comma-separated list of trusted proxy IPs/CIDR ranges

### Chunked Upload (v2.0.0+)
- `CHUNKED_UPLOAD_ENABLED`: Enable/disable chunked upload support (default: true)
- `CHUNKED_UPLOAD_THRESHOLD`: Files >= this size use chunked upload in bytes (default: 100MB)
- `CHUNK_SIZE`: Size of each chunk in bytes (default: 5MB)
- `PARTIAL_UPLOAD_EXPIRY_HOURS`: Hours before abandoned uploads are cleaned up (default: 24)

### Admin Dashboard (Optional)
- `ADMIN_USERNAME`: Admin username (required to enable dashboard, minimum 3 characters)
- `ADMIN_PASSWORD`: Admin password (required to enable dashboard, minimum 8 characters)
- `SESSION_EXPIRY_HOURS`: Admin session expiration time (default: 24 hours)

**Note on Timestamps**: Logs use UTC timestamps (RFC3339 with `Z` suffix) regardless of TZ setting.

**Validation**: The config validates encryption key format (64 hex chars), normalizes blocked extensions (adds `.` prefix, lowercases), and ensures rate limits and expiration values are positive.

---

## Settings Persistence

Starting with v1.1.0, admin-configurable settings persist to the database and override environment variables on startup.

### Database Schema
`settings` table stores 7 admin-configurable settings:
- quota_limit_gb
- max_file_size_bytes
- default_expiration_hours
- max_expiration_hours
- rate_limit_upload
- rate_limit_download
- blocked_extensions (TEXT, comma-separated)

### How It Works
1. **First startup**: No settings in database → uses environment variable values
2. **Admin changes setting**: Handler updates in-memory config AND persists to database
3. **Subsequent startups**: Database settings loaded and override environment variables
4. **Fallback**: If database settings don't exist, falls back to environment variables

### Handler Updates
- `AdminUpdateStorageSettingsHandler`: Persists quota_limit_gb, max_file_size_bytes, expiration settings
- `AdminUpdateSecuritySettingsHandler`: Persists rate limits, blocked_extensions

### Benefits
- No restart required for admin setting changes
- Settings persist across container restarts
- Admin dashboard becomes fully dynamic
- Backward compatible with environment variable-only deployments

---

## Frontend Architecture

### Tab-Based UI
**Dropoff Tab**: File upload with drag-drop, QR code generation, expiration/download limit controls
**Pickup Tab**: Claim code input → retrieve file info → download button

### Two-Step Download Flow
1. User enters claim code → API call to `/api/claim/:code/info`
2. Display file metadata (name, size, downloads remaining, expiration)
3. User clicks download → `window.open(download_url, '_blank')` to trigger browser save dialog

This gives users control over download location (no automatic download).

### Theme Toggle
Dark/light mode with localStorage persistence (reduced size: 2rem, opacity: 0.7 for less intrusiveness).

---

## Chunked Upload Architecture

SafeShare v2.0.0 introduces chunked/resumable uploads for large files (>100MB by default) to overcome HTTP timeout limitations.

**Full Documentation**: See [CHUNKED_UPLOAD.md](CHUNKED_UPLOAD.md) for complete API specifications.

### Overview
**Problem Solved**: HTTP timeout issues for large file uploads that take longer than typical reverse proxy/load balancer timeouts.

**Solution**: Break large files into smaller chunks (5MB each) that can be uploaded independently, tracked, and assembled server-side.

### Components

**Database Migration System** (`internal/database/migrations.go`):
- Embedded SQL migration files using `//go:embed migrations/*.sql`
- `migrations` table tracks applied migrations
- Automatic migration execution on startup

**Partial Uploads Table** (`internal/database/partial_uploads.go`):
Tracks upload sessions with upload_id (UUID), filename, total_size, chunk_size, total_chunks, chunks_received, user_id, etc.

**Chunk Storage** (`internal/utils/chunks.go`):
- Chunks stored at: `{UPLOAD_DIR}/.partial/{upload_id}/chunk_{number}`
- Functions: SaveChunk, ChunkExists, GetMissingChunks, AssembleChunks, DeleteChunks
- Supports out-of-order chunk uploads
- Idempotent chunk uploads

**API Handlers** (`internal/handlers/upload_chunked.go`):
- `UploadInitHandler`: Initialize upload session
- `UploadChunkHandler`: Upload single chunk
- `UploadCompleteHandler`: Assemble chunks into final file
- `UploadStatusHandler`: Check upload progress

**Frontend ChunkedUploader Class** (`internal/static/web/chunked-uploader.js`):
- 499 lines of JavaScript implementing complete chunked upload flow
- Features: Automatic retry, parallel uploads, pause/resume, localStorage persistence
- Event-based architecture: progress, error, complete, chunk_uploaded

### Upload Flow

**Simple Upload** (files < threshold):
```
1. POST /api/upload (multipart/form-data)
2. Server stores file, generates claim code
3. Return claim code to user
```

**Chunked Upload** (files >= threshold):
```
1. Frontend checks file size against CHUNKED_UPLOAD_THRESHOLD
2. POST /api/upload/init (initialize session)
3. Server creates partial_upload record, returns upload_id
4. Frontend splits file into chunks
5. Upload chunks in parallel with retry
6. POST /api/upload/complete/:upload_id
   - Server assembles chunks
   - Encrypts if ENCRYPTION_KEY set
   - Generates claim code
7. Return claim code to user
```

### Security Features
- Respects `REQUIRE_AUTH_FOR_UPLOAD` setting
- Rate limiting on upload initialization
- Validates upload_id, chunk_number, chunk_size
- File extension blocking applied
- Disk space validation before accepting chunks
- Maximum 10,000 chunks per file (prevents DoS)

### Error Handling
Comprehensive error codes: 400, 404, 409, 410, 413, 503, 507

### Performance Characteristics
- Chunk assembly: ~3 seconds for 5000 chunks (25GB file)
- Concurrent chunk uploads: 3 parallel by default (configurable)
- Memory usage during assembly: ~64KB buffer (not entire file in memory)

---

## Webhook Architecture

SafeShare v2.8.0 introduces an event-driven webhook notification system for real-time file lifecycle monitoring.

### Overview
**Problem Solved**: External systems need real-time notifications when files are uploaded, downloaded, deleted, or expired for integration with monitoring tools, notification services, and automated workflows.

**Solution**: Event dispatcher with worker pool architecture that delivers webhooks asynchronously with retry logic, multiple payload formats, and comprehensive delivery tracking.

### Components

**Database Schema** (`internal/database/db.go`, `internal/database/webhooks.go`):

*webhook_configs table:* Stores webhook endpoint configurations
- `id`: Primary key
- `url`: Webhook endpoint URL (HTTP/HTTPS only)
- `secret`: HMAC secret for signature verification
- `service_token`: Optional authentication token for Gotify/ntfy services
- `enabled`: Boolean flag to enable/disable webhook
- `events`: JSON array of subscribed event types
- `format`: Webhook payload format (safeshare/gotify/ntfy/discord)
- `max_retries`: Maximum retry attempts (default: 5)
- `timeout_seconds`: Request timeout (default: 30)
- `created_at`, `updated_at`: Timestamps

*webhook_deliveries table:* Tracks delivery attempts and history
- `id`: Primary key
- `webhook_config_id`: Foreign key to webhook_configs
- `event_type`: Event type (file.uploaded, etc.)
- `payload`: JSON payload sent
- `attempt_count`: Number of delivery attempts
- `status`: Delivery status (pending/success/failed/retrying)
- `response_code`: HTTP response code
- `response_body`: HTTP response body (truncated to 1000 chars)
- `error_message`: Error message if delivery failed
- `created_at`: When delivery was queued
- `completed_at`: When delivery succeeded or exhausted retries
- `next_retry_at`: Scheduled retry time for failed deliveries

**Event Types** (`internal/webhooks/models.go`):
- `file.uploaded` - File successfully uploaded and ready for download
- `file.downloaded` - File downloaded by user (tracks each download)
- `file.deleted` - File deleted by user or admin
- `file.expired` - File expired due to time limit or download limit reached

**Payload Formats** (`internal/webhooks/transformer.go`):
1. **safeshare** (default): Full JSON event with HMAC signature
2. **gotify**: Gotify notification format with service token auth
3. **ntfy**: ntfy.sh plain text format with headers
4. **discord**: Discord webhook embed format

**Webhook Dispatcher** (`internal/webhooks/dispatcher.go`):
- Worker pool architecture with configurable workers (default: 5)
- Buffered event channel (default: 1000 events)
- Async event emission (non-blocking for HTTP handlers)
- Graceful shutdown with in-flight request completion
- Metrics collection via Prometheus

**Delivery Service** (`internal/webhooks/delivery.go`):
- HTTP client with configurable timeout
- HMAC signature generation (SHA-256)
- Exponential backoff retry: 1s, 2s, 4s, 8s, 16s
- Service token injection for Gotify/ntfy
- Response body truncation (max 1000 chars)

**Webhook Handlers** (`internal/handlers/webhook_admin.go`):
- `ListWebhookConfigsHandler`: Get all webhook configs (masks secrets)
- `CreateWebhookConfigHandler`: Create new webhook endpoint
- `UpdateWebhookConfigHandler`: Update webhook (preserves masked secrets)
- `DeleteWebhookConfigHandler`: Delete webhook
- `TestWebhookConfigHandler`: Send test event
- `ListWebhookDeliveriesHandler`: Get delivery history with pagination
- `GetWebhookDeliveryHandler`: Get single delivery details

**Event Emitter** (`internal/handlers/webhook_emitter.go`):
- Global dispatcher instance set by main.go
- `EmitWebhookEvent()`: Helper function called by handlers
- Emits events for file upload, download, delete, expiration

### Webhook Flow

**Event Emission**:
```go
// Handler emits event (non-blocking)
webhooks.EmitWebhookEvent(&webhooks.Event{
    Type: webhooks.EventFileUploaded,
    Timestamp: time.Now(),
    File: webhooks.FileData{
        ClaimCode: "ABC123",
        Filename: "document.pdf",
        Size: 1048576,
        // ...
    },
})
```

**Dispatcher Processing**:
```
1. Event received in buffered channel
2. Worker picks up event from channel
3. Query enabled webhook configs subscribed to event type
4. For each config:
   a. Transform payload to configured format
   b. Create delivery record (status: pending)
   c. Attempt HTTP POST delivery
   d. If successful: Update status to success
   e. If failed: Schedule retry with exponential backoff
5. Worker returns to pool for next event
```

**Retry Logic**:
```
Attempt 1: Immediate
Attempt 2: +1 second
Attempt 3: +2 seconds
Attempt 4: +4 seconds
Attempt 5: +8 seconds
Attempt 6: +16 seconds (if max_retries >= 6)

HTTP 5xx and network errors → retry
HTTP 4xx → mark failed (no retry)
HTTP 2xx → mark success
```

### Security Features

1. **HMAC Signature Verification** (SafeShare format):
   - `X-Webhook-Signature` header contains SHA-256 HMAC of payload
   - Webhook endpoint must verify signature to prevent spoofing

2. **Service Token Masking**:
   - Secrets and service tokens masked in list responses
   - Update endpoint preserves existing values when masked token sent
   - Prevents accidental secret exposure in logs/UI

3. **URL Validation**:
   - Only HTTP/HTTPS schemes allowed (prevents SSRF to file://, etc.)
   - Hostname validation (prevents empty host)

4. **CSRF Protection**:
   - All webhook management endpoints require CSRF token

5. **Request Timeout**:
   - Configurable timeout prevents slow endpoints from blocking workers

6. **Worker Pool Isolation**:
   - Failed webhooks don't impact other webhooks
   - Buffered channel prevents memory exhaustion

### Performance Characteristics

**Event Emission**:
- Non-blocking (handler doesn't wait for delivery)
- Channel write ~microseconds
- No impact on upload/download latency

**Worker Pool**:
- 5 workers handle ~100-500 events/second
- Each worker processes events sequentially
- Configurable workers for high-volume deployments

**Delivery Latency**:
- Immediate delivery attempt
- Typical delivery: 10-100ms (depends on webhook endpoint)
- Retry delays: Exponential backoff (1s to 16s)

**Memory Usage**:
- Buffered channel: 1000 events * ~1KB/event = ~1MB
- Worker goroutines: 5 * ~2KB = ~10KB
- Minimal overhead

### Integration Examples

**Gotify Integration**:
```json
{
  "url": "https://gotify.example.com/message",
  "service_token": "Aabcd1234efgh",
  "format": "gotify",
  "events": ["file.uploaded", "file.downloaded"]
}
```

**ntfy Integration**:
```json
{
  "url": "https://ntfy.sh/safeshare-alerts",
  "service_token": "optional-bearer-token",
  "format": "ntfy",
  "events": ["file.expired", "file.deleted"]
}
```

**Discord Integration**:
```json
{
  "url": "https://discord.com/api/webhooks/.../...",
  "secret": "unused-for-discord",
  "format": "discord",
  "events": ["file.uploaded"]
}
```

**Custom Webhook** (with HMAC verification):
```json
{
  "url": "https://your-app.com/webhooks/safeshare",
  "secret": "your-secret-key-for-hmac",
  "format": "safeshare",
  "events": ["file.uploaded", "file.downloaded", "file.deleted", "file.expired"]
}
```

### Admin Dashboard Integration

The admin dashboard includes a Webhooks tab with:
- Webhook configuration table (URL, events, format, enabled status)
- Create webhook modal with format presets
- Edit webhook with masked secret preservation
- Delete webhook with confirmation
- Test webhook button (sends test event)
- Delivery history table (status, attempts, timestamps)
- Delivery detail modal (full payload, response, errors)

### Monitoring & Observability

**Prometheus Metrics** (`internal/webhooks/metrics.go`):
- `safeshare_webhook_events_total{event_type}` - Events emitted
- `safeshare_webhook_deliveries_total{status}` - Delivery outcomes
- `safeshare_webhook_delivery_duration_seconds` - Delivery latency
- `safeshare_webhook_retries_total{webhook_id}` - Retry attempts

**Structured Logging**:
- Event emissions logged with event_type and claim_code
- Delivery attempts logged with webhook_id, status, response_code
- Retry scheduling logged with next_retry_at

**Delivery History**:
- Admin dashboard shows last 50 deliveries (paginated)
- Full payload, response body, and error messages stored
- Useful for debugging webhook integration issues

---

## Key Dependencies

- **modernc.org/sqlite**: Pure Go SQLite implementation (no CGO required)
- **github.com/google/uuid**: UUID generation for stored filenames
- **github.com/gabriel-vasile/mimetype**: Server-side MIME type detection from file content
- **Standard library**: HTTP server, crypto (AES-256-GCM), logging (slog), file I/O

No external web frameworks or ORMs. Minimal dependencies for security and portability.
