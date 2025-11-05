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

# Run with enterprise security features and admin/user authentication
docker run -d -p 8080:8080 \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=SafeShare2025! \
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

**File Upload/Download:**
```bash
# Test upload (anonymous)
curl -X POST -F "file=@test.txt" -F "expires_in_hours=24" -F "max_downloads=5" \
  http://localhost:8080/api/upload

# Test file info (retrieve metadata without downloading)
curl http://localhost:8080/api/claim/<CLAIM_CODE>/info

# Test download
curl -O http://localhost:8080/api/claim/<CLAIM_CODE>

# Test health
curl http://localhost:8080/health
```

**Admin Authentication & User Management:**
```bash
# Admin login (returns CSRF token)
curl -c admin_cookies.txt \
  -d "username=admin&password=SafeShare2025!" \
  http://localhost:8080/admin/api/login

# Create user account (admin only)
curl -b admin_cookies.txt \
  -H "X-CSRF-Token: <TOKEN_FROM_LOGIN>" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","role":"user"}' \
  http://localhost:8080/admin/api/users/create

# List all users (admin only)
curl -b admin_cookies.txt http://localhost:8080/admin/api/users
```

**User Authentication & Dashboard:**
```bash
# User login
curl -c user_cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"temp_password"}' \
  http://localhost:8080/api/auth/login

# Get current user info
curl -b user_cookies.txt http://localhost:8080/api/auth/user

# Upload file as authenticated user (tracks ownership)
curl -b user_cookies.txt \
  -F "file=@document.pdf" \
  http://localhost:8080/api/upload

# View user's uploaded files
curl -b user_cookies.txt http://localhost:8080/api/user/files

# Delete user's own file
curl -b user_cookies.txt \
  -X DELETE \
  -H "Content-Type: application/json" \
  -d '{"file_id":1}' \
  http://localhost:8080/api/user/files/delete

# Change password
curl -b user_cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"current_password":"temp_password","new_password":"NewSecure123","confirm_password":"NewSecure123"}' \
  http://localhost:8080/api/auth/change-password

# User logout
curl -b user_cookies.txt -X POST http://localhost:8080/api/auth/logout
```

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

1. **Invite-Only Registration**:
   - No public registration endpoint
   - Only admins can create user accounts via dashboard
   - Prevents unauthorized account creation

2. **Temporary Password Flow**:
   - Admin creates user with optional custom password or auto-generated password
   - Auto-generated format: "word1-word2-word3-###" (e.g., "alpha-dragon-ocean-234")
   - New users have `require_password_change: true` flag
   - Frontend prompts for password change on first login
   - Password must be changed before full access granted

3. **Session Management**:
   - Separate session tables for users (`user_sessions`) and admins (`admin_sessions`)
   - HttpOnly cookies prevent XSS attacks
   - SameSite=Strict prevents CSRF on cookies
   - Configurable expiration via SESSION_EXPIRY_HOURS
   - Activity tracking updates last_activity on each request
   - Background cleanup removes expired sessions every 30 minutes

4. **File Ownership**:
   - Authenticated uploads set `user_id` in files table
   - Anonymous uploads leave `user_id` as NULL (backward compatible)
   - Users can only view/delete their own files
   - Admins can view/delete all files

5. **Role-Based Access**:
   - **User role**: Can upload files, view own files, delete own files, change password
   - **Admin role**: Full admin dashboard access + all user permissions
   - Roles assigned during account creation, can be updated by admins

6. **Audit Logging**:
   - All user authentication events logged (login, logout, password change)
   - All admin user management actions logged (create, update, delete, enable/disable, reset)
   - Logs include: timestamp, username, user_id, client_ip, user_agent

### User Dashboard Features

**File Management**:
- Table view: claim code, filename, size, created date, expires date, download count, max downloads
- Copy download link: One-click copy to clipboard
- Delete file: Soft delete with confirmation modal (removes from DB and disk)
- Empty state: Helpful message when no files uploaded yet

**Password Change**:
- Modal dialog for changing password
- Requires current password for verification
- New password confirmation field
- Updates password and clears require_password_change flag

**Navigation**:
- Welcome message with username
- Logout button
- Back to home link

**UI/UX Enhancements**:
- **Responsive header layout**: Four action buttons (Admin Dashboard, Change Password, Upload Files, Logout) with intelligent wrapping at 1200px breakpoint
- **Compact button styling**: Optimized padding (8px 14px) and spacing (8px gap) for better horizontal space utilization
- **Cross-browser clipboard support**: Fallback mechanism for HTTP contexts using execCommand when Clipboard API unavailable
- **Copy link visual feedback**: Button changes to checkmark with green color feedback for 2 seconds
- **Mobile-optimized**: Progressive button sizing and layout adjustments for tablets (≤1024px) and phones (≤768px)
- **Enhanced date formatting**: Compact format (e.g., "Nov 5 @ 7:00 PM") saves table space, shows year only when different from current
- **Tab navigation fix**: Async initialization ensures auth state is known before handling URL hash navigation (fixes Upload Files button redirect)

## Admin Dashboard Architecture

### Overview
The admin dashboard provides web-based administration for SafeShare. It's a fully-featured management interface with secure authentication, CSRF protection, comprehensive file and IP management capabilities, and now includes full user account management.

### Components

**Database Schema** (`internal/database/db.go`, `internal/database/admin.go`):
- `admin_credentials` table: Stores admin username and bcrypt-hashed password (single row with id=1)
- `admin_sessions` table: Stores active admin sessions with expiration tracking
- `blocked_ips` table: IP blocklist with reason and timestamp tracking
- Session cleanup worker: Automatically removes expired admin sessions every 30 minutes

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

**Handlers** (`internal/handlers/admin.go`, `internal/handlers/admin_users.go`):

*Admin Authentication:*
- `AdminLoginHandler`: Validates credentials against database, creates session, sets cookies (session + CSRF)
- `AdminLogoutHandler`: Deletes session from database and clears cookies

*Admin Dashboard:*
- `AdminDashboardDataHandler`: Returns paginated files, stats, blocked IPs, and user counts

*Admin File Management:*
- `AdminDeleteFileHandler`: Deletes file from database and filesystem (requires CSRF)

*Admin IP Management:*
- `AdminBlockIPHandler`: Adds IP to blocklist (requires CSRF)
- `AdminUnblockIPHandler`: Removes IP from blocklist (requires CSRF)

*Admin Settings:*
- `AdminUpdateQuotaHandler`: Dynamically updates storage quota without restart (requires CSRF)
- `AdminChangePasswordHandler`: Changes admin password without restart (requires CSRF)

*Admin User Management:*
- `AdminCreateUserHandler`: Creates new user with optional or auto-generated temporary password (requires CSRF)
- `AdminListUsersHandler`: Returns paginated list of all users with file counts
- `AdminUpdateUserHandler`: Updates user profile - username, email, role (requires CSRF)
- `AdminToggleUserActiveHandler`: Enable/disable user accounts (requires CSRF)
- `AdminResetUserPasswordHandler`: Generates new temporary password for user (requires CSRF)
- `AdminDeleteUserHandler`: Permanently deletes user account (requires CSRF)

**Frontend** (`internal/static/web/admin/`):
- `login.html`: Login page with username/password form
- `dashboard.html`: Four-tab interface (Files, Users, Blocked IPs, Settings)
- `admin.css`: Responsive design with light theme, tables, forms, modals
- `admin.js`: Handles API calls, pagination, search, confirmations, CSRF token management, user management modals

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
- `POST /admin/api/settings/password` - Change admin password (requires AdminAuth + CSRFProtection)
- `POST /admin/api/users/create` - Create user (requires AdminAuth + CSRFProtection)
- `PUT /admin/api/users/:id` - Update user (requires AdminAuth + CSRFProtection)
- `DELETE /admin/api/users/:id` - Delete user (requires AdminAuth + CSRFProtection)
- `POST /admin/api/users/:id/enable` - Enable user (requires AdminAuth + CSRFProtection)
- `POST /admin/api/users/:id/disable` - Disable user (requires AdminAuth + CSRFProtection)
- `POST /admin/api/users/:id/reset-password` - Reset user password (requires AdminAuth + CSRFProtection)

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

**Users Tab**:
- Table view: username, email, role, status (active/inactive), files count, created date, last login, actions
- Create User: Modal dialog with username, email, role, optional password fields
- User Created Success: Displays temporary password with copy-to-clipboard button
- Edit User: Modal dialog to update username, email, role
- Enable/Disable: Toggle user account active state (soft delete)
- Reset Password: Generates new temporary password, displayed in modal with copy button
- Delete User: Permanently removes user account (requires confirmation)
- Pagination: 20 users per page with page navigation

**Blocked IPs Tab**:
- Table view: IP address, reason, blocked date, blocked by
- Add: Block new IP with optional reason
- Unblock: Remove IP from blocklist (requires confirmation)

**Settings Tab**:
- Quota management: Update QUOTA_LIMIT_GB dynamically without restart
- Password management: Change admin password without restart
- System info: Display database path, upload directory

**Real-time Stats** (top cards):
- Total Files: Active file count
- Storage Used: Total bytes used (formatted as B/KB/MB/GB/TB)
- Quota Usage: Percentage used (or "Unlimited" if quota = 0)
- Blocked IPs: Count of blocked IPs
- Total Users: Active user account count

**Recent UI/UX Improvements**:
- **Username tracking**: File listings now show which user uploaded each file (requires SQL JOIN with users table)
- **Async confirmations**: All destructive operations (delete file, delete user, unblock IP) use async/await confirmation dialogs for better UX
- **Enhanced date formatting**: Compact display format (e.g., "Nov 5 @ 7:00 PM") saves table space, shows year only when different from current year
- **Improved form controls**: Enhanced styling for input fields, select dropdowns, and form layouts with better focus states
- **Better table display**: Improved column alignment, consistent spacing, and visual hierarchy
- **Dynamic storage quota updates**: Settings API now accepts `quota_gb` parameter for runtime updates without container restart
- **Universal dark mode**: Theme toggle affects all pages (dashboard, login, admin) with localStorage persistence

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
- `files` table tracks metadata (claim_code, filenames, size, expiration, download limits, user_id)
- `users` table stores user accounts (username, email, password_hash, role, is_active, require_password_change)
- `user_sessions` table stores active user sessions with expiration tracking
- `admin_credentials` table stores admin credentials (single row with id=1)
- `admin_sessions` table stores active admin sessions with expiration tracking
- `blocked_ips` table stores IP blocklist with reason and timestamp
- Indexes on `claim_code` (lookups), `expires_at` (cleanup worker), `username` (login), `email` (uniqueness)
- Foreign keys: `files.user_id` → `users.id` (ON DELETE SET NULL for file ownership)
- Physical files stored separately in `UPLOAD_DIR` with UUID-based names

**Background Cleanup Workers**
Goroutines launched in `main.go` using context for cancellation:

*File Cleanup Worker:*
- Runs every `CLEANUP_INTERVAL_MINUTES` (default: 60)
- Deletes expired files from both database and disk
- Gracefully cancelled on shutdown

*Session Cleanup Worker:*
- Runs every 30 minutes
- Removes expired admin sessions from `admin_sessions` table
- Removes expired user sessions from `user_sessions` table
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
