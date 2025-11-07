# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [2.0.4] - 2025-11-06

### Fixed
- **UI**: Long filenames in user dashboard now truncate with ellipsis instead of causing horizontal scroll
  - Added `max-width: 300px` to filename cells
  - Applied `text-overflow: ellipsis` for better readability
  - Prevents table overflow on mobile and desktop devices

## [2.0.3] - 2025-11-06

### Fixed
- **Critical**: Frontend now respects server's max file size configuration
  - `maxFileSizeBytes` variable was hardcoded to 100MB in JavaScript
  - Now correctly updated from `/api/config` endpoint's `max_file_size` value
  - Fixes "File is too large. Maximum size is 100MB" error when server allows larger files
  - UI display also updates to show correct maximum file size from server

## [2.0.2] - 2025-11-06

### Fixed
- **Critical**: Moved `chunked-uploader.js` to assets directory to fix 404 error
  - File was in web root but static handler only serves from `/assets/*` route
  - Updated script tag in index.html to reference `/assets/chunked-uploader.js`
  - Fixes "stuck at 80%" upload issue where chunked upload code wasn't loading
  - Prevents fallback to simple upload which causes HTTP 413 errors for large files

### Added
- **Automatic version display**: Version now shown in footer, fetched from server
  - Created `internal/handlers/version.go` with version constant
  - Added `version` field to `/api/config` endpoint response
  - Frontend dynamically displays version below footer text (centered)
  - Ensures version display always matches running binary (no version drift)
  - Single source of truth for version updates

## [2.0.1] - 2025-11-06

### Fixed
- **Frontend Integration**: Connected ChunkedUploader class to web UI upload flow
  - Added script tag to load `/chunked-uploader.js` in index.html
  - Modified upload handler to detect file size and route to chunked or simple upload
  - Files ≥100MB (configurable via `CHUNKED_UPLOAD_THRESHOLD`) now automatically use chunked upload
  - Files below threshold continue using simple upload (preserves existing behavior)
  - Progress bar now shows detailed chunk progress for large files (chunk number, speed, ETA)
  - Prevents HTTP 413 Payload Too Large errors for large files
  - Prevents timeout errors during large file uploads

### Changed
- Upload routing now logs which upload method is being used (console.log)
- Progress text enhanced to show chunk-level details during chunked uploads

## [2.0.0] - 2025-11-06

### Added
- **Chunked Upload Support**: Resumable uploads for large files (>100MB) with automatic chunking
  - New API endpoints: `/api/upload/init`, `/api/upload/chunk/:upload_id/:chunk_number`, `/api/upload/complete/:upload_id`, `/api/upload/status/:upload_id`
  - Database migration system with `migrations` table and versioned SQL files
  - `partial_uploads` table to track upload sessions
  - Background cleanup worker for abandoned uploads (24-hour TTL, runs every 6 hours)
  - Chunk storage at `/app/uploads/.partial/{upload_id}/chunk_{number}`
  - Support for up to 10,000 chunks per file (prevents DoS attacks)
- **Frontend ChunkedUploader Class**: Comprehensive JavaScript class for chunked uploads
  - Automatic retry logic with exponential backoff (3 attempts)
  - Parallel chunk uploads (3 concurrent by default, configurable)
  - Pause/resume capability with localStorage persistence
  - Progress tracking with ETA calculation
  - Event-based architecture (`progress`, `error`, `complete`, `chunk_uploaded` events)
  - Cross-page refresh resume capability via localStorage
- **Configuration Options** for chunked uploads:
  - `CHUNKED_UPLOAD_ENABLED` (default: `true`) - Enable/disable chunked uploads
  - `CHUNKED_UPLOAD_THRESHOLD` (default: `104857600` / 100MB) - File size threshold for chunked mode
  - `CHUNK_SIZE` (default: `5242880` / 5MB) - Size of each chunk
  - `PARTIAL_UPLOAD_EXPIRY_HOURS` (default: `24`) - Hours before abandoned uploads are cleaned up
- Updated `/api/config` endpoint to expose chunked upload settings to frontend

### Changed
- **BREAKING**: Database schema updated with migrations system
  - Existing databases will automatically run migrations on startup
  - New `migrations` table tracks applied schema changes
  - `partial_uploads` table added for chunked upload sessions
- Upload flow now automatically chooses simple vs chunked mode based on file size
- Quota calculation now includes in-progress partial uploads (prevents quota bypass)

### Improved
- Buffered I/O for chunk assembly (64KB buffer) for efficient large file processing
- Out-of-order chunk uploads supported (chunks can arrive in any sequence)
- Idempotent chunk uploads (re-uploading same chunk succeeds, retry-safe)
- Chunk integrity verification before assembly
- Comprehensive error handling with detailed error codes

### Security
- Chunked upload endpoints respect `REQUIRE_AUTH_FOR_UPLOAD` setting
- Rate limiting applied to upload initialization
- Validates upload_id (UUID format), chunk_number (range), chunk_size (matches expected)
- File extension blocking applied to chunked uploads
- Disk space validation before accepting chunks
- Maximum chunk count limit (10,000) prevents resource exhaustion

### Fixed
- HTTP timeout issues for large file uploads (>100MB)
- Upload progress accuracy for multi-gigabyte files

### Documentation
- Added `docs/CHUNKED_UPLOAD.md` with comprehensive API documentation
  - Architecture overview and database schema
  - API endpoint specifications with request/response examples
  - curl usage examples for testing
  - Security considerations and error handling reference
  - Frontend integration guide
- Updated inline code documentation

## [1.2.0] - 2025-11-06

### Added
- User authentication system with invite-only registration
- Role-based access control (admin/user roles)
- User dashboard with file management
- Password change functionality
- Admin user management interface
- Require authentication for uploads (configurable via `REQUIRE_AUTH_FOR_UPLOAD`)

### Changed
- Optimized settings tab with 2-column grid layout
- Enhanced mobile responsiveness across all pages
- Improved dark mode consistency

### Fixed
- Fixed password change modal not closing properly
- Fixed delete file modal button alignment
- Fixed theme toggle consistency across pages

### Security
- Added rate limiting to user login endpoint
- Enabled secure cookie flag for HTTPS deployments

## [1.1.0] - 2025-10-15

### Added
- Admin dashboard with file management
- IP blocking functionality
- Dynamic quota adjustment via admin interface
- File password protection

### Changed
- Enhanced logging with structured JSON format
- Improved error messages for user-facing errors

### Fixed
- Fixed CSRF token validation on admin endpoints

### Security
- Added CSRF protection for all admin state-changing operations

## [1.0.0] - 2025-10-01

Initial production release.

### Added
- File upload/download with claim codes
- Automatic file expiration based on time
- Download limits (max downloads per file)
- Encryption at rest support (AES-256-GCM)
- Password protection for files
- Rate limiting (uploads and downloads per IP)
- Security headers (CSP, X-Frame-Options, etc.)
- Filename sanitization to prevent attacks
- MIME type detection from file content
- Admin authentication with dashboard
- Comprehensive audit logging
- Docker support with multi-stage builds
- Health check endpoint
- Graceful shutdown handling

### Security
- Encryption at rest with AES-256-GCM
- Rate limiting (10 uploads/hour, 100 downloads/hour per IP)
- Security headers (CSP, X-Frame-Options, X-Content-Type-Options)
- Filename sanitization to prevent HTTP header injection
- MIME type detection to prevent malware disguise
- File extension blacklist for dangerous file types
- Disk space monitoring and validation
- Maximum file expiration enforcement

[Unreleased]: https://github.com/fjmerc/safeshare/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/fjmerc/safeshare/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/fjmerc/safeshare/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/fjmerc/safeshare/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/fjmerc/safeshare/releases/tag/v1.0.0
