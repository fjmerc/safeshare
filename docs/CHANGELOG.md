# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed
- **Performance**: Optimized chunked upload performance for large files on VPS/cloud storage
  - Upload times improved by 30-150x on network storage (from ~100 minutes to ~2-5 minutes for 1GB files)
  - Increased maximum chunk size from 10MB to 50MB (default remains 5MB)
  - Eliminates implicit sync operations during chunk writes
  - Reduces chunk count by 80% for large files (1GB: 20 chunks vs 200)
  - Backward compatible with existing deployments

### Fixed
- **Upload**: Fixed chunk size validation bug that prevented use of larger chunk sizes
  - HTTP parser now correctly accepts chunk sizes up to configured maximum
  - Previously limited to 5MB default regardless of requested chunk size

## [2.1.0] - 2025-11-08

### Added
- **UI**: Professional toast notification system across entire application
  - Non-blocking notifications with 4 types: info (blue), success (green), error (red), warning (orange)
  - Top-right positioning with smooth slide-in/fade-out animations
  - Auto-dismiss after 3 seconds (configurable per toast)
  - Click to dismiss instantly
  - Multiple toasts stack vertically without overlap
  - Full dark mode support with theme-aware colors
  - Mobile responsive (full-width on small screens)
  - Available on all 6 pages (main, login, dashboard, error, admin login, admin dashboard)
  - XSS protection via HTML escaping
- **UI**: Upload in progress warning banner
  - Fixed-position banner at bottom of viewport appears during active uploads
  - Clear message: "Upload in Progress - Do not navigate away or close this page"
  - Prevents accidental data loss from navigating away during uploads
  - Automatically shows/hides based on upload state
  - Works for both simple and chunked uploads
  - Includes `beforeunload` handler as fallback for tab closes
  - Responsive design with dark mode support
- **Upload**: Cancel upload functionality
  - Users can now abort in-progress uploads (both simple and chunked)
  - Smart button transformation: grey "Remove File" (idle) → red "Cancel Upload" (uploading)
  - File remains selected after cancel for easy re-upload
  - Follows modern upload UX patterns
- **Admin**: Settings validation
  - Max File Size cannot exceed Storage Quota (when quota > 0)
  - Default Expiration cannot exceed Max Expiration
  - Clear error messages with actionable guidance
- **Admin**: Unsaved changes warning
  - Detects unsaved changes in Settings tab
  - Shows confirmation dialog when navigating away
  - Browser beforeunload warning when closing/navigating away from page
  - Automatically clears warning after successful save

### Changed
- **UX**: Replaced all blocking alert() dialogs with non-blocking toast notifications
  - Upload errors now show as dismissible error toasts (4s duration)
  - File validation errors (too large, blocked extension) show as error toasts
  - Success messages (upload complete, link copied) show as success toasts
  - Informational messages (download started, upload cancelled) show as info toasts
  - Warning messages (missing claim code, missing password) show as warning toasts
  - Improves user experience by not interrupting workflow
  - Follows enterprise UX patterns (Google Drive, Dropbox, OneDrive)
- **UI**: Improved chunked upload progress display
  - Removed technical chunk information ("chunk X of Y") from progress text
  - Now shows user-friendly format: "Uploading... X% • SIZE / TOTAL • TIME remaining"
  - Added estimated time remaining (ETA) instead of just upload speed
  - Smart file size formatting (automatically uses MB/GB as appropriate)
  - Human-readable time format (e.g., "6 min", "2h 15m", "45 sec")
  - Cleaner visual presentation with bullet separators
- **Config**: Updated default download rate limit from 100 to 50 per hour
  - Aligns with industry standards (GitHub: 60/hour, npm: 50/hour)
  - Better DoS protection by default

### Fixed
- **Critical**: Fixed memory exhaustion bug for large encrypted files
  - Implemented streaming encryption using chunked AES-256-GCM (64MB chunks)
  - Prevents OOM crashes when uploading/downloading encrypted files >1GB
  - New SFSE1 format (SafeShare File Stream Encrypted v1) for large files
  - Backward compatible with legacy encrypted files
  - Constant memory usage (~64MB buffer) regardless of file size
- **Authentication**: Fixed admin logout button not working for user accounts with admin role
  - AdminLogoutHandler now properly handles both `admin_session` and `user_session` cookies
  - Clears sessions from correct database table based on authentication method
  - Clears all cookies (admin_session, user_session, CSRF) for complete logout
- **Authentication**: Fixed admin login session compatibility issue
  - Admins logging in via `/admin/login` now receive `user_session` cookies instead of `admin_session` cookies
  - Allows admins to access both admin routes and user routes seamlessly
  - Legacy `admin_credentials` authentication still creates `admin_session` cookies for backward compatibility
- **Authentication**: Implemented server-side authentication redirects
  - Replaces client-side redirects with HTTP 302 redirects
  - Eliminates 401 errors in console during navigation
  - No page flashing during authentication flow
  - Login pages redirect to dashboard if already authenticated
- **Upload**: Fixed 80% disk check blocking uploads when quota configured
  - Disk space check now skips 80% limit when quota is set
  - Allows full utilization of configured quota
  - Still validates minimum 1GB free space and actual disk availability
- **Upload**: Improved chunked upload reliability
  - Fixed SQLITE_BUSY errors by using disk-based chunk counting instead of database counter
  - Fixed duplicate response structure syntax error in completion handler
  - Enhanced error handling and status checking
- **UI**: Fixed browser "Leave site?" warning appearing after successful upload
  - Upload state now properly resets to 'idle' after upload completes
  - Users can navigate away from success page without unnecessary warnings
- **UI**: Added "Remove File" button to upload interface
  - Users can now clear selected files without refreshing the page
  - Button appears after file selection (via drag-drop or file picker)
- **UI**: Fixed toast notification positioning and styling on Admin Dashboard
  - Toast notifications now appear 100px from top, preventing overlap with header elements
  - Toast styling now matches user dashboard
  - Removed legacy toast notification system to prevent conflicts
- **UI**: Improved upload warning banner UX
  - Reduced banner height by ~25-30% for less screen intrusion
  - Banner now auto-hides when upload completes (success or error)

## [2.0.7] - 2025-11-07

### Changed
- **Performance**: Increased chunked upload concurrency from 3 to 6 parallel chunks
  - Improves upload throughput by up to 2x for large files
  - Better utilizes available bandwidth (tested with 43.5 Mbit/s connections)
  - Browser connection limits prevent exceeding 6 concurrent connections (HTTP/1.1)
  - HTTP/2 connections benefit from full parallelization
  - No performance impact on server or client stability

### Fixed
- **Critical**: Fixed memory exhaustion bug in chunked upload completion for large files
  - MIME type detection now reads only first 512 bytes instead of entire file into memory
  - Prevents out-of-memory errors and server crashes when uploading large ISO files (>100MB)
  - Fixes "Unexpected token '<'" error caused by HTML error pages being returned instead of JSON
  - Magic number detection works correctly with partial file reads

## [2.0.6] - 2025-11-07

### Fixed
- **Version Display**: Corrected version constant in `/api/config` endpoint
  - Version now correctly displays as "v2.0.6" in footer
  - Fixed bug where v2.0.5 release showed "v2.0.4" due to missed version constant update
  - Updated `internal/handlers/version.go` to reflect actual release version

## [2.0.5] - 2025-11-07

### Fixed
- **UI**: Comprehensive text overflow improvements across all pages
  - **User dashboard**: Reduced filename column `max-width` from 300px to 200px to prevent horizontal scroll with extremely long filenames
  - **Admin dashboard**: Reduced filename column to 200px with ellipsis and hover tooltip for full filename visibility
  - **Admin dashboard**: Added IPv6 address truncation in Uploader IP column (150px max-width with ellipsis)
  - **Admin dashboard**: Fixed action button text truncation with 120px fixed width
  - **Admin dashboard**: Improved table scrolling with 1700px min-width for 11-column layout
  - **Upload success display**: Added filename truncation with ellipsis and hover tooltip
  - **Drop zone**: Improved word-break handling for filenames with sequential characters
  - All text overflow changes ensure content remains accessible while preventing layout issues

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

[Unreleased]: https://github.com/fjmerc/safeshare/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/fjmerc/safeshare/compare/v2.0.7...v2.1.0
[2.0.7]: https://github.com/fjmerc/safeshare/compare/v2.0.6...v2.0.7
[2.0.6]: https://github.com/fjmerc/safeshare/compare/v2.0.5...v2.0.6
[2.0.0]: https://github.com/fjmerc/safeshare/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/fjmerc/safeshare/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/fjmerc/safeshare/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/fjmerc/safeshare/releases/tag/v1.0.0
