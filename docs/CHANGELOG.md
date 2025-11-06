# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

## [1.2.0] - 2025-11-06

### Added
- User authentication system with invite-only registration
- Role-based access control (admin/user roles)
- User dashboard with file management
- Password change functionality
- Admin user management interface
- Configurable upload authentication via `REQUIRE_AUTH_FOR_UPLOAD` environment variable
  - Default: `false` (anonymous uploads allowed, maintains backward compatibility)
  - Set to `true` to enforce authentication for all uploads (invite-only mode)
- Public configuration API endpoint (`/api/config`) for frontend to fetch server settings
- Dynamic frontend behavior based on server configuration
  - Dropoff tab automatically hidden when auth required and user not logged in
  - "Login to Upload" button appears when uploads require authentication
  - Dropoff tab dynamically appears after successful login
  - Seamless UX that adapts to server security policy
- Comprehensive documentation for upload authentication modes in SECURITY.md
- User-friendly HTML error pages for expired/invalid file links
  - Professional error page design with dark/light mode support
  - Helpful navigation actions (Go to Home, Try Another Code)
  - Smart content negotiation: returns HTML for browsers, JSON for API calls
  - Improves UX when users click expired or invalid download links

### Changed
- Optimized settings tab with 2-column grid layout
- Enhanced mobile responsiveness across all pages
- Improved dark mode consistency
- Upload endpoint now uses conditional authentication middleware based on configuration
- Frontend no longer hardcodes authentication requirement for uploads

### Fixed
- Fixed password change modal not closing properly
- Fixed delete file modal button alignment
- Fixed theme toggle consistency across pages
- Added missing login button for users when authentication is required for uploads
- Fixed user dashboard showing expired files as "Active" instead of "Expired"
  - Corrected IsExpired calculation from `file.ExpiresAt.Before(file.CreatedAt)` to `time.Now().After(file.ExpiresAt)`
- Fixed dashboard download URLs using non-existent `/download/` route
  - Changed to correct `/api/claim/` endpoint

### Security
- Added rate limiting to user login endpoint
- Enabled secure cookie flag for HTTPS deployments

## [1.1.0] - 2025-01-01

### Added
- Admin dashboard with file management
- IP blocking functionality
- Dynamic quota adjustment

### Fixed
- Fixed CSRF token validation on admin endpoints

## [1.0.0] - 2024-12-15

Initial production release.

### Added
- File upload/download with claim codes
- Automatic file expiration
- Download limits
- Encryption at rest support
- Password protection for files
- Rate limiting (uploads/downloads)
- Security headers (CSP, X-Frame-Options, etc.)
- Filename sanitization
- MIME type detection
- Admin authentication
- Comprehensive audit logging

[Unreleased]: https://github.com/fjmerc/safeshare/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/fjmerc/safeshare/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/fjmerc/safeshare/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/fjmerc/safeshare/releases/tag/v1.0.0
