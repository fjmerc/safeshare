# Version Management & Release Strategy - SafeShare

This guide defines the versioning, tagging, branching, and release strategy for SafeShare.

---

## Table of Contents

1. [Semantic Versioning](#semantic-versioning)
2. [Git Branching Strategy](#git-branching-strategy)
3. [Version Tagging](#version-tagging)
4. [Release Process](#release-process)
5. [Changelog Management](#changelog-management)
6. [Docker Image Tagging](#docker-image-tagging)
7. [Hotfix Process](#hotfix-process)
8. [Deprecation Policy](#deprecation-policy)

---

## Semantic Versioning

SafeShare follows [Semantic Versioning 2.0.0](https://semver.org/):

```
MAJOR.MINOR.PATCH
```

### Version Components

**MAJOR** version (1.x.x → 2.x.x):
- Breaking changes that require user action
- Database schema changes requiring migration
- Configuration file format changes
- Removal of deprecated features
- API changes that break backwards compatibility

Examples:
- Changing environment variable names
- Removing support for old database schema
- Changing API response formats
- Changing default behavior that affects existing deployments

**MINOR** version (x.1.x → x.2.x):
- New features (backwards compatible)
- New API endpoints
- Performance improvements
- Significant enhancements to existing features

Examples:
- Adding user authentication system
- Adding new configuration options
- Adding admin dashboard features
- Adding encryption at rest support

**PATCH** version (x.x.1 → x.x.2):
- Bug fixes
- Security patches
- Documentation updates
- Minor improvements that don't change functionality

Examples:
- Fixing login validation bug
- Patching XSS vulnerability
- Fixing incorrect error message
- Updating dependencies for security

### Pre-Release Versions

Use suffixes for pre-release versions:

```
v1.0.0-alpha.1    # Alpha (early development, unstable)
v1.0.0-beta.1     # Beta (feature complete, testing)
v1.0.0-rc.1       # Release Candidate (final testing)
```

**Alpha**: Early development, major features incomplete, expect bugs
**Beta**: Feature complete, ready for testing, may have bugs
**RC**: Final testing before release, production-ready

### Version Examples

```
v0.1.0            # Initial development
v0.2.0            # Added feature during development
v1.0.0            # First stable release (production-ready)
v1.0.1            # Bug fix
v1.1.0            # New feature (user authentication)
v1.1.1            # Bug fix in user authentication
v1.2.0            # New feature (admin dashboard)
v2.0.0            # Breaking change (new config format)
v2.0.1            # Bug fix in new config
```

---

## Git Branching Strategy

SafeShare uses **Git Flow** branching model.

### Branch Types

```
main              # Production-ready code
├── develop       # Integration branch for next release
├── feature/*     # New features
├── bugfix/*      # Bug fixes
├── perf/*        # Performance optimizations
├── docs/*        # Documentation updates
├── release/*     # Release preparation
└── hotfix/*      # Emergency production fixes
```

### Branch Descriptions

**main**:
- Always production-ready
- Only contains tagged releases
- Protected branch (requires PR + review)
- Never commit directly to main
- Deployed to production

**develop**:
- Integration branch for next release
- All feature branches merge here
- May be unstable
- Deployed to staging/test environment

**feature/*** (e.g., `feature/user-authentication`):
- Created from `develop`
- One feature per branch
- Merged back to `develop` via PR
- Deleted after merge

**bugfix/*** (e.g., `bugfix/fix-login-validation`):
- Created from `develop`
- Bug fixes for non-critical issues
- Merged back to `develop` via PR
- Deleted after merge

**perf/*** (e.g., `perf/optimize-file-streaming`):
- Created from `develop`
- Performance improvements and optimizations
- Merged back to `develop` via PR
- Deleted after merge

**docs/*** (e.g., `docs/update-api-documentation`):
- Created from `develop`
- Documentation updates and improvements
- Merged back to `develop` via PR
- Deleted after merge

**release/*** (e.g., `release/v1.2.0`):
- Created from `develop` when ready for release
- Only bug fixes and version bumps allowed
- Merged to both `main` and `develop`
- Tagged on `main` after merge

**hotfix/*** (e.g., `hotfix/fix-login-vuln`):
- Created from `main` for urgent fixes
- Merged to both `main` and `develop`
- Tagged immediately

### Branch Protection Rules

**main**:
```
- Require pull request reviews (minimum 1)
- Require status checks to pass
- Require branches to be up to date
- No force push
- No deletions
```

**develop**:
```
- Require pull request reviews (optional)
- Require status checks to pass
- Allow force push (with caution)
```

---

## Version Tagging

### Tag Format

```bash
# Release tags
v1.0.0            # Stable release
v1.0.0-rc.1       # Release candidate
v1.0.0-beta.1     # Beta release
v1.0.0-alpha.1    # Alpha release

# DO NOT use:
1.0.0             # Missing 'v' prefix
v1.0              # Missing patch version
release-1.0.0     # Non-standard format
```

### Creating Tags

**Annotated tags** (recommended for releases):
```bash
# Create annotated tag with message
git tag -a v1.0.0 -m "Release v1.0.0: Initial production release

Features:
- File upload/download with claim codes
- Admin dashboard with authentication
- User authentication system
- Encryption at rest
- Rate limiting and security headers

See CHANGELOG.md for full details."

# Push tag to remote
git push origin v1.0.0
```

**Lightweight tags** (for internal use only):
```bash
# Quick tag without message
git tag v1.0.0-dev
git push origin v1.0.0-dev
```

### Tag Signing (Recommended for Production)

Sign tags with GPG for verification:

```bash
# Generate GPG key (one-time setup)
gpg --full-generate-key

# Configure Git to use GPG
git config --global user.signingkey YOUR_GPG_KEY_ID
git config --global tag.gpgSign true

# Create signed tag
git tag -s v1.0.0 -m "Release v1.0.0"

# Verify signature
git tag -v v1.0.0

# Push signed tag
git push origin v1.0.0
```

Users can verify authenticity:
```bash
git tag -v v1.0.0
```

---

## Release Process

### Standard Release (Minor/Major)

**1. Prepare release branch** (from `develop`):
```bash
# Create release branch
git checkout develop
git pull origin develop
git checkout -b release/v1.2.0

# Update version in files (if applicable)
# - docs/CHANGELOG.md
# - version.txt or VERSION file
git commit -am "chore: bump version to 1.2.0"

# Push release branch
git push -u origin release/v1.2.0
```

**2. Final testing & bug fixes**:
```bash
# Make any final bug fixes on release branch
git commit -am "fix: resolve login issue before release"

# Update changelog
# Add release date to CHANGELOG.md
git commit -am "docs: update changelog for v1.2.0"
```

**3. Merge to main**:
```bash
# Switch to main
git checkout main
git pull origin main

# Merge release branch (no fast-forward to preserve history)
git merge --no-ff release/v1.2.0 -m "Merge release v1.2.0"

# Tag the release
git tag -a v1.2.0 -m "Release v1.2.0

New Features:
- User authentication with invite-only registration
- Role-based access control (RBAC)
- Password change functionality
- Enhanced admin dashboard with user management

Improvements:
- Optimized settings tab layout
- Enhanced mobile responsiveness
- Improved dark mode support

Bug Fixes:
- Fixed password change modal not closing
- Fixed delete modal button alignment
- Fixed theme toggle consistency

See CHANGELOG.md for complete details."

# Push main and tag
git push origin main
git push origin v1.2.0
```

**4. Merge back to develop**:
```bash
# Merge release branch to develop
git checkout develop
git pull origin develop
git merge --no-ff release/v1.2.0 -m "Merge release v1.2.0 back to develop"
git push origin develop
```

**5. Cleanup**:
```bash
# Delete release branch (locally and remotely)
git branch -d release/v1.2.0
git push origin --delete release/v1.2.0
```

**6. CI/CD automatically**:
- Builds Docker image with tag `v1.2.0` and `latest`
- Creates GitHub/GitLab/Gitea release
- Publishes to container registry

---

### Patch Release

For bug fixes and security patches:

```bash
# Work directly on develop (if not urgent)
git checkout develop
git commit -am "fix: resolve session timeout issue"

# Follow release process above with new patch version
# Example: v1.2.0 → v1.2.1
```

---

### Hotfix Release

For critical production bugs:

**1. Create hotfix branch** (from `main`):
```bash
git checkout main
git pull origin main
git checkout -b hotfix/fix-critical-xss

# Make the fix
git commit -am "fix: patch XSS vulnerability in filename display"
```

**2. Merge to main and tag**:
```bash
git checkout main
git merge --no-ff hotfix/fix-critical-xss
git tag -a v1.2.1 -m "Hotfix v1.2.1: Patch XSS vulnerability"
git push origin main v1.2.1
```

**3. Merge to develop**:
```bash
git checkout develop
git merge --no-ff hotfix/fix-critical-xss
git push origin develop
```

**4. Cleanup**:
```bash
git branch -d hotfix/fix-critical-xss
git push origin --delete hotfix/fix-critical-xss
```

---

## Changelog Management

Maintain `CHANGELOG.md` following [Keep a Changelog](https://keepachangelog.com/).

### Changelog Format

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Upcoming feature descriptions

### Changed
- Upcoming changes

### Fixed
- Upcoming fixes

## [1.2.0] - 2025-11-06

### Added
- User authentication system with invite-only registration
- Role-based access control (admin/user roles)
- User dashboard with file management
- Password change functionality
- Admin user management interface

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
- Dynamic quota adjustment

### Fixed
- Fixed CSRF token validation on admin endpoints

## [1.0.0] - 2025-10-01

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
```

### Updating Changelog

```bash
# Before each release, move "Unreleased" items to new version section

# During development (on feature branches):
# Add entries to "Unreleased" section

# When creating release branch:
# Move "Unreleased" items to new version section
# Add release date
# Create new empty "Unreleased" section
```

---

## Docker Image Tagging

### Tag Strategy

For each git tag, create multiple Docker tags:

```bash
# Git tag: v1.2.3

# Docker tags created:
v1.2.3          # Exact version (immutable)
v1.2            # Minor version (updates with patches)
v1              # Major version (updates with minor/patch)
latest          # Latest stable release (main branch only)

# Example:
ghcr.io/fjmerc/safeshare:v1.2.3
ghcr.io/fjmerc/safeshare:v1.2
ghcr.io/fjmerc/safeshare:v1
ghcr.io/fjmerc/safeshare:latest
```

### Branch-Based Tags

```bash
# main branch
latest          # Latest production release

# develop branch
develop         # Latest development build

# Pull request #42
pr-42           # Preview for PR testing

# Commit SHA
sha-a1b2c3d     # Specific commit (for debugging)
```

### Tag Immutability

**Immutable tags** (never overwrite):
- `v1.2.3` (exact version)
- `sha-a1b2c3d` (commit SHA)

**Mutable tags** (can be overwritten):
- `latest` (updated with each release)
- `v1` (updated with minor/patch)
- `v1.2` (updated with patch)
- `develop` (updated with each commit to develop)

### Production vs. Development Tags

```bash
# Production (from main branch)
docker pull safeshare:latest        # Latest stable
docker pull safeshare:v1.2.3        # Specific version

# Development (from develop branch)
docker pull safeshare:develop       # Latest development
docker pull safeshare:v1.2.3-rc.1   # Release candidate

# Testing (from PR)
docker pull safeshare:pr-42         # PR preview
```

---

## Hotfix Process

### When to Hotfix

Create a hotfix when:
- Critical security vulnerability discovered in production
- Data loss bug in production
- Service unavailability in production
- Compliance violation in production

**Do NOT hotfix for**:
- Minor bugs that can wait for next release
- Feature requests
- Non-critical performance issues
- Documentation updates

### Hotfix Workflow

```bash
# 1. Create hotfix branch from main
git checkout main
git pull origin main
git checkout -b hotfix/fix-sql-injection

# 2. Make the fix
vim internal/database/files.go
git commit -am "fix: patch SQL injection in file search"

# 3. Test thoroughly
go test ./...

# 4. Update changelog
vim CHANGELOG.md  # Add hotfix entry
git commit -am "docs: update changelog for v1.2.1"

# 5. Merge to main and tag
git checkout main
git merge --no-ff hotfix/fix-sql-injection
git tag -a v1.2.1 -m "Hotfix v1.2.1: Patch SQL injection vulnerability

CRITICAL SECURITY FIX

Fixed SQL injection vulnerability in file search functionality.
All users should upgrade immediately.

CVE-2025-XXXXX
"

# 6. Push to trigger deployment
git push origin main v1.2.1

# 7. Merge to develop
git checkout develop
git merge --no-ff hotfix/fix-sql-injection
git push origin develop

# 8. Cleanup
git branch -d hotfix/fix-sql-injection

# 9. Notify users
# - Post security advisory on GitHub
# - Email notification to production users
# - Update status page
```

### Security Hotfix Communication

For security vulnerabilities:

1. **Do NOT** create public issue before fix is released
2. Fix vulnerability in private
3. Create security advisory **after** fix is deployed
4. Follow responsible disclosure timeline:
   - Day 0: Vulnerability reported
   - Day 1-7: Develop and test fix
   - Day 7: Release hotfix
   - Day 8: Publish security advisory
   - Day 30: Disclose full details (if appropriate)

---

## Deprecation Policy

### Deprecation Timeline

**Phase 1: Deprecation Notice** (at least 2 minor versions):
- Mark feature as deprecated in documentation
- Add deprecation warning in logs
- Announce in changelog
- Provide migration guide

**Phase 2: Final Warning** (1 minor version):
- Increase warning visibility
- Remind users in release notes

**Phase 3: Removal** (next major version):
- Remove deprecated feature
- Update documentation
- Provide breaking change migration guide

### Example

```
v1.5.0: Deprecate ADMIN_USERNAME/ADMIN_PASSWORD in favor of admin_credentials table
        - Add deprecation warning in logs
        - Document migration in UPGRADING.md

v1.6.0: Reminder that ADMIN_USERNAME/ADMIN_PASSWORD will be removed in v2.0

v2.0.0: Remove ADMIN_USERNAME/ADMIN_PASSWORD support
        - Only admin_credentials table supported
        - Update UPGRADING.md with migration steps
```

---

## Version Management Scripts

### Automated Version Bumping

`scripts/bump-version.sh`:

```bash
#!/bin/bash
# Usage: ./scripts/bump-version.sh major|minor|patch

set -e

BUMP_TYPE=$1

if [ -z "$BUMP_TYPE" ]; then
  echo "Usage: $0 major|minor|patch"
  exit 1
fi

# Get current version from last tag
CURRENT_VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
CURRENT_VERSION=${CURRENT_VERSION#v}  # Remove 'v' prefix

IFS='.' read -ra VERSION_PARTS <<< "$CURRENT_VERSION"
MAJOR=${VERSION_PARTS[0]}
MINOR=${VERSION_PARTS[1]}
PATCH=${VERSION_PARTS[2]}

# Bump version
case $BUMP_TYPE in
  major)
    MAJOR=$((MAJOR + 1))
    MINOR=0
    PATCH=0
    ;;
  minor)
    MINOR=$((MINOR + 1))
    PATCH=0
    ;;
  patch)
    PATCH=$((PATCH + 1))
    ;;
  *)
    echo "Invalid bump type: $BUMP_TYPE"
    exit 1
    ;;
esac

NEW_VERSION="v${MAJOR}.${MINOR}.${PATCH}"

echo "Current version: v$CURRENT_VERSION"
echo "New version: $NEW_VERSION"

# Update version in files (if applicable)
if [ -f "version.txt" ]; then
  echo "$NEW_VERSION" > version.txt
  git add version.txt
fi

# Update CHANGELOG.md
# (Manual step - remind user)
echo ""
echo "Next steps:"
echo "1. Update CHANGELOG.md with changes for $NEW_VERSION"
echo "2. Commit changes: git commit -m 'chore: bump version to $NEW_VERSION'"
echo "3. Tag release: git tag -a $NEW_VERSION -m 'Release $NEW_VERSION'"
echo "4. Push: git push origin main $NEW_VERSION"
```

Usage:
```bash
chmod +x scripts/bump-version.sh
./scripts/bump-version.sh minor  # v1.2.0 → v1.3.0
```

### List Releases

```bash
# List all releases
git tag -l "v*" --sort=-v:refname

# List releases with dates
git tag -l "v*" --sort=-v:refname --format='%(refname:short) %(creatordate:short)'

# Show release notes
git tag -l "v*" -n9 --sort=-v:refname
```

---

## Version Compatibility Matrix

Track compatibility between versions:

| SafeShare Version | Min Docker | Min Go | Database Schema | Config Version |
|-------------------|------------|--------|-----------------|----------------|
| v2.0.0            | 24.0       | 1.21   | 3               | 2              |
| v1.2.0            | 20.10      | 1.21   | 2               | 1              |
| v1.1.0            | 20.10      | 1.20   | 1               | 1              |
| v1.0.0            | 20.10      | 1.20   | 1               | 1              |

---

## Summary

**Quick Reference**:

```bash
# Feature development
git checkout -b feature/my-feature develop
# ... develop ...
git checkout develop
git merge feature/my-feature

# Create release
git checkout -b release/v1.2.0 develop
# ... final fixes ...
git checkout main
git merge release/v1.2.0
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin main v1.2.0

# Hotfix
git checkout -b hotfix/fix-bug main
# ... fix ...
git checkout main
git merge hotfix/fix-bug
git tag -a v1.2.1 -m "Hotfix v1.2.1"
git push origin main v1.2.1
```

**See also**:
- [CI_CD_EXAMPLES.md](./CI_CD_EXAMPLES.md) - Automated release pipelines
- [PRODUCTION.md](./PRODUCTION.md) - Deployment procedures
- [CHANGELOG.md](./CHANGELOG.md) - Version history
