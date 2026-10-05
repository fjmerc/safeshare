# SafeShare Upgrade Guide

This guide provides version-specific upgrade instructions for SafeShare. Always backup your data before upgrading.

## Table of Contents

- [General Upgrade Process](#general-upgrade-process)
- [Pre-Upgrade Checklist](#pre-upgrade-checklist)
- [Version Numbering Note](#version-numbering-note)
- [Version-Specific Upgrades](#version-specific-upgrades)
  - [Upgrading to v1.11.x](#upgrading-to-v111x)
  - [Upgrading to v1.10.x](#upgrading-to-v110x)
  - [Upgrading to v1.9.0](#upgrading-to-v190)
  - [Upgrading to v1.6.0](#upgrading-to-v160)
  - [Upgrading to v2.8.x](#upgrading-to-v28x)
  - [Upgrading to v2.7.x](#upgrading-to-v27x)
  - [Upgrading to v2.6.x](#upgrading-to-v26x)
  - [Upgrading to v2.5.x](#upgrading-to-v25x)
  - [Upgrading to v2.3.x](#upgrading-to-v23x)
  - [Upgrading to v2.1.x](#upgrading-to-v21x)
  - [Upgrading to v2.0.x](#upgrading-to-v20x)
  - [Upgrading from v1.x to v2.x](#upgrading-from-v1x-to-v2x)
- [Rollback Procedures](#rollback-procedures)
- [Post-Upgrade Verification](#post-upgrade-verification)

---

## General Upgrade Process

### Standard Docker Upgrade

```bash
# 1. Backup current state
./backup-safeshare.sh  # Or your backup script

# 2. Pull new image
docker pull safeshare:latest
# Or a specific version (see CHANGELOG.md for the latest release):
docker pull safeshare:<version>

# 3. Stop current container
docker stop safeshare

# 4. Remove old container (volumes are preserved)
docker rm safeshare

# 5. Start with new image
docker run -d \
  --name safeshare \
  # ... your existing configuration ...
  safeshare:<version>

# 6. Verify health
curl http://localhost:8080/health

# 7. Check logs for migration messages
docker logs safeshare | head -50
```

### Docker Compose Upgrade

```bash
# 1. Backup
docker-compose exec safeshare /app/backup.sh

# 2. Update image tag in docker-compose.yml
# Change: image: safeshare:<old-version>
# To:     image: safeshare:<new-version>

# 3. Pull and recreate
docker-compose pull
docker-compose up -d

# 4. Verify
docker-compose logs -f safeshare
```

---

## Pre-Upgrade Checklist

Before upgrading, ensure:

- [ ] **Backup database:** `cp /app/data/safeshare.db /backup/safeshare-$(date +%Y%m%d).db`
- [ ] **Backup uploads:** `tar -czf /backup/uploads-$(date +%Y%m%d).tar.gz /app/uploads`
- [ ] **Backup `audit.key`:** `cp -p /app/data/audit.key /backup/` (v1.11.0+; or note your `AUDIT_LOG_KEY`). The audit log's signing key is not in the database or in SafeShare's built-in backups
- [ ] **Document encryption key:** Verify you have the encryption key stored securely
- [ ] **Note current version:** `curl http://localhost:8080/api/config | jq .version`
- [ ] **Check disk space:** Ensure sufficient space for migrations
- [ ] **Review changelog:** Read [CHANGELOG.md](CHANGELOG.md) for breaking changes
- [ ] **Plan maintenance window:** Some upgrades may require brief downtime

---

## Version Numbering Note

SafeShare's version numbers were reset in November 2025 from v2.8.3 to v1.0.0 (see the Version Reset Notice in [CHANGELOG.md](CHANGELOG.md)). v1.0.0 contains everything in v2.8.3. The **v1.6.0 and later** sections below use the current numbering. The sections titled **v2.x** (and "from v1.x to v2.x") describe the older numbering that preceded the reset, so a "v2.x" install is older than any current v1.x release, and the `v2.x` image tags in those sections are historical.

---

## Version-Specific Upgrades

### Upgrading to v1.11.x

#### v1.11.1

**Backup retention now deletes old backups, including manual ones.** Before v1.11.1, backup folders were named with the hour where the day belongs (`backup-YYYY-10-10T10-52-...`), and the scheduled-backup retention sweep did not recognise that name format, so old backups were never removed. Names now use the real date (`backup-YYYY-MM-DDTHH-MM-SS`, UTC) and the sweep recognises every format SafeShare has produced.

> **Action required if you use scheduled backups with retention** (`AUTO_BACKUP_ENABLED=true` and `AUTO_BACKUP_RETENTION_DAYS` above 0): after upgrading, the first scheduled backup run deletes **every** `backup-*` folder in `BACKUP_DIR` (default `/app/data/backups`) older than the retention period, including manual and CLI backups stored there. Copy anything you want to keep out of `BACKUP_DIR` first. Installs without an enabled schedule are unaffected. See [BACKUP_RESTORE.md](BACKUP_RESTORE.md#scheduled-backups-and-retention).

Frontend: the upload page no longer shows an "Upload Completed" pop-up; claim codes saved in the browser by earlier versions are deleted on the next visit and replaced by a **Recent uploads on this device** list for anonymous uploads. After upgrading, purge your CDN cache for `/assets/*` so browsers pick up the new client.

#### v1.11.0

- **Database migration (automatic):** SQLite `027_audit_logs` creates the `audit_logs` and `audit_log_state` tables. Back up first as usual.
- **Tamper-evident audit log, on by default.** It is enabled unless the server is in anonymous mode (`AUDIT_LOG=auto`); set `AUDIT_LOG=false` to turn it off, or `AUDIT_LOG=true` to record in anonymous mode too (without anything identifying). Any other value stops startup. Entries are kept 365 days by default (adjustable in the admin dashboard's **Audit Log** tab; 0 keeps them forever).
- **Signing key:** on first start SafeShare generates `audit.key` (mode 0600) in the database's directory (`/app/data` in the Docker image, so it lives on the data volume). To supply your own key, set `AUDIT_LOG_KEY` to 64 hex characters (`openssl rand -hex 32`). **Keep the key with the database**: when moving to a new server, copy `audit.key` or set the same `AUDIT_LOG_KEY`; otherwise verification reports older entries as signed with a different key. SafeShare's own backups do not include it.
- **Multiple instances sharing one database must share one key** (set the same `AUDIT_LOG_KEY` on all of them); with separate generated keys, each instance's entries fail verification on the others. (Multi-instance deployments are not otherwise supported yet; see [HA_DEPLOYMENT.md](HA_DEPLOYMENT.md).)
- Ship the application logs off the server: the newest entry's signature is logged every 100 entries and hourly, which is how deletion of the newest entries can be detected. See [SECURITY.md](SECURITY.md) (Audit Log section).

### Upgrading to v1.10.x

No configuration changes and no database migrations.

- **v1.10.1:** two simultaneous uploads of the same chunk with different contents no longer silently replace one another; the first stored wins and the other gets `409 CHUNK_CONFLICT` (success if its bytes are identical). On a filesystem without hard links the old behaviour is kept and a warning is logged once. The Go, Python and TypeScript SDKs now keep polling `/api/upload/status` through `429` instead of abandoning the upload; upgrade your SDKs. Dialogs and notifications are now screen-reader and keyboard accessible.
- **v1.10.0:** Pickup-tab downloads are handed to the browser's own download manager instead of being buffered in page memory (the in-page progress bar and Pause/Cancel buttons are gone; end-to-end encrypted files are unchanged). **Quota behaviour (T30):** a chunked upload that stores no new chunk for an hour stops reserving its full size against `QUOTA_LIMIT_GB` and counts only the bytes received; its next new chunk re-reserves the rest, or fails with `507 QUOTA_EXCEEDED` if the quota has filled meanwhile. Purge your CDN cache for `/assets/*` after upgrading.

### Upgrading to v1.9.0

No database migrations. Behaviour changes to review:

- **Uploads now stream to disk instead of memory.** Regular uploads are written to a temporary file under `.spool/` in the uploads directory (`/app/uploads/.spool/` in the Docker image), and chunks are streamed to disk as they arrive. Server memory use no longer grows with file size, but **the uploads volume now needs free space for in-flight uploads** and should be a local filesystem. The temporary files are unlinked as soon as they are created, so none are left behind after a crash.
- **Stalled uploads are cut off with `408 UPLOAD_TIMEOUT`.** An upload or chunk body that sends nothing for 60 seconds, or averages under 4 KiB/s, is aborted (previously it could hold the connection for up to 6 hours). The web client retries a timed-out chunk automatically; SDK upload calls return the error. A client that sends request headers too slowly is disconnected after 20 seconds. If you have scripts that upload over very slow links, make sure they keep sending data.
- **The upload status endpoint is rate limited.** `GET /api/upload/status/{id}` is limited per IP to 600x `RATE_LIMIT_UPLOAD` per hour (never under 6,000/hour). Clients should keep polling through a `429` rather than treating it as a failure; the web uploader does since v1.9.0 (SDKs since v1.10.1).
- Purge your CDN cache for `/assets/*` after upgrading.

### Upgrading to v1.6.0

Database migrations run automatically on startup (SQLite `024_download_sessions`, `025_scan_integrity`; PostgreSQL 12 and 13). Back up first as usual. Behaviour changes to review:

- **Malware scanning is now enforced when enabled** (`FEATURE_MALWARE_SCAN=true`). Files are scanned before they are stored, so uploads wait for the scan, and **a ClamAV outage blocks new uploads** (503 `SCAN_UNAVAILABLE`). Set `MALWARE_SCAN_ALLOW_UNVERIFIED=true` only if you accept unscanned files during outages. Make sure clamd's `StreamMaxLength` is at least `CLAMAV_MAX_FILE_SIZE` and enable `AlertExceedsMax yes` (see docs/SECURITY.md). Existing files' scan results are relabelled "not scanned", because earlier scans of encrypted deployments inspected ciphertext.
- **Download limits are now strictly enforced.** Files with `max_downloads` use download sessions (`X-Download-Session` header). An interrupted download that resumes *without* the session token uses an additional download; the web UI always sends it. If you proxy SafeShare with CORS, expose and allow `X-Download-Session`.
- **`DOWNLOAD_RESERVATION_TTL` default is now 5 minutes** (was 30); active transfers renew their slot. New: `DOWNLOAD_SESSION_IDLE_TTL` (default 1h), `CLAMAV_SCAN_TIMEOUT` (default 180s), `MALWARE_SCAN_ALLOW_UNVERIFIED`, `MALWARE_SCAN_REJECT_UNSCANNABLE`. Also new (T42, amending ADR-014): `DOWNLOAD_SESSION_COMPLETE_GRACE` (default 5 minutes, `[1s, 1h]` range) lets a resumable download manager finish receiving the last few bytes of a capped file even if the server had already marked that download "complete" — without it, a client that paused right after the server finished writing could get an unhelpful "Download Limit Reached" instead of its remaining bytes. To restore the strict pre-T42 behaviour (a completed session's token never resolves, no matter how soon it's resumed), set `DOWNLOAD_SESSION_COMPLETE_GRACE=0` (or `off`/`disabled`).
- **SDKs:** upgrade the Go, TypeScript and Python SDKs. Older versions silently ignored `download_limit` (Go/TS) and send download passwords in the URL; the server still accepts `?password=` until **2027-03-31**.
- **Frontend:** after upgrading, purge your CDN cache for `/assets/*` and the service worker so browsers pick up the new client.

### Upgrading to v2.8.x

**From:** v2.7.x  
**Breaking Changes:** None  
**Migration Required:** Automatic (database migration 006)

#### New Features
- API Token Authentication for SDK/CLI access
- Token Management UI in user dashboard
- Webhook system for file lifecycle events
- Webhook format presets (Gotify, ntfy, Discord)

#### Upgrade Steps

```bash
# Standard upgrade process
docker pull safeshare:v2.8.3
docker stop safeshare && docker rm safeshare
docker run -d --name safeshare ... safeshare:v2.8.3
```

#### Post-Upgrade
- Database migration 006 creates `api_tokens` table automatically
- Existing sessions and files are preserved
- New API tokens can be created via dashboard

#### Webhook Configuration (Optional)
If you want to receive webhook notifications:

1. Go to Admin Dashboard > Webhooks tab
2. Create new webhook with your endpoint URL
3. Select events to subscribe to
4. Test webhook delivery

---

### Upgrading to v2.7.x

**From:** v2.6.x  
**Breaking Changes:** None  
**Migration Required:** None

#### New Features
- Intelligent health checks (healthy/degraded/unhealthy)
- Prometheus metrics endpoint (`/metrics`)
- SHA256 file integrity verification
- Trusted proxy header validation

#### Upgrade Steps

```bash
# Standard upgrade process
docker pull safeshare:v2.7.0
docker stop safeshare && docker rm safeshare
docker run -d --name safeshare ... safeshare:v2.7.0
```

#### New Configuration Options

```bash
# Trusted proxy configuration (recommended)
-e TRUST_PROXY_HEADERS=auto
-e TRUSTED_PROXY_IPS="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
```

#### Post-Upgrade
- Migration 005 adds `sha256_hash` column automatically
- Existing files won't have checksums (only new uploads)
- Health endpoints now return detailed status

---

### Upgrading to v2.6.x

**From:** v2.5.x  
**Breaking Changes:** None  
**Migration Required:** None

#### New Features
- Resumable download support (HTTP Range requests)
- ResumableDownloader JavaScript class
- Download progress tracking with pause/resume

#### Upgrade Steps

```bash
# Standard upgrade process
docker pull safeshare:v2.6.0
docker stop safeshare && docker rm safeshare
docker run -d --name safeshare ... safeshare:v2.6.0
```

#### Post-Upgrade
- Downloads automatically support resume if interrupted
- No configuration changes needed

---

### Upgrading to v2.5.x

**From:** v2.4.x  
**Breaking Changes:** None  
**Migration Required:** None

#### New Features
- `DOWNLOAD_URL` configuration for bypassing CDN timeouts
- Improved large file download reliability

#### Configuration Change

If using Cloudflare with large files, add:

```bash
-e DOWNLOAD_URL=https://downloads.example.com
```

Create DNS record for `downloads.example.com` pointing to your server with "DNS only" (grey cloud) to bypass Cloudflare proxy.

---

### Upgrading to v2.3.x

**From:** v2.2.x  
**Breaking Changes:** None  
**Migration Required:** Optional (chunk size migration)

#### New Features
- HTTP Range request support for large encrypted files
- CLI import tool for bulk file migrations
- Reduced SFSE1 chunk size (64MB → 10MB) for better streaming

#### Chunk Size Migration (Recommended for Large Encrypted Files)

If you have large encrypted files (>1GB) uploaded before this version, consider migrating to smaller chunks for better HTTP Range performance:

```bash
# Dry run first
docker run --rm \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  safeshare:v2.3.2 \
  /app/migrate-chunks --dry-run \
    --db /app/data/safeshare.db \
    --uploads /app/uploads \
    --enckey "$ENCRYPTION_KEY"

# If dry run looks good, run migration
docker run --rm \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  safeshare:v2.3.2 \
  /app/migrate-chunks \
    --db /app/data/safeshare.db \
    --uploads /app/uploads \
    --enckey "$ENCRYPTION_KEY"
```

**Note:** This migration is optional. Existing files will still work, just with slightly slower Range request performance.

---

### Upgrading to v2.1.x

**From:** v2.0.x  
**Breaking Changes:** Default timeout values changed  
**Migration Required:** None

#### Breaking Changes

**HTTP Timeout Defaults Changed:**
- Read timeout: 15s → 120s
- Write timeout: 15s → 120s
- Chunk size: 5MB → 10MB

If you had custom timeout values, they will be preserved. If you relied on defaults, behavior may change.

#### New Features
- Streaming encryption (SFSE1 format) for large files
- Toast notification system
- Upload cancel functionality
- Memory-efficient encryption (constant ~64MB usage)

#### Encryption Format Migration (Automatic)

New uploads use SFSE1 streaming format automatically. Existing files using legacy format continue to work but may be migrated for better performance:

```bash
# Optional: Migrate legacy encrypted files to SFSE1
docker run --rm \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  safeshare:v2.1.0 \
  /app/migrate-encryption --dry-run \
    --db /app/data/safeshare.db \
    --uploads /app/uploads \
    --enckey "$ENCRYPTION_KEY"
```

---

### Upgrading to v2.0.x

**From:** v1.x  
**Breaking Changes:** Yes (see below)  
**Migration Required:** Database migration (automatic)

#### Breaking Changes

1. **Chunked Upload API:**
   - New endpoints: `/api/upload/init`, `/api/upload/chunk/:id/:num`, `/api/upload/complete/:id`
   - Files ≥100MB automatically use chunked upload

2. **Database Schema:**
   - New `partial_uploads` table for tracking chunked uploads
   - New `migrations` table for schema versioning
   - Automatic migration on startup

3. **Configuration:**
   - New environment variables for chunked upload settings

#### New Configuration Options

```bash
-e CHUNKED_UPLOAD_ENABLED=true           # Enable chunked uploads
-e CHUNKED_UPLOAD_THRESHOLD=104857600    # 100MB threshold
-e CHUNK_SIZE=10485760                   # 10MB chunks
-e PARTIAL_UPLOAD_EXPIRY_HOURS=24        # Cleanup abandoned uploads
```

#### Upgrade Steps

```bash
# 1. Backup (critical!)
docker stop safeshare
docker run --rm -v safeshare-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/safeshare-v1-backup.tar.gz /data

# 2. Upgrade
docker pull safeshare:v2.0.0
docker rm safeshare
docker run -d --name safeshare ... safeshare:v2.0.0

# 3. Verify migrations ran
docker logs safeshare | grep -i migration
```

---

### Upgrading from v1.x to v2.x

**Major Version Upgrade**

This is a significant upgrade with multiple changes. Follow these steps carefully:

#### Step 1: Full Backup

```bash
# Stop SafeShare
docker stop safeshare

# Backup everything
docker run --rm \
  -v safeshare-data:/data \
  -v safeshare-uploads:/uploads \
  -v $(pwd):/backup \
  alpine tar czf /backup/safeshare-v1-complete-backup.tar.gz /data /uploads

# Also backup encryption key
echo "$ENCRYPTION_KEY" > /backup/encryption-key-backup.txt
chmod 600 /backup/encryption-key-backup.txt
```

#### Step 2: Review Breaking Changes

- Chunked upload API added
- Database schema changes (automatic migration)
- New configuration options
- Streaming encryption format (SFSE1)

#### Step 3: Upgrade

```bash
docker pull safeshare:<version>
docker rm safeshare
docker run -d \
  --name safeshare \
  # ... your existing config ...
  # Add new recommended options:
  -e TRUST_PROXY_HEADERS=auto \
  safeshare:<version>
```

#### Step 4: Verify

```bash
# Check version
curl http://localhost:8080/api/config | jq .version

# Check health
curl http://localhost:8080/health | jq .

# Check migrations
docker logs safeshare | grep -i migration

# Test upload/download
curl -X POST -F "file=@test.txt" http://localhost:8080/api/upload
```

#### Step 5: Optional Migrations

After confirming basic functionality:

1. **Migrate encryption format** (if using encryption):
   ```bash
   docker exec safeshare /app/migrate-encryption --dry-run ...
   ```

2. **Migrate chunk sizes** (for better Range request performance):
   ```bash
   docker exec safeshare /app/migrate-chunks --dry-run ...
   ```

---

## Rollback Procedures

### Quick Rollback

If upgrade fails immediately:

```bash
# Stop failed upgrade
docker stop safeshare
docker rm safeshare

# Restore previous version
docker run -d \
  --name safeshare \
  # ... same config ...
  safeshare:<previous-version>
```

### Rollback with Database Restore

If database was modified and needs rollback:

```bash
# 1. Stop SafeShare
docker stop safeshare
docker rm safeshare

# 2. Restore database backup
docker run --rm \
  -v safeshare-data:/data \
  -v $(pwd):/backup \
  alpine sh -c "rm /data/safeshare.db* && tar xzf /backup/safeshare-pre-upgrade.tar.gz -C /"

# 3. Start previous version
docker run -d --name safeshare ... safeshare:<previous-version>
```

### Rollback Considerations

- **Database migrations** are generally forward-only
- **New columns** added in upgrades won't break older versions (ignored)
- **Schema changes** that remove columns cannot be rolled back without backup
- **File format changes** (like SFSE1) require migration tools to reverse

---

## Post-Upgrade Verification

### Basic Checks

```bash
# 1. Version check
curl http://localhost:8080/api/config | jq .version

# 2. Health check
curl http://localhost:8080/health | jq .

# 3. Database integrity
docker exec safeshare sqlite3 /app/data/safeshare.db "PRAGMA integrity_check;"

# 4. Upload test
echo "test" > /tmp/test.txt
curl -X POST -F "file=@/tmp/test.txt" http://localhost:8080/api/upload

# 5. Download test (use claim code from upload)
curl http://localhost:8080/api/claim/CLAIM_CODE -o /tmp/downloaded.txt
diff /tmp/test.txt /tmp/downloaded.txt

# 6. Admin dashboard
curl -I http://localhost:8080/admin/login
```

### Security Verification

```bash
# Check security headers
curl -I http://localhost:8080/ | grep -E "X-Frame|X-Content|Content-Security"

# Check rate limiting works
for i in {1..12}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST -F "file=@/tmp/test.txt" http://localhost:8080/api/upload
done
# Should see 429 after rate limit exceeded
```

### Log Review

```bash
# Check for errors
docker logs safeshare | grep -i error

# Check for migration messages
docker logs safeshare | grep -i migration

# Check startup messages
docker logs safeshare | head -20
```

---

## Migration Tools Reference

### migrate-encryption

Converts legacy encrypted files to SFSE1 streaming format.

```bash
docker exec safeshare /app/migrate-encryption \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "$ENCRYPTION_KEY" \
  [--dry-run]
```

### migrate-chunks

Re-encrypts SFSE1 files with new chunk size (64MB → 10MB).

```bash
docker exec safeshare /app/migrate-chunks \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "$ENCRYPTION_KEY" \
  [--dry-run]
```

### import-file

Imports files directly to storage without network upload.

```bash
docker exec safeshare /app/import-file \
  --source /path/to/file \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  [--enckey "$ENCRYPTION_KEY"] \
  [--expires 168]
```

---

## Support

If you encounter issues during upgrade:

1. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
2. Review [CHANGELOG.md](CHANGELOG.md) for known issues
3. Open issue on [GitHub](https://github.com/fjmerc/safeshare/issues)

---

**Last Updated:** October 2026
**SafeShare Version:** 1.11.1
