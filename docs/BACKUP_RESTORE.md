# SafeShare Backup and Restore Guide

This document describes SafeShare's backup and restore functionality, including the CLI tool, backup modes, and best practices.

## Overview

SafeShare provides a comprehensive backup and restore system that supports:

- **Three backup modes**: config, database, and full
- **SQLite hot backup**: Using VACUUM INTO for consistent backups
- **Encryption key fingerprinting**: Verify the correct key before restore
- **Checksum verification**: SHA256 checksums for all backup files
- **Orphan handling**: Options for handling database records without corresponding files

## Backup Modes

### Config Mode (`--mode config`)

Backs up only configuration tables:
- `settings` - Runtime application settings
- `admin_credentials` - Admin login credentials
- `blocked_ips` - IP blocklist
- `webhook_configs` - Webhook configurations

**Use case**: Quick settings backup before configuration changes.

### Database Mode (`--mode database`)

Backs up the entire database without uploaded files:
- All config tables (above)
- `files` - File metadata records
- `users` - User accounts
- `api_tokens` - API authentication tokens
- `webhook_deliveries` - Webhook delivery history

**Excludes** (never backed up):
- `user_sessions` - Active user sessions
- `admin_sessions` - Active admin sessions
- `partial_uploads` - Incomplete chunked uploads

**Use case**: Regular database backups when files are stored separately.

### Full Mode (`--mode full`)

Backs up everything:
- Complete database (as in database mode)
- All uploaded files from the uploads directory

**Use case**: Complete system backup for disaster recovery.

## Admin Dashboard Management

Starting with SafeShare v1.4.1, backups can be managed through the Admin Dashboard web interface in addition to the CLI tool.

### Accessing the Backups Tab

1. Log into the Admin Dashboard at `/admin/dashboard`
2. Navigate to the **Backups** tab
3. View existing backups in the backup directory
4. Download backups as zip files with one click

### Downloading Backups

The Admin Dashboard provides a convenient way to download backups without SSH/terminal access:

1. In the Backups tab, locate the backup you want to download
2. Click the green download icon next to the backup
3. The backup will be packaged as a zip file and downloaded to your browser

**Supported backup types**: Config, Database, and Full backups can all be downloaded via the web interface.

**Requirements**:
- Admin authentication (admin session or user account with admin role)
- CSRF token (automatically handled by the web interface)

**Technical details**:
- Endpoint: `POST /admin/api/backups/download`
- Request body: `{"filename": "backup-YYYY-MM-DDTHH-MM-SS"}`
- Response: Streaming zip file with `Content-Type: application/zip`

---

## Scheduled Backups and Retention

SafeShare can create backups on a schedule. The scheduler runs inside the SafeShare process and starts only when `AUTO_BACKUP_ENABLED=true`.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTO_BACKUP_ENABLED` | `false` | Enable the backup scheduler |
| `AUTO_BACKUP_SCHEDULE` | `0 2 * * *` | Cron expression (5 fields; daily at 02:00 by default) |
| `AUTO_BACKUP_MODE` | `full` | `full`, `database`, or `config` |
| `AUTO_BACKUP_RETENTION_DAYS` | `30` | Days to keep backups; `0` = keep forever |
| `BACKUP_DIR` | `<DATA_DIR>/backups` | Directory backups are written to |

At startup these variables create (or overwrite) a schedule named `default`. Changes made to that schedule through the admin API (the Admin Dashboard has no schedule editor) are replaced by the environment values on the next restart.

### Retention Deletes Every Backup in `BACKUP_DIR`

> **Warning**: Since v1.11.1, when a scheduled run finishes and the schedule's retention is greater than 0, SafeShare deletes **every** folder in `BACKUP_DIR` whose name matches `backup-*` (`backup-YYYY-MM-DDTHH-MM-SS`, or the older `backup-YYYYMMDD-HHMMSS`, optionally with a `-<number>` suffix) and whose modification time is older than the retention period. This includes **manual backups** made from the Admin Dashboard or the `safeshare-backup` CLI if they are written to the same directory. Folders that do not match that name pattern are left alone.
>
> To keep a backup longer than the retention period, copy it out of `BACKUP_DIR` (or download it from the Admin Dashboard), or set the schedule's retention to `0`.

Retention also removes backup-run history records older than the cutoff.

### Admin API

All endpoints require an admin session. Endpoints that change state also require a CSRF token (`X-CSRF-Token`).

| Method | Path | CSRF | Description |
|--------|------|------|-------------|
| `GET` | `/admin/api/backup-schedules` | No | List schedules (`{"schedules": [...]}`) |
| `GET` | `/admin/api/backup-schedules/{id}` | No | Get one schedule |
| `PUT` | `/admin/api/backup-schedules/{id}` | Yes | Update `name`, `enabled`, `schedule` (cron), `mode`, `retention_days` (unknown fields are rejected) |
| `GET` | `/admin/api/backup-runs` | No | Run history. Query: `schedule_id`, `status`, `trigger_type`, `limit` (1-1000, default 100), `offset` |
| `GET` | `/admin/api/backup-runs/{id}` | No | Get one run |
| `GET` | `/admin/api/backup-stats` | No | Run statistics and `scheduler_running` |
| `POST` | `/admin/api/backup-trigger` | Yes | Start a backup now. Body: `{"mode": "full"}` (default `full`). Returns `202`; `409` if one is already running |
| `GET` | `/admin/api/backup-running` | No | `{"running": false}` or the running backup with `elapsed_ms` and an estimated `progress` |

A backup started through `backup-trigger` is recorded as a run but is not tied to a schedule's retention until the next scheduled run applies it.

---

## CLI Tool Usage

### Building the CLI Tool

```bash
# Build the backup tool
go build -o safeshare-backup ./cmd/safeshare-backup

# Or build inside Docker
docker run --rm -v "$PWD":/app -w /app golang:1.24 \
    go build -o safeshare-backup ./cmd/safeshare-backup
```

### Creating Backups

```bash
# Full backup (database + files)
./safeshare-backup create \
    --mode full \
    --db /app/data/safeshare.db \
    --uploads /app/uploads \
    --output /backups \
    --enckey "your-64-char-hex-encryption-key"

# Database-only backup
./safeshare-backup create \
    --mode database \
    --db /app/data/safeshare.db \
    --output /backups

# Config-only backup
./safeshare-backup create \
    --mode config \
    --db /app/data/safeshare.db \
    --output /backups
```

**Options:**
- `--mode`: Backup mode (config, database, full)
- `--db`: Path to SafeShare database (required)
- `--uploads`: Path to uploads directory (required for full mode)
- `--output`: Output directory for backups (required)
- `--enckey`: Encryption key for fingerprinting (optional but recommended)
- `--quiet`: Minimal output
- `--json`: JSON output format

### Restoring Backups

```bash
# Preview restore (dry run)
./safeshare-backup restore \
    --backup /backups/backup-2024-01-01T12-00-00 \
    --db /app/data/safeshare.db \
    --uploads /app/uploads \
    --dry-run

# Actual restore
./safeshare-backup restore \
    --backup /backups/backup-2024-01-01T12-00-00 \
    --db /app/data/safeshare.db \
    --uploads /app/uploads \
    --enckey "your-64-char-hex-encryption-key"

# Restore with orphan removal
./safeshare-backup restore \
    --backup /backups/backup-2024-01-01T12-00-00 \
    --db /app/data/safeshare.db \
    --orphans remove
```

**Options:**
- `--backup`: Path to backup directory (required)
- `--db`: Path to restore database to (required)
- `--uploads`: Path to restore uploads to (required for full backups)
- `--enckey`: Encryption key for verification
- `--orphans`: Orphan handling mode (keep, remove, prompt)
- `--dry-run`: Preview without making changes
- `--force`: Overwrite existing data without confirmation
- `--quiet`: Minimal output
- `--json`: JSON output format

### Verifying Backups

```bash
# Verify backup integrity
./safeshare-backup verify --backup /backups/backup-2024-01-01T12-00-00

# JSON output
./safeshare-backup verify --backup /backups/backup-2024-01-01T12-00-00 --json
```

**Verification checks:**
- Manifest file exists and is valid JSON
- All files listed in manifest exist
- SHA256 checksums match for all files
- Backup mode is valid
- Required files present for backup mode

### Listing Backups

```bash
# List all backups in a directory
./safeshare-backup list --dir /backups

# JSON output
./safeshare-backup list --dir /backups --json
```

## Backup Structure

Each backup is created as a directory named `backup-YYYY-MM-DDTHH-MM-SS` (UTC). If that name is already taken, `-<number>` is appended. Directories made by older versions may be named `backup-YYYYMMDD-HHMMSS`.

```
backup-YYYY-MM-DDTHH-MM-SS/
├── manifest.json        # Backup metadata and checksums
├── database.db          # SQLite database backup
└── uploads/             # Uploaded files (full mode only)
    ├── uuid-1
    ├── uuid-2
    └── ...
```

### Manifest Format

```json
{
    "version": "1.0",
    "created_at": "2024-01-15T10:30:00Z",
    "safeshare_version": "1.4.0",
    "mode": "full",
    "includes": {
        "settings": true,
        "users": true,
        "file_metadata": true,
        "files": true,
        "webhooks": true,
        "api_tokens": true,
        "blocked_ips": true,
        "admin_credentials": true
    },
    "stats": {
        "users_count": 10,
        "file_records_count": 150,
        "files_backed_up": 150,
        "webhooks_count": 2,
        "api_tokens_count": 5,
        "blocked_ips_count": 3,
        "total_size_bytes": 1073741824,
        "database_size_bytes": 5242880,
        "files_size_bytes": 1068498944
    },
    "checksums": {
        "database.db": "sha256:abc123...",
        "uploads/uuid-1": "sha256:def456..."
    },
    "encryption": {
        "enabled": true,
        "key_fingerprint": "sha256:..."
    }
}
```

## Orphan Handling

When restoring a database-only backup, some file records in the database may reference files that don't exist in the uploads directory. These are called "orphans."

### Orphan Handling Modes

| Mode | Behavior |
|------|----------|
| `keep` | Keep orphan records in the database. Downloads will fail gracefully with a "file not found" error. |
| `remove` | Delete orphan records from the database during restore. |
| `prompt` | Interactive prompt for each orphan (CLI only, not available with `--json`). |

### Recommendations

- **For disaster recovery**: Use `keep` to preserve all metadata
- **For clean slate**: Use `remove` to eliminate broken references
- **For selective cleanup**: Use `prompt` to decide case-by-case

## Encryption Key Fingerprinting

When creating backups with `--enckey`, SafeShare computes a SHA256 fingerprint of your encryption key and stores it in the manifest. This allows verification during restore without storing the actual key.

**During restore:**
- If the provided key's fingerprint doesn't match, you'll receive a warning
- Files encrypted with a different key cannot be decrypted
- The restore will still proceed, but affected files won't be downloadable

## Audit Log Key

SafeShare's audit log (v1.11.0+) is signed with a key that is deliberately **not** stored in the database. Backups contain the database (including the audit log entries) but **not the key**.

Back up `/app/data/audit.key` (the file sits next to the database; mode 0600) together with the database, or set the same `AUDIT_LOG_KEY` (64 hex characters) on the new server. If you restore onto a server with a different key, audit log integrity verification reports the older entries as signed with a different key. A restore on the same server keeps working because the key file stays in place. See the Audit Log section of [SECURITY.md](SECURITY.md).

## Best Practices

### Backup Strategy

1. **Daily database backups**: Run `--mode database` daily
2. **Weekly full backups**: Run `--mode full` weekly
3. **Before major changes**: Create a full backup before upgrades
4. **Keep long-lived backups outside `BACKUP_DIR`** if scheduled retention is enabled (see [Scheduled Backups and Retention](#scheduled-backups-and-retention))

### Backup Script Example

```bash
#!/bin/bash
# SafeShare backup script

BACKUP_DIR="/backups/safeshare"
DB_PATH="/app/data/safeshare.db"
UPLOADS_DIR="/app/uploads"
ENCRYPTION_KEY="your-64-char-hex-key"

# Create timestamped backup
./safeshare-backup create \
    --mode full \
    --db "$DB_PATH" \
    --uploads "$UPLOADS_DIR" \
    --output "$BACKUP_DIR" \
    --enckey "$ENCRYPTION_KEY" \
    --quiet

# Verify the latest backup
LATEST=$(ls -td "$BACKUP_DIR"/backup-* | head -1)
./safeshare-backup verify --backup "$LATEST" --quiet

# Cleanup backups older than 30 days
find "$BACKUP_DIR" -maxdepth 1 -type d -name "backup-*" -mtime +30 -exec rm -rf {} +

# The audit log signing key (/app/data/audit.key) is NOT part of these backups.
# Copy it to a separate, secured location (see "Audit Log Key" below).
```

### Docker Backup Example

```bash
# Backup from Docker container
docker run --rm \
    -v safeshare-data:/app/data:ro \
    -v safeshare-uploads:/app/uploads:ro \
    -v /host/backups:/backups \
    safeshare:latest \
    /app/safeshare-backup create \
        --mode full \
        --db /app/data/safeshare.db \
        --uploads /app/uploads \
        --output /backups
```

## Troubleshooting

### "Path contains invalid characters"

The backup path validation rejects special characters for security. Use simple alphanumeric paths without spaces or special characters.

### "Encryption key fingerprint does not match"

The encryption key provided during restore is different from the one used when the backup was created. Files may not be decryptable with the wrong key.

### "Database is locked"

SQLite database is in use by another process. The backup uses VACUUM INTO which requires exclusive access momentarily. Retry or ensure no other processes are accessing the database.

### Large backup sizes

For very large uploads directories:
1. Consider `--mode database` for more frequent backups
2. Use file-level deduplication in your backup storage
3. Consider compressing the backup directory after creation

## API Reference

The backup functionality is available both programmatically and via HTTP API.

### Go Package API

```go
import "github.com/fjmerc/safeshare/internal/backup"

// Create a backup
result, err := backup.Create(backup.CreateOptions{
    Mode:          backup.ModeFull,
    DBPath:        "/app/data/safeshare.db",
    UploadsDir:    "/app/uploads",
    OutputDir:     "/backups",
    EncryptionKey: "your-64-char-hex-key",
})

// Restore from a backup
result, err := backup.Restore(backup.RestoreOptions{
    InputDir:      "/backups/backup-2024-01-01T12-00-00",
    DBPath:        "/app/data/safeshare.db",
    UploadsDir:    "/app/uploads",
    HandleOrphans: backup.OrphanKeep,
})

// Verify a backup
result := backup.Verify("/backups/backup-2024-01-01T12-00-00")

// List backups
backups, err := backup.ListBackups("/backups")
```

### HTTP API Endpoints

#### Download Backup

**Endpoint**: `POST /admin/api/backups/download`

**Authentication**: Requires admin session cookie and CSRF token

**Request Body** (JSON):
```json
{
  "filename": "backup-2024-01-01T12-00-00"
}
```

**Response**:
- **Content-Type**: `application/zip`
- **Content-Disposition**: `attachment; filename="backup-2024-01-01T12-00-00.zip"`
- **Body**: Streaming zip file containing backup directory

**Example** (using curl with admin session):
```bash
curl -X POST https://share.example.com/admin/api/backups/download \
  -H "Content-Type: application/json" \
  -H "Cookie: admin_session=<session_token>" \
  -H "X-CSRF-Token: <csrf_token>" \
  -d '{"filename": "backup-2024-01-01T12-00-00"}' \
  -o backup.zip
```

**Response Codes**:
- `200 OK` - Backup downloaded successfully
- `400 Bad Request` - Invalid filename or missing parameter
- `401 Unauthorized` - Not authenticated as admin
- `403 Forbidden` - Invalid CSRF token
- `404 Not Found` - Backup not found
- `500 Internal Server Error` - Failed to create zip or read backup files

## Security Considerations

1. **Backup encryption**: Backups contain sensitive data. Store them in encrypted storage.
2. **Access control**: Restrict access to backup directories.
3. **Key management**: Store encryption keys separately from backups.
4. **Secure deletion**: When deleting old backups, use secure deletion methods.
5. **Integrity verification**: Always verify backups after creation and before restore.
