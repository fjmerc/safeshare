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
    --backup /backups/safeshare-backup-20240101-120000 \
    --db /app/data/safeshare.db \
    --uploads /app/uploads \
    --dry-run

# Actual restore
./safeshare-backup restore \
    --backup /backups/safeshare-backup-20240101-120000 \
    --db /app/data/safeshare.db \
    --uploads /app/uploads \
    --enckey "your-64-char-hex-encryption-key"

# Restore with orphan removal
./safeshare-backup restore \
    --backup /backups/safeshare-backup-20240101-120000 \
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
./safeshare-backup verify --backup /backups/safeshare-backup-20240101-120000

# JSON output
./safeshare-backup verify --backup /backups/safeshare-backup-20240101-120000 --json
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

Each backup is created as a directory with the following structure:

```
safeshare-backup-YYYYMMDD-HHMMSS/
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

## Best Practices

### Backup Strategy

1. **Daily database backups**: Run `--mode database` daily
2. **Weekly full backups**: Run `--mode full` weekly
3. **Before major changes**: Create a full backup before upgrades

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
LATEST=$(ls -td "$BACKUP_DIR"/safeshare-backup-* | head -1)
./safeshare-backup verify --backup "$LATEST" --quiet

# Cleanup old backups (keep last 7 daily, 4 weekly)
find "$BACKUP_DIR" -maxdepth 1 -name "safeshare-backup-*" -mtime +30 -exec rm -rf {} \;
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

The backup functionality is also available programmatically:

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
    InputDir:      "/backups/safeshare-backup-20240101-120000",
    DBPath:        "/app/data/safeshare.db",
    UploadsDir:    "/app/uploads",
    HandleOrphans: backup.OrphanKeep,
})

// Verify a backup
result := backup.Verify("/backups/safeshare-backup-20240101-120000")

// List backups
backups, err := backup.ListBackups("/backups")
```

## Security Considerations

1. **Backup encryption**: Backups contain sensitive data. Store them in encrypted storage.
2. **Access control**: Restrict access to backup directories.
3. **Key management**: Store encryption keys separately from backups.
4. **Secure deletion**: When deleting old backups, use secure deletion methods.
5. **Integrity verification**: Always verify backups after creation and before restore.
