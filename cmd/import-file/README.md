# SafeShare Import Tool

A command-line utility for importing existing files into SafeShare without re-uploading over the network. This tool encrypts files locally and adds them directly to the SafeShare database, making it ideal for bulk migrations, initial setup, or server-side file additions.

## Version

**v1.0.0** - Production Ready

## Features

- ✅ **Single file import** - Import individual files with full control
- ✅ **Batch import** - Import entire directories (with optional recursive scanning)
- ✅ **Dry run mode** - Preview what will be imported before executing
- ✅ **Verification** - SHA256 hash checking after encryption to ensure data integrity
- ✅ **Extension validation** - Respects SafeShare's BLOCKED_EXTENSIONS setting
- ✅ **Quota checking** - Validates against QUOTA_LIMIT_GB before importing
- ✅ **Disk space validation** - Ensures sufficient disk space before proceeding
- ✅ **Preservation mode** - Optional --no-delete flag to keep source files
- ✅ **User ownership** - Optional --user-id flag for authenticated imports
- ✅ **Progress reporting** - Real-time progress with encryption/verification times
- ✅ **JSON output** - Machine-readable output for scripting

## Use Cases

1. **Initial migrations** - Move files from other file-sharing systems to SafeShare
2. **Bulk imports** - Add many existing files without uploading through the web interface
3. **Server-side additions** - Add files directly on the server without network transfer
4. **Recovery/restoration** - Restore files from backups into SafeShare
5. **Data center transfers** - Move files between servers in the same data center

## Requirements

- Go 1.21 or higher (for building)
- Direct server access (SSH, console, etc.)
- SafeShare database path
- SafeShare uploads directory path
- Encryption key (must match running SafeShare instance)

## Installation

### Build from source

```bash
cd /path/to/safeshare
go build -o cmd/import-file/import-file ./cmd/import-file
```

The binary will be created at `cmd/import-file/import-file`.

### Using the binary

```bash
# Make executable (if needed)
chmod +x cmd/import-file/import-file

# Run directly
./cmd/import-file/import-file [flags]
```

## Usage

### Single File Import

Import a single file with full control over metadata:

```bash
./import-file \
  --source /path/to/file.iso \
  --filename "Ubuntu 22.04.iso" \
  --expires 168 \
  --maxdownloads 5 \
  --password "mysecret" \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "your-64-char-hex-key" \
  --public-url "https://share.example.com"
```

### Batch Import (Directory)

Import all files in a directory:

```bash
./import-file \
  --directory /path/to/folder \
  --recursive \
  --expires 168 \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "your-64-char-hex-key"
```

### Dry Run (Preview)

See what would be imported without making any changes:

```bash
./import-file \
  --directory /path/to/folder \
  --dry-run \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "your-64-char-hex-key"
```

### With Verification

Enable hash checking to ensure encryption integrity:

```bash
./import-file \
  --source /path/to/large-file.zip \
  --verify \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "your-64-char-hex-key"
```

### Preserve Source Files

Copy instead of move (keep original files):

```bash
./import-file \
  --directory /path/to/folder \
  --no-delete \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "your-64-char-hex-key"
```

### JSON Output (for scripting)

Get machine-readable output:

```bash
./import-file \
  --source /path/to/file.dat \
  --json \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "your-64-char-hex-key" \
  | jq .
```

## Command-Line Flags

### Input Mode (mutually exclusive)

| Flag | Description | Default |
|------|-------------|---------|
| `--source <path>` | Path to single source file | - |
| `--directory <path>` | Path to directory for batch import | - |
| `--recursive` | Recursively scan subdirectories | `false` |

### File Metadata

| Flag | Description | Default |
|------|-------------|---------|
| `--filename <name>` | Display filename (defaults to source filename) | - |
| `--expires <hours>` | Expiration time in hours | `168` (7 days) |
| `--maxdownloads <n>` | Maximum downloads (0 = unlimited) | `0` |
| `--password <pass>` | Optional password protection | - |
| `--user-id <id>` | Optional user ID for file ownership | `0` |

### Database and Storage (required)

| Flag | Description | Default |
|------|-------------|---------|
| `--db <path>` | Path to SafeShare database | **required** |
| `--uploads <path>` | Path to SafeShare uploads directory | **required** |
| `--enckey <key>` | Encryption key (64 hex chars) | **required** |
| `--public-url <url>` | Public URL for download links | `https://share.example.com` |
| `--ip <address>` | Uploader IP to record | `import-tool` |

### Behavior Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--dry-run` | Preview only, no changes | `false` |
| `--verify` | Verify integrity after encryption | `false` |
| `--no-delete` | Preserve source files (copy vs move) | `false` |
| `--quiet` | Minimal output for scripting | `false` |
| `--json` | JSON output format | `false` |

### Other

| Flag | Description |
|------|-------------|
| `--version` | Show version information |
| `-h, --help` | Show usage information |

## Examples

### Example 1: Production Migration (from VPS testing)

Import two large files that were successfully migrated in production:

```bash
# 21GB ISO file
./import-file \
  --source /data/ubuntu-22.04.iso \
  --filename "Ubuntu 22.04.4 LTS Server" \
  --expires 720 \
  --verify \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "$(cat /app/.encryption-key)"

# Result: Encrypted in 6m 30s, claim code: byi2Rpa4tDhxGg3_

# 12GB ZIP file
./import-file \
  --source /data/backup.zip \
  --filename "Production Backup 2025-01-10" \
  --expires 168 \
  --maxdownloads 3 \
  --password "backup2025" \
  --verify \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "$(cat /app/.encryption-key)"

# Result: Encrypted in 3m 29s, claim code: IOXHLMnJOKXJJrKY
```

**Performance observed**: 50-60 MB/s encryption speed on ARM VPS.

### Example 2: Bulk Import with Dry Run

First preview, then execute:

```bash
# Preview what would be imported
./import-file \
  --directory /data/migration \
  --recursive \
  --dry-run \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "your-key"

# If preview looks good, execute
./import-file \
  --directory /data/migration \
  --recursive \
  --verify \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "your-key"
```

### Example 3: Docker Container Import

Import files into a running SafeShare Docker container:

```bash
# Copy files into container's volume
docker cp /local/files safeshare:/app/data/import/

# Execute import inside container
docker exec safeshare /app/import-file \
  --directory /app/data/import \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "$ENCRYPTION_KEY" \
  --no-delete

# Or build and copy binary into container
docker cp cmd/import-file/import-file safeshare:/app/
docker exec safeshare /app/import-file --version
```

### Example 4: Authenticated Import (User Ownership)

Import files and assign ownership to a specific user:

```bash
# Import files for user ID 5
./import-file \
  --directory /data/user-files \
  --user-id 5 \
  --expires 720 \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "your-key"

# Files will appear in user's dashboard at /dashboard
```

### Example 5: Scripting with JSON Output

Automate imports with error handling:

```bash
#!/bin/bash
set -e

RESULT=$(./import-file \
  --source /data/important-file.zip \
  --json \
  --verify \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "$ENCRYPTION_KEY")

# Parse result
CLAIM_CODE=$(echo "$RESULT" | jq -r '.claim_code')
DOWNLOAD_URL=$(echo "$RESULT" | jq -r '.download_url')
SUCCESS=$(echo "$RESULT" | jq -r '.success')

if [ "$SUCCESS" = "true" ]; then
  echo "Import successful!"
  echo "Claim code: $CLAIM_CODE"
  echo "Download: $DOWNLOAD_URL"

  # Send notification email
  echo "$DOWNLOAD_URL" | mail -s "File Ready" user@example.com
else
  ERROR=$(echo "$RESULT" | jq -r '.error')
  echo "Import failed: $ERROR"
  exit 1
fi
```

## Output Examples

### Successful Single File Import

```
======================================================================
FILE IMPORT SUCCESSFUL
======================================================================
Filename:        Ubuntu 22.04.iso
Original Size:   21.50 GB
Encrypted Size:  21.52 GB
Claim Code:      byi2Rpa4tDhxGg3_
Download URL:    https://share.example.com/api/claim/byi2Rpa4tDhxGg3_
Expires At:      2025-11-17T14:30:00Z
Encryption Time: 6m30s
Verification Time: 6m28s
======================================================================
```

### Batch Import Summary

```
[1/15] ubuntu-22.04.iso (21.5 GB)
  ├─ Encrypting... ✓ (6m30s)
  ├─ Verifying... ✓ (6m28s)
  ├─ Claim code: byi2Rpa4tDhxGg3_
  └─ Download: https://share.example.com/api/claim/byi2Rpa4tDhxGg3_

[2/15] backup.zip (12.3 GB)
  ├─ Encrypting... ✓ (3m29s)
  ├─ Verifying... ✓ (3m31s)
  ├─ Claim code: IOXHLMnJOKXJJrKY
  └─ Download: https://share.example.com/api/claim/IOXHLMnJOKXJJrKY

[3/15] malware.exe (1.2 MB)
  └─ SKIPPED: Blocked extension (.exe)

======================================================================
BATCH IMPORT SUMMARY
======================================================================
Total files processed: 15
Successful:           13
Skipped:              1
Failed:               1
Total time:           45m23s
Total size:           118.70 GB
Total encrypted:      118.95 GB

Failed files:
  - /data/huge-file.iso: quota exceeded (50 GB limit)
======================================================================
```

### Dry Run Output

```
DRY RUN MODE - No changes will be made

Files to be imported:

  1. ubuntu-22.04.iso (21.50 GB)
     ├─ Display name: ubuntu-22.04.iso
     ├─ Size: 21.50 GB
     ├─ Expires: 2025-11-17T14:30:00Z
     ├─ Max downloads: unlimited
     ├─ Password protected: false
     └─ Will delete source: true

  2. backup.zip (12.30 GB)
     ├─ Display name: backup.zip
     ├─ Size: 12.30 GB
     ├─ Expires: 2025-11-17T14:30:00Z
     ├─ Max downloads: 5
     ├─ Password protected: true
     └─ Will delete source: true

SUMMARY:
  Total files: 15
  Will import: 13
  Will skip: 1
  Errors: 1
  Total size: 118.70 GB
  Verification: enabled (will double processing time)

Run without --dry-run to perform the import.
```

## Security Considerations

### Server Access Required

This tool requires **direct server access** (SSH, console, physical access). It is designed for **administrators only** and should never be exposed via a web API.

### Encryption Key Management

- The encryption key (`--enckey`) **must match** the key used by the running SafeShare instance
- **Wrong key** = files cannot be downloaded (no decryption possible)
- **Lost key** = data is permanently unrecoverable
- Store the key securely (environment variable, secrets manager, encrypted file)

### Source File Deletion

By default, the tool **deletes source files** after successful import (move operation). This is intentional for migration scenarios, but be cautious:

- Use `--dry-run` to preview before executing
- Use `--no-delete` to preserve source files (copy operation)
- Use `--verify` to ensure encryption succeeded before deletion

### Extension Blocking

The tool respects SafeShare's `BLOCKED_EXTENSIONS` setting from the database. Files with blocked extensions will be **skipped automatically** in batch mode.

### Quota Enforcement

If `QUOTA_LIMIT_GB` is set in SafeShare, the tool will validate quota before importing. Files that would exceed the quota are **skipped** in batch mode.

## File Size Handling

**IMPORTANT**: The import tool correctly stores the **original (decrypted) file size** in the database, NOT the encrypted file size on disk. This is critical for proper HTTP Range request handling and download functionality.

### How It Works

- **Database `file_size` field**: Stores the original file size before encryption
- **Physical file on disk**: Larger due to SFSE1 encryption overhead (~0.1-1% for large files)
- **Why this matters**: `DecryptFileStreamingRange()` uses the database size to calculate byte ranges during downloads

### Example

```
Original file: 10.0 GB
Database file_size: 10,737,418,240 bytes (10.0 GB) ✓
Encrypted file on disk: 10,748,903,168 bytes (10.01 GB)
Overhead: ~11 MB (0.1%)
```

### Technical Details

The SFSE1 encryption format adds:
- Header metadata (version, chunk size, chunk count): ~10 bytes
- Nonce per chunk (12 bytes × number of chunks): ~8 KB for 10 GB file
- Authentication tag per chunk (16 bytes × number of chunks): ~11 KB for 10 GB file

This overhead is automatically handled by the import tool and does not affect users - they see and download the original file size.

## Performance

### Encryption Speed

Based on production testing:

- **ARM VPS**: 50-60 MB/s encryption speed
- **x86_64 server**: Expected 80-120 MB/s (higher single-core performance)

### Verification Overhead

Verification (--verify flag) requires decrypting the entire file to compare hashes, which effectively **doubles the processing time**:

- 21GB file: 6m30s encryption + 6m28s verification = **~13 minutes total**
- 12GB file: 3m29s encryption + 3m31s verification = **~7 minutes total**

Verification is recommended for:
- Production migrations
- Critical data
- Large files where corruption would be expensive

Skip verification for:
- Trusted sources
- Time-sensitive imports
- Small files where re-import is cheap

### Disk Space Requirements

The tool validates that sufficient disk space is available before importing. Required space:

- **Minimum**: File size × 1.1 (encryption adds ~2% overhead + AES-GCM tags)
- **Recommended**: At least 1GB free space total

## Troubleshooting

### Error: "encryption key must be exactly 64 hexadecimal characters"

**Cause**: Invalid encryption key format.

**Solution**: Generate a valid key or retrieve from SafeShare configuration:

```bash
# Generate new key (DO NOT use if SafeShare is already running with a key!)
openssl rand -hex 32

# Get key from Docker container environment
docker exec safeshare env | grep ENCRYPTION_KEY

# Get key from systemd service
systemctl show safeshare.service | grep ENCRYPTION_KEY
```

### Error: "verification failed: hash mismatch"

**Cause**: File was corrupted during encryption or disk error.

**Solution**:
1. Check disk health (`smartctl -a /dev/sdX`)
2. Verify source file integrity
3. Try re-importing the file
4. Check for insufficient disk space

### Error: "quota exceeded"

**Cause**: Import would exceed SafeShare's storage quota.

**Solution**:
1. Check current quota: `sqlite3 safeshare.db "SELECT * FROM settings"`
2. Free up space by deleting expired files
3. Increase quota via admin dashboard
4. Import files individually to stay under quota

### Error: "blocked extension: .exe"

**Cause**: File extension is in SafeShare's blocklist.

**Solution**:
1. This is intentional for security
2. Update `BLOCKED_EXTENSIONS` in admin dashboard if needed
3. Rename file extension (not recommended for security)

### Error: "insufficient disk space"

**Cause**: Not enough free space on uploads directory.

**Solution**:
1. Check disk usage: `df -h /app/uploads`
2. Free up space: delete old files, expand disk, move uploads directory
3. Import smaller files first

### Slow encryption speed

**Cause**: CPU limitations, disk I/O bottleneck, or thermal throttling.

**Solution**:
1. Check CPU usage: `htop`
2. Check disk I/O: `iostat -x 1`
3. Run during off-peak hours
4. Use faster storage (SSD vs HDD)
5. Ensure good cooling/ventilation

### "Failed to open database" error

**Cause**: Database file not found, permissions issue, or wrong path.

**Solution**:
```bash
# Find database location
find / -name "safeshare.db" 2>/dev/null

# Check permissions
ls -l /app/data/safeshare.db

# Fix permissions (match SafeShare user)
chown safeshare:safeshare /app/data/safeshare.db
```

## Limitations

### Current Version (v1.0.0)

- ❌ **No resume capability** - Interrupted imports must restart from beginning
  - Workaround: Import files individually, not in large batches
  - Future: v2.0 will add state tracking and resume capability

- ⚠️ **No parallel processing** - Files are imported sequentially
  - Performance: 50-60 MB/s per file
  - Workaround: Run multiple import-file instances in parallel (different directories)

- ⚠️ **No progress bars** - Encryption happens silently until complete
  - Output: Time duration shown after completion
  - Workaround: Use `--verify` flag to see verification progress too

### Future Enhancements (v2.0 roadmap)

- Resume capability for interrupted imports
- Parallel file processing
- Progress bars with ETA
- Bandwidth limiting (for migrations over slow networks)
- Automatic chunking for very large files (>100GB)

## Version History

### v1.0.0 (2025-11-10)

Initial release with core features:
- Single file and batch directory import
- Dry run preview mode
- SHA256 verification
- Extension and quota validation
- Disk space checking
- User ownership support
- JSON output format
- Comprehensive error handling


## Support

For issues, questions, or feature requests:

1. Check this README and troubleshooting section
2. Review SafeShare main documentation (`CLAUDE.md`, `docs/`)
3. Check SafeShare GitHub issues: https://github.com/fjmerc/safeshare/issues
4. Contact SafeShare administrators

## License

This tool is part of SafeShare and uses the same license as the main project.
