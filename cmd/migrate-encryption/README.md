# SafeShare Encryption Migration Tool

Command-line utility to migrate legacy encrypted files to SFSE1 (Streaming File System Encryption v1) format.

## Purpose

SafeShare originally used a legacy encryption format that loads entire files into memory for decryption. This tool migrates those files to the modern SFSE1 streaming format, which:

- **Eliminates format confusion vulnerabilities** - SFSE1 uses magic header validation
- **Improves performance** - Streaming encryption/decryption for large files
- **Reduces memory usage** - No need to load entire files into RAM
- **Enables HTTP Range support** - Efficient partial content delivery

## Security Context

This migration addresses a P1 security finding where the legacy `IsEncrypted()` function only checked file length (>= 29 bytes) without validating the encrypted structure. While the risk was mitigated by SFSE1 detection taking priority, migrating all files eliminates the vulnerability entirely.

## Prerequisites

- SafeShare database (safeshare.db)
- Uploads directory with encrypted files
- Valid 64-character hex encryption key (same key used for encryption)
- Backup of database and uploads directory (recommended)

## Installation

```bash
# Build from source
cd cmd/migrate-encryption
go build -o migrate-encryption

# Or build from project root
go build -o migrate-encryption ./cmd/migrate-encryption
```

## Usage

### Basic Usage

```bash
./migrate-encryption \
  --db /path/to/safeshare.db \
  --uploads /path/to/uploads \
  --enckey $(cat /path/to/encryption.key)
```

### Dry Run (Preview Changes)

```bash
./migrate-encryption \
  --db ./safeshare.db \
  --uploads ./uploads \
  --enckey "your-64-char-hex-key" \
  --dry-run
```

### Verbose Logging

```bash
./migrate-encryption \
  --db ./safeshare.db \
  --uploads ./uploads \
  --enckey "your-64-char-hex-key" \
  --verbose
```

## Command-Line Flags

| Flag | Description | Required | Default |
|------|-------------|----------|---------|
| `--db` | Path to SQLite database | No | `./safeshare.db` |
| `--uploads` | Path to uploads directory | No | `./uploads` |
| `--enckey` | 64-character hex encryption key | Yes | - |
| `--dry-run` | Preview migration without making changes | No | `false` |
| `--verbose` | Enable debug logging | No | `false` |
| `--version` | Show version and exit | No | - |

## How It Works

1. **Connects to database** - Queries all files (including expired)
2. **Checks encryption format** - For each file:
   - If SFSE1 → Skip (already migrated)
   - If unencrypted → Skip (no migration needed)
   - If legacy encrypted → Migrate
3. **Migrates legacy files**:
   - Decrypts using legacy `DecryptFile()` method
   - Re-encrypts using streaming `EncryptFileStreaming()` (SFSE1)
   - Replaces original file atomically
4. **Reports progress** - Logs each migration with statistics

## Output

The tool provides a detailed summary:

```
=== Migration Summary ===
Total files in database: 150
Already SFSE1 format:    120
Unencrypted files:       20
Legacy encrypted files:  10
Successfully migrated:   10
Failed migrations:       0
```

## Safety Features

- **Dry-run mode** - Preview changes without modifying files
- **Atomic replacement** - Original file only deleted after successful re-encryption
- **Error handling** - Failed migrations are logged, other files continue processing
- **Validation** - Checks encryption key format before starting
- **Cleanup** - Removes temporary files on errors

## Example Session

```bash
$ ./migrate-encryption --db /app/data/safeshare.db --uploads /app/uploads --enckey $(cat key.txt)

2025-01-22T10:30:00Z INFO starting encryption migration db=/app/data/safeshare.db uploads=/app/uploads dry_run=false
2025-01-22T10:30:00Z INFO found files in database count=50
2025-01-22T10:30:01Z INFO found legacy encrypted file claim_code=Abc...xyz filename=document.pdf size=2048576
2025-01-22T10:30:03Z INFO successfully migrated file to SFSE1 claim_code=Abc...xyz filename=document.pdf original_size=2048576 new_size=2048618
...
2025-01-22T10:35:00Z INFO migration completed successfully

=== Migration Summary ===
Total files in database: 50
Already SFSE1 format:    45
Unencrypted files:       3
Legacy encrypted files:  2
Successfully migrated:   2
Failed migrations:       0
```

## Docker Usage

If SafeShare is running in Docker:

```bash
# Stop container first (recommended)
docker stop safeshare

# Run migration inside container
docker run --rm \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  -e ENCRYPTION_KEY="your-64-char-hex-key" \
  safeshare:latest \
  /app/migrate-encryption \
    --db /app/data/safeshare.db \
    --uploads /app/uploads \
    --enckey "$ENCRYPTION_KEY"

# Restart container
docker start safeshare
```

## Performance

- **Small files (<10MB)**: ~100ms per file
- **Large files (>1GB)**: ~10-30 seconds per file (depends on CPU)
- **Memory usage**: Constant (~100MB), not dependent on file size
- **Disk space**: Temporary spike of 2x file size during migration

## Troubleshooting

### "Invalid encryption key"
- Ensure key is exactly 64 hexadecimal characters
- Generate new key: `openssl rand -hex 32`
- Verify key matches the one used for encryption

### "Failed to decrypt legacy file"
- File may be corrupted
- Wrong encryption key
- File might not actually be encrypted (false positive from length check)

### "File not found on disk"
- Database references file that doesn't exist in uploads directory
- Check `stored_filename` matches actual file on disk
- Skipped automatically, won't fail migration

### "Failed migrations: N"
- Check verbose logs for specific errors
- Disk space issues (need 2x file size temporarily)
- Permission issues (can't write to uploads directory)

## Best Practices

1. **Backup first** - Always backup database and uploads before migration
2. **Use dry-run** - Preview changes before actual migration
3. **Stop SafeShare** - Avoid concurrent file access during migration
4. **Monitor logs** - Use `--verbose` flag for detailed progress
5. **Check disk space** - Ensure 2x largest file size available
6. **Verify after** - Download a few files to confirm successful migration

## Post-Migration

After migration completes successfully:

1. **Restart SafeShare** - New downloads use SFSE1 format automatically
2. **Test downloads** - Verify files decrypt correctly
3. **Monitor logs** - Check for any decryption errors
4. **(Optional) Remove legacy support** - Update code to remove legacy decryption paths

## Security Improvements

After migrating all files to SFSE1:

- ✅ Format confusion vulnerability eliminated (SFSE1 uses magic header)
- ✅ Timing attacks mitigated (10ms normalization on decryption errors)
- ✅ Memory exhaustion prevented (streaming vs. full-file-in-memory)
- ✅ Better HTTP Range support (efficient partial decryption)

## Support

For issues or questions:
- Check verbose logs (`--verbose` flag)
- Review [SafeShare documentation](../../docs/)
- Report bugs at: https://github.com/fjmerc/safeshare/issues

## Version History

- **v1.0.0** (2025-01-22) - Initial release
  - Migrate legacy encrypted files to SFSE1 format
  - Dry-run mode
  - Verbose logging
  - Atomic file replacement
