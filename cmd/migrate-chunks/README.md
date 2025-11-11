# SFSE1 Chunk Size Migration Tool

This tool migrates existing SFSE1-encrypted files from 64MB chunks to 10MB chunks to improve HTTP Range request performance and prevent client timeouts during decryption.

## Why Migrate?

**Problem:** Files encrypted with 64MB chunks take too long to decrypt the first chunk, causing HTTP timeout issues for clients requesting partial file downloads (HTTP Range requests).

**Solution:** Re-encrypt files with 10MB chunks, reducing time-to-first-byte from ~65 seconds to ~10 seconds (or less with profiling optimizations).

## Prerequisites

- Go 1.21+ installed
- Access to SafeShare upload directory
- 64-character hex encryption key (same key used for original encryption)
- Sufficient disk space (migration requires temporary storage equal to file sizes being migrated)

## Building

```bash
# From project root
go build -o cmd/migrate-chunks/migrate-chunks ./cmd/migrate-chunks

# Or build from this directory
cd cmd/migrate-chunks
go build -o migrate-chunks .
```

## Usage

### Basic Usage

```bash
./migrate-chunks \
  --upload-dir /app/uploads \
  --encryption-key "your-64-character-hex-key"
```

### Dry Run (Preview)

Preview what would be migrated without making changes:

```bash
./migrate-chunks \
  --upload-dir /app/uploads \
  --encryption-key "your-64-character-hex-key" \
  --dry-run
```

### Verbose Logging

Enable debug logs to see detailed progress:

```bash
./migrate-chunks \
  --upload-dir /app/uploads \
  --encryption-key "your-64-character-hex-key" \
  --verbose
```

## Command-Line Flags

| Flag | Description | Required | Default |
|------|-------------|----------|---------|
| `--upload-dir` | Path to SafeShare upload directory | No | `./uploads` |
| `--encryption-key` | 64-character hex encryption key | Yes | - |
| `--dry-run` | Preview without making changes | No | `false` |
| `--verbose` | Enable debug logging | No | `false` |

## Migration Process

The tool performs a safe, atomic migration for each file:

1. **Scan** upload directory for SFSE1 files
2. **Read** chunk size from file header
3. **Skip** files already using 10MB chunks
4. **For each file needing migration:**
   - Decrypt to temporary file (`.decrypted.tmp`)
   - Encrypt with 10MB chunks to new temp file (`.encrypted.tmp`)
   - Create backup of original (`.backup`)
   - Atomically replace original with new file
   - Remove backup on success
   - Clean up temp files

**Safety features:**
- Backup created before replacing original
- Backup restored if migration fails
- Temp files automatically cleaned up
- Original file preserved until migration succeeds

## Output

### JSON Structured Logs

The tool outputs JSON logs that can be parsed by log aggregation tools:

```json
{"time":"2025-01-11T...","level":"INFO","msg":"File needs migration","path":"/app/uploads/abc123.enc","size_mb":1024,"old_chunk_mb":64,"new_chunk_mb":10}
{"time":"2025-01-11T...","level":"INFO","msg":"Successfully migrated file","path":"/app/uploads/abc123.enc"}
```

### Summary Statistics

```
=== MIGRATION COMPLETE ===
Successfully migrated: 42 files
Failed: 0 files
```

## Examples

### Docker Container Migration

```bash
# Get encryption key from container
ENCKEY=$(docker exec safeshare printenv ENCRYPTION_KEY)

# Run migration inside container
docker exec safeshare /app/migrate-chunks \
  --upload-dir /app/uploads \
  --encryption-key "$ENCKEY"
```

### Dry Run Before Migrating Production

```bash
# Preview what would be migrated
./migrate-chunks \
  --upload-dir /mnt/storage/safeshare/uploads \
  --encryption-key "$(cat /etc/safeshare/encryption.key)" \
  --dry-run \
  --verbose | tee migration-preview.log

# Review the preview
grep "Would migrate" migration-preview.log

# Run actual migration
./migrate-chunks \
  --upload-dir /mnt/storage/safeshare/uploads \
  --encryption-key "$(cat /etc/safeshare/encryption.key)" \
  --verbose | tee migration.log
```

### Migrate Specific Subdirectory

```bash
# Only migrate files in specific subdirectory
./migrate-chunks \
  --upload-dir /app/uploads/user-123 \
  --encryption-key "$ENCRYPTION_KEY"
```

## Performance

Migration speed depends on:
- File sizes
- Disk I/O performance
- CPU performance (AES-GCM encryption/decryption)

**Typical performance (ARM VPS):**
- Small files (<100MB): 1-5 seconds per file
- Large files (1-10GB): 1-10 minutes per file
- Throughput: ~54-58 MB/s encryption, similar decryption

**Example:** Migrating a 1GB file takes approximately:
- Decrypt: 18 seconds
- Encrypt: 18 seconds
- Total: ~36 seconds + disk I/O overhead

## Troubleshooting

### Error: "encryption key must be 64 hex characters"

The encryption key must be exactly 64 hexadecimal characters (0-9, a-f). Generate a new key with:

```bash
openssl rand -hex 32
```

### Error: "Failed to decrypt"

Causes:
- Wrong encryption key
- File corrupted
- File not actually SFSE1 encrypted

Solutions:
- Verify encryption key matches original
- Check file integrity
- Use `--verbose` to see detailed error messages

### Error: "No space left on device"

Migration requires temporary disk space equal to file size (decrypt + encrypt temps).

Solutions:
- Free up disk space
- Migrate files in batches
- Use external storage for upload directory

### Files Skipped: "unexpected chunk size"

The tool only migrates files with 64MB chunks. Files with other chunk sizes are skipped as they don't need migration.

## Post-Migration

After successful migration:

1. **Verify files are accessible:**
   ```bash
   # Test download a migrated file
   curl "http://localhost:8080/api/claim/YOUR_CLAIM_CODE" -o test.dat
   ```

2. **Check profiling logs:**
   ```bash
   # Look for performance improvements in logs
   docker logs safeshare 2>&1 | grep "DecryptFileStreamingRange: completed"
   ```

3. **Monitor client timeouts:**
   - Should see reduction in timeout errors
   - Time-to-first-byte should be under 10 seconds (vs 65 seconds before)

## Integration with Deployment

### During Deployment

Add migration step to deployment process:

```bash
#!/bin/bash
# deploy-with-migration.sh

# 1. Build new image with 10MB chunk size
docker build -t safeshare:latest .

# 2. Stop current container
docker stop safeshare

# 3. Run migration on existing files
docker run --rm \
  -v safeshare-uploads:/app/uploads \
  -e ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  safeshare:latest \
  /app/migrate-chunks --upload-dir /app/uploads --encryption-key "$ENCRYPTION_KEY"

# 4. Start new container
docker run -d --name safeshare -p 8080:8080 \
  -v safeshare-uploads:/app/uploads \
  -e ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  safeshare:latest
```

### Automated Migration Check

Add to container startup script to auto-migrate on first run:

```bash
# In entrypoint.sh
if [ -f /app/migrate-chunks ] && [ ! -f /app/data/.migration-complete ]; then
  echo "Running chunk size migration..."
  /app/migrate-chunks --upload-dir /app/uploads --encryption-key "$ENCRYPTION_KEY"
  touch /app/data/.migration-complete
fi

# Start SafeShare
/app/safeshare
```

## Safety Considerations

1. **Backup before migration:**
   ```bash
   tar -czf uploads-backup-$(date +%Y%m%d).tar.gz /app/uploads/
   ```

2. **Test on non-production first:**
   - Copy a few files to test directory
   - Run migration on test directory
   - Verify files can be decrypted/downloaded

3. **Monitor disk space:**
   - Migration requires 2x file size temporarily
   - Use `--dry-run` to estimate space needed

4. **Incremental migration:**
   - Migrate files in batches
   - Test after each batch
   - Allows rollback if issues discovered

## Related Documentation

- [Encryption Documentation](../../docs/ENCRYPTION.md)
- [HTTP Range Support](../../docs/HTTP_RANGE_SUPPORT.md)
- [Performance Tuning](../../CLAUDE.md#encryption-architecture)
