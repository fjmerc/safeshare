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
| `--enckey` | 64-character hex encryption key | Yes (except `--verify` without `--verify-decrypt`) | - |
| `--dry-run` | Preview migration without making changes | No | `false` |
| `--verbose` | Enable debug logging | No | `false` |
| `--version` | Show version and exit | No | - |
| `--verify` | Read-only: classify every stored file and report problems (see below) | No | `false` |
| `--verify-decrypt` | With `--verify`: also decrypt the first chunk of each SFSE file to check the key | No | `false` |
| `--verify-hash` | With `--verify`: read every byte of every file and check content integrity end to end (implies `--verify-decrypt`) | No | `false` |
| `--all` | With `--verify`: include expired files too | No | `false` (non-expired only) |

## Read-Only Verification (`--verify`)

`--verify` audits every stored file against its database record without
changing anything — it opens the database with SQLite's `mode=ro`, never
issues a write statement, and only ever `os.Open`s stored files for
reading. It's the tool to run before/after a deployment, or in CI against a
copy of production data, to catch problems the migration/upgrade tools
would otherwise trip over.

For each file it classifies the on-disk format (plaintext, SFSE1, SFSE2, or
legacy single-shot AES-256-GCM) by comparing on-disk size — and, where
present, the SFSE header — against the database record, not by any
length-based heuristic. SFSE files additionally get their header and
declared ciphertext size structurally validated. With `--verify-decrypt`,
the first chunk of each SFSE file is also decrypted, which is the only way
to catch a wrong `--enckey` without decrypting the whole file.

```bash
# Classify + validate headers only (no key needed unless you want
# ErrEncryptionKeyMissing rows distinguished from everything else):
./migrate-encryption --verify --db ./safeshare.db --uploads ./uploads

# Also check the key actually decrypts each SFSE file's first chunk:
./migrate-encryption --verify --verify-decrypt \
  --db ./safeshare.db --uploads ./uploads --enckey "your-64-char-hex-key"

# Full content-integrity pass (see --verify-hash below):
./migrate-encryption --verify --verify-hash \
  --db ./safeshare.db --uploads ./uploads --enckey "your-64-char-hex-key"

# Include expired files too:
./migrate-encryption --verify --all --db ./safeshare.db --uploads ./uploads
```

Output is a summary table of per-format counts plus a list of problem rows
(claim code shown only as a short prefix, stored filename, DB size, disk
size, and the specific problem: missing file, size mismatch, bad header,
missing key, or wrong key). Exit code is `0` when no problems were found,
`1` otherwise — safe to wire into a CI gate or a pre-deploy check.

### `--verify-hash`: full content-integrity check

`--verify-hash` reads **every byte of every file** — this is slow (a full
pass over the whole uploads directory) and is not something you'd run
routinely on a large deployment, unlike the header/size-only default
`--verify`. What it does per format:

- **SFSE1 / SFSE2**: streams the whole file through the same decrypting
  reader the server itself uses, authenticating every chunk's AEAD tag in
  order (catches tampering/corruption `--verify-decrypt`'s first-chunk-only
  check can't see) and, when the row has a `sha256_hash`, verifying the
  whole-file SHA-256 digest.
- **Plaintext**: streams the file through SHA-256 and compares against
  `sha256_hash` when the row has one.
- **Legacy** (pre-streaming, single-shot AES-256-GCM): decrypted and
  checked the same way, using the existing whole-buffer `DecryptFile`
  helper — there is no streaming legacy decryptor in this codebase, since
  legacy predates SFSE entirely. To avoid buffering an unexpectedly huge
  legacy file into memory, anything over 256MB is **skipped** (reported in
  an informational `skipped` count, not a problem).
- Rows with an empty `sha256_hash` are reported in an informational
  `no_hash` count, not a problem — the AEAD/GCM tag check still ran and
  still catches corruption, there's simply nothing to cross-check a digest
  against.

**Run `--verify-hash` before upgrading to the release that serves claim
downloads via the new seekable SFSE reader** (ADR-017 part 2/3). That
reader enforces the declared ciphertext size and, where a hash is on
record, the whole-file SHA-256 **for SFSE1 too** — checks the old
range-decrypt download path never performed for SFSE1. `--verify-hash` is
how you find out *before* the upgrade whether any existing SFSE1 file would
fail those checks, rather than a user finding out via a failed download
after.

### A note on WAL and read-only opens

SafeShare's database runs in WAL mode. Even with `--verify`'s read-only
open (`mode=ro` plus `PRAGMA query_only`), SQLite may still create
`safeshare.db-wal` / `safeshare.db-shm` alongside the database file if they
don't already exist — this is normal SQLite WAL-mode bookkeeping, not a
write to the database's actual contents, and `--verify` never touches
`safeshare.db` itself. To avoid a permission error from that bookkeeping
(or an unreadable existing `-wal`/`-shm` file), run `--verify` as the same
user that owns the database's directory/files.

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
