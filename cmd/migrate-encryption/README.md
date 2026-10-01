# SafeShare Encryption Migration Tool

Command-line utility to migrate legacy encrypted files, and re-seal SFSE1 files, to SFSE2 (Streaming File System Encryption v2) format.

## Purpose

SafeShare originally used a legacy encryption format that loads entire files into memory for decryption, then an SFSE1 streaming format with no per-chunk authentication. This tool brings every stored file up to **SFSE2** (ADR-011), which:

- **Eliminates format confusion vulnerabilities** - a magic header + version byte identify the format, never a length-based heuristic
- **Authenticates every chunk's identity and position** - per-chunk AAD (file identity, chunk index, is-last flag) defeats truncation, chunk reordering, and cross-file splicing — SFSE1 could not detect any of these
- **Improves performance** - streaming encryption/decryption for large files
- **Reduces memory usage** - no need to load entire files into RAM (except the inherently whole-buffer legacy decrypt step, see below)
- **Enables HTTP Range support** - efficient partial content delivery

As of the 3c-3 hardening pass:

- **Legacy (pre-SFSE) files are migrated straight to SFSE2** (never SFSE1) — the plain `migrate-encryption` command below.
- **Existing SFSE1 files can be re-sealed to SFSE2 in place** with the new `--upgrade-format` flag (master finding #10) — see [Upgrading SFSE1 to SFSE2](#upgrading-sfse1-to-sfse2---upgrade-format) below.

## Security Context

This migration addresses a P1 security finding where the legacy `IsEncrypted()` function only checked file length (>= 29 bytes) without validating the encrypted structure. While the risk was mitigated by SFSE1/SFSE2 detection taking priority, migrating all files eliminates the vulnerability entirely. `--upgrade-format` closes a second, later finding (master #10): SFSE1 has no per-chunk AAD, so an attacker who can write to the uploads directory (or a corrupted/truncated disk) can splice, reorder, or truncate an SFSE1 file's chunks undetected in ways SFSE2 defeats.

## Prerequisites

- SafeShare database (safeshare.db)
- Uploads directory with encrypted files
- Valid 64-character hex encryption key (same key used for encryption)
- Backup of database and uploads directory (recommended)

**Local SQLite + local filesystem only.** This tool reads and writes the
SQLite file and uploads directory named by `--db`/`--uploads` directly — it
has no PostgreSQL or S3 support. If your deployment is actually configured
with `DATABASE_TYPE=postgresql` and/or `STORAGE_TYPE=s3`, every subcommand
(including `--verify`) refuses to run at startup with a clear error, rather
than silently classifying/migrating a local SQLite file and uploads
directory the running server never reads from.

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
| `--upgrade-format` | Re-seal every SFSE1 file to SFSE2 in place (see [below](#upgrading-sfse1-to-sfse2---upgrade-format)). Requires `--enckey`. Mutually exclusive with `--verify` | No | `false` |

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

## Upgrading SFSE1 to SFSE2 (`--upgrade-format`)

SFSE1 files have no per-chunk authentication (AAD) — a chunk's AES-GCM tag
only authenticates that chunk's own bytes, not its position or which file
it belongs to. SFSE2 (ADR-011) fixes this by binding every chunk's tag to
the file's identity, its index, and whether it's the last chunk, which
defeats truncation, chunk reordering, and cross-file splicing SFSE1 could
not detect (master finding #10). `--upgrade-format` re-seals every SFSE1
file already in your uploads directory to SFSE2 in place, without waiting
for it to naturally cycle through re-encryption some other way.

```bash
# Preview what would be upgraded (no changes made):
./migrate-encryption --upgrade-format --dry-run \
  --db ./safeshare.db --uploads ./uploads --enckey "your-64-char-hex-key"

# Actually upgrade:
./migrate-encryption --upgrade-format \
  --db ./safeshare.db --uploads ./uploads --enckey "your-64-char-hex-key"
```

It only ever touches files it classifies as SFSE1 — plaintext, SFSE2, and
legacy files are left alone (`--verify` reports a per-file breakdown; look
for the `upgradable` count). `--enckey` is required; the tool refuses to
start without one, since SFSE1 files cannot be read or re-encrypted
without the key.

### How it's crash-safe

For each file, the tool:

1. Streams the SFSE1 file through the same verified, authenticating reader
   (`utils.OpenSFSEReader`) a normal claim download uses, straight into a
   freshly re-encrypted SFSE2 temp file in the *same* uploads directory —
   never buffering the whole file in memory. If `sha256_hash` is already
   set on the row, it's verified during this same pass; if it's empty, it's
   computed as a side effect of the same pass (no second read).
2. fsyncs the temp file and the uploads directory.
3. Commits a single DB transaction updating `enc_file_id` (and
   `sha256_hash`, if it was empty) to describe the new file.
4. Atomically renames the temp file over the original.
5. fsyncs the uploads directory again.

The DB commit happens **before** the rename, deliberately — a process crash
between those two steps leaves the row already describing SFSE2 while the
file on disk is still, briefly, the untouched SFSE1 original. That's safe
to read through: SFSE1's decoder never consults `enc_file_id` at all (SFSE1
predates per-chunk AAD entirely), so a request that opens the file in that
window still decrypts it correctly. Re-running the tool after any
interruption is always safe and resumes correctly — it decides what needs
doing by looking at each file's actual on-disk format, not by trusting the
DB row. See the `commitFormatUpgrade` doc comment in
`cmd/migrate-encryption/upgrade.go` for the full crash-safety argument, and
`upgrade_test.go` for tests that simulate a crash at each step and assert
the invariant holds.

### Running while the server is up

`--upgrade-format` takes a process-local lock (an flock on
`<uploads>/.safeshare-migrate-encryption.lock`) so two copies of this tool
can't run concurrently against the same uploads directory and race each
other's temp files. **That lock does not coordinate with the live SafeShare
server.** In the (very narrow) window between the DB commit and the rename
described above, a request that already read the *old* database row but
doesn't open the file until *after* the rename will get a clean decrypt
error (never corrupted output — every check in the read path is
fail-closed), and would need to retry. This window is a handful of
syscalls wide against a request's full round trip through the server's own
DB read and file open, so it's very unlikely to be hit in practice — but if
your deployment cannot tolerate even the possibility of a single request
needing to retry, run `--upgrade-format` during a maintenance window, or
stop the SafeShare server first. The tool logs a warning to this effect
every time it runs (outside `--dry-run`).

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
   - If already SFSE (SFSE1 or SFSE2) → Skip (this command doesn't touch it — SFSE1 files are `--upgrade-format`'s job, see above)
   - If unencrypted → Skip (no migration needed)
   - If legacy encrypted → Migrate
3. **Migrates legacy files**:
   - Decrypts using legacy `DecryptFile()` method (necessarily whole-buffer — legacy predates streaming encryption)
   - Re-encrypts as **SFSE2** using `EncryptFileStreamingV2FromReader()`, with a fresh `enc_file_id`
   - Commits the new `enc_file_id` (and `sha256_hash`, if the row didn't already have one) to the database, then atomically renames the new file into place — the same crash-safe DB-commit-then-rename sequence `--upgrade-format` uses; see that section above for why it's safe
4. **Reports progress** - Logs each migration with statistics

## Output

The tool provides a detailed summary:

```
=== Migration Summary ===
Total files in database: 150
Already SFSE format:     120
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
2025-01-22T10:30:03Z INFO successfully migrated file to SFSE2 claim_code=Abc...xyz filename=document.pdf original_size=2048576 new_size=2048636
...
2025-01-22T10:35:00Z INFO migration completed successfully

=== Migration Summary ===
Total files in database: 50
Already SFSE format:     45
Unencrypted files:       3
Legacy encrypted files:  2
Successfully migrated:   2
Failed migrations:       0
```

## Docker Usage

`migrate-encryption` ships inside the SafeShare image at `/app/migrate-encryption`,
alongside `/app/import-file`. Run it with `docker exec` **against the running
`safeshare` container**, not `docker run` against the image — `docker exec`
runs as the image's `USER safeshare` (uid 1000), the same user that owns
`/app/data` and `/app/uploads` inside the container, so every file this tool
creates or rewrites keeps the correct owner and permissions automatically.

**Do not** run a copy of this binary directly on the Docker *host* (outside
the container) unless you know the host uid/gid actually matches the
container's `safeshare:safeshare` (1000:1000) — SSH/console access to the
host is very often root, and this tool preserves whatever mode and owner
(when running as root) the *original* file already had, but that's no
substitute for actually running as the same user the live server runs as.
Running it via `docker exec` sidesteps the question entirely.

```bash
# Run migration inside the already-running container:
docker exec safeshare /app/migrate-encryption \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "$ENCRYPTION_KEY"

# --upgrade-format works the same way:
docker exec safeshare /app/migrate-encryption \
  --upgrade-format \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "$ENCRYPTION_KEY"

# --verify, likewise (read-only — safe to run anytime, including against a
# live container):
docker exec safeshare /app/migrate-encryption \
  --verify --verify-hash \
  --db /app/data/safeshare.db \
  --uploads /app/uploads \
  --enckey "$ENCRYPTION_KEY"
```

`ENCRYPTION_KEY` must be set in your shell before running these — `docker
exec` does not read the container's own environment for a variable you
reference in your local shell's `"$ENCRYPTION_KEY"`. Either `export
ENCRYPTION_KEY=...` first, or pull it from wherever the container's own
`-e ENCRYPTION_KEY=...` value came from.

For the mutating commands (plain migration, `--upgrade-format`), see
["Running while the server is up"](#running-while-the-server-is-up) above —
running via `docker exec` while the container keeps serving requests is
supported, with the same narrow, fail-closed residual window documented
there. Stopping the container first (`docker stop safeshare`, run the
command via a throwaway container instead, then `docker start safeshare`)
remains an option for deployments that want to eliminate that window
entirely, but is no longer the default recommendation.

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

After migration (or `--upgrade-format`) completes successfully:

1. **Restart SafeShare** - not strictly required (the server re-reads each file's format from its own header at request time), but a good moment to bounce anyway
2. **Test downloads** - Verify files decrypt correctly
3. **Monitor logs** - Check for any decryption errors
4. **Run `--verify --verify-hash`** - confirm no file was left in a problem state

## Security Improvements

After migrating all files to SFSE2 (legacy migration, and `--upgrade-format` for any remaining SFSE1 files):

- ✅ Format confusion vulnerability eliminated (magic header + version byte, never a length heuristic)
- ✅ Per-chunk AAD authenticates chunk identity, index, and last-chunk position — defeats truncation, reordering, and cross-file splicing (master finding #10; SFSE1 could not detect any of these)
- ✅ Timing attacks mitigated (10ms normalization on decryption errors)
- ✅ Memory exhaustion prevented (streaming vs. full-file-in-memory, except the inherently whole-buffer legacy decrypt step)
- ✅ Better HTTP Range support (efficient partial decryption)

## Support

For issues or questions:
- Check verbose logs (`--verbose` flag)
- Review [SafeShare documentation](../../docs/)
- Report bugs at: https://github.com/fjmerc/safeshare/issues

## Version History

- **Unreleased** (3c-3 hardening pass) - SFSE2 everywhere
  - Legacy files now migrate straight to SFSE2, not SFSE1
  - New `--upgrade-format` flag re-seals existing SFSE1 files to SFSE2 in place (master finding #10), crash-safe via a DB-commit-then-rename sequence
  - `--verify` reports SFSE1 files as `upgradable`
- **v1.0.0** (2025-01-22) - Initial release
  - Migrate legacy encrypted files to SFSE1 format
  - Dry-run mode
  - Verbose logging
  - Atomic file replacement
