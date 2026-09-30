# SafeShare Security Features

## Enterprise Security Implementation

SafeShare includes enterprise-grade security features designed for production deployments.

## 👤 User Authentication & Authorization

### Overview
SafeShare implements a comprehensive user authentication system with invite-only registration, role-based access control, and secure session management.

### Features
- **Invite-only registration**: Admin-managed user accounts prevent unauthorized access
- **Role-based access**: User and admin roles with different permission levels
- **Session-based authentication**: Secure httpOnly cookies with configurable expiry
- **Password security**: Bcrypt hashing (cost factor 10) for all passwords
- **Temporary passwords**: Force password change on first login for new accounts
- **File ownership tracking**: Authenticated uploads linked to user accounts
- **Anonymous uploads supported**: Public use cases still work without authentication
- **Public downloads**: No authentication required for claim code downloads

### Upload Authentication Modes

SafeShare supports two authentication modes for file uploads, controlled by the `REQUIRE_AUTH_FOR_UPLOAD` environment variable:

**Anonymous Mode (Default - `REQUIRE_AUTH_FOR_UPLOAD=false`)**:
- Allows anyone to upload files without creating an account
- Suitable for public file sharing services
- Files uploaded by anonymous users have `UserID=NULL` in the database
- IP address tracking still provides basic accountability
- Rate limiting and IP blocking still apply

**Authenticated Mode (`REQUIRE_AUTH_FOR_UPLOAD=true`)**:
- Requires valid user authentication for all uploads
- Enforces invite-only uploads (only registered users can upload)
- All uploads are linked to user accounts for full accountability
- Provides audit trails for compliance requirements
- Recommended for private deployments and controlled environments
- Frontend hides Dropoff tab for unauthenticated users and displays "Login to Upload" button
- After successful login, Dropoff tab appears automatically

**Use Cases:**
- **Anonymous Mode**: Public file sharing, temporary file transfer services, low-risk environments
- **Authenticated Mode**: Corporate deployments, compliance-sensitive environments, preventing abuse from strangers, user accountability requirements

**Security Consideration:** Frontend authentication checks can be bypassed. Backend enforcement (via this configuration) ensures actual security by rejecting unauthenticated API requests at the server level.

### User Management

**Admin-Only User Creation:**
Admins can create user accounts via the admin dashboard:

1. Navigate to the **Users** tab in `/admin/dashboard`
2. Click "Create User"
3. Provide username, email, role (user/admin), and optional password
4. If no password provided, a temporary password is auto-generated
5. New user receives temporary password and must change it on first login

**User Roles:**
- **User**: Can upload files, view their own upload history, delete own files
- **Admin**: Full access to admin dashboard, user management, all files

**Account Management:**
- **Enable/Disable**: Temporarily disable user accounts without deleting data
- **Reset Password**: Generate new temporary password requiring change on next login
- **Delete User**: Permanently remove user account (uploaded files can optionally be deleted or kept)

### API Endpoints

**User Authentication:**
```bash
# Login (sets session cookie)
POST /api/auth/login
Content-Type: application/json
{"username": "user", "password": "password"}

# Logout (clears session)
POST /api/auth/logout

# Get current user info
GET /api/auth/user

# Change password
POST /api/auth/change-password
Content-Type: application/json
{"current_password": "old", "new_password": "new", "confirm_password": "new"}
```

**User Dashboard:**
```bash
# Get user's uploaded files
GET /api/user/files?limit=50&offset=0

# Delete user's own file
DELETE /api/user/files/delete
Content-Type: application/json
{"file_id": 123}
```

**Admin User Management:**
```bash
# Create user (admin only)
POST /admin/api/users/create
X-CSRF-Token: <token>
Content-Type: application/json
{
  "username": "newuser",
  "email": "user@example.com",
  "role": "user",
  "password": "optional_custom_password"
}

# List all users (admin only)
GET /admin/api/users?limit=50&offset=0

# Update user (admin only)
PUT /admin/api/users/:id
X-CSRF-Token: <token>
Content-Type: application/json
{"username": "updated", "email": "new@example.com", "role": "admin"}

# Enable/disable user (admin only)
POST /admin/api/users/:id/enable
POST /admin/api/users/:id/disable
X-CSRF-Token: <token>

# Reset user password (admin only)
POST /admin/api/users/:id/reset-password
X-CSRF-Token: <token>

# Delete user (admin only)
DELETE /admin/api/users/:id
X-CSRF-Token: <token>
```

### Security Properties

✅ **Bcrypt password hashing** - Passwords hashed with cost factor 10
✅ **Secure session tokens** - Generated using crypto/rand (32 bytes)
✅ **HttpOnly cookies** - Prevents XSS attacks on session tokens
✅ **SameSite cookies** - Prevents CSRF attacks on authentication
✅ **Separate session stores** - User and admin sessions isolated
✅ **Session expiry** - Configurable via SESSION_EXPIRY_HOURS (default: 24 hours)
✅ **Activity tracking** - Last activity timestamp updated on each request
✅ **Automatic cleanup** - Background worker removes expired sessions
✅ **Audit logging** - All authentication events logged with IP and timestamp

### Web Interface

**User Pages:**
- Login: `http://localhost:8080/login`
- Dashboard: `http://localhost:8080/dashboard`
- Homepage: Shows user status and login/logout buttons

**Admin Pages:**
- Admin Login: `http://localhost:8080/admin/login`
- Admin Dashboard: `http://localhost:8080/admin/dashboard`
- Users tab: Full user management interface

### Best Practices

⚠️ **Production Deployment:**
1. Use strong admin passwords (minimum 16 characters, mixed case, numbers, symbols)
2. Use HTTPS in production (set cookie Secure flag)
3. Set SESSION_EXPIRY_HOURS appropriately for your use case
4. Monitor audit logs for suspicious authentication activity
5. Regularly review user accounts and disable inactive users
6. Use temporary passwords for all new user accounts
7. Enforce password complexity in client-side validation

⚠️ **Security Considerations:**
- **Invite-only**: Prevents unauthorized account creation
- **No password reset via email**: Admin must reset passwords manually
- **Session fixation prevention**: New session token generated on login
- **Brute force protection**: Rate limiting on login endpoints (5 attempts per 15 minutes)
- **SQL injection prevention**: All queries use parameterized statements

---

## 🕵️ Anonymous Mode

### Overview
Anonymous mode prevents SafeShare from storing or displaying IP addresses, protecting uploader identity even from server administrators. This is critical for whistleblower scenarios and privacy-sensitive deployments.

### Setup

Enable anonymous mode by setting the environment variable:
```bash
docker run -e ANONYMOUS_MODE=true ...
```

### What It Does

- **Database**: Uploader IP addresses are not stored (NULL instead of IP)
- **Logs**: IP addresses are redacted in all log output (replaced with `[redacted]`)
- **Admin dashboard**: IP columns show `[redacted]` instead of real IPs
- **Rate limiting**: Still functional (uses hashed IPs internally, never stored)
- **Audit logs**: IP fields redacted in all audit log entries

### Behavior

- **Default**: Disabled (`ANONYMOUS_MODE=false`)
- **Combines with other features**: Works alongside `STRIP_METADATA`, E2E encryption, and Tor deployment for maximum anonymity
- **Irreversible per-upload**: IPs are never written to disk, so there is no data to recover later

---

## 🧹 File Metadata Stripping

### Overview
Uploaded files can contain identifying metadata such as EXIF data (GPS coordinates, camera model, serial numbers, timestamps), document properties (author name, organization), and other embedded information. A whistleblower uploading a phone photo could leak their exact location through GPS metadata.

### Setup

Enable metadata stripping by setting the environment variable:
```bash
docker run -e STRIP_METADATA=true ...
```

When enabled, SafeShare automatically strips metadata from supported file types during upload. The stripping is **lossless** — image quality is preserved exactly; only metadata segments are removed.

### Supported File Types

| File Type | What's Stripped | Method |
|-----------|----------------|--------|
| JPEG | APP1-APP15 (EXIF, XMP, IPTC, ICC), COM — GPS, camera info, author, timestamps | Byte-level segment removal |
| PNG | tEXt, iTXt, zTXt, eXIf, tIME chunks — author, software, comments, timestamps | Chunk filtering |
| DOCX | docProps/ — author, company, template, revision history, timestamps | ZIP entry removal + XML filtering |
| XLSX | docProps/ — same as DOCX | ZIP entry removal + XML filtering |
| PPTX | docProps/ — same as DOCX | ZIP entry removal + XML filtering |
| PDF | Info dictionary (Author, Creator, Producer, dates), XMP metadata, document ID | pdfcpu library |
| MP4/MOV | udta (GPS, camera), meta (iTunes metadata), mvhd/tkhd timestamps | Manual atom parsing |
| MP3 | ID3v2 tags, ID3v1 tags, APE tags — artist, album, GPS, comments | Manual tag removal |

### Behavior

- **Default**: Disabled (`STRIP_METADATA=false`)
- **Unsupported types**: Passed through unchanged (no error)
- **Stripping failures**: Non-fatal — a warning is logged and the original file is kept
- **With encryption**: Metadata is stripped before encryption
- **File hash/size**: Recomputed after stripping so database records are accurate

### Limitations

- HEIC/HEIF, FLAC, WAV, OGG, and WebM files are not currently supported
- Legacy Office formats (.doc, .xls, .ppt) are not supported — only modern Open XML formats
- Office document comments and tracked changes (which may contain author names) are not stripped — only file-level metadata in docProps/
- Already-uploaded files are not retroactively stripped
- Metadata stripping is irreversible — the original metadata cannot be recovered

---

## 🔐 Encryption at Rest

### Overview
Files are encrypted using **AES-256-GCM** before being stored on disk. This protects against:
- Disk theft
- Backup leaks
- Unauthorized server access
- Compliance requirements (HIPAA, SOC2, GDPR)

### Setup

**1. Generate an encryption key:**
```bash
openssl rand -hex 32
```

**2. Set the environment variable:**
```bash
export ENCRYPTION_KEY="your-64-character-hex-key"
```

**3. Run SafeShare:**
```bash
docker run -d \
  -p 8080:8080 \
  -e ENCRYPTION_KEY="your-64-character-hex-key" \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  safeshare:latest
```

### Technical Details
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key size**: 256 bits (32 bytes)
- **Nonce**: 12 bytes (randomly generated per file)
- **Authentication**: Built-in via GCM mode
- **Format**: `[nonce(12)][ciphertext][tag(16)]`

### Security Properties
✅ **Authenticated encryption** - Detects tampering
✅ **Unique nonce per file** - Prevents replay attacks
✅ **Zero-knowledge server** - Server cannot read encrypted files
✅ **Backward compatible** - Works with existing plain files

### Key Management
⚠️ **IMPORTANT**: Store the encryption key securely!
- **Development**: Use environment variable
- **Production**: Use secrets manager (AWS Secrets Manager, Vault, etc.)
- **Lost key = lost files** - No recovery possible

### Backward Compatibility
- Existing files remain unencrypted (if uploaded before key was set)
- New files are encrypted if key is configured
- Downloads automatically detect and decrypt encrypted files

---

## 🚫 File Extension Blacklist

### Overview
Blocks dangerous file types to prevent malware distribution.

### Default Blocked Extensions
```
.exe, .bat, .cmd, .sh, .ps1, .dll, .so, .msi,
.scr, .vbs, .jar, .com, .app, .deb, .rpm
```

### Configuration

**Disable all blocking:**
```bash
export BLOCKED_EXTENSIONS=""
```

**Custom blacklist:**
```bash
export BLOCKED_EXTENSIONS=".exe,.bat,.ps1"
```

**Add to defaults:**
```bash
export BLOCKED_EXTENSIONS=".exe,.bat,.cmd,.sh,.ps1,.dll,.so,.msi,.scr,.vbs,.jar,.com,.app,.deb,.rpm,.apk,.ipa"
```

### Limitations
⚠️ **Known bypass**: Files can be zipped to circumvent extension filtering
⚠️ **Double extensions**: `.pdf.exe` files are detected and blocked
⚠️ **Rename attack**: Users can rename files after download

**Recommendation**: Combine with virus scanning for comprehensive protection.

---

## 🦠 Malware Scanning (ClamAV)

### Overview

Optional real-time malware scanning via a ClamAV sidecar, enabled with `FEATURE_MALWARE_SCAN=true`. See ADR-015 (`SafeShare-Planning/06-Architecture-Decisions/ADR-015-synchronous-plaintext-scanning.md`) for the full design rationale.

Scanning is **synchronous** and runs against the **original, unencrypted upload content** before the file is encrypted or stored, and before a claim code is generated — an infected upload is rejected outright (`422 MALWARE_DETECTED`) and never becomes downloadable. This matters specifically when `ENCRYPTION_KEY` is also set: scanning the plaintext (rather than the at-rest ciphertext) is the only way a scan result means anything.

### Download gate

Every download is gated on the file's own scan verdict, not just on whether scanning is currently enabled:

| `scan_status` | Download behavior |
|---|---|
| `infected` | Always blocked — `410 FILE_QUARANTINED` |
| `pending` | Blocked — `423`, retry after 15s (legacy value; nothing in the current design writes it, but old rows are still honored) |
| `error` | Blocked — `403 SCAN_FAILED` |
| `clean` | Allowed |
| `not_scanned` | Allowed (see below) |
| unset (scanning disabled, or pre-scanning-feature file) | Allowed |

### End-to-end encrypted and oversized uploads

Client-side (E2E) encrypted uploads are still scanned server-side — an attacker could smuggle plaintext malware through the `client_encrypted` flag — but a non-infected result is recorded as `not_scanned` rather than `clean`, since the server cannot verify the genuinely-decrypted content is safe. The same applies to uploads larger than `CLAMAV_MAX_FILE_SIZE`. A detected infection is still `infected` either way.

By default, `not_scanned` uploads are accepted. Set `MALWARE_SCAN_REJECT_UNSCANNABLE=true` to reject them outright (`422 UNSCANNABLE_UPLOAD`) instead.

### Scanner unavailability

If ClamAV cannot be reached, times out, or returns an unrecognized response, the scan is treated as failed — uploads are rejected (`503 SCAN_UNAVAILABLE`) and downloads of previously-`error`/`pending` files are blocked, by default. Set `MALWARE_SCAN_ALLOW_UNVERIFIED=true` to instead proceed without a verified scan (logged as a startup `WARN`); this never overrides a confirmed `infected` verdict.

⚠️ **`MALWARE_SCAN_ALLOW_UNVERIFIED` is uploader-triggerable, not just an operator escape hatch.** A clamd `ERROR` reply or a scan timeout are both things an uploader can deliberately provoke (a crafted/oversized stream, a payload shaped to run near `CLAMAV_SCAN_TIMEOUT`), and with this flag on, doing so gets their upload waved through as `scan_status=error` instead of blocked. In other words, a sufficiently motivated attacker can use it to *effectively disable scanning for their own upload* against a server running with this flag set. Only enable it if you've accepted that trade-off (e.g. availability matters more than guaranteed scanning for your deployment) — it does not weaken the `infected` verdict path, which is never bypassable.

Chunked-upload scan failures retry (3×, with backoff) only on a clamd **connection** failure (dial/refused/DNS) — a timeout waiting for a verdict, or a clamd `ERROR` reply, is not retried, since retrying against the same clamd would just reproduce the same outcome while holding an assembly-worker slot.

### Configuration

```bash
export FEATURE_MALWARE_SCAN=true
export CLAMAV_HOST=clamav
export CLAMAV_PORT=3310
export CLAMAV_TIMEOUT=30                    # seconds; IDLE timeout only — TCP dial and each individual write while streaming
export CLAMAV_SCAN_TIMEOUT=180              # seconds; separate bound on waiting for clamd's verdict AFTER the full stream is sent — see below
export CLAMAV_MAX_FILE_SIZE=104857600       # bytes; keep <= clamd's own StreamMaxLength
export MALWARE_SCAN_ALLOW_UNVERIFIED=false  # true: fail open on scanner errors (not on confirmed infections) — see warning above
export MALWARE_SCAN_REJECT_UNSCANNABLE=false # true: reject E2E/oversized uploads outright
```

`CLAMAV_TIMEOUT` vs `CLAMAV_SCAN_TIMEOUT`: clamd buffers the **entire** INSTREAM before it starts scanning, so zero reply bytes flow while a large file is actually being scanned — that wait is bounded by `CLAMAV_SCAN_TIMEOUT`, not `CLAMAV_TIMEOUT`. Keep `CLAMAV_SCAN_TIMEOUT` comfortably above clamd's own `MaxScanTime` (see hardening below): if it's lower, large-but-legitimate uploads fail with `SCAN_UNAVAILABLE` well before clamd would have finished.

### Hardening clamd itself

SafeShare trusts clamd's response at face value, so a permissively-configured clamd can silently under-report threats. In `clamd.conf`, set:

- **`AlertExceedsMax yes`** — without this, a file that exceeds clamd's own internal scan limits (`MaxFileSize`, `MaxScanSize`, `MaxRecursion`, etc.) is reported clean (`stream: OK`) rather than flagged, regardless of what `CLAMAV_MAX_FILE_SIZE` is set to on the SafeShare side. A `Heuristics.Limits.Exceeded.*` signature name in a `FOUND` reply — which this alert setting produces — is treated the same as any other match: `scan_status=infected`.
- **`StreamMaxLength`** must be `>= CLAMAV_MAX_FILE_SIZE`. If clamd's own limit is lower, clamd rejects larger streams (`INSTREAM size limit exceeded. ERROR`), which SafeShare treats as a scan error — the upload is refused with `SCAN_UNAVAILABLE`, or stored with `scan_status=error` under `MALWARE_SCAN_ALLOW_UNVERIFIED` — so files between the two limits can never be uploaded normally.
- **`MaxScanTime`** should be comfortably *below* `CLAMAV_SCAN_TIMEOUT` (SafeShare's client-side wait), so clamd itself gives up and replies before SafeShare's deadline does — otherwise SafeShare times out and reports `SCAN_UNAVAILABLE` for a scan that was actually still progressing normally.
- **`AlertEncrypted yes`** (and `AlertEncryptedArchive` / `AlertEncryptedDoc` as appropriate for your threat model) — flags encrypted archives/documents clamd cannot look inside, which would otherwise scan as clean despite being unexamined.

### Limitations

⚠️ **Legacy scan results**: files scanned before this synchronous design (upgrading from an older SafeShare version) have their `clean`/`pending`/`error` scan status relabeled `not_scanned` on migration — a pre-upgrade "clean" verdict may have been computed against ciphertext and cannot be trusted. Re-scan such files out of band if certainty is required.
⚠️ **E2E encryption vs. scanning**: these two features are in tension by design — a server that can decrypt content to scan it isn't offering true end-to-end confidentiality. Operators must choose the trade-off that fits their threat model via `MALWARE_SCAN_REJECT_UNSCANNABLE`.
⚠️ **Signature-based**: ClamAV, like any signature-based scanner, does not catch zero-day malware.
⚠️ **CLI import bypasses scanning entirely**: files imported via `cmd/import-file` never go through the HTTP upload path and are therefore never scanned — they're recorded as `scan_status=not_scanned`, `scan_result="imported via CLI"` unconditionally (the CLI has no reliable way to read the server's live, admin-toggleable scan setting). Treat CLI-imported content as unverified regardless of `FEATURE_MALWARE_SCAN`.

---

## 🔑 Password Protection

### Overview
Optional password protection for file downloads using bcrypt-hashed passwords. Files can be protected with a password during upload, requiring both the claim code and password for download.

### Features
- **Optional**: Files without passwords work normally
- **Bcrypt hashing**: Passwords hashed with cost factor 10
- **Secure verification**: Constant-time comparison via bcrypt
- **Audit logging**: Failed password attempts logged with client IP

### Usage

**Upload with password (Web UI):**
1. Select file and configure expiration/download limits
2. Enter password in "Password (optional)" field
3. Upload file - password will be hashed and stored securely

**Upload with password (API):**
```bash
curl -X POST \
  -F "file=@confidential.pdf" \
  -F "password=MySecretPass123" \
  -F "expires_in_hours=24" \
  http://localhost:8080/api/upload
```

**Download with password (Web UI):**
1. Enter claim code in Pickup tab
2. If password-protected, password field will appear
3. Enter password and click Download

**Download with password (API):**
```bash
curl -O "http://localhost:8080/api/claim/ABC123?password=MySecretPass123"
```

### API Response Fields

**Claim Info includes password_required:**
```json
{
  "claim_code": "ABC123",
  "original_filename": "confidential.pdf",
  "password_required": true,
  ...
}
```

### Security Properties
✅ **bcrypt hashing** - Passwords hashed with industry-standard algorithm
✅ **No plaintext storage** - Only hashes stored in database
✅ **Constant-time comparison** - Prevents timing attacks
✅ **Failed attempt logging** - All failed password attempts logged with IP
✅ **Optional feature** - No impact on non-password-protected files

### Security Logging

**Incorrect password attempt:**
```json
{
  "level": "warn",
  "msg": "file access denied",
  "reason": "incorrect_password",
  "claim_code": "ABC...23",
  "filename": "confidential.pdf",
  "client_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0..."
}
```

**Upload with password:**
```json
{
  "level": "info",
  "msg": "file uploaded",
  "claim_code": "ABC...23",
  "filename": "confidential.pdf",
  "password_protected": true,
  ...
}
```

### Best Practices
✅ Use strong passwords (12+ characters, mixed case, numbers, symbols)
✅ Don't share passwords via the same channel as claim codes
✅ Combine with download limits and short expiration times
✅ Monitor logs for brute force attempts on password-protected files

---

## 🎯 Download Limit Enforcement

### Overview
`max_downloads` on a shared file is enforced via a resumable download-session
pattern (ADR-014, amending ADR-012). A recipient's download only counts once
they have actually received the file, and a download that is split across
several HTTP requests — a paused/resumed browser download, a retried
connection — still counts exactly once, by presenting an `X-Download-Session`
bearer token issued on the first response.

### Bounded, accepted leakage
Small "probe" requests (e.g. a link-preview crawler fetching a few bytes, or
a browser range-checking a resumable download before starting) are free and
do not consume a download, up to a small per-file byte budget
(`B = 4 * clamp(file_size / 16, 1, 64 KiB)`). This is an intentional,
bounded trade-off: without it, any HTTP client probe would burn the only
download of a `max_downloads=1` file (the original SH-2.3/ADR-012 bug this
design replaces). Once a file's cumulative "free" probe bytes reach `B`,
every subsequent tokenless byte on that file counts immediately — so the
maximum a client can ever extract from a single-use file without spending its
one download is `B` bytes (at most 256 KiB for very large files, far less for
small ones), never the whole file. A `max_downloads=1` file therefore cannot
be fully exfiltrated by staying under the per-request threshold; it can only
leak a small, capped prefix before either the recipient's real download or an
attacker's own probing spends the file's only credit.

### Session tokens are bearer credentials
The `X-Download-Session` token is a 256-bit `crypto/rand` value; only its
SHA-256 hash is stored server-side, and only a short, non-reversible prefix
of that hash is ever written to logs. Presenting a valid token for a file is
sufficient to resume (or, for an uncommitted session, credit) that download
— treat it with the same care as the claim code itself. An unrecognised,
foreign (issued for a different file), or expired token is silently treated
as a fresh download attempt rather than rejected with a distinguishing error,
so a guessed or replayed token can't be used to probe for the existence of
other sessions.

### Abandoned session cleanup
A background reaper releases sessions that stop making progress: an
uncommitted (not-yet-credited) session is released after a short lease
timeout (`DOWNLOAD_RESERVATION_TTL`, default 5 minutes) if no bytes have been
received recently, while a committed session's resumability window is bounded
separately (`DOWNLOAD_SESSION_IDLE_TTL`, default 1 hour; hard cap 24 hours)
since the download has already been credited and reaping it is pure
bookkeeping cleanup, not a security control. A genuinely slow-but-active
transfer renews its own lease as bytes flow, so transfer duration alone never
causes a released slot or a double-delivered file.

### Post-completion resume grace window (T42)
The server marks a capped download's session "complete" as soon as it has
written the entire file to the response — but a client (a resumable download
manager, including SafeShare's own web UI and most browsers' built-in one)
can still be interrupted between receiving the last byte and finishing its
own write to disk. Without any allowance for this, a resume attempt in that
narrow window would present a perfectly valid session token that the server
had already retired, and get an unhelpful "Download Limit Reached" instead of
its remaining bytes. `DOWNLOAD_SESSION_COMPLETE_GRACE` (default 5 minutes,
clamped to `[1s, 1h]`; an unparseable or negative value fails closed to `0`
rather than silently defaulting to enabled; `0`, or the words `off` /
`false` / `disabled` / `none` / `no`, disable it outright) lets a
trusted-token resume still resolve a session for a short window after it
completed — but ONLY for a genuine tail resume (a partial `Range` that
starts after byte 0 and reaches EOF), never a plain re-request of the whole
file or an arbitrary range; anything else against a completed session is
treated exactly like an unresolved token.

This does not reopen the replay concern the completed-session check above
exists for. `ReserveSessionBytes`' ~2×(file size) ceiling now bounds
`bytes_reserved` for a session's **entire lifetime** — the request that
creates the session charges its own declared range against the ceiling
immediately, the same way every resume already did — not just the resumes on
top of an unaccounted-for first transfer. A normal download plus pause/resume
retries stays well within that budget; a client that tries to extract more
than roughly two copies of the file total, through any combination of an
initial request and resumes, before or after completion, eventually gets a
charge refused and falls back to a fresh reservation, which then enforces
`max_downloads` normally. Re-committing/re-completing an already-committed/
-completed session is an idempotent no-op — `download_count` is never
incremented and the `file.downloaded` webhook is never re-fired for a
grace-window resume. The background reaper also protects a just-completed
session's row from being swept by `DOWNLOAD_SESSION_IDLE_TTL` before its own
grace window elapses, so the window is never "open" in policy but empty in
practice. See ADR-014's addendum for the full design.

## 📊 Enhanced Audit Logging

### Overview
Comprehensive JSON-formatted logs for security monitoring and compliance.

### Log Events

#### File Uploaded
```json
{
  "time": "2025-11-04T22:00:00Z",
  "level": "INFO",
  "msg": "file uploaded",
  "claim_code": "Xy9kLm8pQz4vDwE",
  "filename": "document.pdf",
  "file_extension": ".pdf",
  "size": 1048576,
  "expires_at": "2025-11-06T22:00:00Z",
  "max_downloads": 5,
  "client_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0..."
}
```

#### File Downloaded
```json
{
  "time": "2025-11-04T22:05:00Z",
  "level": "INFO",
  "msg": "file downloaded",
  "claim_code": "Xy9kLm8pQz4vDwE",
  "filename": "document.pdf",
  "size": 1048576,
  "download_count": 1,
  "remaining_downloads": "4",
  "client_ip": "192.168.1.200",
  "user_agent": "curl/7.68.0"
}
```

#### Access Denied - Blocked Extension
```json
{
  "time": "2025-11-04T22:10:00Z",
  "level": "WARN",
  "msg": "blocked file extension",
  "filename": "malware.exe",
  "extension": ".exe",
  "client_ip": "192.168.1.100"
}
```

#### Access Denied - Download Limit
```json
{
  "time": "2025-11-04T22:15:00Z",
  "level": "WARN",
  "msg": "file access denied",
  "reason": "download_limit_reached",
  "claim_code": "Xy9kLm8pQz4vDwE",
  "filename": "document.pdf",
  "download_count": 5,
  "max_downloads": 5,
  "client_ip": "192.168.1.300"
}
```

#### Access Denied - Not Found/Expired
```json
{
  "time": "2025-11-04T22:20:00Z",
  "level": "WARN",
  "msg": "file access denied",
  "reason": "not_found_or_expired",
  "claim_code": "InvalidCode123",
  "client_ip": "192.168.1.400"
}
```

### Log Aggregation
Logs are JSON-formatted for easy parsing by:
- **Splunk**: `source="/var/log/safeshare/*.log" | spath`
- **ELK Stack**: Logstash with JSON codec
- **Datadog**: Log pipeline with JSON parsing
- **CloudWatch**: Filter patterns on JSON fields

### Compliance Mapping
- **HIPAA**: Audit trail of file access (§164.312(b))
- **SOC 2**: Monitoring and logging (CC7.2)
- **GDPR**: Data processing records (Article 30)
- **PCI-DSS**: Log all access to cardholder data (Req 10)

---

## 🎛️ Admin Dashboard Security

SafeShare includes a secure web-based admin dashboard for managing files, blocking IPs, and adjusting quotas.

### Overview

The admin dashboard provides comprehensive administrative capabilities with enterprise-grade security:
- Session-based authentication
- CSRF protection on all state-changing operations
- Rate-limited login attempts
- IP blocking and unblocking
- File management (view, search, delete)
- Dynamic quota adjustment
- Complete audit logging

### Setup

Enable the admin dashboard by setting both environment variables:

```bash
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="your_secure_password_here"  # Minimum 8 characters
export SESSION_EXPIRY_HOURS=24  # Optional, defaults to 24 hours
```

**Access**:
- Login: `http://your-server:8080/admin/login`
- Dashboard: `http://your-server:8080/admin/dashboard`

### Security Features

#### 1. Session Management
- **Secure tokens**: 32-byte cryptographically random tokens (crypto/rand)
- **HttpOnly cookies**: Prevents XSS attacks
- **SameSite=Strict**: Prevents CSRF attacks on cookies
- **Automatic expiration**: Configurable session timeout (default: 24 hours)
- **Activity tracking**: Last activity timestamp updated on each request
- **Background cleanup**: Expired sessions removed every 30 minutes

#### 2. CSRF Protection
- **Independent tokens**: Separate from session tokens
- **Token validation**: Required for all POST/PUT/DELETE/PATCH requests
- **Cookie + header verification**: Token must match between cookie and request header
- **24-hour lifetime**: Tokens expire automatically
- **Logged failures**: All CSRF validation failures are logged with IP

#### 3. Rate Limiting
- **Login protection**: 5 attempts per 15 minutes per IP
- **In-memory tracking**: Efficient sliding window algorithm
- **Auto cleanup**: Old attempts automatically removed
- **HTTP 429 response**: Clear feedback when limit exceeded

#### 4. Audit Logging
All admin actions are logged with full context:

**Login Success**:
```json
{
  "time": "2025-11-05T07:38:15Z",
  "level": "INFO",
  "msg": "admin login successful",
  "username": "admin",
  "ip": "192.168.254.1",
  "user_agent": "Mozilla/5.0..."
}
```

**File Deletion**:
```json
{
  "time": "2025-11-05T07:40:52Z",
  "level": "INFO",
  "msg": "admin deleted file",
  "claim_code": "Jsi...ue",
  "filename": "test-file.txt",
  "size": 18,
  "admin_ip": "192.168.254.1"
}
```

**IP Blocking**:
```json
{
  "time": "2025-11-05T07:30:14Z",
  "level": "INFO",
  "msg": "admin blocked IP",
  "blocked_ip": "192.168.1.100",
  "reason": "Test block",
  "admin_ip": "192.168.254.1"
}
```

**Quota Update**:
```json
{
  "time": "2025-11-05T07:30:44Z",
  "level": "INFO",
  "msg": "admin updated storage quota",
  "old_quota_gb": 0,
  "new_quota_gb": 10,
  "admin_ip": "192.168.254.1"
}
```

### Dashboard Features

#### Files Tab
- View all uploaded files with full metadata
- Search by claim code, filename, or uploader IP
- Pagination (20 files per page)
- Delete files before expiration
- See password protection status
- Monitor download counts

#### Blocked IPs Tab
- Block IP addresses from uploads/downloads
- View all blocked IPs with reason and timestamp
- Unblock IPs with one click
- Automatic enforcement on all file operations

#### Settings Tab
- Adjust storage quota without restart
- View system configuration
- Real-time stats update

### IP Blocking

When an IP is blocked:
1. **Immediate enforcement**: Blocks take effect instantly
2. **Upload prevention**: HTTP 403 on upload attempts
3. **Download prevention**: HTTP 403 on download attempts
4. **Audit trail**: All blocked attempts logged
5. **Admin bypass**: Admin dashboard remains accessible

**Canonical matching and CIDR ranges**: an entry accepts a bare IPv4/IPv6
address or a CIDR range (e.g. `203.0.113.0/24`, `2001:db8:1:2::/64`), and is
canonicalized before storage — IPv4-mapped IPv6 addresses are unmapped, zone
IDs are dropped, and hex is lowercased/compressed — so the same logical
address always matches the blocklist regardless of how it was typed or how
a proxy represented it on the wire. A CIDR broader than `/8` (IPv4) or `/32`
(IPv6) is rejected, as is any range that would include loopback or the
requesting admin's own current IP, to prevent an operator from locking
themselves out with a typo.

**IPv6 rate limiting**: by default, IPv6 clients are rate-limited and
concurrency-capped per `/64` prefix rather than per exact address, since many
residential/mobile IPv6 allocations let a client rotate addresses freely
within their own `/64`. Configurable via `RATE_LIMIT_IPV6_PREFIX` (default
`64`, valid range 48–128; `128` restores strict per-address limiting). This
does not affect what's logged or stored as the client's IP — audit logs and
`uploader_ip` always keep the full address; only the rate-limit/concurrency
bucket key is grouped.

Grouping by `/64` is the same tradeoff IPv4 clients behind NAT already have:
one abuser sharing a `/64` (or a NAT gateway) can exhaust the rate limit or
trigger a login lockout for every other client sharing that same allocation,
since they all group into the same bucket. This is expected, not a bug —
without it, an attacker could bypass every limit for free by requesting a
new address within their own `/64` on each attempt. If a deployment sees
this cause real collateral impact (e.g. many legitimate users sharing one
provider's `/64`), set `RATE_LIMIT_IPV6_PREFIX=128` to restore strict
per-address limiting, accepting the original address-rotation bypass in
exchange for finer-grained isolation between clients. The IP-blocklist's
Block IP action is unaffected either way — it's always per-address or
per-explicit-CIDR, never implicitly grouped by `/64` — so blocking a
rotating IPv6 abuser outright requires blocking its `/64` explicitly (e.g.
`2001:db8:1234:5678::/64`), not just the one address seen in a log line; see
the admin dashboard's Block IP field for this exact suggestion.

**Blocked access log**:
```json
{
  "time": "2025-11-05T08:00:00Z",
  "level": "WARN",
  "msg": "blocked IP attempted access",
  "ip": "192.168.1.100",
  "path": "/api/upload",
  "method": "POST",
  "user_agent": "curl/7.81.0"
}
```

### Security Best Practices

**1. Strong Credentials**:
- Use minimum 12-character passwords
- Mix uppercase, lowercase, numbers, symbols
- Never use default credentials in production

**2. HTTPS Deployment**:
- Always use HTTPS in production
- Update cookie settings to `Secure: true`
- Configure reverse proxy with TLS

**3. Network Isolation**:
- Restrict admin dashboard to internal networks
- Use VPN for remote admin access
- Consider IP whitelisting at firewall level

**4. Session Management**:
- Keep SESSION_EXPIRY_HOURS reasonable (12-24 hours)
- Log out when done with admin tasks
- Monitor active sessions via database

**5. Audit Review**:
- Regularly review admin action logs
- Set up alerts for suspicious activity
- Export logs to SIEM for analysis

### Database Tables

**admin_sessions**:
```sql
CREATE TABLE admin_sessions (
    id INTEGER PRIMARY KEY,
    session_token TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT NOT NULL,
    user_agent TEXT
);
```

**blocked_ips**:
```sql
CREATE TABLE blocked_ips (
    id INTEGER PRIMARY KEY,
    ip_address TEXT UNIQUE NOT NULL,
    reason TEXT NOT NULL,
    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    blocked_by TEXT DEFAULT 'admin'
);
```

---

## 🛡️ Production Security Features

SafeShare includes 7 critical security features required for production deployment.

### 1. Rate Limiting

**Protection**: Prevents DoS attacks and resource exhaustion

**Configuration**:
```bash
export RATE_LIMIT_UPLOAD=10      # Uploads per hour per IP
export RATE_LIMIT_DOWNLOAD=100   # Downloads per hour per IP
```

**How it works**:
- Tracks requests per IP address using sliding window algorithm
- Separate limits for uploads and downloads
- Returns HTTP 429 (Too Many Requests) when limit exceeded
- Automatic cleanup of old records

**Testing**:
```bash
# Test upload rate limit (should fail on 11th request)
for i in {1..12}; do
  curl -X POST -F "file=@test.txt" http://localhost:8080/api/upload
done
```

### 2. Filename Sanitization

**Protection**: Prevents HTTP header injection, path traversal, and log injection attacks

**How it works**:
- Removes control characters, newlines, quotes from filenames
- Prevents directory traversal sequences (`../`, `..\\`)
- Sanitizes Content-Disposition headers
- Limits filename length to 255 characters

**Example**:
```bash
# Attempt header injection (will be sanitized)
curl -F 'file=@test.txt;filename="evil\r\nX-Injected: true\r\n\r\nMALICIOUS"' \
  http://localhost:8080/api/upload

# Filename becomes: evil_X-Injected__true___MALICIOUS
```

### 3. Security Headers

**Protection**: Prevents clickjacking, XSS, MIME sniffing, and other browser-based attacks

**Headers Added**:
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; ...
Referrer-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

**Verification**:
```bash
curl -I http://localhost:8080/ | grep -E "X-Frame|X-Content|Content-Security"
```

### 4. MIME Type Detection

**Protection**: Prevents malware from masquerading as safe file types

**How it works**:
- Uses server-side content detection (magic bytes)
- Ignores user-provided Content-Type header
- Stores detected MIME type in database
- Logs both user-provided and detected types

**Example**:
```bash
# Upload .exe file claiming to be PNG (will be detected)
curl -F "file=@malware.exe;type=image/png" http://localhost:8080/api/upload

# Server logs:
# "detected_mime": "application/x-msdownload"
# "user_provided_mime": "image/png"
```

**Dependency**: `github.com/gabriel-vasile/mimetype`

### 5. Disk Space Monitoring

**Protection**: Prevents disk exhaustion and service outages

**Limits**:
- Minimum free space: 1 GB
- Maximum disk usage: 80%

**How it works**:
- Pre-upload disk space check
- Rejects uploads if insufficient space
- Health endpoint includes disk metrics
- Real-time monitoring via `/health` endpoint

**Configuration**: Automatic, no configuration needed

**Monitoring**:
```bash
# Check disk space metrics
curl http://localhost:8080/health | jq '{
  total: .disk_total_bytes,
  free: .disk_free_bytes,
  used_percent: .disk_used_percent
}'
```

### 6. Maximum Expiration Validation

**Protection**: Prevents disk space abuse from files that never expire

**Configuration**:
```bash
export MAX_EXPIRATION_HOURS=168  # 7 days (default)
```

**How it works**:
- Validates expiration time on upload
- Rejects requests exceeding maximum
- Returns HTTP 400 with error message

**Example**:
```bash
# Attempt 30-day expiration (will fail if max is 168 hours)
curl -F "file=@test.txt" -F "expires_in_hours=720" \
  http://localhost:8080/api/upload

# Response: HTTP 400
# {"error": "Expiration time exceeds maximum allowed (168 hours)"}
```

### 7. Storage Quota Management

**Protection**: Prevents disk abuse and enables multi-tenant deployments with per-application limits

**Configuration**:
```bash
export QUOTA_LIMIT_GB=20  # Maximum 20GB total storage (0 = unlimited)
```

**How it works**:
- Tracks total storage usage via database query
- Pre-upload validation: rejects if quota would be exceeded
- Automatic quota reclamation when files expire
- Health endpoint exposes quota metrics
- Returns HTTP 507 (Insufficient Storage) when quota exceeded

**Example**:
```bash
# Set 20GB quota
docker run -d -p 8080:8080 \
  -e QUOTA_LIMIT_GB=20 \
  safeshare:latest

# Upload will fail if it would exceed quota
curl -F "file=@large.iso" http://localhost:8080/api/upload

# Response: HTTP 507
# {"error": "Storage quota exceeded. Current usage: 18.50 GB / 20 GB"}
```

**Monitoring**:
```bash
# Check quota usage
curl http://localhost:8080/health | jq '{
  quota_limit_gb: (.quota_limit_bytes / 1073741824),
  quota_used_percent: .quota_used_percent,
  storage_used_gb: (.storage_used_bytes / 1073741824)
}'

# Example output:
# {
#   "quota_limit_gb": 20,
#   "quota_used_percent": 75.5,
#   "storage_used_gb": 15.1
# }
```

**Benefits**:
- ✅ Prevents runaway disk usage
- ✅ Enables predictable resource allocation
- ✅ Supports multi-tenant deployments
- ✅ Automatic cleanup frees quota
- ✅ Real-time monitoring via health endpoint

---

## 🔒 Complete Enterprise Deployment Example

```bash
# Generate encryption key
ENCRYPTION_KEY=$(openssl rand -hex 32)

# Start with all security features enabled
docker run -d \
  -p 8080:8080 \
  --name safeshare \
  -e ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  -e BLOCKED_EXTENSIONS=".exe,.bat,.cmd,.sh,.ps1,.dll,.so,.msi,.scr,.vbs,.jar" \
  -e MAX_FILE_SIZE=104857600 \
  -e DEFAULT_EXPIRATION_HOURS=24 \
  -e MAX_EXPIRATION_HOURS=168 \
  -e RATE_LIMIT_UPLOAD=10 \
  -e RATE_LIMIT_DOWNLOAD=100 \
  -e QUOTA_LIMIT_GB=20 \
  -e TZ=Europe/Berlin \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  --restart unless-stopped \
  safeshare:latest

# View security logs
docker logs -f safeshare | jq 'select(.level=="WARN" or .level=="ERROR")'
```

---

## 🛡️ Security Best Practices

### 1. Always Use TLS
SafeShare does NOT include built-in TLS. Use a reverse proxy:
- ✅ Traefik with Let's Encrypt (recommended)
- ✅ nginx with certbot
- ✅ Caddy (automatic HTTPS)

### 2. Secure the Encryption Key
```bash
# BAD - key in command line (visible in history)
docker run -e ENCRYPTION_KEY=abc123...

# GOOD - key from file
docker run -e ENCRYPTION_KEY=$(cat /secure/path/encryption.key)

# BETTER - use Docker secrets
docker secret create safeshare_key encryption.key
docker service create --secret safeshare_key safeshare:latest
```

### 3. Monitor Logs
Set up alerts for suspicious activity:
```bash
# Alert on multiple failed access attempts from same IP
docker logs safeshare | jq -r 'select(.msg=="file access denied") | .client_ip' | sort | uniq -c | awk '$1 > 10'
```

### 4. Regular Updates
```bash
# Check for updates
docker pull safeshare:latest

# Restart with new image
docker stop safeshare && docker rm safeshare
docker run -d ... safeshare:latest
```

### 5. Backup Strategy
```bash
# Backup database and uploads (encrypted!)
docker run --rm -v safeshare-data:/data -v $(pwd):/backup alpine tar czf /backup/safeshare-backup.tar.gz /data

# Store encryption key separately from backups
```

---

## 🔍 Security Audit Checklist

### Production-Required (P0)
- [x] Rate limiting enabled (DoS protection)
- [x] Filename sanitization active (header injection prevention)
- [x] Security headers configured (XSS/clickjacking prevention)
- [x] MIME type detection enabled (malware prevention)
- [x] Disk space monitoring active (exhaustion prevention)
- [x] Maximum expiration limits enforced (abuse prevention)

### Enterprise Security
- [x] TLS/HTTPS enabled via reverse proxy
- [x] Encryption at rest configured
- [x] File extension blacklist enabled
- [x] Audit logging active
- [x] Regular log monitoring
- [x] Encryption key stored in secrets manager

### Operational Security
- [x] Automatic file expiration configured
- [x] Download limits enforced
- [x] Non-root container user
- [x] Regular security updates

---

## 📞 Security Vulnerability Disclosure Policy

### Responsible Disclosure

We take security seriously at SafeShare. If you discover a security vulnerability, we appreciate your help in disclosing it to us responsibly.

### How to Report

**Do NOT create public GitHub issues for security vulnerabilities.**

1. **Email:** security@yourcompany.com
2. **Subject:** `[SECURITY] Brief description of issue`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any proof-of-concept code
   - Your suggested fix (if any)

### What to Expect

| Timeline | Action |
|----------|--------|
| Within 48 hours | Acknowledgment of your report |
| Within 7 days | Initial assessment and severity rating |
| Within 30 days | Fix developed and tested |
| Within 45 days | Security patch released |
| After patch release | Public disclosure (coordinated with reporter) |

### Severity Ratings

We use CVSS v3.1 for severity assessment:

| Severity | CVSS Score | Response Time |
|----------|------------|---------------|
| Critical | 9.0 - 10.0 | 24-48 hours |
| High | 7.0 - 8.9 | 7 days |
| Medium | 4.0 - 6.9 | 30 days |
| Low | 0.1 - 3.9 | Next release |

### Scope

**In Scope:**
- Authentication and authorization bypasses
- SQL injection, XSS, CSRF vulnerabilities
- Remote code execution
- Encryption weaknesses
- Data exposure or leakage
- Denial of service vulnerabilities
- Path traversal attacks
- Session management issues

**Out of Scope:**
- Social engineering attacks
- Physical security issues
- Vulnerabilities in third-party dependencies (report to upstream)
- Issues in outdated versions (please test on latest)
- Theoretical vulnerabilities without proof-of-concept

### Safe Harbor

We will not take legal action against researchers who:
- Make a good faith effort to avoid privacy violations and data destruction
- Do not access, modify, or delete data belonging to others
- Stop testing and report immediately upon discovering a vulnerability
- Do not publicly disclose until we've had reasonable time to fix

### Recognition

We believe in recognizing security researchers for their contributions:

- Acknowledgment in security advisories (with permission)
- Mention in CHANGELOG.md security fixes (with permission)
- Potential inclusion in a future security hall of fame

### Security Advisories

Security advisories are published via:
- GitHub Security Advisories
- CHANGELOG.md with `[Security]` tag
- Version release notes

### Past Security Fixes

Notable security improvements:

| Version | Fix | Severity |
|---------|-----|----------|
| v1.7.1 | Login brute-force lockout never took effect for admin/user password logins | High |
| v1.7.1 | Remote crash (`fatal error: concurrent map iteration and map write`) from concurrent TOTP/SSO login requests | High |
| v1.7.1 | Login lockout counter bypassable via parallel request bursts from one IP | Medium |
| v1.7.0 | Client IP spoofing via X-Forwarded-For behind proxies/CDNs | High |
| v1.7.0 | Download memory exhaustion and stalled-reader lockout (decrypt admission, legacy cap) | Medium |
| v2.8.2 | Constant-time token comparison | Medium |
| v2.8.2 | Session invalidation on password change | High |
| v2.8.2 | SQL LIKE wildcard injection fix | Medium |
| v2.8.2 | Integer overflow in chunk calculations | High |
| v2.7.0 | Trusted proxy header validation | High |
| v2.7.0 | Defense-in-depth filename validation | Medium |
| v2.1.0 | Streaming encryption (memory exhaustion fix) | High |

### Security Update Policy

- **Supported versions:** Current major version and previous major version
- **Critical fixes:** Backported to all supported versions
- **EOL versions:** Not patched; please upgrade

| Version | Status | Support Until |
|---------|--------|---------------|
| 2.x | Active | Current |
| 1.x | EOL | Security fixes only until Dec 2025 |

---

## CI/CD Security Scanning

SafeShare implements comprehensive automated security scanning in the CI/CD pipeline.

### Vulnerability Scanning Tools

#### 1. govulncheck (Go Vulnerability Scanner)

Scans Go dependencies for known vulnerabilities from the [Go Vulnerability Database](https://vuln.go.dev/).

**When it runs:**
- On every push to `develop` branch
- On every pull request
- Weekly scheduled scan (Sundays at midnight UTC)

**Integration:**
- Results uploaded to GitHub Security tab (SARIF format)
- Blocks builds if critical vulnerabilities found in direct dependencies
- Text output available in CI logs

#### 2. Trivy (Container Scanner)

Scans Docker images for OS and library vulnerabilities.

**When it runs:**
- After Docker image is built and pushed
- PR builds get local single-platform scan
- Weekly scheduled scan of `latest` image
- Filesystem scan on scheduled runs

**Configuration:**
- Severity levels: CRITICAL, HIGH, MEDIUM
- Scans both OS packages and Go libraries
- Results uploaded to GitHub Security tab

**Integration:**
- Container scan runs after successful image push
- Filesystem scan checks go.mod dependencies
- Non-blocking to allow assessment before action

### Dependency Management

#### Dependabot

Automated dependency update PRs for:

| Ecosystem | Directory | Schedule |
|-----------|-----------|----------|
| Go modules | `/` | Weekly (Monday) |
| Go SDK | `/sdk/go` | Weekly (Monday) |
| Docker | `/` | Weekly (Monday) |
| GitHub Actions | `/` | Weekly (Monday) |

**Features:**
- Grouped updates for AWS SDK (reduces PR noise)
- Grouped updates for golang.org/x packages
- Semantic commit prefixes (`deps`, `deps(docker)`, etc.)
- PR labels for easy filtering

### GitHub Security Tab

All security findings are uploaded to the GitHub Security tab:

1. Navigate to **Security** > **Code scanning alerts**
2. Filter by tool: `govulncheck`, `trivy-container`, `trivy-filesystem`
3. View vulnerability details, severity, and affected code

### Manual Security Scan

Run a security scan manually:

1. Go to **Actions** > **Security Scan**
2. Click **Run workflow**
3. Select scan type: `all`, `govulncheck`, or `trivy`
4. View results in workflow logs and Security tab

### Responding to Vulnerabilities

**Critical/High Severity:**
1. Create hotfix branch from `main`
2. Update affected dependency
3. Test thoroughly
4. Merge via expedited review

**Medium/Low Severity:**
1. Add to next sprint backlog
2. Update in regular release cycle
3. Document in CHANGELOG.md

---

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## License

MIT License - See LICENSE file
