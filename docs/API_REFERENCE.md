# SafeShare API Reference

Complete API documentation for SafeShare file sharing service.

**Base URL (Development)**: `http://localhost:8080`  
**Base URL (Production)**: `https://your-domain.com`

⚠️ **Production Warning:** SafeShare MUST be deployed behind HTTPS in production. Set `HTTPS_ENABLED=true` when using a reverse proxy. See [PRODUCTION.md](PRODUCTION.md) for details.

**Version**: 1.5.0

## OpenAPI Specification

SafeShare provides a machine-readable OpenAPI 3.0 specification for programmatic API access:

- **OpenAPI Spec File**: [`openapi.yaml`](openapi.yaml)

### Using the OpenAPI Specification

The OpenAPI specification enables:

1. **SDK Generation**: Use tools like `openapi-generator` to create client libraries:
   ```bash
   # Generate Python SDK
   openapi-generator generate -i docs/openapi.yaml -g python -o sdk/python
   
   # Generate TypeScript SDK  
   openapi-generator generate -i docs/openapi.yaml -g typescript-fetch -o sdk/typescript
   
   # Generate Go SDK
   openapi-generator generate -i docs/openapi.yaml -g go -o sdk/go
   ```

2. **API Testing**: Import into Postman, Insomnia, or other API testing tools

3. **Documentation**: Generate interactive API docs with Swagger UI or ReDoc:
   ```bash
   # Using Docker to serve Swagger UI
   docker run -p 8081:8080 -e SWAGGER_JSON=/docs/openapi.yaml \
     -v $(pwd)/docs:/docs swaggerapi/swagger-ui
   ```

4. **Validation**: Validate request/response schemas during development

### Official SDKs

Pre-built SDKs are available for common languages:

| Language | Location | Installation |
|----------|----------|-------------|
| Python | [`sdk/python`](../sdk/python/) | `pip install safeshare-sdk` |
| TypeScript/JavaScript | [`sdk/typescript`](../sdk/typescript/) | `npm install safeshare-sdk` |
| Go | [`sdk/go`](../sdk/go/) | `go get github.com/fjmerc/safeshare/sdk/go` |

See individual SDK README files for detailed usage examples and advanced patterns.

---

## Table of Contents

1. [Authentication](#authentication)
2. [API Token Authentication](#api-token-authentication)
3. [File Sharing](#file-sharing)
4. [User Management](#user-management)
5. [Admin Operations](#admin-operations)
6. [Health & Monitoring](#health--monitoring)
7. [Webhooks](#webhooks)
8. [Error Responses](#error-responses)

---

## Authentication

### User Login

Create an authenticated session for a user account.

**Endpoint**: `POST /api/auth/login`

**Request Body** (JSON):
```json
{
  "username": "user",
  "password": "password"
}
```

**Response** (200 OK):
```json
{
  "id": 1,
  "username": "user",
  "email": "user@example.com",
  "role": "user",
  "require_password_change": false
}
```

**Sets Cookie**: `user_session` (HttpOnly, SameSite=Strict)

---

### User Logout

End the current user session.

**Endpoint**: `POST /api/auth/logout`

**Authentication**: Required (user_session cookie)

**Response**: 200 OK (clears session cookie)

---

### Get Current User

Retrieve information about the currently authenticated user.

**Endpoint**: `GET /api/auth/user`

**Authentication**: Required (user_session cookie)

**Response** (200 OK):
```json
{
  "id": 1,
  "username": "user",
  "email": "user@example.com",
  "role": "user",
  "require_password_change": false
}
```

---

### Change Password

Update the current user's password.

**Endpoint**: `POST /api/auth/change-password`

**Authentication**: Required (user_session cookie)

**Request Body** (JSON):
```json
{
  "current_password": "old_password",
  "new_password": "new_password",
  "confirm_password": "new_password"
}
```

**Response**: 200 OK

**Error Responses**:
- 400 Bad Request: Password validation failed
- 401 Unauthorized: Current password incorrect

---

## API Token Authentication

API tokens provide programmatic access to SafeShare for SDKs, CLIs, and automation scripts. Tokens use Bearer authentication and support granular scope-based permissions.

### Token Format

```
safeshare_<64 hex characters>
```

- **Total length**: 74 characters
- **Entropy**: 256 bits (64 hex characters = 32 bytes)
- **Prefix**: `safeshare_` for easy identification by secret scanning tools

**Example**: `safeshare_a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd`

### Authentication

Include the token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer safeshare_<your-token>" \
  https://your-domain.com/api/user/files
```

**Authentication Priority**:
1. Bearer token in `Authorization` header (checked first)
2. Session cookie `user_session` (fallback)

### Available Scopes

| Scope | Description | Typical Use Case |
|-------|-------------|------------------|
| `upload` | Upload files via `/api/upload` | Backup scripts, CI/CD |
| `download` | Download files via `/api/claim/:code` | Automated retrievals |
| `manage` | List, rename, delete own files | File management apps |
| `admin` | Admin operations (admin users only) | Admin automation |

**Scope Restrictions**:
- Users can only request scopes matching their role
- Regular users cannot request `admin` scope
- Admin users can request any scope

### Security Considerations

- **Tokens shown once**: The full token is only returned at creation. Store it securely.
- **Hashed storage**: Tokens are stored as SHA-256 hashes (never in plaintext)
- **Timing attack protection**: Authentication responses have normalized timing
- **Session-only operations**: Token creation and revocation require session auth (not API tokens)
- **Maximum 50 tokens per user**: Prevents abuse
- **Maximum 365-day expiration**: Tokens cannot be created with unlimited lifetime

---

### Create API Token

Create a new API token for the authenticated user.

**Endpoint**: `POST /api/tokens`

**Authentication**: Required (session cookie only - API tokens cannot create other tokens)

**Request Body** (JSON):
```json
{
  "name": "My Backup Script",
  "scopes": ["upload", "download"],
  "expires_in_days": 90
}
```

**Parameters**:
- `name` (required): Human-readable token name (1-100 characters)
- `scopes` (required): Array of permission scopes (at least one required)
- `expires_in_days` (optional): Days until expiration (1-365, null for no expiration)

**Response** (201 Created):
```json
{
  "id": 1,
  "name": "My Backup Script",
  "token": "safeshare_a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd",
  "scopes": ["upload", "download"],
  "expires_at": "2026-02-25T10:00:00Z",
  "created_at": "2025-11-27T10:00:00Z"
}
```

**Important**: The `token` field is only included in the creation response. Save it immediately - it cannot be retrieved later.

**Error Responses**:
- 400 Bad Request: Missing name, invalid scopes, or validation failed
- 401 Unauthorized: Not authenticated
- 403 Forbidden: 
  - `SESSION_REQUIRED`: API tokens cannot create other tokens
  - `SCOPE_EXCEEDS_ROLE`: Requested scopes exceed user's role
  - `MAX_TOKENS_REACHED`: User has 50 tokens already

**Error Response Format**:
```json
{
  "error": "API tokens cannot create other tokens. Please use web session.",
  "code": "SESSION_REQUIRED"
}
```

---

### List API Tokens

Retrieve all API tokens for the authenticated user.

**Endpoint**: `GET /api/tokens`

**Authentication**: Required (session cookie or API token with `manage` scope)

**Response** (200 OK):
```json
{
  "tokens": [
    {
      "id": 1,
      "name": "My Backup Script",
      "token_prefix": "safeshare_a1b***bcd",
      "scopes": ["upload", "download"],
      "last_used_at": "2025-11-27T15:30:00Z",
      "expires_at": "2026-02-25T10:00:00Z",
      "created_at": "2025-11-27T10:00:00Z"
    },
    {
      "id": 2,
      "name": "CI/CD Pipeline",
      "token_prefix": "safeshare_x9y***z12",
      "scopes": ["upload"],
      "last_used_at": null,
      "expires_at": null,
      "created_at": "2025-11-20T08:00:00Z"
    }
  ]
}
```

**Note**: The full token value is never returned in list operations. Only the masked `token_prefix` is shown for identification.

---

### Revoke API Token

Revoke (delete) an API token.

**Endpoint**: `DELETE /api/tokens/:id`

**Authentication**: Required (session cookie only - API tokens cannot revoke tokens)

**Response** (200 OK):
```json
{
  "message": "Token revoked successfully"
}
```

**Error Responses**:
- 400 Bad Request: Invalid token ID format
- 401 Unauthorized: Not authenticated
- 403 Forbidden:
  - `SESSION_REQUIRED`: API tokens cannot revoke other tokens
- 404 Not Found: Token doesn't exist or not owned by user

---

### Admin: List All Tokens

List all API tokens in the system (admin only).

**Endpoint**: `GET /admin/api/tokens`

**Authentication**: Required (admin session)

**Query Parameters**:
- `limit` (optional): Results per page (default: 50, max: 100)
- `offset` (optional): Pagination offset (default: 0)
- `user_id` (optional): Filter by user ID

**Response** (200 OK):
```json
{
  "tokens": [
    {
      "id": 1,
      "user_id": 5,
      "username": "john",
      "name": "Backup Script",
      "token_prefix": "safeshare_a1b***bcd",
      "scopes": ["upload", "download"],
      "last_used_at": "2025-11-27T15:30:00Z",
      "expires_at": "2026-02-25T10:00:00Z",
      "created_at": "2025-11-27T10:00:00Z"
    }
  ],
  "total": 42
}
```

---

### Admin: Revoke Any Token

Revoke any user's API token (admin only).

**Endpoint**: `DELETE /admin/api/tokens/revoke?id=:id`

**Authentication**: Required (admin session + CSRF token)

**Response** (200 OK):
```json
{
  "message": "Token revoked successfully"
}
```

**Error Responses**:
- 400 Bad Request: Missing or invalid token ID
- 404 Not Found: Token doesn't exist

---

### Using API Tokens with Endpoints

API tokens can authenticate most user endpoints. Here are examples:

**Upload a file**:
```bash
curl -X POST \
  -H "Authorization: Bearer safeshare_<token>" \
  -F "file=@document.pdf" \
  -F "expires_in_hours=48" \
  http://localhost:8080/api/upload
```

**List your files**:
```bash
curl -H "Authorization: Bearer safeshare_<token>" \
  http://localhost:8080/api/user/files
```

**Download a file**:
```bash
curl -H "Authorization: Bearer safeshare_<token>" \
  -O http://localhost:8080/api/claim/Xy9kLm8pQz4vDwE
```

**Note**: Download endpoint authentication is optional. API tokens are only needed if `REQUIRE_AUTH_FOR_UPLOAD` is enabled or for accessing file management endpoints.

---

### Token Lifecycle

1. **Creation**: User creates token via web session (POST /api/tokens)
2. **Usage**: Token used in `Authorization: Bearer` header
3. **Tracking**: `last_used_at` updated on each successful authentication
4. **Expiration**: Tokens automatically expire at `expires_at` (if set)
5. **Revocation**: User revokes via web session (DELETE /api/tokens/:id)
6. **Cleanup**: Expired tokens automatically deleted by background worker

---

## File Sharing

### Upload File (Simple)

Upload a file and receive a unique claim code. For files under the chunked upload threshold (default: 100MB).

**Endpoint**: `POST /api/upload`

**Authentication**: Optional (depends on REQUIRE_AUTH_FOR_UPLOAD setting)

**Request**: `multipart/form-data`

**Parameters**:
- `file` (required): The file to upload
- `expires_in_hours` (optional): Hours until expiration (default: 24, 0 = never expire)
- `max_downloads` (optional): Maximum downloads (default: unlimited, 0 = unlimited)
- `password` (optional): Password protection (bcrypt-hashed)

**Example**:
```bash
curl -X POST \
  -F "file=@document.pdf" \
  -F "expires_in_hours=48" \
  -F "max_downloads=5" \
  -F "password=secret123" \
  http://localhost:8080/api/upload
```

**Response** (201 Created):
```json
{
  "claim_code": "Xy9kLm8pQz4vDwE",
  "expires_at": "2025-11-23T14:30:00Z",
  "download_url": "http://localhost:8080/api/claim/Xy9kLm8pQz4vDwE",
  "max_downloads": 5,
  "file_size": 1048576,
  "original_filename": "document.pdf",
  "sha256_hash": "a3b2c1d4e5f6..."
}
```

**Error Responses**:
- 400 Bad Request: Invalid parameters or missing file
- 403 Forbidden: Authentication required (if REQUIRE_AUTH_FOR_UPLOAD=true)
- 413 Payload Too Large: File exceeds MAX_FILE_SIZE
- 422 Unprocessable Entity (`MALWARE_DETECTED`): the file was scanned and found infected; it is rejected and never stored — no claim code is issued
- 422 Unprocessable Entity (`UNSCANNABLE_UPLOAD`): the file cannot be scanned (end-to-end encrypted or exceeds the scan size limit) and this server requires all uploads to be scannable (`MALWARE_SCAN_REJECT_UNSCANNABLE=true`)
- 503 Service Unavailable (`SCAN_UNAVAILABLE`, `Retry-After` header set): malware scanning is enabled but the scanner could not be reached; retry after the given delay
- 507 Insufficient Storage: Disk full or quota exceeded

> **Malware scanning** (ADR-015): when `FEATURE_MALWARE_SCAN=true`, the upload is scanned synchronously — before encryption/storage and before a claim code is generated — so `POST /api/upload` may take noticeably longer to respond. See [SECURITY.md](SECURITY.md#-malware-scanning-clamav) for the full behavior, including the `not_scanned` status used for end-to-end encrypted or oversized uploads.

---

### Chunked Upload - Initialize

Initialize a chunked upload session for large files (>= CHUNKED_UPLOAD_THRESHOLD).

**Endpoint**: `POST /api/upload/init`

**Authentication**: Optional (depends on REQUIRE_AUTH_FOR_UPLOAD setting)

**Request Body** (JSON):
```json
{
  "filename": "large-file.zip",
  "total_size": 262144000,
  "chunk_size": 10485760,
  "expires_in_hours": 24,
  "max_downloads": 5,
  "password": "optional_password"
}
```

**Response** (200 OK):
```json
{
  "upload_id": "550e8400-e29b-41d4-a716-446655440000",
  "chunk_size": 10485760,
  "total_chunks": 25,
  "expires_at": "2025-11-22T12:00:00Z"
}
```

**See Also**: [CHUNKED_UPLOAD.md](CHUNKED_UPLOAD.md) for complete chunked upload documentation.

---

### Chunked Upload - Upload Chunk

Upload a single chunk of a file.

**Endpoint**: `POST /api/upload/chunk/:upload_id/:chunk_number`

**Authentication**: Optional (depends on REQUIRE_AUTH_FOR_UPLOAD setting)

**Request**: `multipart/form-data`

**Parameters**:
- `chunk` (required): The chunk data (max size: CHUNK_SIZE)

**Response** (200 OK):
```json
{
  "upload_id": "550e8400-...",
  "chunk_number": 0,
  "chunks_received": 1,
  "total_chunks": 25,
  "complete": false
}
```

---

### Chunked Upload - Complete

Finalize a chunked upload and assemble the file.

**Endpoint**: `POST /api/upload/complete/:upload_id`

**Authentication**: Optional (depends on REQUIRE_AUTH_FOR_UPLOAD setting)

**Response** (200 OK - synchronous completion):
```json
{
  "claim_code": "aFYR83-afRPqrb-8",
  "download_url": "http://localhost:8080/api/claim/aFYR83-afRPqrb-8",
  "expires_at": "2025-11-22T12:00:00Z",
  "max_downloads": 5,
  "file_size": 262144000,
  "original_filename": "large-file.zip",
  "sha256_hash": "b4c3d2e1f0..."
}
```

**Response** (202 Accepted - asynchronous processing):
```json
{
  "upload_id": "550e8400-...",
  "status": "processing",
  "message": "File assembly in progress. Check status endpoint for completion."
}
```

---

### Chunked Upload - Check Status

Check the status of a chunked upload session.

**Endpoint**: `GET /api/upload/status/:upload_id`

**Authentication**: Optional (depends on REQUIRE_AUTH_FOR_UPLOAD setting)

**Response** (200 OK):
```json
{
  "upload_id": "550e8400-...",
  "filename": "large-file.zip",
  "status": "uploading",
  "chunks_received": 20,
  "total_chunks": 25,
  "missing_chunks": [5, 12, 18],
  "complete": false,
  "expires_at": "2025-11-22T12:00:00Z"
}
```

**Status Values**:
- `uploading`: Chunks being received
- `processing`: File assembly in progress (includes the malware scan, when `FEATURE_MALWARE_SCAN=true` — see ADR-015)
- `completed`: Upload complete, claim code available
- `failed`: Upload failed (check `error_message`; `error_code` gives a machine-readable reason, e.g. `MALWARE_DETECTED`, `SCAN_UNAVAILABLE`, when applicable)

**Rate limit**: This endpoint is limited per IP to 600x `RATE_LIMIT_UPLOAD` requests per hour (never under 6,000/hour), well above the ~1,800/hour sent by a client polling every 2 seconds. If you do receive `429`, keep polling (back off briefly) rather than treating it as an upload failure; the assembly continues server-side.

---

### Download File

Download a file using its claim code, or check its size/availability
without downloading it.

**Endpoint**: `GET /api/claim/:code`, `HEAD /api/claim/:code`

`HEAD` returns exactly the same headers a `GET` would (`Content-Length`,
`ETag`, `Accept-Ranges`, `Content-Type`, `Content-Disposition`, ...) with no
body, and goes through every access check `GET` does — claim-code validity,
expiry, malware-scan status, password, **and download-limit** (a `HEAD` on a
file that's already exhausted its `max_downloads` gets the same `410 Gone`
a `GET` would). It never counts against `max_downloads` and never reserves
or spends a download-session slot — use it to check availability before
committing to a real download (SafeShare's own web UI does this).

**Authentication**: None required

**Query Parameters**:
- `password` (optional, deprecated — prefer the `X-File-Password` request header): Required if file is password-protected

**Example**:
```bash
# Without password
curl -O http://localhost:8080/api/claim/Xy9kLm8pQz4vDwE

# With password
curl -O -H "X-File-Password: secret123" http://localhost:8080/api/claim/Xy9kLm8pQz4vDwE

# Check size/availability without downloading
curl -I http://localhost:8080/api/claim/Xy9kLm8pQz4vDwE
```

**Response** (200 OK):
- Binary file data (omitted for `HEAD`)
- Headers:
  - `Content-Type`: Original file MIME type
  - `Content-Disposition`: attachment; filename="original_name.pdf" (RFC 6266, with a UTF-8 `filename*=` value alongside the ASCII fallback)
  - `Content-Length`: File size in bytes
  - `Accept-Ranges`: bytes (supports HTTP Range requests)
  - `ETag`: a strong validator for conditional requests and resume (see below)
  - `Last-Modified`: the file's upload time

**Response** (206 Partial Content):
- Returned for a well-formed, satisfiable single-range `Range` request
- Headers include `Content-Range`
- An unsupported or malformed `Range` header (multiple ranges, or a
  syntactically invalid one) is *not* rejected — it's treated as if no
  `Range` header were sent, and the full file is returned with `200 OK`

**Response** (304 Not Modified):
- Returned when `If-None-Match` (checked against `ETag`) or
  `If-Modified-Since` (checked against `Last-Modified`) indicates the
  client's cached copy is current. Empty body. Never counts against
  `max_downloads` or spends a download-session slot.
- `If-Range` is also supported, so a resumed download safely falls back to
  a full re-download (200) instead of an incorrect byte range if the
  underlying file changed.

**Every response** (200, 206, 304, 416, error, and `HEAD`) includes
`Cache-Control: private, no-store` — claim responses can depend on
per-recipient state and must never be cached by a browser or CDN.

**Files with `max_downloads` set** also include:
- `X-Download-Session`: an opaque bearer token for this download session.
  Resumable clients (pause/resume, retry) should send it back as an
  `X-Download-Session` request header on follow-up Range requests for the
  same file so the resumed download is recognised as a continuation and
  counts once, not once per request. See `docs/HTTP_RANGE_SUPPORT.md` for the
  full counting semantics (ADR-014). Never set on a `HEAD` request.

**Error Responses**:
- 401 Unauthorized: Password required or incorrect
- 404 Not Found: Invalid claim code or file expired
- 410 Gone: Download limit reached, **or** (`FILE_QUARANTINED`) the file was found infected by a malware scan
- 416 Range Not Satisfiable: the `Range` header was syntactically valid but describes bytes the file doesn't have (e.g. a start position beyond the file's size, or any range at all against a zero-byte file). A malformed or multi-range `Range` header is *not* an error — see the 200/206 notes above.
- 423 Locked (`SCAN_PENDING`, `Retry-After` header set): the file's malware scan has not completed yet
- 403 Forbidden (`SCAN_FAILED`): the file's malware scan errored and it cannot be verified safe
- 503 Service Unavailable (`SERVER_BUSY`, `Retry-After` header set): the server's encrypted-download memory budget is temporarily exhausted; retry after the given delay
- 429 Too Many Requests (`TOO_MANY_INFLIGHT`, `Retry-After` header set): too many concurrent downloads in flight — either for this file from this IP, or (for encrypted content) for this IP across every file; retry after the given delay

> See [SECURITY.md](SECURITY.md#-malware-scanning-clamav) for the full ADR-015 download-gating behavior, including the `MALWARE_SCAN_ALLOW_UNVERIFIED` opt-out, and [HTTP_RANGE_SUPPORT.md](HTTP_RANGE_SUPPORT.md) for the full Range/conditional-request/admission-control design (ADR-017).

---

### Get File Info

Retrieve file metadata without downloading.

**Endpoint**: `GET /api/claim/:code/info`

**Authentication**: None required

**Query Parameters**:
- `password` (optional): Required if file is password-protected

**Response** (200 OK):
```json
{
  "claim_code": "Xy9kLm8pQz4vDwE",
  "original_filename": "document.pdf",
  "file_size": 1048576,
  "created_at": "2025-11-21T10:00:00Z",
  "expires_at": "2025-11-23T10:00:00Z",
  "download_count": 2,
  "max_downloads": 5,
  "downloads_remaining": 3,
  "password_protected": true,
  "sha256_hash": "a3b2c1d4e5f6...",
  "scan_status": "clean",
  "download_available": true
}
```

`scan_status` is one of `clean`, `infected`, `pending`, `error`, `not_scanned`, or omitted (scanning disabled, or file predates the malware scanning feature). `download_available` is `false` exactly when `GET /api/claim/:code` would currently be blocked by the scan gate (see ADR-015) — check it before presenting a download link so the recipient gets a clear "still being scanned" state instead of a failed download.

**Error Responses**:
- 401 Unauthorized: Password required or incorrect
- 404 Not Found: Invalid claim code or file expired

---

## User Management

### List User's Files

Retrieve paginated list of files uploaded by the current user.

**Endpoint**: `GET /api/user/files`

**Authentication**: Required (user_session cookie)

**Query Parameters**:
- `limit` (optional): Number of results per page (default: 50, max: 100)
- `offset` (optional): Pagination offset (default: 0)

**Response** (200 OK):
```json
{
  "files": [
    {
      "id": 1,
      "claim_code": "Xy9kLm8pQz4vDwE",
      "original_filename": "document.pdf",
      "file_size": 1048576,
      "created_at": "2025-11-21T10:00:00Z",
      "expires_at": "2025-11-23T10:00:00Z",
      "download_count": 2,
      "completed_downloads": 1,
      "max_downloads": 5,
      "password_protected": true,
      "sha256_hash": "a3b2c1d4e5f6..."
    }
  ],
  "total": 42,
  "limit": 50,
  "offset": 0
}
```

---

### Delete User's File

Delete a file owned by the current user.

**Endpoint**: `DELETE /api/user/files/delete`

**Authentication**: Required (user_session cookie)

**Request Body** (JSON):
```json
{
  "file_id": 1
}
```

**Response**: 200 OK

**Error Responses**:
- 403 Forbidden: File not owned by user
- 404 Not Found: File doesn't exist

---

### Rename User's File

Change the original filename of a user's uploaded file.

**Endpoint**: `POST /api/user/files/rename`

**Authentication**: Required (user_session cookie)

**Request Body** (JSON):
```json
{
  "file_id": 1,
  "new_filename": "updated-document.pdf"
}
```

**Response**: 200 OK

**Error Responses**:
- 400 Bad Request: Invalid filename
- 403 Forbidden: File not owned by user
- 404 Not Found: File doesn't exist

---

### Update File Expiration

Modify the expiration time of a user's uploaded file.

**Endpoint**: `POST /api/user/files/update-expiration`

**Authentication**: Required (user_session cookie)

**Request Body** (JSON):
```json
{
  "file_id": 1,
  "expires_in_hours": 72
}
```

**Response**: 200 OK

**Error Responses**:
- 400 Bad Request: Invalid expiration value (exceeds MAX_EXPIRATION_HOURS)
- 403 Forbidden: File not owned by user
- 404 Not Found: File doesn't exist

---

### Regenerate Claim Code

Generate a new claim code for a user's uploaded file.

**Endpoint**: `POST /api/user/files/regenerate-claim-code`

**Authentication**: Required (user_session cookie)

**Request Body** (JSON):
```json
{
  "file_id": 1
}
```

**Response** (200 OK):
```json
{
  "claim_code": "NewClaimCode123",
  "download_url": "http://localhost:8080/api/claim/NewClaimCode123"
}
```

**Error Responses**:
- 403 Forbidden: File not owned by user
- 404 Not Found: File doesn't exist

**Note**: The old claim code becomes invalid immediately. This is useful for revoking access.

---

## Admin Operations

**Note**: All admin endpoints require authentication (admin_session or user_session with admin role) and most require CSRF token validation.

### Admin Login

Create an authenticated admin session.

**Endpoint**: `POST /admin/api/login`

**Request Body** (form or JSON):
```json
{
  "username": "admin",
  "password": "admin_password"
}
```

**Response** (200 OK):
```json
{
  "username": "admin"
}
```

**Sets Cookies**:
- `user_session` (for admin accounts created via user management)
- `csrf_token` (for CSRF protection)

---

### Get Dashboard Data

Retrieve admin dashboard statistics and file listings.

**Endpoint**: `GET /admin/api/dashboard`

**Authentication**: Required (admin session)

**Query Parameters**:
- `limit` (optional): Files per page (default: 20)
- `offset` (optional): Pagination offset
- `search` (optional): Search query (claim code, filename, or uploader IP)

**Response** (200 OK):
```json
{
  "stats": {
    "total_files": 150,
    "storage_used_bytes": 5368709120,
    "quota_used_percent": 52.4,
    "blocked_ips_count": 5,
    "partial_upload_size_bytes": 104857600,
    "total_users": 12
  },
  "files": [...],
  "blocked_ips": [...],
  "total_files": 150
}
```

---

### Delete File (Admin)

Delete any file from the system.

**Endpoint**: `POST /admin/api/files/delete`

**Authentication**: Required (admin session + CSRF token)

**Request Body** (JSON):
```json
{
  "claim_code": "Xy9kLm8pQz4vDwE"
}
```

**Response**: 200 OK

---

### Bulk Delete Files

Delete multiple files at once.

**Endpoint**: `POST /admin/api/files/delete/bulk`

**Authentication**: Required (admin session + CSRF token)

**Request Body** (JSON):
```json
{
  "claim_codes": ["code1", "code2", "code3"]
}
```

**Response** (200 OK):
```json
{
  "deleted_count": 3
}
```

---

### Block IP Address

Add an IP address or CIDR range to the blocklist.

**Endpoint**: `POST /admin/api/ip/block`

**Authentication**: Required (admin session + CSRF token)

**Request Body** (JSON):
```json
{
  "ip_address": "192.168.1.100",
  "reason": "Spam uploads"
}
```

`ip_address` accepts either a bare IPv4/IPv6 address (`192.168.1.100`, `2001:db8::1`) or a CIDR range (`203.0.113.0/24`, `2001:db8:1:2::/64`). It's canonicalized before storage — IPv4-mapped IPv6 addresses are unmapped, zone IDs are dropped, and hex is lowercased/compressed — so the same logical address or range always matches regardless of how it was typed. A CIDR range broader than `/8` (IPv4) or `/32` (IPv6), including `0.0.0.0/0` and `::/0`, is rejected (400) to avoid a typo blocking most of the address space.

Three self-lockout guards refuse a block outright (409) rather than persisting it:
- it includes loopback (`127.0.0.0/8` or `::1`);
- it includes the requesting admin's own current client IP;
- it fully contains a configured `TRUSTED_PROXY_IPS` entry — either the trusted range/host itself (e.g. blocking `10.0.0.0/8` when that's a trusted range, or a `/16` that contains a trusted `/24`), or a range that contains a trusted entry that's itself a single host (an explicitly named reverse proxy). SafeShare relies on that range to resolve real client IPs, so blocking it (or enough of it) would break request handling for every client behind it, not just an attacker.

A target that merely sits *inside* a broader `TRUSTED_PROXY_IPS` range (the common case — the default `TRUSTED_PROXY_IPS` is whole private ranges like `192.168.0.0/16`, and blocking one LAN host under it is normal) is **not** refused, but the 200 response's `message` includes a caution: if that range is your reverse proxy's own peer address, its requests that arrive without a usable forwarded header (see `TRUST_PROXY_HEADERS`) will now be blocked too.

**Response**: 200 OK
```json
{
  "success": true,
  "message": "IP blocked successfully"
}
```
With a caution (see above):
```json
{
  "success": true,
  "message": "IP blocked successfully Note: 192.168.1.50 is inside the configured TRUSTED_PROXY_IPS range 192.168.0.0/16. If that range includes your reverse proxy, any of its requests that arrive without a usable forwarded header will now be blocked too."
}
```

**Errors** (all responses are `{"success": false, "message": "..."}`):
- `400 Bad Request` — missing/invalid `ip_address`, or an overly-broad CIDR range
- `409 Conflict` — the block was refused as a self-lockout risk (loopback, the admin's own IP, or a trusted-proxy range/host — see above), or the canonical address/range is already blocked (possibly under a different original spelling)

---

### Unblock IP Address

Remove an IP address or CIDR range from the blocklist.

**Endpoint**: `POST /admin/api/ip/unblock`

**Authentication**: Required (admin session + CSRF token)

**Request Body** (JSON):
```json
{
  "ip_address": "192.168.1.100"
}
```

`ip_address` is canonicalized the same way as Block IP Address before lookup, so it doesn't need to be typed identically to how it was originally blocked (and, for a legacy row too broad to canonicalize, falls back to an exact match on the stored string).

**Response**: 200 OK, `{"success": true, "message": "IP unblocked successfully"}`

**Errors** (all responses are `{"success": false, "message": "..."}`):
- `400 Bad Request` — missing `ip_address`
- `404 Not Found` — no blocklist entry matched

---

### Update Storage Settings

Modify storage-related configuration at runtime.

**Endpoint**: `POST /admin/api/settings/storage`

**Authentication**: Required (admin session + CSRF token)

**Request Body** (JSON):
```json
{
  "quota_gb": 100,
  "max_file_size_bytes": 209715200,
  "default_expiration_hours": 48,
  "max_expiration_hours": 336
}
```

**Response**: 200 OK

**Note**: Settings persist to database and survive restarts.

---

### Update Security Settings

Modify security-related configuration at runtime.

**Endpoint**: `POST /admin/api/settings/security`

**Authentication**: Required (admin session + CSRF token)

**Request Body** (JSON):
```json
{
  "rate_limit_upload": 20,
  "rate_limit_download": 100,
  "blocked_extensions": [".exe", ".bat", ".cmd"]
}
```

**Response**: 200 OK

---

### Get Configuration

Retrieve current server configuration.

**Endpoint**: `GET /admin/api/config`

**Authentication**: Required (admin session)

**Response** (200 OK):
```json
{
  "chunk_size": 10485760,
  "chunked_upload_threshold": 104857600,
  "encryption_enabled": true,
  "max_file_size": 104857600,
  "read_timeout": 120,
  "write_timeout": 120
}
```

---

### Configuration Assistant

Analyze deployment environment and get optimized configuration recommendations.

**Endpoint**: `POST /admin/api/config-assistant/analyze`

**Authentication**: Required (admin session + CSRF token)

**Request Body** (JSON):
```json
{
  "storage_type": "network",
  "network_speed_mbps": 100,
  "cdn_used": true,
  "cdn_timeout_seconds": 100,
  "average_file_size_mb": 500,
  "concurrent_users": 50,
  "network_latency_ms": 50
}
```

**Response** (200 OK):
```json
{
  "recommendations": {
    "chunk_size": 20971520,
    "read_timeout": 200,
    "write_timeout": 200,
    "max_file_size": 5368709120
  },
  "current_settings": {...},
  "immediate_settings": {...},
  "restart_required_settings": {...},
  "reasoning": [...]
}
```

---

### User Management Endpoints

#### Create User
**POST** `/admin/api/users/create`

#### List Users
**GET** `/admin/api/users`

#### Update User
**PUT** `/admin/api/users/:id`

#### Delete User
**DELETE** `/admin/api/users/:id`

#### Enable/Disable User
**POST** `/admin/api/users/:id/enable`
**POST** `/admin/api/users/:id/disable`

#### Reset User Password
**POST** `/admin/api/users/:id/reset-password`

**See Also**: [SECURITY.md](SECURITY.md#user-authentication) for detailed user management documentation.

---

### Admin: Audit Log

Tamper-evident audit log (ADR-018). Enabled by default except in anonymous mode (`AUDIT_LOG=auto`); see [SECURITY.md](SECURITY.md) (Audit Log section). All endpoints require an admin session; state-changing requests (`verify`, and `PUT` on `retention`) also require a CSRF token (`X-CSRF-Token`).

#### List Entries

**Endpoint**: `GET /admin/api/audit-logs`

**Query parameters** (all optional):

| Parameter | Description |
|-----------|-------------|
| `event_type` | `AUTH`, `FILE`, `ADMIN`, `SECURITY`, `CONFIG`, or `SYSTEM` |
| `outcome` | `SUCCESS`, `FAILURE`, or `DENIED` |
| `action` | Exact action name (for example `backup_create`) |
| `username` | Exact username |
| `ip` | Exact IP address |
| `resource_type`, `resource_id` | Resource the action touched |
| `search` | Substring of action, username, resource ID or details |
| `since`, `until` | RFC 3339 time or `YYYY-MM-DD`; `since` is inclusive, `until` exclusive |
| `limit` | Page size (default 50, maximum 1000) |
| `before_id` | Return only entries with a smaller ID (paging) |

Entries are returned newest first. To fetch the next page, pass `next_before_id` from the previous response as `before_id`.

```bash
curl -b "admin_session=<session>" \
  "https://share.example.com/admin/api/audit-logs?event_type=AUTH&outcome=FAILURE&limit=100"
```

**Response** (200 OK):
```json
{
  "entries": [
    {
      "id": 1842,
      "timestamp": "2026-01-15T10:30:00.123456Z",
      "event_type": "AUTH",
      "action": "login",
      "outcome": "FAILURE",
      "username": "alice",
      "ip_address": "203.0.113.7",
      "user_agent": "Mozilla/5.0 ...",
      "resource_type": "user",
      "details": "{\"reason\":\"missing_credentials\"}",
      "prev_hash": "...",
      "entry_hash": "...",
      "key_id": "a1b2c3d4e5f60718"
    }
  ],
  "next_before_id": 1743
}
```

`next_before_id` is present only when the page was full. Empty fields (`user_id`, `username`, `resource_type`, etc.) are omitted. `details` is a JSON object serialized as a string. Values in the example are illustrative.

**Errors**: `400 INVALID_FILTER` (bad date, `limit` or `before_id`), `401`, `500`.

#### Export

**Endpoint**: `GET /admin/api/audit-logs/export?format=csv|jsonl`

Accepts the same filters as the list endpoint (except paging). `format` defaults to `csv`. Returns an attachment named `safeshare-audit-YYYYMMDD-HHMMSS.csv` (`text/csv`) or `.jsonl` (`application/x-ndjson`), newest first, including `prev_hash`, `entry_hash` and `key_id`. An export is capped at 100,000 entries; if it stops early the last line says so (`# export incomplete: ...` in CSV, `{"export_incomplete": true, ...}` in JSON Lines), so narrow the filters. The CSV prefixes text starting with `=`, `+`, `-` or `@` with `'` to block spreadsheet formula injection, so it is not an exact copy of what was signed; use JSON Lines for that. Each export is itself recorded in the audit log.

**Errors**: `400 INVALID_FILTER`, `400 INVALID_FORMAT`.

#### Verify Integrity

**Endpoint**: `POST /admin/api/audit-logs/verify`

**Authentication**: Admin session + CSRF token

Re-checks the whole signature chain. No request body.

**Response** (200 OK):
```json
{
  "verification": { "valid": true, "checked": 1842, "last_id": 1842 },
  "key_id": "a1b2c3d4e5f60718",
  "duration_ms": 41
}
```

The `verification` object also carries `first_id`, `last_hash` and, when `valid` is `false`, `problem`/`problem_id` (the first inconsistency), `problems` (up to 20 `{id, description}` items) and `problem_count`. Checking continues past the first problem. Each verification is recorded in the audit log.

**Errors**: `409 VERIFY_IN_PROGRESS` (one is already running), `503 FEATURE_DISABLED` (audit log is off), `500`.

#### Retention

**Endpoint**: `GET /admin/api/audit-logs/retention` and `PUT /admin/api/audit-logs/retention`

**Authentication**: Admin session; `PUT` also requires a CSRF token

`GET` returns the current setting; `PUT` changes it. Both return:

```json
{ "retention_days": 365, "enabled": true }
```

`last_prune_error` and `last_prune_error_at` are included if the most recent daily prune failed.

**PUT body**: `{"retention_days": 365}`. `0` keeps entries forever; otherwise the value must be between 30 and 36500. Anything else returns `400 INVALID_REQUEST`.

---

### Admin: Backups

Manage backups in `BACKUP_DIR` (default `<DATA_DIR>/backups`). Backup folder names look like `backup-2026-01-15T02-00-00`. All endpoints require an admin session; everything except the list also requires a CSRF token. Details and CLI usage: [BACKUP_RESTORE.md](BACKUP_RESTORE.md).

| Method | Path | Body / query | Description |
|--------|------|--------------|-------------|
| `GET` | `/admin/api/backups` | none | List backups: `{"backups": [{"filename", "path", "mode", "size", "created_at", "version", "verified"}]}` |
| `POST` | `/admin/api/backups` | `{"mode": "full"}` (`config`, `database` or `full`; default `full`) | Create a backup synchronously |
| `DELETE` | `/admin/api/backups` | `?filename=<name>` (or `{"backup_path": ...}`) | Delete a backup folder |
| `POST` | `/admin/api/backups/verify` | `{"filename": "<name>"}` (or `backup_path`) | Verify checksums; returns `{"valid", "errors", "mode", "version"}` and marks a valid backup as verified |
| `POST` | `/admin/api/backups/restore` | `{"filename": "<name>", "handle_orphans": "keep"\|"remove", "dry_run": false, "force": false}` | Restore the database (and uploads for full backups) |
| `POST` | `/admin/api/backups/download` | `{"filename": "<name>"}` | Stream the backup as a zip |

Paths outside `BACKUP_DIR` are rejected with `403`.

### Admin: Backup Scheduler

Scheduled backups (enabled with `AUTO_BACKUP_ENABLED=true`). See [BACKUP_RESTORE.md](BACKUP_RESTORE.md#scheduled-backups-and-retention), including the warning that scheduled retention deletes **every** `backup-*` folder in `BACKUP_DIR` older than the retention period, manual backups included.

| Method | Path | CSRF | Description |
|--------|------|------|-------------|
| `GET` | `/admin/api/backup-schedules` | No | `{"schedules": [...]}` |
| `GET` / `PUT` | `/admin/api/backup-schedules/{id}` | PUT only | Get or update (`name`, `enabled`, `schedule`, `mode`, `retention_days`) |
| `GET` | `/admin/api/backup-runs` | No | Run history; query `schedule_id`, `status`, `trigger_type`, `limit` (max 1000, default 100), `offset` |
| `GET` | `/admin/api/backup-runs/{id}` | No | One run |
| `GET` | `/admin/api/backup-stats` | No | `{"stats": {...}, "scheduler_running": true}` |
| `POST` | `/admin/api/backup-trigger` | Yes | Start a backup now (`{"mode": "full"}`); `202 Accepted`, or `409` if one is running |
| `GET` | `/admin/api/backup-running` | No | `{"running": false}` or `{"running": true, "run": {...}, "elapsed_ms", "progress"}` |

### Admin: Bulk Extend Tokens

**Endpoint**: `POST /admin/api/tokens/bulk-extend`

**Authentication**: Admin session + CSRF token

**Request Body** (JSON):
```json
{ "token_ids": [12, 13, 14], "days": 30, "confirm": true }
```

`confirm` must be `true`. At most 100 token IDs per request; `days` must be 1-365.

**Response** (200 OK): `{"message": "...", "extended_count": 3}`

**Errors** (`code`): `CONFIRMATION_REQUIRED`, `MISSING_TOKEN_IDS`, `INVALID_DAYS`, `DAYS_TOO_LARGE`, `TOO_MANY_TOKENS`, `INVALID_TOKEN_ID` (all `400`).

### Admin: SSO Links

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/admin/api/sso/links` | List links between users and SSO providers. Query: `page` (default 1), `per_page` (default 50, max 100), `provider_id`. Returns `{"links": [...], "page", "per_page", "total_count", "total_pages"}` |
| `DELETE` | `/admin/api/sso/links/{id}` | Unlink a user's SSO identity (CSRF token required). `404` if the link doesn't exist |

---

## Health & Monitoring

### Comprehensive Health Check

Get detailed health status with resource metrics.

**Endpoint**: `GET /health`

**Authentication**: None required

**Response** (200 OK - Healthy):
```json
{
  "status": "healthy",
  "uptime_seconds": 86400,
  "total_files": 150,
  "storage_used_bytes": 5368709120,
  "disk_total_bytes": 1000000000000,
  "disk_free_bytes": 500000000000,
  "disk_available_bytes": 500000000000,
  "disk_used_percent": 50.0,
  "quota_limit_bytes": 107374182400,
  "quota_used_percent": 5.0,
  "database_metrics": {
    "size_bytes": 10485760,
    "wal_size_bytes": 524288,
    "page_count": 2560,
    "page_size": 4096,
    "index_count": 8
  }
}
```

**Response** (503 Service Unavailable - Unhealthy/Degraded):
```json
{
  "status": "degraded",
  "uptime_seconds": 86400,
  ...
  "status_details": [
    "disk_low: Only 1.8GB free (< 2GB threshold)",
    "quota_high: Storage quota at 96% (> 95% threshold)"
  ]
}
```

**Status Levels**:
- `healthy` (200): All systems operational
- `degraded` (503): Warning conditions exist
- `unhealthy` (503): Critical conditions exist

---

### Liveness Probe

Fast health check for process aliveness (< 10ms).

**Endpoint**: `GET /health/live`

**Authentication**: None required

**Response** (200 OK):
```json
{
  "status": "alive",
  "database_connected": true
}
```

**Use Case**: Kubernetes/Docker liveness probes

---

### Readiness Probe

Check if service is ready to accept traffic.

**Endpoint**: `GET /health/ready`

**Authentication**: None required

**Response** (200 OK):
```json
{
  "status": "ready",
  "uptime_seconds": 86400
}
```

**Response** (503 Service Unavailable):
```json
{
  "status": "not_ready",
  "reason": "database_unavailable"
}
```

**Use Case**: Kubernetes/Docker readiness probes

---

### Prometheus Metrics

Expose metrics in Prometheus format for monitoring and alerting.

**Endpoint**: `GET /metrics`

**Authentication**: None required

**Response**: Prometheus text format

**Metrics Exported**:
- `safeshare_uploads_total` - Total upload requests (counter)
- `safeshare_downloads_total` - Total download requests (counter)
- `safeshare_chunked_uploads_total` - Chunked uploads (counter)
- `safeshare_http_requests_total` - HTTP requests by method/path (counter)
- `safeshare_http_request_duration_seconds` - Request latency (histogram)
- `safeshare_upload_size_bytes` - Upload sizes (histogram)
- `safeshare_download_size_bytes` - Download sizes (histogram)
- `safeshare_storage_used_bytes` - Current storage usage (gauge)
- `safeshare_active_files_count` - Number of active files (gauge)
- `safeshare_storage_quota_used_percent` - Quota usage percentage (gauge)
- `safeshare_health_status` - Health status (gauge: 0=unhealthy, 1=degraded, 2=healthy)
- `safeshare_health_checks_total` - Health check count (counter)
- `safeshare_health_check_duration_seconds` - Health check duration (histogram)

**See Also**: [PROMETHEUS.md](PROMETHEUS.md) for Grafana dashboards and alerting rules.

---

### Public Configuration

Retrieve public-facing configuration (no authentication required).

**Endpoint**: `GET /api/config`

**Authentication**: None required

**Response** (200 OK):
```json
{
  "version": "2.8.0",
  "max_file_size": 104857600,
  "default_expiration_hours": 24,
  "max_expiration_hours": 168,
  "chunked_upload_enabled": true,
  "chunked_upload_threshold": 104857600,
  "chunk_size": 10485760,
  "require_auth_for_upload": false,
  "malware_scan_enabled": false,
  "unscannable_uploads_rejected": false
}
```

`malware_scan_enabled` and `unscannable_uploads_rejected` reflect `FEATURE_MALWARE_SCAN` and `MALWARE_SCAN_REJECT_UNSCANNABLE` (ADR-015) — clients use them to decide whether to show scan-related upload messaging and whether to offer end-to-end encryption at all.

**Use Case**: Frontend configuration, dynamic UI updates

---

## Error Responses

All endpoints return consistent error format:

```json
{
  "error": "Human-readable error message",
  "code": "ERROR_CODE"
}
```

### Common HTTP Status Codes

- **200 OK**: Request successful
- **201 Created**: Resource created (uploads)
- **202 Accepted**: Request accepted for async processing
- **206 Partial Content**: Range request successful
- **400 Bad Request**: Invalid request parameters
- **401 Unauthorized**: Authentication required or failed
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource doesn't exist
- **408 Request Timeout**: An upload body stalled (nothing received for 60 seconds, or under 4 KiB/s on average) - `UPLOAD_TIMEOUT`; retry the upload or chunk
- **410 Gone**: Resource expired or limit reached
- **413 Payload Too Large**: File exceeds size limit
- **416 Range Not Satisfiable**: `Range` header was syntactically valid but describes bytes the resource doesn't have (a malformed or multi-range `Range` header is not an error — it's ignored and the full resource is returned instead)
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error
- **503 Service Unavailable**: Service degraded or unavailable
- **507 Insufficient Storage**: Disk full or quota exceeded

### Common Error Codes

- `invalid_request`: Malformed request
- `missing_file`: No file provided in upload
- `file_too_large`: Exceeds MAX_FILE_SIZE
- `invalid_claim_code`: Claim code doesn't exist or expired
- `download_limit_reached`: Max downloads exceeded
- `password_required`: File requires password
- `incorrect_password`: Wrong password provided
- `quota_exceeded`: Storage quota full
- `disk_full`: Insufficient disk space
- `rate_limit_exceeded`: Too many requests from IP
- `auth_required`: Authentication required
- `permission_denied`: Insufficient privileges
- `extension_blocked`: File type not allowed
- `MALWARE_DETECTED`: Upload scanned and rejected as infected (ADR-015; not retryable)
- `UNSCANNABLE_UPLOAD`: Upload cannot be scanned (E2E encrypted or too large) and this server requires scannable uploads
- `SCAN_UNAVAILABLE`: Malware scanner unreachable/timed out; retryable after the `Retry-After` delay
- `FILE_QUARANTINED`: Download blocked — the file was found infected
- `SCAN_PENDING`: Download blocked — the file's scan hasn't completed yet; retryable after the `Retry-After` delay
- `SCAN_FAILED`: Download blocked — the file's scan errored and it could not be verified

---

## Rate Limiting

SafeShare implements IP-based rate limiting:

- **Uploads**: Configurable (default: 10 per hour per IP). Applies to `/api/upload` and `/api/upload/init`
- **Chunk uploads**: 10x the upload limit (`/api/upload/chunk/...` and `/api/upload/complete/...`, each counted separately per IP)
- **Upload status**: 600x the upload limit, never under 6,000 per hour (`/api/upload/status/...`)
- **Downloads**: Configurable (default: 50 per hour per IP)
- **Admin Login**: 5 attempts per 15 minutes per IP
- **User Login**: 5 attempts per 15 minutes per IP

Rate limits can be adjusted via admin dashboard or environment variables.

---

## HTTP/2 Support

SafeShare supports HTTP/2 for improved performance:

- **HTTP/2 over TLS**: Automatic via ALPN (when HTTPS enabled)
- **h2c (cleartext)**: Enabled for development/testing
- **Max Concurrent Streams**: 250 (optimized for chunked uploads)

Clients should use HTTP/2 for best performance with chunked uploads.

---

## CORS

SafeShare does not include CORS headers by default. If you need cross-origin access, configure your reverse proxy (nginx, Traefik, etc.) to add appropriate CORS headers.

---

## Webhooks

SafeShare supports webhook notifications for file lifecycle events. Configure webhooks via the admin dashboard to receive real-time notifications when files are uploaded, downloaded, deleted, or expired.

### List Webhook Configurations

Retrieve all configured webhooks.

**Endpoint**: `GET /admin/api/webhooks`

**Authentication**: Required (admin session)

**Response** (200 OK):
```json
[
  {
    "id": 1,
    "url": "https://your-server.com/webhook",
    "secret": "••••••••••••••••",
    "service_token": "",
    "enabled": true,
    "events": ["file.uploaded", "file.downloaded", "file.deleted", "file.expired"],
    "format": "safeshare",
    "max_retries": 5,
    "timeout_seconds": 30,
    "created_at": "2025-11-20T10:00:00Z",
    "updated_at": "2025-11-20T10:00:00Z"
  }
]
```

**Note**: Secrets and service tokens are masked (`••••••••`) in list responses for security.

---

### Create Webhook Configuration

Create a new webhook endpoint.

**Endpoint**: `POST /admin/api/webhooks`

**Authentication**: Required (admin session + CSRF token)

**Request Body** (JSON):
```json
{
  "url": "https://your-server.com/webhook",
  "secret": "your-webhook-secret-key",
  "service_token": "optional-gotify-or-ntfy-token",
  "enabled": true,
  "events": ["file.uploaded", "file.downloaded", "file.deleted", "file.expired"],
  "format": "safeshare",
  "max_retries": 5,
  "timeout_seconds": 30
}
```

**Parameters**:
- `url` (required): Webhook endpoint URL (HTTP/HTTPS only)
- `secret` (required): Secret key for HMAC signature verification
- `service_token` (optional): Authentication token for Gotify/ntfy services
- `enabled` (required): Enable/disable webhook
- `events` (required): Array of event types to subscribe to
- `format` (optional): Payload format (default: `safeshare`)
- `max_retries` (optional): Max retry attempts (default: 5)
- `timeout_seconds` (optional): Request timeout (default: 30)

**Supported Event Types**:
- `file.uploaded` - File successfully uploaded
- `file.downloaded` - File downloaded by user. For files with `max_downloads` set, this fires once the download is fully complete (all bytes delivered, possibly across several resumed requests) — the download can already have been counted toward `max_downloads` earlier, so `file.expired` may fire before `file.downloaded` for the same download.
- `file.deleted` - File deleted by user or admin
- `file.expired` - File expired (time-based or download limit)

**Supported Formats**:
- `safeshare` (default) - SafeShare JSON format
- `gotify` - Gotify notification format
- `ntfy` - ntfy.sh notification format
- `discord` - Discord webhook format

**Response** (201 Created):
```json
{
  "id": 1,
  "url": "https://your-server.com/webhook",
  "secret": "your-webhook-secret-key",
  "service_token": "optional-token",
  "enabled": true,
  "events": ["file.uploaded", "file.downloaded", "file.deleted", "file.expired"],
  "format": "safeshare",
  "max_retries": 5,
  "timeout_seconds": 30,
  "created_at": "2025-11-20T10:00:00Z",
  "updated_at": "2025-11-20T10:00:00Z"
}
```

**Error Responses**:
- 400 Bad Request: Invalid URL, missing required fields, or invalid format
- 403 Forbidden: CSRF token validation failed

---

### Update Webhook Configuration

Update an existing webhook endpoint.

**Endpoint**: `PUT /admin/api/webhooks/update?id=:id`

**Authentication**: Required (admin session + CSRF token)

**Request Body** (JSON):
```json
{
  "url": "https://updated-server.com/webhook",
  "secret": "updated-secret",
  "service_token": "••••••••••••••••",
  "enabled": false,
  "events": ["file.uploaded"],
  "format": "gotify",
  "max_retries": 3,
  "timeout_seconds": 20
}
```

**Note**: To preserve existing secret or service_token without changing it, send the masked value (`••••••••••••••••`) received from the GET endpoint. SafeShare will automatically preserve the existing value.

**Response**: 200 OK (same as create response)

**Error Responses**:
- 400 Bad Request: Invalid webhook ID or parameters
- 404 Not Found: Webhook doesn't exist

---

### Delete Webhook Configuration

Delete a webhook endpoint.

**Endpoint**: `DELETE /admin/api/webhooks/delete?id=:id`

**Authentication**: Required (admin session + CSRF token)

**Response** (200 OK):
```json
{
  "message": "Webhook configuration deleted successfully"
}
```

**Error Responses**:
- 404 Not Found: Webhook doesn't exist

---

### Test Webhook

Send a test event to verify webhook configuration.

**Endpoint**: `POST /admin/api/webhooks/test?id=:id`

**Authentication**: Required (admin session + CSRF token)

**Response** (200 OK - Success):
```json
{
  "success": true,
  "response_code": 200,
  "response_body": "OK"
}
```

**Response** (200 OK - Failure):
```json
{
  "success": false,
  "response_code": 500,
  "response_body": "Internal Server Error",
  "error": "connection timeout"
}
```

**Test Event Payload**:
The test sends a `file.uploaded` event with dummy data:
```json
{
  "event": "file.uploaded",
  "timestamp": "2025-11-20T10:00:00Z",
  "file": {
    "claim_code": "TEST123",
    "filename": "test-file.txt",
    "size": 1024,
    "mime_type": "text/plain",
    "expires_at": "2025-11-21T10:00:00Z"
  }
}
```

---

### List Webhook Deliveries

Retrieve webhook delivery history with pagination.

**Endpoint**: `GET /admin/api/webhook-deliveries`

**Authentication**: Required (admin session)

**Query Parameters**:
- `limit` (optional): Results per page (default: 50, max: 1000)
- `offset` (optional): Pagination offset (default: 0)

**Response** (200 OK):
```json
[
  {
    "id": 1,
    "webhook_config_id": 1,
    "event_type": "file.uploaded",
    "payload": "{...}",
    "attempt_count": 1,
    "status": "success",
    "response_code": 200,
    "response_body": "OK",
    "error_message": null,
    "created_at": "2025-11-20T10:00:00Z",
    "completed_at": "2025-11-20T10:00:01Z",
    "next_retry_at": null
  }
]
```

**Status Values**:
- `pending` - Queued for delivery
- `success` - Delivered successfully (HTTP 2xx)
- `failed` - Failed after max retries
- `retrying` - Scheduled for retry

---

### Get Webhook Delivery Details

Retrieve details of a specific webhook delivery.

**Endpoint**: `GET /admin/api/webhook-deliveries/detail?id=:id`

**Authentication**: Required (admin session)

**Response** (200 OK):
```json
{
  "id": 1,
  "webhook_config_id": 1,
  "event_type": "file.uploaded",
  "payload": "{\"event\":\"file.uploaded\",\"timestamp\":\"2025-11-20T10:00:00Z\",\"file\":{...}}",
  "attempt_count": 3,
  "status": "retrying",
  "response_code": 503,
  "response_body": "Service Unavailable",
  "error_message": "connection timeout",
  "created_at": "2025-11-20T10:00:00Z",
  "completed_at": null,
  "next_retry_at": "2025-11-20T10:05:00Z"
}
```

---

### Webhook Payload Formats

#### SafeShare Format (Default)

```json
{
  "event": "file.uploaded",
  "timestamp": "2025-11-20T10:00:00Z",
  "file": {
    "id": 123,
    "claim_code": "Xy9kLm8pQz4vDwE",
    "filename": "document.pdf",
    "size": 1048576,
    "mime_type": "application/pdf",
    "expires_at": "2025-11-22T10:00:00Z"
  }
}
```

**HMAC Signatures**: Each delivery includes:
- `X-SafeShare-Signature-V2`: SHA-256 HMAC of `<timestamp>.<payload>` (recommended — replay-resistant)
- `X-SafeShare-Timestamp`: Unix timestamp (seconds) when the delivery was signed
- `X-SafeShare-Signature`: legacy SHA-256 HMAC of the payload only (kept for backward compatibility)
- `X-SafeShare-Signature-Algorithm`: `sha256` (applies to both signatures — both are HMAC-SHA256; they differ only in the signed message)

#### Gotify Format

```json
{
  "title": "File Uploaded",
  "message": "document.pdf (1.00 MB)",
  "priority": 5,
  "extras": {
    "client::display": {
      "contentType": "text/markdown"
    },
    "safeshare": {
      "event": "file.uploaded",
      "claim_code": "Xy9kLm8pQz4vDwE",
      "filename": "document.pdf",
      "size": 1048576
    }
  }
}
```

**Authentication**: Uses `service_token` in URL query parameter (`?token=xxx`) or `X-Gotify-Key` header.

#### ntfy Format

POST body (plain text):
```
File Uploaded: document.pdf (1.00 MB)
```

Headers:
- `Title: File Uploaded`
- `Tags: file,upload`
- `Priority: 3`
- `Authorization: Bearer <service_token>` (if service_token configured)

#### Discord Format

```json
{
  "content": null,
  "embeds": [
    {
      "title": "File Uploaded",
      "description": "**Filename:** document.pdf\n**Size:** 1.00 MB\n**Claim Code:** `Xy9kLm8pQz4vDwE`",
      "color": 5814783,
      "timestamp": "2025-11-20T10:00:00Z"
    }
  ]
}
```

---

### Webhook Security

**HMAC Signature Verification** (SafeShare format):

Verify the timestamped signature (`X-SafeShare-Signature-V2`) and reject
deliveries whose timestamp is outside a tolerance window (5 minutes
recommended). This prevents an attacker who captured a delivery from
replaying it later.

```python
import hmac
import hashlib
import time

TOLERANCE_SECONDS = 300  # 5 minutes

def verify_webhook(secret, payload, timestamp, signature):
    # Reject replayed deliveries outside the tolerance window
    if abs(time.time() - int(timestamp)) > TOLERANCE_SECONDS:
        return False
    expected = hmac.new(
        secret.encode('utf-8'),
        f"{timestamp}.{payload}".encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

# Example usage
secret = "your-webhook-secret-key"
payload = request.body  # Raw JSON string, exactly as received
timestamp = request.headers.get('X-SafeShare-Timestamp')
signature = request.headers.get('X-SafeShare-Signature-V2')

if timestamp and signature and verify_webhook(secret, payload, timestamp, signature):
    # Process webhook
    pass
else:
    # Reject webhook
    return 403
```

**Legacy verification**: older receivers that verify `X-SafeShare-Signature`
(HMAC of the payload only, no timestamp) continue to work, but should migrate
to the V2 signature since the legacy scheme does not protect against replay.

**Retry Logic**:
- Exponential backoff: 1s, 2s, 4s, 8s, 16s
- Max retries: Configurable (default: 5)
- HTTP 5xx and network errors trigger retries
- HTTP 4xx errors do not trigger retries (client error)

**Timeout**:
- Configurable per webhook (default: 30 seconds)
- Prevents slow webhook endpoints from blocking workers

---

---

## SDK / Client Libraries

Official SDKs are planned for Python, TypeScript/JavaScript, and Go. See the [SDK Integration Roadmap](SDK_INTEGRATION_ROADMAP.md) for progress.

In the meantime, the API follows REST principles and can be used with any HTTP client library.

**Recommended Libraries**:
- JavaScript/Node.js: `axios`, `fetch`
- Python: `requests`, `httpx`
- Go: `net/http`
- Java: `OkHttp`, `HttpClient`
- Rust: `reqwest`

---

## API Versioning

SafeShare uses semantic versioning (MAJOR.MINOR.PATCH). The API is currently unversioned (v1 implicit). Breaking changes will be communicated via major version bumps.

Current API compatibility: SafeShare 2.0.0+

---

## Further Documentation

- [CHUNKED_UPLOAD.md](CHUNKED_UPLOAD.md) - Detailed chunked upload implementation
- [SECURITY.md](SECURITY.md) - Security features and best practices
- [PROMETHEUS.md](PROMETHEUS.md) - Monitoring and metrics
- [HTTP_RANGE_SUPPORT.md](HTTP_RANGE_SUPPORT.md) - Resumable downloads

---

**Last Updated**: 2025-11-27
**Version**: 2.8.4
