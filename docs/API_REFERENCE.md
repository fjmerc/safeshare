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
- 507 Insufficient Storage: Disk full or quota exceeded

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
- `processing`: File assembly in progress
- `completed`: Upload complete, claim code available
- `failed`: Upload failed (check error_message field)

---

### Download File

Download a file using its claim code.

**Endpoint**: `GET /api/claim/:code`

**Authentication**: None required

**Query Parameters**:
- `password` (optional): Required if file is password-protected

**Example**:
```bash
# Without password
curl -O http://localhost:8080/api/claim/Xy9kLm8pQz4vDwE

# With password
curl -O "http://localhost:8080/api/claim/Xy9kLm8pQz4vDwE?password=secret123"
```

**Response** (200 OK):
- Binary file data
- Headers:
  - `Content-Type`: Original file MIME type
  - `Content-Disposition`: attachment; filename="original_name.pdf"
  - `Content-Length`: File size in bytes
  - `Accept-Ranges`: bytes (supports HTTP Range requests)

**Response** (206 Partial Content):
- Returned when Range header is present
- Headers include `Content-Range`

**Error Responses**:
- 401 Unauthorized: Password required or incorrect
- 404 Not Found: Invalid claim code or file expired
- 410 Gone: Download limit reached
- 416 Range Not Satisfiable: Invalid byte range

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
  "sha256_hash": "a3b2c1d4e5f6..."
}
```

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

Add an IP address to the blocklist.

**Endpoint**: `POST /admin/api/ip/block`

**Authentication**: Required (admin session + CSRF token)

**Request Body** (JSON):
```json
{
  "ip_address": "192.168.1.100",
  "reason": "Spam uploads"
}
```

**Response**: 200 OK

---

### Unblock IP Address

Remove an IP address from the blocklist.

**Endpoint**: `POST /admin/api/ip/unblock`

**Authentication**: Required (admin session + CSRF token)

**Request Body** (JSON):
```json
{
  "ip_address": "192.168.1.100"
}
```

**Response**: 200 OK

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
  "require_auth_for_upload": false
}
```

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
- **410 Gone**: Resource expired or limit reached
- **413 Payload Too Large**: File exceeds size limit
- **416 Range Not Satisfiable**: Invalid byte range
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

---

## Rate Limiting

SafeShare implements IP-based rate limiting:

- **Uploads**: Configurable (default: 10 per hour per IP)
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
- `file.downloaded` - File downloaded by user
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

**HMAC Signature**: Sent in `X-Webhook-Signature` header using SHA-256 HMAC of the JSON payload.

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

```python
import hmac
import hashlib

def verify_webhook(secret, payload, signature):
    expected = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

# Example usage
secret = "your-webhook-secret-key"
payload = request.body  # Raw JSON string
signature = request.headers.get('X-Webhook-Signature')

if verify_webhook(secret, payload, signature):
    # Process webhook
    pass
else:
    # Reject webhook
    return 403
```

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
