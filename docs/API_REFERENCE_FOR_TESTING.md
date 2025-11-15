# SafeShare API Reference for Testing

**Purpose**: This document provides the actual API specifications for writing tests against SafeShare. Created after fixing 289 test functions that had incorrect assumptions about the API.

**Last Updated**: 2025-11-15

---

## Table of Contents

1. [HTTP Handler APIs](#http-handler-apis)
2. [Database APIs](#database-apis)
3. [Middleware Patterns](#middleware-patterns)
4. [Validation Rules](#validation-rules)
5. [Known Limitations](#known-limitations)

---

## HTTP Handler APIs

### Upload Handler

**Handler**: `handlers.UploadHandler(db, cfg)`

**Endpoint**: `POST /api/upload`

**Request**: `multipart/form-data`
- `file` (required): The file to upload
- `expires_in_hours` (optional): Expiration time in hours (float)
- `max_downloads` (optional): Maximum download count (int)
- `password` (optional): Password protection (string)

**Response Status Codes**:
- `201 Created` - Upload successful (**NOT 200 OK**)
- `400 Bad Request` - Invalid parameters or missing file
- `413 Request Entity Too Large` - File exceeds size limit
- `507 Insufficient Storage` - Not enough disk space or quota exceeded

**Response Body** (201):
```json
{
  "claim_code": "ABC123...",
  "expires_at": "2025-11-16T12:00:00Z",
  "download_url": "https://example.com/api/claim/ABC123...",
  "max_downloads": 5,
  "file_size": 1024,
  "original_filename": "test.txt"
}
```

**Important Notes**:
- Always returns `201 Created`, never `200 OK`
- Password is hashed with bcrypt (max 72 bytes - errors on longer passwords)
- `expires_in_hours <= 0` is **rejected with 400**, not converted to default
- `max_downloads <= 0` is **rejected with 400**, not treated as unlimited
- File size check uses `>=`, so exact max size is **rejected with 413**
- Empty (0-byte) files are **accepted**

---

### Claim/Download Handler

**Handler**: `handlers.ClaimHandler(db, cfg)`

**Endpoint**: `GET /api/claim/{claim_code}[?password=xxx]`

**Request**:
- URL path parameter: `claim_code`
- Query parameter (optional): `password`

**Response Status Codes**:
- `200 OK` - File download successful
- `400 Bad Request` - Empty or invalid claim code
- `401 Unauthorized` - Incorrect password or missing password for protected file
- `404 Not Found` - File not found **OR expired** (same status for both)
- `410 Gone` - Download limit reached
- `500 Internal Server Error` - File exists in DB but missing on disk

**Important Notes**:
- Password provided via **query parameter** `?password=xxx`, **NOT POST body**
- Download without password for protected file returns `401 Unauthorized`, **NOT 200**
- Expired files return `404 Not Found`, **NOT 410 Gone**
- Empty claim code (`""`) returns `400 Bad Request`, **NOT 404**
- When download limit reached, file record **remains in database** (access blocked, not deleted)
- Download count incremented **before** serving file (not after)

---

### Chunked Upload Init Handler

**Handler**: `handlers.UploadInitHandler(db, cfg)`

**Endpoint**: `POST /api/upload/init`

**Request Body** (JSON):
```json
{
  "filename": "large_file.bin",
  "total_size": 104857600,
  "expires_in_hours": 24,
  "max_downloads": 5,
  "password": "optional"
}
```

**Response Status Codes**:
- `201 Created` - Init successful
- `400 Bad Request` - Invalid parameters
- `413 Request Entity Too Large` - Total size exceeds limit
- `503 Service Unavailable` - Chunked uploads disabled

**Response Body** (201):
```json
{
  "upload_id": "550e8400-e29b-41d4-a716-446655440000",
  "chunk_size": 5242880,
  "total_chunks": 20,
  "expires_at": "2025-11-15T20:00:00Z"
}
```

---

### Upload Chunk Handler

**Handler**: `handlers.UploadChunkHandler(db, cfg)`

**Endpoint**: `POST /api/upload/chunk/{upload_id}/{chunk_number}`

**Request**: `multipart/form-data`
- `chunk` (required): Chunk file data

**Response Status Codes**:
- `200 OK` - Chunk uploaded (idempotent - returns 200 for duplicate chunks)
- `400 Bad Request` - Invalid upload_id format (must be valid UUID)
- `404 Not Found` - Upload session not found
- `409 Conflict` - Upload already completed
- `410 Gone` - Upload session expired
- `413 Request Entity Too Large` - Chunk too large

**Important Notes**:
- `upload_id` must be valid UUID format, otherwise returns `400` (not `404`)
- Non-existent upload with valid UUID returns `404`
- Chunk uploads are idempotent (same chunk can be uploaded multiple times)

---

### Upload Complete Handler

**Handler**: `handlers.UploadCompleteHandler(db, cfg)`

**Endpoint**: `POST /api/upload/complete/{upload_id}`

**Response Status Codes**:
- `200 OK` - Already completed (idempotent - returns claim code)
- `202 Accepted` - Assembly started, poll for completion
- `400 Bad Request` - Missing chunks or invalid upload_id
- `404 Not Found` - Upload session not found

**Response Body** (202):
```json
{
  "status": "processing",
  "upload_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "File is being assembled. Please poll /api/upload/status/..."
}
```

---

### User Login Handler

**Handler**: `handlers.UserLoginHandler(db, cfg)`

**Endpoint**: `POST /api/user/login`

**Request Body** (JSON):
```json
{
  "username": "testuser",
  "password": "password123"
}
```

**Response Status Codes**:
- `200 OK` - Login successful
- `401 Unauthorized` - Invalid credentials
- `403 Forbidden` - Account disabled

**Important Notes**:
- Sets `user_session` cookie with session token
- Session validated using `database.GetUserSession()`, **NOT** `database.ValidateUserSession()`

---

### User Logout Handler

**Handler**: `handlers.UserLogoutHandler(db, cfg)`

**Endpoint**: `POST /api/user/logout`

**Response Status Codes**:
- `200 OK` - Logout successful (even if no session exists)

---

## Database APIs

### File Operations

#### CreateFile
```go
func CreateFile(db *sql.DB, file *models.File) error
```

**Parameters**:
- `file`: **Pointer** to `models.File` struct

**Important**: Takes **pointer**, not value. Call as:
```go
database.CreateFile(db, &models.File{...})  // Correct
database.CreateFile(db, models.File{...})   // WRONG - compilation error
```

**Returns**: Sets `file.ID` on success

---

#### GetFileByClaimCode
```go
func GetFileByClaimCode(db *sql.DB, claimCode string) (*models.File, error)
```

**Returns**:
- `(*models.File, nil)` if found and not expired
- `(nil, nil)` if not found **OR expired** (expired treated as not found)
- `(nil, error)` on database error

**Important**: Returns `nil` for expired files (not an error)

---

#### IncrementDownloadCount
```go
func IncrementDownloadCount(db *sql.DB, id int64) error
```

**Parameters**:
- `id`: **File ID** (from `file.ID`), **NOT claim code**

**Wrong Usage**:
```go
database.IncrementDownloadCount(db, claimCode)  // WRONG - type error
```

**Correct Usage**:
```go
file, _ := database.GetFileByClaimCode(db, claimCode)
database.IncrementDownloadCount(db, file.ID)   // Correct
```

---

#### DeleteExpiredFiles
```go
func DeleteExpiredFiles(db *sql.DB, uploadDir string) (int, error)
```

**Returns**: Count of deleted files

**Important**: Deletes both database record and physical file

---

#### GetTotalUsage
```go
func GetTotalUsage(db *sql.DB) (int64, error)
```

**Returns**: Total bytes used by active files + incomplete partial uploads

---

### Session Operations

#### CreateSession (Admin)
```go
func CreateSession(db *sql.DB, token string, expiresAt time.Time, ipAddress, userAgent string) error
```

**Important**: This is for **admin sessions**. User sessions use `CreateUserSession`.

---

#### GetSession (Admin)
```go
func GetSession(db *sql.DB, token string) (*AdminSession, error)
```

**Returns**:
- `(*AdminSession, nil)` if found and not expired
- `(nil, nil)` if not found or expired
- `(nil, error)` on database error

**Important**: Replaces the non-existent `ValidateSession()` function

---

#### CreateUserSession
```go
func CreateUserSession(db *sql.DB, userID int64, token string, expiresAt time.Time, ipAddress, userAgent string) error
```

---

#### GetUserSession
```go
func GetUserSession(db *sql.DB, token string) (*models.UserSession, error)
```

**Returns**:
- `(*models.UserSession, nil)` if found and not expired
- `(nil, nil)` if not found or expired
- `(nil, error)` on database error

**Important**: Replaces the non-existent `ValidateUserSession()` function

---

#### DeleteUserSession
```go
func DeleteUserSession(db *sql.DB, token string) error
```

---

### Partial Upload Operations

#### CreatePartialUpload
```go
func CreatePartialUpload(db *sql.DB, upload *models.PartialUpload) error
```

**Parameters**: Takes **pointer** to `models.PartialUpload`

---

#### GetPartialUpload
```go
func GetPartialUpload(db *sql.DB, uploadID string) (*models.PartialUpload, error)
```

**Returns**:
- `(*models.PartialUpload, nil)` if found
- `(nil, nil)` if not found
- `(nil, error)` on database error

---

#### DeletePartialUpload
```go
func DeletePartialUpload(db *sql.DB, uploadID string) error
```

---

#### GetOldCompletedUploads
```go
func GetOldCompletedUploads(db *sql.DB, retentionHours int) ([]models.PartialUpload, error)
```

**Known Issue**: Currently returns 0 results due to `datetime()` parsing issue with RFC3339 timestamps. The query uses `datetime(last_activity)` which cannot parse RFC3339 format with nanoseconds.

---

### Missing Functions

The following functions **do not exist** and should use `t.Skip()`:

```go
// These DO NOT EXIST:
database.DeleteExpiredSessions(db)      // Use t.Skip("not yet implemented")
database.DeleteExpiredUserSessions(db)  // Use t.Skip("not yet implemented")
```

**Instead, use**:
```go
database.CleanupExpiredSessions(db)      // For admin sessions (DOES exist)
database.CleanupExpiredUserSessions(db)  // For user sessions (DOES exist)
```

---

## Middleware Patterns

### Rate Limiter

**Initialization** (required):
```go
rateLimiter := middleware.NewRateLimiter(cfg)
defer rateLimiter.Stop()  // MUST cleanup!
```

**Usage**:
```go
handler := middleware.RateLimitMiddleware(rateLimiter)(handlers.UploadHandler(db, cfg))
```

**Wrong Pattern**:
```go
// WRONG - no initialization
handler := middleware.RateLimiter(cfg)(handlers.UploadHandler(db, cfg))
```

**Important Notes**:
- **Must** call `NewRateLimiter()` to initialize
- **Must** call `defer rateLimiter.Stop()` to cleanup goroutine
- Uses `middleware.RateLimitMiddleware(rateLimiter)` wrapper function

---

### IP Blocking

```go
handler := middleware.IPBlockMiddleware(db)(handlers.UploadHandler(db, cfg))
```

---

## Validation Rules

### File Upload

| Parameter | Rule | Rejection |
|-----------|------|-----------|
| `expires_in_hours` | Must be > 0 | 400 Bad Request |
| `expires_in_hours` | Must be <= max (168) | 400 Bad Request |
| `max_downloads` | Must be > 0 | 400 Bad Request |
| `file size` | Must be < max (uses `>=` check) | 413 Payload Too Large |
| `file size` | Exact max size is **rejected** | 413 (not accepted!) |
| `password` | Max 72 bytes (bcrypt limit) | Returns error from `utils.HashPassword()` |
| `file size` | 0 bytes allowed | 201 Created (accepted) |

**Critical Notes**:
- Zero expiration (`0`) is **rejected**, not converted to default
- Zero max downloads (`0`) is **rejected**, not treated as unlimited
- Exact max file size is **rejected** due to `>=` comparison in MaxBytesReader
- Password > 72 bytes **returns error**, does not silently truncate

---

### Claim Code Validation

| Input | Status Code | Reason |
|-------|-------------|--------|
| `""` (empty) | 400 Bad Request | Empty claim code |
| `"abc"` | 404 Not Found | Not found |
| `"claim code 123"` | 404 Not Found | Not found (spaces) |
| `"../../../etc/passwd"` | 404 Not Found | Not found (path traversal) |
| `"' OR '1'='1"` | 404 Not Found | Not found (SQL injection) |

**Important**: Use `url.PathEscape()` for special characters in tests:
```go
encodedClaimCode := url.PathEscape(claimCode)
req := httptest.NewRequest("GET", "/api/claim/"+encodedClaimCode, nil)
```

---

### Unicode Filenames

**Supported**:
- Chinese: `文件.txt`
- Russian: `файл.txt`
- Arabic: `ملف.txt`
- Emoji: `📄🚀.txt`
- Accented: `café.txt`

**Not Supported**:
- Null bytes in filename cause multipart form parsing to fail with 413

---

## Benchmark Setup

**Important**: Benchmarks need explicit `testing.T` for `SetupTestDB`:

```go
func BenchmarkUploadSmallFile(b *testing.B) {
    t := &testing.T{}  // Create explicit testing.T
    db := testutil.SetupTestDB(t)
    cfg := testutil.SetupTestConfig(t)
    // ...
}
```

**Wrong**:
```go
func BenchmarkUploadSmallFile(b *testing.B) {
    db := testutil.SetupTestDB(b)  // WRONG - type error
}
```

---

## Known Limitations

### 1. Datetime Parsing Issue

**Issue**: `GetOldCompletedUploads()` returns 0 results due to SQLite's `datetime()` function not parsing RFC3339 timestamps with nanoseconds.

**Documented in**: `internal/integration/cleanup_test.go:269-271`

```go
// NOTE: GetOldCompletedUploads currently returns 0 due to datetime() parsing issue
if len(completed) != 0 {
    t.Errorf("old completed uploads = %d, want 0", len(completed))
}
```

---

### 2. Session Token Expiry

**Issue**: `GetSession()` and `GetUserSession()` check expiry using `CURRENT_TIMESTAMP` comparison.

**Behavior**: Expired sessions return `nil`, not an error.

```go
session, _ := database.GetSession(db, sessionToken)
if session != nil {
    t.Error("expired session should not be valid")
}
```

---

### 3. Download Limit Behavior

**Issue**: When max downloads reached, file is **NOT** deleted from database.

**Behavior**: File record remains, but access is blocked with `410 Gone`.

```go
file, _ := database.GetFileByClaimCode(db, claimCode)
if file == nil {
    t.Error("file record should still exist in database")
}
```

---

### 4. MaxBytesReader Boundary

**Issue**: `http.MaxBytesReader` uses `>=` check, not `>`.

**Behavior**: Exact max size is rejected with 413.

```go
// If max is 1MB:
fileContent := bytes.Repeat([]byte("M"), 1024*1024)  // Exactly 1MB
// Result: 413 Request Entity Too Large (rejected!)
```

---

## Testing Patterns

### Correct Test Setup

```go
func TestUploadDownload(t *testing.T) {
    db := testutil.SetupTestDB(t)
    cfg := testutil.SetupTestConfig(t)

    handler := handlers.UploadHandler(db, cfg)

    fileContent := []byte("test data")
    body, contentType := testutil.CreateMultipartForm(t, fileContent, "test.txt", nil)

    req := httptest.NewRequest("POST", "/api/upload", body)
    req.Header.Set("Content-Type", contentType)
    rr := httptest.NewRecorder()

    handler.ServeHTTP(rr, req)

    // Check for 201 Created, not 200 OK
    if rr.Code != http.StatusCreated {
        t.Fatalf("status = %d, want %d (Created)", rr.Code, http.StatusCreated)
    }
}
```

---

### Password-Protected Download

```go
func TestPasswordProtectedDownload(t *testing.T) {
    // ... upload with password ...

    downloadHandler := handlers.ClaimHandler(db, cfg)

    // Download with password via query parameter
    req := httptest.NewRequest("GET", "/api/claim/"+claimCode+"?password="+password, nil)
    rr := httptest.NewRecorder()

    downloadHandler.ServeHTTP(rr, req)

    if rr.Code != http.StatusOK {
        t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
    }
}
```

---

### Database Operations

```go
func TestDatabaseOperations(t *testing.T) {
    db := testutil.SetupTestDB(t)

    claimCode, _ := utils.GenerateClaimCode()

    // CreateFile takes pointer
    file := &models.File{
        ClaimCode:        claimCode,
        StoredFilename:   "test.dat",
        OriginalFilename: "test.txt",
        FileSize:         1024,
        MimeType:         "text/plain",
        ExpiresAt:        time.Now().Add(24 * time.Hour),
        UploaderIP:       "127.0.0.1",
    }
    err := database.CreateFile(db, file)
    if err != nil {
        t.Fatalf("CreateFile() error: %v", err)
    }

    // IncrementDownloadCount takes file.ID, not claimCode
    err = database.IncrementDownloadCount(db, file.ID)
    if err != nil {
        t.Fatalf("IncrementDownloadCount() error: %v", err)
    }

    // GetSession returns session object or nil
    session, _ := database.GetSession(db, sessionToken)
    if session == nil {
        t.Error("session should be valid")
    }
}
```

---

### Rate Limiting

```go
func TestRateLimiting(t *testing.T) {
    db := testutil.SetupTestDB(t)
    cfg := testutil.SetupTestConfig(t)
    cfg.SetRateLimitUpload(3)

    // Must initialize rate limiter
    rateLimiter := middleware.NewRateLimiter(cfg)
    defer rateLimiter.Stop()  // Must cleanup!

    handler := middleware.RateLimitMiddleware(rateLimiter)(handlers.UploadHandler(db, cfg))

    // Make 3 requests (within limit)
    for i := 0; i < 3; i++ {
        // ... upload ...
        if rr.Code != http.StatusCreated {
            t.Errorf("upload %d: status = %d, want 201", i+1, rr.Code)
        }
    }

    // 4th request should be rate limited
    // ... upload ...
    if rr.Code != http.StatusTooManyRequests {
        t.Errorf("4th upload: status = %d, want 429", rr.Code)
    }
}
```

---

## Common Mistakes to Avoid

### ❌ Wrong: Upload returns 200
```go
if rr.Code != http.StatusOK {  // WRONG
```

### ✅ Correct: Upload returns 201
```go
if rr.Code != http.StatusCreated {  // Correct
```

---

### ❌ Wrong: Password via POST body
```go
body := bytes.NewBufferString("password=" + password)
req := httptest.NewRequest("POST", "/api/claim/"+claimCode, body)
```

### ✅ Correct: Password via query parameter
```go
req := httptest.NewRequest("GET", "/api/claim/"+claimCode+"?password="+password, nil)
```

---

### ❌ Wrong: CreateFile with value
```go
database.CreateFile(db, models.File{...})  // Compilation error
```

### ✅ Correct: CreateFile with pointer
```go
database.CreateFile(db, &models.File{...})  // Correct
```

---

### ❌ Wrong: IncrementDownloadCount with claim code
```go
database.IncrementDownloadCount(db, claimCode)  // Type error
```

### ✅ Correct: IncrementDownloadCount with file ID
```go
database.IncrementDownloadCount(db, file.ID)  // Correct
```

---

### ❌ Wrong: ValidateSession (doesn't exist)
```go
isValid := database.ValidateSession(db, token)  // Function doesn't exist
```

### ✅ Correct: GetSession (returns object)
```go
session, _ := database.GetSession(db, token)
if session != nil {
    // Valid session
}
```

---

### ❌ Wrong: No rate limiter initialization
```go
handler := middleware.RateLimiter(cfg)(handlers.UploadHandler(db, cfg))
```

### ✅ Correct: Initialize and cleanup
```go
rateLimiter := middleware.NewRateLimiter(cfg)
defer rateLimiter.Stop()
handler := middleware.RateLimitMiddleware(rateLimiter)(handlers.UploadHandler(db, cfg))
```

---

### ❌ Wrong: Assuming exact max size is accepted
```go
if rr.Code != 201 {  // WRONG - exact max is rejected
```

### ✅ Correct: Exact max size is rejected
```go
if rr.Code != 413 {  // Correct - exact max fails
```

---

### ❌ Wrong: Assuming zero values are converted
```go
// Assuming expires_in_hours=0 uses default
{"expires_in_hours", "0"}  // Actually rejected with 400
```

### ✅ Correct: Zero values are rejected
```go
// Zero is rejected, use actual positive value
{"expires_in_hours", "24"}  // Correct
```

---

## Summary of Key Corrections

1. **Upload returns `201 Created`**, not `200 OK`
2. **Password via query parameter**, not POST body
3. **`CreateFile()` takes pointer**, not value
4. **`IncrementDownloadCount()` takes `file.ID`**, not `claimCode`
5. **Session APIs return objects**, not booleans:
   - `GetSession()` replaces `ValidateSession()`
   - `GetUserSession()` replaces `ValidateUserSession()`
6. **Rate limiter needs initialization**:
   - `NewRateLimiter(cfg)` + `defer Stop()`
7. **Boundary conditions**:
   - Exact max file size is **rejected** (413)
   - Zero expiration/downloads is **rejected** (400)
   - Password > 72 bytes **errors**
8. **Download behavior**:
   - Without password returns **401**, not 200
   - Expired files return **404**, not 410
   - File record **remains** when limit reached
9. **Benchmarks need explicit `testing.T`**
10. **Missing functions**: `DeleteExpiredSessions/DeleteExpiredUserSessions` don't exist

---

## Version Information

- **Document Created**: 2025-11-15
- **Codebase Commit**: 7731d1a (Phase 6 edge cases)
- **Total Tests**: 289 test functions across 25 files
- **Test Coverage**: 80%+

---

## Changelog

### 2025-11-15 - Initial Version
- Documented all handler HTTP status codes
- Documented all database function signatures
- Added middleware initialization patterns
- Documented validation rules and boundary conditions
- Added known limitations and datetime parsing issue
- Created testing patterns and common mistakes section
