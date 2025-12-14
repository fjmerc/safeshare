# SafeShare API Versioning & Compatibility Policy

This document describes SafeShare's API versioning strategy, backward compatibility guarantees, and deprecation policies.

## Table of Contents

- [Versioning Strategy](#versioning-strategy)
- [API Stability Guarantees](#api-stability-guarantees)
- [Backward Compatibility](#backward-compatibility)
- [Breaking Changes](#breaking-changes)
- [Deprecation Policy](#deprecation-policy)
- [API Changelog](#api-changelog)
- [SDK Compatibility](#sdk-compatibility)
- [OpenAPI Specification](#openapi-specification)

---

## Versioning Strategy

SafeShare follows [Semantic Versioning 2.0.0](https://semver.org/):

```
MAJOR.MINOR.PATCH
  │     │     └── Bug fixes, security patches (no API changes)
  │     └──────── New features, backward-compatible changes
  └────────────── Breaking changes (rare)
```

### Version Examples

| Version | Type | Description |
|---------|------|-------------|
| 2.8.0 → 2.8.1 | Patch | Bug fix, no API changes |
| 2.7.0 → 2.8.0 | Minor | New webhook API, existing APIs unchanged |
| 1.x → 2.0.0 | Major | Chunked upload API added, some breaking changes |

---

## API Stability Guarantees

### Stable APIs (No Breaking Changes)

These APIs are stable and will not have breaking changes within a major version:

| Endpoint | Since | Stability |
|----------|-------|-----------|
| `POST /api/upload` | v1.0.0 | Stable |
| `GET /api/claim/:code` | v1.0.0 | Stable |
| `GET /api/claim/:code/info` | v1.0.0 | Stable |
| `GET /api/config` | v1.0.0 | Stable |
| `GET /health` | v1.0.0 | Stable |
| `POST /api/auth/login` | v1.1.0 | Stable |
| `GET /api/user/files` | v1.1.0 | Stable |

### Stable with Extensions

These APIs are stable but may receive new fields (additive changes only):

| Endpoint | Since | Notes |
|----------|-------|-------|
| `GET /health` | v1.0.0 | New metrics fields may be added |
| `GET /api/config` | v1.0.0 | New config fields may be added |
| Upload responses | v1.0.0 | New fields like `sha256_hash` added |

### Beta APIs

These APIs are newer and may change:

| Endpoint | Since | Notes |
|----------|-------|-------|
| `GET /admin/api/webhooks` | v2.8.0 | Webhook management |
| `GET /metrics` | v2.7.0 | Prometheus metrics |

---

## Backward Compatibility

### What We Guarantee

Within a major version (e.g., all 2.x releases):

1. **Existing endpoints remain available**
   - No endpoint removal without deprecation period
   - URL paths don't change

2. **Request formats are preserved**
   - Required parameters stay required
   - Parameter types don't change
   - Form field names stay the same

3. **Response structure is preserved**
   - Existing fields are not removed
   - Field types don't change
   - Error response format is consistent

4. **HTTP status codes are consistent**
   - Same errors return same status codes
   - Success responses use same codes

### What May Change (Non-Breaking)

These changes are considered **non-breaking** and may happen in minor releases:

1. **Adding new optional parameters**
   ```json
   // Before v2.7.0
   POST /api/upload
   file=@document.pdf

   // After v2.7.0 (new optional parameter)
   POST /api/upload
   file=@document.pdf
   description=Optional+description  // New, optional
   ```

2. **Adding new response fields**
   ```json
   // Before v2.7.0
   {"claim_code": "ABC123", "download_url": "..."}

   // After v2.7.0
   {"claim_code": "ABC123", "download_url": "...", "sha256_hash": "abc..."}
   ```

3. **Adding new endpoints**
   - New functionality via new URLs
   - Doesn't affect existing integrations

4. **Adding new error codes**
   - New error scenarios may return new error codes
   - Existing error codes remain the same

5. **Performance improvements**
   - Faster responses
   - More efficient processing

### Client Recommendations

To ensure compatibility across versions:

```python
# Good: Ignore unknown fields
response = client.upload("file.txt")
claim_code = response["claim_code"]  # Use known fields

# Good: Check for optional fields
sha256 = response.get("sha256_hash")  # May not exist in older versions

# Bad: Fail on unknown fields
if len(response) != 3:  # Breaks when new fields added
    raise Error("Unexpected response")
```

---

## Breaking Changes

### What Constitutes a Breaking Change

These changes require a major version bump:

1. **Removing endpoints**
2. **Removing required fields from responses**
3. **Changing field types** (e.g., string → number)
4. **Changing parameter requirements** (optional → required)
5. **Changing authentication mechanisms**
6. **Changing URL paths**
7. **Changing error response format**

### Breaking Change Process

When a breaking change is necessary:

1. **Announcement:** Documented in CHANGELOG.md at least one minor version before
2. **Deprecation period:** Minimum 3 months for stable APIs
3. **Migration guide:** Provided in [UPGRADING.md](UPGRADING.md)
4. **Major version bump:** Breaking changes only in major releases

### Historical Breaking Changes

| Version | Change | Migration |
|---------|--------|-----------|
| v2.0.0 | Chunked upload API added | Automatic (SDK handles) |
| v2.1.0 | SFSE1 encryption format | Migration tool provided |
| v2.3.0 | Reduced chunk size (64MB→10MB) | Migration tool provided |

---

## Deprecation Policy

### Deprecation Timeline

```
Announcement → 1 minor release → Deprecated (still works) → 
  → 3 months minimum → Major release (removed)
```

### Deprecation Notices

Deprecated features are marked in:

1. **API responses:** `X-Deprecated: true` header
2. **Documentation:** Marked as deprecated with alternative
3. **CHANGELOG.md:** Listed in deprecation section
4. **Server logs:** Warning when deprecated feature used

### Current Deprecations

| Feature | Deprecated In | Removal Target | Alternative |
|---------|--------------|----------------|-------------|
| None currently | - | - | - |

### Example Deprecation Response

```http
HTTP/1.1 200 OK
X-Deprecated: true
X-Deprecation-Notice: This endpoint will be removed in v3.0.0. Use /api/v2/files instead.
Content-Type: application/json

{"status": "ok", "warning": "This endpoint is deprecated"}
```

---

## API Changelog

### v2.8.0 (November 2025)

**Added:**
- `POST /api/tokens` - Create API token
- `GET /api/tokens` - List API tokens
- `DELETE /api/tokens/:id` - Revoke API token
- `GET /admin/api/webhooks` - List webhooks
- `POST /admin/api/webhooks` - Create webhook
- `PUT /admin/api/webhooks/update` - Update webhook
- `DELETE /admin/api/webhooks/delete` - Delete webhook
- `POST /admin/api/webhooks/test` - Test webhook
- `GET /admin/api/webhook-deliveries` - Delivery history
- `DELETE /admin/api/webhook-deliveries/clear` - Clear history

**Changed:**
- Upload responses include `sha256_hash` field (optional)
- Health endpoint includes more detailed status

### v2.7.0 (November 2025)

**Added:**
- `GET /metrics` - Prometheus metrics endpoint
- `GET /health/live` - Liveness probe
- `GET /health/ready` - Readiness probe

**Changed:**
- `/health` now returns intelligent status (healthy/degraded/unhealthy)
- File info includes `sha256_hash` field

### v2.6.0 (November 2025)

**Added:**
- HTTP Range request support on all download endpoints
- `Accept-Ranges: bytes` header on downloads

### v2.3.0 (November 2025)

**Added:**
- HTTP Range request support for encrypted files
- Import tool for bulk migrations

### v2.0.0 (November 2025)

**Added:**
- `POST /api/upload/init` - Initialize chunked upload
- `POST /api/upload/chunk/:id/:num` - Upload chunk
- `POST /api/upload/complete/:id` - Complete upload
- `GET /api/upload/status/:id` - Check upload status

**Changed:**
- Files ≥100MB use chunked upload automatically (configurable)

---

## SDK Compatibility

### SDK Version Matrix

| SafeShare Version | Python SDK | TypeScript SDK | Go SDK |
|-------------------|------------|----------------|--------|
| 2.8.x | 1.0.x+ | 1.0.x+ | 1.0.x+ |
| 2.7.x | 1.0.x+ | 1.0.x+ | 1.0.x+ |
| 2.6.x | 1.0.x+ | 1.0.x+ | 1.0.x+ |
| 2.0.x - 2.5.x | 1.0.x+ | 1.0.x+ | 1.0.x+ |

### SDK Compatibility Guidelines

SDKs are designed for forward compatibility:

1. **Ignore unknown fields** - SDKs won't fail on new response fields
2. **Optional new features** - New SDK features are optional
3. **Graceful degradation** - SDKs work with older servers (some features unavailable)

### Checking Server Compatibility

```python
# Python
config = client.get_config()
if config.version >= "2.8.0":
    # Use webhook features
    pass
```

```typescript
// TypeScript
const config = await client.getConfig();
if (compareVersions(config.version, "2.8.0") >= 0) {
    // Use webhook features
}
```

```go
// Go
config, _ := client.GetConfig(ctx)
if semver.Compare("v"+config.Version, "v2.8.0") >= 0 {
    // Use webhook features
}
```

---

## OpenAPI Specification

SafeShare provides an OpenAPI 3.0 specification for API documentation and client generation.

### Specification Location

```
docs/openapi.yaml
```

### Using the Specification

**Generate client code:**
```bash
# Python
openapi-generator generate -i docs/openapi.yaml -g python -o sdk/python-generated

# TypeScript
openapi-generator generate -i docs/openapi.yaml -g typescript-fetch -o sdk/ts-generated

# Go
openapi-generator generate -i docs/openapi.yaml -g go -o sdk/go-generated
```

**View in Swagger UI:**
```bash
docker run -p 8081:8080 -e SWAGGER_JSON=/spec/openapi.yaml \
  -v $(pwd)/docs:/spec swaggerapi/swagger-ui
```

### Specification Updates

The OpenAPI specification is updated with each release:
- New endpoints added
- New parameters documented
- Response schemas updated
- Deprecations marked

---

## API Rate Limits

### Default Limits

| Endpoint Type | Default Limit | Configurable |
|---------------|---------------|--------------|
| Upload | 10/hour/IP | `RATE_LIMIT_UPLOAD` |
| Download | 50/hour/IP | `RATE_LIMIT_DOWNLOAD` |
| Admin Login | 5/15min/IP | Fixed |
| User Login | 5/15min/IP | Fixed |

### Rate Limit Headers

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1699999999
Retry-After: 3600

{"error": "Rate limit exceeded", "retry_after": 3600}
```

### Handling Rate Limits

```python
from safeshare.exceptions import RateLimitError

try:
    result = client.upload("file.txt")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after} seconds")
    time.sleep(e.retry_after)
    result = client.upload("file.txt")
```

---

## Error Response Format

### Standard Error Response

All API errors follow this format:

```json
{
    "error": "Human-readable error message",
    "code": "ERROR_CODE",
    "details": {}  // Optional additional details
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_REQUEST` | 400 | Malformed request |
| `AUTHENTICATION_REQUIRED` | 401 | Missing or invalid auth |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `FILE_TOO_LARGE` | 413 | Exceeds size limit |
| `RATE_LIMITED` | 429 | Too many requests |
| `QUOTA_EXCEEDED` | 507 | Storage quota exceeded |
| `INTERNAL_ERROR` | 500 | Server error |

### Error Code Stability

Error codes are stable within a major version. New error codes may be added in minor versions.

---

## Contact

For API questions or concerns about compatibility:

- **GitHub Issues:** [SafeShare Issues](https://github.com/fjmerc/safeshare/issues)
- **Documentation:** [API Reference](API_REFERENCE.md)

---

**Last Updated:** December 2025
**SafeShare Version:** 1.5.0
