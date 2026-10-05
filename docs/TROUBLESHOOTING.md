# SafeShare Troubleshooting Guide

This guide covers common issues and their solutions when deploying and operating SafeShare.

## Table of Contents

- [Installation & Startup Issues](#installation--startup-issues)
- [Upload Issues](#upload-issues)
- [Download Issues](#download-issues)
- [Authentication Issues](#authentication-issues)
- [Database Issues](#database-issues)
- [Encryption Issues](#encryption-issues)
- [Reverse Proxy Issues](#reverse-proxy-issues)
- [Performance Issues](#performance-issues)
- [Webhook Issues](#webhook-issues)
- [CDN & Caching Issues](#cdn--caching-issues)
- [Monitoring & Health Check Issues](#monitoring--health-check-issues)
- [SDK & API Issues](#sdk--api-issues)
- [Debug Logging](#debug-logging)

---

## Installation & Startup Issues

### Container fails to start

**Symptoms:**
- Container exits immediately after starting
- `docker logs` shows configuration errors

**Solutions:**

1. **Check environment variables:**
   ```bash
   # Verify required variables are set
   docker inspect safeshare | jq '.[0].Config.Env'
   ```

2. **Validate encryption key format:**
   ```bash
   # Key must be exactly 64 hexadecimal characters
   echo $ENCRYPTION_KEY | wc -c  # Should output 65 (64 chars + newline)
   ```

3. **Check volume permissions:**
   ```bash
   # Fix volume ownership
   docker run --rm -v safeshare-data:/data -v safeshare-uploads:/uploads \
     alpine chown -R 1000:1000 /data /uploads
   ```

### "Permission denied" errors

**Symptoms:**
- Cannot write to database or upload directory
- HTTP 500 errors on upload

**Solutions:**

```bash
# Option 1: Fix existing volume permissions
docker run --rm \
  -v safeshare-data:/data \
  -v safeshare-uploads:/uploads \
  alpine sh -c "chown -R 1000:1000 /data /uploads && chmod -R 755 /data /uploads"

# Option 2: Use bind mounts with correct ownership
mkdir -p /var/safeshare/{data,uploads}
chown -R 1000:1000 /var/safeshare
```

### Port already in use

**Symptoms:**
- "bind: address already in use" error

**Solutions:**

```bash
# Find what's using port 8080
sudo lsof -i :8080

# Use a different port
docker run -p 8081:8080 safeshare:latest
```

---

## Upload Issues

### "File is too large" error

**Symptoms:**
- HTTP 413 Request Entity Too Large
- Upload fails with size error

**Solutions:**

1. **Check server configuration:**
   ```bash
   curl http://localhost:8080/api/config | jq .max_file_size
   ```

2. **Increase max file size:**
   ```bash
   docker run -e MAX_FILE_SIZE=524288000 safeshare:latest  # 500MB
   ```

3. **Check reverse proxy limits:**
   ```nginx
   # nginx
   client_max_body_size 500M;
   ```

### Upload stuck at percentage or fails

**Symptoms:**
- Upload hangs at specific percentage
- "Failed to fetch" or timeout errors

**Causes & Solutions:**

1. **Timeout issues (large files):**

   Upload and chunk requests get a transfer deadline that scales with the expected size (assuming at least 64 KiB/s, plus a 60-second margin, capped at 6 hours). `READ_TIMEOUT` and `WRITE_TIMEOUT` (120 seconds by default) are kept as a floor, so you normally don't need to raise them for large files. On top of that deadline, a request body that sends nothing for **60 seconds**, or averages **under 4 KiB/s**, is cut off with `408 UPLOAD_TIMEOUT` (see below).

   If a proxy or CDN in front of SafeShare times out first, raise its limits instead (see [REVERSE_PROXY.md](REVERSE_PROXY.md)) or use chunked uploads, which split the transfer into short requests.

2. **`408 UPLOAD_TIMEOUT` ("Upload stalled and timed out"):**
   - The server stopped receiving data for 60 seconds, or the connection averaged under 4 KiB/s.
   - Retry the upload. The web client retries a timed-out chunk automatically; SDK upload calls return the error, and retrying the upload works.
   - Common causes: a very slow or unstable uplink (mobile, Tor), a client that paused mid-upload (for example a laptop going to sleep), or a proxy that stalls while forwarding the body. Check the proxy's logs for upstream timeouts at the same time.

3. **`429` while polling upload status:**
   - After a chunked upload, clients poll `GET /api/upload/status/{id}` until the file is assembled. That endpoint is limited per IP to 600x `RATE_LIMIT_UPLOAD` requests per hour (never under 6,000/hour), so you normally only hit it when many uploads share one IP (a busy NAT, or Tor).
   - Keep polling more slowly: the assembly continues on the server. The web uploader (v1.9.0+) and the SDKs (v1.10.1+) already do this. Older SDKs abandon the upload on a 429; upgrade them.
   - Raise `RATE_LIMIT_UPLOAD` if it happens regularly.

4. **File modified during upload:**
   - Ensure file isn't being downloaded or modified
   - Wait for antivirus scans to complete
   - Error message: "ERR_UPLOAD_FILE_CHANGED"

5. **Network instability:**
   - Chunked uploads automatically retry
   - Check network connectivity
   - Try again on stable connection

### "Blocked file extension" error

**Symptoms:**
- HTTP 400 with blocked extension message

**Solutions:**

1. **Check blocked extensions:**
   ```bash
   curl http://localhost:8080/api/config | jq .blocked_extensions
   ```

2. **Customize blocklist:**
   ```bash
   # Allow .exe files (not recommended for security)
   docker run -e BLOCKED_EXTENSIONS=".bat,.cmd,.ps1" safeshare:latest
   
   # Disable blocklist entirely (dangerous!)
   docker run -e BLOCKED_EXTENSIONS="" safeshare:latest
   ```

### "Storage quota exceeded" error

**Symptoms:**
- HTTP 507 Insufficient Storage

**Solutions:**

1. **Check current usage:**
   ```bash
   curl http://localhost:8080/health | jq '{quota_used_percent, storage_used_bytes}'
   ```

2. **Increase quota:**
   ```bash
   docker run -e QUOTA_LIMIT_GB=100 safeshare:latest
   ```

3. **Clean up expired files manually:**
   - Wait for automatic cleanup (runs every hour by default)
   - Or restart container to trigger immediate cleanup

4. **Chunked uploads reserve their full size up front:** `POST /api/upload/init` returns `507 QUOTA_EXCEEDED` if the whole file doesn't fit in the remaining quota. A started upload that stores no new chunk for an hour stops reserving its full size; its next new chunk re-reserves the rest, or fails with `507 QUOTA_EXCEEDED` if the quota has filled in the meantime.

5. **Disk full (`507 INSUFFICIENT_STORAGE`):** uploads are spooled to `.spool/` inside the uploads volume and chunks to `.partial/`, so the volume needs free space beyond the stored files.

### Rate limit exceeded (HTTP 429)

**Symptoms:**
- "Too many requests" error
- Upload/download blocked temporarily

**Solutions:**

1. **Wait for rate limit window to reset** (default: 1 hour)

2. **Adjust rate limits:**
   ```bash
   docker run \
     -e RATE_LIMIT_UPLOAD=50 \
     -e RATE_LIMIT_DOWNLOAD=500 \
     safeshare:latest
   ```

---

## Download Issues

### Download fails at percentage

**Symptoms:**
- Download stops partway through
- Browser shows network error

**Causes & Solutions:**

1. **CDN timeout (Cloudflare 524 error):**
   - Use `DOWNLOAD_URL` to bypass CDN for large files
   - See [CDN & Caching Issues](#cdn--caching-issues)

2. **Connection interruption:**
   - SafeShare supports HTTP Range requests, and the web UI hands downloads to the browser's own download manager, which can usually resume an interrupted download
   - It can't resume a password-protected download (the browser re-requests it without the password), and resuming a file with a download limit may be refused once its one allowed download has been used; in either case, start the download again from the Pickup tab
   - For very large files on unreliable connections, `curl -C -` resumes uncapped files; for a file with a download limit, send the `X-Download-Session` header from the first response back on the resume (see `docs/HTTP_RANGE_SUPPORT.md`)

3. **File corruption:**
   ```bash
   # Verify file integrity via API
   curl http://localhost:8080/api/claim/CLAIM_CODE/info | jq .sha256_hash
   ```

### "File not found or expired" error

**Symptoms:**
- HTTP 404 on download
- Claim code doesn't work

**Causes:**

1. **File expired:** Check expiration time was set correctly during upload
2. **Download limit reached:** File may have reached max downloads
3. **File deleted:** Admin or user may have deleted the file
4. **Typo in claim code:** Claim codes are case-sensitive

**Verification:**
```bash
# Check file status (if you have admin access)
curl -b cookies.txt http://localhost:8080/admin/api/dashboard | jq '.files[] | select(.claim_code | contains("ABC"))'
```

### "Password required" error

**Symptoms:**
- HTTP 401 Unauthorized
- `password_required: true` in response

**Solutions:**

```bash
# Download with password
curl -O "http://localhost:8080/api/claim/CLAIM_CODE?password=yourpassword"

# Or via SDK
client.download("CLAIM_CODE", "file.pdf", password="yourpassword")
```

### Slow download speeds

**Symptoms:**
- Downloads much slower than expected
- Long time to first byte

**Causes & Solutions:**

1. **Large encrypted files:**
   - SFSE1 format uses 10MB chunks for better streaming
   - Files encrypted with old 64MB chunks may be slower
   - Consider running `migrate-chunks` tool

2. **Server resources:**
   ```bash
   # Check server health
   curl http://localhost:8080/health | jq .
   ```

3. **Network/CDN issues:**
   - Try direct download bypassing CDN
   - Check CDN configuration

---

## Authentication Issues

### Admin login fails

**Symptoms:**
- "Invalid credentials" error
- Cannot access admin dashboard

**Solutions:**

1. **Verify credentials are set:**
   ```bash
   docker inspect safeshare | jq '.[0].Config.Env | map(select(startswith("ADMIN_")))'
   ```

2. **Check minimum requirements:**
   - Username: minimum 3 characters
   - Password: minimum 8 characters

3. **Rate limiting:**
   - 5 login attempts per 15 minutes per IP
   - Wait and try again

### User session expires unexpectedly

**Symptoms:**
- Logged out without action
- "Session expired" messages

**Solutions:**

1. **Adjust session duration:**
   ```bash
   docker run -e SESSION_EXPIRY_HOURS=72 safeshare:latest
   ```

2. **Check system time:**
   - Ensure server time is correct
   - Session validation uses UTC timestamps

### CSRF token errors

**Symptoms:**
- "CSRF token invalid" error
- State-changing operations fail

**Causes & Solutions:**

1. **Expired CSRF token:**
   - Refresh the page to get new token
   - CSRF tokens expire after 24 hours

2. **Multiple tabs:**
   - CSRF tokens are per-session
   - Using multiple tabs may cause conflicts
   - Refresh the tab before submitting

### API token not working

**Symptoms:**
- HTTP 401 Unauthorized with Bearer token
- "Invalid token" error

**Solutions:**

1. **Verify token format:**
   ```bash
   # Token must start with "safeshare_"
   curl -H "Authorization: Bearer safeshare_abc123..." http://localhost:8080/api/user/files
   ```

2. **Check token scopes:**
   - Token must have required scope for operation
   - Scopes: `upload`, `download`, `manage`, `admin`

3. **Token may be expired or revoked:**
   - Create new token via dashboard

---

## Database Issues

### "Database locked" errors

**Symptoms:**
- HTTP 500 errors
- "database is locked" in logs

**Solutions:**

1. **Ensure single instance:**
   ```bash
   # Check for multiple containers using same volume
   docker ps | grep safeshare
   ```

2. **Enable WAL mode (should be automatic):**
   ```bash
   docker exec safeshare sqlite3 /app/data/safeshare.db "PRAGMA journal_mode;"
   # Should return "wal"
   ```

3. **Restart container:**
   ```bash
   docker restart safeshare
   ```

### Database corruption

**Symptoms:**
- Persistent errors
- "database disk image is malformed"

**Solutions:**

1. **Check integrity:**
   ```bash
   docker exec safeshare sqlite3 /app/data/safeshare.db "PRAGMA integrity_check;"
   ```

2. **Attempt recovery:**
   ```bash
   # Stop container first
   docker stop safeshare
   
   # Backup current database
   docker run --rm -v safeshare-data:/data -v $(pwd):/backup \
     alpine cp /data/safeshare.db /backup/safeshare-corrupted.db
   
   # Attempt to recover
   docker run --rm -v safeshare-data:/data alpine sh -c "
     sqlite3 /data/safeshare.db '.dump' | sqlite3 /data/safeshare-recovered.db
     mv /data/safeshare.db /data/safeshare-bad.db
     mv /data/safeshare-recovered.db /data/safeshare.db
   "
   ```

3. **Restore from backup** (if recovery fails)

### High disk usage from database

**Symptoms:**
- Database file very large
- WAL file keeps growing

**Solutions:**

1. **Run VACUUM:**
   ```bash
   docker exec safeshare sqlite3 /app/data/safeshare.db "VACUUM;"
   ```

2. **Checkpoint WAL:**
   ```bash
   docker exec safeshare sqlite3 /app/data/safeshare.db "PRAGMA wal_checkpoint(TRUNCATE);"
   ```

---

## Encryption Issues

### "cipher: message authentication failed"

**Symptoms:**
- Download fails with decryption error
- "authentication failed" in logs

**Causes & Solutions:**

1. **Wrong encryption key:**
   - Ensure same key is used that was used for upload
   - Key cannot be recovered - files encrypted with wrong key are lost

2. **File corruption:**
   - Storage corruption may cause this
   - Check filesystem for errors

3. **Key format issue:**
   ```bash
   # Key must be exactly 64 hex characters
   echo -n "$ENCRYPTION_KEY" | xxd -r -p | wc -c  # Should output 32
   ```

### Lost encryption key

**Symptoms:**
- Cannot decrypt any files
- Key not stored anywhere

**Reality:**
- **Files are permanently lost** if key is lost
- No recovery mechanism exists (by design)

**Prevention:**
- Store key in password manager
- Store key in secrets manager (AWS, Vault, etc.)
- Keep secure backup separate from backups

### Migration from legacy encryption

**Symptoms:**
- Old files using legacy format
- Performance issues with large files

**Solution:**
```bash
# Run encryption migration tool
docker run --rm \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  -e ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  safeshare:latest \
  /app/migrate-encryption --dry-run

# If dry-run looks good, run actual migration
docker run --rm \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  -e ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  safeshare:latest \
  /app/migrate-encryption
```

---

## Reverse Proxy Issues

### Wrong URLs in responses

**Symptoms:**
- Download URLs show `http://localhost:8080`
- Incorrect protocol (http instead of https)

**Solutions:**

1. **Set PUBLIC_URL:**
   ```bash
   docker run -e PUBLIC_URL=https://share.example.com safeshare:latest
   ```

2. **Configure proxy headers:**
   ```nginx
   # nginx
   proxy_set_header X-Forwarded-Proto $scheme;
   proxy_set_header X-Forwarded-Host $host;
   ```

### IP addresses show as proxy IP

**Symptoms:**
- All requests show same IP (proxy IP)
- Rate limiting affects all users

**Solutions:**

1. **Configure trusted proxies (recommended):**
   ```bash
   docker run \
     -e TRUST_PROXY_HEADERS=auto \
     -e TRUSTED_PROXY_IPS="10.0.0.0/8,172.16.0.0/12" \
     safeshare:latest
   ```

2. **Configure proxy to forward real IP:**
   ```nginx
   # nginx
   proxy_set_header X-Real-IP $remote_addr;
   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   ```

### Large file uploads fail through proxy

**Symptoms:**
- HTTP 413 from proxy (not SafeShare)
- Timeout errors on large uploads

**Solutions:**

```nginx
# nginx - increase limits
client_max_body_size 500M;
proxy_read_timeout 600s;
proxy_send_timeout 600s;
```

```yaml
# Traefik - no limits by default, but check middleware
# Ensure no requestBodyLimit middleware is applied
```

See [REVERSE_PROXY.md](REVERSE_PROXY.md) for detailed configurations.

---

## Performance Issues

### High memory usage

**Symptoms:**
- Container using excessive RAM
- OOM kills

**Causes & Solutions:**

1. **Older versions buffered uploads in memory:**
   - Since v1.9.0, regular uploads stream to a temporary file under `.spool/` in the uploads directory and chunks stream straight to disk, so memory no longer grows with file size (a 512 MB upload peaked at about 2 GB of RAM before). If you see high memory with an older version, upgrade.
   - Large end-to-end encrypted files are decrypted in the browser, which needs the whole file in memory; that is browser memory, not the server's.

2. **Many concurrent encrypted downloads:**
   - Legacy-format encrypted files are decrypted fully in memory. `DOWNLOAD_DECRYPT_MEMORY_BUDGET` (default 256 MiB) caps decrypt memory across all downloads, and `LEGACY_DECRYPT_MAX_BYTES` (default 128 MiB) refuses larger legacy files. Run `migrate-encryption` to move legacy files to the streaming format.

3. **Many concurrent uploads:**
   - Concurrent chunked-upload assembly is capped by `ASSEMBLY_WORKERS_MAX` (default: 10); requests beyond it get `503`
   - Memory itself is not the limiting factor for uploads; check disk space and I/O instead

3. **Database queries:**
   ```bash
   # Check database size
   curl http://localhost:8080/health | jq .database_metrics
   ```

### Slow response times

**Symptoms:**
- High latency on all requests
- Slow dashboard loading

**Solutions:**

1. **Check health status:**
   ```bash
   curl http://localhost:8080/health | jq .status_details
   ```

2. **Database optimization:**
   ```bash
   # Run VACUUM
   docker exec safeshare sqlite3 /app/data/safeshare.db "VACUUM;"
   
   # Analyze tables
   docker exec safeshare sqlite3 /app/data/safeshare.db "ANALYZE;"
   ```

3. **Check disk I/O:**
   - Use SSD storage for uploads and database
   - Check disk space availability

### Chunked upload slow

**Symptoms:**
- Large file uploads slower than expected
- Concurrency not optimal

**Solutions:**

1. **Check HTTP/2 support:**
   - HTTP/2 allows higher concurrency (12 vs 6 workers)
   - Ensure HTTPS is properly configured

2. **Adjust chunk size:**
   ```bash
   # Increase chunk size for fast networks
   docker run -e CHUNK_SIZE=20971520 safeshare:latest  # 20MB
   ```

3. **Check server resources:**
   - CPU for encryption
   - Disk I/O for writes

---

## Webhook Issues

### Webhooks not triggering

**Symptoms:**
- No webhook deliveries
- Events not appearing in delivery history

**Solutions:**

1. **Verify webhook is enabled:**
   - Check admin dashboard > Webhooks tab
   - Ensure "Enabled" toggle is on

2. **Check event subscription:**
   - Webhook must be subscribed to relevant event types
   - Events: `file.uploaded`, `file.downloaded`, `file.deleted`, `file.expired`

3. **Check webhook URL:**
   - URL must be accessible from server
   - HTTPS recommended

### Webhook delivery failures

**Symptoms:**
- Delivery status: "failed" or "retrying"
- Error messages in delivery details

**Common Errors:**

1. **Connection refused:**
   - Webhook endpoint not running
   - Firewall blocking connection

2. **Timeout:**
   ```bash
   # Increase timeout (default: 30s)
   # Edit webhook config in admin dashboard
   ```

3. **401/403 errors:**
   - Check service token configuration
   - Gotify: Token should be app token
   - ntfy: Token should be access token

4. **SSL certificate errors:**
   - Ensure valid SSL certificate
   - Self-signed certs may fail

### Webhook signature verification failing

**Symptoms:**
- Receiving webhooks but signature doesn't match
- 401 errors on your webhook endpoint

**Solutions:**

1. **Check secret key:**
   - Same secret must be configured in SafeShare and your endpoint
   - Secret is HMAC-SHA256 key

2. **Verify signature calculation:**
   ```python
   import hmac
   import hashlib
   
   def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
       expected = hmac.new(
           secret.encode(),
           payload,
           hashlib.sha256
       ).hexdigest()
       return hmac.compare_digest(f"sha256={expected}", signature)
   ```

---

## CDN & Caching Issues

### Cloudflare 524 timeout errors

**Symptoms:**
- Large file downloads fail with 524 error
- Downloads work for small files

**Cause:** Cloudflare has 100-second timeout for proxied connections.

**Solutions:**

1. **Use separate download domain:**
   ```bash
   docker run \
     -e PUBLIC_URL=https://share.example.com \
     -e DOWNLOAD_URL=https://downloads.example.com \
     safeshare:latest
   ```

2. **Configure download subdomain:**
   - Create `downloads.example.com` pointing to same server
   - Set DNS to "DNS only" (grey cloud) in Cloudflare
   - This bypasses Cloudflare proxy for downloads

### Stale content after deployment

**Symptoms:**
- Users see old version after update
- Changes not visible

**Solutions:**

1. **Purge Cloudflare cache:**
   - Cloudflare Dashboard > Caching > Purge Cache
   - Purge specific URLs or everything

2. **Verify cache status:**
   ```bash
   curl -sI https://share.example.com/assets/app.js | grep cf-cache-status
   # MISS = fresh, HIT = cached
   ```

3. **Add cache-busting:**
   - Frontend assets should have version in filename
   - Or use query strings: `app.js?v=<version>`
   - Browsers also keep a service-worker cache; it is refreshed when `CACHE_VERSION` in `service-worker.js` changes (see [FRONTEND.md](FRONTEND.md))

### Assets not loading (CORS errors)

**Symptoms:**
- Browser console shows CORS errors
- Static assets blocked

**Solutions:**

1. **Check CSP headers:**
   - SafeShare sets appropriate CSP headers
   - Custom proxy config may override them

2. **Verify CDN settings:**
   - Ensure CDN doesn't modify headers
   - Check for conflicting security headers

---

## Monitoring & Health Check Issues

### Health check returning unhealthy

**Symptoms:**
- `/health` returns HTTP 503
- Container marked unhealthy

**Check status details:**
```bash
curl http://localhost:8080/health | jq .status_details
```

**Common causes:**

1. **Disk space < 500MB:**
   ```bash
   df -h /app/uploads
   # Free up space or expand disk
   ```

2. **Database connection failed:**
   ```bash
   # Check database file
   docker exec safeshare ls -la /app/data/safeshare.db
   ```

3. **Upload directory not writable:**
   ```bash
   # Fix permissions
   docker exec safeshare touch /app/uploads/test && \
   docker exec safeshare rm /app/uploads/test
   ```

### Prometheus metrics not available

**Symptoms:**
- `/metrics` endpoint returns 404 or empty

**Solutions:**

1. **Verify endpoint:**
   ```bash
   curl http://localhost:8080/metrics
   ```

2. **Check Prometheus scrape config:**
   ```yaml
   scrape_configs:
     - job_name: 'safeshare'
       static_configs:
         - targets: ['safeshare:8080']
       metrics_path: '/metrics'
   ```

---

## SDK & API Issues

### SDK authentication failing

**Symptoms:**
- 401 errors from SDK
- "Invalid token" responses

**Solutions:**

1. **Check token format:**
   ```python
   # Python SDK
   client = SafeShareClient(
       base_url="https://share.example.com",
       api_token="safeshare_abc123..."  # Must include "safeshare_" prefix
   )
   ```

2. **Verify scopes:**
   - Token needs appropriate scope for operation
   - Check token scopes in dashboard

### Chunked upload via SDK failing

**Symptoms:**
- Large file uploads fail
- Chunk upload errors

**Solutions:**

1. **Check server config:**
   ```python
   config = client.get_config()
   print(f"Chunk threshold: {config.chunked_upload_threshold}")
   print(f"Chunk size: {config.chunk_size}")
   ```

2. **Enable debug logging:**
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

---

## Debug Logging

### Log level and format

SafeShare writes JSON-structured logs to stdout at a fixed `INFO` level. There is no `LOG_LEVEL` or `LOG_FORMAT` setting, so debug-level messages are not available. Read the logs with `docker logs safeshare`.

For a record of who did what (logins, admin actions, uploads and downloads), use the tamper-evident audit log in the admin dashboard's **Audit Log** tab (see [SECURITY.md](SECURITY.md)); it is separate from the application log.

### View specific log types

```bash
# Security events only
docker logs safeshare | jq 'select(.level=="WARN" or .level=="ERROR")'

# Authentication events
docker logs safeshare | jq 'select(.msg | contains("login"))'

# Upload events
docker logs safeshare | jq 'select(.msg | contains("upload"))'

# Webhook events
docker logs safeshare | jq 'select(.msg | contains("webhook"))'
```

### Export logs for support

```bash
# Export last 1000 lines as JSON
docker logs safeshare --tail 1000 > safeshare-debug.json

# Include container info
docker inspect safeshare > safeshare-config.json
```

---

## Getting Help

If you've tried the solutions above and still have issues:

1. **Check existing issues:** [GitHub Issues](https://github.com/fjmerc/safeshare/issues)

2. **Gather debug info:**
   - SafeShare version: `curl http://localhost:8080/api/config | jq .version`
   - Health status: `curl http://localhost:8080/health`
   - Relevant logs (sanitized of sensitive data)

3. **Open new issue:** Include version, steps to reproduce, expected vs actual behavior

4. **Security issues:** See [Security Reporting](SECURITY.md#security-reporting)

---

**Last Updated:** October 2026
**SafeShare Version:** 1.11.1
