# SafeShare Security Features

## Enterprise Security Implementation

SafeShare includes enterprise-grade security features designed for production deployments.

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

## 📞 Security Reporting

If you discover a security vulnerability, please email:
- **Email**: security@yourcompany.com
- **PGP Key**: (include if available)
- **Response Time**: Within 48 hours

Do NOT create public GitHub issues for security vulnerabilities.

---

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## License

MIT License - See LICENSE file
