# Production Deployment Guide - SafeShare

This guide walks you through deploying SafeShare to production with enterprise-grade security and reliability.

**Prerequisites**:
- Docker installed
- Domain name with DNS configured
- Server with minimum 2GB RAM, 20GB disk space
- Basic understanding of Docker and reverse proxies

---

## Table of Contents

1. [Quick Start (TL;DR)](#quick-start-tldr)
2. [Pre-Deployment Security Hardening](#pre-deployment-security-hardening)
3. [HTTPS Setup (Critical)](#https-setup-critical)
4. [Environment Configuration](#environment-configuration)
5. [Database & Storage Setup](#database--storage-setup)
6. [Monitoring & Logging](#monitoring--logging)
7. [Backup Strategy](#backup-strategy)
8. [Post-Deployment Verification](#post-deployment-verification)
9. [Maintenance & Updates](#maintenance--updates)

---

## Quick Start (TL;DR)

```bash
# 1. Generate encryption key
ENCRYPTION_KEY=$(openssl rand -hex 32)

# 2. Deploy with Traefik (automatic HTTPS)
docker network create web

docker run -d \
  -p 80:80 -p 443:443 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v traefik-certs:/letsencrypt \
  --name traefik \
  --network web \
  traefik:v2.10 \
  --api.dashboard=true \
  --providers.docker=true \
  --providers.docker.exposedbydefault=false \
  --entrypoints.web.address=:80 \
  --entrypoints.websecure.address=:443 \
  --certificatesresolvers.letsencrypt.acme.email=your@email.com \
  --certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json \
  --certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web

# 3. Deploy SafeShare with HTTPS enabled
docker run -d \
  --name safeshare \
  --network web \
  -e ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD="YourStrongPassword123!" \
  -e RATE_LIMIT_UPLOAD=10 \
  -e RATE_LIMIT_DOWNLOAD=100 \
  -e MAX_EXPIRATION_HOURS=168 \
  -e QUOTA_LIMIT_GB=50 \
  -e BLOCKED_EXTENSIONS=".exe,.bat,.cmd,.sh,.ps1,.dll,.so,.msi,.scr,.vbs,.jar" \
  -e TZ=Europe/Berlin \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  -l "traefik.enable=true" \
  -l "traefik.http.routers.safeshare.rule=Host(\`share.yourdomain.com\`)" \
  -l "traefik.http.routers.safeshare.entrypoints=websecure" \
  -l "traefik.http.routers.safeshare.tls.certresolver=letsencrypt" \
  -l "traefik.http.services.safeshare.loadbalancer.server.port=8080" \
  --restart unless-stopped \
  safeshare:latest

# 4. Store encryption key securely
echo "$ENCRYPTION_KEY" > /secure/path/safeshare-encryption-key.txt
chmod 600 /secure/path/safeshare-encryption-key.txt
```

**⚠️ CRITICAL**: Before deploying, read the [Pre-Deployment Security Hardening](#pre-deployment-security-hardening) section!

---

## Pre-Deployment Security Hardening

### 1. Fix Critical Security Issues

**Required changes before production deployment:**

#### A. Enable Secure Cookie Flag

**Option 1: Environment Variable (Recommended)**

Add to your code:
```go
// internal/config/config.go
type Config struct {
    // ... existing fields ...
    HTTPSEnabled bool
}

func Load() *Config {
    httpsEnabled := os.Getenv("HTTPS_ENABLED") == "true"

    return &Config{
        // ... existing fields ...
        HTTPSEnabled: httpsEnabled,
    }
}
```

Update cookie settings:
```go
// internal/middleware/admin.go:186
cookie := &http.Cookie{
    Name:     "csrf_token",
    Value:    token,
    Path:     "/admin",
    HttpOnly: false,
    Secure:   cfg.HTTPSEnabled, // ✅ Use config
    SameSite: http.SameSiteStrictMode,
}

// internal/handlers/user_auth.go:124, 180
http.SetCookie(w, &http.Cookie{
    Name:     "user_session",
    Value:    sessionToken,
    Path:     "/",
    HttpOnly: true,
    Secure:   cfg.HTTPSEnabled, // ✅ Use config
    SameSite: http.SameSiteStrictMode,
})
```

Set environment variable:
```bash
-e HTTPS_ENABLED=true
```

**Option 2: Hardcode (Quick Fix)**

Simply change `Secure: false` to `Secure: true` in:
- `internal/middleware/admin.go:186`
- `internal/handlers/user_auth.go:124`
- `internal/handlers/user_auth.go:180`

#### B. Add User Login Rate Limiting

Create middleware:
```go
// internal/middleware/ratelimit.go (add new function)
// RateLimitUserLogin rate limits user login attempts
func RateLimitUserLogin() func(http.Handler) http.Handler {
    type loginAttempt struct {
        count      int
        lastAttempt time.Time
    }

    attempts := make(map[string]*loginAttempt)
    maxAttempts := 5
    windowMinutes := 15

    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            clientIP := getClientIP(r)

            // Clean up old entries
            now := time.Now()
            for ip, attempt := range attempts {
                if now.Sub(attempt.lastAttempt) > time.Duration(windowMinutes)*time.Minute {
                    delete(attempts, ip)
                }
            }

            // Check rate limit
            if attempt, exists := attempts[clientIP]; exists {
                if attempt.count >= maxAttempts {
                    if now.Sub(attempt.lastAttempt) < time.Duration(windowMinutes)*time.Minute {
                        slog.Warn("user login rate limit exceeded",
                            "ip", clientIP,
                            "attempts", attempt.count,
                        )
                        http.Error(w, "Too many login attempts. Please try again later.", http.StatusTooManyRequests)
                        return
                    }
                    attempt.count = 0
                }
            }

            defer func() {
                if attempts[clientIP] == nil {
                    attempts[clientIP] = &loginAttempt{}
                }
                attempts[clientIP].count++
                attempts[clientIP].lastAttempt = now
            }()

            next.ServeHTTP(w, r)
        })
    }
}
```

Update route registration:
```go
// cmd/safeshare/main.go
rateLimitedUserLogin := middleware.RateLimitUserLogin()(
    http.HandlerFunc(handlers.UserLoginHandler(db, cfg)),
)
mux.Handle("/api/auth/login", rateLimitedUserLogin)
```

**Rebuild after making these changes:**
```bash
docker build -t safeshare:v1.0.0 .
```

---

## HTTPS Setup (Critical)

SafeShare does NOT include built-in TLS. You **MUST** use a reverse proxy with HTTPS.

### Option 1: Traefik (Recommended - Automatic Let's Encrypt)

**Advantages**: Automatic certificate management, Docker integration, easy configuration

```bash
# Create Docker network
docker network create web

# Deploy Traefik
docker run -d \
  -p 80:80 \
  -p 443:443 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v traefik-certs:/letsencrypt \
  --name traefik \
  --network web \
  traefik:v2.10 \
  --api.dashboard=true \
  --providers.docker=true \
  --providers.docker.exposedbydefault=false \
  --entrypoints.web.address=:80 \
  --entrypoints.web.http.redirections.entryPoint.to=websecure \
  --entrypoints.web.http.redirections.entryPoint.scheme=https \
  --entrypoints.websecure.address=:443 \
  --certificatesresolvers.letsencrypt.acme.email=your@email.com \
  --certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json \
  --certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web

# Deploy SafeShare with Traefik labels
docker run -d \
  --name safeshare \
  --network web \
  -e HTTPS_ENABLED=true \
  -e ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD="YourStrongPassword123!" \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  -l "traefik.enable=true" \
  -l "traefik.http.routers.safeshare.rule=Host(\`share.yourdomain.com\`)" \
  -l "traefik.http.routers.safeshare.entrypoints=websecure" \
  -l "traefik.http.routers.safeshare.tls.certresolver=letsencrypt" \
  -l "traefik.http.services.safeshare.loadbalancer.server.port=8080" \
  --restart unless-stopped \
  safeshare:latest
```

### Option 2: Caddy (Automatic HTTPS, Zero Config)

```bash
# Caddyfile
share.yourdomain.com {
    reverse_proxy safeshare:8080
}
```

```bash
docker run -d \
  -p 80:80 -p 443:443 \
  -v $PWD/Caddyfile:/etc/caddy/Caddyfile \
  -v caddy_data:/data \
  caddy:latest

docker run -d \
  --name safeshare \
  --link caddy \
  -e HTTPS_ENABLED=true \
  safeshare:latest
```

### Option 3: nginx + Certbot

```bash
# nginx.conf
server {
    listen 443 ssl http2;
    server_name share.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/share.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/share.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://safeshare:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name share.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

```bash
# Get Let's Encrypt certificate
certbot certonly --nginx -d share.yourdomain.com

# Deploy nginx
docker run -d \
  -p 80:80 -p 443:443 \
  -v $PWD/nginx.conf:/etc/nginx/conf.d/default.conf \
  -v /etc/letsencrypt:/etc/letsencrypt:ro \
  nginx:alpine

# Deploy SafeShare
docker run -d --name safeshare -e HTTPS_ENABLED=true safeshare:latest
```

---

## Environment Configuration

### Required Environment Variables

```bash
# Security (Required)
HTTPS_ENABLED=true                    # Enable secure cookies
ENCRYPTION_KEY=<64-char-hex>          # Generate: openssl rand -hex 32
ADMIN_USERNAME=admin                  # Admin dashboard username
ADMIN_PASSWORD=<strong-password>      # Minimum 16 characters recommended

# File Security
BLOCKED_EXTENSIONS=".exe,.bat,.cmd,.sh,.ps1,.dll,.so,.msi,.scr,.vbs,.jar,.com,.app,.deb,.rpm"
MAX_FILE_SIZE=104857600               # 100MB in bytes
MAX_EXPIRATION_HOURS=168              # 7 days

# Rate Limiting
RATE_LIMIT_UPLOAD=10                  # Uploads per hour per IP
RATE_LIMIT_DOWNLOAD=100               # Downloads per hour per IP

# Storage
QUOTA_LIMIT_GB=50                     # Total storage quota (0 = unlimited)
UPLOAD_DIR=/app/uploads               # File storage directory
DB_PATH=/app/data/safeshare.db        # Database path

# Sessions
SESSION_EXPIRY_HOURS=24               # Session lifetime

# Operational
TZ=Europe/Berlin                      # Timezone for display (logs always UTC)
PUBLIC_URL=https://share.yourdomain.com  # Public-facing URL
```

### Optional Environment Variables

```bash
# Defaults
PORT=8080                             # HTTP server port
DEFAULT_EXPIRATION_HOURS=24           # Default file expiration
CLEANUP_INTERVAL_MINUTES=60           # Cleanup worker interval
```

### Dynamic Settings (v1.1.0+)

**Important:** Starting with v1.1.0, most admin settings persist to the database and can be changed dynamically via the admin dashboard **without requiring a restart**.

**Settings with Database Persistence:**
- `QUOTA_LIMIT_GB` - Storage quota limit
- `MAX_FILE_SIZE` - Maximum upload file size
- `DEFAULT_EXPIRATION_HOURS` - Default file expiration time
- `MAX_EXPIRATION_HOURS` - Maximum allowed expiration time
- `RATE_LIMIT_UPLOAD` - Upload rate limit per IP
- `RATE_LIMIT_DOWNLOAD` - Download rate limit per IP
- `BLOCKED_EXTENSIONS` - Blocked file extensions list

**How It Works:**
1. On first startup, SafeShare uses environment variable values
2. Changes made via admin dashboard are saved to the database
3. On subsequent restarts, database settings override environment variables
4. Settings take effect immediately (no restart required)

**Recommendation:** Set sensible defaults via environment variables, then use the admin dashboard for runtime adjustments.

### Secrets Management

**DO NOT** hardcode secrets in docker-compose.yml or scripts!

**Development**:
```bash
# Use .env file (add to .gitignore)
echo "ENCRYPTION_KEY=$(openssl rand -hex 32)" > .env
echo "ADMIN_PASSWORD=..." >> .env
docker run --env-file .env safeshare:latest
```

**Production**:

**Option 1: Docker Secrets**
```bash
# Create secrets
echo "$(openssl rand -hex 32)" | docker secret create safeshare_key -
echo "YourStrongPassword" | docker secret create safeshare_admin_pass -

# Use in Docker Swarm
docker service create \
  --name safeshare \
  --secret safeshare_key \
  --secret safeshare_admin_pass \
  safeshare:latest
```

**Option 2: Environment Variables from Vault/AWS Secrets Manager**
```bash
# Fetch from AWS Secrets Manager
ENCRYPTION_KEY=$(aws secretsmanager get-secret-value \
  --secret-id safeshare/encryption-key \
  --query SecretString \
  --output text)

docker run -e ENCRYPTION_KEY="$ENCRYPTION_KEY" safeshare:latest
```

**Option 3: Kubernetes Secrets**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: safeshare-secrets
type: Opaque
data:
  encryption-key: <base64-encoded>
  admin-password: <base64-encoded>
```

---

## Database & Storage Setup

### Volume Strategy

**Persistent volumes are CRITICAL** - data loss will occur without them!

```bash
# Create named volumes (recommended for production)
docker volume create safeshare-data      # Database
docker volume create safeshare-uploads   # File storage

# Mount volumes
docker run -d \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  safeshare:latest
```

**Bind mounts (alternative)**:
```bash
mkdir -p /var/safeshare/{data,uploads}
chown -R 1000:1000 /var/safeshare  # Match container user

docker run -d \
  -v /var/safeshare/data:/app/data \
  -v /var/safeshare/uploads:/app/uploads \
  safeshare:latest
```

### Database Maintenance

SafeShare uses SQLite with WAL mode for better concurrency.

**Vacuum database** (reclaim space):
```bash
# Stop SafeShare
docker stop safeshare

# Backup first!
docker run --rm \
  -v safeshare-data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/safeshare-db-backup.tar.gz /data

# Vacuum
docker run --rm \
  -v safeshare-data:/app/data \
  --entrypoint sqlite3 \
  safeshare:latest \
  /app/data/safeshare.db "VACUUM;"

# Restart
docker start safeshare
```

**Check database integrity**:
```bash
docker exec safeshare sqlite3 /app/data/safeshare.db "PRAGMA integrity_check;"
```

---

## Monitoring & Logging

### Health Checks

SafeShare provides three health check endpoints with intelligent status detection for container orchestration and monitoring.

#### Health Check Endpoints

**1. `/health` - Comprehensive Health Check**

Full health status with detailed metrics:

```bash
curl https://share.yourdomain.com/health
```

Response when healthy:
```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "total_files": 42,
  "storage_used_bytes": 5368709120,
  "disk_total_bytes": 107374182400,
  "disk_free_bytes": 53687091200,
  "disk_used_percent": 50.0,
  "disk_available_bytes": 53687091200,
  "quota_limit_bytes": 53687091200,
  "quota_used_percent": 10.0,
  "database_metrics": {
    "size_bytes": 102400,
    "size_mb": 0.1,
    "page_count": 25,
    "page_size": 4096,
    "index_count": 5,
    "wal_size_bytes": 8192
  }
}
```

Response when degraded (HTTP 503):
```json
{
  "status": "degraded",
  "status_details": [
    "warning: disk space low (1.5 GB remaining)",
    "warning: quota usage high (96.5%)"
  ],
  "uptime_seconds": 3600,
  ...
}
```

Response when unhealthy (HTTP 503):
```json
{
  "status": "unhealthy",
  "status_details": [
    "critical: disk space < 500MB (400 MB remaining)"
  ],
  "uptime_seconds": 3600,
  ...
}
```

**2. `/health/live` - Liveness Probe** (fast, < 10ms)

Minimal check: Is the process alive and can it ping the database?

```bash
curl https://share.yourdomain.com/health/live
```

Response:
```json
{"status": "alive"}  // HTTP 200 OK
{"status": "unhealthy"}  // HTTP 503 if database unreachable
```

**3. `/health/ready` - Readiness Probe**

Comprehensive check: Is the instance ready to accept traffic?

```bash
curl https://share.yourdomain.com/health/ready
```

Returns same response as `/health` with intelligent status detection.

#### Health Status Conditions

**Unhealthy (HTTP 503) - Critical failure requiring restart:**
- Database connection fails
- Database query fails
- Disk space < 500MB
- Disk usage > 98%
- Upload directory not writable

**Degraded (HTTP 503) - Warning, operational but problematic:**
- Disk space < 2GB
- Disk usage > 90%
- Quota usage > 95%
- Database WAL file > 100MB (needs checkpointing)
- Stats query takes > 100ms

**Healthy (HTTP 200) - All systems operational:**
- All checks pass
- Adequate resources available

#### Docker Health Check

Use the liveness endpoint for fast health checks:

```bash
docker run -d \
  --health-cmd="wget --no-verbose --tries=1 --spider http://localhost:8080/health/live || exit 1" \
  --health-interval=30s \
  --health-timeout=5s \
  --health-start-period=5s \
  --health-retries=3 \
  safeshare:latest
```

#### Kubernetes Probes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: safeshare
spec:
  containers:
  - name: safeshare
    image: safeshare:latest
    ports:
    - containerPort: 8080
    livenessProbe:
      httpGet:
        path: /health/live
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 10
      timeoutSeconds: 2
      failureThreshold: 3
    readinessProbe:
      httpGet:
        path: /health/ready
        port: 8080
      initialDelaySeconds: 10
      periodSeconds: 5
      timeoutSeconds: 3
      failureThreshold: 2
```

#### Health Check Troubleshooting

**Status: degraded**
- Check disk space: `df -h`
- Check quota usage in `/health` response
- Monitor database WAL size: `ls -lh /app/data/safeshare.db-wal`
- Consider running VACUUM or checkpoint

**Status: unhealthy**
- Check database connectivity: `docker exec safeshare sqlite3 /app/data/safeshare.db "SELECT 1"`
- Check disk space: `df -h` (must have > 500MB free)
- Check upload directory permissions: `docker exec safeshare ls -la /app/uploads`
- Review logs: `docker logs safeshare --tail 100`

**Liveness probe failing**
- Database is unreachable (restart required)
- Process is deadlocked (restart required)

**Readiness probe failing**
- Disk space critically low (free up space)
- Quota exhausted (increase quota or delete files)
- Upload directory permission issues (fix permissions)

### Log Aggregation

SafeShare uses JSON-structured logging for easy aggregation.

**Splunk**:
```bash
# Forward Docker logs to Splunk
docker run -d \
  --log-driver=splunk \
  --log-opt splunk-token=<token> \
  --log-opt splunk-url=https://splunk.example.com:8088 \
  safeshare:latest
```

**ELK Stack (Elasticsearch, Logstash, Kibana)**:
```bash
# Logstash pipeline
input {
  docker {
    host => "unix:///var/run/docker.sock"
    codec => json
  }
}

filter {
  if [docker][name] == "safeshare" {
    json {
      source => "message"
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "safeshare-%{+YYYY.MM.dd}"
  }
}
```

**Datadog**:
```bash
docker run -d \
  --label com.datadoghq.ad.logs='[{"source":"safeshare","service":"safeshare"}]' \
  safeshare:latest
```

**CloudWatch (AWS)**:
```bash
docker run -d \
  --log-driver=awslogs \
  --log-opt awslogs-region=us-east-1 \
  --log-opt awslogs-group=safeshare \
  --log-opt awslogs-stream=production \
  safeshare:latest
```

### Security Alerts

Set up alerts for security events:

```bash
# Alert on multiple failed login attempts
docker logs safeshare | jq -r '
  select(.msg=="admin login failed" or .msg=="user login failed") |
  .client_ip
' | sort | uniq -c | awk '$1 > 5 { print $2 }'

# Alert on blocked file uploads
docker logs safeshare | jq -r '
  select(.msg=="blocked file extension") |
  "\(.timestamp) \(.client_ip) attempted to upload \(.extension)"
'

# Alert on quota exceeded
docker logs safeshare | jq -r '
  select(.msg=="quota exceeded") |
  "\(.timestamp) Quota exceeded: \(.current_usage_gb)GB / \(.quota_limit_gb)GB"
'
```

### Metrics Collection

Use Prometheus for metrics:

```bash
# Add to SafeShare: Prometheus exporter endpoint
# For now, scrape /health endpoint

# prometheus.yml
scrape_configs:
  - job_name: 'safeshare'
    static_configs:
      - targets: ['safeshare:8080']
    metrics_path: '/health'
    scrape_interval: 60s
```

---

## Backup Strategy

### What to Backup

1. **Database** (`/app/data/safeshare.db`) - Contains all metadata
2. **Uploads** (`/app/uploads/`) - Contains actual files
3. **Encryption Key** - CRITICAL: Lost key = lost encrypted files

### Backup Script

```bash
#!/bin/bash
# backup-safeshare.sh

BACKUP_DIR="/backups/safeshare"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="safeshare_backup_${TIMESTAMP}.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup database and uploads
docker run --rm \
  -v safeshare-data:/data \
  -v safeshare-uploads:/uploads \
  -v "$BACKUP_DIR":/backup \
  alpine tar czf "/backup/$BACKUP_FILE" /data /uploads

# Verify backup
if [ -f "$BACKUP_DIR/$BACKUP_FILE" ]; then
  echo "Backup created: $BACKUP_FILE"
  echo "Size: $(du -h "$BACKUP_DIR/$BACKUP_FILE" | cut -f1)"

  # Optional: Upload to S3
  # aws s3 cp "$BACKUP_DIR/$BACKUP_FILE" s3://my-backup-bucket/safeshare/

  # Optional: Keep only last 7 days
  find "$BACKUP_DIR" -name "safeshare_backup_*.tar.gz" -mtime +7 -delete
else
  echo "ERROR: Backup failed!"
  exit 1
fi
```

**Schedule with cron**:
```bash
# Daily backup at 2 AM
0 2 * * * /usr/local/bin/backup-safeshare.sh >> /var/log/safeshare-backup.log 2>&1
```

### Restore from Backup

```bash
#!/bin/bash
# restore-safeshare.sh

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
  echo "Usage: $0 <backup-file.tar.gz>"
  exit 1
fi

# Stop SafeShare
docker stop safeshare

# Restore data
docker run --rm \
  -v safeshare-data:/data \
  -v safeshare-uploads:/uploads \
  -v "$(dirname "$BACKUP_FILE")":/backup \
  alpine sh -c "
    rm -rf /data/* /uploads/*
    tar xzf /backup/$(basename "$BACKUP_FILE") -C /
  "

# Restart SafeShare
docker start safeshare

echo "Restore complete!"
```

### Encryption Key Backup

**CRITICAL**: Store encryption key separately from backups!

```bash
# Store in password manager (1Password, LastPass, Bitwarden)
# Or store in separate secure location

# Bad: Encryption key in same backup as encrypted files
# Good: Encryption key in password manager, backups in S3
```

---

## Post-Deployment Verification

### Security Checklist

```bash
# 1. Verify HTTPS redirect
curl -I http://share.yourdomain.com
# Should return: HTTP 301 -> HTTPS

# 2. Check security headers
curl -I https://share.yourdomain.com | grep -E "Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options"

# 3. Verify secure cookies
curl -I https://share.yourdomain.com/admin/login
# Should show: Secure; HttpOnly; SameSite=Strict

# 4. Test rate limiting
for i in {1..12}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -F "file=@test.txt" https://share.yourdomain.com/api/upload
done
# Should return 429 after 10 requests

# 5. Test file upload
curl -F "file=@test.txt" https://share.yourdomain.com/api/upload
# Should return claim code

# 6. Test admin login
curl -c cookies.txt \
  -d "username=admin&password=YourPassword" \
  https://share.yourdomain.com/admin/api/login
# Should return CSRF token

# 7. Check health endpoint
curl https://share.yourdomain.com/health | jq .
# Should return healthy status

# 8. Verify encryption (if enabled)
docker exec safeshare ls -lh /app/uploads/
# Encrypted files should have different sizes than originals

# 9. Test file expiration
# Upload with 1 minute expiration, wait, verify deletion

# 10. Check logs
docker logs safeshare | jq . | tail -20
# Should show JSON-formatted logs
```

### Performance Testing

```bash
# Load testing with Apache Bench
ab -n 100 -c 10 https://share.yourdomain.com/

# Upload performance
time curl -F "file=@100mb.bin" https://share.yourdomain.com/api/upload
```

---

## Maintenance & Updates

### Regular Tasks

**Weekly**:
```bash
# Check disk space
docker exec safeshare df -h /app/uploads

# Review security logs
docker logs safeshare | jq 'select(.level=="WARN" or .level=="ERROR")'
```

**Monthly**:
```bash
# Update Docker image
docker pull safeshare:latest
docker stop safeshare
docker rm safeshare
# Re-run docker run command with updated image

# Vacuum database
docker exec safeshare sqlite3 /app/data/safeshare.db "VACUUM;"

# Check certificate expiry (if not using auto-renewal)
openssl s_client -connect share.yourdomain.com:443 | openssl x509 -noout -dates
```

**Quarterly**:
```bash
# Security audit
# Review user accounts, disable inactive users
# Review blocked IPs
# Check for SafeShare updates

# Test restore from backup
./restore-safeshare.sh /backups/safeshare/latest.tar.gz
```

### Update Procedure

```bash
# 1. Backup current state
./backup-safeshare.sh

# 2. Pull new version
docker pull safeshare:v1.1.0

# 3. Stop current container
docker stop safeshare

# 4. Remove old container (volumes are preserved)
docker rm safeshare

# 5. Start new container (same volumes, updated image)
docker run -d \
  --name safeshare \
  # ... same configuration ...
  safeshare:v1.1.0

# 6. Verify health
curl https://share.yourdomain.com/health

# 7. Check logs for errors
docker logs safeshare | tail -50

# 8. Rollback if needed
# docker stop safeshare
# docker rm safeshare
# docker run ... safeshare:v1.0.0
```

---

## Troubleshooting

### Common Issues

**1. "Permission denied" on volumes**
```bash
# Fix volume permissions
docker run --rm \
  -v safeshare-data:/data \
  -v safeshare-uploads:/uploads \
  alpine chown -R 1000:1000 /data /uploads
```

**2. "Database locked" errors**
```bash
# SQLite WAL mode should prevent this
# If it occurs, check for multiple instances accessing same database
docker ps | grep safeshare
```

**3. Certificates not renewing**
```bash
# Check Traefik logs
docker logs traefik | grep acme

# Manually trigger renewal
docker exec traefik sh -c "rm /letsencrypt/acme.json"
docker restart traefik
```

**4. High disk usage**
```bash
# Check quota usage
curl https://share.yourdomain.com/health | jq .quota_used_percent

# Manually trigger cleanup
docker exec safeshare /app/safeshare -cleanup-now  # (if implemented)
```

**5. Rate limiting not working**
```bash
# Check if middleware is applied
docker logs safeshare | grep "rate limit"

# Restart to clear in-memory counters
docker restart safeshare
```

---

## Security Incident Response

If you suspect a security breach:

1. **Immediately**:
   ```bash
   # Block suspicious IP
   docker exec safeshare sqlite3 /app/data/safeshare.db \
     "INSERT INTO blocked_ips (ip_address, reason) VALUES ('x.x.x.x', 'Security incident');"
   ```

2. **Investigate**:
   ```bash
   # Check recent logins
   docker logs safeshare | jq 'select(.msg | contains("login"))'

   # Check file access from suspicious IP
   docker logs safeshare | jq 'select(.client_ip=="x.x.x.x")'
   ```

3. **Rotate credentials**:
   ```bash
   # Change admin password via dashboard
   # Force all users to change passwords
   # Regenerate ENCRYPTION_KEY (will break existing encrypted files!)
   ```

4. **Audit**:
   ```bash
   # Export all logs for analysis
   docker logs safeshare > incident-logs-$(date +%Y%m%d).json

   # Review all user accounts
   # Review all files for suspicious content
   ```

---

## Next Steps

1. ✅ Read this guide completely
2. ✅ Fix the 2 critical security issues (HTTPS + rate limiting)
3. ✅ Set up monitoring and logging
4. ✅ Test deployment in staging environment
5. ✅ Create backup/restore procedures
6. ✅ Deploy to production
7. ✅ Schedule regular maintenance
8. ✅ Set up security alerts

**Additional Resources**:
- [SECURITY_AUDIT.md](./SECURITY_AUDIT.md) - Security audit report
- [CI_CD_EXAMPLES.md](./CI_CD_EXAMPLES.md) - CI/CD configurations
- [VERSION_STRATEGY.md](./VERSION_STRATEGY.md) - Version management
- [REVERSE_PROXY.md](./REVERSE_PROXY.md) - Detailed proxy configs

**Support**:
- GitHub Issues: https://github.com/fjmerc/safeshare/issues
- Security Issues: security@yourcompany.com (private disclosure)
