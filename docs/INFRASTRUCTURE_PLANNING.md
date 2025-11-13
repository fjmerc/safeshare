# Infrastructure Planning Guide

## Why This Document Exists

You can configure SafeShare to accept 100 GB files, but that doesn't mean your infrastructure can actually handle them. **This guide helps you set realistic file size limits based on your deployment architecture.**

## The Core Constraint: Timeouts

SafeShare uses chunked uploads to handle large files. Each chunk is a separate HTTP request that must complete before your infrastructure times out.

**The fundamental equation:**
```
Chunk Upload Time < Infrastructure Timeout
```

If a 15 MB chunk takes 35 seconds to upload, but your proxy times out at 30 seconds, **uploads will fail** no matter how you configure SafeShare.

## Common Infrastructure Timeouts

Different infrastructure layers impose different timeout limits:

| Layer | Typical Timeout | Configurable? | Impact |
|-------|----------------|---------------|--------|
| **SafeShare (direct)** | 120s (default) | ✅ Yes (`READ_TIMEOUT`) | Only applies if no proxy |
| **nginx** | 60s (default) | ✅ Yes (`proxy_read_timeout`) | Common reverse proxy |
| **Apache** | 300s (default) | ✅ Yes (`ProxyTimeout`) | Common reverse proxy |
| **Traefik** | 90s (default) | ✅ Yes (`respondingTimeouts.readTimeout`) | Docker-friendly proxy |
| **Caddy** | No limit | ✅ Already optimal | Best for large files |
| **CDNs (free tier)** | 30-60s | ❌ **No** | Strictest limitation |
| **CDNs (paid tier)** | 100-600s | ⚠️ Sometimes | Check your plan |
| **Load balancers (AWS ALB)** | 60s | ✅ Yes (up to 4000s) | Cloud infrastructure |
| **Load balancers (GCP)** | 30s | ✅ Yes (up to 3600s) | Cloud infrastructure |

**Critical insight:** Your **shortest timeout** in the chain determines your maximum chunk upload time.

## Step-by-Step: Finding Your Limits

### Step 1: Identify Your Infrastructure Stack

Map out every layer between users and SafeShare:

```
[User] → [CDN?] → [Load Balancer?] → [Reverse Proxy?] → [SafeShare]
```

**Example stacks:**

**Stack A (Simple):**
```
User → Caddy → SafeShare
Shortest timeout: None (Caddy has no timeout)
```

**Stack B (Common):**
```
User → CDN (60s) → nginx (120s) → SafeShare (120s)
Shortest timeout: 60s (CDN wins)
```

**Stack C (Complex):**
```
User → CDN (30s) → AWS ALB (60s) → Traefik (90s) → SafeShare (120s)
Shortest timeout: 30s (CDN wins)
```

### Step 2: Test Your Actual Upload Speed

**Don't trust your internet plan specs.** Test real-world upload performance:

```bash
# Create a test chunk (15 MB - SafeShare default)
dd if=/dev/urandom of=test-chunk.bin bs=1M count=15

# Time the upload
time curl -X POST -F "file=@test-chunk.bin" https://your-domain.com/api/upload
```

**Calculate your effective upload speed:**
```
Effective Upload Speed = 15 MB ÷ (time in seconds)
```

**Real-world speeds are typically 60-80% of advertised:**

| Advertised | Theoretical | Actual Reality |
|------------|-------------|----------------|
| 5 Mbps upload | 0.625 MB/s | **0.4-0.5 MB/s** |
| 10 Mbps upload | 1.25 MB/s | **0.8-1.0 MB/s** |
| 40 Mbps upload | 5 MB/s | **3.5-4 MB/s** |
| 100 Mbps upload | 12.5 MB/s | **8-10 MB/s** |
| 1 Gbps upload | 125 MB/s | **80-100 MB/s** |

### Step 3: Calculate Safe Chunk Upload Time

**Formula:**
```
Chunk Upload Time = CHUNK_SIZE ÷ Effective Upload Speed
```

**Safety requirement:**
```
Chunk Upload Time < (Shortest Timeout × 0.7)
```

Use 70% of timeout as a safety margin for network variance and retries.

**Examples:**

| Upload Speed | Chunk Size | Upload Time | 30s timeout | 60s timeout | 120s timeout |
|-------------|------------|-------------|-------------|-------------|--------------|
| 0.5 MB/s | 15 MB | 30s | ❌ Fails | ⚠️ Risky | ✅ Safe |
| 0.5 MB/s | 10 MB | 20s | ✅ Safe | ✅ Safe | ✅ Safe |
| 2 MB/s | 15 MB | 7.5s | ✅ Safe | ✅ Safe | ✅ Safe |
| 5 MB/s | 15 MB | 3s | ✅ Safe | ✅ Safe | ✅ Safe |
| 10 MB/s | 20 MB | 2s | ✅ Safe | ✅ Safe | ✅ Safe |

### Step 4: Determine Maximum Practical File Size

**It's not just about timeouts - it's about user experience:**

```
Max Practical File Size = Upload Speed × Acceptable Upload Duration × Reliability Factor
```

**Acceptable upload duration** (user psychology):
- **Excellent UX**: < 5 minutes (users stay on page)
- **Acceptable UX**: 5-15 minutes (users will wait)
- **Poor UX**: 15-60 minutes (high abandonment risk)
- **Unacceptable**: > 60 minutes (connection instability, tab closures)

**Reliability factor** (infrastructure stability):
- Direct connection, wired network: **0.9**
- Through CDN/multiple proxies: **0.7-0.8**
- Mobile/wireless connection: **0.5-0.6**
- Mobile hotspot: **0.3-0.5**

**Example calculations:**

| Scenario | Speed | Duration | Factor | Max Size |
|----------|-------|----------|--------|----------|
| Business fiber, direct | 50 MB/s | 5 min | 0.9 | **13.5 GB** |
| Home cable, CDN | 4 MB/s | 15 min | 0.7 | **2.5 GB** |
| Home DSL, CDN | 1 MB/s | 15 min | 0.7 | **630 MB** |
| Mobile hotspot | 0.7 MB/s | 10 min | 0.5 | **210 MB** |

## Common Deployment Scenarios

### Scenario A: Behind a CDN Free Tier

**Infrastructure:**
```
User → CDN (30-60s timeout) → nginx → SafeShare
```

**Characteristics:**
- ❌ Cannot change CDN timeout
- ✅ Free SSL/DDoS protection
- ⚠️ Strict timeout enforcement

**Configuration strategy:**

If CDN timeout is 30s:
```bash
# Use smaller chunks to stay under timeout
CHUNK_SIZE=10485760           # 10 MB
MAX_FILE_SIZE=2147483648      # 2 GB (reasonable)

# Requires upload speed > 0.5 MB/s for 10MB chunks
# 10 MB ÷ 0.5 MB/s = 20s (safe for 30s timeout)
```

If CDN timeout is 60s:
```bash
CHUNK_SIZE=15728640           # 15 MB (default)
MAX_FILE_SIZE=5368709120      # 5 GB (reasonable)

# Requires upload speed > 0.5 MB/s for 15MB chunks
# 15 MB ÷ 0.5 MB/s = 30s (safe for 60s timeout)
```

**Red flag:** If your users consistently have < 0.5 MB/s upload, you'll need to:
- Use even smaller chunks (5 MB)
- Lower max file size to < 1 GB
- Or bypass CDN for upload endpoint (see Advanced Solutions)

### Scenario B: Direct Connection with Configurable Reverse Proxy

**Infrastructure:**
```
User → nginx/Traefik/Apache → SafeShare
```

**Characteristics:**
- ✅ Full timeout control
- ✅ Can optimize for large files
- ⚠️ Must manage SSL certificates yourself

**Configuration strategy:**

```bash
# nginx.conf
proxy_read_timeout 300s;      # 5 minutes per chunk
proxy_send_timeout 300s;
client_max_body_size 50m;     # Slightly larger than chunk

# SafeShare config
CHUNK_SIZE=20971520           # 20 MB (larger chunks = fewer requests)
MAX_FILE_SIZE=53687091200     # 50 GB
READ_TIMEOUT=300
WRITE_TIMEOUT=300

# Requires upload speed > 0.5 MB/s
# 20 MB ÷ 0.5 MB/s = 40s (safe for 300s timeout)
```

**This setup handles:**
- 50 GB file on 10 MB/s connection = ~83 minutes
- 10 GB file on 2 MB/s connection = ~83 minutes
- 5 GB file on 1 MB/s connection = ~83 minutes

### Scenario C: Cloud Infrastructure (AWS/GCP/Azure)

**Infrastructure:**
```
User → Cloud Load Balancer → Application Server (SafeShare)
```

**Characteristics:**
- ⚠️ Load balancer timeouts vary by cloud provider
- ✅ High bandwidth available
- ✅ Can configure timeouts (with limits)

**AWS ALB (Application Load Balancer):**
```bash
# ALB idle timeout: 60s default, configurable up to 4000s
aws elbv2 modify-load-balancer-attributes \
  --load-balancer-arn <arn> \
  --attributes Key=idle_timeout.timeout_seconds,Value=300
```

**GCP Load Balancer:**
```bash
# Backend service timeout: 30s default, up to 3600s (1 hour)
gcloud compute backend-services update <name> \
  --timeout=600s
```

**Configuration strategy:**
```bash
# Set load balancer timeout: 600s (10 minutes)
# SafeShare config
CHUNK_SIZE=20971520           # 20 MB
MAX_FILE_SIZE=107374182400    # 100 GB
READ_TIMEOUT=600
WRITE_TIMEOUT=600
```

### Scenario D: No Proxy (Development/Internal Use)

**Infrastructure:**
```
User → SafeShare (direct)
```

**Configuration strategy:**
```bash
# Maximum flexibility - limited only by SafeShare timeouts
CHUNK_SIZE=20971520           # 20 MB
MAX_FILE_SIZE=107374182400    # 100 GB
READ_TIMEOUT=600              # 10 minutes per chunk
WRITE_TIMEOUT=600
```

**Warning:** Only suitable for:
- Development/testing
- Internal networks (not internet-exposed)
- Must handle SSL termination separately if needed

## The CDN Dilemma

### When CDN Timeouts Become a Problem

You're hitting CDN limitations when:

1. **Upload speeds are low** (< 1 MB/s) and CDN timeout is strict (< 60s)
2. **File sizes are large** (> 5 GB) requiring many chunks
3. **Chunk failures are frequent** with `NETWORK_ERROR` or timeout codes

### Solutions

**Option 1: Bypass CDN for Upload Endpoint**

Use CDN for downloads and UI, but direct traffic to origin for uploads:

```nginx
# On your origin server, expose upload endpoint directly
server {
    listen 443 ssl;
    server_name uploads.yourdomain.com;  # Different subdomain

    location /api/upload/ {
        proxy_pass http://localhost:8080;
        proxy_read_timeout 300s;
        client_max_body_size 50m;
    }
}

# CDN handles everything else
server {
    listen 443 ssl;
    server_name share.yourdomain.com;

    location / {
        # Served through CDN
    }
}
```

DNS setup:
```
uploads.yourdomain.com  →  A record to origin IP (bypasses CDN)
share.yourdomain.com    →  CNAME to CDN
```

**Option 2: Upgrade CDN Tier**

| CDN Tier | Typical Timeout | Cost Impact |
|----------|----------------|-------------|
| Free | 30-60s | $0/month |
| Pro/Business | 100-600s | $20-200/month |
| Enterprise | Configurable | $200+/month |

**Worth upgrading if:**
- You need to support files > 5 GB
- Users have slow connections (< 2 MB/s)
- You can't bypass CDN for uploads

**Option 3: Use Alternative Upload Method**

For very large files (> 50 GB), HTTP chunked upload may not be the best choice:

```bash
# SFTP (bypasses HTTP entirely, no timeout)
sftp user@server:/uploads/

# S3 presigned URLs (direct to object storage)
# Users upload to S3, SafeShare references objects

# WebSocket-based upload (if CDN supports it)
# Better for resumable uploads
```

## Configuration Examples

### Conservative (Broad Compatibility)

**Use when:** Users have varying connection speeds, you're using a CDN free tier

```bash
MAX_FILE_SIZE=1073741824      # 1 GB - safe for most scenarios
CHUNK_SIZE=10485760           # 10 MB - completes quickly
CHUNKED_UPLOAD_THRESHOLD=52428800   # 50 MB
READ_TIMEOUT=120
WRITE_TIMEOUT=120
```

**Works with:**
- CDN with 30s timeout + 0.5 MB/s upload
- Mobile users
- International users with latency

### Balanced (Good UX + Reasonable Limits)

**Use when:** Most users have decent connections (> 2 MB/s), configurable reverse proxy

```bash
MAX_FILE_SIZE=10737418240     # 10 GB
CHUNK_SIZE=15728640           # 15 MB - default
CHUNKED_UPLOAD_THRESHOLD=104857600  # 100 MB
READ_TIMEOUT=180
WRITE_TIMEOUT=180
```

**Works with:**
- nginx/Apache with 180s timeout
- Home/office internet
- 10 GB upload takes ~42 minutes on 4 MB/s

### Aggressive (Large Files, Fast Connections)

**Use when:** Enterprise/internal deployment, users have fast connections, direct connection or high timeout limits

```bash
MAX_FILE_SIZE=107374182400    # 100 GB
CHUNK_SIZE=20971520           # 20 MB - larger chunks
CHUNKED_UPLOAD_THRESHOLD=104857600  # 100 MB
READ_TIMEOUT=600              # 10 minutes per chunk
WRITE_TIMEOUT=600
```

**Requires:**
- Reverse proxy timeout ≥ 600s
- User upload speed ≥ 2 MB/s for good UX
- 100 GB upload takes ~2.8 hours on 10 MB/s

## Monitoring and Validation

### Test Your Configuration Before Going Live

```bash
# 1. Test chunk upload time
dd if=/dev/urandom of=test-chunk.bin bs=1M count=15
time curl -X POST -F "file=@test-chunk.bin" https://your-domain.com/api/upload

# Should complete in < 70% of your shortest timeout

# 2. Test at your maximum file size
# Create test file at your MAX_FILE_SIZE
dd if=/dev/urandom of=max-test.bin bs=1M count=2048  # 2 GB example

# Monitor upload
time curl -X POST -F "file=@max-test.bin" https://your-domain.com/api/upload

# Should complete without chunk failures

# 3. Simulate slow connection
# Use browser DevTools to throttle to "Slow 3G" and test upload
# Or use tc on Linux:
tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms
# Run tests, then remove:
tc qdisc del dev eth0 root
```

### Watch for Warning Signs

```bash
# Check for timeout-related failures
docker logs safeshare | grep -i "timeout\|network_error" | wc -l

# If you see many failures, your limits are too aggressive

# Check average chunk upload time
docker logs safeshare | jq -r 'select(.msg=="chunk uploaded") | .duration_ms' | \
  awk '{sum+=$1; count++} END {print "Avg: " sum/count "ms"}'

# Should be well under your timeout (in milliseconds)
```

## Decision Matrix

Use this to quickly determine your max file size:

| Your Upload Speed | CDN Timeout | No CDN/High Timeout |
|-------------------|-------------|---------------------|
| **< 1 MB/s** (Slow) | 500 MB - 1 GB | 2-5 GB |
| **1-5 MB/s** (Average) | 2-5 GB | 10-20 GB |
| **5-10 MB/s** (Good) | 5-10 GB | 20-50 GB |
| **> 10 MB/s** (Fast) | 10-20 GB | 50-100 GB |

**If you need more than 100 GB:** Consider SFTP, object storage (S3), or specialized large file transfer solutions.

## Summary: The Three Questions

Before setting `MAX_FILE_SIZE`, answer these:

1. **What's my shortest infrastructure timeout?**
   - Find the minimum timeout in your stack
   - This determines max chunk upload time

2. **What's my users' typical upload speed?**
   - Test real-world performance
   - Account for 60-80% efficiency

3. **How long will users wait?**
   - < 5 min = excellent UX
   - 15+ min = high abandonment risk
   - Use: `Max Size = Speed × Time × Reliability Factor`

**The golden rule:** It's better to set conservative limits that work reliably than aggressive limits that frustrate users with timeouts.

---

## See Also

- [CHUNKED_UPLOAD.md](./CHUNKED_UPLOAD.md) - Technical implementation details
- [PRODUCTION.md](./PRODUCTION.md) - Production deployment guide
- [REVERSE_PROXY.md](./REVERSE_PROXY.md) - Reverse proxy configurations
