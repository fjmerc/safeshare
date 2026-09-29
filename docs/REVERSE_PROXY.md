# Reverse Proxy Configuration

SafeShare is designed to work seamlessly behind reverse proxies like Traefik, nginx, Caddy, and others.

## How It Works

SafeShare builds download URLs in responses using one of these methods (in priority order):

1. **PUBLIC_URL environment variable** (if set) - Recommended for production
2. **X-Forwarded-Proto and X-Forwarded-Host headers** - Auto-detection
3. **Request headers** - Fallback for direct connections

## Configuration Methods

### Method 1: Set PUBLIC_URL (Recommended)

The simplest and most reliable method:

```bash
docker run -d \
  -e PUBLIC_URL=https://share.yourdomain.com \
  -p 8080:8080 \
  safeshare:latest
```

**Pros:**
- Explicit and predictable
- Works with any reverse proxy
- No header configuration needed

**Cons:**
- Must match your actual domain

### Method 2: Reverse Proxy Headers (Auto-detect)

Let SafeShare auto-detect from proxy headers:

```bash
docker run -d -p 8080:8080 safeshare:latest
```

Ensure your reverse proxy sends these headers:
- `X-Forwarded-Proto` (http or https)
- `X-Forwarded-Host` (your domain)

**Pros:**
- Works automatically with properly configured proxies
- No hardcoded URLs

**Cons:**
- Requires proxy to send correct headers

## Traefik Configuration

### Option 1: Docker Compose with Traefik

```yaml
version: '3.8'

services:
  safeshare:
    image: safeshare:latest
    environment:
      - PUBLIC_URL=https://share.yourdomain.com  # Set your domain
    volumes:
      - safeshare-data:/app/data
      - safeshare-uploads:/app/uploads
    networks:
      - traefik-network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.safeshare.rule=Host(`share.yourdomain.com`)"
      - "traefik.http.routers.safeshare.entrypoints=websecure"
      - "traefik.http.routers.safeshare.tls=true"
      - "traefik.http.routers.safeshare.tls.certresolver=letsencrypt"
      - "traefik.http.services.safeshare.loadbalancer.server.port=8080"

volumes:
  safeshare-data:
  safeshare-uploads:

networks:
  traefik-network:
    external: true
```

### Option 2: Traefik File Configuration

```yaml
# traefik/config/safeshare.yml
http:
  routers:
    safeshare:
      rule: "Host(`share.yourdomain.com`)"
      service: safeshare
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt

  services:
    safeshare:
      loadBalancer:
        servers:
          - url: "http://safeshare:8080"
```

## nginx Configuration

> **Important**: `$proxy_add_x_forwarded_for` **appends** nginx's view of
> the connecting peer to whatever `X-Forwarded-For` the client sent, instead
> of replacing it. This is required for SafeShare's spoof-resistant IP
> resolution (see "How It Works" below) to work at all — if you (or a
> config you copy from elsewhere) instead use `$remote_addr` or relay the
> client's own header unchanged, nginx becomes a hop that doesn't actually
> vouch for anything, and SafeShare has no way to tell a real proxy hop from
> a client-forged one. Always use `$proxy_add_x_forwarded_for` here, never a
> bare `$remote_addr` or a pass-through of the incoming header.

```nginx
server {
    listen 443 ssl http2;
    server_name share.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;

        # Important for file uploads
        client_max_body_size 100M;
    }
}
```

**With PUBLIC_URL:**

```bash
docker run -d \
  -e PUBLIC_URL=https://share.yourdomain.com \
  -p 8080:8080 \
  safeshare:latest
```

## Caddy Configuration

Caddy automatically sets forwarded headers!

**Caddyfile:**
```
share.yourdomain.com {
    reverse_proxy localhost:8080
}
```

**With PUBLIC_URL:**
```bash
docker run -d \
  -e PUBLIC_URL=https://share.yourdomain.com \
  -p 8080:8080 \
  safeshare:latest
```

## Apache Configuration

```apache
<VirtualHost *:443>
    ServerName share.yourdomain.com

    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Host "share.yourdomain.com"

    ProxyPass / http://localhost:8080/
    ProxyPassReverse / http://localhost:8080/

    # Important for file uploads
    LimitRequestBody 104857600
</VirtualHost>
```

## Testing Your Setup

After configuring your reverse proxy:

```bash
# Upload a file
curl -X POST -F "file=@test.txt" https://share.yourdomain.com/api/upload

# Check the download_url in response - should match your domain
{
  "claim_code": "abc123xyz",
  "download_url": "https://share.yourdomain.com/api/claim/abc123xyz",
  ...
}
```

## Troubleshooting

### Download URLs show wrong domain/protocol

**Problem:** URLs show `http://localhost:8080` instead of your domain

**Solutions:**
1. Set `PUBLIC_URL` environment variable
2. Ensure reverse proxy sends `X-Forwarded-Proto` and `X-Forwarded-Host` headers
3. Check proxy logs to verify headers are being sent

### File upload fails with 413 error

**Problem:** Large files rejected by reverse proxy

**Solutions:**
- **nginx**: Set `client_max_body_size 100M;`
- **Apache**: Set `LimitRequestBody 104857600`
- **Traefik**: No configuration needed (no upload limits by default)
- **Caddy**: No configuration needed (no upload limits by default)

### TLS/HTTPS not detected

**Problem:** Download URLs use `http://` instead of `https://`

**Solutions:**
1. Set `PUBLIC_URL=https://yourdomain.com`
2. Ensure proxy sends `X-Forwarded-Proto: https` header

## Security Considerations

### Proxy Header Trust Configuration

SafeShare v2.7.0+ includes configurable proxy header trust validation to prevent IP spoofing attacks.

**Environment Variable**: `TRUST_PROXY_HEADERS`

**Valid Values**:
- `auto` (default, **recommended**) - Only trust headers from RFC1918 private IPs and localhost
- `true` - Always trust proxy headers (**SECURITY WARNING: vulnerable to IP spoofing**)
- `false` - Never trust proxy headers (use for direct internet exposure)

**Trusted Proxy IPs**: `TRUSTED_PROXY_IPS` (comma-separated IPs/CIDR ranges, plus the optional `cloudflare` keyword)
- Default: `127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`
- Used both when `TRUST_PROXY_HEADERS=auto` (to decide whether to trust the immediate peer) and, regardless of `TRUST_PROXY_HEADERS`, to decide which `X-Forwarded-For` entries are themselves proxy hops versus the real client (see "How It Works" below)
- The special keyword `cloudflare` expands to Cloudflare's published edge IP ranges (IPv4 and IPv6). It is **not** included by default — Cloudflare Workers can originate requests from the same ranges as the edge network, so trusting them is an explicit, informed choice. Add it explicitly: `TRUSTED_PROXY_IPS=...,cloudflare`
- `TRUSTED_PROXY_IPS` is validated at startup: an unknown keyword or malformed CIDR fails config load with an error rather than being silently ignored
- **Narrow this to your actual proxy's IP where you can**, rather than a whole private range. The defaults (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) trust *any* address in those ranges as a proxy hop — on a typical Docker setup that means any other container, or the Docker bridge gateway itself, can act as a trusted hop and choose the client IP SafeShare sees for a request it sends directly. If your reverse proxy has a stable address (e.g. a fixed container IP or a Docker Compose service alias resolved to one), list that address specifically instead of the whole subnet.

**About the `cloudflare` keyword, Workers, and the CF-Connecting-IP veto** (read this before enabling it): a Cloudflare Worker can make outbound requests that themselves originate from inside Cloudflare's published IP ranges — so a naive "skip every entry that matches a trusted range" walk would let a malicious Worker's own egress IP be skipped as if it were a second proxy hop, re-exposing the client-controlled leftmost entry the `cloudflare` keyword is meant to protect against. SafeShare guards against this two ways:

1. **One-hop budget**: at most **one** `X-Forwarded-For` entry may ever be attributed to Cloudflare per request (or the direct connection itself, if SafeShare sits right behind Cloudflare with no local reverse proxy — see "How It Works" below). Once that one hop is consumed, the very next entry is always treated as the candidate client, even if it also happens to look like a Cloudflare or local trusted address.
2. **CF-Connecting-IP veto**: whenever that candidate depends on trusting Cloudflare at all, it's only accepted if it matches the `CF-Connecting-IP` header — a header only Cloudflare's real edge/proxy layer sets, never SafeShare's own reverse proxy. A mismatch, a missing header, or a malformed one fails closed onto the Cloudflare hop (or `RemoteAddr`) instead of the candidate. This header is only ever a veto; it is never itself the value SafeShare uses. (Cloudflare's Pseudo-IPv4 feature is handled too: in "Add header" mode `CF-Connecting-IP` stays the real address and a separate `Cf-Pseudo-IPv4` header is added; in "Overwrite" mode both `CF-Connecting-IP` and the edge-appended `X-Forwarded-For` entry become the synthesized IPv4 address. Both modes keep `CF-Connecting-IP` and that `X-Forwarded-For` entry in agreement, so SafeShare checks `CF-Connecting-IP` only and deliberately ignores `Cf-Pseudo-IPv4`, which a Worker could set to match a forged entry.) If Cloudflare is configured to strip visitor IP headers (for example the "Remove visitor IP headers" managed transform), every visitor falls back to the Cloudflare hop's address; SafeShare logs a one-time warning when this happens.

The one-hop budget alone isn't enough for **Cloudflare Tunnel**: the entry your own reverse proxy appends there is the `cloudflared` daemon's own local address (e.g. a Docker container IP), not a published Cloudflare range, so it's trusted as an ordinary local hop and the walk can still land on an attacker-forged entry past a Worker's own Cloudflare-range egress hop. **The `cloudflare` keyword is safe to use with Tunnel only because of the CF-Connecting-IP veto** — make sure you're running a version of SafeShare that includes it (T41's third pass) before relying on Tunnel + the keyword together.

**Residual exposure — read this if a Worker can reach your origin at all**: the veto closes the gap when a request genuinely went through Cloudflare's edge/proxy layer (normal proxied traffic, and Tunnel). It does **not** close the case where a Worker (or anything else) connects to your origin **directly**, bypassing Cloudflare's proxy entirely — for example by calling your origin's raw IP, or a DNS-only ("grey-cloud") hostname that isn't proxied. At that point the request is just an ordinary HTTP client that happens to egress from a Cloudflare-owned IP: it can forge `CF-Connecting-IP` (and `Cf-Pseudo-IPv4`) itself, exactly like any other header, and SafeShare has no way to tell that apart from a value Cloudflare's real edge set. Two things are **not** sufficient to close this:
- **Allow-listing Cloudflare's IP ranges is not sufficient** — that's exactly what a Worker's own egress IP is inside.
- **The global Authenticated Origin Pulls (AOP) certificate is not sufficient** — it's shared by every Cloudflare customer, so it proves "some Cloudflare zone" made this request, not that *your* zone's proxy did.

To fully close this, your origin (or the reverse proxy in front of it) must accept **only** traffic that actually came through Cloudflare's proxy for *your* zone/hostname:
- **Zone- or hostname-level Authenticated Origin Pulls** with your own per-zone client certificate (not the shared global one), enforced by Traefik/nginx via mTLS, or
- **Cloudflare Tunnel exclusively** for that hostname, with nothing else able to reach the origin's listener at all.

If you also serve a **DNS-only (grey-cloud) hostname** for downloads (e.g. to bypass Cloudflare's timeout limits — see "Handling Large Files" below), route it to a **separate Traefik entrypoint/router that does not trust Cloudflare ranges for forwarded headers** (don't add `cloudflare` to the `TRUSTED_PROXY_IPS` an unproxied hostname's router uses). A grey-cloud hostname bypasses Cloudflare's edge by design, so nothing arriving there should ever be treated as Cloudflare-vouched-for.

When neither AOP nor Tunnel-exclusivity is in place, a request that actually came from a Worker is attributed to *the Worker's own egress IP* whenever it goes through Cloudflare's real proxy (the veto still does that much), but a Worker bypassing Cloudflare's proxy can, in principle, forge its way to any candidate the walk would otherwise produce. If you need to fully trust per-visitor attribution for Worker-adjacent traffic, put one of the two controls above in place; if you can't, treat `TRUSTED_PROXY_IPS=...,cloudflare` as "good enough to stop casual XFF spoofing of ordinary traffic," not as a hard security boundary against a determined Cloudflare-hosted attacker.

#### Configuration Examples

**Recommended (auto mode with default trusted IPs)**:
```bash
docker run -d \
  -e TRUST_PROXY_HEADERS=auto \
  -p 8080:8080 \
  safeshare:latest
```

This configuration:
- ✅ Trusts `X-Forwarded-For` from Traefik/nginx running on same host (127.0.0.1)
- ✅ Trusts headers from private network reverse proxies (10.x.x.x, 192.168.x.x)
- ❌ Rejects `X-Forwarded-For` from public internet IPs (prevents spoofing)

**Custom Trusted Proxy IPs**:
```bash
docker run -d \
  -e TRUST_PROXY_HEADERS=auto \
  -e TRUSTED_PROXY_IPS="10.0.0.0/8,172.16.0.0/12,203.0.113.10" \
  -p 8080:8080 \
  safeshare:latest
```

**Always Trust (behind a trusted single-hop proxy only)**:
```bash
# ⚠️ SECURITY WARNING: Only use if SafeShare is NOT directly exposed to the
# internet, and TRUSTED_PROXY_IPS covers every hop that can append to
# X-Forwarded-For (see "How It Works" above) -- "true" skips the RemoteAddr
# check, it does not skip the rightmost-untrusted walk.
# For Cloudflare specifically, prefer the auto mode + cloudflare keyword
# example above instead of this.
docker run -d \
  -e TRUST_PROXY_HEADERS=true \
  -p 8080:8080 \
  safeshare:latest
```

**Never Trust (direct internet exposure)**:
```bash
# Use when SafeShare is directly exposed to internet without reverse proxy
docker run -d \
  -e TRUST_PROXY_HEADERS=false \
  -p 8080:8080 \
  safeshare:latest
```

#### How It Works

**auto mode** (recommended):
1. Extract IP from `RemoteAddr` (direct connection source)
2. Check if source IP matches `TRUSTED_PROXY_IPS` ranges
3. If matched: Trust `X-Forwarded-For` and `X-Real-IP` headers
4. If not matched: Ignore proxy headers, use `RemoteAddr` directly

**true mode** (use with caution):
- Always trusts `X-Forwarded-For` and `X-Real-IP` headers, regardless of the
  immediate peer's address
- Still walks `X-Forwarded-For` the same way `auto` mode does (see below) —
  "true" changes *whether* headers are trusted, not *which entry* is picked
- Logs at debug level when a trusted peer sends no usable forwarded header

**false mode**:
- Never trusts proxy headers
- Always uses `RemoteAddr` for rate limiting and IP blocking
- Use when no reverse proxy is present

**Which `X-Forwarded-For` entry is used** (both `auto` and `true` modes,
once headers are trusted): SafeShare walks the header **from the right**
(the entries closest to it), skipping any entry that is itself a trusted
proxy per `TRUSTED_PROXY_IPS`, and returns the first entry that is not. This
matters because a proxy *appends* the peer it saw to the end of the chain —
so the rightmost entries were written by proxies in the request path, while
the **leftmost entry is whatever the original client sent and is therefore
attacker-controlled**. Trusting the leftmost entry (an earlier SafeShare
behavior, tracked as finding T41) let any client set its own apparent IP —
bypassing rate limits, IP blocks, and poisoning audit logs — simply by
sending its own `X-Forwarded-For` header through an otherwise-trusted proxy.
`X-Real-IP` is only consulted when `X-Forwarded-For` is absent entirely.

Local (operator-listed) trusted entries and the `cloudflare` keyword's
entries are **not** treated the same way while walking:

- Local entries may be skipped without limit — your own reverse proxy
  chain (e.g. an internal load balancer in front of Traefik) can be any
  number of hops, and SafeShare trusts every one of them equally because
  the operator vouches for all of them.
- **At most one** `cloudflare`-range entry may ever be skipped as a hop per
  request (or the direct connection itself, if there's no local reverse
  proxy between SafeShare and Cloudflare). The entry immediately after that
  one hop is always the client, full stop — even if it also happens to
  look like a Cloudflare or local trusted address. See "About the
  `cloudflare` keyword and Workers" above for why this asymmetry exists.

A chain that is trusted end-to-end with **no** Cloudflare hop involved
(e.g. a fully internal request that happens to pass through several of your
own proxies) still resolves to the leftmost entry, same as before T41 —
reaching that case already requires `RemoteAddr` itself, and every hop in
between, to match your own `TRUSTED_PROXY_IPS`, so keep that list as narrow
as your actual topology requires.

**Practical implication**: every hop between the client and SafeShare that
can legitimately add or forward an `X-Forwarded-For` entry must be listed in
`TRUSTED_PROXY_IPS` (or covered by the `cloudflare` keyword), including a
CDN/edge network in front of your reverse proxy. An untrusted intermediate
hop is treated as the real client for the entries to its right — see the
Cloudflare section below.

#### Security Impact

**Without proper configuration**, attackers can:
- Bypass IP-based rate limiting by spoofing `X-Forwarded-For` header
- Evade IP blocks by spoofing source IP
- Exhaust rate limits for legitimate users

**With auto mode and a complete `TRUSTED_PROXY_IPS` list**, SafeShare:
- Only accepts `X-Forwarded-For` entries appended after the last trusted hop
- Prevents IP spoofing from public internet, even through a trusted proxy
  chain (the leftmost, client-controlled entry is never used)
- Maintains accurate rate limiting and IP blocking

**Upgrade note**: if you deploy behind Cloudflare (or any proxy chain where
an intermediate hop is not listed in `TRUSTED_PROXY_IPS`), that hop's IP is
now what SafeShare sees as "the client" for every visitor, since it is the
first untrusted entry the rightmost walk finds. Add every such hop to
`TRUSTED_PROXY_IPS` — for Cloudflare, add the `cloudflare` keyword — or
every visitor will appear to come from the same IP, breaking per-IP rate
limiting and IP blocking.

#### Deployment Scenarios

**Scenario 1: Traefik/nginx on same host**
```bash
# Recommended: auto mode (default)
TRUST_PROXY_HEADERS=auto
# Traefik connects from 127.0.0.1 → trusted by default
```

**Scenario 2: Separate reverse proxy server**
```bash
# Reverse proxy at 10.0.1.5
TRUST_PROXY_HEADERS=auto
TRUSTED_PROXY_IPS="10.0.1.5,10.0.0.0/8"
```

**Scenario 3: Behind Cloudflare/CDN**
```bash
# Recommended: auto mode with Cloudflare's edge ranges added explicitly.
# This correctly resolves the real visitor IP (rightmost X-Forwarded-For
# entry after skipping Cloudflare's own hop) instead of treating every
# visitor as "Cloudflare" or trusting a client-supplied leftmost entry.
TRUST_PROXY_HEADERS=auto
TRUSTED_PROXY_IPS="127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,cloudflare"
```
`TRUST_PROXY_HEADERS=true` without the `cloudflare` keyword is no longer
recommended here: it trusts the header, but with no Cloudflare ranges in
`TRUSTED_PROXY_IPS` the rightmost-untrusted walk stops at the Cloudflare
edge IP (the first entry it doesn't recognize as a trusted proxy) — so every
visitor is logged and rate-limited as if they were Cloudflare itself.

**Scenario 4: Direct internet exposure**
```bash
# No reverse proxy
TRUST_PROXY_HEADERS=false
```

### Header Validation

Ensure your reverse proxy:

1. **Strips incoming X-Forwarded headers** from clients
2. **Sets its own X-Forwarded headers**
3. **Only accepts connections from trusted sources**
4. **Configure SafeShare's TRUST_PROXY_HEADERS appropriately**

### Example Traefik Security

Traefik automatically handles this correctly by default.

### Example nginx Security

> **Important**: use `$proxy_add_x_forwarded_for`, not `$remote_addr` or a
> pass-through of the client's own header. It must **append** nginx's own
> view of the connecting peer to the existing `X-Forwarded-For` value — the
> comment below says "strip", but the mechanism that actually matters for
> SafeShare's spoof resistance is nginx reliably appending its own hop, not
> deleting the client's. A config that instead relays the client's raw
> header unchanged (or that doesn't add nginx's own hop at all) makes
> nginx a hop that vouches for nothing, and SafeShare cannot then tell a
> genuine proxy hop from a client-forged one (see "How It Works" above).

```nginx
# nginx's own hop is appended by $proxy_add_x_forwarded_for below --
# this does NOT strip a client-forged X-Forwarded-For, it appends to it,
# which is what makes the appended (rightmost) entry trustworthy.
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
```

## Cloudflare Configuration

Cloudflare is a popular CDN that works well with SafeShare, but requires special configuration for large files.

### Basic Setup

Cloudflare acts as both CDN and reverse proxy. SafeShare is compatible with Cloudflare when properly configured.

**DNS Configuration:**
```
share.example.com     A    your-server-ip   (Proxied - orange cloud)
downloads.example.com A    your-server-ip   (DNS only - grey cloud)
```

**SafeShare Configuration:**
```bash
docker run -d \
  -e PUBLIC_URL=https://share.example.com \
  -e DOWNLOAD_URL=https://downloads.example.com \
  -e TRUST_PROXY_HEADERS=auto \
  -e TRUSTED_PROXY_IPS="127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,cloudflare" \
  safeshare:latest
```
The `cloudflare` keyword tells SafeShare which `X-Forwarded-For` hop belongs
to Cloudflare's edge network, so it can be skipped when resolving the real
visitor IP (see "How It Works" above). Without it, every visitor behind
Cloudflare is logged and rate-limited as the Cloudflare edge IP.

### Handling Large Files

Cloudflare has timeout limits that affect large file downloads:

| Plan | Timeout | Max File Impact |
|------|---------|----------------|
| Free/Pro | 100s | ~500MB @ 5MB/s |
| Business | 600s (configurable) | ~3GB @ 5MB/s |
| Enterprise | 6000s | Very large files |

**Solution: Bypass Cloudflare for Downloads**

1. Create `downloads.example.com` pointing to same server
2. Set to "DNS Only" (grey cloud) in Cloudflare
3. Configure `DOWNLOAD_URL` in SafeShare

Downloads will go directly to your server, bypassing Cloudflare's timeout.

### Upload Limits

| Cloudflare Plan | Max Upload Size |
|-----------------|----------------|
| Free | 100MB |
| Pro | 100MB |
| Business | 200MB |
| Enterprise | 500MB+ |

For larger uploads, either:
- Upgrade Cloudflare plan
- Create upload domain with DNS-only (bypasses Cloudflare)
- Use chunked uploads (works within limits)

### SSL/TLS Configuration

**Cloudflare SSL Settings:**
1. SSL/TLS mode: **Full (Strict)** (recommended)
2. Minimum TLS: **1.2**
3. Always Use HTTPS: **On**

**Origin Server:**
- Install SSL certificate on your server (Let's Encrypt)
- Or use Cloudflare Origin Certificate

### Cloudflare Page Rules

**Recommended Rules:**

1. **Cache Static Assets:**
   - URL: `share.example.com/assets/*`
   - Cache Level: Cache Everything
   - Edge Cache TTL: 1 day

2. **Bypass Cache for API:**
   - URL: `share.example.com/api/*`
   - Cache Level: Bypass

3. **Bypass Cache for Admin:**
   - URL: `share.example.com/admin/*`
   - Cache Level: Bypass
   - Security Level: High

### Real IP Configuration

Cloudflare appends the real client IP to `X-Forwarded-For` (it also sends it
separately in `CF-Connecting-IP`, which SafeShare does not currently read).

**Important:** When behind Cloudflare, add the `cloudflare` keyword to
`TRUSTED_PROXY_IPS` so SafeShare knows which hop is Cloudflare's edge and
resolves the real visitor IP instead of the edge IP:
```bash
-e TRUST_PROXY_HEADERS=auto
-e TRUSTED_PROXY_IPS="127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,cloudflare"
```

Cloudflare IPs are **not** trusted by default in `auto` mode — the
`cloudflare` keyword must be added explicitly (see "Trusted Proxy Security"
above for why it isn't a default). Without it, every visitor is logged and
rate-limited as the Cloudflare edge IP rather than their own.

### Cache Purging

After deploying updates, purge Cloudflare's cache:

**Manual:**
1. Cloudflare Dashboard → Caching → Configuration
2. Purge Cache → Purge Everything (or specific URLs)

**API:**
```bash
curl -X POST "https://api.cloudflare.com/client/v4/zones/ZONE_ID/purge_cache" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"files": ["https://share.example.com/assets/app.js"]}'
```

**Verify Cache Status:**
```bash
curl -sI https://share.example.com/assets/app.js | grep cf-cache-status
# HIT = cached, MISS = fresh from origin
```

### Security Features to Enable

| Feature | Setting | Purpose |
|---------|---------|--------|
| WAF | Managed Rules | Block common attacks |
| Bot Fight Mode | On | Protect against bots |
| Rate Limiting | Custom rules | Additional DoS protection |
| Browser Integrity Check | On | Block bad browsers |
| Challenge Passage | 30 minutes | Reduce friction |

### Troubleshooting

**524 Origin Timeout:**
- Download taking too long
- Solution: Use `DOWNLOAD_URL` with DNS-only subdomain

**Error 520:**
- Origin returned empty response
- Check SafeShare logs and health endpoint

**Error 522:**
- Connection timed out
- Verify server is running and firewall allows Cloudflare IPs

**Stale Assets:**
- Purge Cloudflare cache
- Try hard refresh (Ctrl+Shift+R)

---

## Complete Production Example (Traefik)

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.tlschallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@yourdomain.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    ports:
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - traefik-certs:/letsencrypt
    networks:
      - traefik-network

  safeshare:
    image: safeshare:latest
    environment:
      - PUBLIC_URL=https://share.yourdomain.com
      - MAX_FILE_SIZE=104857600
      - DEFAULT_EXPIRATION_HOURS=24
    volumes:
      - safeshare-data:/app/data
      - safeshare-uploads:/app/uploads
    networks:
      - traefik-network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.safeshare.rule=Host(`share.yourdomain.com`)"
      - "traefik.http.routers.safeshare.entrypoints=websecure"
      - "traefik.http.routers.safeshare.tls=true"
      - "traefik.http.routers.safeshare.tls.certresolver=letsencrypt"
      - "traefik.http.services.safeshare.loadbalancer.server.port=8080"

volumes:
  traefik-certs:
  safeshare-data:
  safeshare-uploads:

networks:
  traefik-network:
    name: traefik-network
```

Deploy:
```bash
docker-compose up -d
```

Test:
```bash
curl -X POST -F "file=@test.txt" https://share.yourdomain.com/api/upload
```
