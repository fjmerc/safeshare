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

### Header Validation

SafeShare trusts `X-Forwarded-*` headers. Ensure your reverse proxy:

1. **Strips incoming X-Forwarded headers** from clients
2. **Sets its own X-Forwarded headers**
3. **Only accepts connections from trusted sources**

### Example Traefik Security

Traefik automatically handles this correctly by default.

### Example nginx Security

```nginx
# Strip any X-Forwarded headers from client
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
```

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
