# Tor Hidden Service Deployment

Deploy SafeShare as a Tor hidden service (.onion address) for maximum anonymity. Neither the operator nor users can be identified by network analysis.

## Prerequisites

- Docker and Docker Compose installed
- Basic familiarity with Tor hidden services
- A Linux host (recommended: Debian/Ubuntu)

## Quick Start with Docker Compose

The simplest deployment uses SafeShare + a Tor sidecar container. The Tor container creates and manages the hidden service automatically.

```yaml
# docker-compose.tor.yml
services:
  safeshare:
    image: safeshare:latest
    environment:
      - ANONYMOUS_MODE=true
      - STRIP_METADATA=true
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - TRUST_PROXY_HEADERS=false
      - PUBLIC_URL=http://${ONION_ADDRESS}
      - ADMIN_USERNAME=${ADMIN_USERNAME}
      - ADMIN_PASSWORD=${ADMIN_PASSWORD}
    volumes:
      - safeshare-data:/app/data
      - safeshare-uploads:/app/uploads
    # IMPORTANT: No port exposure — only accessible via Tor
    networks:
      - tor-net

  tor:
    image: goldy/tor-hidden-service
    environment:
      SERVICE1_TOR_SERVICE_HOSTS: "80:safeshare:8080"
      SERVICE1_TOR_SERVICE_VERSION: "3"
    volumes:
      - tor-keys:/var/lib/tor/hidden_service
    networks:
      - tor-net

volumes:
  safeshare-data:
  safeshare-uploads:
  tor-keys:

networks:
  tor-net:
    driver: bridge
```

### Step 1: Generate an encryption key

```bash
export ENCRYPTION_KEY=$(openssl rand -hex 32)
echo "ENCRYPTION_KEY=$ENCRYPTION_KEY" >> .env
echo "ADMIN_USERNAME=admin" >> .env
echo "ADMIN_PASSWORD=$(openssl rand -base64 16)" >> .env
```

**Save the encryption key securely.** Lost key = lost files (no recovery possible).

### Step 2: Start the services

```bash
docker compose -f docker-compose.tor.yml up -d
```

### Step 3: Get your .onion address

The first startup takes 30-60 seconds while Tor generates your hidden service keys.

```bash
docker compose -f docker-compose.tor.yml exec tor cat /var/lib/tor/hidden_service/hostname
```

This prints your `.onion` address (e.g., `abc123...xyz.onion`).

### Step 4: Set the PUBLIC_URL

Update your `.env` file with the onion address:

```bash
echo "ONION_ADDRESS=$(docker compose -f docker-compose.tor.yml exec tor cat /var/lib/tor/hidden_service/hostname)" >> .env
docker compose -f docker-compose.tor.yml up -d  # Restart with PUBLIC_URL set
```

### Step 5: Verify

Open Tor Browser and navigate to your `.onion` address. You should see the SafeShare upload page.

## SafeShare Configuration for Tor

These environment variables are recommended for Tor deployments:

| Variable | Value | Why |
|----------|-------|-----|
| `ANONYMOUS_MODE` | `true` | Prevents IP storage in database and logs |
| `STRIP_METADATA` | `true` | Removes EXIF/GPS data and document author info from uploads |
| `TRUST_PROXY_HEADERS` | `false` | Tor connections are direct, not proxied |
| `PUBLIC_URL` | `http://<onion>.onion` | Ensures correct download URLs |
| `ENCRYPTION_KEY` | 64-char hex | Encrypts files at rest on disk |
| `REQUIRE_AUTH_FOR_UPLOAD` | `true` (optional) | Limits uploads to registered users |

## Security Hardening Checklist

- [ ] **Enable `ANONYMOUS_MODE=true`** — IPs never written to database or logs
- [ ] **Enable `STRIP_METADATA=true`** — Uploaded files scrubbed of identifying metadata
- [ ] **Set a strong `ENCRYPTION_KEY`** — 64 hex chars, generated with `openssl rand -hex 32`
- [ ] **Do NOT expose port 8080** — SafeShare should only be reachable through Tor
- [ ] **Do NOT use a reverse proxy that logs IPs** — defeats the purpose of Tor
- [ ] **Use a strong admin password** — generated, not guessable
- [ ] **Keep Tor keys backed up** — losing `tor-keys` volume means losing your .onion address
- [ ] **Consider client-side encryption** — for maximum protection, even a compromised server cannot read files
- [ ] **Disable Docker logging** if you need full deniability:
  ```yaml
  services:
    safeshare:
      logging:
        driver: "none"
    tor:
      logging:
        driver: "none"
  ```

## Manual Tor Setup (Without Docker)

If you prefer to run Tor natively:

### 1. Install Tor

```bash
# Debian/Ubuntu
sudo apt install tor

# Fedora
sudo dnf install tor
```

### 2. Configure the hidden service

Edit `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/safeshare/
HiddenServicePort 80 127.0.0.1:8080
```

### 3. Start Tor

```bash
sudo systemctl enable --now tor
```

### 4. Get your .onion address

```bash
sudo cat /var/lib/tor/safeshare/hostname
```

### 5. Run SafeShare

```bash
docker run -d \
  --name safeshare \
  -p 127.0.0.1:8080:8080 \
  -e ANONYMOUS_MODE=true \
  -e STRIP_METADATA=true \
  -e TRUST_PROXY_HEADERS=false \
  -e PUBLIC_URL="http://$(sudo cat /var/lib/tor/safeshare/hostname)" \
  -e ENCRYPTION_KEY="$(cat /path/to/encryption.key)" \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD="$(cat /path/to/admin.password)" \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  safeshare:latest
```

Note: Bind to `127.0.0.1:8080` (not `0.0.0.0:8080`) so SafeShare is only reachable via Tor, not directly from the network.

## Verification

### Confirm the hidden service is working

1. Open **Tor Browser**
2. Navigate to your `.onion` address
3. You should see the SafeShare upload page
4. Upload a test file and verify the claim code URL uses your `.onion` address

### Confirm no IP leakage

```bash
# Check SafeShare logs — should show "redacted" not real IPs
docker logs safeshare 2>&1 | grep -i "ip\|address"

# If ANONYMOUS_MODE is working, you'll see "redacted" instead of IPs
```

### Confirm metadata stripping

1. Upload a JPEG with GPS data through Tor Browser
2. Download it and check with `exiftool` — GPS/EXIF data should be removed

## Performance Considerations

| Factor | Impact | Mitigation |
|--------|--------|------------|
| **Latency** | Tor adds 200-500ms per hop (3 hops = 0.6-1.5s) | Expected — no mitigation needed |
| **Throughput** | Tor circuits typically sustain 1-5 MB/s | Set reasonable file size limits |
| **Large files** | Uploads >100MB may time out or be slow | Consider increasing `READ_TIMEOUT` and `WRITE_TIMEOUT` |
| **Chunked uploads** | Work normally over Tor | Smaller chunk sizes (5MB) may be more reliable |

### Recommended timeout settings for Tor

```yaml
environment:
  - READ_TIMEOUT=300    # 5 minutes
  - WRITE_TIMEOUT=300   # 5 minutes
```

## Backup Considerations

- **Back up the `tor-keys` volume** — this contains your hidden service private key. Losing it means losing your .onion address permanently.
- **Back up SafeShare data** as usual (see `docs/BACKUP_RESTORE.md`)
- Store backups encrypted and off-site

## Threat Model

| Threat | Protected? | Notes |
|--------|-----------|-------|
| Network observer sees server IP | Yes | Tor hides the server's real IP |
| Network observer sees user IP | Yes | Tor hides the user's real IP |
| Server operator identifies uploaders | Yes (with `ANONYMOUS_MODE`) | No IPs stored |
| File metadata reveals identity | Yes (with `STRIP_METADATA`) | EXIF/author data stripped |
| Server compromise reveals file contents | Partial | Server-side encryption protects at rest; client-side encryption provides full protection |
| Correlation attacks (timing) | Partial | Tor provides some protection; high-traffic services are harder to correlate |

## Troubleshooting

### Hidden service not reachable
- Check Tor logs: `docker compose -f docker-compose.tor.yml logs tor`
- Ensure the `tor-net` network connects both containers
- Wait 60-90 seconds after first start for Tor to establish circuits

### Downloads show wrong URL
- Verify `PUBLIC_URL` is set to your `.onion` address
- Include `http://` prefix (not `https://` — Tor already encrypts end-to-end)

### Slow uploads/downloads
- Increase `READ_TIMEOUT` and `WRITE_TIMEOUT` to 300+ seconds
- Reduce `CHUNK_SIZE` to 5MB for more reliable chunked uploads
- Tor throughput varies — retry at different times of day

### Lost .onion address
- If the `tor-keys` volume is deleted, the address is gone permanently
- Generate a new one and redistribute the new address
