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
| `MAX_ENCRYPTED_DOWNLOADS_PER_IP` | `0` (disabled), or a value sized to expected concurrent visitors | See below — the default of 8 applies per *apparent* IP, and every Tor visitor shares the same one |

### `MAX_ENCRYPTED_DOWNLOADS_PER_IP` and hidden services

SafeShare bounds how many encrypted (password-protected or server-side-encrypted) downloads a single client IP may have in flight at once (default 8), *and* how much of the shared decrypt-memory budget one client may use concurrently (a quarter of `DOWNLOAD_DECRYPT_MEMORY_BUDGET`) — both to stop one client from monopolizing server resources (see `docs/HTTP_RANGE_SUPPORT.md`'s "Encrypted-Download Admission Control"). Over a Tor hidden service — or behind any reverse proxy `TRUST_PROXY_HEADERS=false` doesn't see through — every visitor's connection to SafeShare arrives from the *same* local address (the Tor daemon or proxy forwarding to the app), not their own. Both limits therefore apply to **all Tor visitors combined**, not per real visitor: the 9th concurrent encrypted download from *any* two different Tor users gets rejected with `429 TOO_MANY_INFLIGHT`, and (independently) two Tor visitors' downloads together could get capped at a single quarter-share of the memory budget.

This is the same reason `TRUST_PROXY_HEADERS=false` is recommended above (a hidden service has no meaningful per-visitor IP to trust in the first place) — both caps have an identical blind spot, because both are keyed by apparent client address. Either:

- **Set `MAX_ENCRYPTED_DOWNLOADS_PER_IP=0`** to disable *both* the per-IP concurrency cap and the per-client memory-budget share — `0` means no per-client limits of either kind; only the global `DOWNLOAD_DECRYPT_MEMORY_BUDGET` ceiling still bounds aggregate decrypt memory across all downloads combined. This doesn't remove protection — it removes the *per-visitor* accounting that Tor makes meaningless, while keeping the one limit (the global budget) that's still meaningful regardless of how many visitors share an apparent address. Or,
- **Raise `MAX_ENCRYPTED_DOWNLOADS_PER_IP`** to a value sized for your expected number of concurrent Tor visitors, if you'd still like some ceiling (both concurrency and memory share) on how much of the shared budget flows through this one apparent address.

This limitation is inherent to not being able to distinguish visitors behind a single forwarding point — it applies equally to any non-Tor deployment sitting behind a proxy that doesn't forward (or isn't trusted to forward) real client IPs.

### Login lockout and hidden services

The same blind spot applies to the admin and user login lockout (5 failed password attempts per 15 minutes, per apparent client IP — see `docs/SECURITY.md`). Because every Tor visitor's connection arrives from the same local address, the lockout is effectively shared by every visitor combined, not per real person: five failed login attempts from *any* combination of Tor visitors locks *all* Tor visitors out of admin or user password login for 15 minutes.

**What's changed:** a successful login only refunds that one request's own reservation now, instead of counting toward the limit — it does not reset the whole counter (an earlier version of this fix did a full reset; that turned out to be exploitable by anyone who already controls one account on the shared address, so it was changed to a refund - see `docs/CHANGELOG.md`'s `[Unreleased]` entry). Accidental collateral lockout from ordinary use (several visitors simply logging in one after another) can no longer happen the way it used to; it now takes several *actual* failed attempts within the window, from any mix of visitors, to trip the lockout, and a lockout lasts exactly 15 minutes from the last failed attempt that counted (a rejected, already-locked-out attempt doesn't itself extend that window).

A per-username (per-account) limit, independent of the shared apparent IP, was prototyped for this release and then removed: a security audit found the throttle itself could be turned into a denial of service against a chosen account (an attacker requesting faster than the throttle's per-attempt delay could keep that account's login rejected indefinitely, including for its legitimate owner - see `docs/CHANGELOG.md`'s `[Unreleased]` entry for the full explanation). Login lockout is per-IP only for now.

**What hasn't changed:** the per-IP lockout still has no way to distinguish individual Tor visitors sharing the hidden service's single apparent address, so five genuine failed attempts from any mix of visitors — malicious or just several people mistyping a password back-to-back — still locks out everyone behind that address for 15 minutes. This remains a known limitation, not something `MAX_ENCRYPTED_DOWNLOADS_PER_IP`-style tuning can work around.

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
