# Verifying a SafeShare Server and Release

Browser end-to-end encryption runs in JavaScript that the server sends. If the server, or something between it and you, sends altered code, that code could leak keys or files before they are encrypted. SafeShare can't prevent that, but from v1.17.0 on it makes it detectable:

- each release publishes the SHA-256 of every web page and script (`web-assets.sha256`);
- `safeshare-cli verify <url>` compares what a running server sends with those hashes;
- the server binaries in the Docker image rebuild byte-for-byte from the release's source, so you can check the image, not only the source.

If you can't trust any served JavaScript, don't use the browser: `safeshare-cli` and the SDKs encrypt on your own machine (see [E2E_ENCRYPTION.md](E2E_ENCRYPTION.md#command-line-tool-and-sdks)).

## Checking a running server

```bash
safeshare-cli verify https://share.example.com

# Over Tor (the release download from GitHub goes through Tor too)
safeshare-cli verify --proxy socks5://127.0.0.1:9050 http://example.onion
```

The command reads the version the server reports, downloads that release's `web-assets.sha256` from GitHub, fetches each page and script from the server, and compares. It sends no API token or cookies.

| Result | Meaning |
|--------|---------|
| `VERIFIED` (exit 0) | Every page and script the server sent matches the release. |
| `NOT VERIFIED` (exit 2) | At least one file differs. It was changed on the server or on the way. Don't use this server's in-browser encryption. |
| `COULD NOT VERIFY` (exit 1) | Something couldn't be fetched (network error, a redirect, a challenge page, a 404). Nothing differed, but the check is incomplete. |

Per file you may also see:

- `not served`: a 404 for something the server only serves with some settings (the admin pages when there is no admin, the app manifest in Ghost mode). Visitors can't load it either, so it is fine.
- `not checked`: pages that need a login (`/dashboard`, `/admin/dashboard`) and the error page, which is filled in for each error. Their scripts are still checked.

The service worker has two genuine versions: the normal one and, in Ghost mode, a small script that removes it. Either matches.

Options:

- `--version 1.17.0` compares against a release other than the one the server reports. The reported version comes from the server (operators can set it with `APP_VERSION`), so it is only a hint. The command always says which release it compared against, and warns when that is not the latest: a server can serve an old, genuine release that has known security problems.
- `--manifest web-assets.sha256` uses a file instead of downloading it, for example one you made yourself (below), or for releases before v1.17.0, which don't publish one.
- `--all` lists every file, not only the ones that didn't match.

### What it can't tell you

- **It checks what the server sent to you, then.** A compromised server that recognises the check (by address, timing, or the client) can send other visitors, or you on another visit, different code. Run it over the same network path as the browser (for a `.onion`, over Tor), and more than once.
- **A CDN that rewrites pages fails the check.** Cloudflare Web Analytics (which adds its `beacon.min.js` script to pages), Rocket Loader, Email Address Obfuscation, Automatic HTTPS Rewrites and similar features change the HTML, so the check reports a mismatch. That is correct: the page visitors get is not the released one. Turn those features off for SafeShare to pass. Some of them only rewrite requests that look like a browser opening a page, so the check asks for pages the way a browser does. A Tor `.onion` address bypasses any CDN.
- **It only partly checks response headers.** It warns when the page's Content Security Policy lets scripts load from anywhere other than the server itself (SafeShare sends `script-src 'self'`). A reverse proxy that replaces the policy with a looser one, such as one allowing `'unsafe-inline'` or a public CDN, lets injected scripts run that these hashes don't cover. Other headers aren't checked.
- **It trusts GitHub and the CLI.** The hashes come from the GitHub release over HTTPS. Build `safeshare-cli` yourself from source, or make the hash list from a checkout you reviewed:

```bash
git clone https://github.com/fjmerc/safeshare && cd safeshare
git checkout v1.17.0
scripts/web-asset-hashes.sh > /tmp/web-assets.sha256
diff /tmp/web-assets.sha256 <(curl -sL https://github.com/fjmerc/safeshare/releases/download/v1.17.0/web-assets.sha256)
safeshare-cli verify https://share.example.com --manifest /tmp/web-assets.sha256
```

The web files are embedded in the server exactly as they are in the source tree (`internal/static/web/`), so the hashes don't depend on how the server was built.

### Checking by hand

Without the CLI, fetch a file and compare its hash with the release's list. `index.html` is served at `/`, everything under `assets/` at `/assets/...`:

```bash
curl -s https://share.example.com/assets/crypto.js | sha256sum
grep ' assets/crypto.js$' web-assets.sha256

# Pages: ask like a browser, or a CDN may send you a different page than visitors get
curl -s -H 'Accept: text/html' https://share.example.com/ | sha256sum
grep ' index.html$' web-assets.sha256
```

## Checking a Docker image

The server binaries are built with `-trimpath -buildvcs=false` and no timestamps, so the same source and Go version give identical bytes. Each release's CI rebuilds the binaries from the tag, outside Docker, and checks they match the pushed image for both linux/amd64 and linux/arm64 before publishing their hashes as `binaries.sha256`. Every pull request checks linux/amd64 the same way; linux/arm64 is checked at release, after the image is pushed, so a release without `binaries.sha256` didn't pass the check.

To check yourself (needs Docker):

```bash
git checkout v1.17.0
scripts/verify-image.sh fjmerc/safeshare:1.17.0
```

It pulls the image, copies out `safeshare`, `import-file` and `migrate-encryption` for each architecture, rebuilds them from your checkout in the official `golang` image for the Go version in `go.mod`, and prints `REPRODUCED` if they are identical. `--local-go` builds with the `go` on your PATH instead (it must be the same version), and `linux/amd64` or `linux/arm64` limits it to one architecture. If Docker can't see `/tmp`, set `TMPDIR` to a directory it can.

Only the binaries are reproducible, not the whole image: its Alpine packages (CA certificates, time zone data) are installed at build time and change as Alpine updates them, so the image digest differs between builds.
