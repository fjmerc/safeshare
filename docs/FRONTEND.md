# SafeShare Frontend Documentation

## Overview

SafeShare includes an embedded web UI for uploading, sharing and picking up files, plus user and admin dashboards. The frontend is embedded directly into the Go binary (`//go:embed web/*` in `internal/static/static.go`), maintaining the single-binary deployment goal. It is plain HTML, CSS and vanilla JavaScript with no build step.

## Features

### Upload Interface (Dropoff tab)
- **Drag & drop** file upload, with a **Browse files** button as the keyboard-accessible fallback
- **Live file size validation**
- **Upload progress** (announced to screen readers as a progress bar)
- **Configurable expiration** (hours input with quick-select buttons from 1 hour up to 365 days)
- **Download limits** (number input; blank = unlimited)
- **Optional password** for the file
- **Optional end-to-end encryption** in the browser (`crypto.js`, available over HTTPS; see [E2E_ENCRYPTION.md](E2E_ENCRYPTION.md))
- **Chunked, resumable uploads** for large files (`chunked-uploader.js`; see [CHUNKED_UPLOAD.md](CHUNKED_UPLOAD.md)). The client retries timed-out chunks and keeps polling the status endpoint through rate limiting (`429`)

### Results Display
- Large, copyable **claim code**
- Full **download URL** with copy button
- **File details** (name, size, expiration, downloads)
- **QR code** for mobile sharing, generated client-side with the bundled `qrcode.min.js`
- One-click **copy to clipboard**
- When a password was set, a reminder that it isn't saved anywhere and can't be recovered

### Recent Uploads
Since v1.11.1 the upload page no longer shows a pop-up with saved claim codes.
- **Signed-in users**: nothing is stored in the browser; the success screen links to **My Uploads**, where every upload and claim code already lives.
- **Anonymous uploads** (when sign-in isn't required): a **Recent uploads on this device** list under the upload area, with copy-code, copy-link and remove buttons and a **Clear all** link. Each entry disappears when its file expires, and the list is cleared on logout.
- Claim codes saved by earlier versions are deleted on the next visit.

### Pickup Tab
1. Enter a claim code; the page calls `/api/claim/:code/info` and shows file metadata (name, size, downloads remaining, expiration).
2. Enter the password if the file needs one (sent in the request body, never the URL).
3. Download is handed to the browser's own download manager (v1.10.0), which saves straight to disk with its own progress, pause and resume. End-to-end encrypted files are still decrypted in the page, which needs the whole file in memory.

### User Experience
- **Dark/Light mode**: follows the operating system setting until you pick a theme, then persists the choice in `localStorage` (`theme-init.js` applies it before first paint)
- **Responsive design**, checked from 320px phones to desktop; dashboards' tables become stacked cards on small screens
- **Accessibility**: labelled form fields, visible focus outlines, arrow-key navigation in tab lists, WCAG AA contrast in both themes, and 44px minimum touch targets
- **Accessible dialogs** (`dialogs.js`): any modal becoming visible is marked `role="dialog"` / `aria-modal`, labelled by its heading, receives focus, traps Tab, closes on Escape (unless it has no close button or sets `data-modal-no-escape`), and returns focus when closed
- **Accessible toasts** (`toast.js`): `showToast(message, type, duration)` messages are also announced through ARIA live regions (errors and warnings immediately)
- **Installable PWA**: `manifest.json` and `service-worker.js` (see Service Worker below), including a Web Share Target for sharing files from the OS share sheet

## Admin Dashboard

SafeShare includes an admin dashboard for file, user and system management. It is **disabled by default**; enable it by setting `ADMIN_USERNAME` and `ADMIN_PASSWORD`.

### Authentication
- Login page with username/password (`/admin/login`)
- Session management with configurable expiration
- CSRF protection on all state-changing operations
- Rate-limited login (5 attempts per 15 minutes)
- Auto-logout on session expiration

### Tabs
The dashboard (`dashboard.html`) has eleven tabs, with real-time statistics cards above them:

| Tab | Purpose |
|-----|---------|
| Files | All uploaded files with search, pagination, delete |
| Users | Create, edit, enable/disable, reset password, delete |
| Blocked IPs | IP blocklist (add with reason, unblock) |
| Enterprise Features | Runtime feature flags |
| Webhooks | Webhook configurations and delivery history |
| SSO Providers | OIDC providers and user SSO links |
| API Tokens | All users' tokens with usage stats; revoke, bulk revoke, bulk extend |
| Backups | List, create, verify, restore, download, delete backups |
| Audit Log | Filter, page, export (CSV/JSON Lines) and verify the tamper-evident log; adjust retention |
| Settings | Storage quota, security settings, password change, system info |
| Configuration Assistant | Recommends timeouts, chunk size and limits for your environment |

The admin tab list supports arrow-key navigation. Destructive actions use confirmation dialogs.

### File Structure

```
internal/static/
├── static.go                  # Go embed handler
└── web/
    ├── index.html             # Main page (Dropoff / Pickup)
    ├── login.html             # User sign-in (including the two-factor step)
    ├── dashboard.html         # User dashboard (My Uploads, API Tokens, Security, SSO Linked Accounts)
    ├── error.html             # Error page
    ├── service-worker.js      # PWA service worker (CACHE_VERSION)
    ├── assets/
    │   ├── style.css          # Shared styles, theme tokens, dark mode
    │   ├── theme-init.js      # Applies saved/OS theme before first paint
    │   ├── error-theme-toggle.js
    │   ├── app.js             # Main page logic (upload, pickup, recent uploads)
    │   ├── chunked-uploader.js# Chunked/resumable upload client
    │   ├── crypto.js          # Client-side end-to-end encryption
    │   ├── qrcode.min.js      # Bundled QR code library (no CDN)
    │   ├── dialogs.js         # Accessible modal behavior
    │   ├── toast.js           # Toast notifications and ARIA live regions
    │   ├── login.js           # Login page logic
    │   ├── dashboard.js       # User dashboard logic
    │   ├── manifest.json      # PWA manifest
    │   ├── logo.svg, favicon*, android-chrome-*, apple-touch-icon.png
    └── admin/
        ├── login.html         # Admin login page
        ├── dashboard.html     # Admin dashboard (eleven tabs)
        └── assets/
            ├── admin.css      # Dashboard styles
            ├── admin.js       # Dashboard logic
            └── admin-login.js # Admin login logic
```

### Admin API Endpoints
The dashboard talks to the `/admin/api/...` endpoints documented in [API_REFERENCE.md](API_REFERENCE.md). Public routes are `GET /admin/login` and `POST /admin/api/login`; everything else requires an admin session, and state-changing requests also require a CSRF token (`X-CSRF-Token`).

### Access URLs
- Main app: `http://localhost:8080/`
- Admin login: `http://localhost:8080/admin/login`
- Admin dashboard: `http://localhost:8080/admin/dashboard`

## Technical Stack

| Component | Technology |
|-----------|-----------|
| HTML | Semantic HTML5 |
| CSS | Pure CSS with Grid/Flexbox and CSS custom properties |
| JavaScript | Vanilla ES6+ (no frameworks) |
| QR Code | `qrcode.min.js`, bundled locally |

### Why This Stack?

1. **No build tools required** - Simple deployment
2. **Fast loading** - Minimal overhead, static assets embedded in the binary
3. **Works offline for the app shell** - the service worker caches the page and its assets after the first visit
4. **Easy to customize** - Plain HTML/CSS/JS
5. **Security-focused** - No third-party scripts; the default Content-Security-Policy is `script-src 'self'`

## Usage

### Accessing the UI

```
http://localhost:8080/
```

### Upload Workflow

1. **Select file**: drag and drop onto the upload zone, or use Browse files
2. **Configure** (optional): expiration (default 24 hours), download limit, password, end-to-end encryption
3. **Upload**: click "Upload File" and watch the progress bar
4. **Share**: copy the claim code or download URL, or scan the QR code

### Download Workflow

Recipients can download in two ways:

1. **Via web UI**: use the Pickup tab, or visit the download URL directly
2. **Via API**: use the `/api/claim/:code` endpoint with curl, wget, or any HTTP client

## Customization

### Changing Colors

All colors come from CSS custom properties ("theme tokens") at the top of `internal/static/web/assets/style.css`: the `:root` block for the light theme and a dark-theme override block. Main tokens:

```css
:root {
    --primary-color: #2563eb;   /* fills behind white text; --primary-hover, --primary-text, --primary-tint */
    --success-color: #047857;   /* plus --success-hover/-text/-tint */
    --danger-color: #dc2626;    /* plus --danger-hover/-text/-tint */
    --warning-color: #b45309;   /* plus --warning-text/-tint */
    --bg-primary: #ffffff;      /* --bg-secondary, --bg-tertiary */
    --text-primary: #111827;    /* --text-secondary, --text-muted */
    --border-color: #e5e7eb;    /* decorative dividers */
    --border-strong: #6b7280;   /* form controls */
    --focus-ring: #2563eb;
}
```

When changing colors, keep text/background pairs at WCAG AA contrast (4.5:1) in both themes.

### Changing Branding

Edit `internal/static/web/index.html` (title and tagline) and replace `assets/logo.svg`, the favicons and the `android-chrome-*` / `apple-touch-icon` images.

### Service Worker and Cache Version

The service worker (`service-worker.js`) serves static files cache-first. **Any change to HTML, JS or CSS under `internal/static/web/` requires bumping `CACHE_VERSION`** in `service-worker.js` (for example `safeshare-v79` to `safeshare-v80`); otherwise browsers keep serving the old cached files. New assets that should work offline must also be added to its `STATIC_ASSETS` list. The service worker never intercepts `/api/`, `/admin/`, `/health` or `/metrics`.

If SafeShare is behind a CDN, purge its cache for the changed assets after deploying.

### Disabling Frontend

To run API-only mode (no frontend):

1. Remove the static routes from `cmd/safeshare/main.go`
2. Remove the static import
3. Rebuild

Or simply use the API endpoints directly and ignore the UI.

## Browser Compatibility

| Browser | Version | Support |
|---------|---------|---------|
| Chrome | 90+ | Full |
| Firefox | 88+ | Full |
| Safari | 14+ | Full |
| Edge | 90+ | Full |
| Mobile Safari | iOS 14+ | Full |
| Chrome Mobile | Android 10+ | Full |

## Features in Detail

### Dark Mode

Follows the OS setting until the user chooses a theme with the toggle in the header; the choice is saved in `localStorage` (`theme`).

### QR Code

Generated client-side with the bundled `qrcode.min.js` (served from `/assets/`, no CDN or third-party request). The QR code contains the full download URL.

### Copy to Clipboard

Uses the `navigator.clipboard` API with a fallback for older browsers and non-HTTPS contexts. The button shows a checkmark briefly after copying.

### File Size Validation

Client-side validation warns before uploading files that exceed server limits; the server enforces them.

### Upload Progress

Progress is reported with XMLHttpRequest progress events (simple uploads) or per-chunk completion (chunked uploads).

## API Integration

The main page uses these endpoints (see [API_REFERENCE.md](API_REFERENCE.md) and [CHUNKED_UPLOAD.md](CHUNKED_UPLOAD.md)):

- `GET /api/config` - public configuration (limits, chunk settings, feature flags)
- `POST /api/upload` - simple upload (multipart: `file`, `expires_in_hours`, `max_downloads`, optional password)
- `POST /api/upload/init`, `/api/upload/chunk/:id/:num`, `/api/upload/complete/:id`, `GET /api/upload/status/:id` - chunked upload
- `GET /api/claim/:code/info`, `/api/claim/:code` - pickup

## Security Considerations

### CSP (Content Security Policy)

`internal/middleware/security.go` sets a strict policy on every response: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`. Because `script-src` is `'self'`, no inline scripts or third-party scripts can be added to the pages; put new JavaScript in files under `assets/`.

### HTTPS Only

Always run behind a reverse proxy with HTTPS in production (end-to-end encryption and the PWA features also need a secure context).

### Input Validation and XSS

- Validation happens on both client and server (file size, parameters; file type is validated by the server)
- Dynamic content is inserted with `textContent` or escaped before `innerHTML`

## Troubleshooting

### Frontend doesn't load

1. Check the server is running: `curl http://localhost:8080/health`
2. Check logs: `docker logs safeshare`
3. Check the browser console for errors

### Frontend shows old content after an upgrade

The frontend is embedded at compile time, and the service worker caches it. Rebuild/pull the new image, make sure `CACHE_VERSION` was bumped, and (if behind a CDN) purge the CDN cache. A hard refresh does not clear a CDN cache.

### Upload fails

Common causes: file too large (`MAX_FILE_SIZE`), a stalled connection (`408 UPLOAD_TIMEOUT`), disk full or quota exceeded (`507`). See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

### Dark mode doesn't persist

`localStorage` may be disabled; check the browser's privacy settings.

## Future Enhancements

Not implemented:

- [ ] Multi-file upload (batch)
- [ ] Compression before upload
- [ ] Email notification option
- [ ] Custom expiration dates/times
- [ ] File preview (images/PDFs)

(Password-protected files, resumable chunked uploads and a client-side recent-uploads list are already implemented.)

## Development

### Local Development

Frontend files are embedded at compile time, so changes need a rebuild (or run the binary/Docker image again). For quick iteration you can serve `internal/static/web` with a static file server, but API calls then need to point at a running backend.

### Building

```bash
go build -o safeshare ./cmd/safeshare
```

No separate frontend build step is needed.

## License

Same as main project (MIT).
