# SafeShare Frontend Documentation

## Overview

SafeShare now includes a modern, embedded web UI that provides an intuitive interface for file uploads and sharing. The frontend is embedded directly into the Go binary, maintaining the single-binary deployment goal.

## Features

### Upload Interface
- ✅ **Drag & drop** file upload
- ✅ **Click to browse** fallback
- ✅ **Live file size validation**
- ✅ **Upload progress indicator**
- ✅ **Configurable expiration** (quick select: 1h, 24h, 48h, 7d)
- ✅ **Download limits** (quick select: once, 5x, 10x, unlimited)

### Results Display
- ✅ **Large, copyable claim code**
- ✅ **Full download URL** with copy button
- ✅ **File details** (name, size, expiration, downloads)
- ✅ **QR code generation** for mobile sharing
- ✅ **One-click copy** to clipboard

### User Experience
- ✅ **Dark/Light mode** toggle with persistence
- ✅ **Responsive design** (mobile, tablet, desktop)
- ✅ **Modern, clean interface**
- ✅ **Accessibility features** (ARIA labels, keyboard navigation)
- ✅ **Smooth animations** and transitions

## Admin Dashboard

SafeShare includes a comprehensive admin dashboard for file and user management.

### Features

#### Authentication
- ✅ **Secure login page** with username/password
- ✅ **Session management** with configurable expiration
- ✅ **CSRF protection** on all operations
- ✅ **Rate-limited login** (5 attempts per 15 minutes)
- ✅ **Auto-logout** on session expiration

#### Dashboard Interface
- ✅ **Three-tab navigation** (Files, Blocked IPs, Settings)
- ✅ **Real-time statistics** cards
- ✅ **Responsive design** for desktop and tablet
- ✅ **Modern table views** with sorting and pagination
- ✅ **Search and filter** capabilities
- ✅ **Confirmation modals** for destructive actions

#### Files Management
- ✅ **View all uploaded files** with full metadata
- ✅ **Search** by claim code, filename, or uploader IP
- ✅ **Pagination** (20 files per page)
- ✅ **Delete files** before expiration
- ✅ **Password protection indicator**
- ✅ **Download count tracking**

#### IP Blocking
- ✅ **Block IP addresses** from uploads/downloads
- ✅ **Custom blocking reason** field
- ✅ **View all blocked IPs** in table
- ✅ **Unblock with one click**
- ✅ **Automatic enforcement** on all endpoints

#### Settings
- ✅ **Dynamic quota adjustment** (no restart required)
- ✅ **Real-time percentage updates**
- ✅ **System information** display

#### Recent Improvements
- ✅ **Username tracking**: File listings now show which user uploaded each file (SQL JOIN with users table)
- ✅ **Async confirmations**: All destructive operations use async/await confirmation dialogs for smoother UX
- ✅ **Enhanced date formatting**: Compact format (e.g., "Nov 5 @ 7:00 PM") saves table space
- ✅ **Improved form controls**: Better styling for inputs, selects, and form layouts with enhanced focus states
- ✅ **Better table display**: Improved column alignment, consistent spacing, and visual hierarchy
- ✅ **Dynamic storage quota updates**: Settings API accepts `quota_gb` parameter for runtime updates
- ✅ **Universal dark mode**: Theme toggle persists across all pages (dashboard, login, admin) using localStorage
- ✅ **Cross-browser clipboard**: Fallback to execCommand for HTTP contexts when Clipboard API unavailable

### User Interface

**Login Page** (`/admin/login`):
- Clean, centered login form
- Username and password fields
- Modern gradient background
- Error message display
- Responsive layout

**Dashboard** (`/admin/dashboard`):
- Header with logout button
- Four stat cards (Files, Storage, Quota, Blocked IPs)
- Tab navigation
- Content area with tables and forms
- Footer information

**Color Scheme**:
- Primary: `#2563eb` (Blue)
- Danger: `#dc2626` (Red)
- Success: `#16a34a` (Green)
- Background: `#f9fafb` (Light gray)
- Text: `#111827` (Dark gray)

### File Structure

```
internal/static/web/admin/
├── login.html              # Login page
├── dashboard.html          # Main dashboard
└── assets/
    ├── admin.css          # Dashboard styles (~8KB)
    └── admin.js           # Dashboard logic (~10KB)
```

### Technical Implementation

**JavaScript Features**:
- Vanilla JavaScript (no frameworks)
- Fetch API for AJAX requests
- Cookie-based session management
- CSRF token handling
- Client-side pagination
- Search debouncing (500ms)
- Confirmation dialogs
- Error handling and user feedback

**CSS Features**:
- CSS Grid for layouts
- Flexbox for components
- Responsive tables
- Modal overlays
- Hover effects
- Smooth transitions

**Security**:
- HttpOnly session cookies
- SameSite cookie attribute
- CSRF token validation
- XSS prevention (innerHTML escaping)
- Input sanitization

### API Endpoints

**Public** (no auth):
- `GET /admin/login` - Login page
- `POST /admin/api/login` - Authentication

**Protected** (requires session):
- `GET /admin/dashboard` - Dashboard page
- `GET /admin/api/dashboard` - Dashboard data
- `POST /admin/api/logout` - Logout

**Protected + CSRF** (requires session + token):
- `POST /admin/api/files/delete` - Delete file
- `POST /admin/api/ip/block` - Block IP
- `POST /admin/api/ip/unblock` - Unblock IP
- `POST /admin/api/quota/update` - Update quota

### Access Control

Admin dashboard is **disabled by default**. Enable by setting:

```bash
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="secure_password_123"
```

**URL Access**:
- Main app: `http://localhost:8080/`
- Admin login: `http://localhost:8080/admin/login`
- Admin dashboard: `http://localhost:8080/admin/dashboard`

### Browser Support

Same as main application:
- ✅ Chrome/Edge 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Opera 76+

## Technical Stack

| Component | Technology | Size |
|-----------|-----------|------|
| HTML | Semantic HTML5 | ~5KB |
| CSS | Pure CSS with CSS Grid/Flexbox | ~10KB |
| JavaScript | Vanilla ES6+ | ~12KB |
| QR Code | qrcode.js (CDN) | ~14KB |
| **Total embedded** | | **~27KB minified** |

### Why This Stack?

1. **No build tools required** - Simple deployment
2. **Fast loading** - Minimal overhead
3. **Works offline** - After first load
4. **Easy to customize** - Plain HTML/CSS/JS
5. **Security-focused** - No complex dependencies

## File Structure

```
internal/static/
├── static.go              # Go embed handler
└── web/
    ├── index.html         # Main UI page
    └── assets/
        ├── style.css      # Styles with dark mode
        └── app.js         # UI logic and interactions
```

## Usage

### Accessing the UI

Once the server is running, simply navigate to:

```
http://localhost:8080/
```

Or with your domain:

```
https://share.yourdomain.com/
```

### Upload Workflow

1. **Select File**
   - Drag and drop a file onto the upload zone
   - Or click to browse and select

2. **Configure Settings** (optional)
   - Set expiration time (default: 24 hours)
   - Set download limit (default: unlimited)

3. **Upload**
   - Click "Upload File"
   - Watch progress bar

4. **Share**
   - Copy claim code or download URL
   - Scan QR code with mobile device
   - Share with recipient

### Download Workflow

Recipients can download in two ways:

1. **Via Web UI**
   - Visit the download URL directly
   - Browser will download the file

2. **Via API**
   - Use the `/api/claim/:code` endpoint
   - curl, wget, or any HTTP client

## Customization

### Changing Colors

Edit `internal/static/web/assets/style.css`:

```css
:root {
    --primary-color: #3b82f6;  /* Change to your brand color */
    --success-color: #10b981;
    /* ... other colors */
}
```

### Changing Branding

Edit `internal/static/web/index.html`:

```html
<h1>🔒 SafeShare</h1>  <!-- Change title -->
<p class="subtitle">Your custom tagline</p>
```

### Disabling Frontend

To run API-only mode (no frontend):

1. Remove the static routes from `cmd/safeshare/main.go`
2. Remove the static import
3. Rebuild

Or simply use the API endpoints directly and ignore the UI.

## Browser Compatibility

| Browser | Version | Support |
|---------|---------|---------|
| Chrome | 90+ | ✅ Full |
| Firefox | 88+ | ✅ Full |
| Safari | 14+ | ✅ Full |
| Edge | 90+ | ✅ Full |
| Mobile Safari | iOS 14+ | ✅ Full |
| Chrome Mobile | Android 10+ | ✅ Full |

## Features in Detail

### Dark Mode

Automatically saves preference to `localStorage`. Toggle with the moon/sun button in the header.

**Implementation:**
- CSS variables for theming
- JavaScript toggle
- Persistent across sessions

### QR Code

Generated client-side using qrcode.js library loaded from CDN.

**Features:**
- High error correction level (H)
- 200x200px display
- White background (works with any theme)
- Contains full download URL

### Copy to Clipboard

Uses modern `navigator.clipboard` API with fallback for older browsers.

**Visual feedback:**
- Button changes to checkmark
- Temporary "copied" state
- Returns to normal after 2 seconds

### File Size Validation

Client-side validation prevents uploads exceeding server limits.

**Features:**
- Shows maximum in upload zone
- Validates before upload
- Clear error message

### Upload Progress

Real-time progress tracking using XMLHttpRequest with progress events.

**Features:**
- Percentage display
- Animated progress bar
- Smooth transitions

## API Integration

The frontend uses these API endpoints:

### Upload
```javascript
POST /api/upload
Content-Type: multipart/form-data

Form fields:
- file: (binary)
- expires_in_hours: (optional number)
- max_downloads: (optional number)
```

### Health Check
```javascript
GET /health

Response:
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "total_files": 42,
  "storage_used_bytes": 104857600
}
```

## Security Considerations

### CSP (Content Security Policy)

Consider adding CSP headers for production:

```go
w.Header().Set("Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'")
```

### HTTPS Only

Always run behind reverse proxy with HTTPS in production.

### Input Validation

All validation happens on both client and server:
- File size (client warns, server enforces)
- File type (server validates)
- Parameter ranges (both sides)

## Performance

### Load Time
- **First visit:** ~50-100ms (embedded files)
- **Subsequent visits:** Instant (browser cache)
- **File size:** 26.3MB Docker image (+0.3MB from API-only)

### Resource Usage
- **Memory:** Negligible (~100KB runtime)
- **CPU:** Minimal (only during uploads)
- **Network:** One-time download of QR library (~14KB)

## Troubleshooting

### Frontend doesn't load

**Check:**
1. Server is running: `curl http://localhost:8080/health`
2. Logs show no errors: `docker logs safeshare`
3. Browser console for errors

### Upload fails

**Common causes:**
1. File too large (check `MAX_FILE_SIZE`)
2. Network timeout (large files on slow connections)
3. Server disk full

**Solution:**
- Check server logs
- Verify file size
- Check available disk space

### QR code doesn't generate

**Cause:** CDN blocked or offline

**Solution:**
- Download qrcode.js locally
- Update script src in index.html
- Rebuild with embedded library

### Dark mode doesn't persist

**Cause:** localStorage disabled

**Solution:**
- Check browser privacy settings
- Allow localStorage for the domain

## Future Enhancements

Potential improvements (not implemented):

- [ ] Password-protected files
- [ ] Multi-file upload (batch)
- [ ] Compression before upload
- [ ] Upload resume capability
- [ ] Email notification option
- [ ] Custom expiration dates/times
- [ ] File preview (images/PDFs)
- [ ] Upload history (client-side only)

## Development

### Local Development

For local development with live reload, you can use a simple file server:

```bash
# From the project root
cd internal/static/web
python3 -m http.server 8000

# Or use any static file server
npx serve
```

Then update `app.js` API calls to point to `http://localhost:8080` for the backend.

### Building

Frontend is automatically embedded when building the Go binary:

```bash
go build -o safeshare ./cmd/safeshare
```

No separate build step needed!

## License

Same as main project (MIT).
