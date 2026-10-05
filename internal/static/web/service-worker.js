// SafeShare Service Worker
// Enables PWA functionality: cache-first static assets, network-first pages
// with an offline fallback, and the Web Share Target handler

const CACHE_VERSION = 'safeshare-v80';
const STATIC_CACHE = `${CACHE_VERSION}-static`;
const RUNTIME_CACHE = `${CACHE_VERSION}-runtime`;
// Web Share Target cache - unversioned so page JS can always find it
// Must match SHARE_TARGET_CACHE in app.js
const SHARE_TARGET_CACHE = 'safeshare-share-target';
// Shown when a page can't be reached and there is no cached copy to fall back on
const OFFLINE_PAGE = '/assets/offline.html';

// Assets to cache on service worker installation
const STATIC_ASSETS = [
  '/',
  '/assets/app.js',
  '/assets/style.css',
  '/assets/toast.js',
  '/assets/dialogs.js',
  '/assets/chunked-uploader.js',
  '/assets/qrcode.min.js',
  '/assets/crypto.js',
  '/assets/theme-init.js',
  '/assets/error-theme-toggle.js',
  '/assets/login.js',
  '/assets/dashboard.js',
  '/assets/pwa.js',
  '/assets/offline.html',
  '/assets/logo.svg',
  '/assets/android-chrome-192x192.png',
  '/assets/android-chrome-512x512.png',
  '/assets/apple-touch-icon.png',
  '/assets/manifest.json'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  console.log('[Service Worker] Installing...');
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => {
        console.log('[Service Worker] Caching static assets');
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => {
        console.log('[Service Worker] Installation complete');
        // Force activation of new service worker
        return self.skipWaiting();
      })
      .catch((error) => {
        // Rethrow so the install fails and is retried on the next load, rather
        // than activating with an empty cache and no offline fallback
        console.error('[Service Worker] Installation failed:', error);
        throw error;
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  console.log('[Service Worker] Activating...');
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((cacheName) => {
              // Delete caches that don't match current version
              return cacheName.startsWith('safeshare-') &&
                     cacheName !== STATIC_CACHE &&
                     cacheName !== RUNTIME_CACHE &&
                     cacheName !== SHARE_TARGET_CACHE;
            })
            .map((cacheName) => {
              console.log('[Service Worker] Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            })
        );
      })
      .then(() => {
        console.log('[Service Worker] Activation complete');
        // Take control of all clients immediately
        return self.clients.claim();
      })
  );
});

// Fetch event - route requests by type (share target, pages, static assets)
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Handle Web Share Target API - intercept POST from OS share sheet
  if (request.method === 'POST' && url.searchParams.has('share-target')) {
    // Block cross-origin form submissions (OS share sheet typically has no Referer)
    const referer = request.headers.get('Referer');
    if (referer) {
      try {
        const refererUrl = new URL(referer);
        if (refererUrl.origin !== self.location.origin) {
          event.respondWith(Response.redirect('/', 303));
          return;
        }
      } catch (e) {
        event.respondWith(Response.redirect('/', 303));
        return;
      }
    }

    event.respondWith(
      request.formData().then((formData) => {
        const file = formData.get('file');
        if (!file) {
          return Response.redirect('/', 303);
        }
        // Cache the shared file so the page can retrieve it
        return caches.open(SHARE_TARGET_CACHE).then((cache) => {
          return cache.put('shared-file', new Response(file, {
            headers: {
              'Content-Type': file.type,
              'X-Share-Filename': encodeURIComponent(file.name)
            }
          }));
        }).then(() => {
          return Response.redirect('/?share-target', 303);
        });
      }).catch(() => {
        return Response.redirect('/', 303);
      })
    );
    return;
  }

  // CRITICAL FIX: Skip cross-origin requests entirely
  // Let the browser handle these natively to avoid Service Worker streaming issues
  if (url.origin !== self.location.origin) {
    // Don't intercept - browser handles cross-origin requests directly
    return;
  }

  // Skip caching for API requests (uploads, downloads, admin)
  // DON'T intercept - let browser handle these natively to avoid SW streaming issues
  if (url.pathname.startsWith('/api/') ||
      url.pathname.startsWith('/admin/') ||
      url.pathname.startsWith('/health') ||
      url.pathname.startsWith('/metrics')) {
    // Let browser handle API endpoints natively (no SW interception)
    return;
  }

  // Page navigations: network first. Pages must never be answered from cache
  // while the server is reachable - /login and /dashboard redirect based on the
  // session cookie, and a cached copy would skip that check. Offline, '/' falls
  // back to its precached copy; everything else gets the offline page.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(() => {
        const fallback = url.pathname === '/'
          ? caches.match('/').then((cached) => cached || caches.match(OFFLINE_PAGE))
          : caches.match(OFFLINE_PAGE);
        return fallback.then((response) => response || Response.error());
      })
    );
    return;
  }

  // Only static assets are cached. Anything else (non-GET requests, and any
  // future non-/assets/ route) goes straight to the network so per-session
  // responses can never be cached and replayed.
  if (request.method !== 'GET' || !url.pathname.startsWith('/assets/')) {
    return;
  }

  // For static assets: Cache first, network fallback
  event.respondWith(
    caches.match(request)
      .then((cachedResponse) => {
        if (cachedResponse) {
          console.log('[Service Worker] Serving from cache:', url.pathname);
          return cachedResponse;
        }

        // Not in cache, fetch from network
        console.log('[Service Worker] Fetching from network:', url.pathname);
        return fetch(request)
          .then((response) => {
            // Don't cache non-successful responses
            if (!response || response.status !== 200 || response.type === 'error') {
              return response;
            }

            // Cache successful responses (clone because response can only be used once)
            const responseToCache = response.clone();
            caches.open(RUNTIME_CACHE)
              .then((cache) => {
                cache.put(request, responseToCache);
              });

            return response;
          })
          .catch((error) => {
            console.error('[Service Worker] Fetch failed:', error);
            // Could return a custom offline page here
            throw error;
          });
      })
  );
});

// Handle messages from clients
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    console.log('[Service Worker] Received SKIP_WAITING message');
    self.skipWaiting();
  }
});
