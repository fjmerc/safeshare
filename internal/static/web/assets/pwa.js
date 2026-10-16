// SafeShare PWA support: service worker registration and the install prompt.
// Loaded on every page; the install button and iOS hint only exist on the home page.
(function() {
    'use strict';

    // Anonymous (Ghost) mode leaves no service worker or cache on the visitor's
    // device, so nothing is registered until /api/config says otherwise. If
    // that request fails the answer is unknown and the page stays without a
    // worker (it works fully without one).
    // Resolves to true (anonymous mode), false (normal mode) or null (unknown)
    function loadAnonymousMode() {
        return fetch('/api/config', { cache: 'no-store' })
            .then((response) => (response.ok ? response.json() : null))
            .then((config) => (config && typeof config.anonymous_mode === 'boolean' ? config.anonymous_mode : null))
            .catch(() => null);
    }

    // Remove any worker and caches left by an earlier visit, from before the
    // instance switched to anonymous mode. The server also serves a
    // self-removing worker script at /service-worker.js for browsers that
    // never run this code.
    function removeServiceWorkerTraces() {
        // Unregister first: until then the old worker can still refill its caches
        const unregistered = 'serviceWorker' in navigator
            ? navigator.serviceWorker.getRegistrations()
                .then((regs) => Promise.all(regs.map((reg) => reg.unregister())))
            : Promise.resolve();
        return unregistered
            .then(() => (window.caches
                ? caches.keys().then((keys) => Promise.all(keys.map((key) => caches.delete(key))))
                : null))
            .catch(() => {});
    }

    function registerServiceWorker() {
        navigator.serviceWorker.register('/service-worker.js')
            .then((registration) => {
                registration.addEventListener('updatefound', () => {
                    const newWorker = registration.installing;
                    if (!newWorker) return;

                    newWorker.addEventListener('statechange', () => {
                        if (newWorker.state === 'installed' && navigator.serviceWorker.controller && window.showToast) {
                            window.showToast('A new version is available. Refresh to update.', 'info');
                        }
                    });
                });
            })
            .catch((error) => {
                console.log('Service Worker registration failed:', error);
            });
    }

    // beforeinstallprompt can fire before /api/config answers, so catch it now
    // and let the install UI pick it up once the mode is known.
    let earlyInstallPrompt = null;
    let onInstallPrompt = null;
    window.addEventListener('beforeinstallprompt', (e) => {
        // Only the home page has an install button; elsewhere leave the browser's own prompt alone
        if (!document.getElementById('installAppBtn')) return;
        e.preventDefault();
        earlyInstallPrompt = e;
        if (onInstallPrompt) onInstallPrompt(e);
    });

    const modeKnown = loadAnonymousMode();

    modeKnown.then((anonymous) => {
        if (anonymous === true) {
            removeServiceWorkerTraces();
            // No app install in anonymous mode: it would need the worker
            const manifestLink = document.querySelector('link[rel="manifest"]');
            if (manifestLink) manifestLink.remove();
        } else if (anonymous === false && 'serviceWorker' in navigator) {
            if (document.readyState === 'complete') {
                registerServiceWorker();
            } else {
                window.addEventListener('load', registerServiceWorker);
            }
        }
    });

    const IOS_HINT_DISMISSED_KEY = 'safeshare-ios-install-hint-dismissed';

    function isStandalone() {
        return window.matchMedia('(display-mode: standalone)').matches ||
            window.navigator.standalone === true;
    }

    // Safari on iPhone/iPod, or iPadOS (which reports itself as a Mac with touch
    // support). Other iOS browsers and in-app webviews lack Add to Home Screen
    // or put it elsewhere, so the hint would mislead there.
    function isIOSSafari() {
        const ua = window.navigator.userAgent;
        const isIOS = /iPhone|iPad|iPod/.test(ua) ||
            (ua.includes('Macintosh') && window.navigator.maxTouchPoints > 1);
        return isIOS && /Safari/.test(ua) && !/CriOS|FxiOS|EdgiOS|OPiOS|GSA/.test(ua);
    }

    function hintDismissed() {
        try {
            return localStorage.getItem(IOS_HINT_DISMISSED_KEY) === '1';
        } catch (e) {
            return false;
        }
    }

    function rememberHintDismissed() {
        try {
            localStorage.setItem(IOS_HINT_DISMISSED_KEY, '1');
        } catch (e) {
            // Storage unavailable (private mode) - the hint just comes back next visit
        }
    }

    function initInstallUI() {
        const installBtn = document.getElementById('installAppBtn');
        const iosHint = document.getElementById('iosInstallHint');
        if (isStandalone()) return;

        // Chromium browsers (Android, desktop): offer the native install prompt
        let deferredPrompt = null;

        // Don't strand keyboard focus on <body> when the focused button disappears
        function hideInstallButton() {
            if (document.activeElement === installBtn) {
                const firstTab = document.querySelector('.tab-button[aria-selected="true"]');
                if (firstTab) firstTab.focus();
            }
            installBtn.hidden = true;
        }

        if (installBtn) {
            onInstallPrompt = (e) => {
                deferredPrompt = e;
                installBtn.hidden = false;
            };
            if (earlyInstallPrompt) onInstallPrompt(earlyInstallPrompt);

            // A deferred prompt can only be shown once, so the button goes away
            // whatever the user chooses; Chrome refires beforeinstallprompt later
            // if they dismissed it.
            installBtn.addEventListener('click', async () => {
                if (!deferredPrompt) return;
                deferredPrompt.prompt();
                await deferredPrompt.userChoice.catch(() => {});
                deferredPrompt = null;
                hideInstallButton();
            });

            window.addEventListener('appinstalled', () => {
                deferredPrompt = null;
                hideInstallButton();
            });
        }

        // iOS has no install prompt API - explain the manual Add to Home Screen step
        if (iosHint && isIOSSafari() && !hintDismissed()) {
            iosHint.hidden = false;
            const dismissBtn = document.getElementById('iosInstallHintDismiss');
            if (dismissBtn) {
                dismissBtn.addEventListener('click', () => {
                    iosHint.hidden = true;
                    rememberHintDismissed();
                });
            }
        }
    }

    // Install affordances only in normal mode (anonymous mode has no worker)
    function startInstallUI() {
        modeKnown.then((anonymous) => {
            if (anonymous === false) initInstallUI();
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startInstallUI);
    } else {
        startInstallUI();
    }
})();
