// SafeShare PWA support: service worker registration and the install prompt.
// Loaded on every page; the install button and iOS hint only exist on the home page.
(function() {
    'use strict';

    // Register service worker for PWA functionality
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
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
        });
    }

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
            window.addEventListener('beforeinstallprompt', (e) => {
                e.preventDefault();
                deferredPrompt = e;
                installBtn.hidden = false;
            });

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

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initInstallUI);
    } else {
        initInstallUI();
    }
})();
