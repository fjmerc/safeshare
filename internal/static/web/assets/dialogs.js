/**
 * Accessible modal dialogs (audit #12).
 *
 * The pages show modals in three ways - a `show` class (user dashboard), a
 * `hidden` class (share modal), and inline `display` (admin dashboard) - and
 * none of them were exposed to assistive technology as dialogs. Rather than
 * touch every open/close call, this watches for any modal becoming visible
 * and, while it is open:
 *   - marks it role="dialog" aria-modal="true", labelled by its heading;
 *   - moves focus into it (to `data-modal-initial-focus` if it has one),
 *     and keeps Tab / Shift+Tab inside it;
 *   - closes it on Escape by clicking its own close/cancel button
 *     (`data-modal-close`, else a ...Cancel.../...Close... button); a modal
 *     without one (e.g. a progress dialog) or marked `data-modal-no-escape`
 *     (one-time secrets) ignores Escape;
 * and when it closes, returns focus to whatever had it before.
 */
(function() {
    'use strict';

    const MODAL_SELECTOR = '.modal, .share-modal, .recovery-modal, .e2e-decrypt-overlay';
    // A modal's own header first: some have per-step headings in the body
    // (a modal can also set aria-labelledby itself).
    const HEADING_SELECTORS = ['.modal-header', 'h1, h2, h3'];
    // Explicit markup first; the id patterns are a fallback for the many
    // modals whose dismiss button is simply called ...Cancel... / ...Close...
    const CLOSE_SELECTORS = [
        '[data-modal-close]',
        '.modal-close',
        '.share-modal-close',
        'button[id*="Cancel"]', 'button[id*="cancel"]',
        'button[id*="Close"]', 'button[id*="close"]',
    ];
    const FOCUSABLE_SELECTOR = [
        'a[href]', 'button:not([disabled])', 'input:not([disabled]):not([type="hidden"])',
        'select:not([disabled])', 'textarea:not([disabled])', '[tabindex]:not([tabindex="-1"])',
    ].join(', ');

    // Open modals, most recently opened last, with the element that had
    // focus before each one opened.
    const openStack = [];
    let headingIdCounter = 0;

    function isShown(el) {
        if (!el.isConnected || el.classList.contains('hidden')) return false;
        const style = window.getComputedStyle(el);
        return style.display !== 'none' && style.visibility !== 'hidden';
    }

    function focusableIn(modal) {
        return Array.from(modal.querySelectorAll(FOCUSABLE_SELECTOR))
            .filter(el => el.getClientRects().length > 0);
    }

    function labelDialog(modal) {
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        if (modal.hasAttribute('aria-labelledby') || modal.hasAttribute('aria-label')) return;
        const heading = HEADING_SELECTORS.map(sel => modal.querySelector(sel)).find(Boolean);
        if (heading) {
            if (!heading.id) heading.id = `dialog-heading-${++headingIdCounter}`;
            modal.setAttribute('aria-labelledby', heading.id);
        }
    }

    function opened(modal) {
        if (openStack.some(entry => entry.modal === modal)) return;
        labelDialog(modal);
        openStack.push({ modal, returnFocus: document.activeElement });
        // Let the page's own open handler finish first: some focus a
        // specific field themselves, which should win.
        setTimeout(() => {
            if (!isShown(modal) || modal.contains(document.activeElement)) return;
            // A modal can name its initial focus (e.g. Cancel on a destructive
            // confirmation, so a held Enter can't confirm it); otherwise the
            // first focusable element.
            const target = modal.querySelector('[data-modal-initial-focus]:not([disabled])') || focusableIn(modal)[0];
            if (target) {
                target.focus();
            } else {
                if (!modal.hasAttribute('tabindex')) modal.setAttribute('tabindex', '-1');
                modal.focus();
            }
        }, 0);
    }

    function closed(modal) {
        const index = openStack.findIndex(entry => entry.modal === modal);
        if (index === -1) return;
        const [{ returnFocus }] = openStack.splice(index, 1);
        // Only restore focus if it was lost with the modal (not if the page
        // deliberately moved it somewhere else, e.g. into another modal), and
        // only to something that can still take it.
        const active = document.activeElement;
        const lost = !active || active === document.body || modal.contains(active);
        if (lost && returnFocus && returnFocus.isConnected && returnFocus !== document.body &&
            returnFocus.getClientRects().length > 0) {
            returnFocus.focus();
        }
    }

    function checkAll() {
        // Closes before opens, so when one modal replaces another (e.g. create
        // token -> token created) the first gives focus back before the
        // second records where focus was.
        const modals = Array.from(document.querySelectorAll(MODAL_SELECTOR));
        modals.filter(m => !isShown(m)).forEach(closed);
        modals.filter(isShown).forEach(opened);
        // A modal removed from the page entirely (e.g. the recovery modal).
        openStack.filter(entry => !entry.modal.isConnected).forEach(entry => closed(entry.modal));
    }

    function topModal() {
        for (let i = openStack.length - 1; i >= 0; i--) {
            if (isShown(openStack[i].modal)) return openStack[i].modal;
        }
        return null;
    }

    document.addEventListener('keydown', (event) => {
        const modal = topModal();
        if (!modal) return;

        if (event.defaultPrevented || event.isComposing) return;

        if (event.key === 'Escape') {
            // Modals showing a one-time secret opt out, so a stray Escape
            // can't dismiss it before it's been copied.
            if (modal.hasAttribute('data-modal-no-escape')) return;
            const usable = el => el.getClientRects().length > 0 && !el.disabled;
            let closeButton = null;
            for (const selector of CLOSE_SELECTORS) {
                closeButton = Array.from(modal.querySelectorAll(selector)).find(usable);
                if (closeButton) break;
            }
            if (closeButton) {
                event.preventDefault();
                closeButton.click();
            }
            return;
        }

        if (event.key !== 'Tab') return;
        const focusable = focusableIn(modal);
        if (focusable.length === 0) {
            event.preventDefault();
            return;
        }
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        const active = document.activeElement;
        if (event.shiftKey && (active === first || !modal.contains(active))) {
            event.preventDefault();
            last.focus();
        } else if (!event.shiftKey && (active === last || !modal.contains(active))) {
            event.preventDefault();
            first.focus();
        }
    });

    function start() {
        checkAll();
        // Ignore the many unrelated changes (progress bars, toasts): only a
        // modal's own attributes, or modals added or removed, matter.
        const touchesModal = (node) => node.nodeType === Node.ELEMENT_NODE &&
            (node.matches(MODAL_SELECTOR) || node.querySelector(MODAL_SELECTOR) !== null);
        new MutationObserver((mutations) => {
            const relevant = mutations.some(m => m.type === 'attributes'
                ? m.target.matches(MODAL_SELECTOR)
                : Array.from(m.addedNodes).some(touchesModal) || Array.from(m.removedNodes).some(touchesModal));
            if (relevant) checkAll();
        }).observe(document.body, {
            subtree: true,
            childList: true,
            attributes: true,
            attributeFilter: ['class', 'style', 'hidden'],
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
