/**
 * Toast Notification System
 *
 * Professional, non-blocking toast notifications for SafeShare.
 * Follows enterprise UX patterns (Google Drive, Dropbox, OneDrive).
 *
 * Usage:
 *   showToast('File uploaded successfully', 'success');
 *   showToast('Upload cancelled', 'info');
 *   showToast('File not found', 'error');
 *   showToast('Please enter a claim code', 'warning');
 *
 * Toast types: 'info', 'success', 'error', 'warning'
 * Duration: Auto-dismiss after specified milliseconds (default: 3000)
 */

(function() {
    'use strict';

    /**
     * Show a toast notification
     * @param {string} message - The message to display
     * @param {string} type - Toast type: 'info', 'success', 'error', 'warning'
     * @param {number} duration - Auto-dismiss duration in milliseconds (default: 3000)
     * @returns {string} Toast ID
     */
    function showToast(message, type = 'info', duration = 3000) {
        // Get or create toast container
        let container = document.getElementById('toastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toastContainer';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }

        // Icon mapping
        const icons = {
            info: 'ℹ️',
            success: '✓',
            error: '✕',
            warning: '⚠️'
        };

        // Create toast element
        const toast = document.createElement('div');
        const toastId = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
        toast.id = toastId;
        toast.className = `toast toast-${type}`;

        // Create toast content. The icon is decorative; screen readers get
        // the message through the live regions below instead (#25).
        toast.innerHTML = `
            <span class="toast-icon" aria-hidden="true">${icons[type] || icons.info}</span>
            <span class="toast-message">${escapeHtml(message)}</span>
        `;
        announce(message, type === 'error' || type === 'warning');

        // Add click to dismiss
        toast.addEventListener('click', () => {
            dismissToast(toast);
        });

        // Add to container
        container.appendChild(toast);

        // Auto-dismiss
        if (duration > 0) {
            setTimeout(() => {
                dismissToast(toast);
            }, duration);
        }

        return toastId;
    }

    /**
     * Dismiss a toast with animation
     * @param {HTMLElement} toast - Toast element to dismiss
     */
    function dismissToast(toast) {
        if (!toast || !toast.parentElement) return;

        // Add exit animation
        toast.classList.add('toast-exit');

        // Remove from DOM after animation completes
        setTimeout(() => {
            if (toast.parentElement) {
                toast.parentElement.removeChild(toast);
            }
        }, 300); // Match animation duration in CSS
    }

    // Screen readers only announce changes to a live region that already
    // existed, so two visually hidden regions are created up front: polite
    // for info/success, assertive for errors and warnings (#25).
    const liveRegions = {};

    function createLiveRegions() {
        if (liveRegions.polite && liveRegions.polite.isConnected) return false;
        for (const [key, politeness] of [['polite', 'polite'], ['assertive', 'assertive']]) {
            const region = document.createElement('div');
            region.className = 'toast-live-region';
            region.setAttribute('aria-live', politeness);
            region.setAttribute('aria-atomic', 'false');
            region.setAttribute('role', politeness === 'assertive' ? 'alert' : 'status');
            Object.assign(region.style, {
                position: 'absolute', width: '1px', height: '1px', margin: '-1px',
                padding: '0', overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap', border: '0',
            });
            document.body.appendChild(region);
            liveRegions[key] = region;
        }
        return true;
    }

    function announce(message, urgent) {
        // Each message is its own node, so toasts shown together are all
        // read out instead of overwriting each other. A region created just
        // now needs a moment before a change to it is picked up.
        const justCreated = createLiveRegions();
        const region = urgent ? liveRegions.assertive : liveRegions.polite;
        setTimeout(() => {
            const line = document.createElement('div');
            line.textContent = message;
            region.appendChild(line);
            setTimeout(() => line.remove(), 10000);
        }, justCreated ? 150 : 0);
    }

    if (document.body) {
        createLiveRegions();
    } else {
        document.addEventListener('DOMContentLoaded', createLiveRegions);
    }

    /**
     * Escape HTML to prevent XSS
     * @param {string} text - Text to escape
     * @returns {string} Escaped text
     */
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Expose showToast globally
    window.showToast = showToast;

})();
