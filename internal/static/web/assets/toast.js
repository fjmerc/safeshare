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
        const toastId = `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        toast.id = toastId;
        toast.className = `toast toast-${type}`;

        // Create toast content
        toast.innerHTML = `
            <span class="toast-icon">${icons[type] || icons.info}</span>
            <span class="toast-message">${escapeHtml(message)}</span>
        `;

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
