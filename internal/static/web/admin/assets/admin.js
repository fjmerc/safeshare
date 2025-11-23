// Admin Dashboard JavaScript

// Global state
let currentPage = 1;
let searchTerm = '';
let csrfToken = '';

// Unsaved changes tracking for Settings tab
let hasUnsavedChanges = false;
let originalSettingsValues = {};

// Initialize CSRF token
function getCSRFToken() {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        const parts = cookie.trim().split('=');
        const name = parts[0];
        const value = parts.slice(1).join('='); // Handle '=' in token value
        if (name === 'csrf_token') {
            return value;
        }
    }
    return sessionStorage.getItem('csrf_token') || '';
}

// Storage quota unit conversion helpers
function populateStorageQuotaWithUnit(quotaGB) {
    const quotaInput = document.getElementById('storageQuota');
    const unitSelect = document.getElementById('storageQuotaUnit');

    // Smart unit selection: show in TB if divisible by 1024
    if (quotaGB >= 1024 && quotaGB % 1024 === 0) {
        quotaInput.value = quotaGB / 1024;
        unitSelect.value = 'TB';
    } else {
        quotaInput.value = quotaGB;
        unitSelect.value = 'GB';
    }

    updateStorageQuotaHelperText();
}

function convertQuotaToGB(value, unit) {
    const multipliers = { 'GB': 1, 'TB': 1024 };
    return Math.round(value * multipliers[unit]);
}

function convertQuotaFromGB(quotaGB, targetUnit) {
    const divisors = { 'GB': 1, 'TB': 1024 };
    return quotaGB / divisors[targetUnit];
}

function updateStorageQuotaHelperText() {
    const helperText = document.getElementById('storageQuotaHelp');
    if (helperText) {
        helperText.textContent = 'Set to 0 for unlimited storage';
    }
}

function handleStorageQuotaUnitChange() {
    const quotaInput = document.getElementById('storageQuota');
    const unitSelect = document.getElementById('storageQuotaUnit');
    const oldUnit = unitSelect.dataset.previousUnit || 'GB';
    const newUnit = unitSelect.value;

    if (oldUnit === newUnit) return;

    const currentValue = parseFloat(quotaInput.value);
    if (isNaN(currentValue) || currentValue < 0) {
        unitSelect.dataset.previousUnit = newUnit;
        updateStorageQuotaHelperText();
        return;
    }

    // Convert current value to new unit
    const quotaGB = convertQuotaToGB(currentValue, oldUnit);
    const newValue = convertQuotaFromGB(quotaGB, newUnit);
    quotaInput.value = Math.round(newValue * 1000) / 1000; // Round to 3 decimals

    unitSelect.dataset.previousUnit = newUnit;
    updateStorageQuotaHelperText();
}

// File size unit conversion helpers
function populateFileSizeWithUnit(sizeMB) {
    const sizeInput = document.getElementById('maxFileSize');
    const unitSelect = document.getElementById('maxFileSizeUnit');

    // Smart unit selection: show in GB if divisible by 1024, TB if very large
    if (sizeMB >= 1024 && sizeMB % 1024 === 0) {
        const sizeGB = sizeMB / 1024;
        if (sizeGB >= 1024 && sizeGB % 1024 === 0) {
            sizeInput.value = sizeGB / 1024;
            unitSelect.value = 'TB';
        } else {
            sizeInput.value = sizeGB;
            unitSelect.value = 'GB';
        }
    } else {
        sizeInput.value = sizeMB;
        unitSelect.value = 'MB';
    }

    updateFileSizeHelperText();
}

function convertToMB(value, unit) {
    const multipliers = { 'MB': 1, 'GB': 1024, 'TB': 1024 * 1024 };
    return Math.round(value * multipliers[unit]);
}

function convertFromMB(sizeMB, targetUnit) {
    const divisors = { 'MB': 1, 'GB': 1024, 'TB': 1024 * 1024 };
    return sizeMB / divisors[targetUnit];
}

function updateFileSizeHelperText() {
    const helperText = document.getElementById('maxFileSizeHelp');
    if (helperText) {
        helperText.textContent = 'Maximum allowed file size for uploads';
    }
}

function handleFileSizeUnitChange() {
    const sizeInput = document.getElementById('maxFileSize');
    const unitSelect = document.getElementById('maxFileSizeUnit');
    const oldUnit = unitSelect.dataset.previousUnit || 'MB';
    const newUnit = unitSelect.value;

    if (oldUnit === newUnit) return;

    const currentValue = parseFloat(sizeInput.value);
    if (isNaN(currentValue) || currentValue <= 0) {
        unitSelect.dataset.previousUnit = newUnit;
        updateFileSizeHelperText();
        return;
    }

    // Convert current value to new unit
    const sizeMB = convertToMB(currentValue, oldUnit);
    const newValue = convertFromMB(sizeMB, newUnit);
    sizeInput.value = Math.round(newValue * 1000) / 1000; // Round to 3 decimals

    unitSelect.dataset.previousUnit = newUnit;
    updateFileSizeHelperText();
}

// Expiration time unit conversion helpers
function populateExpirationWithUnit(hours) {
    const expirationInput = document.getElementById('maxExpiration');
    const unitSelect = document.getElementById('maxExpirationUnit');

    // Smart unit selection: show in days if divisible by 24
    if (hours >= 24 && hours % 24 === 0) {
        expirationInput.value = hours / 24;
        unitSelect.value = 'days';
    } else {
        expirationInput.value = hours;
        unitSelect.value = 'hours';
    }

    updateExpirationHelperText();
}

function populateDefaultExpirationWithUnit(hours) {
    const expirationInput = document.getElementById('defaultExpiration');
    const unitSelect = document.getElementById('defaultExpirationUnit');

    // Smart unit selection: show in days if divisible by 24
    if (hours >= 24 && hours % 24 === 0) {
        expirationInput.value = hours / 24;
        unitSelect.value = 'days';
    } else {
        expirationInput.value = hours;
        unitSelect.value = 'hours';
    }

    updateDefaultExpirationHelperText();
}

function convertToHours(value, unit) {
    const multipliers = { 'hours': 1, 'days': 24 };
    return Math.round(value * multipliers[unit]);
}

function convertFromHours(hours, targetUnit) {
    const divisors = { 'hours': 1, 'days': 24 };
    return hours / divisors[targetUnit];
}

function updateExpirationHelperText() {
    const helperText = document.getElementById('maxExpirationHelp');
    if (helperText) {
        helperText.textContent = 'Maximum allowed expiration time';
    }
}

function updateDefaultExpirationHelperText() {
    const helperText = document.getElementById('defaultExpirationHelp');
    if (helperText) {
        helperText.textContent = 'Default time before files expire';
    }
}

function handleExpirationUnitChange() {
    const expirationInput = document.getElementById('maxExpiration');
    const unitSelect = document.getElementById('maxExpirationUnit');
    const oldUnit = unitSelect.dataset.previousUnit || 'hours';
    const newUnit = unitSelect.value;

    if (oldUnit === newUnit) return;

    const currentValue = parseFloat(expirationInput.value);
    if (isNaN(currentValue) || currentValue <= 0) {
        unitSelect.dataset.previousUnit = newUnit;
        updateExpirationHelperText();
        return;
    }

    // Convert current value to new unit
    const hours = convertToHours(currentValue, oldUnit);
    const newValue = convertFromHours(hours, newUnit);
    expirationInput.value = Math.round(newValue * 1000) / 1000; // Round to 3 decimals

    unitSelect.dataset.previousUnit = newUnit;
    updateExpirationHelperText();
}

function handleDefaultExpirationUnitChange() {
    const expirationInput = document.getElementById('defaultExpiration');
    const unitSelect = document.getElementById('defaultExpirationUnit');
    const oldUnit = unitSelect.dataset.previousUnit || 'hours';
    const newUnit = unitSelect.value;

    if (oldUnit === newUnit) return;

    const currentValue = parseFloat(expirationInput.value);
    if (isNaN(currentValue) || currentValue <= 0) {
        unitSelect.dataset.previousUnit = newUnit;
        updateDefaultExpirationHelperText();
        return;
    }

    // Convert current value to new unit
    const hours = convertToHours(currentValue, oldUnit);
    const newValue = convertFromHours(hours, newUnit);
    expirationInput.value = Math.round(newValue * 1000) / 1000; // Round to 3 decimals

    unitSelect.dataset.previousUnit = newUnit;
    updateDefaultExpirationHelperText();
}

// Reset to default values functions
async function resetStorageDefaults() {
    const confirmed = await confirm('Reset all storage settings to default values? This will not save automatically.');
    if (!confirmed) return;

    // Default values from internal/config/config.go
    // Storage Quota: 0 GB = unlimited
    populateStorageQuotaWithUnit(0);

    // Max File Size: 104857600 bytes = 100 MB
    populateFileSizeWithUnit(100);

    // Default Expiration: 24 hours = 1 day
    populateDefaultExpirationWithUnit(24);

    // Max Expiration: 168 hours = 7 days
    populateExpirationWithUnit(168);

    // Trigger unsaved changes detection
    checkSettingsChanged();

    showSuccess('Storage settings reset to defaults. Click "Update Settings" to save.');
}

async function resetSecurityDefaults() {
    const confirmed = await confirm('Reset all security settings to default values? This will not save automatically.');
    if (!confirmed) return;

    // Default values from internal/config/config.go
    document.getElementById('rateLimitUpload').value = 10;
    document.getElementById('rateLimitDownload').value = 50;
    document.getElementById('blockedExtensions').value = '.exe,.bat,.cmd,.sh,.ps1,.dll,.so,.msi,.scr,.vbs,.jar,.com,.app,.deb,.rpm';

    // Trigger unsaved changes detection
    checkSettingsChanged();

    showSuccess('Security settings reset to defaults. Click "Update Settings" to save.');
}

// Format bytes to human-readable size
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = date - now;

    // Check if expiration is far in the future (>90 years = "never expire")
    const ninetyYearsInMs = 90 * 365 * 24 * 60 * 60 * 1000;
    if (diff > ninetyYearsInMs) {
        return 'Never';
    }

    const month = date.toLocaleString('en-US', { month: 'short' });
    const day = date.getDate();
    const time = date.toLocaleString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });

    // Only show year if different from current year
    if (date.getFullYear() !== now.getFullYear()) {
        return `${month} ${day}, ${date.getFullYear()} @ ${time}`;
    }

    return `${month} ${day} @ ${time}`;
}

// Fetch dashboard data
async function loadDashboardData(page = 1, search = '') {
    try {
        const response = await fetch(`/admin/api/dashboard?page=${page}&page_size=20&search=${encodeURIComponent(search)}`);

        if (!response.ok) {
            if (response.status === 401) {
                window.location.href = '/admin/login';
                return;
            }
            throw new Error('Failed to load dashboard data');
        }

        const data = await response.json();

        // Update stats
        document.getElementById('statTotalFiles').textContent = data.stats.total_files || 0;
        document.getElementById('statStorageUsed').textContent = formatBytes(data.stats.storage_used_bytes || 0);

        // Display partial upload disk space usage
        const partialSize = formatBytes(data.stats.partial_uploads_bytes || 0);
        document.getElementById('statPartialUploads').textContent = partialSize;

        if (data.stats.quota_limit_bytes > 0) {
            const percent = data.stats.quota_used_percent.toFixed(1);
            document.getElementById('statQuotaUsage').textContent = percent + '%';
        } else {
            document.getElementById('statQuotaUsage').textContent = 'Unlimited';
        }

        document.getElementById('statBlockedIPs').textContent = data.blocked_ips?.length || 0;

        // Update system info
        if (data.system_info) {
            document.getElementById('db-path').textContent = data.system_info.db_path || './safeshare.db';
            document.getElementById('upload-dir').textContent = data.system_info.upload_dir || './uploads';
            document.getElementById('partial-dir').textContent = data.system_info.partial_dir || './uploads/.partial';
        }

        // Update files table
        updateFilesTable(data.files || []);

        // Update pagination
        updatePagination(data.pagination);

        // Update blocked IPs table
        updateBlockedIPsTable(data.blocked_ips || []);

    } catch (error) {
        console.error('Error loading dashboard:', error);
        showError('Failed to load dashboard data');
    }
}

// Update files table
function updateFilesTable(files) {
    const tbody = document.getElementById('filesTableBody');

    if (files.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10" class="loading">No files found</td></tr>';

        // Reset select all checkbox even when no files
        const selectAllCheckbox = document.getElementById('selectAllCheckbox');
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = false;
        }

        // Update delete selected button visibility (should hide it)
        updateDeleteSelectedButton();
        return;
    }

    tbody.innerHTML = files.map(file => `
        <tr>
            <td>
                <input type="checkbox" class="file-checkbox" data-claim-code="${escapeHtml(file.claim_code)}">
            </td>
            <td><code>${escapeHtml(file.claim_code)}</code></td>
            <td class="filename-cell" title="${escapeHtml(file.original_filename)}">${escapeHtml(file.original_filename)}</td>
            <td>${formatBytes(file.file_size)}</td>
            <td>${file.username ? escapeHtml(file.username) : '<em style="color: #94a3b8;">Anonymous</em>'}</td>
            <td class="ip-cell" title="${escapeHtml(file.uploader_ip || 'Unknown')}">${escapeHtml(file.uploader_ip || 'Unknown')}</td>
            <td>${formatDate(file.created_at)}</td>
            <td>${formatDate(file.expires_at)}</td>
            <td>${file.completed_downloads} / ${file.max_downloads || '∞'}</td>
            <td><span class="badge ${file.password_protected ? 'badge-yes' : 'badge-no'}">${file.password_protected ? 'Yes' : 'No'}</span></td>
            <td>
                <button class="btn-small btn-delete" onclick="deleteFile('${escapeHtml(file.claim_code)}')">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="3 6 5 6 21 6"></polyline>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                    </svg>
                    Delete
                </button>
            </td>
        </tr>
    `).join('');

    // Reset select all checkbox
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');
    if (selectAllCheckbox) {
        selectAllCheckbox.checked = false;
    }

    // Update delete selected button visibility
    updateDeleteSelectedButton();
}

// Update blocked IPs table
function updateBlockedIPsTable(blockedIPs) {
    const tbody = document.getElementById('blockedIPsTableBody');

    if (blockedIPs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="loading">No blocked IPs</td></tr>';
        return;
    }

    tbody.innerHTML = blockedIPs.map(ip => `
        <tr>
            <td><code>${escapeHtml(ip.IPAddress)}</code></td>
            <td>${escapeHtml(ip.Reason)}</td>
            <td>${formatDate(ip.BlockedAt)}</td>
            <td>${escapeHtml(ip.BlockedBy)}</td>
            <td>
                <button class="btn-small btn-action" onclick="unblockIP('${escapeHtml(ip.IPAddress)}')">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    Unblock
                </button>
            </td>
        </tr>
    `).join('');
}

// Update pagination
function updatePagination(pagination) {
    const container = document.getElementById('pagination');

    if (!pagination || pagination.total_pages <= 1) {
        container.innerHTML = '';
        return;
    }

    let html = '';

    // Previous button
    html += `<button onclick="goToPage(${pagination.page - 1})" ${pagination.page === 1 ? 'disabled' : ''}>Previous</button>`;

    // Page numbers
    const maxPages = 5;
    let startPage = Math.max(1, pagination.page - Math.floor(maxPages / 2));
    let endPage = Math.min(pagination.total_pages, startPage + maxPages - 1);

    if (endPage - startPage < maxPages - 1) {
        startPage = Math.max(1, endPage - maxPages + 1);
    }

    for (let i = startPage; i <= endPage; i++) {
        html += `<button class="${i === pagination.page ? 'active' : ''}" onclick="goToPage(${i})">${i}</button>`;
    }

    // Next button
    html += `<button onclick="goToPage(${pagination.page + 1})" ${pagination.page === pagination.total_pages ? 'disabled' : ''}>Next</button>`;

    container.innerHTML = html;
}

// Delete file
async function deleteFile(claimCode) {
    if (!await confirm(`Delete file with claim code ${claimCode}?`)) {
        return;
    }

    try {
        const response = await fetch(`/admin/api/files/delete`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': getCSRFToken()
            },
            body: new URLSearchParams({ claim_code: claimCode })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showSuccess('File deleted successfully');
            loadDashboardData(currentPage, searchTerm);
        } else {
            showError(data.message || 'Failed to delete file');
        }
    } catch (error) {
        console.error('Error deleting file:', error);
        showError('Failed to delete file');
    }
}

// Block IP
async function blockIP(ipAddress, reason) {
    try {
        const response = await fetch('/admin/api/ip/block', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': getCSRFToken()
            },
            body: new URLSearchParams({
                ip_address: ipAddress,
                reason: reason
            })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showSuccess('IP blocked successfully');
            loadDashboardData(currentPage, searchTerm);
        } else {
            showError(data.message || 'Failed to block IP');
        }
    } catch (error) {
        console.error('Error blocking IP:', error);
        showError('Failed to block IP');
    }
}

// Unblock IP
async function unblockIP(ipAddress) {
    if (!await confirm(`Unblock IP address ${ipAddress}?`)) {
        return;
    }

    try {
        const response = await fetch('/admin/api/ip/unblock', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': getCSRFToken()
            },
            body: new URLSearchParams({ ip_address: ipAddress })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showSuccess('IP unblocked successfully');
            loadDashboardData(currentPage, searchTerm);
        } else {
            showError(data.message || 'Failed to unblock IP');
        }
    } catch (error) {
        console.error('Error unblocking IP:', error);
        showError('Failed to unblock IP');
    }
}

// Update storage settings
async function updateStorageSettings(formData) {
    try {
        const response = await fetch('/admin/api/settings/storage', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': getCSRFToken()
            },
            body: new URLSearchParams(formData)
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showSuccess(data.message);
            loadDashboardData(currentPage, searchTerm);
            // Clear unsaved changes flag and update original values
            captureOriginalSettingsValues();
        } else {
            showError(data.message || 'Failed to update storage settings');
        }
    } catch (error) {
        console.error('Error updating storage settings:', error);
        showError('Failed to update storage settings');
    }
}

// Update security settings
async function updateSecuritySettings(formData) {
    try {
        const response = await fetch('/admin/api/settings/security', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': getCSRFToken()
            },
            body: new URLSearchParams(formData)
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showSuccess(data.message);
            loadDashboardData(currentPage, searchTerm);
            // Clear unsaved changes flag and update original values
            captureOriginalSettingsValues();
        } else {
            showError(data.message || 'Failed to update security settings');
        }
    } catch (error) {
        console.error('Error updating security settings:', error);
        showError('Failed to update security settings');
    }
}

// Change admin password
async function changePassword(formData) {
    try {
        const response = await fetch('/admin/api/settings/password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': getCSRFToken()
            },
            body: new URLSearchParams(formData)
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showSuccess(data.message);
            // Clear password form
            document.getElementById('passwordForm').reset();
            // Clear unsaved changes flag and update original values
            captureOriginalSettingsValues();
        } else {
            showError(data.message || 'Failed to change password');
        }
    } catch (error) {
        console.error('Error changing password:', error);
        showError('Failed to change password');
    }
}

// Load current config values into settings forms
async function loadConfigValues() {
    try {
        const response = await fetch('/admin/api/config');

        if (!response.ok) {
            console.error('Failed to load config values');
            return;
        }

        const data = await response.json();

        // Populate storage settings
        const quotaGB = data.quota_limit_gb || 0;
        populateStorageQuotaWithUnit(quotaGB);

        // Populate max file size with smart unit selection
        const maxFileSizeMB = Math.round(data.max_file_size_bytes / (1024 * 1024)) || 100;
        populateFileSizeWithUnit(maxFileSizeMB);

        // Populate default expiration with smart unit selection
        const defaultExpirationHours = data.default_expiration_hours || 24;
        populateDefaultExpirationWithUnit(defaultExpirationHours);

        // Populate max expiration with smart unit selection
        const maxExpirationHours = data.max_expiration_hours || 168;
        populateExpirationWithUnit(maxExpirationHours);

        // Populate security settings
        document.getElementById('rateLimitUpload').value = data.rate_limit_upload || 10;
        document.getElementById('rateLimitDownload').value = data.rate_limit_download || 100;
        document.getElementById('blockedExtensions').value = (data.blocked_extensions || []).join(',');

        // Capture original values for change detection
        captureOriginalSettingsValues();
    } catch (error) {
        console.error('Error loading config values:', error);
    }
}

// Capture current settings values as original (for unsaved changes detection)
function captureOriginalSettingsValues() {
    originalSettingsValues = {
        storageQuota: document.getElementById('storageQuota')?.value || '',
        storageQuotaUnit: document.getElementById('storageQuotaUnit')?.value || 'GB',
        maxFileSize: document.getElementById('maxFileSize')?.value || '',
        maxFileSizeUnit: document.getElementById('maxFileSizeUnit')?.value || 'MB',
        defaultExpiration: document.getElementById('defaultExpiration')?.value || '',
        defaultExpirationUnit: document.getElementById('defaultExpirationUnit')?.value || 'hours',
        maxExpiration: document.getElementById('maxExpiration')?.value || '',
        maxExpirationUnit: document.getElementById('maxExpirationUnit')?.value || 'hours',
        rateLimitUpload: document.getElementById('rateLimitUpload')?.value || '',
        rateLimitDownload: document.getElementById('rateLimitDownload')?.value || '',
        blockedExtensions: document.getElementById('blockedExtensions')?.value || '',
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
    };
    hasUnsavedChanges = false;
}

// Check if settings have changed from original values
function checkSettingsChanged() {
    const currentValues = {
        storageQuota: document.getElementById('storageQuota')?.value || '',
        storageQuotaUnit: document.getElementById('storageQuotaUnit')?.value || 'GB',
        maxFileSize: document.getElementById('maxFileSize')?.value || '',
        maxFileSizeUnit: document.getElementById('maxFileSizeUnit')?.value || 'MB',
        defaultExpiration: document.getElementById('defaultExpiration')?.value || '',
        defaultExpirationUnit: document.getElementById('defaultExpirationUnit')?.value || 'hours',
        maxExpiration: document.getElementById('maxExpiration')?.value || '',
        maxExpirationUnit: document.getElementById('maxExpirationUnit')?.value || 'hours',
        rateLimitUpload: document.getElementById('rateLimitUpload')?.value || '',
        rateLimitDownload: document.getElementById('rateLimitDownload')?.value || '',
        blockedExtensions: document.getElementById('blockedExtensions')?.value || '',
        currentPassword: document.getElementById('currentPassword')?.value || '',
        newPassword: document.getElementById('newPassword')?.value || '',
        confirmPassword: document.getElementById('confirmPassword')?.value || ''
    };

    // Check if any value has changed
    for (const key in currentValues) {
        if (currentValues[key] !== originalSettingsValues[key]) {
            hasUnsavedChanges = true;
            return;
        }
    }

    hasUnsavedChanges = false;
}

// Logout
async function logout() {
    try {
        await fetch('/admin/api/logout', {
            method: 'POST',
            headers: {
                'X-CSRF-Token': getCSRFToken()
            }
        });

        window.location.href = '/admin/login';
    } catch (error) {
        console.error('Logout error:', error);
        window.location.href = '/admin/login';
    }
}

// Helper functions
function goToPage(page) {
    currentPage = page;
    loadDashboardData(page, searchTerm);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

function truncate(str, length) {
    return str.length > length ? str.substring(0, length) + '...' : str;
}

// Helper functions for toast notifications (use universal toast.js)
function showError(message) {
    showToast(message, 'error');
}

function showSuccess(message) {
    showToast(message, 'success');
}

function showWarning(message) {
    showToast(message, 'warning');
}

function confirm(message) {
    return new Promise((resolve) => {
        const modal = document.getElementById('confirmModal');
        const confirmMsg = document.getElementById('confirmMessage');
        const yesBtn = document.getElementById('confirmYes');
        const noBtn = document.getElementById('confirmNo');

        confirmMsg.textContent = message;
        modal.style.display = 'flex';

        function cleanup(result) {
            modal.style.display = 'none';
            yesBtn.onclick = null;
            noBtn.onclick = null;
            resolve(result);
        }

        yesBtn.onclick = () => cleanup(true);
        noBtn.onclick = () => cleanup(false);
    });
}

// Get selected claim codes
function getSelectedClaimCodes() {
    const checkboxes = document.querySelectorAll('.file-checkbox:checked');
    return Array.from(checkboxes).map(cb => cb.dataset.claimCode);
}

// Update delete selected button visibility
function updateDeleteSelectedButton() {
    const selectedCount = document.querySelectorAll('.file-checkbox:checked').length;
    const deleteBtn = document.getElementById('deleteSelectedBtn');

    if (deleteBtn) {
        if (selectedCount > 0) {
            deleteBtn.style.display = 'inline-flex';
            deleteBtn.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="3 6 5 6 21 6"></polyline>
                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                </svg>
                Delete Selected (${selectedCount})
            `;
        } else {
            deleteBtn.style.display = 'none';
        }
    }
}

// Handle select all checkbox
function handleSelectAll(checked) {
    const checkboxes = document.querySelectorAll('.file-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = checked;
    });
    updateDeleteSelectedButton();
}

// Handle individual checkbox change
function handleCheckboxChange() {
    updateDeleteSelectedButton();

    // Update select all checkbox state
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');
    const allCheckboxes = document.querySelectorAll('.file-checkbox');
    const checkedCheckboxes = document.querySelectorAll('.file-checkbox:checked');

    if (selectAllCheckbox && allCheckboxes.length > 0) {
        selectAllCheckbox.checked = allCheckboxes.length === checkedCheckboxes.length;
    }
}

// Bulk delete files
async function deleteSelectedFiles() {
    const claimCodes = getSelectedClaimCodes();

    if (claimCodes.length === 0) {
        showError('No files selected');
        return;
    }

    if (!await confirm(`Delete ${claimCodes.length} selected file(s)?`)) {
        return;
    }

    try {
        const response = await fetch('/admin/api/files/delete/bulk', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': getCSRFToken()
            },
            body: new URLSearchParams({ claim_codes: claimCodes.join(',') })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showSuccess(`Successfully deleted ${data.deleted_count} file(s)`);
            loadDashboardData(currentPage, searchTerm);
        } else {
            showError(data.message || 'Failed to delete files');
        }
    } catch (error) {
        console.error('Error deleting files:', error);
        showError('Failed to delete files');
    }
}

// Theme Management
function loadTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);
}

function updateThemeIcon(theme) {
    const sunIcon = document.querySelector('.theme-icon-sun');
    const moonIcon = document.querySelector('.theme-icon-moon');

    if (sunIcon && moonIcon) {
        if (theme === 'dark') {
            sunIcon.style.display = 'block';
            moonIcon.style.display = 'none';
        } else {
            sunIcon.style.display = 'none';
            moonIcon.style.display = 'block';
        }
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Load theme preference first (works for both login and dashboard pages)
    loadTheme();

    // Universal password toggle handler for all password fields
    document.querySelectorAll('[data-password-toggle]').forEach(button => {
        button.addEventListener('click', () => {
            const targetId = button.getAttribute('data-password-toggle');
            const passwordInput = document.getElementById(targetId);
            const eyeIcon = button.querySelector('.eye-icon');
            const eyeOffIcon = button.querySelector('.eye-off-icon');

            if (passwordInput && eyeIcon && eyeOffIcon) {
                if (passwordInput.type === 'password') {
                    passwordInput.type = 'text';
                    eyeIcon.style.display = 'none';
                    eyeOffIcon.style.display = 'block';
                } else {
                    passwordInput.type = 'password';
                    eyeIcon.style.display = 'block';
                    eyeOffIcon.style.display = 'none';
                }
            }
        });
    });

    // Theme toggle button (available on both pages)
    document.getElementById('themeToggle')?.addEventListener('click', toggleTheme);

    // Only initialize dashboard-specific features if we're on the dashboard page
    if (!document.querySelector('.dashboard-page')) {
        return;
    }

    // Get CSRF token
    csrfToken = getCSRFToken();

    // Tab switching with unsaved changes warning
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const tabName = btn.dataset.tab;

            // Check for unsaved changes when leaving Settings tab
            const currentTab = document.querySelector('.tab-btn.active')?.dataset.tab;
            if (currentTab === 'settings' && hasUnsavedChanges) {
                const leave = await confirm('You have unsaved changes that will be lost. Do you want to leave this page?');
                if (!leave) {
                    return; // Stay on Settings tab
                }
                // User chose to leave, clear the unsaved changes flag
                hasUnsavedChanges = false;
            }

            // Update active button
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Update active content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(tabName + 'Tab').classList.add('active');
        });
    });

    // Search
    let searchTimeout;
    document.getElementById('searchInput')?.addEventListener('input', (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            searchTerm = e.target.value;
            currentPage = 1;
            loadDashboardData(1, searchTerm);
        }, 500);
    });

    // Refresh button
    document.getElementById('refreshBtn')?.addEventListener('click', (e) => {
        const btn = e.currentTarget;
        btn.classList.add('btn-refreshing');
        setTimeout(() => btn.classList.remove('btn-refreshing'), 600);
        loadDashboardData(currentPage, searchTerm);
    });

    // Logout button
    document.getElementById('logoutBtn')?.addEventListener('click', logout);

    // Block IP form
    document.getElementById('blockIPForm')?.addEventListener('submit', (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const ipAddress = formData.get('ip_address');
        
        // Validate IP address is not empty
        if (!ipAddress || ipAddress.trim() === '') {
            showError('IP address is required');
            return;
        }
        
        blockIP(ipAddress, formData.get('reason') || 'Blocked by admin');
        e.target.reset();
    });

    // Storage settings form
    document.getElementById('storageForm')?.addEventListener('submit', (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);

        // Convert storage quota to GB before sending
        const quota = parseFloat(formData.get('storage_quota'));
        const quotaUnit = formData.get('storage_quota_unit');
        const quotaGB = convertQuotaToGB(quota, quotaUnit);

        // Convert file size to MB before sending
        const fileSize = parseFloat(formData.get('max_file_size'));
        const fileUnit = formData.get('max_file_size_unit');
        const fileSizeMB = convertToMB(fileSize, fileUnit);

        // Convert default expiration to hours before sending
        const defaultExpiration = parseFloat(formData.get('default_expiration'));
        const defaultExpirationUnit = formData.get('default_expiration_unit');
        const defaultExpirationHours = convertToHours(defaultExpiration, defaultExpirationUnit);

        // Convert max expiration to hours before sending
        const maxExpiration = parseFloat(formData.get('max_expiration'));
        const maxExpirationUnit = formData.get('max_expiration_unit');
        const maxExpirationHours = convertToHours(maxExpiration, maxExpirationUnit);

        // Validation: Default Expiration cannot exceed Max Expiration
        if (defaultExpirationHours > maxExpirationHours) {
            showError('Default Expiration cannot exceed Max Expiration. Please reduce the default expiration or increase the maximum.');
            return;
        }

        // Validation: Max File Size cannot exceed Storage Quota (when quota is not unlimited)
        if (quotaGB > 0) {
            const quotaMB = quotaGB * 1024;
            if (fileSizeMB > quotaMB) {
                showError('Max File Size cannot exceed Storage Quota. Please reduce the file size limit or increase the storage quota.');
                return;
            }
        }

        // Replace with GB, MB, and hours values
        formData.set('quota_gb', quotaGB);
        formData.set('max_file_size_mb', fileSizeMB);
        formData.set('default_expiration_hours', defaultExpirationHours);
        formData.set('max_expiration_hours', maxExpirationHours);
        formData.delete('storage_quota');
        formData.delete('storage_quota_unit');
        formData.delete('max_file_size');
        formData.delete('max_file_size_unit');
        formData.delete('default_expiration');
        formData.delete('default_expiration_unit');
        formData.delete('max_expiration');
        formData.delete('max_expiration_unit');

        updateStorageSettings(formData);
    });

    // Security settings form
    document.getElementById('securityForm')?.addEventListener('submit', (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        updateSecuritySettings(formData);
    });

    // Password change form
    document.getElementById('passwordForm')?.addEventListener('submit', (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        changePassword(formData);
    });

    // Load config values when Settings tab is opened
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            if (btn.dataset.tab === 'settings') {
                loadConfigValues();
            }
        });
    });

    // Select all checkbox
    document.getElementById('selectAllCheckbox')?.addEventListener('change', (e) => {
        handleSelectAll(e.target.checked);
    });

    // Delete selected button
    document.getElementById('deleteSelectedBtn')?.addEventListener('click', () => {
        deleteSelectedFiles();
    });

    // Individual checkbox changes (use event delegation)
    document.getElementById('filesTableBody')?.addEventListener('change', (e) => {
        if (e.target.classList.contains('file-checkbox')) {
            handleCheckboxChange();
        }
    });

    // Users tab event listeners
    document.getElementById('createUserBtn')?.addEventListener('click', () => {
        showCreateUserModal();
    });

    document.getElementById('refreshUsersBtn')?.addEventListener('click', (e) => {
        const btn = e.currentTarget;
        btn.classList.add('btn-refreshing');
        setTimeout(() => btn.classList.remove('btn-refreshing'), 600);
        loadUsers();
    });

    document.getElementById('createUserForm')?.addEventListener('submit', (e) => {
        e.preventDefault();
        createUser();
    });

    document.getElementById('editUserForm')?.addEventListener('submit', (e) => {
        e.preventDefault();
        updateUser();
    });

    // Load users when Users tab is opened
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            if (btn.dataset.tab === 'users') {
                loadUsers();
            } else if (btn.dataset.tab === 'settings') {
                loadConfigValues();
            } else if (btn.dataset.tab === 'webhooks') {
                loadWebhooks();
                loadDeliveries();
            }
        });
    });

    // Webhook event listeners
    document.getElementById('createWebhookBtn')?.addEventListener('click', showCreateWebhookModal);
    document.getElementById('refreshWebhooksBtn')?.addEventListener('click', (e) => {
        const btn = e.currentTarget;
        btn.classList.add('btn-refreshing');
        setTimeout(() => btn.classList.remove('btn-refreshing'), 600);
        loadWebhooks();
        loadDeliveries();
    });

    // Webhook form submission
    document.getElementById('webhookForm')?.addEventListener('submit', (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        saveWebhook(formData);
    });

    // Webhook format change handler - show/hide service token field
    document.getElementById('webhookFormat')?.addEventListener('change', (e) => {
        updateServiceTokenVisibility(e.target.value);
    });

    // Delivery filters
    document.getElementById('deliveryEventFilter')?.addEventListener('change', (e) => {
        currentDeliveryFilters.event = e.target.value;
        loadDeliveries();
    });

    document.getElementById('deliveryStatusFilter')?.addEventListener('change', (e) => {
        currentDeliveryFilters.status = e.target.value;
        loadDeliveries();
    });

    // Auto-refresh checkbox
    document.getElementById('autoRefreshDeliveries')?.addEventListener('change', toggleAutoRefresh);

    // Add input event listeners for Settings tab fields to detect changes
    const settingsFields = [
        'storageQuota',
        'storageQuotaUnit',
        'maxFileSize',
        'maxFileSizeUnit',
        'defaultExpiration',
        'defaultExpirationUnit',
        'maxExpiration',
        'maxExpirationUnit',
        'rateLimitUpload',
        'rateLimitDownload',
        'blockedExtensions',
        'currentPassword',
        'newPassword',
        'confirmPassword'
    ];

    settingsFields.forEach(fieldId => {
        const field = document.getElementById(fieldId);
        if (field) {
            field.addEventListener('input', checkSettingsChanged);
        }
    });

    // Add special handlers for storage quota unit conversion
    const storageQuotaUnitSelect = document.getElementById('storageQuotaUnit');
    const storageQuotaInput = document.getElementById('storageQuota');

    if (storageQuotaUnitSelect) {
        // Initialize previous unit tracking
        storageQuotaUnitSelect.dataset.previousUnit = storageQuotaUnitSelect.value;

        // Handle unit changes
        storageQuotaUnitSelect.addEventListener('change', () => {
            handleStorageQuotaUnitChange();
            checkSettingsChanged();
        });
    }

    if (storageQuotaInput) {
        // Update helper text when value changes
        storageQuotaInput.addEventListener('input', updateStorageQuotaHelperText);
    }

    // Add special handlers for file size unit conversion
    const fileSizeUnitSelect = document.getElementById('maxFileSizeUnit');
    const fileSizeInput = document.getElementById('maxFileSize');

    if (fileSizeUnitSelect) {
        // Initialize previous unit tracking
        fileSizeUnitSelect.dataset.previousUnit = fileSizeUnitSelect.value;

        // Handle unit changes
        fileSizeUnitSelect.addEventListener('change', () => {
            handleFileSizeUnitChange();
            checkSettingsChanged();
        });
    }

    if (fileSizeInput) {
        // Update helper text when value changes
        fileSizeInput.addEventListener('input', updateFileSizeHelperText);
    }

    // Add special handlers for default expiration unit conversion
    const defaultExpirationUnitSelect = document.getElementById('defaultExpirationUnit');
    const defaultExpirationInput = document.getElementById('defaultExpiration');

    if (defaultExpirationUnitSelect) {
        // Initialize previous unit tracking
        defaultExpirationUnitSelect.dataset.previousUnit = defaultExpirationUnitSelect.value;

        // Handle unit changes
        defaultExpirationUnitSelect.addEventListener('change', () => {
            handleDefaultExpirationUnitChange();
            checkSettingsChanged();
        });
    }

    if (defaultExpirationInput) {
        // Update helper text when value changes
        defaultExpirationInput.addEventListener('input', updateDefaultExpirationHelperText);
    }

    // Add special handlers for max expiration unit conversion
    const maxExpirationUnitSelect = document.getElementById('maxExpirationUnit');
    const maxExpirationInput = document.getElementById('maxExpiration');

    if (maxExpirationUnitSelect) {
        // Initialize previous unit tracking
        maxExpirationUnitSelect.dataset.previousUnit = maxExpirationUnitSelect.value;

        // Handle unit changes
        maxExpirationUnitSelect.addEventListener('change', () => {
            handleExpirationUnitChange();
            checkSettingsChanged();
        });
    }

    if (maxExpirationInput) {
        // Update helper text when value changes
        maxExpirationInput.addEventListener('input', updateExpirationHelperText);
    }

    // Browser navigation warning (beforeunload)
    window.addEventListener('beforeunload', (e) => {
        if (hasUnsavedChanges) {
            e.preventDefault();
            e.returnValue = ''; // Chrome requires returnValue to be set
        }
    });

    // Load initial data
    loadDashboardData();
    loadConfigValues(); // Load config values for settings tab

    // Cleanup partial uploads button handler
    document.getElementById('cleanupPartialUploadsBtn')?.addEventListener('click', async () => {
        const confirmed = await confirm(
            'This will delete partial uploads that were STARTED more than 24 hours ago.\n\n⚠️ WARNING: Large files being uploaded over slow connections may be affected if the upload session has been running for more than 24 hours.\n\nContinue?'
        );

        if (!confirmed) return;

        const btn = document.getElementById('cleanupPartialUploadsBtn');
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Cleaning...';

        try {
            const response = await fetch('/admin/api/partial-uploads/cleanup', {
                method: 'POST',
                headers: {
                    'X-CSRF-Token': getCSRFToken()
                }
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to cleanup partial uploads');
            }

            showToast(data.message, 'success');

            // Refresh dashboard data to update stats
            loadDashboardData();
        } catch (error) {
            console.error('Cleanup error:', error);
            showToast(error.message, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    });

    // ============ Configuration Assistant Event Listeners ============

    // Global variable to store recommendations
    let currentRecommendations = null;

    // Show/hide CDN timeout field based on checkbox
    document.getElementById('usingCDN')?.addEventListener('change', (e) => {
        const cdnTimeoutGroup = document.getElementById('cdnTimeoutGroup');
        if (e.target.checked) {
            cdnTimeoutGroup.style.display = 'block';
        } else {
            cdnTimeoutGroup.style.display = 'none';
            document.getElementById('cdnTimeout').value = '0';
        }
    });

    // Configuration Assistant form submission
    document.getElementById('configAssistantForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData(e.target);
        const requestData = {
            upload_speed: parseFloat(formData.get('upload_speed')),
            download_speed: parseFloat(formData.get('download_speed')),
            network_latency: formData.get('network_latency'),
            typical_file_size: formData.get('typical_file_size'),
            deployment_type: formData.get('deployment_type'),
            user_load: formData.get('user_load'),
            storage_capacity: parseInt(formData.get('storage_capacity')) || 0,
            using_cdn: document.getElementById('usingCDN').checked,
            cdn_timeout: parseInt(formData.get('cdn_timeout')) || 0,
            encryption_enabled: document.getElementById('encryptionEnabled').checked
        };

        try {
            const response = await fetch('/admin/api/config-assistant/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': getCSRFToken()
                },
                body: JSON.stringify(requestData)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to get recommendations');
            }

            // Store recommendations globally
            currentRecommendations = data;

            // Display recommendations
            displayRecommendations(data);

            // Show recommendations section, hide questionnaire
            document.getElementById('questionnaireSection').style.display = 'none';
            document.getElementById('recommendationsSection').style.display = 'block';

        } catch (error) {
            console.error('Configuration assistant error:', error);
            showError(error.message || 'Failed to analyze configuration');
        }
    });

    // Back to questionnaire button
    document.getElementById('backToQuestionnaireBtn')?.addEventListener('click', () => {
        document.getElementById('questionnaireSection').style.display = 'block';
        document.getElementById('recommendationsSection').style.display = 'none';
    });

    // Apply recommendations button
    document.getElementById('applyRecommendationsBtn')?.addEventListener('click', async () => {
        if (!currentRecommendations) {
            showError('No recommendations available');
            return;
        }

        const confirmed = await confirm(
            'This will update your SafeShare settings with the recommended values. Do you want to continue?'
        );

        if (!confirmed) return;

        try {
            // Apply recommendations via existing settings endpoints
            const recommendations = currentRecommendations.recommendations;

            // Prepare storage settings update
            const storageFormData = new FormData();
            storageFormData.append('quota_gb', recommendations.quota_limit_gb);
            storageFormData.append('max_file_size_mb', recommendations.max_file_size / (1024 * 1024));
            storageFormData.append('default_expiration_hours', recommendations.default_expiration_hours);
            storageFormData.append('max_expiration_hours', recommendations.max_expiration_hours);

            // Update storage settings
            await updateStorageSettings(storageFormData);

            // Prepare security settings update
            const securityFormData = new FormData();
            securityFormData.append('rate_limit_upload', recommendations.rate_limit_upload);
            securityFormData.append('rate_limit_download', recommendations.rate_limit_download);
            securityFormData.append('blocked_extensions', recommendations.blocked_extensions.join(','));

            // Update security settings
            await updateSecuritySettings(securityFormData);

            showSuccess('Recommended settings applied successfully!');

            // Reload config values to reflect changes
            await loadConfigValues();

            // Go back to questionnaire for next analysis
            document.getElementById('questionnaireSection').style.display = 'block';
            document.getElementById('recommendationsSection').style.display = 'none';

        } catch (error) {
            console.error('Failed to apply recommendations:', error);
            showError('Failed to apply some recommendations. Please check the logs.');
        }
    });
});

// ============ Configuration Assistant Helper Functions ============

function displayRecommendations(data) {
    const { recommendations, current_config, analysis } = data;

    // Update summary text
    document.getElementById('recommendationSummary').textContent = analysis.summary;

    // Immediate Settings
    const immediateComparisons = [
        {
            setting: 'Max File Size',
            current: formatBytes(current_config.max_file_size),
            recommended: formatBytes(recommendations.max_file_size),
            impact: analysis.impacts.max_file_size || 'Optimized for your file sizes',
            changed: current_config.max_file_size !== recommendations.max_file_size
        },
        {
            setting: 'Storage Quota',
            current: current_config.quota_limit_gb === 0 ? 'Unlimited' : current_config.quota_limit_gb + ' GB',
            recommended: recommendations.quota_limit_gb === 0 ? 'Unlimited' : recommendations.quota_limit_gb + ' GB',
            impact: analysis.impacts.quota_limit_gb || 'Based on available storage',
            changed: current_config.quota_limit_gb !== recommendations.quota_limit_gb
        },
        {
            setting: 'Default Expiration',
            current: current_config.default_expiration_hours + ' hours',
            recommended: recommendations.default_expiration_hours + ' hours',
            impact: analysis.impacts.default_expiration_hours || 'Standard retention period',
            changed: current_config.default_expiration_hours !== recommendations.default_expiration_hours
        },
        {
            setting: 'Max Expiration',
            current: current_config.max_expiration_hours + ' hours',
            recommended: recommendations.max_expiration_hours + ' hours',
            impact: analysis.impacts.max_expiration_hours || 'Maximum retention limit',
            changed: current_config.max_expiration_hours !== recommendations.max_expiration_hours
        },
        {
            setting: 'Upload Rate Limit',
            current: current_config.rate_limit_upload + ' per hour',
            recommended: recommendations.rate_limit_upload + ' per hour',
            impact: analysis.impacts.rate_limit_upload || 'Balanced for your user load',
            changed: current_config.rate_limit_upload !== recommendations.rate_limit_upload
        },
        {
            setting: 'Download Rate Limit',
            current: current_config.rate_limit_download + ' per hour',
            recommended: recommendations.rate_limit_download + ' per hour',
            impact: analysis.impacts.rate_limit_download || 'Optimized for download traffic',
            changed: current_config.rate_limit_download !== recommendations.rate_limit_download
        }
    ];

    // Performance Settings (require restart)
    const performanceComparisons = [
        {
            setting: 'Chunk Size',
            current: formatBytes(current_config.chunk_size),
            recommended: formatBytes(recommendations.chunk_size),
            impact: analysis.impacts.chunk_size || 'Optimized for network speed',
            changed: current_config.chunk_size !== recommendations.chunk_size
        },
        {
            setting: 'Read Timeout',
            current: current_config.read_timeout + ' seconds',
            recommended: recommendations.read_timeout + ' seconds',
            impact: analysis.impacts.read_timeout || 'Based on chunk size and upload speed',
            changed: current_config.read_timeout !== recommendations.read_timeout
        },
        {
            setting: 'Write Timeout',
            current: current_config.write_timeout + ' seconds',
            recommended: recommendations.write_timeout + ' seconds',
            impact: analysis.impacts.write_timeout || 'Matched to read timeout',
            changed: current_config.write_timeout !== recommendations.write_timeout
        },
        {
            setting: 'Chunked Upload Threshold',
            current: formatBytes(current_config.chunked_upload_threshold),
            recommended: formatBytes(recommendations.chunked_upload_threshold),
            impact: analysis.impacts.chunked_upload_threshold || 'When to start chunking',
            changed: current_config.chunked_upload_threshold !== recommendations.chunked_upload_threshold
        },
        {
            setting: 'Partial Upload Expiry',
            current: current_config.partial_upload_expiry_hours + ' hours',
            recommended: recommendations.partial_upload_expiry_hours + ' hours',
            impact: analysis.impacts.partial_upload_expiry_hours || 'Cleanup interval for abandoned uploads',
            changed: current_config.partial_upload_expiry_hours !== recommendations.partial_upload_expiry_hours
        }
    ];

    // Operational Settings (require restart)
    const operationalComparisons = [
        {
            setting: 'Session Expiry',
            current: current_config.session_expiry_hours + ' hours',
            recommended: recommendations.session_expiry_hours + ' hours',
            impact: analysis.impacts.session_expiry_hours || 'User session lifetime',
            changed: current_config.session_expiry_hours !== recommendations.session_expiry_hours
        },
        {
            setting: 'Cleanup Interval',
            current: current_config.cleanup_interval_minutes + ' minutes',
            recommended: recommendations.cleanup_interval_minutes + ' minutes',
            impact: analysis.impacts.cleanup_interval_minutes || 'How often to cleanup expired files',
            changed: current_config.cleanup_interval_minutes !== recommendations.cleanup_interval_minutes
        },
        {
            setting: 'Require Auth for Upload',
            current: current_config.require_auth_for_upload ? 'Enabled' : 'Disabled',
            recommended: recommendations.require_auth_for_upload ? 'Enabled' : 'Disabled',
            impact: analysis.impacts.require_auth_for_upload || 'Prevent anonymous uploads',
            changed: current_config.require_auth_for_upload !== recommendations.require_auth_for_upload
        },
        {
            setting: 'HTTPS Enabled',
            current: current_config.https_enabled ? 'Yes' : 'No',
            recommended: recommendations.https_enabled ? 'Yes' : 'No',
            impact: analysis.impacts.https_enabled || 'Secure cookie flag',
            changed: current_config.https_enabled !== recommendations.https_enabled
        },
        {
            setting: 'Chunked Upload Enabled',
            current: current_config.chunked_upload_enabled ? 'Yes' : 'No',
            recommended: recommendations.chunked_upload_enabled ? 'Yes' : 'No',
            impact: 'Enable large file upload support',
            changed: current_config.chunked_upload_enabled !== recommendations.chunked_upload_enabled
        }
    ];

    // Populate immediate settings table
    const immediateTbody = document.getElementById('immediateSettingsTableBody');
    immediateTbody.innerHTML = '';
    populateTable(immediateTbody, immediateComparisons);

    // Populate performance settings table
    const performanceTbody = document.getElementById('performanceSettingsTableBody');
    performanceTbody.innerHTML = '';
    populateTable(performanceTbody, performanceComparisons);

    // Populate operational settings table
    const operationalTbody = document.getElementById('operationalSettingsTableBody');
    operationalTbody.innerHTML = '';
    populateTable(operationalTbody, operationalComparisons);

    // Generate .env file content
    generateEnvFileContent(recommendations);

    // Show additional recommendations if available
    if (analysis.additional_recommendations && analysis.additional_recommendations.length > 0) {
        document.getElementById('additionalRecommendations').style.display = 'block';
        const content = document.getElementById('additionalRecommendationsContent');
        content.innerHTML = '<ul style="list-style: disc; margin-left: 20px;">' +
            analysis.additional_recommendations.map(rec =>
                `<li style="margin-bottom: 8px;">${escapeHtml(rec)}</li>`
            ).join('') +
            '</ul>';
    } else {
        document.getElementById('additionalRecommendations').style.display = 'none';
    }
}

// Helper function to populate comparison tables
function populateTable(tbody, comparisons) {
    comparisons.forEach(item => {
        const row = document.createElement('tr');
        if (item.changed) {
            // Subtle left border indicator for changed values
            row.style.borderLeft = '4px solid var(--primary-color)';
            row.style.backgroundColor = 'rgba(59, 130, 246, 0.05)'; // Very subtle blue tint
        }
        row.innerHTML = `
            <td style="text-align: left; font-weight: 600;">
                ${item.changed ? '<span style="display: inline-block; width: 8px; height: 8px; background: var(--primary-color); border-radius: 50%; margin-right: 8px;"></span>' : ''}
                ${escapeHtml(item.setting)}
            </td>
            <td style="text-align: center; ${item.changed ? 'opacity: 0.6;' : ''}">${escapeHtml(item.current)}</td>
            <td style="text-align: center; font-weight: 600; color: ${item.changed ? 'var(--primary-color)' : 'inherit'};">${escapeHtml(item.recommended)}</td>
            <td style="text-align: left; font-size: 13px; ${item.changed ? 'font-style: italic;' : ''}">${escapeHtml(item.impact)}</td>
        `;
        tbody.appendChild(row);
    });
}

// Generate .env file content for restart-required settings
function generateEnvFileContent(recommendations) {
    const envLines = [];

    envLines.push('# ========================================');
    envLines.push('# SafeShare Performance Settings');
    envLines.push('# ========================================');
    envLines.push('');
    envLines.push('# Chunk Size for Uploads');
    envLines.push(`CHUNK_SIZE=${recommendations.chunk_size}`);
    envLines.push('');
    envLines.push('# HTTP Timeouts (seconds)');
    envLines.push(`READ_TIMEOUT=${recommendations.read_timeout}`);
    envLines.push(`WRITE_TIMEOUT=${recommendations.write_timeout}`);
    envLines.push('');
    envLines.push('# Chunked Upload Configuration');
    envLines.push(`CHUNKED_UPLOAD_THRESHOLD=${recommendations.chunked_upload_threshold}`);
    envLines.push(`CHUNKED_UPLOAD_ENABLED=${recommendations.chunked_upload_enabled}`);
    envLines.push(`PARTIAL_UPLOAD_EXPIRY_HOURS=${recommendations.partial_upload_expiry_hours}`);
    envLines.push('');
    envLines.push('# ========================================');
    envLines.push('# SafeShare Operational Settings');
    envLines.push('# ========================================');
    envLines.push('');
    envLines.push('# Session and Cleanup');
    envLines.push(`SESSION_EXPIRY_HOURS=${recommendations.session_expiry_hours}`);
    envLines.push(`CLEANUP_INTERVAL_MINUTES=${recommendations.cleanup_interval_minutes}`);
    envLines.push('');
    envLines.push('# Security Settings (OPTIONAL - uncomment if needed)');
    envLines.push(`# REQUIRE_AUTH_FOR_UPLOAD=${recommendations.require_auth_for_upload}  # Recommended: ${recommendations.require_auth_for_upload}`);
    envLines.push(`HTTPS_ENABLED=${recommendations.https_enabled}`);
    envLines.push('');
    envLines.push('# Encryption at Rest (OPTIONAL - generate with: openssl rand -hex 32)');
    envLines.push('# ENCRYPTION_KEY=your-64-character-hex-key-here');

    if (recommendations.public_url) {
        envLines.push('');
        envLines.push('# Public URL (set this to your domain)');
        envLines.push(`PUBLIC_URL=${recommendations.public_url}`);
    }

    const envContent = envLines.join('\n');
    document.getElementById('envFileContent').textContent = envContent;

    // Set up copy button handler
    const copyBtn = document.getElementById('copyEnvBtn');
    copyBtn.onclick = () => {
        navigator.clipboard.writeText(envContent).then(() => {
            showSuccess('.env content copied to clipboard!');
        }).catch(() => {
            showError('Failed to copy to clipboard');
        });
    };
}

// ============ User Management Functions ============

let usersData = [];

async function loadUsers() {
    try {
        const response = await fetch('/admin/api/users', {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('Failed to load users');
        }

        const data = await response.json();
        usersData = data.users || [];
        displayUsers(usersData);
    } catch (error) {
        console.error('Load users error:', error);
        showToast('Failed to load users', 'error');
    }
}

function displayUsers(users) {
    const tbody = document.getElementById('usersTableBody');

    if (!users || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty">No users found</td></tr>';
        return;
    }

    tbody.innerHTML = users.map(user => `
        <tr>
            <td><strong>${escapeHtml(user.username)}</strong></td>
            <td>${escapeHtml(user.email)}</td>
            <td>
                <span class="badge ${user.role === 'admin' ? 'badge-primary' : 'badge-secondary'}">
                    ${user.role}
                </span>
            </td>
            <td>
                <span class="badge ${user.is_active ? 'badge-success' : 'badge-danger'}">
                    ${user.is_active ? 'Active' : 'Disabled'}
                </span>
            </td>
            <td>${user.file_count || 0}</td>
            <td>${new Date(user.created_at).toLocaleDateString()}</td>
            <td>${user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}</td>
            <td class="actions">
                <button class="btn-icon btn-primary" onclick="editUser(${user.id})" title="Edit">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                    </svg>
                </button>
                <button class="btn-icon ${user.is_active ? 'btn-warning' : 'btn-success'}"
                        onclick="toggleUserStatus(${user.id}, ${user.is_active})"
                        title="${user.is_active ? 'Disable' : 'Enable'}">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        ${user.is_active ?
                            '<circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>' :
                            '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>'
                        }
                    </svg>
                </button>
                <button class="btn-icon btn-info" onclick="resetUserPassword(${user.id})" title="Reset Password">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                    </svg>
                </button>
                <button class="btn-icon btn-danger" onclick="deleteUser(${user.id})" title="Delete">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="3 6 5 6 21 6"></polyline>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                    </svg>
                </button>
            </td>
        </tr>
    `).join('');
}

function showCreateUserModal() {
    document.getElementById('createUserModal').style.display = 'flex';
    document.getElementById('createUserForm').reset();
}

function hideCreateUserModal() {
    document.getElementById('createUserModal').style.display = 'none';
}

async function createUser() {
    const form = document.getElementById('createUserForm');
    const formData = new FormData(form);

    const userData = {
        username: formData.get('username'),
        email: formData.get('email'),
        password: formData.get('password') || ''
    };

    try {
        const csrfToken = getCookie('csrf_token');
        const response = await fetch('/admin/api/users/create', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify(userData)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to create user');
        }

        hideCreateUserModal();
        showUserCreatedModal(data);
        loadUsers();
        showToast('User created successfully', 'success');
    } catch (error) {
        console.error('Create user error:', error);
        showToast(error.message, 'error');
    }
}

function showUserCreatedModal(data) {
    document.getElementById('createdUsername').textContent = data.username;
    document.getElementById('createdEmail').textContent = data.email;
    document.getElementById('createdPassword').textContent = data.temporary_password;
    document.getElementById('userCreatedModal').style.display = 'flex';
}

function hideUserCreatedModal() {
    document.getElementById('userCreatedModal').style.display = 'none';
}

function copyPassword() {
    const password = document.getElementById('createdPassword').textContent;

    // Try modern clipboard API first
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(password).then(() => {
            showToast('Password copied to clipboard', 'success');
        }).catch(() => {
            // Fallback to textarea method
            copyToClipboardFallback(password);
        });
    } else {
        // Use fallback method
        copyToClipboardFallback(password);
    }
}

function copyToClipboardFallback(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
        document.execCommand('copy');
        showToast('Password copied to clipboard', 'success');
    } catch (err) {
        showToast('Failed to copy password', 'error');
    }
    document.body.removeChild(textarea);
}

function editUser(userId) {
    const user = usersData.find(u => u.id === userId);
    if (!user) return;

    document.getElementById('editUserId').value = user.id;
    document.getElementById('editUsername').value = user.username;
    document.getElementById('editEmail').value = user.email;
    document.getElementById('editRole').value = user.role;
    document.getElementById('editUserModal').style.display = 'flex';
}

function hideEditUserModal() {
    document.getElementById('editUserModal').style.display = 'none';
}

async function updateUser() {
    const userId = document.getElementById('editUserId').value;
    const username = document.getElementById('editUsername').value;
    const email = document.getElementById('editEmail').value;
    const role = document.getElementById('editRole').value;

    try {
        const csrfToken = getCookie('csrf_token');
        const response = await fetch(`/admin/api/users/${userId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify({ username, email, role })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to update user');
        }

        hideEditUserModal();
        loadUsers();
        showToast('User updated successfully', 'success');
    } catch (error) {
        console.error('Update user error:', error);
        showToast(error.message, 'error');
    }
}

async function toggleUserStatus(userId, currentStatus) {
    const action = currentStatus ? 'disable' : 'enable';
    const message = `Are you sure you want to ${action} this user?`;

    if (!await confirm(message)) return;

    try {
        const csrfToken = getCookie('csrf_token');
        const response = await fetch(`/admin/api/users/${userId}/${action}`, {
            method: 'POST',
            headers: {
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include'
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || `Failed to ${action} user`);
        }

        loadUsers();
        showToast(`User ${action}d successfully`, 'success');
    } catch (error) {
        console.error('Toggle user status error:', error);
        showToast(error.message, 'error');
    }
}

async function resetUserPassword(userId) {
    if (!await confirm('Generate a new temporary password for this user?')) return;

    try {
        const csrfToken = getCookie('csrf_token');
        const response = await fetch(`/admin/api/users/${userId}/reset-password`, {
            method: 'POST',
            headers: {
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include'
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to reset password');
        }

        document.getElementById('resetPassword').textContent = data.temporary_password;
        document.getElementById('resetPasswordModal').style.display = 'flex';
        showToast('Password reset successfully', 'success');
    } catch (error) {
        console.error('Reset password error:', error);
        showToast(error.message, 'error');
    }
}

function hideResetPasswordModal() {
    document.getElementById('resetPasswordModal').style.display = 'none';
}

function copyResetPassword() {
    const password = document.getElementById('resetPassword').textContent;

    // Try modern clipboard API first
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(password).then(() => {
            showToast('Password copied to clipboard', 'success');
        }).catch(() => {
            // Fallback to textarea method
            copyToClipboardFallback(password);
        });
    } else {
        // Use fallback method
        copyToClipboardFallback(password);
    }
}

async function deleteUser(userId) {
    if (!await confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;

    try {
        const csrfToken = getCookie('csrf_token');
        const response = await fetch(`/admin/api/users/${userId}`, {
            method: 'DELETE',
            headers: {
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include'
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to delete user');
        }

        loadUsers();
        showToast('User deleted successfully', 'success');
    } catch (error) {
        console.error('Delete user error:', error);
        showToast(error.message, 'error');
    }
}

// ============ WEBHOOK MANAGEMENT FUNCTIONS ============

let autoRefreshInterval = null;

// Load webhook configurations
async function loadWebhooks() {
    try {
        const response = await fetch('/admin/api/webhooks');

        if (!response.ok) {
            throw new Error('Failed to load webhooks');
        }

        const webhooks = await response.json();
        updateWebhooksTable(webhooks || []);
    } catch (error) {
        console.error('Error loading webhooks:', error);
        showError('Failed to load webhook configurations');
    }
}

// Update webhooks table
function updateWebhooksTable(webhooks) {
    const tbody = document.getElementById('webhooksTableBody');

    if (webhooks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="loading">No webhooks configured</td></tr>';
        return;
    }

    tbody.innerHTML = webhooks.map(webhook => {
        const truncatedURL = webhook.url.length > 50 ? webhook.url.substring(0, 50) + '...' : webhook.url;
        const eventBadges = webhook.events.map(event => 
            `<span class="badge badge-info" style="margin: 2px; font-size: 11px;">${escapeHtml(event)}</span>`
        ).join('');

        return `
            <tr>
                <td>${webhook.id}</td>
                <td title="${escapeHtml(webhook.url)}">${escapeHtml(truncatedURL)}</td>
                <td><span class="badge ${webhook.enabled ? 'badge-yes' : 'badge-no'}">${webhook.enabled ? 'Yes' : 'No'}</span></td>
                <td>${eventBadges}</td>
                <td>${webhook.max_retries}</td>
                <td>${webhook.timeout_seconds}s</td>
                <td class="actions">
                    <button class="btn-icon btn-primary" onclick="editWebhook(${webhook.id})" title="Edit webhook">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                        </svg>
                    </button>
                    <button class="btn-icon btn-warning" onclick="testWebhook(${webhook.id})" title="Test webhook">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                        </svg>
                    </button>
                    <button class="btn-icon btn-danger" onclick="deleteWebhook(${webhook.id})" title="Delete webhook">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="3 6 5 6 21 6"></polyline>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                        </svg>
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

// Show create webhook modal
function showCreateWebhookModal() {
    document.getElementById('webhookModalTitle').textContent = 'Add Webhook';
    document.getElementById('webhookId').value = '';
    document.getElementById('webhookForm').reset();
    document.getElementById('webhookEnabled').checked = true;
    document.getElementById('webhookFormat').value = 'safeshare';
    document.getElementById('webhookMaxRetries').value = 5;
    document.getElementById('webhookTimeout').value = 30;
    document.getElementById('webhookServiceToken').value = '';
    
    // Hide service token field by default (safeshare format doesn't need it)
    updateServiceTokenVisibility('safeshare');
    
    document.getElementById('webhookModal').style.display = 'flex';
}

// Hide webhook modal
function hideWebhookModal() {
    document.getElementById('webhookModal').style.display = 'none';
}

// Update service token field visibility based on webhook format
function updateServiceTokenVisibility(format) {
    const serviceTokenGroup = document.getElementById('serviceTokenGroup');
    const serviceTokenHelp = document.getElementById('serviceTokenHelp');
    
    if (format === 'gotify' || format === 'ntfy') {
        serviceTokenGroup.style.display = 'block';
        
        // Update help text based on format
        if (format === 'gotify') {
            serviceTokenHelp.textContent = 'Gotify application token (will be appended to URL as ?token=...)';
        } else if (format === 'ntfy') {
            serviceTokenHelp.textContent = 'ntfy access token (sent as Authorization: Bearer header for private topics)';
        }
    } else {
        serviceTokenGroup.style.display = 'none';
    }
}

// Generate random webhook secret
function generateWebhookSecret() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let secret = '';
    for (let i = 0; i < 32; i++) {
        secret += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    const secretInput = document.getElementById('webhookSecret');
    secretInput.type = 'text';
    secretInput.value = secret;
    showSuccess('Secret generated successfully');
}

// Edit webhook
async function editWebhook(webhookId) {
    try {
        const response = await fetch('/admin/api/webhooks');
        if (!response.ok) {
            throw new Error('Failed to load webhook');
        }

        const webhooks = await response.json();
        const webhook = webhooks.find(w => w.id === webhookId);

        if (!webhook) {
            throw new Error('Webhook not found');
        }

        // Populate form
        document.getElementById('webhookModalTitle').textContent = 'Edit Webhook';
        document.getElementById('webhookId').value = webhook.id;
        document.getElementById('webhookURL').value = webhook.url;
        document.getElementById('webhookSecret').value = webhook.secret;
        document.getElementById('webhookServiceToken').value = webhook.service_token || '';
        document.getElementById('webhookEnabled').checked = webhook.enabled;
        document.getElementById('webhookFormat').value = webhook.format || 'safeshare';
        document.getElementById('webhookMaxRetries').value = webhook.max_retries;
        document.getElementById('webhookTimeout').value = webhook.timeout_seconds;

        // Update service token visibility based on format
        updateServiceTokenVisibility(webhook.format || 'safeshare');

        // Check event checkboxes
        document.querySelectorAll('.webhook-event').forEach(cb => {
            cb.checked = webhook.events.includes(cb.value);
        });

        document.getElementById('webhookModal').style.display = 'flex';
    } catch (error) {
        console.error('Error loading webhook:', error);
        showError(error.message);
    }
}

// Save webhook (create or update)
async function saveWebhook(formData) {
    const webhookId = document.getElementById('webhookId').value;
    const url = formData.get('url');
    const secret = formData.get('secret');
    const serviceToken = formData.get('service_token') || '';
    const enabled = document.getElementById('webhookEnabled').checked;
    const format = formData.get('format') || 'safeshare';
    const maxRetries = parseInt(formData.get('max_retries'));
    const timeoutSeconds = parseInt(formData.get('timeout_seconds'));

    // Get selected events
    const events = Array.from(document.querySelectorAll('.webhook-event:checked'))
        .map(cb => cb.value);

    if (events.length === 0) {
        showError('Please select at least one event type');
        return;
    }

    const payload = {
        url,
        secret,
        service_token: serviceToken,
        enabled,
        events,
        format,
        max_retries: maxRetries,
        timeout_seconds: timeoutSeconds
    };

    try {
        let response;
        if (webhookId) {
            // Update existing webhook
            response = await fetch(`/admin/api/webhooks/update?id=${webhookId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': getCSRFToken()
                },
                body: JSON.stringify(payload)
            });
        } else {
            // Create new webhook
            response = await fetch('/admin/api/webhooks', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': getCSRFToken()
                },
                body: JSON.stringify(payload)
            });
        }

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to save webhook');
        }

        hideWebhookModal();
        loadWebhooks();
        showSuccess(webhookId ? 'Webhook updated successfully' : 'Webhook created successfully');
    } catch (error) {
        console.error('Error saving webhook:', error);
        showError(error.message);
    }
}

// Delete webhook
async function deleteWebhook(webhookId) {
    if (!await confirm('Delete this webhook configuration?')) {
        return;
    }

    try {
        const response = await fetch(`/admin/api/webhooks/delete?id=${webhookId}`, {
            method: 'DELETE',
            headers: {
                'X-CSRF-Token': getCSRFToken()
            }
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to delete webhook');
        }

        loadWebhooks();
        showSuccess('Webhook deleted successfully');
    } catch (error) {
        console.error('Error deleting webhook:', error);
        showError(error.message);
    }
}

// Test webhook
async function testWebhook(webhookId) {
    try {
        const response = await fetch(`/admin/api/webhooks/test?id=${webhookId}`, {
            method: 'POST',
            headers: {
                'X-CSRF-Token': getCSRFToken()
            }
        });

        const data = await response.json();

        if (data.success) {
            showSuccess(`Test webhook sent successfully. Response: ${data.response_code}`);
        } else {
            showWarning(`Test webhook failed: ${data.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error testing webhook:', error);
        showError('Failed to send test webhook');
    }
}

// Load webhook deliveries
let currentDeliveryFilters = { event: '', status: '' };

async function loadDeliveries() {
    try {
        const response = await fetch('/admin/api/webhook-deliveries?limit=50&offset=0');

        if (!response.ok) {
            throw new Error('Failed to load deliveries');
        }

        const deliveries = await response.json();
        updateDeliveriesTable(deliveries || []);
    } catch (error) {
        console.error('Error loading deliveries:', error);
        showError('Failed to load webhook deliveries');
    }
}

// Update deliveries table
function updateDeliveriesTable(deliveries) {
    const tbody = document.getElementById('deliveriesTableBody');

    // Apply filters
    let filteredDeliveries = deliveries;
    if (currentDeliveryFilters.event) {
        filteredDeliveries = filteredDeliveries.filter(d => d.event_type === currentDeliveryFilters.event);
    }
    if (currentDeliveryFilters.status) {
        filteredDeliveries = filteredDeliveries.filter(d => d.status === currentDeliveryFilters.status);
    }

    if (filteredDeliveries.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading">No deliveries found</td></tr>';
        return;
    }

    tbody.innerHTML = filteredDeliveries.map(delivery => {
        let statusBadge;
        switch (delivery.status) {
            case 'success':
                statusBadge = '<span class="badge badge-yes">Success</span>';
                break;
            case 'failed':
                statusBadge = '<span class="badge badge-no">Failed</span>';
                break;
            case 'retrying':
                statusBadge = '<span class="badge badge-warning">Retrying</span>';
                break;
            default:
                statusBadge = '<span class="badge badge-info">Unknown</span>';
        }

        return `
            <tr>
                <td>${formatDate(delivery.created_at)}</td>
                <td><span class="badge badge-info" style="font-size: 11px;">${escapeHtml(delivery.event_type)}</span></td>
                <td>${statusBadge}</td>
                <td>${delivery.response_code || '-'}</td>
                <td>${delivery.attempt_count}</td>
                <td>
                    <button class="btn-small btn-action" onclick="viewDeliveryDetails(${delivery.id})" title="View details">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                            <circle cx="12" cy="12" r="3"></circle>
                        </svg>
                        Details
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

// View delivery details
async function viewDeliveryDetails(deliveryId) {
    try {
        const response = await fetch(`/admin/api/webhook-deliveries/detail?id=${deliveryId}`);

        if (!response.ok) {
            throw new Error('Failed to load delivery details');
        }

        const delivery = await response.json();
        displayDeliveryDetails(delivery);
    } catch (error) {
        console.error('Error loading delivery details:', error);
        showError('Failed to load delivery details');
    }
}

// Display delivery details in modal
function displayDeliveryDetails(delivery) {
    const content = document.getElementById('deliveryDetailContent');
    
    let statusBadge;
    switch (delivery.status) {
        case 'success':
            statusBadge = '<span class="badge badge-yes">Success</span>';
            break;
        case 'failed':
            statusBadge = '<span class="badge badge-no">Failed</span>';
            break;
        case 'retrying':
            statusBadge = '<span class="badge badge-warning">Retrying</span>';
            break;
        default:
            statusBadge = '<span class="badge badge-info">Unknown</span>';
    }

    content.innerHTML = `
        <div style="display: grid; gap: 16px;">
            <div>
                <strong>Delivery ID:</strong> ${delivery.id}
            </div>
            <div>
                <strong>Webhook Config ID:</strong> ${delivery.webhook_config_id}
            </div>
            <div>
                <strong>Event Type:</strong> <span class="badge badge-info" style="font-size: 11px;">${escapeHtml(delivery.event_type)}</span>
            </div>
            <div>
                <strong>Status:</strong> ${statusBadge}
            </div>
            <div>
                <strong>Attempt Count:</strong> ${delivery.attempt_count}
            </div>
            <div>
                <strong>Response Code:</strong> ${delivery.response_code || '-'}
            </div>
            <div>
                <strong>Created At:</strong> ${formatDate(delivery.created_at)}
            </div>
            ${delivery.completed_at ? `<div><strong>Completed At:</strong> ${formatDate(delivery.completed_at)}</div>` : ''}
            ${delivery.next_retry_at ? `<div><strong>Next Retry:</strong> ${formatDate(delivery.next_retry_at)}</div>` : ''}
            <div>
                <strong>Payload:</strong>
                <pre style="background: var(--bg-light); padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 12px; margin-top: 8px;">${escapeHtml(delivery.payload)}</pre>
            </div>
            ${delivery.response_body ? `
                <div>
                    <strong>Response Body:</strong>
                    <pre style="background: var(--bg-light); padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 12px; margin-top: 8px;">${escapeHtml(delivery.response_body)}</pre>
                </div>
            ` : ''}
            ${delivery.error_message ? `
                <div>
                    <strong>Error Message:</strong>
                    <pre style="background: var(--bg-light); padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 12px; margin-top: 8px; color: var(--danger-color);">${escapeHtml(delivery.error_message)}</pre>
                </div>
            ` : ''}
        </div>
    `;

    document.getElementById('deliveryDetailModal').style.display = 'flex';
}

// Hide delivery detail modal
function hideDeliveryDetailModal() {
    document.getElementById('deliveryDetailModal').style.display = 'none';
}

// Handle auto-refresh
function toggleAutoRefresh() {
    const checkbox = document.getElementById('autoRefreshDeliveries');
    if (checkbox.checked) {
        // Start auto-refresh
        autoRefreshInterval = setInterval(() => {
            loadDeliveries();
        }, 10000); // 10 seconds
    } else {
        // Stop auto-refresh
        if (autoRefreshInterval) {
            clearInterval(autoRefreshInterval);
            autoRefreshInterval = null;
        }
    }
}
