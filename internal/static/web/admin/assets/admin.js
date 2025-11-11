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
            <td>${file.download_count} / ${file.max_downloads || '∞'}</td>
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
        blockIP(formData.get('ip_address'), formData.get('reason') || 'Blocked by admin');
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
            }
        });
    });

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
});

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
