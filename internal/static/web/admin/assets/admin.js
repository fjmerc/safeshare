// Admin Dashboard JavaScript

// Global state
let currentPage = 1;
let searchTerm = '';
let csrfToken = '';

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
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
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

        if (data.stats.quota_limit_bytes > 0) {
            const percent = data.stats.quota_used_percent.toFixed(1);
            document.getElementById('statQuotaUsage').textContent = percent + '%';
        } else {
            document.getElementById('statQuotaUsage').textContent = 'Unlimited';
        }

        document.getElementById('statBlockedIPs').textContent = data.blocked_ips?.length || 0;

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
        return;
    }

    tbody.innerHTML = files.map(file => `
        <tr>
            <td>
                <input type="checkbox" class="file-checkbox" data-claim-code="${escapeHtml(file.claim_code)}">
            </td>
            <td><code>${escapeHtml(file.claim_code)}</code></td>
            <td title="${escapeHtml(file.original_filename)}">${truncate(escapeHtml(file.original_filename), 30)}</td>
            <td>${formatBytes(file.file_size)}</td>
            <td>${escapeHtml(file.uploader_ip || 'Unknown')}</td>
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
        document.getElementById('quotaGB').value = data.quota_limit_gb || 0;
        document.getElementById('maxFileSizeMB').value = Math.round(data.max_file_size_bytes / (1024 * 1024)) || 100;
        document.getElementById('defaultExpirationHours').value = data.default_expiration_hours || 24;
        document.getElementById('maxExpirationHours').value = data.max_expiration_hours || 168;

        // Populate security settings
        document.getElementById('rateLimitUpload').value = data.rate_limit_upload || 10;
        document.getElementById('rateLimitDownload').value = data.rate_limit_download || 100;
        document.getElementById('blockedExtensions').value = (data.blocked_extensions || []).join(',');
    } catch (error) {
        console.error('Error loading config values:', error);
    }
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

function truncate(str, length) {
    return str.length > length ? str.substring(0, length) + '...' : str;
}

// Toast notification system
function showToast(message, type = 'success') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    const title = type === 'success' ? 'Success' : type === 'error' ? 'Error' : 'Warning';

    toast.innerHTML = `
        <div class="toast-content">
            <div class="toast-title">${title}</div>
            <div class="toast-message">${escapeHtml(message)}</div>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">×</button>
    `;

    container.appendChild(toast);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        toast.style.animation = 'slideInRight 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

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

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Only initialize if we're on the dashboard page
    if (!document.querySelector('.dashboard-page')) {
        return;
    }

    // Get CSRF token
    csrfToken = getCSRFToken();

    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tabName = btn.dataset.tab;

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
    document.getElementById('refreshBtn')?.addEventListener('click', () => {
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

    document.getElementById('refreshUsersBtn')?.addEventListener('click', () => {
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

    // Load initial data
    loadDashboardData();
    loadConfigValues(); // Load config values for settings tab
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
                <button class="btn-icon btn-secondary" onclick="resetUserPassword(${user.id})" title="Reset Password">
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
    navigator.clipboard.writeText(password).then(() => {
        showToast('Password copied to clipboard', 'success');
    }).catch(() => {
        showToast('Failed to copy password', 'error');
    });
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

    if (!confirm(message)) return;

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
    if (!confirm('Generate a new temporary password for this user?')) return;

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
    navigator.clipboard.writeText(password).then(() => {
        showToast('Password copied to clipboard', 'success');
    }).catch(() => {
        showToast('Failed to copy password', 'error');
    });
}

async function deleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;

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
