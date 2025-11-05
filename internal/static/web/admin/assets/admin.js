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
        tbody.innerHTML = '<tr><td colspan="9" class="loading">No files found</td></tr>';
        return;
    }

    tbody.innerHTML = files.map(file => `
        <tr>
            <td><code>${escapeHtml(file.claim_code)}</code></td>
            <td title="${escapeHtml(file.original_filename)}">${truncate(escapeHtml(file.original_filename), 30)}</td>
            <td>${formatBytes(file.file_size)}</td>
            <td>${escapeHtml(file.uploader_ip || 'Unknown')}</td>
            <td>${formatDate(file.created_at)}</td>
            <td>${formatDate(file.expires_at)}</td>
            <td>${file.download_count} / ${file.max_downloads || '∞'}</td>
            <td><span class="badge ${file.password_protected ? 'badge-yes' : 'badge-no'}">${file.password_protected ? 'Yes' : 'No'}</span></td>
            <td>
                <button class="btn-small btn-delete" onclick="deleteFile('${escapeHtml(file.claim_code)}')">Delete</button>
            </td>
        </tr>
    `).join('');
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
                <button class="btn-small btn-action" onclick="unblockIP('${escapeHtml(ip.IPAddress)}')">Unblock</button>
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

// Update quota
async function updateQuota(quotaGB) {
    try {
        const response = await fetch('/admin/api/quota/update', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': getCSRFToken()
            },
            body: new URLSearchParams({ quota_gb: quotaGB })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showSuccess(`Quota updated from ${data.old_quota_gb}GB to ${data.new_quota_gb}GB`);
            loadDashboardData(currentPage, searchTerm);
        } else {
            showError(data.message || 'Failed to update quota');
        }
    } catch (error) {
        console.error('Error updating quota:', error);
        showError('Failed to update quota');
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

function showError(message) {
    alert('Error: ' + message);
}

function showSuccess(message) {
    alert(message);
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

    // Quota form
    document.getElementById('quotaForm')?.addEventListener('submit', (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        updateQuota(formData.get('quota_gb'));
    });

    // Load initial data
    loadDashboardData();
});
