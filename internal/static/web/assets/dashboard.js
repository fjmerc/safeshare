        // Load theme preference from localStorage
        (function() {
            const savedTheme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', savedTheme);
        })();

        // Universal password toggle handler
        document.addEventListener('DOMContentLoaded', () => {
            document.querySelectorAll('[data-password-toggle]').forEach(button => {
                button.addEventListener('click', () => {
                    const targetId = button.getAttribute('data-password-toggle');
                    const passwordInput = document.getElementById(targetId);
                    const eyeIcon = button.querySelector('.eye-icon');
                    const eyeOffIcon = button.querySelector('.eye-off-icon');

                    if (passwordInput.type === 'password') {
                        passwordInput.type = 'text';
                        if (eyeIcon && eyeOffIcon) {
                            eyeIcon.style.display = 'none';
                            eyeOffIcon.style.display = 'block';
                        }
                    } else {
                        passwordInput.type = 'password';
                        if (eyeIcon && eyeOffIcon) {
                            eyeIcon.style.display = 'block';
                            eyeOffIcon.style.display = 'none';
                        }
                    }
                });
            });
        });

        let currentUser = null;

        // CSRF token helper
        function getCSRFToken() {
            const cookies = document.cookie.split(';');
            // User dashboard uses user_csrf_token, admin uses csrf_token
            for (let cookie of cookies) {
                const parts = cookie.trim().split('=');
                const name = parts[0];
                const value = parts.slice(1).join('='); // Handle '=' in token value
                if (name === 'user_csrf_token') {
                    return value;
                }
            }
            // Fallback to admin csrf_token or sessionStorage
            for (let cookie of cookies) {
                const parts = cookie.trim().split('=');
                const name = parts[0];
                const value = parts.slice(1).join('=');
                if (name === 'csrf_token') {
                    return value;
                }
            }
            return sessionStorage.getItem('csrf_token') || '';
        }
        let fileToDelete = null;
        let fileToRename = { id: null, currentName: '' };
        let fileToEditExpiration = { id: null, currentExpiration: '' };
        let maxExpirationHours = 168; // Default, will be loaded from config

        // Check authentication and load user info
        async function checkAuth() {
            try {
                const response = await fetch('/api/auth/user', {
                    credentials: 'include'
                });

                if (response.ok) {
                    currentUser = await response.json();
                    document.getElementById('userName').textContent = currentUser.username;

                    // Show admin dashboard button if user is admin
                    if (currentUser.role === 'admin') {
                        document.getElementById('adminDashboardBtn').style.display = 'inline-flex';
                    }

                    // Check if password change is required
                    const urlParams = new URLSearchParams(window.location.search);
                    if (currentUser.require_password_change || urlParams.get('change_password') === 'true') {
                        showToast('Please change your temporary password to continue.', 'info');
                        showChangePasswordModal();
                    }

                    loadConfig();
                    loadFiles();
                    loadTokens();
                    loadMFAStatus();
                    initSSOLinkedAccounts();
                } else {
                    // Not authenticated, redirect to login
                    window.location.href = '/login';
                }
            } catch (error) {
                console.error('Auth check failed:', error);
                window.location.href = '/login';
            }
        }

        // Load config (for max expiration hours)
        async function loadConfig() {
            try {
                const response = await fetch('/api/config');
                if (response.ok) {
                    const config = await response.json();
                    maxExpirationHours = config.max_expiration_hours || 168;
                }
            } catch (error) {
                console.error('Failed to load config:', error);
                // Keep default value
            }
        }

        // Load files
        async function loadFiles() {
            try {
                const response = await fetch('/api/user/files?limit=100&offset=0', {
                    credentials: 'include'
                });

                if (response.ok) {
                    const data = await response.json();
                    displayFiles(data.files);
                } else {
                    showToast('Failed to load files', 'error');
                }
            } catch (error) {
                console.error('Failed to load files:', error);
                showToast('Network error loading files', 'error');
            }
        }

        // Display files in table
        function displayFiles(files) {
            const container = document.getElementById('filesContainer');

            if (!files || files.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                        </svg>
                        <h3>No files yet</h3>
                        <p>Upload your first file to get started!</p>
                    </div>
                `;
                return;
            }

            let tableHTML = `
                <div class="files-table-wrapper">
                    <table class="files-table">
                        <thead>
                            <tr>
                                <th>File Name</th>
                                <th>File Size</th>
                                <th>Claim Code</th>
                                <th>Uploaded</th>
                                <th>Expires</th>
                                <th style="text-align: center;">Downloads</th>
                                <th style="text-align: center;">Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
            `;

            files.forEach(file => {
                const createdDate = formatCompactDate(file.created_at);
                const createdDateFull = new Date(file.created_at).toLocaleString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true });

                // Check if "never expire" (year 9999)
                const expiresDateObj = new Date(file.expires_at);
                const expiresDate = expiresDateObj.getFullYear() === 9999 ? 'Never' : formatCompactDate(file.expires_at);
                const expiresDateFull = expiresDateObj.getFullYear() === 9999 ? 'Never expires' : expiresDateObj.toLocaleString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true });

                const downloads = file.max_downloads ? `${file.completed_downloads}/${file.max_downloads}` : file.completed_downloads;

                let statusBadge = '';
                if (file.is_expired) {
                    statusBadge = '<span class="badge badge-danger">Expired</span>';
                } else if (file.max_downloads && file.completed_downloads >= file.max_downloads) {
                    statusBadge = '<span class="badge badge-warning">Limit Reached</span>';
                } else {
                    statusBadge = '<span class="badge badge-success">Active</span>';
                }

                const downloadUrl = file.download_url;

                tableHTML += `
                    <tr>
                        <td>
                            <div class="file-name">
                                <span class="file-name-text">${escapeHtml(file.original_filename)}</span>
                                <svg class="inline-edit-icon" data-action="renameFile" data-file-id="${file.id}" data-filename="${escapeHtml(file.original_filename)}" title="Rename file" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"></path>
                                </svg>
                            </div>
                        </td>
                        <td><span class="file-size">${formatFileSize(file.file_size)}</span></td>
                        <td><span class="claim-code">${file.claim_code}</span></td>
                        <td><span class="date-truncate" title="${createdDateFull}">${createdDate}</span></td>
                        <td>
                            <div class="file-name-expires">
                                <span class="file-name-text" title="${expiresDateFull}">${expiresDate}</span>
                                <svg class="inline-edit-icon" data-action="editExpiration" data-file-id="${file.id}" data-expires-at="${file.expires_at}" title="Edit expiration" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"></path>
                                </svg>
                            </div>
                        </td>
                        <td style="text-align: center;">${downloads}</td>
                        <td style="text-align: center;">${statusBadge}</td>
                        <td class="actions-col">
                            <div class="actions-cell">
                                <button class="btn-icon btn-primary" data-action="openShareModal" data-file-id="${file.id}" data-filename="${escapeHtml(file.original_filename)}" data-file-size="${file.file_size}" data-download-url="${downloadUrl}" data-expires-at="${file.expires_at}" data-max-downloads="${file.max_downloads || ''}" data-download-count="${file.completed_downloads}" data-claim-code="${file.claim_code}" title="Share File">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <circle cx="18" cy="5" r="3"></circle>
                                        <circle cx="6" cy="12" r="3"></circle>
                                        <circle cx="18" cy="19" r="3"></circle>
                                        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line>
                                        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line>
                                    </svg>
                                </button>
                                <button class="btn-icon btn-danger" data-action="deleteFile" data-file-id="${file.id}" title="Delete">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <polyline points="3 6 5 6 21 6"></polyline>
                                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                                    </svg>
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            });

            tableHTML += `
                    </tbody>
                </table>
            </div>
            `;

            container.innerHTML = tableHTML;
        }

        // Delete file
        function deleteFile(fileId) {
            fileToDelete = fileId;
            document.getElementById('deleteModal').classList.add('show');
        }

        async function confirmDelete() {
            if (!fileToDelete) return;

            try {
                const response = await fetch('/api/user/files/delete', {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'include',
                    body: JSON.stringify({ file_id: fileToDelete }),
                });

                if (response.ok) {
                    showToast('File deleted successfully', 'success');
                    loadFiles();
                } else {
                    const data = await response.json();
                    showToast(data.error || 'Failed to delete file', 'error');
                }
            } catch (error) {
                console.error('Delete failed:', error);
                showToast('Network error deleting file', 'error');
            }

            hideDeleteModal();
        }

        function hideDeleteModal() {
            document.getElementById('deleteModal').classList.remove('show');
            fileToDelete = null;
        }

        // Rename file
        function renameFile(fileId, currentName) {
            fileToRename = { id: fileId, currentName: currentName };
            document.getElementById('newFilename').value = currentName;
            document.getElementById('renameModal').classList.add('show');
            // Focus the input field
            setTimeout(() => document.getElementById('newFilename').focus(), 100);
        }

        async function confirmRename() {
            if (!fileToRename.id) return;

            const newFilename = document.getElementById('newFilename').value.trim();
            if (!newFilename) {
                showToast('Filename cannot be empty', 'error');
                return;
            }

            try {
                const response = await fetch('/api/user/files/rename', {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'include',
                    body: JSON.stringify({
                        file_id: fileToRename.id,
                        new_filename: newFilename,
                    }),
                });

                const data = await response.json();

                if (response.ok) {
                    showToast('File renamed successfully', 'success');
                    loadFiles();
                    hideRenameModal();
                } else {
                    showToast(data.error || 'Failed to rename file', 'error');
                }
            } catch (error) {
                console.error('Rename failed:', error);
                showToast('Network error renaming file', 'error');
            }
        }

        function hideRenameModal() {
            document.getElementById('renameModal').classList.remove('show');
            fileToRename = { id: null, currentName: '' };
            document.getElementById('newFilename').value = '';
        }

        // Edit file expiration
        function editExpiration(fileId, currentExpiration) {
            fileToEditExpiration = { id: fileId, currentExpiration: currentExpiration };

            // Check if current expiration is "never expire" (year 9999)
            const expirationDate = new Date(currentExpiration);
            const isNeverExpire = expirationDate.getFullYear() === 9999;

            const neverExpireCheckbox = document.getElementById('neverExpireCheckbox');
            const expirationOptionsContainer = document.getElementById('expirationOptionsContainer');
            const datetimeInput = document.getElementById('newExpiration');
            const previewContainer = document.getElementById('expirationPreview');
            const previewDate = document.getElementById('expirationPreviewDate');
            const maxExpirationText = document.getElementById('maxExpirationText');

            // Reset form
            neverExpireCheckbox.checked = isNeverExpire;
            datetimeInput.value = '';
            previewContainer.style.display = 'none';
            document.querySelectorAll('.preset-btn').forEach(btn => btn.classList.remove('selected'));

            // Set min/max attributes for datetime input
            const now = new Date();
            const minDatetime = new Date(now.getTime() - now.getTimezoneOffset() * 60000)
                .toISOString()
                .slice(0, 16);
            datetimeInput.setAttribute('min', minDatetime);

            const maxDate = new Date(now.getTime() + maxExpirationHours * 60 * 60 * 1000);
            const maxDatetime = new Date(maxDate.getTime() - maxDate.getTimezoneOffset() * 60000)
                .toISOString()
                .slice(0, 16);
            datetimeInput.setAttribute('max', maxDatetime);

            // Set maximum expiration text
            maxExpirationText.textContent = formatCompactDate(maxDate.toISOString());

            // Toggle options visibility based on "Never expire" checkbox
            function toggleExpirationOptions() {
                if (neverExpireCheckbox.checked) {
                    expirationOptionsContainer.style.display = 'none';
                } else {
                    expirationOptionsContainer.style.display = 'block';
                }
            }

            // Update expiration preview
            function updatePreview(hours) {
                if (!hours || hours <= 0 || neverExpireCheckbox.checked) {
                    previewContainer.style.display = 'none';
                    return;
                }

                const futureDate = new Date(Date.now() + hours * 60 * 60 * 1000);
                previewDate.textContent = formatCompactDate(futureDate.toISOString());
                previewContainer.style.display = 'block';
            }

            // Initial toggle
            toggleExpirationOptions();

            // Never expire checkbox handler
            neverExpireCheckbox.addEventListener('change', function() {
                toggleExpirationOptions();
                if (this.checked) {
                    previewContainer.style.display = 'none';
                    customValueInput.value = '';
                    document.querySelectorAll('.preset-btn').forEach(btn => btn.classList.remove('selected'));
                }
            });

            // Preset button handlers
            document.querySelectorAll('.preset-btn').forEach(btn => {
                btn.addEventListener('click', function(e) {
                    e.preventDefault();
                    const hours = parseInt(this.getAttribute('data-hours'));

                    // Validate against max expiration
                    if (hours > maxExpirationHours) {
                        showToast(`Cannot exceed maximum of ${maxExpirationHours} hours`, 'error');
                        return;
                    }

                    // Calculate future date
                    const futureDate = new Date(Date.now() + hours * 60 * 60 * 1000);

                    // Convert to local datetime format for input (YYYY-MM-DDTHH:MM)
                    const localDatetime = new Date(futureDate.getTime() - futureDate.getTimezoneOffset() * 60000)
                        .toISOString()
                        .slice(0, 16);

                    // Populate datetime input
                    datetimeInput.value = localDatetime;

                    // Update UI
                    document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('selected'));
                    this.classList.add('selected');

                    // Update preview
                    updatePreview(hours);
                });
            });

            // Datetime input change handler
            datetimeInput.addEventListener('change', function() {
                // Clear preset selection when manually changing datetime
                document.querySelectorAll('.preset-btn').forEach(btn => btn.classList.remove('selected'));

                if (this.value) {
                    // Calculate hours from now until selected datetime
                    const selectedDate = new Date(this.value);
                    const hours = Math.round((selectedDate.getTime() - Date.now()) / (1000 * 60 * 60));
                    updatePreview(hours);
                } else {
                    previewContainer.style.display = 'none';
                }
            });

            // Show modal
            document.getElementById('editExpirationModal').classList.add('show');
        }

        async function confirmExpirationUpdate() {
            if (!fileToEditExpiration.id) return;

            const neverExpireCheckbox = document.getElementById('neverExpireCheckbox');
            const datetimeInput = document.getElementById('newExpiration');
            let isoExpiration;

            if (neverExpireCheckbox.checked) {
                // Set to "never expire" sentinel date
                isoExpiration = '9999-12-31T23:59:59Z';
            } else {
                // Get value from datetime input
                const newExpiration = datetimeInput.value;
                if (!newExpiration) {
                    showToast('Please select an expiration date or choose a preset', 'error');
                    return;
                }

                // Convert local datetime to ISO8601/RFC3339
                const expirationDate = new Date(newExpiration);
                isoExpiration = expirationDate.toISOString();
            }

            try {
                const response = await fetch('/api/user/files/update-expiration', {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'include',
                    body: JSON.stringify({
                        file_id: fileToEditExpiration.id,
                        new_expiration: isoExpiration,
                    }),
                });

                const data = await response.json();

                if (response.ok) {
                    showToast('Expiration updated successfully', 'success');
                    loadFiles();
                    hideExpirationModal();
                } else {
                    showToast(data.error || 'Failed to update expiration', 'error');
                }
            } catch (error) {
                console.error('Update expiration failed:', error);
                showToast('Network error updating expiration', 'error');
            }
        }

        function hideExpirationModal() {
            document.getElementById('editExpirationModal').classList.remove('show');
            fileToEditExpiration = { id: null, currentExpiration: '' };
            document.getElementById('neverExpireCheckbox').checked = false;
            document.getElementById('newExpiration').value = '';
            document.getElementById('expirationPreview').style.display = 'none';
            document.querySelectorAll('.preset-btn').forEach(btn => btn.classList.remove('selected'));
        }

        // Change password
        function showChangePasswordModal() {
            document.getElementById('changePasswordModal').classList.add('show');
        }

        function hideChangePasswordModal() {
            document.getElementById('changePasswordModal').classList.remove('show');
            document.getElementById('changePasswordForm').reset();
        }

        async function changePassword() {
            const currentPassword = document.getElementById('currentPassword').value;
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;

            if (newPassword !== confirmPassword) {
                showToast('New passwords do not match', 'error');
                return;
            }

            if (newPassword.length < 8) {
                showToast('Password must be at least 8 characters', 'error');
                return;
            }

            try {
                const response = await fetch('/api/auth/change-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'include',
                    body: JSON.stringify({
                        current_password: currentPassword,
                        new_password: newPassword,
                        confirm_password: confirmPassword,
                    }),
                });

                const data = await response.json();

                if (response.ok) {
                    showToast('Password changed successfully', 'success');
                    hideChangePasswordModal();

                    // Remove change_password URL parameter if present
                    const url = new URL(window.location);
                    if (url.searchParams.has('change_password')) {
                        url.searchParams.delete('change_password');
                        window.history.replaceState({}, '', url);
                    }

                    // Refresh user info
                    checkAuth();
                } else {
                    showToast(data.error || 'Failed to change password', 'error');
                }
            } catch (error) {
                console.error('Password change failed:', error);
                showToast('Network error changing password', 'error');
            }
        }

        // Logout
        async function logout() {
            try {
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    credentials: 'include',
                });
                window.location.href = '/login';
            } catch (error) {
                console.error('Logout failed:', error);
                window.location.href = '/login';
            }
        }

        // Utility functions

        function copyDownloadLink(url, button) {
            // Try modern Clipboard API first, with fallback
            const copyToClipboard = (text) => {
                // Modern Clipboard API
                if (navigator.clipboard && window.isSecureContext) {
                    return navigator.clipboard.writeText(text);
                } else {
                    // Fallback for non-secure contexts (HTTP)
                    return new Promise((resolve, reject) => {
                        const textArea = document.createElement('textarea');
                        textArea.value = text;
                        textArea.style.position = 'fixed';
                        textArea.style.left = '-999999px';
                        textArea.style.top = '-999999px';
                        document.body.appendChild(textArea);
                        textArea.focus();
                        textArea.select();

                        try {
                            const successful = document.execCommand('copy');
                            document.body.removeChild(textArea);
                            if (successful) {
                                resolve();
                            } else {
                                reject(new Error('Copy command failed'));
                            }
                        } catch (err) {
                            document.body.removeChild(textArea);
                            reject(err);
                        }
                    });
                }
            };

            copyToClipboard(url).then(() => {
                // Visual feedback on button
                const originalHTML = button.innerHTML;
                button.innerHTML = `
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                `;
                button.style.background = '#10b981';
                button.style.borderColor = '#10b981';
                button.style.color = 'white';

                showToast('Download link copied to clipboard', 'success');

                // Reset after 2 seconds
                setTimeout(() => {
                    button.innerHTML = originalHTML;
                    button.style.background = '';
                    button.style.borderColor = '';
                    button.style.color = '';
                }, 2000);
            }).catch((err) => {
                console.error('Copy failed:', err);
                showToast('Failed to copy link', 'error');
            });
        }

        function formatFileSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
            if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
            return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Format date in compact format (e.g., "11/05/25 3:45 PM")
        function formatCompactDate(dateString) {
            const date = new Date(dateString);
            const month = String(date.getMonth() + 1).padStart(2, '0'); // Months are 0-indexed
            const day = String(date.getDate()).padStart(2, '0');
            const year = String(date.getFullYear()).slice(-2); // Get last 2 digits of year
            const time = date.toLocaleString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });

            return `${month}/${day}/${year} ${time}`;
        }

        // Refresh files with animation
        function refreshFiles() {
            const btn = document.getElementById('refreshBtn');
            btn.classList.add('btn-refreshing');
            setTimeout(() => btn.classList.remove('btn-refreshing'), 600);
            loadFiles();
        }

        // Toggle theme
        function toggleTheme() {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);

            // Update theme icon
            const sunIcon = document.querySelector('.theme-icon-sun');
            const moonIcon = document.querySelector('.theme-icon-moon');

            if (sunIcon && moonIcon) {
                if (newTheme === 'dark') {
                    sunIcon.style.display = 'block';
                    moonIcon.style.display = 'none';
                } else {
                    sunIcon.style.display = 'none';
                    moonIcon.style.display = 'block';
                }
            }
        }

        // ========== Share Functions ==========

        // State for current share data
        let currentShareData = null;

        // Open share modal or use Web Share API
        async function openShareModal(fileData) {
            currentShareData = fileData;

            // Check if Web Share API is supported
            if (navigator.share) {
                try {
                    const shareText = generateShareMessage(currentShareData);
                    await navigator.share({
                        title: `File shared: ${currentShareData.original_filename}`,
                        text: shareText,
                        url: currentShareData.download_url
                    });
                    // User completed share (or cancelled, which is fine)
                } catch (error) {
                    // Only show error if it's not a user cancellation
                    if (error.name !== 'AbortError') {
                        console.error('Share error:', error);
                        // Fallback to modal
                        showShareModal();
                    }
                }
            } else {
                // Web Share API not supported, show modal
                showShareModal();
            }
        }

        // Show share modal
        function showShareModal() {
            const shareModal = document.getElementById('shareModal');
            if (shareModal) {
                shareModal.classList.remove('hidden');
            }
        }

        // Close share modal
        function closeShareModal() {
            const shareModal = document.getElementById('shareModal');
            if (shareModal) {
                shareModal.classList.add('hidden');
            }
        }

        // Show detailed share modal
        function showDetailedShareModal() {
            if (!currentShareData) {
                showToast('No file data available', 'error');
                return;
            }

            // Populate modal with file data
            document.getElementById('shareFileName').textContent = currentShareData.original_filename;
            document.getElementById('shareFileSize').textContent = formatFileSize(currentShareData.file_size);
            document.getElementById('shareExpires').textContent = formatCompactDate(currentShareData.expires_at);

            const downloadsText = currentShareData.max_downloads
                ? `${currentShareData.download_count}/${currentShareData.max_downloads}`
                : `${currentShareData.download_count}/∞`;
            document.getElementById('shareDownloads').textContent = downloadsText;

            document.getElementById('shareDownloadUrl').value = currentShareData.download_url;

            // Show modal
            document.getElementById('detailedShareModal').classList.add('show');
        }

        // Hide detailed share modal
        function hideDetailedShareModal() {
            document.getElementById('detailedShareModal').classList.remove('show');
        }

        // Copy share link from detailed modal
        function copyShareLink() {
            const urlInput = document.getElementById('shareDownloadUrl');
            urlInput.select();

            try {
                document.execCommand('copy');
                showToast('Link copied to clipboard!', 'success');
            } catch (err) {
                // Fallback for modern browsers
                navigator.clipboard.writeText(urlInput.value).then(() => {
                    showToast('Link copied to clipboard!', 'success');
                }).catch(() => {
                    showToast('Failed to copy link', 'error');
                });
            }
        }

        // Show regenerate confirmation modal
        function showRegenerateConfirmation() {
            if (!currentShareData) {
                showToast('No file data available', 'error');
                return;
            }

            // Populate current claim code
            document.getElementById('currentClaimCodeDisplay').textContent = currentShareData.claim_code;

            // Show confirmation modal
            document.getElementById('regenerateConfirmModal').classList.add('show');
        }

        // Hide regenerate confirmation modal
        function hideRegenerateConfirmation() {
            document.getElementById('regenerateConfirmModal').classList.remove('show');
        }

        // Execute claim code regeneration
        async function executeRegenerateClaim() {
            if (!currentShareData || !currentShareData.id) {
                showToast('No file data available', 'error');
                return;
            }

            const confirmBtn = document.getElementById('confirmRegenerateBtn');
            const originalText = confirmBtn.textContent;
            confirmBtn.disabled = true;
            confirmBtn.textContent = 'Regenerating...';

            try {
                const response = await fetch('/api/user/files/regenerate-claim-code', {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'include',
                    body: JSON.stringify({
                        file_id: currentShareData.id
                    }),
                });

                const data = await response.json();

                if (response.ok) {
                    // Update currentShareData with new values
                    currentShareData.claim_code = data.claim_code;
                    currentShareData.download_url = data.download_url;

                    // Update detailed share modal
                    document.getElementById('shareDownloadUrl').value = data.download_url;

                    // Hide confirmation modal
                    hideRegenerateConfirmation();

                    // Show success message
                    showToast('Claim code regenerated! Old link no longer works.', 'success');

                    // Reload files to update table
                    loadFiles();
                } else {
                    showToast(data.error || 'Failed to regenerate claim code', 'error');
                }
            } catch (error) {
                console.error('Regenerate claim code failed:', error);
                showToast('Network error', 'error');
            } finally {
                confirmBtn.disabled = false;
                confirmBtn.textContent = originalText;
            }
        }

        // Handle share via email
        function handleShareViaEmail() {
            if (!currentShareData) {
                showToast('No file data available to share', 'error', 3000);
                return;
            }

            const subject = encodeURIComponent(`File shared: ${currentShareData.original_filename}`);
            const body = encodeURIComponent(generateEmailBody(currentShareData));
            const mailtoUrl = `mailto:?subject=${subject}&body=${body}`;

            // Open email client
            window.location.href = mailtoUrl;

            // Close modal and show feedback
            closeShareModal();
            showToast('Opening email client...', 'info', 2000);
        }

        // Handle copy link
        async function handleShareCopyLink() {
            if (!currentShareData) {
                showToast('No file data available to share', 'error', 3000);
                return;
            }

            const success = await copyToClipboard(currentShareData.download_url, 'Download link copied!');
            if (success) {
                closeShareModal();
            }
        }

        // Handle copy details
        async function handleShareCopyDetails() {
            if (!currentShareData) {
                showToast('No file data available to share', 'error', 3000);
                return;
            }

            const message = generateShareMessage(currentShareData);
            const success = await copyToClipboard(message, 'File details copied!');
            if (success) {
                closeShareModal();
            }
        }

        // Generate share message
        function generateShareMessage(data) {
            const expiresDate = new Date(data.expires_at);
            const formattedExpires = expiresDate.toLocaleString('en-US', {
                month: 'long',
                day: 'numeric',
                year: 'numeric',
                hour: 'numeric',
                minute: '2-digit',
                hour12: true
            });

            let message = `Hi! I've shared a file with you via SafeShare.\n\n`;
            message += `File: ${data.original_filename}\n`;
            message += `Size: ${formatFileSize(data.file_size)}\n`;
            message += `Expires: ${formattedExpires}\n\n`;
            message += `Download link:\n${data.download_url}\n\n`;
            message += `Alternatively, you can go to ${window.location.origin} and enter this claim code: ${data.claim_code}\n\n`;

            if (data.max_downloads) {
                message += `Note: This link can be used ${data.max_downloads} time(s).\n`;
            }

            message += `This file will be automatically deleted after expiration.`;

            return message;
        }

        // Generate email body
        function generateEmailBody(data) {
            const expiresDate = new Date(data.expires_at);
            const formattedExpires = expiresDate.toLocaleString('en-US', {
                month: 'long',
                day: 'numeric',
                year: 'numeric',
                hour: 'numeric',
                minute: '2-digit',
                hour12: true
            });

            let body = `Hi,\n\n`;
            body += `I've shared a file with you using SafeShare:\n\n`;
            body += `File: ${data.original_filename}\n`;
            body += `Size: ${formatFileSize(data.file_size)}\n`;
            body += `Expires: ${formattedExpires}\n\n`;
            body += `Download link:\n${data.download_url}\n\n`;
            body += `Alternatively, you can go to ${window.location.origin} and enter this claim code:\n${data.claim_code}\n\n`;

            if (data.max_downloads) {
                body += `Note: This file can be downloaded ${data.max_downloads} time(s).\n\n`;
            }

            body += `This file will be automatically deleted after expiration.\n\n`;
            body += `SafeShare is a secure temporary file sharing service with automatic expiration.`;

            return body;
        }

        // Copy to clipboard utility
        async function copyToClipboard(text, successMessage = 'Copied to clipboard') {
            try {
                await navigator.clipboard.writeText(text);
                showToast(successMessage, 'success', 3000);
                return true;
            } catch (error) {
                // Fallback for older browsers
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);
                textarea.select();

                try {
                    const success = document.execCommand('copy');
                    document.body.removeChild(textarea);

                    if (success) {
                        showToast(successMessage, 'success', 3000);
                        return true;
                    } else {
                        showToast('Failed to copy to clipboard', 'error', 3000);
                        return false;
                    }
                } catch (fallbackError) {
                    document.body.removeChild(textarea);
                    showToast('Failed to copy to clipboard', 'error', 3000);
                    return false;
                }
            }
        }

        // ========== End Share Functions ==========

        // ========== API Token Management Functions ==========

        let tokenToRevoke = null;
        let createdTokenSecret = null;

        // Load tokens
        async function loadTokens() {
            try {
                const response = await fetch('/api/tokens', {
                    credentials: 'include'
                });

                if (response.ok) {
                    const data = await response.json();
                    displayTokens(data.tokens || []);
                } else {
                    console.error('Failed to load tokens:', response.status);
                    displayTokens([]);
                }
            } catch (error) {
                console.error('Failed to load tokens:', error);
                displayTokens([]);
            }
        }

        // Display tokens in table
        function displayTokens(tokens) {
            const container = document.getElementById('tokensContainer');

            if (!tokens || tokens.length === 0) {
                container.innerHTML = `
                    <div class="empty-state-compact">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path>
                        </svg>
                        <span>No API tokens yet. Create one to enable programmatic access.</span>
                    </div>
                `;
                return;
            }

            let tableHTML = `
                <div class="files-table-wrapper">
                    <table class="tokens-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Scopes</th>
                                <th>Usage</th>
                                <th>Created</th>
                                <th>Expires</th>
                                <th>Last Used</th>
                                <th style="text-align: center;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
            `;

            tokens.forEach(token => {
                const createdDate = formatCompactDate(token.created_at);
                const expiresDisplay = formatTokenExpiration(token.expires_at);
                const lastUsed = token.last_used_at ? formatCompactDate(token.last_used_at) : '<span class="token-date">Never</span>';

                // Build scope badges with validation and escaping
                let scopesBadges = '';
                const validScopes = ['upload', 'download', 'manage', 'admin'];
                if (token.scopes && token.scopes.length > 0) {
                    token.scopes.forEach(scope => {
                        // Escape scope for both CSS class and content
                        const escapedScope = escapeHtml(scope);
                        // Only render known scopes with specific styling
                        if (validScopes.includes(scope)) {
                            scopesBadges += `<span class="scope-badge scope-badge-${escapedScope}">${escapedScope}</span>`;
                        } else {
                            // Unknown scope - render safely with generic styling
                            scopesBadges += `<span class="scope-badge">${escapedScope}</span>`;
                        }
                    });
                } else {
                    scopesBadges = '<span class="token-date">None</span>';
                }

                // Build usage stats display
                const usageStats = formatTokenUsageStats(token.usage_stats);

                tableHTML += `
                    <tr>
                        <td><span class="token-name">${escapeHtml(token.name)}</span></td>
                        <td><div class="scopes-cell">${scopesBadges}</div></td>
                        <td style="text-align: center;">${usageStats}</td>
                        <td><span class="token-date">${createdDate}</span></td>
                        <td>${expiresDisplay}</td>
                        <td>${lastUsed}</td>
                        <td style="text-align: center;">
                            <div style="display: flex; gap: 6px; justify-content: center;">
                                <button class="btn-icon btn-secondary" data-action="rotateToken" data-token-id="${token.id}" data-token-name="${escapeHtml(token.name)}" title="Rotate Token (Generate New)">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"></path>
                                    </svg>
                                </button>
                                <button class="btn-icon btn-danger" data-action="revokeToken" data-token-id="${token.id}" data-token-name="${escapeHtml(token.name)}" title="Revoke Token">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <polyline points="3 6 5 6 21 6"></polyline>
                                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                                    </svg>
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            });

            tableHTML += `
                        </tbody>
                    </table>
                </div>
            `;

            container.innerHTML = tableHTML;
        }

        // Refresh tokens with animation
        function refreshTokens() {
            const btn = document.getElementById('refreshTokensBtn');
            btn.classList.add('btn-refreshing');
            setTimeout(() => btn.classList.remove('btn-refreshing'), 600);
            loadTokens();
        }

        // Show create token modal
        function showCreateTokenModal() {
            // Reset form
            document.getElementById('tokenName').value = '';
            document.getElementById('scopeUpload').checked = false;
            document.getElementById('scopeDownload').checked = false;
            document.getElementById('scopeManage').checked = false;
            document.getElementById('tokenExpirationDays').value = '90';

            // Reset scope checkbox visual states
            document.querySelectorAll('.scope-checkbox-container').forEach(container => {
                container.classList.remove('selected');
            });

            // Reset expiration preset buttons
            document.querySelectorAll('.token-preset-btn').forEach(btn => {
                btn.classList.remove('selected');
                if (btn.getAttribute('data-days') === '90') {
                    btn.classList.add('selected');
                }
            });

            // Setup expiration preset handlers
            setupTokenExpirationPresets();

            document.getElementById('createTokenModal').classList.add('show');
            setTimeout(() => document.getElementById('tokenName').focus(), 100);
        }

        // Hide create token modal
        function hideCreateTokenModal() {
            document.getElementById('createTokenModal').classList.remove('show');
        }

        // Setup expiration preset button handlers
        function setupTokenExpirationPresets() {
            document.querySelectorAll('.token-preset-btn').forEach(btn => {
                btn.onclick = function(e) {
                    e.preventDefault();
                    const days = this.getAttribute('data-days');
                    document.getElementById('tokenExpirationDays').value = days;

                    // Update UI
                    document.querySelectorAll('.token-preset-btn').forEach(b => b.classList.remove('selected'));
                    this.classList.add('selected');
                };
            });
        }

        // Toggle scope checkbox visual state
        function toggleScopeCheckbox(container) {
            const checkbox = container.querySelector('input[type="checkbox"]');
            // Toggle is handled by the label click, update visual state
            setTimeout(() => {
                if (checkbox.checked) {
                    container.classList.add('selected');
                } else {
                    container.classList.remove('selected');
                }
            }, 0);
        }

        // Create token
        async function createToken() {
            const name = document.getElementById('tokenName').value.trim();
            if (!name) {
                showToast('Token name is required', 'error');
                return;
            }

            // Collect selected scopes
            const scopes = [];
            if (document.getElementById('scopeUpload').checked) scopes.push('upload');
            if (document.getElementById('scopeDownload').checked) scopes.push('download');
            if (document.getElementById('scopeManage').checked) scopes.push('manage');

            if (scopes.length === 0) {
                showToast('Please select at least one permission', 'error');
                return;
            }

            const expirationDays = parseInt(document.getElementById('tokenExpirationDays').value);

            const createBtn = document.getElementById('createTokenBtn');
            const originalText = createBtn.textContent;
            createBtn.disabled = true;
            createBtn.textContent = 'Creating...';

            try {
                const requestBody = {
                    name: name,
                    scopes: scopes
                };

                // Only add expires_in_days if not "never" (0)
                if (expirationDays > 0) {
                    requestBody.expires_in_days = expirationDays;
                }

                const response = await fetch('/api/tokens', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'include',
                    body: JSON.stringify(requestBody),
                });

                const data = await response.json();

                if (response.ok) {
                    hideCreateTokenModal();
                    showTokenCreatedModal(data);
                    loadTokens();
                } else {
                    showToast(data.error || 'Failed to create token', 'error');
                }
            } catch (error) {
                console.error('Create token failed:', error);
                showToast('Network error creating token', 'error');
            } finally {
                createBtn.disabled = false;
                createBtn.textContent = originalText;
            }
        }

        // Show token created modal
        function showTokenCreatedModal(tokenData) {
            createdTokenSecret = tokenData.token;
            document.getElementById('createdTokenName').textContent = tokenData.name;
            document.getElementById('createdTokenValue').textContent = tokenData.token;
            document.getElementById('tokenCreatedModal').classList.add('show');
        }

        // Hide token created modal
        function hideTokenCreatedModal() {
            document.getElementById('tokenCreatedModal').classList.remove('show');
            createdTokenSecret = null;
        }

        // Copy created token to clipboard
        async function copyCreatedToken() {
            if (!createdTokenSecret) return;

            try {
                await navigator.clipboard.writeText(createdTokenSecret);
                showToast('Token copied to clipboard!', 'success');
            } catch (error) {
                // Fallback for older browsers
                const textarea = document.createElement('textarea');
                textarea.value = createdTokenSecret;
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);
                textarea.select();

                try {
                    document.execCommand('copy');
                    showToast('Token copied to clipboard!', 'success');
                } catch (fallbackError) {
                    showToast('Failed to copy token', 'error');
                }

                document.body.removeChild(textarea);
            }
        }

        // Revoke token - show confirmation modal
        function revokeToken(tokenId, tokenName) {
            tokenToRevoke = { id: tokenId, name: tokenName };
            document.getElementById('revokeTokenName').textContent = tokenName;
            document.getElementById('revokeTokenModal').classList.add('show');
        }

        // Hide revoke token modal
        function hideRevokeTokenModal() {
            document.getElementById('revokeTokenModal').classList.remove('show');
            tokenToRevoke = null;
        }

        // Confirm revoke token
        async function confirmRevokeToken() {
            if (!tokenToRevoke) return;

            const confirmBtn = document.getElementById('confirmRevokeBtn');
            const originalText = confirmBtn.textContent;
            confirmBtn.disabled = true;
            confirmBtn.textContent = 'Revoking...';

            try {
                const response = await fetch(`/api/tokens/${tokenToRevoke.id}`, {
                    method: 'DELETE',
                    credentials: 'include',
                    headers: {
                        'X-CSRF-Token': getCSRFToken()
                    }
                });

                if (response.ok) {
                    hideRevokeTokenModal();
                    showToast('Token revoked successfully', 'success');
                    loadTokens();
                } else {
                    const data = await response.json();
                    showToast(data.error || 'Failed to revoke token', 'error');
                }
            } catch (error) {
                console.error('Revoke token failed:', error);
                showToast('Network error revoking token', 'error');
            } finally {
                confirmBtn.disabled = false;
                confirmBtn.textContent = originalText;
            }
        }

        // Format token expiration with warning indicators
        function formatTokenExpiration(expiresAt) {
            if (!expiresAt) {
                return '<span class="token-never">Never</span>';
            }

            const expirationDate = new Date(expiresAt);
            
            // Check for "never expire" (year 9999)
            if (expirationDate.getFullYear() === 9999) {
                return '<span class="token-never">Never</span>';
            }

            const now = new Date();
            const daysUntilExpiry = Math.ceil((expirationDate - now) / (1000 * 60 * 60 * 24));
            const dateStr = formatCompactDate(expiresAt);

            // Already expired
            if (daysUntilExpiry < 0) {
                return `
                    <div class="expiration-warning danger">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="15" y1="9" x2="9" y2="15"></line>
                            <line x1="9" y1="9" x2="15" y2="15"></line>
                        </svg>
                        <span class="token-date">${dateStr}</span>
                        <span class="expiration-badge badge-danger">Expired</span>
                    </div>
                `;
            }

            // Expires in less than 3 days (critical)
            if (daysUntilExpiry <= 3) {
                return `
                    <div class="expiration-warning danger">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                            <line x1="12" y1="9" x2="12" y2="13"></line>
                            <line x1="12" y1="17" x2="12.01" y2="17"></line>
                        </svg>
                        <span class="token-date">${dateStr}</span>
                        <span class="expiration-badge badge-danger">${daysUntilExpiry}d left</span>
                    </div>
                `;
            }

            // Expires in less than 7 days (warning)
            if (daysUntilExpiry <= 7) {
                return `
                    <div class="expiration-warning">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                            <line x1="12" y1="9" x2="12" y2="13"></line>
                            <line x1="12" y1="17" x2="12.01" y2="17"></line>
                        </svg>
                        <span class="token-date">${dateStr}</span>
                        <span class="expiration-badge badge-warning">${daysUntilExpiry}d left</span>
                    </div>
                `;
            }

            // Normal expiration (no warning)
            return `<span class="token-date">${dateStr}</span>`;
        }

        // Format token usage stats
        function formatTokenUsageStats(usageStats) {
            if (!usageStats) {
                return '<span class="token-date">No data</span>';
            }

            const requests = usageStats.total_requests || 0;
            const dataTransferred = usageStats.total_bytes_transferred || 0;
            
            // Format data transferred
            let dataStr = '';
            if (dataTransferred > 0) {
                dataStr = formatFileSize(dataTransferred);
            } else {
                dataStr = '0 B';
            }

            return `
                <div class="token-stats-summary">
                    <span class="stat-item" title="Total API requests">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 12h-4l-3 9L9 3l-3 9H2"></path>
                        </svg>
                        ${requests}
                    </span>
                    <span class="stat-divider">|</span>
                    <span class="stat-item" title="Data transferred">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="7 10 12 15 17 10"></polyline>
                            <line x1="12" y1="15" x2="12" y2="3"></line>
                        </svg>
                        ${dataStr}
                    </span>
                </div>
            `;
        }

        // Token to rotate state
        let tokenToRotate = null;

        // Show rotate token confirmation modal
        function rotateToken(tokenId, tokenName) {
            tokenToRotate = { id: tokenId, name: tokenName };
            document.getElementById('rotateTokenName').textContent = tokenName;
            document.getElementById('rotateTokenModal').classList.add('show');
        }

        // Hide rotate token modal
        function hideRotateTokenModal() {
            document.getElementById('rotateTokenModal').classList.remove('show');
            tokenToRotate = null;
        }

        // Confirm and execute token rotation
        async function confirmRotateToken() {
            if (!tokenToRotate) return;

            const confirmBtn = document.getElementById('confirmRotateBtn');
            const originalText = confirmBtn.textContent;
            confirmBtn.disabled = true;
            confirmBtn.textContent = 'Rotating...';

            try {
                const response = await fetch(`/api/tokens/${tokenToRotate.id}/rotate`, {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'X-CSRF-Token': getCSRFToken()
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    hideRotateTokenModal();
                    
                    // Show the new token
                    document.getElementById('rotatedTokenValue').textContent = data.token;
                    document.getElementById('rotatedTokenModal').classList.add('show');
                    
                    // Refresh the tokens list
                    loadTokens();
                } else {
                    const data = await response.json();
                    showToast(data.error || 'Failed to rotate token', 'error');
                }
            } catch (error) {
                console.error('Rotate token failed:', error);
                showToast('Network error rotating token', 'error');
            } finally {
                confirmBtn.disabled = false;
                confirmBtn.textContent = originalText;
            }
        }

        // Copy rotated token to clipboard
        function copyRotatedToken() {
            const tokenValue = document.getElementById('rotatedTokenValue').textContent;
            
            const showCopySuccess = () => {
                const btn = document.getElementById('copyRotatedTokenBtn');
                const originalHTML = btn.innerHTML;
                btn.innerHTML = `
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    Copied!
                `;
                setTimeout(() => {
                    btn.innerHTML = originalHTML;
                }, 2000);
            };
            
            // Try modern Clipboard API first, fall back to execCommand for non-secure contexts
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(tokenValue).then(() => {
                    showCopySuccess();
                }).catch(err => {
                    console.error('Failed to copy token:', err);
                    fallbackCopyRotatedToken(tokenValue, showCopySuccess);
                });
            } else {
                fallbackCopyRotatedToken(tokenValue, showCopySuccess);
            }
        }
        
        // Fallback copy for rotated token (non-secure contexts)
        function fallbackCopyRotatedToken(text, onSuccess) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            
            try {
                const successful = document.execCommand('copy');
                if (successful) {
                    onSuccess();
                } else {
                    showToast('Failed to copy token to clipboard', 'error');
                }
            } catch (err) {
                console.error('Fallback copy failed:', err);
                showToast('Failed to copy token to clipboard', 'error');
            }
            
            document.body.removeChild(textArea);
        }

        // Hide rotated token modal
        function hideRotatedTokenModal() {
            document.getElementById('rotatedTokenModal').classList.remove('show');
        }

        // ========== End API Token Management Functions ==========

        // ========== MFA Management Functions ==========

        // Simple QR Code generator - creates SVG data URL
        // Based on QRCode.js algorithm, simplified for TOTP URLs
        const QRCodeGenerator = (function() {
            // QR Code encoding for alphanumeric data
            const PAD0 = 0xEC, PAD1 = 0x11;
            
            // Error correction level L (7%)
            const ECL = { ordinal: 1 };
            
            // Reed-Solomon error correction
            const EXP = [], LOG = [];
            (function() {
                let x = 1;
                for (let i = 0; i < 255; i++) {
                    EXP[i] = x;
                    LOG[x] = i;
                    x <<= 1;
                    if (x >= 256) x ^= 0x11D;
                }
            })();
            
            function rsGenPoly(n) {
                let result = [1];
                for (let i = 0; i < n; i++) {
                    const newResult = new Array(result.length + 1).fill(0);
                    for (let j = 0; j < result.length; j++) {
                        newResult[j] ^= result[j];
                        newResult[j + 1] ^= (result[j] * EXP[i]) % 255 === 0 ? 0 : EXP[(LOG[result[j]] + i) % 255];
                    }
                    result = newResult.map(v => v & 255 ? EXP[LOG[v] % 255] : 0);
                }
                return result;
            }
            
            function rsEncode(data, poly) {
                const result = new Array(poly.length - 1).fill(0);
                for (const b of data) {
                    const factor = b ^ result[0];
                    result.shift();
                    result.push(0);
                    if (factor) {
                        for (let i = 0; i < result.length; i++) {
                            result[i] ^= EXP[(LOG[poly[i + 1]] + LOG[factor]) % 255] || 0;
                        }
                    }
                }
                return result;
            }
            
            function encodeBytes(text) {
                // Byte mode encoding
                const bytes = new TextEncoder().encode(text);
                const bits = [];
                // Mode indicator (0100 = byte)
                bits.push(0, 1, 0, 0);
                // Character count (8 bits for version 1-9)
                for (let i = 7; i >= 0; i--) bits.push((bytes.length >> i) & 1);
                // Data
                for (const b of bytes) {
                    for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
                }
                // Terminator
                while (bits.length < 8) bits.push(0);
                return bits;
            }
            
            function getVersion(dataLen) {
                // Version capacities for byte mode, ECL L
                const caps = [0, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271, 321, 367, 425, 458, 520, 586, 644, 718, 792, 858];
                for (let v = 1; v <= 20; v++) {
                    if (dataLen <= caps[v]) return v;
                }
                return 20;
            }
            
            function getDataCodewords(version) {
                // Total data codewords for ECL L
                const total = [0, 19, 34, 55, 80, 108, 136, 156, 194, 232, 274, 324, 370, 428, 461, 523, 589, 647, 721, 795, 861];
                return total[version];
            }
            
            function getECCodewords(version) {
                // EC codewords for ECL L
                const ec = [0, 7, 10, 15, 20, 26, 36, 40, 48, 60, 72, 80, 96, 104, 120, 132, 144, 168, 180, 196, 224];
                return ec[version];
            }
            
            function createMatrix(version) {
                const size = version * 4 + 17;
                const matrix = Array(size).fill(null).map(() => Array(size).fill(null));
                
                // Finder patterns
                function setFinder(row, col) {
                    for (let r = -1; r <= 7; r++) {
                        for (let c = -1; c <= 7; c++) {
                            const rr = row + r, cc = col + c;
                            if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
                            const isBlack = (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
                                           (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
                                           (r >= 2 && r <= 4 && c >= 2 && c <= 4);
                            matrix[rr][cc] = isBlack ? 1 : 0;
                        }
                    }
                }
                setFinder(0, 0);
                setFinder(0, size - 7);
                setFinder(size - 7, 0);
                
                // Timing patterns
                for (let i = 8; i < size - 8; i++) {
                    if (matrix[6][i] === null) matrix[6][i] = i % 2 === 0 ? 1 : 0;
                    if (matrix[i][6] === null) matrix[i][6] = i % 2 === 0 ? 1 : 0;
                }
                
                // Dark module
                matrix[size - 8][8] = 1;
                
                // Alignment patterns for version >= 2
                if (version >= 2) {
                    const positions = [6, Math.floor((size - 13) / 2) + 6, size - 7];
                    for (const r of positions) {
                        for (const c of positions) {
                            if (matrix[r][c] !== null) continue;
                            for (let dr = -2; dr <= 2; dr++) {
                                for (let dc = -2; dc <= 2; dc++) {
                                    const isBlack = dr === -2 || dr === 2 || dc === -2 || dc === 2 || (dr === 0 && dc === 0);
                                    matrix[r + dr][c + dc] = isBlack ? 1 : 0;
                                }
                            }
                        }
                    }
                }
                
                return { matrix, size };
            }
            
            function placeData(matrix, size, bits) {
                let bitIdx = 0;
                let upward = true;
                
                for (let col = size - 1; col >= 0; col -= 2) {
                    if (col === 6) col = 5;
                    
                    for (let i = 0; i < size; i++) {
                        const row = upward ? size - 1 - i : i;
                        
                        for (let c = 0; c <= 1; c++) {
                            const cc = col - c;
                            if (matrix[row][cc] === null) {
                                matrix[row][cc] = bitIdx < bits.length ? bits[bitIdx] : 0;
                                bitIdx++;
                            }
                        }
                    }
                    upward = !upward;
                }
            }
            
            function applyMask(matrix, size) {
                // Apply mask pattern 0 (simple checkerboard)
                for (let r = 0; r < size; r++) {
                    for (let c = 0; c < size; c++) {
                        if (matrix[r][c] !== null && (r + c) % 2 === 0) {
                            matrix[r][c] ^= 1;
                        }
                    }
                }
            }
            
            function addFormatInfo(matrix, size) {
                // Format info for ECL L, mask 0
                const formatBits = [1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0];
                let bitIdx = 0;
                
                // Horizontal and vertical
                for (let i = 0; i <= 5; i++) matrix[8][i] = formatBits[bitIdx++];
                matrix[8][7] = formatBits[bitIdx++];
                matrix[8][8] = formatBits[bitIdx++];
                matrix[7][8] = formatBits[bitIdx++];
                for (let i = 5; i >= 0; i--) matrix[i][8] = formatBits[bitIdx++];
                
                bitIdx = 0;
                for (let i = size - 1; i >= size - 8; i--) matrix[8][i] = formatBits[bitIdx++];
                for (let i = size - 7; i < size; i++) matrix[i][8] = formatBits[bitIdx++];
            }
            
            function toSvgDataUrl(matrix, size) {
                const scale = 4;
                const margin = 4;
                const fullSize = (size + margin * 2) * scale;
                
                let paths = '';
                for (let r = 0; r < size; r++) {
                    for (let c = 0; c < size; c++) {
                        if (matrix[r][c] === 1) {
                            const x = (c + margin) * scale;
                            const y = (r + margin) * scale;
                            paths += `M${x},${y}h${scale}v${scale}h-${scale}z`;
                        }
                    }
                }
                
                const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${fullSize} ${fullSize}" width="200" height="200"><rect width="100%" height="100%" fill="white"/><path d="${paths}" fill="black"/></svg>`;
                return 'data:image/svg+xml;base64,' + btoa(svg);
            }
            
            return function generate(text) {
                const version = getVersion(text.length);
                const { matrix, size } = createMatrix(version);
                
                // Encode data
                const bits = encodeBytes(text);
                const dataCodewords = getDataCodewords(version);
                const ecCodewords = getECCodewords(version);
                
                // Pad to capacity
                while (bits.length < dataCodewords * 8) {
                    const pad = bits.length % 16 < 8 ? PAD0 : PAD1;
                    for (let i = 7; i >= 0; i--) bits.push((pad >> i) & 1);
                }
                
                // Convert to bytes and add error correction
                const dataBytes = [];
                for (let i = 0; i < bits.length; i += 8) {
                    let byte = 0;
                    for (let j = 0; j < 8; j++) byte = (byte << 1) | (bits[i + j] || 0);
                    dataBytes.push(byte);
                }
                
                const poly = rsGenPoly(ecCodewords);
                const ecBytes = rsEncode(dataBytes, poly);
                
                // Interleave and convert to bits
                const allBytes = [...dataBytes, ...ecBytes];
                const allBits = [];
                for (const b of allBytes) {
                    for (let i = 7; i >= 0; i--) allBits.push((b >> i) & 1);
                }
                
                // Place data and apply mask
                placeData(matrix, size, allBits);
                applyMask(matrix, size);
                addFormatInfo(matrix, size);
                
                return toSvgDataUrl(matrix, size);
            };
        })();

        // MFA state
        let mfaStatus = null;
        let mfaSetupData = null;
        let mfaRecoveryCodes = [];
        let mfaWizardStep = 1;

        // WebAuthn state
        let webauthnCredentials = [];
        let webauthnRegistrationInProgress = false;
        let webauthnCredentialToDelete = null;
        let webauthnCredentialToRename = null;

        // Load MFA status
        async function loadMFAStatus() {
            try {
                const response = await fetch('/api/user/mfa/status', {
                    credentials: 'include'
                });

                if (response.ok) {
                    mfaStatus = await response.json();
                    displayMFAStatus(mfaStatus);
                } else {
                    // MFA might not be enabled on server
                    const data = await response.json();
                    displayMFANotAvailable(data.error || 'MFA is not available');
                }
            } catch (error) {
                console.error('Failed to load MFA status:', error);
                displayMFANotAvailable('Failed to load MFA status');
            }
        }

        // Refresh MFA status
        function refreshMFAStatus() {
            const btn = document.getElementById('refreshMFABtn');
            btn.classList.add('btn-refreshing');
            loadMFAStatus().finally(() => {
                btn.classList.remove('btn-refreshing');
            });
        }

        // Display MFA status in the UI
        function displayMFAStatus(status) {
            const container = document.getElementById('mfaContainer');

            if (!status.enabled) {
                // MFA feature is disabled on the server
                container.innerHTML = `
                    <div class="mfa-not-available">
                        <div class="mfa-not-available-text">
                            <h4>Two-Factor Authentication Not Available</h4>
                            <p>MFA is currently disabled on this server. Contact your administrator to enable it.</p>
                        </div>
                    </div>
                `;
                return;
            }

            const isTOTPEnabled = status.totp_enabled;
            const isTOTPServerEnabled = status.totp_server_enabled;
            const isWebAuthnServerEnabled = status.webauthn_server_enabled;
            const webauthnCredCount = status.webauthn_credentials || 0;
            const recoveryCodesRemaining = status.recovery_codes_remaining || 0;
            const verifiedAt = status.totp_verified_at ? new Date(status.totp_verified_at).toLocaleDateString() : 'N/A';
            // Determine recovery codes status class
            let recoveryClass = 'success';
            if (recoveryCodesRemaining === 0) {
                recoveryClass = 'danger';
            } else if (recoveryCodesRemaining < 3) {
                recoveryClass = 'warning';
            }

            let html = '';

            // TOTP Section (if TOTP is enabled on server)
            if (isTOTPServerEnabled) {
                html += `
                    <div class="mfa-status-card">
                        <div class="mfa-method-header">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="5" y="2" width="14" height="20" rx="2" ry="2"></rect>
                                <line x1="12" y1="18" x2="12.01" y2="18"></line>
                            </svg>
                            <div>
                                <h4 style="margin: 0; font-size: 14px; font-weight: 600;">Authenticator App (TOTP)</h4>
                                <p style="margin: 2px 0 0 0; font-size: 12px; color: #6b7280;">Use an app like Google Authenticator or Authy</p>
                            </div>
                            <span class="mfa-method-badge ${isTOTPEnabled ? 'enabled' : 'disabled'}">
                                ${isTOTPEnabled ? 'Enabled' : 'Not Set Up'}
                            </span>
                        </div>
                `;

                if (isTOTPEnabled) {
                    html += `
                        <div class="mfa-details" style="margin-top: 12px;">
                            <div class="mfa-detail-item">
                                <div class="mfa-detail-label">Enabled Since</div>
                                <div class="mfa-detail-value">${escapeHtml(verifiedAt)}</div>
                            </div>
                            <div class="mfa-detail-item">
                                <div class="mfa-detail-label">Recovery Codes</div>
                                <div class="mfa-detail-value ${recoveryClass}">${recoveryCodesRemaining} remaining</div>
                            </div>
                        </div>
                        ${recoveryCodesRemaining < 3 ? `
                        <div style="background: #fef3c7; border: 1px solid #fcd34d; border-radius: 8px; padding: 12px; margin-top: 12px; display: flex; align-items: center; gap: 10px;">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2" style="flex-shrink: 0;">
                                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                                <line x1="12" y1="9" x2="12" y2="13"></line>
                                <line x1="12" y1="17" x2="12.01" y2="17"></line>
                            </svg>
                            <span style="color: #92400e; font-size: 13px;">You have few recovery codes left. Consider regenerating them.</span>
                        </div>
                        ` : ''}
                        <div class="mfa-actions" style="margin-top: 16px;">
                            <button class="btn btn-danger btn-sm" data-action="showDisableMFAModal">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <line x1="18" y1="6" x2="6" y2="18"></line>
                                    <line x1="6" y1="6" x2="18" y2="18"></line>
                                </svg>
                                Disable TOTP
                            </button>
                        </div>
                    `;
                } else {
                    html += `
                        <div class="mfa-actions" style="margin-top: 16px;">
                            <button class="btn btn-success btn-sm" data-action="showMFASetupModal">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <line x1="12" y1="5" x2="12" y2="19"></line>
                                    <line x1="5" y1="12" x2="19" y2="12"></line>
                                </svg>
                                Set Up Authenticator App
                            </button>
                        </div>
                    `;
                }

                html += '</div>';
            }

            // WebAuthn Section (if WebAuthn is enabled on server)
            if (isWebAuthnServerEnabled) {
                html += `
                    <div class="mfa-status-card" style="margin-top: 16px;">
                        <div class="mfa-method-header">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M15 7h2a5 5 0 0 1 0 10h-2m-6 0H7A5 5 0 0 1 7 7h2"></path>
                                <line x1="8" y1="12" x2="16" y2="12"></line>
                            </svg>
                            <div>
                                <h4 style="margin: 0; font-size: 14px; font-weight: 600;">Hardware Security Keys</h4>
                                <p style="margin: 2px 0 0 0; font-size: 12px; color: #6b7280;">YubiKey, Touch ID, Windows Hello, or other FIDO2 devices</p>
                            </div>
                            <span class="mfa-method-badge ${webauthnCredCount > 0 ? 'enabled' : 'disabled'}">
                                ${webauthnCredCount > 0 ? webauthnCredCount + ' key' + (webauthnCredCount > 1 ? 's' : '') : 'Not Set Up'}
                            </span>
                        </div>
                        <div id="webauthnCredentialsList" style="margin-top: 12px;">
                            <!-- Credentials will be loaded here -->
                            <div class="webauthn-loading">Loading security keys...</div>
                        </div>
                        <div class="mfa-actions" style="margin-top: 16px;">
                            <button class="btn btn-success btn-sm" data-action="showWebAuthnRegisterModal">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <line x1="12" y1="5" x2="12" y2="19"></line>
                                    <line x1="5" y1="12" x2="19" y2="12"></line>
                                </svg>
                                Add Security Key
                            </button>
                        </div>
                    </div>
                `;

                // Load WebAuthn credentials after rendering
                setTimeout(() => loadWebAuthnCredentials(), 0);
            }

            container.innerHTML = html;
        }

        // Display MFA not available state
        function displayMFANotAvailable(message) {
            const container = document.getElementById('mfaContainer');
            container.innerHTML = `
                <div class="mfa-not-available">
                    <div class="mfa-not-available-text">
                        <h4>MFA Status Unavailable</h4>
                        <p>${escapeHtml(message)}</p>
                    </div>
                </div>
            `;
        }

        // ========================================
        // WebAuthn Functions
        // ========================================

        // Load WebAuthn credentials list
        async function loadWebAuthnCredentials() {
            const container = document.getElementById('webauthnCredentialsList');
            if (!container) return;

            try {
                const response = await fetch('/api/user/mfa/webauthn/credentials', {
                    credentials: 'include'
                });

                if (!response.ok) {
                    const data = await response.json();
                    container.innerHTML = `<div class="webauthn-no-credentials">Failed to load credentials: ${escapeHtml(data.error || 'Unknown error')}</div>`;
                    return;
                }

                webauthnCredentials = await response.json();
                displayWebAuthnCredentials(webauthnCredentials);
            } catch (error) {
                console.error('Failed to load WebAuthn credentials:', error);
                container.innerHTML = '<div class="webauthn-no-credentials">Failed to load security keys</div>';
            }
        }

        // Display WebAuthn credentials in the list
        function displayWebAuthnCredentials(credentials) {
            const container = document.getElementById('webauthnCredentialsList');
            if (!container) return;

            if (!credentials || credentials.length === 0) {
                container.innerHTML = '<div class="webauthn-no-credentials">No security keys registered. Add one to enhance your account security.</div>';
                return;
            }

            let html = '';
            for (const cred of credentials) {
                const createdDate = new Date(cred.created_at).toLocaleDateString();
                const lastUsed = cred.last_used_at ? new Date(cred.last_used_at).toLocaleDateString() : 'Never';
                
                html += `
                    <div class="webauthn-credential-item" data-credential-id="${cred.id}">
                        <div class="webauthn-credential-icon">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M15 7h2a5 5 0 0 1 0 10h-2m-6 0H7A5 5 0 0 1 7 7h2"></path>
                                <line x1="8" y1="12" x2="16" y2="12"></line>
                            </svg>
                        </div>
                        <div class="webauthn-credential-info">
                            <div class="webauthn-credential-name">${escapeHtml(cred.name)}</div>
                            <div class="webauthn-credential-meta">Added ${createdDate} • Last used: ${lastUsed}</div>
                        </div>
                        <div class="webauthn-credential-actions">
                            <button data-action="showWebAuthnRenameModal" data-cred-id="${cred.id}" data-cred-name="${escapeHtml(cred.name)}"
                                    title="Rename">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                                </svg>
                            </button>
                            <button class="delete" data-action="showWebAuthnDeleteModal" data-cred-id="${cred.id}" data-cred-name="${escapeHtml(cred.name)}"
                                    title="Delete">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polyline points="3 6 5 6 21 6"></polyline>
                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                                    <line x1="10" y1="11" x2="10" y2="17"></line>
                                    <line x1="14" y1="11" x2="14" y2="17"></line>
                                </svg>
                            </button>
                        </div>
                    </div>
                `;
            }

            container.innerHTML = html;
        }

        // Show WebAuthn registration modal
        function showWebAuthnRegisterModal() {
            document.getElementById('webauthnKeyName').value = '';
            document.getElementById('webauthnRegisterError').style.display = 'none';
            document.getElementById('webauthnRegisterBtn').disabled = false;
            document.getElementById('webauthnRegisterBtn').textContent = 'Register Key';
            document.getElementById('webauthnRegisterModal').classList.add('show');
        }

        // Hide WebAuthn registration modal
        function hideWebAuthnRegisterModal() {
            document.getElementById('webauthnRegisterModal').classList.remove('show');
            webauthnRegistrationInProgress = false;
        }

        // Base64URL encoding/decoding utilities for WebAuthn
        function base64URLEncode(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.length; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        function base64URLDecode(str) {
            str = str.replace(/-/g, '+').replace(/_/g, '/');
            while (str.length % 4) str += '=';
            const binary = atob(str);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        }

        // Register a new WebAuthn credential
        async function registerWebAuthnCredential() {
            if (webauthnRegistrationInProgress) return;

            const keyName = document.getElementById('webauthnKeyName').value.trim();
            const errorEl = document.getElementById('webauthnRegisterError');
            const btn = document.getElementById('webauthnRegisterBtn');

            // Check for secure context (required for WebAuthn)
            if (!window.isSecureContext || !navigator.credentials) {
                errorEl.textContent = 'Security keys require HTTPS or localhost. Please access this site via HTTPS or localhost to register a security key.';
                errorEl.style.display = 'block';
                return;
            }

            if (!keyName) {
                errorEl.textContent = 'Please enter a name for your security key';
                errorEl.style.display = 'block';
                return;
            }

            webauthnRegistrationInProgress = true;
            errorEl.style.display = 'none';
            btn.disabled = true;
            btn.textContent = 'Starting registration...';

            try {
                // Get CSRF token from user_csrf_token cookie
                const csrfToken = getCSRFToken();

                // Step 1: Begin registration - get challenge from server
                const beginResponse = await fetch('/api/user/mfa/webauthn/register/begin', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ name: keyName })
                });

                if (!beginResponse.ok) {
                    const data = await beginResponse.json();
                    throw new Error(data.error || 'Failed to start registration');
                }

                const response = await beginResponse.json();
                const options = response.options; // Server wraps options in 'options' field
                
                // Convert challenge and user ID from base64url to ArrayBuffer
                options.publicKey.challenge = base64URLDecode(options.publicKey.challenge);
                options.publicKey.user.id = base64URLDecode(options.publicKey.user.id);

                // Convert excludeCredentials if present
                if (options.publicKey.excludeCredentials) {
                    options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(cred => ({
                        ...cred,
                        id: base64URLDecode(cred.id)
                    }));
                }

                btn.textContent = 'Touch your security key...';

                // Step 2: Create credential using browser WebAuthn API
                const credential = await navigator.credentials.create(options);

                btn.textContent = 'Completing registration...';

                // Step 3: Send credential to server to complete registration
                // Build the credential object in the format expected by go-webauthn
                const credentialData = {
                    id: credential.id,
                    rawId: base64URLEncode(credential.rawId),
                    type: credential.type,
                    response: {
                        attestationObject: base64URLEncode(credential.response.attestationObject),
                        clientDataJSON: base64URLEncode(credential.response.clientDataJSON)
                    }
                };

                // Include transports if available
                if (credential.response.getTransports) {
                    credentialData.response.transports = credential.response.getTransports();
                }

                // Wrap in the request structure expected by backend
                const finishRequest = {
                    name: keyName,
                    response: credentialData
                };

                const finishResponse = await fetch('/api/user/mfa/webauthn/register/finish', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify(finishRequest)
                });

                if (!finishResponse.ok) {
                    const data = await finishResponse.json();
                    throw new Error(data.error || 'Failed to complete registration');
                }

                // Success!
                hideWebAuthnRegisterModal();
                showToast('Security key registered successfully', 'success');
                loadMFAStatus(); // Refresh MFA status

            } catch (error) {
                console.error('WebAuthn registration failed:', error);
                errorEl.textContent = error.message || 'Registration failed. Please try again.';
                errorEl.style.display = 'block';
                btn.disabled = false;
                btn.textContent = 'Register Key';
            } finally {
                webauthnRegistrationInProgress = false;
            }
        }

        // Show delete confirmation modal
        function showWebAuthnDeleteModal(credentialId, credentialName) {
            webauthnCredentialToDelete = credentialId;
            document.getElementById('webauthnDeleteName').textContent = credentialName;
            document.getElementById('webauthnDeleteModal').classList.add('show');
        }

        // Hide delete confirmation modal
        function hideWebAuthnDeleteModal() {
            document.getElementById('webauthnDeleteModal').classList.remove('show');
            webauthnCredentialToDelete = null;
        }

        // Delete WebAuthn credential
        async function confirmWebAuthnDelete() {
            if (!webauthnCredentialToDelete) return;

            const btn = document.getElementById('webauthnDeleteConfirmBtn');
            btn.disabled = true;
            btn.textContent = 'Deleting...';

            try {
                const csrfToken = getCSRFToken();

                const response = await fetch(`/api/user/mfa/webauthn/credentials/${webauthnCredentialToDelete}`, {
                    method: 'DELETE',
                    credentials: 'include',
                    headers: {
                        'X-CSRF-Token': csrfToken
                    }
                });

                if (!response.ok) {
                    const data = await response.json();
                    throw new Error(data.error || 'Failed to delete security key');
                }

                hideWebAuthnDeleteModal();
                showToast('Security key deleted', 'success');
                loadMFAStatus(); // Refresh MFA status

            } catch (error) {
                console.error('Failed to delete WebAuthn credential:', error);
                showToast(error.message || 'Failed to delete security key', 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Delete';
            }
        }

        // Show rename modal
        function showWebAuthnRenameModal(credentialId, currentName) {
            webauthnCredentialToRename = credentialId;
            document.getElementById('webauthnNewName').value = currentName;
            document.getElementById('webauthnRenameError').style.display = 'none';
            document.getElementById('webauthnRenameModal').classList.add('show');
        }

        // Hide rename modal
        function hideWebAuthnRenameModal() {
            document.getElementById('webauthnRenameModal').classList.remove('show');
            webauthnCredentialToRename = null;
        }

        // Rename WebAuthn credential
        async function confirmWebAuthnRename() {
            if (!webauthnCredentialToRename) return;

            const newName = document.getElementById('webauthnNewName').value.trim();
            const errorEl = document.getElementById('webauthnRenameError');
            const btn = document.getElementById('webauthnRenameConfirmBtn');

            if (!newName) {
                errorEl.textContent = 'Please enter a name';
                errorEl.style.display = 'block';
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Saving...';
            errorEl.style.display = 'none';

            try {
                const csrfToken = getCSRFToken();

                const response = await fetch(`/api/user/mfa/webauthn/credentials/${webauthnCredentialToRename}`, {
                    method: 'PATCH',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ name: newName })
                });

                if (!response.ok) {
                    const data = await response.json();
                    throw new Error(data.error || 'Failed to rename security key');
                }

                hideWebAuthnRenameModal();
                showToast('Security key renamed', 'success');
                loadWebAuthnCredentials(); // Just refresh the credentials list

            } catch (error) {
                console.error('Failed to rename WebAuthn credential:', error);
                errorEl.textContent = error.message || 'Failed to rename security key';
                errorEl.style.display = 'block';
            } finally {
                btn.disabled = false;
                btn.textContent = 'Rename';
            }
        }

        // ========================================
        // End WebAuthn Functions
        // ========================================

        // Show MFA setup wizard modal
        function showMFASetupModal() {
            mfaWizardStep = 1;
            mfaSetupData = null;
            mfaRecoveryCodes = [];
            updateMFAWizardUI();
            document.getElementById('mfaSetupModal').classList.add('show');
        }

        // Hide MFA setup modal
        function hideMFASetupModal() {
            document.getElementById('mfaSetupModal').classList.remove('show');
            // Reset wizard state
            mfaWizardStep = 1;
            mfaSetupData = null;
            mfaRecoveryCodes = [];
            document.getElementById('mfaVerifyCode').value = '';
            document.getElementById('mfaVerifyError').style.display = 'none';
            document.getElementById('mfaRecoveryConfirm').checked = false;
        }

        // Update MFA wizard UI based on current step
        function updateMFAWizardUI() {
            // Update step indicators
            for (let i = 1; i <= 4; i++) {
                const stepEl = document.getElementById(`mfaStep${i}Indicator`);
                const stepContent = document.getElementById(`mfaStep${i}`);
                const connector = document.getElementById(`mfaConnector${i - 1}`);

                if (i < mfaWizardStep) {
                    stepEl.classList.add('completed');
                    stepEl.classList.remove('active');
                    stepEl.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg>';
                    if (connector) connector.classList.add('completed');
                } else if (i === mfaWizardStep) {
                    stepEl.classList.add('active');
                    stepEl.classList.remove('completed');
                    stepEl.textContent = i;
                    if (connector) connector.classList.remove('completed');
                } else {
                    stepEl.classList.remove('active', 'completed');
                    stepEl.textContent = i;
                    if (connector) connector.classList.remove('completed');
                }

                // Show/hide step content
                if (i === mfaWizardStep) {
                    stepContent.classList.add('active');
                } else {
                    stepContent.classList.remove('active');
                }
            }

            // Update buttons
            const cancelBtn = document.getElementById('mfaSetupCancelBtn');
            const backBtn = document.getElementById('mfaSetupBackBtn');
            const nextBtn = document.getElementById('mfaSetupNextBtn');

            // Show/hide back button
            if (mfaWizardStep > 1 && mfaWizardStep < 4) {
                backBtn.style.display = 'inline-flex';
            } else {
                backBtn.style.display = 'none';
            }

            // Update next button text
            switch (mfaWizardStep) {
                case 1:
                    nextBtn.textContent = 'Get Started';
                    nextBtn.classList.remove('btn-success');
                    nextBtn.classList.add('btn-primary');
                    cancelBtn.style.display = 'inline-flex';
                    break;
                case 2:
                    nextBtn.textContent = 'Continue';
                    nextBtn.classList.remove('btn-success');
                    nextBtn.classList.add('btn-primary');
                    cancelBtn.style.display = 'inline-flex';
                    break;
                case 3:
                    nextBtn.textContent = 'Verify';
                    nextBtn.classList.remove('btn-success');
                    nextBtn.classList.add('btn-primary');
                    cancelBtn.style.display = 'inline-flex';
                    break;
                case 4:
                    nextBtn.textContent = 'Done';
                    nextBtn.classList.remove('btn-primary');
                    nextBtn.classList.add('btn-success');
                    cancelBtn.style.display = 'none';
                    backBtn.style.display = 'none';
                    break;
            }
        }

        // Navigate to next step in wizard
        async function mfaWizardNextStep() {
            const nextBtn = document.getElementById('mfaSetupNextBtn');

            switch (mfaWizardStep) {
                case 1:
                    // Start TOTP setup
                    nextBtn.disabled = true;
                    nextBtn.textContent = 'Setting up...';
                    try {
                        const response = await fetch('/api/user/mfa/totp/setup', {
                            method: 'POST',
                            credentials: 'include',
                            headers: {
                                'X-CSRF-Token': getCSRFToken()
                            }
                        });

                        if (response.ok) {
                            mfaSetupData = await response.json();
                            // Generate QR code locally using SVG data URL (CSP compliant, no third-party)
                            const qrUrl = QRCodeGenerator(mfaSetupData.url);
                            document.getElementById('mfaQRCodeImg').src = qrUrl;
                            // Format secret key for display (add spaces every 4 chars)
                            const formattedSecret = mfaSetupData.secret.match(/.{1,4}/g).join(' ');
                            document.getElementById('mfaSecretKey').textContent = formattedSecret;
                            mfaWizardStep = 2;
                            updateMFAWizardUI();
                        } else {
                            const data = await response.json();
                            showToast(data.error || 'Failed to start MFA setup', 'error');
                        }
                    } catch (error) {
                        console.error('MFA setup failed:', error);
                        showToast('Network error during MFA setup', 'error');
                    } finally {
                        nextBtn.disabled = false;
                        nextBtn.textContent = 'Get Started';
                    }
                    break;

                case 2:
                    // Move to verification step
                    mfaWizardStep = 3;
                    updateMFAWizardUI();
                    // Focus the input
                    setTimeout(() => document.getElementById('mfaVerifyCode').focus(), 100);
                    break;

                case 3:
                    // Verify TOTP code
                    const code = document.getElementById('mfaVerifyCode').value.trim();
                    const errorEl = document.getElementById('mfaVerifyError');

                    // Validate code format
                    if (!/^\d{6}$/.test(code)) {
                        errorEl.textContent = 'Please enter a 6-digit code';
                        errorEl.style.display = 'block';
                        document.getElementById('mfaVerifyCode').classList.add('error');
                        setTimeout(() => document.getElementById('mfaVerifyCode').classList.remove('error'), 400);
                        return;
                    }

                    nextBtn.disabled = true;
                    nextBtn.textContent = 'Verifying...';
                    errorEl.style.display = 'none';

                    try {
                        const response = await fetch('/api/user/mfa/totp/verify', {
                            method: 'POST',
                            credentials: 'include',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-CSRF-Token': getCSRFToken()
                            },
                            body: JSON.stringify({ code: code })
                        });

                        if (response.ok) {
                            const data = await response.json();
                            mfaRecoveryCodes = data.recovery_codes || [];
                            // Display recovery codes
                            displayRecoveryCodes(mfaRecoveryCodes);
                            mfaWizardStep = 4;
                            updateMFAWizardUI();
                        } else {
                            const data = await response.json();
                            errorEl.textContent = data.error || 'Invalid code. Please try again.';
                            errorEl.style.display = 'block';
                            document.getElementById('mfaVerifyCode').classList.add('error');
                            setTimeout(() => document.getElementById('mfaVerifyCode').classList.remove('error'), 400);
                        }
                    } catch (error) {
                        console.error('MFA verification failed:', error);
                        errorEl.textContent = 'Network error. Please try again.';
                        errorEl.style.display = 'block';
                    } finally {
                        nextBtn.disabled = false;
                        nextBtn.textContent = 'Verify';
                    }
                    break;

                case 4:
                    // Check if user confirmed they saved codes
                    if (!document.getElementById('mfaRecoveryConfirm').checked) {
                        showToast('Please confirm that you have saved your recovery codes', 'error');
                        return;
                    }
                    // Done - close modal and refresh status
                    hideMFASetupModal();
                    showToast('Two-factor authentication has been enabled!', 'success');
                    loadMFAStatus();
                    break;
            }
        }

        // Navigate to previous step in wizard
        function mfaWizardPrevStep() {
            if (mfaWizardStep > 1 && mfaWizardStep < 4) {
                mfaWizardStep--;
                updateMFAWizardUI();
            }
        }

        // Display recovery codes in the grid
        function displayRecoveryCodes(codes) {
            const grid = document.getElementById('mfaRecoveryCodesGrid');
            grid.innerHTML = codes.map(code => `<div class="mfa-recovery-code">${escapeHtml(code)}</div>`).join('');
        }

        // Copy MFA secret to clipboard
        function copyMFASecret() {
            if (!mfaSetupData || !mfaSetupData.secret) return;
            
            // Try modern Clipboard API first, fall back to execCommand for non-secure contexts
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(mfaSetupData.secret).then(() => {
                    showToast('Secret key copied to clipboard', 'success');
                }).catch(err => {
                    console.error('Failed to copy:', err);
                    fallbackCopyToClipboard(mfaSetupData.secret);
                });
            } else {
                fallbackCopyToClipboard(mfaSetupData.secret);
            }
        }
        
        // Fallback copy method for non-secure contexts (HTTP on LAN)
        function fallbackCopyToClipboard(text, successMessage = 'Copied to clipboard') {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-9999px';
            textArea.style.top = '-9999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            
            try {
                const successful = document.execCommand('copy');
                if (successful) {
                    showToast(successMessage, 'success');
                } else {
                    showToast('Failed to copy. Please select and copy manually.', 'error');
                }
            } catch (err) {
                console.error('Fallback copy failed:', err);
                showToast('Failed to copy. Please select and copy manually.', 'error');
            }
            
            document.body.removeChild(textArea);
        }

        // Download recovery codes as text file
        function downloadRecoveryCodes() {
            if (!mfaRecoveryCodes || mfaRecoveryCodes.length === 0) return;

            const content = `SafeShare Recovery Codes
================================
Generated: ${new Date().toISOString()}

These codes can be used to access your account if you lose
access to your authenticator app. Each code can only be used once.

KEEP THESE CODES SAFE AND SECURE!

${mfaRecoveryCodes.join('\n')}

================================
If you lose these codes and your authenticator app,
you may be locked out of your account.
`;

            const blob = new Blob([content], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'safeshare-recovery-codes.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('Recovery codes downloaded', 'success');
        }

        // Copy all recovery codes to clipboard
        function copyRecoveryCodes() {
            if (!mfaRecoveryCodes || mfaRecoveryCodes.length === 0) return;
            const codesText = mfaRecoveryCodes.join('\n');
            
            // Try modern Clipboard API first, fall back to execCommand for non-secure contexts
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(codesText).then(() => {
                    showToast('Recovery codes copied to clipboard', 'success');
                }).catch(err => {
                    console.error('Failed to copy:', err);
                    fallbackCopyToClipboard(codesText);
                });
            } else {
                fallbackCopyToClipboard(codesText);
            }
        }

        // Show MFA disable confirmation modal
        function showDisableMFAModal() {
            document.getElementById('mfaDisableCode').value = '';
            document.getElementById('mfaDisableError').style.display = 'none';
            document.getElementById('mfaDisableModal').classList.add('show');
            setTimeout(() => document.getElementById('mfaDisableCode').focus(), 100);
        }

        // Hide MFA disable modal
        function hideMFADisableModal() {
            document.getElementById('mfaDisableModal').classList.remove('show');
            document.getElementById('mfaDisableCode').value = '';
            document.getElementById('mfaDisableError').style.display = 'none';
        }

        // Confirm and disable MFA
        async function confirmDisableMFA() {
            const code = document.getElementById('mfaDisableCode').value.trim();
            const errorEl = document.getElementById('mfaDisableError');
            const confirmBtn = document.getElementById('mfaDisableConfirmBtn');

            // Validate code format
            if (!/^\d{6}$/.test(code)) {
                errorEl.textContent = 'Please enter a 6-digit code';
                errorEl.style.display = 'block';
                document.getElementById('mfaDisableCode').classList.add('error');
                setTimeout(() => document.getElementById('mfaDisableCode').classList.remove('error'), 400);
                return;
            }

            confirmBtn.disabled = true;
            confirmBtn.textContent = 'Disabling...';
            errorEl.style.display = 'none';

            try {
                const response = await fetch('/api/user/mfa/totp', {
                    method: 'DELETE',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': getCSRFToken()
                    },
                    body: JSON.stringify({ code: code })
                });

                if (response.ok) {
                    hideMFADisableModal();
                    showToast('Two-factor authentication has been disabled', 'success');
                    loadMFAStatus();
                } else {
                    const data = await response.json();
                    errorEl.textContent = data.error || 'Invalid code. Please try again.';
                    errorEl.style.display = 'block';
                    document.getElementById('mfaDisableCode').classList.add('error');
                    setTimeout(() => document.getElementById('mfaDisableCode').classList.remove('error'), 400);
                }
            } catch (error) {
                console.error('MFA disable failed:', error);
                errorEl.textContent = 'Network error. Please try again.';
                errorEl.style.display = 'block';
            } finally {
                confirmBtn.disabled = false;
                confirmBtn.textContent = 'Disable MFA';
            }
        }

        // ========== End MFA Management Functions ==========

        // Initialize theme icons on load
        document.addEventListener('DOMContentLoaded', () => {
            const theme = document.documentElement.getAttribute('data-theme');
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

            // Initialize share modal event listeners
            const shareModal = document.getElementById('shareModal');
            const shareModalClose = document.querySelector('.share-modal-close');
            const shareViaEmail = document.getElementById('shareViaEmail');
            const shareCopyLink = document.getElementById('shareCopyLink');
            const shareCopyDetails = document.getElementById('shareCopyDetails');

            // Close modal button
            if (shareModalClose) {
                shareModalClose.addEventListener('click', closeShareModal);
            }

            // Share options
            if (shareViaEmail) {
                shareViaEmail.addEventListener('click', handleShareViaEmail);
            }

            if (shareCopyLink) {
                shareCopyLink.addEventListener('click', handleShareCopyLink);
            }

            if (shareCopyDetails) {
                shareCopyDetails.addEventListener('click', handleShareCopyDetails);
            }

            // Close modal on background click
            if (shareModal) {
                shareModal.addEventListener('click', (e) => {
                    if (e.target === shareModal) {
                        closeShareModal();
                    }
                });
            }

            // Close modal on Escape key
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && shareModal && !shareModal.classList.contains('hidden')) {
                    closeShareModal();
                }
            });
        });

        // ===== SSO LINKED ACCOUNTS MANAGEMENT =====

        // SSO state variables
        let ssoEnabled = false;
        let ssoProviders = [];
        let userSSOLinks = [];

        // Initialize SSO Linked Accounts section
        async function initSSOLinkedAccounts() {
            try {
                // First check if SSO is enabled
                const configResponse = await fetch('/api/config', {
                    credentials: 'include'
                });

                if (configResponse.ok) {
                    const config = await configResponse.json();
                    ssoEnabled = config.sso_enabled === true;
                }

                if (ssoEnabled) {
                    // Show the SSO section
                    const ssoSection = document.getElementById('ssoLinkedAccountsSection');
                    if (ssoSection) {
                        ssoSection.style.display = 'block';
                    }
                    // Load SSO providers and user links
                    await loadUserSSOData();
                }
            } catch (error) {
                console.error('Failed to initialize SSO linked accounts:', error);
            }
        }

        // Load SSO providers and user's linked accounts
        async function loadUserSSOData() {
            const container = document.getElementById('ssoLinkedAccountsContainer');
            if (!container) return;

            container.innerHTML = '<div class="sso-loading">Loading SSO providers...</div>';

            try {
                // Fetch available SSO providers (only enabled ones)
                const providersResponse = await fetch('/api/sso/providers', {
                    credentials: 'include'
                });

                if (!providersResponse.ok) {
                    throw new Error('Failed to load SSO providers');
                }

                ssoProviders = await providersResponse.json();

                // Fetch user's linked SSO accounts
                const linksResponse = await fetch('/api/sso/links', {
                    credentials: 'include'
                });

                if (linksResponse.ok) {
                    userSSOLinks = await linksResponse.json();
                } else {
                    userSSOLinks = [];
                }

                // Render the UI
                renderSSOLinkedAccountsUI();
            } catch (error) {
                console.error('Failed to load SSO data:', error);
                container.innerHTML = `
                    <div class="sso-disabled-notice">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="8" x2="12" y2="12"></line>
                            <line x1="12" y1="16" x2="12.01" y2="16"></line>
                        </svg>
                        <div class="sso-disabled-notice-text">
                            <strong>Unable to Load SSO Data</strong>
                            ${escapeHtml(error.message)}
                        </div>
                    </div>
                `;
            }
        }

        // Render the SSO linked accounts UI
        function renderSSOLinkedAccountsUI() {
            const container = document.getElementById('ssoLinkedAccountsContainer');
            if (!container) return;

            // Filter to only show enabled providers
            const enabledProviders = ssoProviders.filter(p => p.enabled);

            if (enabledProviders.length === 0) {
                container.innerHTML = `
                    <div class="sso-empty-state">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                            <circle cx="8.5" cy="7" r="4"></circle>
                            <line x1="20" y1="8" x2="20" y2="14"></line>
                            <line x1="23" y1="11" x2="17" y2="11"></line>
                        </svg>
                        <h4>No SSO Providers Available</h4>
                        <p>Your administrator has not configured any SSO providers yet.</p>
                    </div>
                `;
                return;
            }

            // Create a map of user's linked providers
            const linkedProvidersMap = new Map();
            userSSOLinks.forEach(link => {
                linkedProvidersMap.set(link.provider_id, link);
            });

            let html = '<div class="sso-providers-grid">';

            for (const provider of enabledProviders) {
                const link = linkedProvidersMap.get(provider.id);
                const isLinked = !!link;
                const providerTypeClass = getProviderTypeClass(provider.provider_type);

                html += `
                    <div class="sso-provider-card ${isLinked ? 'linked' : ''}">
                        <div class="sso-provider-header">
                            <div class="sso-provider-icon ${providerTypeClass}">
                                ${getProviderIcon(provider.provider_type)}
                            </div>
                            <div class="sso-provider-info">
                                <h4 class="sso-provider-name">${escapeHtml(provider.name)}</h4>
                                <div class="sso-provider-type">${escapeHtml(provider.provider_type)}</div>
                            </div>
                        </div>
                        <div class="sso-provider-status ${isLinked ? 'linked' : ''}">
                            <div class="sso-status-dot ${isLinked ? 'linked' : ''}"></div>
                            <span class="sso-status-text ${isLinked ? 'linked' : ''}">
                                ${isLinked ? 'Linked' : 'Not Linked'}
                            </span>
                        </div>
                `;

                if (isLinked) {
                    const linkedAt = new Date(link.linked_at).toLocaleDateString();
                    const lastLogin = link.last_login_at
                        ? new Date(link.last_login_at).toLocaleDateString()
                        : 'Never';

                    html += `
                        <div class="sso-link-info">
                            <div><strong>External ID:</strong> ${escapeHtml(link.external_id || 'N/A')}</div>
                            <div><strong>Linked:</strong> ${linkedAt}</div>
                            <div><strong>Last Login:</strong> ${lastLogin}</div>
                        </div>
                        <div class="sso-provider-actions">
                            <button class="btn btn-danger btn-sm sso-unlink-btn"
                                data-link-id="${link.id}"
                                data-provider-name="${escapeHtml(provider.name)}"
                                title="Unlink this SSO account">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M18 6L6 18M6 6l12 12"></path>
                                </svg>
                                Unlink
                            </button>
                        </div>
                    `;
                } else {
                    html += `
                        <div class="sso-provider-actions">
                            <button class="btn btn-primary btn-sm sso-link-btn"
                                data-provider-id="${provider.id}"
                                data-provider-name="${escapeHtml(provider.name)}"
                                title="Link your account with ${escapeHtml(provider.name)}">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
                                    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
                                </svg>
                                Link Account
                            </button>
                        </div>
                    `;
                }

                html += '</div>';
            }

            html += '</div>';
            container.innerHTML = html;

            // Attach event listeners using event delegation (safer than inline onclick)
            container.addEventListener('click', handleSSOButtonClick);
        }

        // Handle SSO button clicks via event delegation (prevents XSS)
        function handleSSOButtonClick(e) {
            // Handle unlink button
            const unlinkBtn = e.target.closest('.sso-unlink-btn');
            if (unlinkBtn) {
                const linkId = parseInt(unlinkBtn.dataset.linkId, 10);
                const providerName = unlinkBtn.dataset.providerName;
                unlinkSSOProvider(linkId, providerName);
                return;
            }

            // Handle link button
            const linkBtn = e.target.closest('.sso-link-btn');
            if (linkBtn) {
                const providerId = parseInt(linkBtn.dataset.providerId, 10);
                const providerName = linkBtn.dataset.providerName;
                linkSSOProvider(providerId, providerName);
                return;
            }
        }

        // Get CSS class for provider type
        function getProviderTypeClass(providerType) {
            const type = (providerType || '').toLowerCase();
            if (type.includes('google')) return 'google';
            if (type.includes('microsoft') || type.includes('azure')) return 'microsoft';
            if (type.includes('okta')) return 'okta';
            return '';
        }

        // Get icon for provider type
        function getProviderIcon(providerType) {
            const type = (providerType || '').toLowerCase();

            // Generic SSO/OIDC icon
            return `
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
            `;
        }

        // Link SSO provider
        async function linkSSOProvider(providerId, providerName) {
            try {
                // Store return URL for after SSO flow
                sessionStorage.setItem('sso_link_return', window.location.href);

                // Redirect to SSO link endpoint
                window.location.href = `/api/sso/link/${providerId}`;
            } catch (error) {
                console.error('Failed to initiate SSO link:', error);
                showToast('Failed to initiate SSO link: ' + error.message, 'error');
            }
        }

        // Unlink SSO provider
        async function unlinkSSOProvider(linkId, providerName) {
            if (!confirm(`Are you sure you want to unlink your ${providerName} account? You will no longer be able to sign in using this provider.`)) {
                return;
            }

            try {
                const response = await fetch(`/api/sso/links/${linkId}`, {
                    method: 'DELETE',
                    credentials: 'include',
                    headers: {
                        'X-CSRF-Token': getCSRFToken()
                    }
                });

                if (response.ok) {
                    showToast(`Successfully unlinked ${providerName} account`, 'success');
                    await loadUserSSOData();
                } else {
                    const data = await response.json();
                    throw new Error(data.error || 'Failed to unlink account');
                }
            } catch (error) {
                console.error('Failed to unlink SSO account:', error);
                showToast('Failed to unlink account: ' + error.message, 'error');
            }
        }

        // Refresh SSO linked accounts
        async function refreshSSOLinkedAccounts() {
            const btn = document.getElementById('refreshSSOBtn');
            if (btn) {
                btn.classList.add('btn-refreshing');
                btn.disabled = true;
            }

            try {
                await loadUserSSOData();
                showToast('SSO accounts refreshed', 'success');
            } catch (error) {
                showToast('Failed to refresh SSO accounts', 'error');
            } finally {
                if (btn) {
                    btn.classList.remove('btn-refreshing');
                    btn.disabled = false;
                }
            }
        }

        // Check for SSO link callback on page load
        function checkSSOLinkCallback() {
            const urlParams = new URLSearchParams(window.location.search);
            const ssoLinked = urlParams.get('sso_linked');
            const ssoError = urlParams.get('sso_error');

            if (ssoLinked === 'true') {
                showToast('SSO account linked successfully!', 'success');
                // Clean up URL
                window.history.replaceState({}, document.title, window.location.pathname);
            } else if (ssoError) {
                showToast('SSO link failed: ' + decodeURIComponent(ssoError), 'error');
                // Clean up URL
                window.history.replaceState({}, document.title, window.location.pathname);
            }
        }

        // Initialize
        checkAuth();
        checkSSOLinkCallback();

        // =====================================================
        // Event Listener Initialization (CSP-compliant)
        // Replaces all inline onclick handlers from HTML
        // =====================================================
        document.addEventListener('DOMContentLoaded', function() {
            // Theme toggle
            document.getElementById('themeToggle').addEventListener('click', toggleTheme);

            // Header action buttons
            document.getElementById('adminDashboardBtn').addEventListener('click', function() { window.location.href = '/admin'; });
            document.getElementById('changePasswordBtn').addEventListener('click', showChangePasswordModal);
            document.getElementById('uploadFilesBtn').addEventListener('click', function() { window.location.href = '/#dropoff'; });
            document.getElementById('logoutBtn').addEventListener('click', logout);

            // Refresh buttons
            document.getElementById('refreshBtn').addEventListener('click', refreshFiles);
            document.getElementById('refreshTokensBtn').addEventListener('click', refreshTokens);
            document.getElementById('refreshMFABtn').addEventListener('click', refreshMFAStatus);
            document.getElementById('refreshSSOBtn').addEventListener('click', refreshSSOLinkedAccounts);

            // Show create token modal
            document.getElementById('showCreateTokenBtn').addEventListener('click', showCreateTokenModal);

            // Change Password modal
            document.getElementById('changePasswordCancelBtn').addEventListener('click', hideChangePasswordModal);
            document.getElementById('changePasswordSubmitBtn').addEventListener('click', changePassword);

            // Delete confirmation modal
            document.getElementById('deleteCancelBtn').addEventListener('click', hideDeleteModal);
            document.getElementById('deleteConfirmBtn').addEventListener('click', confirmDelete);

            // Rename modal
            document.getElementById('renameCancelBtn').addEventListener('click', hideRenameModal);
            document.getElementById('renameConfirmBtn').addEventListener('click', confirmRename);

            // Expiration modal
            document.getElementById('expirationCancelBtn').addEventListener('click', hideExpirationModal);
            document.getElementById('expirationConfirmBtn').addEventListener('click', confirmExpirationUpdate);

            // Scope checkbox labels (toggleScopeCheckbox uses `this`)
            document.getElementById('scopeUploadLabel').addEventListener('click', function() { toggleScopeCheckbox(this); });
            document.getElementById('scopeDownloadLabel').addEventListener('click', function() { toggleScopeCheckbox(this); });
            document.getElementById('scopeManageLabel').addEventListener('click', function() { toggleScopeCheckbox(this); });

            // Create token modal
            document.getElementById('createTokenCancelBtn').addEventListener('click', hideCreateTokenModal);
            document.getElementById('createTokenBtn').addEventListener('click', createToken);

            // Token created modal
            document.getElementById('copyCreatedTokenBtn').addEventListener('click', copyCreatedToken);
            document.getElementById('tokenCreatedDoneBtn').addEventListener('click', hideTokenCreatedModal);

            // Revoke token modal
            document.getElementById('revokeTokenCancelBtn').addEventListener('click', hideRevokeTokenModal);
            document.getElementById('confirmRevokeBtn').addEventListener('click', confirmRevokeToken);

            // Rotate token modal
            document.getElementById('rotateTokenCancelBtn').addEventListener('click', hideRotateTokenModal);
            document.getElementById('confirmRotateBtn').addEventListener('click', confirmRotateToken);

            // Rotated token success modal
            document.getElementById('copyRotatedTokenBtn').addEventListener('click', copyRotatedToken);
            document.getElementById('rotatedTokenDoneBtn').addEventListener('click', hideRotatedTokenModal);

            // Share modal - show details
            document.getElementById('shareShowDetails').addEventListener('click', function() { showDetailedShareModal(); closeShareModal(); });

            // Detailed share modal
            document.getElementById('copyShareLinkBtn').addEventListener('click', copyShareLink);
            document.getElementById('showRegenerateBtn').addEventListener('click', showRegenerateConfirmation);
            document.getElementById('detailedShareCloseBtn').addEventListener('click', hideDetailedShareModal);

            // Regenerate claim code confirmation modal
            document.getElementById('regenerateCancelBtn').addEventListener('click', hideRegenerateConfirmation);
            document.getElementById('confirmRegenerateBtn').addEventListener('click', executeRegenerateClaim);

            // MFA setup wizard
            document.getElementById('copyMFASecretBtn').addEventListener('click', copyMFASecret);
            document.getElementById('downloadRecoveryCodesBtn').addEventListener('click', downloadRecoveryCodes);
            document.getElementById('copyRecoveryCodesBtn').addEventListener('click', copyRecoveryCodes);
            document.getElementById('mfaSetupCancelBtn').addEventListener('click', hideMFASetupModal);
            document.getElementById('mfaSetupBackBtn').addEventListener('click', mfaWizardPrevStep);
            document.getElementById('mfaSetupNextBtn').addEventListener('click', mfaWizardNextStep);

            // WebAuthn register modal
            document.getElementById('webauthnRegisterCancelBtn').addEventListener('click', hideWebAuthnRegisterModal);
            document.getElementById('webauthnRegisterBtn').addEventListener('click', registerWebAuthnCredential);

            // WebAuthn delete modal
            document.getElementById('webauthnDeleteCancelBtn').addEventListener('click', hideWebAuthnDeleteModal);
            document.getElementById('webauthnDeleteConfirmBtn').addEventListener('click', confirmWebAuthnDelete);

            // WebAuthn rename modal
            document.getElementById('webauthnRenameCancelBtn').addEventListener('click', hideWebAuthnRenameModal);
            document.getElementById('webauthnRenameConfirmBtn').addEventListener('click', confirmWebAuthnRename);

            // MFA disable modal
            document.getElementById('mfaDisableCancelBtn').addEventListener('click', hideMFADisableModal);
            document.getElementById('mfaDisableConfirmBtn').addEventListener('click', confirmDisableMFA);

            // Event delegation for dynamically generated buttons (replaces inline onclick handlers)
            document.addEventListener('click', function(e) {
                var btn = e.target.closest('[data-action]');
                if (!btn) return;
                var action = btn.getAttribute('data-action');
                switch (action) {
                    case 'renameFile':
                        renameFile(parseInt(btn.getAttribute('data-file-id')), btn.getAttribute('data-filename'));
                        break;
                    case 'editExpiration':
                        editExpiration(parseInt(btn.getAttribute('data-file-id')), btn.getAttribute('data-expires-at'));
                        break;
                    case 'openShareModal':
                        openShareModal({
                            id: parseInt(btn.getAttribute('data-file-id')),
                            original_filename: btn.getAttribute('data-filename'),
                            file_size: parseInt(btn.getAttribute('data-file-size')),
                            download_url: btn.getAttribute('data-download-url'),
                            expires_at: btn.getAttribute('data-expires-at'),
                            max_downloads: btn.getAttribute('data-max-downloads') ? parseInt(btn.getAttribute('data-max-downloads')) : null,
                            download_count: parseInt(btn.getAttribute('data-download-count')),
                            claim_code: btn.getAttribute('data-claim-code')
                        });
                        break;
                    case 'deleteFile':
                        deleteFile(parseInt(btn.getAttribute('data-file-id')));
                        break;
                    case 'rotateToken':
                        rotateToken(parseInt(btn.getAttribute('data-token-id')), btn.getAttribute('data-token-name'));
                        break;
                    case 'revokeToken':
                        revokeToken(parseInt(btn.getAttribute('data-token-id')), btn.getAttribute('data-token-name'));
                        break;
                    case 'showDisableMFAModal':
                        showDisableMFAModal();
                        break;
                    case 'showMFASetupModal':
                        showMFASetupModal();
                        break;
                    case 'showWebAuthnRegisterModal':
                        showWebAuthnRegisterModal();
                        break;
                    case 'showWebAuthnRenameModal':
                        showWebAuthnRenameModal(parseInt(btn.getAttribute('data-cred-id')), btn.getAttribute('data-cred-name'));
                        break;
                    case 'showWebAuthnDeleteModal':
                        showWebAuthnDeleteModal(parseInt(btn.getAttribute('data-cred-id')), btn.getAttribute('data-cred-name'));
                        break;
                }
            });
        });
