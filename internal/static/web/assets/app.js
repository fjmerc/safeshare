// SafeShare Frontend Application
(function() {
    'use strict';

    // State
    let selectedFile = null;
    let maxFileSizeBytes = 104857600; // 100MB default

    // DOM Elements - Dropoff Tab
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const uploadButton = document.getElementById('uploadButton');
    const expirationHours = document.getElementById('expirationHours');
    const maxDownloads = document.getElementById('maxDownloads');
    const uploadSection = document.getElementById('uploadSection');
    const resultsSection = document.getElementById('resultsSection');
    const uploadProgress = document.getElementById('uploadProgress');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const newUploadButton = document.getElementById('newUploadButton');
    const themeToggle = document.getElementById('themeToggle');

    // DOM Elements - Pickup Tab
    const claimCodeInput = document.getElementById('claimCodeInput');
    const retrieveButton = document.getElementById('retrieveButton');
    const fileInfoSection = document.getElementById('fileInfoSection');
    const downloadButton = document.getElementById('downloadButton');
    const newPickupButton = document.getElementById('newPickupButton');
    const limitWarning = document.getElementById('limitWarning');
    const passwordPrompt = document.getElementById('passwordPrompt');

    // DOM Elements - User Menu
    const userMenu = document.getElementById('userMenu');
    const userMenuTrigger = document.getElementById('userMenuTrigger');
    const userMenuDropdown = document.getElementById('userMenuDropdown');
    const userName = document.getElementById('userName');
    const logoutBtn = document.getElementById('logoutBtn');

    // State - Pickup
    let currentFileInfo = null;

    // State - User
    let currentUser = null;

    // Initialize
    function init() {
        loadTheme();
        checkAuth();
        fetchMaxFileSize();
        setupEventListeners();
    }

    // Load theme preference
    function loadTheme() {
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        updateThemeIcon(savedTheme);
    }

    // Update theme icon
    function updateThemeIcon(theme) {
        const icon = themeToggle.querySelector('.theme-icon');
        icon.textContent = theme === 'dark' ? '☀️' : '🌙';
    }

    // Fetch max file size from health endpoint
    async function fetchMaxFileSize() {
        try {
            // Try to get config from server
            const response = await fetch('/health');
            if (response.ok) {
                // Max file size is configured server-side, use default for display
                document.getElementById('maxFileSize').textContent = formatFileSize(maxFileSizeBytes);
            }
        } catch (error) {
            console.log('Using default max file size');
        }
    }

    // Check authentication status
    async function checkAuth() {
        try {
            const response = await fetch('/api/auth/user', {
                credentials: 'include'
            });

            if (response.ok) {
                const data = await response.json();
                currentUser = data; // API returns user object directly, not nested
                showUserStatus(true);
            } else {
                currentUser = null;
                showUserStatus(false);
            }
        } catch (error) {
            console.log('Not authenticated');
            currentUser = null;
            showUserStatus(false);
        }
    }

    // Show/hide user menu based on authentication
    function showUserStatus(isLoggedIn) {
        if (isLoggedIn && currentUser) {
            userMenu.classList.remove('hidden');
            userName.textContent = currentUser.username;
        } else {
            userMenu.classList.add('hidden');
        }
    }

    // Toggle user menu dropdown
    function toggleUserMenu(e) {
        e.stopPropagation();
        userMenuDropdown.classList.toggle('show');
    }

    // Close user menu when clicking outside
    function closeUserMenuOnClickOutside(e) {
        if (!userMenu.contains(e.target)) {
            userMenuDropdown.classList.remove('show');
        }
    }

    // Handle logout
    async function handleLogout() {
        try {
            const response = await fetch('/api/auth/logout', {
                method: 'POST',
                credentials: 'include'
            });

            if (response.ok) {
                currentUser = null;
                showUserStatus(false);
                // Optional: show a success message
                console.log('Logged out successfully');
            } else {
                console.error('Logout failed');
            }
        } catch (error) {
            console.error('Logout error:', error);
        }
    }

    // Setup event listeners
    function setupEventListeners() {
        // Tab switching
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.addEventListener('click', handleTabSwitch);
        });

        // Dropoff Tab - Drop zone events
        dropZone.addEventListener('click', () => fileInput.click());
        dropZone.addEventListener('dragover', handleDragOver);
        dropZone.addEventListener('dragleave', handleDragLeave);
        dropZone.addEventListener('drop', handleDrop);

        // Dropoff Tab - File input
        fileInput.addEventListener('change', handleFileSelect);

        // Dropoff Tab - Upload button
        uploadButton.addEventListener('click', handleUpload);

        // Dropoff Tab - Quick select buttons
        document.querySelectorAll('.btn-small[data-hours]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                expirationHours.value = e.target.dataset.hours;
                // Remove active class from all hour buttons
                document.querySelectorAll('.btn-small[data-hours]').forEach(b => b.classList.remove('active'));
                // Add active class to clicked button
                e.target.classList.add('active');
            });
        });

        document.querySelectorAll('.btn-small[data-downloads]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                maxDownloads.value = e.target.dataset.downloads;
                // Remove active class from all download buttons
                document.querySelectorAll('.btn-small[data-downloads]').forEach(b => b.classList.remove('active'));
                // Add active class to clicked button
                e.target.classList.add('active');
            });
        });

        // Set default active states on first buttons
        const firstHourBtn = document.querySelector('.btn-small[data-hours]');
        const firstDownloadBtn = document.querySelector('.btn-small[data-downloads]');
        if (firstHourBtn) firstHourBtn.classList.add('active');
        if (firstDownloadBtn) firstDownloadBtn.classList.add('active');

        // Clear active state when user manually types in input
        expirationHours.addEventListener('input', () => {
            const currentValue = expirationHours.value;
            let matchFound = false;
            document.querySelectorAll('.btn-small[data-hours]').forEach(btn => {
                if (btn.dataset.hours === currentValue) {
                    btn.classList.add('active');
                    matchFound = true;
                } else {
                    btn.classList.remove('active');
                }
            });
        });

        maxDownloads.addEventListener('input', () => {
            const currentValue = maxDownloads.value;
            let matchFound = false;
            document.querySelectorAll('.btn-small[data-downloads]').forEach(btn => {
                if (btn.dataset.downloads === currentValue) {
                    btn.classList.add('active');
                    matchFound = true;
                } else {
                    btn.classList.remove('active');
                }
            });
        });

        // Dropoff Tab - New upload button
        newUploadButton.addEventListener('click', resetForm);

        // Pickup Tab - Retrieve button
        retrieveButton.addEventListener('click', handleRetrieve);

        // Pickup Tab - Enter key on claim code input
        claimCodeInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                handleRetrieve();
            }
        });

        // Pickup Tab - Download button
        downloadButton.addEventListener('click', handleDownload);

        // Pickup Tab - New pickup button
        newPickupButton.addEventListener('click', resetPickupForm);

        // Theme toggle
        themeToggle.addEventListener('click', toggleTheme);

        // User menu
        if (userMenuTrigger) {
            userMenuTrigger.addEventListener('click', toggleUserMenu);
        }

        // Close user menu when clicking outside
        document.addEventListener('click', closeUserMenuOnClickOutside);

        // Logout button
        if (logoutBtn) {
            logoutBtn.addEventListener('click', handleLogout);
        }

        // Universal password toggle handler for all password fields
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

        // Copy buttons
        document.querySelectorAll('.btn-copy').forEach(btn => {
            btn.addEventListener('click', handleCopy);
        });
    }

    // Handle drag over
    function handleDragOver(e) {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    }

    // Handle drag leave
    function handleDragLeave(e) {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
    }

    // Handle drop
    function handleDrop(e) {
        e.preventDefault();
        dropZone.classList.remove('drag-over');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            selectedFile = files[0];
            updateDropZone();
        }
    }

    // Handle file select
    function handleFileSelect(e) {
        if (e.target.files.length > 0) {
            selectedFile = e.target.files[0];
            updateDropZone();
        }
    }

    // Update drop zone display
    function updateDropZone() {
        if (selectedFile) {
            // Validate file size
            if (selectedFile.size > maxFileSizeBytes) {
                alert(`File is too large. Maximum size is ${formatFileSize(maxFileSizeBytes)}`);
                selectedFile = null;
                uploadButton.disabled = true;
                return;
            }

            dropZone.querySelector('h2').textContent = selectedFile.name;
            dropZone.querySelector('p').textContent = `Size: ${formatFileSize(selectedFile.size)}`;
            uploadButton.disabled = false;
        }
    }

    // Handle upload
    async function handleUpload() {
        if (!selectedFile) return;

        const formData = new FormData();
        formData.append('file', selectedFile);

        const expiresIn = parseFloat(expirationHours.value);
        if (expiresIn && expiresIn > 0) {
            formData.append('expires_in_hours', expiresIn);
        }

        const maxDl = parseInt(maxDownloads.value);
        if (maxDl && maxDl > 0) {
            formData.append('max_downloads', maxDl);
        }

        const password = document.getElementById('uploadPassword').value.trim();
        if (password) {
            formData.append('password', password);
        }

        // Show progress
        uploadProgress.classList.remove('hidden');
        uploadButton.disabled = true;

        try {
            const xhr = new XMLHttpRequest();

            // Progress event
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const percent = (e.loaded / e.total) * 100;
                    progressFill.style.width = percent + '%';
                    progressText.textContent = `Uploading... ${Math.round(percent)}%`;
                }
            });

            // Load event
            xhr.addEventListener('load', () => {
                if (xhr.status === 201) {
                    const response = JSON.parse(xhr.responseText);
                    showResults(response);
                } else {
                    const error = JSON.parse(xhr.responseText);
                    // Show user-friendly error message
                    let errorMsg = error.error || 'Upload failed';
                    if (error.code === 'BLOCKED_EXTENSION') {
                        errorMsg = `⚠️ Security Alert\n\n${error.error}\n\nBlocked file types include executables and scripts for security reasons.`;
                    }
                    alert(errorMsg);
                    resetProgress();
                }
            });

            // Error event
            xhr.addEventListener('error', () => {
                alert('Upload failed. Please try again.');
                resetProgress();
            });

            xhr.open('POST', '/api/upload');
            xhr.send(formData);

        } catch (error) {
            alert('Upload failed: ' + error.message);
            resetProgress();
        }
    }

    // Show results
    function showResults(data) {
        try {
            // Populate results
            document.getElementById('claimCode').textContent = data.claim_code;
            document.getElementById('downloadUrl').value = data.download_url;
            document.getElementById('fileName').textContent = data.original_filename;
            document.getElementById('fileSize').textContent = formatFileSize(data.file_size);
            document.getElementById('expiresAt').textContent = formatDate(data.expires_at);
            document.getElementById('maxDownloadsInfo').textContent = data.max_downloads || 'Unlimited';

            // Generate QR code (optional - if library loaded)
            const qrcodeDiv = document.getElementById('qrcode');
            qrcodeDiv.innerHTML = ''; // Clear previous

            if (typeof QRCode !== 'undefined') {
                try {
                    new QRCode(qrcodeDiv, {
                        text: data.download_url,
                        width: 200,
                        height: 200,
                        colorDark: '#000000',
                        colorLight: '#ffffff',
                        correctLevel: QRCode.CorrectLevel.H
                    });
                } catch (qrError) {
                    console.error('QR Code generation failed:', qrError);
                    qrcodeDiv.innerHTML = '<p style="padding: 2rem; color: #6b7280;">QR code unavailable</p>';
                }
            } else {
                console.warn('QRCode library not loaded');
                qrcodeDiv.innerHTML = '<p style="padding: 2rem; color: #6b7280;">QR code unavailable (library not loaded)</p>';
            }

            // Hide upload section, show results
            uploadSection.classList.add('hidden');
            resultsSection.classList.remove('hidden');
        } catch (error) {
            console.error('Error showing results:', error);
            alert('Upload successful but error displaying results. Claim code: ' + data.claim_code);
        }
    }

    // Reset form
    function resetForm() {
        selectedFile = null;
        fileInput.value = '';
        uploadButton.disabled = true;
        dropZone.querySelector('h2').textContent = 'Drop file here or click to browse';
        dropZone.querySelector('p').innerHTML = `Maximum file size: <span id="maxFileSize">${formatFileSize(maxFileSizeBytes)}</span>`;
        expirationHours.value = 24;
        maxDownloads.value = '';
        document.getElementById('uploadPassword').value = '';

        resetProgress();

        resultsSection.classList.add('hidden');
        uploadSection.classList.remove('hidden');
    }

    // Reset progress
    function resetProgress() {
        uploadProgress.classList.add('hidden');
        progressFill.style.width = '0%';
        progressText.textContent = 'Uploading...';
        uploadButton.disabled = false;
    }

    // Toggle theme
    function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeIcon(newTheme);
    }

    // Handle copy to clipboard
    async function handleCopy(e) {
        const copyId = e.currentTarget.dataset.copy;
        const element = document.getElementById(copyId);
        const text = element.tagName === 'INPUT' ? element.value : element.textContent;

        try {
            await navigator.clipboard.writeText(text);

            // Visual feedback
            const btn = e.currentTarget;
            const originalText = btn.textContent;
            btn.textContent = '✓';
            btn.classList.add('copied');

            setTimeout(() => {
                btn.textContent = originalText;
                btn.classList.remove('copied');
            }, 2000);
        } catch (error) {
            // Fallback for older browsers
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);

            alert('Copied to clipboard!');
        }
    }

    // Format file size
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';

        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));

        return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
    }

    // Format date
    function formatDate(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diff = date - now;

        // Show relative time if within 7 days
        if (diff > 0 && diff < 7 * 24 * 60 * 60 * 1000) {
            const hours = Math.floor(diff / (1000 * 60 * 60));
            const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

            if (hours > 24) {
                const days = Math.floor(hours / 24);
                return `in ${days} day${days > 1 ? 's' : ''}`;
            } else if (hours > 0) {
                return `in ${hours} hour${hours > 1 ? 's' : ''} ${minutes} min`;
            } else {
                return `in ${minutes} minute${minutes > 1 ? 's' : ''}`;
            }
        }

        // Otherwise show full date
        return date.toLocaleString();
    }

    // ===== TAB SWITCHING =====

    // Handle tab switching
    function handleTabSwitch(e) {
        const targetTab = e.target.dataset.tab;

        // Check if user is trying to access Dropoff tab without authentication
        if (targetTab === 'dropoff' && !currentUser) {
            // Redirect to login page
            window.location.href = '/login';
            return;
        }

        // Update tab buttons
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.remove('active');
        });
        e.target.classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(targetTab + 'Tab').classList.add('active');
    }

    // ===== PICKUP TAB HANDLERS =====

    // Handle retrieve file info
    async function handleRetrieve() {
        const claimCode = claimCodeInput.value.trim();

        if (!claimCode) {
            alert('Please enter a claim code');
            return;
        }

        // Disable button during request
        retrieveButton.disabled = true;
        retrieveButton.textContent = 'Retrieving...';

        try {
            const response = await fetch(`/api/claim/${claimCode}/info`);

            if (!response.ok) {
                const error = await response.json();
                alert(`Error: ${error.error || 'File not found or expired'}`);
                retrieveButton.disabled = false;
                retrieveButton.textContent = 'Retrieve File';
                return;
            }

            const data = await response.json();
            currentFileInfo = data;
            displayFileInfo(data);

        } catch (error) {
            alert('Failed to retrieve file info: ' + error.message);
            retrieveButton.disabled = false;
            retrieveButton.textContent = 'Retrieve File';
        }
    }

    // Display file info
    function displayFileInfo(data) {
        // Populate file details
        document.getElementById('pickupFileName').textContent = data.original_filename;
        document.getElementById('pickupFileSize').textContent = formatFileSize(data.file_size);
        document.getElementById('pickupMimeType').textContent = data.mime_type;
        document.getElementById('pickupExpiresAt').textContent = formatDate(data.expires_at);

        // Downloads info
        const downloadsText = data.max_downloads
            ? `${data.download_count} / ${data.max_downloads}`
            : `${data.download_count} / Unlimited`;
        document.getElementById('pickupDownloads').textContent = downloadsText;

        // Show/hide warning if download limit reached
        if (data.download_limit_reached) {
            limitWarning.classList.remove('hidden');
            downloadButton.disabled = true;
        } else {
            limitWarning.classList.add('hidden');
            downloadButton.disabled = false;
        }

        // Show/hide password prompt if password is required
        if (data.password_required) {
            passwordPrompt.classList.remove('hidden');
        } else {
            passwordPrompt.classList.add('hidden');
        }

        // Show file info section
        fileInfoSection.classList.remove('hidden');
        retrieveButton.disabled = false;
        retrieveButton.textContent = 'Retrieve File';
    }

    // Handle download
    function handleDownload() {
        if (!currentFileInfo) return;

        // Build download URL with password if required
        let downloadUrl = currentFileInfo.download_url;

        if (currentFileInfo.password_required) {
            const password = document.getElementById('downloadPassword').value.trim();
            if (!password) {
                alert('Please enter the password to download this file');
                return;
            }
            downloadUrl += `?password=${encodeURIComponent(password)}`;
        }

        // Open in new tab - browser will prompt for download location
        window.open(downloadUrl, '_blank');

        // Alternative: Force download with invisible link
        // const link = document.createElement('a');
        // link.href = downloadUrl;
        // link.download = currentFileInfo.original_filename;
        // document.body.appendChild(link);
        // link.click();
        // document.body.removeChild(link);

        // Show success message
        setTimeout(() => {
            alert('Download started! Check your browser\'s download location.');
        }, 500);
    }

    // Reset pickup form
    function resetPickupForm() {
        claimCodeInput.value = '';
        document.getElementById('downloadPassword').value = '';
        fileInfoSection.classList.add('hidden');
        currentFileInfo = null;
        retrieveButton.disabled = false;
        retrieveButton.textContent = 'Retrieve File';
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
