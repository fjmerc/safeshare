// SafeShare Frontend Application
(function() {
    'use strict';

    // State
    let selectedFile = null;
    let maxFileSizeBytes = 104857600; // 100MB default
    let uploadState = 'idle'; // 'idle', 'uploading', 'completed'
    let filePreparationState = 'idle'; // 'idle', 'preparing', 'ready'
    let currentUploadXhr = null; // For simple upload cancellation
    let currentChunkedUploader = null; // For chunked upload cancellation

    // DOM Elements - Dropoff Tab
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const uploadButton = document.getElementById('uploadButton');
    const removeFileButton = document.getElementById('removeFileButton');
    const expirationHours = document.getElementById('expirationHours');
    const maxDownloads = document.getElementById('maxDownloads');
    const uploadSection = document.getElementById('uploadSection');
    const resultsSection = document.getElementById('resultsSection');
    const uploadProgress = document.getElementById('uploadProgress');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const newUploadButton = document.getElementById('newUploadButton');
    const themeToggle = document.getElementById('themeToggle');
    const uploadWarningBanner = document.getElementById('uploadWarningBanner');

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

    // State - Server config
    let serverConfig = {
        require_auth_for_upload: false,
        max_file_size: 104857600, // Default 100MB
        chunked_upload_enabled: false,
        chunked_upload_threshold: 104857600, // Default 100MB
        chunk_size: 5242880 // Default 5MB
    };

    // Note: Toast notification system is now loaded from toast.js

    // Initialize
    async function init() {
        loadTheme();
        await fetchServerConfig(); // Fetch server configuration first
        await checkAuth(); // Wait for auth check before handling tabs
        updateDropoffTabVisibility(); // Update tab visibility based on config and auth
        fetchMaxFileSize();
        setupEventListeners();
        handleInitialTab();
        checkForCompletedUploads(); // Check for saved completions to recover
        setupBeforeUnloadProtection(); // Prevent navigation during upload
    }

    // Fetch server configuration
    async function fetchServerConfig() {
        try {
            const response = await fetch('/api/config');
            if (response.ok) {
                serverConfig = await response.json();
                console.log('Server config loaded:', serverConfig);

                // Display version in footer
                if (serverConfig.version) {
                    const versionElement = document.getElementById('versionInfo');
                    if (versionElement) {
                        versionElement.textContent = `v${serverConfig.version}`;
                    }
                }

                // Update max file size from server config
                if (serverConfig.max_file_size) {
                    maxFileSizeBytes = serverConfig.max_file_size;
                    // Update display in UI
                    const maxFileSizeDisplay = document.getElementById('maxFileSize');
                    if (maxFileSizeDisplay) {
                        maxFileSizeDisplay.textContent = formatFileSize(maxFileSizeBytes);
                    }
                }

                // Log chunked upload configuration
                if (serverConfig.chunked_upload_enabled) {
                    console.log('Chunked upload enabled:', {
                        threshold: formatFileSize(serverConfig.chunked_upload_threshold),
                        chunkSize: formatFileSize(serverConfig.chunk_size)
                    });
                }
            } else {
                console.warn('Failed to fetch server config, using defaults');
            }
        } catch (error) {
            console.error('Error fetching server config:', error);
        }
    }

    // Update Dropoff tab visibility based on server config and auth status
    function updateDropoffTabVisibility() {
        // Show Dropoff tab if: anonymous uploads allowed OR user is logged in
        const shouldShowDropoff = !serverConfig.require_auth_for_upload || currentUser !== null;

        const dropoffButton = document.querySelector('.tab-button[data-tab="dropoff"]');
        const dropoffContent = document.getElementById('dropoffTab');
        const pickupButton = document.querySelector('.tab-button[data-tab="pickup"]');
        const pickupContent = document.getElementById('pickupTab');
        const loginToUploadBtn = document.getElementById('loginToUploadBtn');

        if (shouldShowDropoff) {
            // Show Dropoff tab, hide login button
            if (dropoffButton) dropoffButton.classList.remove('hidden');
            if (dropoffContent) dropoffContent.classList.remove('hidden');
            if (loginToUploadBtn) loginToUploadBtn.classList.add('hidden');
        } else {
            // Hide Dropoff tab, show login button, activate Pickup as default
            if (dropoffButton) {
                dropoffButton.classList.add('hidden');
                dropoffButton.classList.remove('active');
            }
            if (dropoffContent) {
                dropoffContent.classList.add('hidden');
                dropoffContent.classList.remove('active');
            }

            // Show login button for users to authenticate
            if (loginToUploadBtn) loginToUploadBtn.classList.remove('hidden');

            // Make sure Pickup tab is visible and active
            if (pickupButton) pickupButton.classList.add('active');
            if (pickupContent) pickupContent.classList.add('active');
        }
    }

    // Handle initial tab based on URL hash
    function handleInitialTab() {
        const hash = window.location.hash.substring(1); // Remove the #
        if (hash === 'dropoff' || hash === 'pickup') {
            const tabButton = document.querySelector(`.tab-button[data-tab="${hash}"]`);
            if (tabButton) {
                // If trying to access dropoff without auth, will be redirected by handleTabSwitch
                tabButton.click();
            }
        }
    }

    // Load theme preference
    function loadTheme() {
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        updateThemeIcon(savedTheme);
    }

    // Update theme icon
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
        // Update Dropoff tab visibility when auth status changes
        updateDropoffTabVisibility();
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
        // Warn user before navigating away during upload
        window.addEventListener('beforeunload', (e) => {
            if (uploadState === 'uploading') {
                // Standard way to trigger browser's confirmation dialog
                e.preventDefault();
                e.returnValue = ''; // Required for Chrome
                return ''; // Required for some browsers
            }
        });

        // Tab switching (exclude login button)
        document.querySelectorAll('.tab-button:not(.login-to-upload)').forEach(btn => {
            btn.addEventListener('click', handleTabSwitch);
        });

        // Login to upload button
        const loginToUploadBtn = document.getElementById('loginToUploadBtn');
        if (loginToUploadBtn) {
            loginToUploadBtn.addEventListener('click', () => {
                window.location.href = '/login';
            });
        }

        // Dropoff Tab - Drop zone events
        dropZone.addEventListener('click', () => fileInput.click());
        dropZone.addEventListener('dragover', handleDragOver);
        dropZone.addEventListener('dragleave', handleDragLeave);
        dropZone.addEventListener('drop', handleDrop);

        // Dropoff Tab - File input
        fileInput.addEventListener('change', handleFileSelect);

        // Dropoff Tab - Upload button
        uploadButton.addEventListener('click', handleUpload);

        // Dropoff Tab - Remove file / Cancel upload button
        removeFileButton.addEventListener('click', handleRemoveOrCancel);

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

        // Set default active states to 24h and unlimited
        const defaultHourBtn = document.querySelector('.btn-small[data-hours="24"]');
        const unlimitedDownloadBtn = document.querySelector('.btn-small[data-downloads=""]');
        if (defaultHourBtn) defaultHourBtn.classList.add('active');
        if (unlimitedDownloadBtn) unlimitedDownloadBtn.classList.add('active');

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

        // Copy buttons - Use event delegation to handle dynamically created buttons
        // This prevents the recurring null reference error when buttons are recreated
        document.addEventListener('click', (e) => {
            const copyButton = e.target.closest('.btn-copy');
            if (copyButton) {
                // Create a synthetic event with the button as currentTarget
                const syntheticEvent = {
                    currentTarget: copyButton,
                    preventDefault: () => e.preventDefault(),
                    stopPropagation: () => e.stopPropagation()
                };
                handleCopy(syntheticEvent);
            }
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
            prepareFile(selectedFile);
        }
    }

    // Handle file select
    function handleFileSelect(e) {
        if (e.target.files.length > 0) {
            selectedFile = e.target.files[0];
            prepareFile(selectedFile);
        }
    }

    // Prepare file for upload (show loading state and verify accessibility)
    async function prepareFile(file) {
        // Set preparing state
        filePreparationState = 'preparing';
        showFilePreparationState(file);

        try {
            // Check file is accessible
            const fileSize = file.size;
            const fileName = file.name;

            // Ensure minimum visual feedback (300ms) so users see the loading state
            const minDelay = new Promise(resolve => setTimeout(resolve, 300));

            // For large files (>100MB), verify file is accessible by reading first byte
            const fileCheck = new Promise((resolve, reject) => {
                if (fileSize > 100 * 1024 * 1024) { // > 100MB
                    const reader = new FileReader();
                    reader.onload = () => resolve();
                    reader.onerror = () => reject(new Error('File is not accessible'));
                    // Read just 1 byte to verify accessibility without loading entire file
                    reader.readAsArrayBuffer(file.slice(0, 1));
                } else {
                    // Small files don't need accessibility check
                    resolve();
                }
            });

            // Wait for both minimum delay and file check
            await Promise.all([minDelay, fileCheck]);

            // File is ready
            filePreparationState = 'ready';
            updateDropZone();

        } catch (error) {
            // File preparation failed
            filePreparationState = 'idle';
            selectedFile = null;
            showToast('Failed to prepare file: ' + error.message, 'error', 4000);
            resetDropZoneDisplay();
        }
    }

    // Show file preparation loading state
    function showFilePreparationState(file) {
        const dropZoneTitle = dropZone.querySelector('h2');
        const dropZoneText = dropZone.querySelector('p');
        const spinner = dropZone.querySelector('.file-preparation-spinner');

        // Show spinner
        if (spinner) {
            spinner.classList.remove('hidden');
        }

        // Update text
        dropZoneTitle.textContent = file.name;
        dropZoneText.innerHTML = `<span class="preparing-text">Preparing file...</span>`;

        // Disable upload button and show preparing state
        uploadButton.disabled = true;
        uploadButton.textContent = 'Preparing...';

        // Hide remove button during preparation
        removeFileButton.classList.add('hidden');
    }

    // Reset drop zone to initial state
    function resetDropZoneDisplay() {
        const spinner = dropZone.querySelector('.file-preparation-spinner');
        if (spinner) {
            spinner.classList.add('hidden');
        }

        dropZone.querySelector('h2').textContent = 'Drop file here or click to browse';
        dropZone.querySelector('p').innerHTML = `Maximum file size: <span id="maxFileSize">${formatFileSize(maxFileSizeBytes)}</span>`;
        uploadButton.disabled = true;
        uploadButton.textContent = 'Upload File';
        removeFileButton.classList.add('hidden');
    }

    // Update drop zone display
    function updateDropZone() {
        if (selectedFile && filePreparationState === 'ready') {
            // Hide spinner
            const spinner = dropZone.querySelector('.file-preparation-spinner');
            if (spinner) {
                spinner.classList.add('hidden');
            }

            // Validate file size
            if (selectedFile.size > maxFileSizeBytes) {
                showToast(`File is too large. Maximum size is ${formatFileSize(maxFileSizeBytes)}`, 'error', 4000);
                selectedFile = null;
                uploadButton.disabled = true;
                filePreparationState = 'idle';
                updateRemoveButtonState();
                resetDropZoneDisplay();
                return;
            }

            dropZone.querySelector('h2').textContent = selectedFile.name;
            dropZone.querySelector('p').textContent = `Size: ${formatFileSize(selectedFile.size)}`;
            uploadButton.disabled = false;
            uploadButton.textContent = 'Upload File';
            updateRemoveButtonState();
        }
    }

    // Handle upload - routes to chunked or simple upload based on file size
    async function handleUpload() {
        if (!selectedFile) return;

        // Check if file should use chunked upload
        if (serverConfig.chunked_upload_enabled &&
            selectedFile.size >= serverConfig.chunked_upload_threshold) {
            console.log('Using chunked upload for large file:', formatFileSize(selectedFile.size));
            await handleChunkedUpload();
        } else {
            console.log('Using simple upload for file:', formatFileSize(selectedFile.size));
            await handleSimpleUpload();
        }
    }

    // Show upload warning banner
    function showUploadWarning() {
        if (uploadWarningBanner) {
            uploadWarningBanner.classList.remove('hidden');
        }
    }

    // Hide upload warning banner
    function hideUploadWarning() {
        if (uploadWarningBanner) {
            uploadWarningBanner.classList.add('hidden');
        }
    }

    // Handle simple upload (existing logic for files below threshold)
    async function handleSimpleUpload() {
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

        // Update upload state
        uploadState = 'uploading';
        updateRemoveButtonState();
        showUploadWarning();

        // Show progress
        uploadProgress.classList.remove('hidden');
        uploadButton.disabled = true;

        try {
            const xhr = new XMLHttpRequest();
            currentUploadXhr = xhr; // Store for cancellation

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
                    // Save completion to localStorage for recovery
                    ChunkedUploader.saveCompletion(response);
                    showResults(response);
                } else {
                    const error = JSON.parse(xhr.responseText);
                    // Show user-friendly error message
                    let errorMsg = error.error || 'Upload failed';
                    if (error.code === 'BLOCKED_EXTENSION') {
                        showToast(`Security Alert: ${error.error}. Blocked file types include executables and scripts.`, 'error', 5000);
                    } else {
                        showToast(errorMsg, 'error', 4000);
                    }
                    resetProgress();
                }
            });

            // Error event
            xhr.addEventListener('error', () => {
                showToast('Upload failed. Please try again.', 'error', 4000);
                resetProgress();
            });

            // Abort event
            xhr.addEventListener('abort', () => {
                console.log('Upload cancelled by user');
                resetProgress();
            });

            xhr.open('POST', '/api/upload');
            xhr.send(formData);

        } catch (error) {
            showToast('Upload failed: ' + error.message, 'error', 4000);
            resetProgress();
        }
    }

    // Handle chunked upload for large files
    async function handleChunkedUpload() {
        if (!selectedFile) return;

        // Get upload parameters
        const expiresIn = parseFloat(expirationHours.value);
        const maxDl = parseInt(maxDownloads.value) || 0;
        const password = document.getElementById('uploadPassword').value.trim();

        // Update upload state
        uploadState = 'uploading';
        updateRemoveButtonState();
        showUploadWarning();

        // Show progress
        uploadProgress.classList.remove('hidden');
        uploadButton.disabled = true;
        progressText.textContent = 'Preparing to upload...';

        try {
            // Create uploader instance
            const uploader = new ChunkedUploader(selectedFile, {
                expiresInHours: expiresIn || 24,
                maxDownloads: maxDl,
                password: password
            });
            currentChunkedUploader = uploader; // Store for cancellation

            // Register progress event
            uploader.on('progress', (data) => {
                const percent = data.percentage;
                progressFill.style.width = percent + '%';

                // Show user-friendly progress (no technical chunk details)
                const uploaded = formatFileSize(data.uploadedBytes);
                const total = formatFileSize(data.totalBytes);
                const timeRemaining = formatTimeRemaining(data.estimatedTimeRemaining);

                progressText.textContent = `Uploading... ${Math.round(percent)}% • ${uploaded} / ${total} • ${timeRemaining} remaining`;
            });

            // Register error event
            uploader.on('error', (data) => {
                console.error('Chunked upload error:', data);

                // Detect file change errors (ERR_UPLOAD_FILE_CHANGED)
                let errorMessage;
                if (data.error && data.error.includes('Failed to fetch')) {
                    errorMessage = 'The file changed while uploading. Please ensure the file isn\'t being modified and try again.';
                } else {
                    errorMessage = `Upload failed at ${data.stage}: ${data.error}`;
                }

                showToast(errorMessage, 'error', 4000);
                resetProgress();
            });

            // Register complete event
            uploader.on('complete', (data) => {
                console.log('Chunked upload complete:', data);
                showResults(data);
            });

            // Register cancelled event
            uploader.on('cancelled', (data) => {
                console.log('Chunked upload cancelled:', data);
                resetProgress();
            });

            // Register assembling event (when file assembly starts)
            uploader.on('assembling', (data) => {
                console.log('File assembly started:', data);
                progressText.textContent = 'Assembling file... This may take a moment for large files.';
                // Keep progress bar at 100% (chunks are uploaded)
                progressFill.style.width = '100%';
            });

            // Register assembling progress event (polling updates)
            uploader.on('assembling_progress', (data) => {
                console.log('Assembly progress:', data);
                // Update UI with polling status
                const elapsed = Math.round((data.attempts * 2) / 60); // Rough estimate in minutes
                if (elapsed > 0) {
                    progressText.textContent = `Assembling file... (~${elapsed} min elapsed)`;
                } else {
                    progressText.textContent = 'Assembling file... Please wait.';
                }
            });

            // Execute upload flow
            console.log('Initializing chunked upload...');
            await uploader.init();

            progressText.textContent = 'Starting upload...';
            await uploader.uploadAllChunks();

            progressText.textContent = 'Completing upload...';
            const result = await uploader.complete();

            console.log('Chunked upload successful:', result);

        } catch (error) {
            console.error('Chunked upload error:', error);
            // Don't show error toast for user-initiated cancellation
            if (error.message !== 'Upload cancelled') {
                // Detect file change errors (ERR_UPLOAD_FILE_CHANGED)
                let errorMessage;
                if (error.message && error.message.includes('Failed to fetch')) {
                    errorMessage = 'The file changed while uploading. Please ensure the file isn\'t being modified and try again.';
                } else {
                    errorMessage = error.message;
                }

                showToast(`Upload failed: ${errorMessage}`, 'error', 4000);
            }
            resetProgress();
        }
    }

    // Show results
    function showResults(data) {
        try {
            // Recovery feature: Upload completions are saved by upload handlers
            // (ChunkedUploader.complete() for chunked, XHR handler for simple)

            // Send browser notification
            sendUploadCompleteNotification(data);

            // Populate results
            document.getElementById('claimCode').textContent = data.claim_code;
            document.getElementById('downloadUrl').value = data.download_url;
            const fileNameElement = document.getElementById('fileName');
            fileNameElement.textContent = data.original_filename;
            fileNameElement.title = data.original_filename; // Show full name on hover
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

            // Reset upload state to prevent beforeunload warning
            uploadState = 'idle';

            // Hide upload warning banner
            hideUploadWarning();

            // Show success toast
            showToast('File uploaded successfully', 'success', 3000);
        } catch (error) {
            console.error('Error showing results:', error);
            showToast('Upload successful but error displaying results', 'warning', 4000);
            // Hide warning banner even if there's an error displaying results
            hideUploadWarning();
        }
    }

    // Clear selected file
    function clearSelectedFile() {
        selectedFile = null;
        fileInput.value = '';
        uploadButton.disabled = true;
        uploadState = 'idle';
        filePreparationState = 'idle';
        updateRemoveButtonState();
        resetDropZoneDisplay();
    }

    // Handle remove file or cancel upload based on current state
    function handleRemoveOrCancel() {
        if (uploadState === 'uploading') {
            // Cancel the upload
            cancelUpload();
        } else {
            // Remove the selected file
            clearSelectedFile();
        }
    }

    // Cancel current upload (simple or chunked)
    function cancelUpload() {
        if (currentUploadXhr) {
            // Cancel simple upload
            currentUploadXhr.abort();
            currentUploadXhr = null;
        } else if (currentChunkedUploader) {
            // Cancel chunked upload
            currentChunkedUploader.abort();
            currentChunkedUploader = null;
        }
        // resetProgress() will be called by the abort/cancelled event handlers
    }

    // Update remove button state based on upload state
    function updateRemoveButtonState() {
        if (uploadState === 'uploading') {
            // Show as cancel button
            removeFileButton.textContent = '✕ Cancel Upload';
            removeFileButton.classList.remove('btn-remove-file');
            removeFileButton.classList.add('btn-cancel');
            removeFileButton.classList.remove('hidden');
        } else if (selectedFile) {
            // Show as remove button
            removeFileButton.textContent = '✕ Remove File';
            removeFileButton.classList.add('btn-remove-file');
            removeFileButton.classList.remove('btn-cancel');
            removeFileButton.classList.remove('hidden');
        } else {
            // Hide button
            removeFileButton.classList.add('hidden');
        }
    }

    // Reset form
    function resetForm() {
        // Mark completions as viewed since user has seen results and is moving on
        ChunkedUploader.markCompletionsAsViewed();

        clearSelectedFile();
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

        // Reset upload state
        uploadState = 'idle';
        currentUploadXhr = null;
        currentChunkedUploader = null;
        updateRemoveButtonState();
        hideUploadWarning();
    }

    // Toggle theme
    function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeIcon(newTheme);
    }

    // Copy text to clipboard with toast notification
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

    // Handle copy to clipboard
    async function handleCopy(e) {
        const copyId = e.currentTarget.dataset.copy;
        const element = document.getElementById(copyId);

        // Defensive null check: element might not exist if results section is hidden/cleared
        if (!element) {
            console.error(`Copy failed: Element with ID '${copyId}' not found in DOM`);
            return;
        }

        // Additional defensive check: ensure element has text content or value
        const text = element.tagName === 'INPUT' ? element.value : element.textContent;
        if (!text || text.trim() === '') {
            console.error(`Copy failed: Element with ID '${copyId}' has no text content`);
            showToast('Nothing to copy', 'error', 3000);
            return;
        }

        // Context-specific toast messages
        let successMessage = 'Copied to clipboard';
        if (copyId === 'claimCode') {
            successMessage = 'Claim code copied!';
        } else if (copyId === 'downloadUrl') {
            successMessage = 'Download link copied to clipboard';
        }

        const success = await copyToClipboard(text, successMessage);

        if (success) {
            // Visual feedback on button
            const btn = e.currentTarget;
            const originalText = btn.textContent;
            btn.textContent = '✓';
            btn.classList.add('copied');

            setTimeout(() => {
                btn.textContent = originalText;
                btn.classList.remove('copied');
            }, 2000);

            // Mark completions as viewed if user copied claim code or download URL
            if (copyId === 'claimCode' || copyId === 'downloadUrl') {
                ChunkedUploader.markCompletionsAsViewed();
            }
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

    // Format time remaining (seconds to human-readable)
    function formatTimeRemaining(seconds) {
        if (!seconds || seconds < 0 || !isFinite(seconds)) {
            return 'calculating...';
        }

        if (seconds < 60) {
            return `${Math.round(seconds)} sec`;
        } else if (seconds < 3600) {
            const minutes = Math.floor(seconds / 60);
            return `${minutes} min`;
        } else {
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`;
        }
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
        // Only enforce if server requires authentication for uploads
        if (targetTab === 'dropoff' && serverConfig.require_auth_for_upload && !currentUser) {
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
            showToast('Please enter a claim code', 'warning', 3000);
            return;
        }

        // Disable button during request
        retrieveButton.disabled = true;
        retrieveButton.textContent = 'Retrieving...';

        try {
            const response = await fetch(`/api/claim/${claimCode}/info`);

            if (!response.ok) {
                const error = await response.json();
                showToast(`Error: ${error.error || 'File not found or expired'}`, 'error', 4000);
                retrieveButton.disabled = false;
                retrieveButton.textContent = 'Retrieve File';
                return;
            }

            const data = await response.json();
            currentFileInfo = data;
            displayFileInfo(data);

        } catch (error) {
            showToast('Failed to retrieve file info: ' + error.message, 'error', 4000);
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
                showToast('Please enter the password to download this file', 'warning', 3000);
                return;
            }
            downloadUrl += `?password=${encodeURIComponent(password)}`;
        }

        // Open in new tab - browser will prompt for download location
        window.open(downloadUrl, '_blank');

        // Show info message
        setTimeout(() => {
            showToast('Download started', 'info', 2000);
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

    // ========================================
    // Upload Recovery & Protection Features
    // ========================================

    /**
     * Check for completed uploads in localStorage and show recovery modal
     */
    function checkForCompletedUploads() {
        const completions = ChunkedUploader.getUnviewedCompletions();

        if (completions.length > 0) {
            console.log('Found', completions.length, 'unviewed completed uploads');
            showRecoveryModal(completions);
        }
    }

    /**
     * Show recovery modal with completed uploads
     * @param {Array} completions - Array of completion objects
     */
    function showRecoveryModal(completions) {
        // Create modal HTML
        const modal = document.createElement('div');
        modal.id = 'recoveryModal';
        modal.className = 'recovery-modal';
        modal.innerHTML = `
            <div class="recovery-modal-content">
                <div class="recovery-header">
                    <div class="recovery-icon">✓</div>
                    <h2>Upload${completions.length > 1 ? 's' : ''} Completed!</h2>
                    <p>Your upload${completions.length > 1 ? 's have' : ' has'} finished. Here ${completions.length > 1 ? 'are' : 'is'} your claim code${completions.length > 1 ? 's' : ''}:</p>
                </div>
                <div class="recovery-uploads">
                    ${completions.map((completion, index) => `
                        <div class="recovery-upload" data-index="${index}">
                            <div class="recovery-file-info">
                                <div class="recovery-filename" title="${escapeHtml(completion.filename)}">
                                    ${escapeHtml(completion.filename)}
                                </div>
                                <div class="recovery-filesize">${formatFileSize(completion.file_size)}</div>
                            </div>
                            <div class="recovery-claim">
                                <label>Claim Code:</label>
                                <div class="recovery-code-display">
                                    <code class="recovery-claim-code">${completion.claim_code}</code>
                                    <button class="btn-copy-recovery" data-claim="${completion.claim_code}" aria-label="Copy claim code">
                                        📋
                                    </button>
                                </div>
                            </div>
                            <div class="recovery-actions">
                                <button class="btn-recovery-download" data-url="${escapeHtml(completion.download_url)}">
                                    ⬇️ Download
                                </button>
                                <button class="btn-recovery-copy-url" data-url="${escapeHtml(completion.download_url)}">
                                    🔗 Copy Link
                                </button>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Copy claim code buttons
        modal.querySelectorAll('.btn-copy-recovery').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const claimCode = e.currentTarget.dataset.claim;
                const success = await copyToClipboard(claimCode, 'Claim code copied!');
                if (success) {
                    ChunkedUploader.markCompletionsAsViewed();
                    modal.remove();
                }
            });
        });

        // Download buttons
        modal.querySelectorAll('.btn-recovery-download').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const url = e.currentTarget.dataset.url;
                window.open(url, '_blank');
            });
        });

        // Copy URL buttons
        modal.querySelectorAll('.btn-recovery-copy-url').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const url = e.currentTarget.dataset.url;
                const success = await copyToClipboard(url, 'Download link copied!');
                if (success) {
                    ChunkedUploader.markCompletionsAsViewed();
                    modal.remove();
                }
            });
        });

        // Close on background click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                ChunkedUploader.markCompletionsAsViewed();
                modal.remove();
            }
        });
    }

    /**
     * Setup beforeunload protection to prevent navigation during upload
     */
    function setupBeforeUnloadProtection() {
        window.addEventListener('beforeunload', (e) => {
            // Only show warning if upload is in progress
            if (uploadState === 'uploading') {
                e.preventDefault();
                e.returnValue = ''; // Chrome requires returnValue to be set
                return ''; // Some browsers show this message
            }
        });
    }

    /**
     * Request notification permission and send upload complete notification
     * @param {Object} data - Upload completion data
     */
    function sendUploadCompleteNotification(data) {
        // Check if Notification API is supported
        if (!('Notification' in window)) {
            console.log('Browser does not support notifications');
            return;
        }

        // Check permission
        if (Notification.permission === 'granted') {
            showNotification(data);
        } else if (Notification.permission !== 'denied') {
            // Request permission
            Notification.requestPermission().then(permission => {
                if (permission === 'granted') {
                    showNotification(data);
                }
            });
        }
    }

    /**
     * Show browser notification
     * @param {Object} data - Upload completion data
     */
    function showNotification(data) {
        try {
            const notification = new Notification('Upload Complete!', {
                body: `${data.original_filename} (${formatFileSize(data.file_size)}) is ready to download`,
                icon: '/assets/logo.svg',
                badge: '/assets/logo.svg',
                tag: 'safeshare-upload',
                requireInteraction: false
            });

            // Focus window when notification is clicked
            notification.onclick = () => {
                window.focus();
                notification.close();
            };

        } catch (e) {
            console.warn('Failed to show notification:', e);
        }
    }

    /**
     * Escape HTML to prevent XSS in dynamically created content
     * @param {string} str - String to escape
     * @returns {string} - Escaped string
     */
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
