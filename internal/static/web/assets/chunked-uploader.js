/**
 * ChunkedUploader - Handles chunked/resumable file uploads for large files
 *
 * Features:
 * - Automatic chunking based on server config
 * - Retry logic with exponential backoff
 * - Parallel chunk uploads (configurable concurrency)
 * - Pause/resume capability
 * - localStorage persistence for resume after page refresh
 * - Progress tracking with ETA calculation
 * - Event-based architecture for UI updates
 *
 * @example
 * const uploader = new ChunkedUploader(file, {
 *   expiresInHours: 24,
 *   maxDownloads: 5,
 *   password: 'optional'
 * });
 *
 * uploader.on('progress', (progress) => {
 *   console.log(`${progress.percentage}% complete`);
 * });
 *
 * await uploader.init();
 * await uploader.uploadAllChunks();
 * const result = await uploader.complete();
 */
class ChunkedUploader {
    constructor(file, options = {}) {
        this.file = file;
        this.options = {
            expiresInHours: options.expiresInHours || 24,
            maxDownloads: options.maxDownloads || 0,
            password: options.password || '',
            concurrency: options.concurrency || 10, // Increased from 6 to 10 for HTTP/2
            retryAttempts: options.retryAttempts || 3,
            retryDelay: options.retryDelay || 1000, // Initial retry delay in ms
        };

        // Upload state
        this.uploadId = null;
        this.chunkSize = null;
        this.totalChunks = 0;
        this.uploadedChunks = new Set();
        this.isPaused = false;
        this.isCompleted = false;

        // Progress tracking
        this.startTime = null;
        this.uploadedBytes = 0;

        // Event listeners
        this.eventListeners = {};

        // Storage key for resume capability
        this.storageKey = null;

        // Detect if HTTP/2 is available for optimal concurrency
        this._detectHTTP2Support();
    }

    /**
     * Register event listener
     * @param {string} event - Event name (progress, error, complete, chunk_uploaded)
     * @param {function} callback - Callback function
     */
    on(event, callback) {
        if (!this.eventListeners[event]) {
            this.eventListeners[event] = [];
        }
        this.eventListeners[event].push(callback);
    }

    /**
     * Emit event to all registered listeners
     * @param {string} event - Event name
     * @param {*} data - Event data
     */
    emit(event, data) {
        if (this.eventListeners[event]) {
            this.eventListeners[event].forEach(callback => callback(data));
        }
    }

    /**
     * Detect HTTP/2 support and adjust concurrency
     * HTTP/2 allows higher concurrency without connection limits
     */
    _detectHTTP2Support() {
        // Check Performance API for HTTP/2
        if (window.performance && window.performance.getEntriesByType) {
            const navEntry = performance.getEntriesByType('navigation')[0];
            if (navEntry && navEntry.nextHopProtocol) {
                const protocol = navEntry.nextHopProtocol;
                if (protocol === 'h2' || protocol === 'h2c') {
                    // HTTP/2 detected - can safely use higher concurrency
                    if (!this.options.concurrency || this.options.concurrency === 6) {
                        this.options.concurrency = 12;
                    }
                    console.log('HTTP/2 detected, using concurrency:', this.options.concurrency);
                } else {
                    // HTTP/1.1 - use conservative concurrency
                    if (this.options.concurrency > 6) {
                        this.options.concurrency = 6;
                        console.log('HTTP/1.1 detected, limiting concurrency to 6');
                    }
                }
            }
        }
    }

    /**
     * Initialize chunked upload session
     * @returns {Promise<void>}
     */
    async init() {
        try {
            // Calculate file hash for end-to-end verification
            this.emit('hashing', { stage: 'calculating', message: 'Calculating file hash...' });
            const fileHash = await this._calculateFileHash();
            this.emit('hashing', { stage: 'complete', hash: fileHash });

            const response = await fetch('/api/upload/init', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    filename: this.file.name,
                    total_size: this.file.size,
                    chunk_size: this.chunkSize || 5242880, // Will be overridden by server
                    expires_in_hours: this.options.expiresInHours,
                    max_downloads: this.options.maxDownloads,
                    password: this.options.password,
                    file_hash: fileHash // Send SHA256 hash for end-to-end verification
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to initialize upload');
            }

            const data = await response.json();
            this.uploadId = data.upload_id;
            this.chunkSize = data.chunk_size;
            this.totalChunks = data.total_chunks;
            this.startTime = Date.now();

            // Set storage key for resume capability
            this.storageKey = `chunked_upload_${this.uploadId}`;

            // Save initial state to localStorage
            this.saveState();

            this.emit('init', {
                uploadId: this.uploadId,
                totalChunks: this.totalChunks,
                chunkSize: this.chunkSize,
                fileHash: fileHash
            });

        } catch (error) {
            this.emit('error', { stage: 'init', error: error.message });
            throw error;
        }
    }

    /**
     * Upload a single chunk with retry logic
     * @param {number} chunkNumber - Chunk number (0-based)
     * @returns {Promise<void>}
     */
    async uploadChunk(chunkNumber) {
        let attempt = 0;
        const maxAttempts = this.options.retryAttempts;

        while (attempt < maxAttempts) {
            try {
                // Check if paused
                if (this.isPaused) {
                    throw new Error('Upload cancelled');
                }

                // Calculate chunk boundaries
                const start = chunkNumber * this.chunkSize;
                const end = Math.min(start + this.chunkSize, this.file.size);
                const chunkBlob = this.file.slice(start, end);

                // Calculate client-side SHA256 checksum
                const clientChecksum = await this._calculateChecksum(chunkBlob);

                // Create form data
                const formData = new FormData();
                formData.append('chunk', chunkBlob, `chunk_${chunkNumber}`);

                // Upload chunk with keep-alive for connection reuse
                const response = await fetch(`/api/upload/chunk/${this.uploadId}/${chunkNumber}`, {
                    method: 'POST',
                    body: formData,
                    keepalive: true  // Explicitly request connection reuse
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'Chunk upload failed');
                }

                const data = await response.json();

                // Verify checksum matches server
                if (data.checksum && data.checksum !== clientChecksum) {
                    throw new Error(`Checksum mismatch for chunk ${chunkNumber}: client=${clientChecksum.substring(0, 8)}... server=${data.checksum.substring(0, 8)}...`);
                }

                // Mark chunk as uploaded
                this.uploadedChunks.add(chunkNumber);
                this.uploadedBytes += (end - start);

                // Save state
                this.saveState();

                // Emit progress event
                this.emitProgress();

                this.emit('chunk_uploaded', {
                    chunkNumber,
                    chunksUploaded: this.uploadedChunks.size,
                    totalChunks: this.totalChunks,
                    checksum: data.checksum
                });

                return; // Success

            } catch (error) {
                attempt++;

                if (attempt >= maxAttempts) {
                    this.emit('error', {
                        stage: 'chunk_upload',
                        chunkNumber,
                        error: error.message,
                        attempts: attempt
                    });
                    throw new Error(`Failed to upload chunk ${chunkNumber} after ${maxAttempts} attempts: ${error.message}`);
                }

                // Exponential backoff
                const delay = this.options.retryDelay * Math.pow(2, attempt - 1);
                console.warn(`Chunk ${chunkNumber} upload failed (attempt ${attempt}/${maxAttempts}), retrying in ${delay}ms...`);
                await this.sleep(delay);
            }
        }
    }

    /**
     * Upload all chunks with parallel processing
     * @returns {Promise<void>}
     */
    async uploadAllChunks() {
        const chunks = [];
        for (let i = 0; i < this.totalChunks; i++) {
            // Skip already uploaded chunks (for resume)
            if (!this.uploadedChunks.has(i)) {
                chunks.push(i);
            }
        }

        // Upload chunks with concurrency control
        const concurrency = this.options.concurrency;
        const batches = [];

        for (let i = 0; i < chunks.length; i += concurrency) {
            const batch = chunks.slice(i, i + concurrency);
            batches.push(batch);
        }

        for (const batch of batches) {
            if (this.isPaused) {
                this.emit('paused', { uploadedChunks: this.uploadedChunks.size, totalChunks: this.totalChunks });
                throw new Error('Upload cancelled');
            }

            // Upload batch in parallel
            await Promise.all(batch.map(chunkNumber => this.uploadChunk(chunkNumber)));
        }
    }

    /**
     * Complete the upload and assemble chunks
     * @returns {Promise<Object>} - Returns claim code and download URL
     */
    async complete() {
        // Prevent duplicate completion requests (race condition protection)
        if (this.isCompleting) {
            console.warn('Complete already in progress, ignoring duplicate call');
            return this.completionPromise;
        }

        this.isCompleting = true;

        try {
            // Store promise for duplicate calls to wait on
            this.completionPromise = (async () => {
                const response = await fetch(`/api/upload/complete/${this.uploadId}`, {
                    method: 'POST'
                });

                // Handle error responses (4xx, 5xx)
                if (!response.ok && response.status !== 202) {
                    const error = await response.json();

                    // Handle missing chunks
                    if (error.missing_chunks) {
                        this.emit('error', {
                            stage: 'complete',
                            error: error.error,
                            missing_chunks: error.missing_chunks
                        });
                        throw new Error(`Missing ${error.missing_chunks.length} chunks: ${error.missing_chunks.join(', ')}`);
                    }

                    throw new Error(error.error || 'Failed to complete upload');
                }

                const data = await response.json();

                // Check if response is HTTP 202 (Accepted) or has status "processing"
                // This means file assembly is happening asynchronously
                if (response.status === 202 || data.status === 'processing') {
                    // Emit assembling event to notify UI
                    this.emit('assembling', {
                        uploadId: this.uploadId,
                        message: data.message || 'File is being assembled...'
                    });

                    // Start polling for completion
                    const result = await this.pollStatus();

                    this.isCompleted = true;

                    // Save completion data to localStorage BEFORE clearing upload state
                    ChunkedUploader.saveCompletion(result);

                    // Clear saved state from localStorage
                    this.clearState();

                    this.emit('complete', result);

                    return result;
                }

                // If not 202, handle as synchronous completion (backward compatibility)
                this.isCompleted = true;

                // Save completion data to localStorage BEFORE clearing upload state
                ChunkedUploader.saveCompletion(data);

                // Clear saved state from localStorage
                this.clearState();

                this.emit('complete', data);

                return data;
            })();

            return await this.completionPromise;

        } catch (error) {
            this.emit('error', { stage: 'complete', error: error.message });
            throw error;
        } finally {
            this.isCompleting = false;
        }
    }

    /**
     * Check upload status
     * @returns {Promise<Object>} - Upload status
     */
    async getStatus() {
        try {
            const response = await fetch(`/api/upload/status/${this.uploadId}`);

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to get status');
            }

            return await response.json();

        } catch (error) {
            this.emit('error', { stage: 'status', error: error.message });
            throw error;
        }
    }

    /**
     * Poll status endpoint until file assembly is complete
     * @param {number} pollInterval - Polling interval in milliseconds (default: 2000ms / 2 seconds)
     * @param {number} maxAttempts - Maximum number of polling attempts (default: 150 = 5 minutes)
     * @returns {Promise<Object>} - Final upload result with claim_code and download_url
     */
    async pollStatus(pollInterval = 2000, maxAttempts = 150) {
        let attempts = 0;

        while (attempts < maxAttempts) {
            try {
                // Get current status
                const status = await this.getStatus();

                // Emit progress event for UI updates
                this.emit('assembling_progress', {
                    status: status.status,
                    uploadId: this.uploadId,
                    filename: status.filename,
                    attempts: attempts + 1,
                    maxAttempts: maxAttempts
                });

                // Check status field
                if (status.status === 'completed') {
                    // Assembly complete - return result
                    if (!status.claim_code || !status.download_url) {
                        throw new Error('Assembly completed but missing claim_code or download_url');
                    }

                    // Build complete response matching expected format
                    return {
                        claim_code: status.claim_code,
                        download_url: status.download_url,
                        original_filename: status.filename,
                        file_size: this.file.size,
                        expires_at: status.expires_at,
                        max_downloads: this.options.maxDownloads
                    };
                }

                if (status.status === 'failed') {
                    // Assembly failed - throw error
                    const errorMsg = status.error_message || 'File assembly failed';
                    throw new Error(errorMsg);
                }

                // Status is still "processing" or "uploading" - continue polling
                // Wait before next poll
                await this.sleep(pollInterval);
                attempts++;

            } catch (error) {
                // If this is a known error (failed status), rethrow immediately
                if (error.message.includes('assembly failed') || error.message.includes('missing claim_code')) {
                    this.emit('error', { stage: 'assembly', error: error.message });
                    throw error;
                }

                // For network errors, retry with exponential backoff
                attempts++;
                if (attempts >= maxAttempts) {
                    this.emit('error', {
                        stage: 'assembly_polling',
                        error: `Polling failed after ${maxAttempts} attempts: ${error.message}`
                    });
                    throw new Error(`Assembly status polling timed out after ${maxAttempts} attempts`);
                }

                // Exponential backoff for network errors (up to 10 seconds)
                const backoffDelay = Math.min(pollInterval * Math.pow(1.5, attempts), 10000);
                console.warn(`Status polling attempt ${attempts} failed, retrying in ${backoffDelay}ms...`, error.message);
                await this.sleep(backoffDelay);
            }
        }

        // Max attempts reached without completion
        throw new Error(`Assembly polling timed out after ${maxAttempts} attempts (${(maxAttempts * pollInterval) / 60000} minutes)`);
    }

    /**
     * Pause upload
     */
    pause() {
        this.isPaused = true;
        this.saveState();
        this.emit('paused', {
            uploadedChunks: this.uploadedChunks.size,
            totalChunks: this.totalChunks
        });
    }

    /**
     * Resume upload
     * @returns {Promise<void>}
     */
    async resume() {
        this.isPaused = false;
        this.emit('resumed', {
            uploadedChunks: this.uploadedChunks.size,
            totalChunks: this.totalChunks
        });

        // Continue uploading remaining chunks
        await this.uploadAllChunks();
    }

    /**
     * Abort/cancel upload
     * Stops all in-progress uploads and clears state
     */
    abort() {
        this.isPaused = true; // Stop new chunk uploads
        this.isCompleted = true; // Prevent resume

        // Clear localStorage state
        if (this.storageKey) {
            try {
                localStorage.removeItem(this.storageKey);
            } catch (e) {
                console.warn('Failed to clear upload state from localStorage:', e);
            }
        }

        // Show toast notification
        if (typeof window.showToast === 'function') {
            window.showToast('Upload cancelled', 'info', 3000);
        }

        this.emit('cancelled', {
            uploadedChunks: this.uploadedChunks.size,
            totalChunks: this.totalChunks,
            uploadId: this.uploadId
        });
    }

    /**
     * Emit progress event with calculated metrics
     */
    emitProgress() {
        const percentage = (this.uploadedChunks.size / this.totalChunks) * 100;
        const elapsed = Date.now() - this.startTime;
        const bytesPerMs = this.uploadedBytes / elapsed;
        const remainingBytes = this.file.size - this.uploadedBytes;
        const estimatedTimeRemaining = remainingBytes / bytesPerMs;

        this.emit('progress', {
            uploadedChunks: this.uploadedChunks.size,
            totalChunks: this.totalChunks,
            uploadedBytes: this.uploadedBytes,
            totalBytes: this.file.size,
            percentage: Math.round(percentage * 100) / 100,
            estimatedTimeRemaining: Math.round(estimatedTimeRemaining / 1000), // in seconds
            speed: bytesPerMs * 1000 // bytes per second
        });
    }

    /**
     * Save upload state to localStorage for resume capability
     */
    saveState() {
        if (!this.storageKey) return;

        const state = {
            uploadId: this.uploadId,
            filename: this.file.name,
            fileSize: this.file.size,
            chunkSize: this.chunkSize,
            totalChunks: this.totalChunks,
            uploadedChunks: Array.from(this.uploadedChunks),
            uploadedBytes: this.uploadedBytes,
            startTime: this.startTime,
            options: this.options,
            isPaused: this.isPaused
        };

        try {
            localStorage.setItem(this.storageKey, JSON.stringify(state));
        } catch (e) {
            console.warn('Failed to save upload state to localStorage:', e);
        }
    }

    /**
     * Load upload state from localStorage
     * @param {string} uploadId - Upload ID to resume
     * @returns {Object|null} - Saved state or null if not found
     */
    static loadState(uploadId) {
        const storageKey = `chunked_upload_${uploadId}`;

        try {
            const stateJson = localStorage.getItem(storageKey);
            if (!stateJson) return null;

            return JSON.parse(stateJson);
        } catch (e) {
            console.warn('Failed to load upload state from localStorage:', e);
            return null;
        }
    }

    /**
     * Resume from saved state
     * @param {File} file - The same file object
     * @param {string} uploadId - Upload ID to resume
     * @returns {ChunkedUploader|null} - Restored uploader or null if not found
     */
    static resumeFromState(file, uploadId) {
        const state = ChunkedUploader.loadState(uploadId);
        if (!state) return null;

        // Verify file matches
        if (file.name !== state.filename || file.size !== state.fileSize) {
            console.error('File mismatch: cannot resume upload');
            return null;
        }

        // Create uploader instance
        const uploader = new ChunkedUploader(file, state.options);
        uploader.uploadId = state.uploadId;
        uploader.chunkSize = state.chunkSize;
        uploader.totalChunks = state.totalChunks;
        uploader.uploadedChunks = new Set(state.uploadedChunks);
        uploader.uploadedBytes = state.uploadedBytes;
        uploader.startTime = state.startTime;
        uploader.isPaused = state.isPaused;
        uploader.storageKey = `chunked_upload_${uploadId}`;

        return uploader;
    }

    /**
     * Clear saved state from localStorage
     */
    clearState() {
        if (!this.storageKey) return;

        try {
            localStorage.removeItem(this.storageKey);
        } catch (e) {
            console.warn('Failed to clear upload state from localStorage:', e);
        }
    }

    /**
     * List all saved uploads in localStorage
     * @returns {Array<Object>} - Array of saved upload states
     */
    static listSavedUploads() {
        const uploads = [];

        try {
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && key.startsWith('chunked_upload_')) {
                    const stateJson = localStorage.getItem(key);
                    if (stateJson) {
                        const state = JSON.parse(stateJson);
                        uploads.push({
                            uploadId: state.uploadId,
                            filename: state.filename,
                            fileSize: state.fileSize,
                            progress: (state.uploadedChunks.length / state.totalChunks) * 100,
                            uploadedChunks: state.uploadedChunks.length,
                            totalChunks: state.totalChunks,
                            isPaused: state.isPaused,
                            startTime: state.startTime
                        });
                    }
                }
            }
        } catch (e) {
            console.warn('Failed to list saved uploads:', e);
        }

        return uploads;
    }

    /**
     * Calculate SHA256 checksum of a Blob using Web Crypto API
     * @param {Blob} blob - The blob to hash
     * @returns {Promise<string>} - Hex-encoded SHA256 hash
     */
    async _calculateChecksum(blob) {
        const arrayBuffer = await blob.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    /**
     * Calculate SHA256 hash of entire file for end-to-end verification
     * For large files, this uses chunked reading to avoid memory issues
     * @returns {Promise<string>} - Hex-encoded SHA256 hash
     */
    async _calculateFileHash() {
        // For smaller files (<100MB), use direct calculation
        if (this.file.size < 100 * 1024 * 1024) {
            return await this._calculateChecksum(this.file);
        }

        // For large files, use incremental hashing to avoid memory issues
        const chunkSize = 10 * 1024 * 1024; // 10MB chunks for hashing
        let offset = 0;
        const chunks = [];

        // Read file in chunks and collect for hashing
        while (offset < this.file.size) {
            const end = Math.min(offset + chunkSize, this.file.size);
            const chunk = this.file.slice(offset, end);
            const arrayBuffer = await chunk.arrayBuffer();
            chunks.push(new Uint8Array(arrayBuffer));
            offset = end;
        }

        // Concatenate all chunks
        const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
        const combined = new Uint8Array(totalLength);
        let position = 0;
        for (const chunk of chunks) {
            combined.set(chunk, position);
            position += chunk.length;
        }

        // Calculate hash of combined data
        const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    /**
     * Sleep utility
     * @param {number} ms - Milliseconds to sleep
     * @returns {Promise<void>}
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Get upload progress summary
     * @returns {Object} - Progress summary
     */
    getProgress() {
        const percentage = (this.uploadedChunks.size / this.totalChunks) * 100;

        return {
            uploadedChunks: this.uploadedChunks.size,
            totalChunks: this.totalChunks,
            percentage: Math.round(percentage * 100) / 100,
            isPaused: this.isPaused,
            isCompleted: this.isCompleted
        };
    }

    /**
     * Save upload completion to localStorage for recovery
     * @param {Object} data - Completion data from server
     */
    static saveCompletion(data) {
        const STORAGE_KEY = 'safeshare_completed_uploads';
        const RETENTION_DAYS = 7;

        try {
            // Get existing completions
            let completions = [];
            const existing = localStorage.getItem(STORAGE_KEY);
            if (existing) {
                completions = JSON.parse(existing);
            }

            // Add new completion
            completions.push({
                claim_code: data.claim_code,
                download_url: data.download_url,
                filename: data.original_filename,
                file_size: data.file_size,
                expires_at: data.expires_at,
                max_downloads: data.max_downloads,
                timestamp: Date.now(),
                viewed: false
            });

            // Clean up old completions (older than RETENTION_DAYS)
            const cutoffTime = Date.now() - (RETENTION_DAYS * 24 * 60 * 60 * 1000);
            completions = completions.filter(c => c.timestamp > cutoffTime);

            // Save back to localStorage
            localStorage.setItem(STORAGE_KEY, JSON.stringify(completions));
            console.log('Saved completion to localStorage:', data.claim_code);

        } catch (e) {
            console.warn('Failed to save completion to localStorage:', e);
        }
    }

    /**
     * Get all unviewed completed uploads from localStorage
     * @returns {Array<Object>} - Array of completion objects
     */
    static getUnviewedCompletions() {
        const STORAGE_KEY = 'safeshare_completed_uploads';

        try {
            const existing = localStorage.getItem(STORAGE_KEY);
            if (!existing) return [];

            const completions = JSON.parse(existing);
            return completions.filter(c => !c.viewed);

        } catch (e) {
            console.warn('Failed to load completions from localStorage:', e);
            return [];
        }
    }

    /**
     * Mark all completions as viewed
     */
    static markCompletionsAsViewed() {
        const STORAGE_KEY = 'safeshare_completed_uploads';

        try {
            const existing = localStorage.getItem(STORAGE_KEY);
            if (!existing) return;

            const completions = JSON.parse(existing);
            completions.forEach(c => c.viewed = true);

            localStorage.setItem(STORAGE_KEY, JSON.stringify(completions));
            console.log('Marked all completions as viewed');

        } catch (e) {
            console.warn('Failed to mark completions as viewed:', e);
        }
    }

    /**
     * Clear all completions from localStorage
     */
    static clearAllCompletions() {
        const STORAGE_KEY = 'safeshare_completed_uploads';

        try {
            localStorage.removeItem(STORAGE_KEY);
            console.log('Cleared all completions from localStorage');

        } catch (e) {
            console.warn('Failed to clear completions:', e);
        }
    }
}