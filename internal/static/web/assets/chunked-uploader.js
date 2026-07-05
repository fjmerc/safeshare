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
            clientEncrypted: !!options.clientEncrypted,
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

        // Network metrics for adaptive concurrency
        this.networkMetrics = {
            consecutiveSuccesses: 0,
            consecutiveFailures: 0,
            recentLatencies: [],      // Keep last 10 latencies
            avgLatency: 0,
            baselineLatency: null,    // Median of first 3 chunk latencies (Guard 2 anchor)
            minConcurrency: 2,
            maxConcurrency: 20,
            adjustmentThreshold: 5,   // Adjust after 5 consecutive successes/failures
            latencyThreshold: 8000,   // Initial value, recalculated in init() based on chunk size
            staticLatencyThreshold: 8000, // Chunk-size-based floor for the recalibrated threshold
            latencyDegradationLimit: 0.5  // Don't increase if latency >50% worse than baseline
        };

        // Progress throttling for better UI performance
        this.progressThrottle = {
            lastEmit: 0,
            minInterval: 250,         // Minimum 250ms between progress events
            chunksSinceLastEmit: 0,
            chunkThreshold: 5         // Or emit every 5 chunks, whichever comes first
        };

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
     * Detect HTTP/2 or HTTP/3 support and adjust concurrency
     * HTTP/2 and HTTP/3 allow higher concurrency without connection limits
     */
    _detectHTTP2Support() {
        // Check Performance API for HTTP/2 or HTTP/3
        if (window.performance && window.performance.getEntriesByType) {
            const navEntry = performance.getEntriesByType('navigation')[0];
            if (navEntry && navEntry.nextHopProtocol) {
                const protocol = navEntry.nextHopProtocol;
                // HTTP/2 (h2, h2c) or HTTP/3 (h3, h3-29, h3-*) support multiplexing
                if (protocol === 'h2' || protocol === 'h2c' || protocol === 'h3' || protocol.startsWith('h3-')) {
                    // HTTP/2 or HTTP/3 detected - can safely use higher concurrency
                    if (this.options.concurrency <= 10) {
                        this.options.concurrency = 12;
                    }
                    console.log(`${protocol.toUpperCase()} detected, using concurrency:`, this.options.concurrency);
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
                    client_encrypted: this.options.clientEncrypted
                })
            });

            if (!response.ok) {
                const error = await this.parseErrorResponse(response);
                throw error;
            }

            const data = await response.json();
            this.uploadId = data.upload_id;
            this.chunkSize = data.chunk_size;
            this.totalChunks = data.total_chunks;
            this.startTime = Date.now();

            // Calculate adaptive latency threshold based on actual chunk size
            // Formula: (chunkSize / 1.25MB/s) * 2x overhead
            // Assumes minimum 10 Mbps connection (1.25 MB/s) with 2x safety margin
            const chunkSizeMB = this.chunkSize / (1024 * 1024);
            this.networkMetrics.staticLatencyThreshold = Math.round((chunkSizeMB / 1.25) * 1000 * 2);
            this.networkMetrics.latencyThreshold = this.networkMetrics.staticLatencyThreshold;

            console.log(`Adaptive latency threshold: ${this.networkMetrics.latencyThreshold}ms for ${chunkSizeMB.toFixed(1)}MB chunks (${(this.networkMetrics.latencyThreshold / 1000).toFixed(1)}s)`);

            // Set storage key for resume capability
            this.storageKey = `chunked_upload_${this.uploadId}`;

            // Save initial state to localStorage
            this.saveState();

            this.emit('init', {
                uploadId: this.uploadId,
                totalChunks: this.totalChunks,
                chunkSize: this.chunkSize
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

                // Track upload latency for adaptive concurrency
                const uploadStartTime = Date.now();

                // Upload chunk (HTTP/2 handles connection reuse automatically)
                const response = await fetch(`/api/upload/chunk/${this.uploadId}/${chunkNumber}`, {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    const error = await this.parseErrorResponse(response);
                    throw error;
                }

                const data = await response.json();

                // Calculate upload latency
                const uploadLatency = Date.now() - uploadStartTime;

                // Verify checksum matches server (only if client-side checksum was calculated)
                if (clientChecksum && data.checksum && data.checksum !== clientChecksum) {
                    throw new Error(`Checksum mismatch for chunk ${chunkNumber}: client=${clientChecksum.substring(0, 8)}... server=${data.checksum.substring(0, 8)}...`);
                }

                // Track success for adaptive concurrency
                this._trackUploadSuccess(uploadLatency);

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

                // Track failure for adaptive concurrency (before retrying)
                if (attempt === 1) {  // Only track on first failure to avoid double-counting
                    this._trackUploadFailure();
                }

                // Check if retry is recommended by server
                if (error.retryRecommended === false) {
                    this.emit('error', {
                        stage: 'chunk_upload',
                        chunkNumber,
                        error: error.message,
                        code: error.code,
                        retryRecommended: false
                    });
                    throw new Error(`Chunk ${chunkNumber} upload failed (non-retryable error: ${error.code}): ${error.message}`);
                }

                if (attempt >= maxAttempts) {
                    this.emit('error', {
                        stage: 'chunk_upload',
                        chunkNumber,
                        error: error.message,
                        code: error.code,
                        attempts: attempt
                    });
                    throw new Error(`Failed to upload chunk ${chunkNumber} after ${maxAttempts} attempts: ${error.message}`);
                }

                // Use server-provided retry_after if available, otherwise exponential backoff
                const delay = error.retryAfter
                    ? error.retryAfter * 1000  // Convert seconds to milliseconds
                    : this.options.retryDelay * Math.pow(2, attempt - 1);

                console.warn(`Chunk ${chunkNumber} upload failed (attempt ${attempt}/${maxAttempts}, code: ${error.code || 'UNKNOWN'}), retrying in ${delay}ms...`);
                await this.sleep(delay);
            }
        }
    }

    /**
     * Upload all chunks with a sliding-window worker pool.
     *
     * Keeps `options.concurrency` chunks in flight at all times instead of
     * uploading fixed batches (where the slowest chunk stalls the whole batch).
     * Workers re-read `options.concurrency` between chunks, so adaptive
     * concurrency adjustments take effect mid-upload: the pool shrinks by
     * letting excess workers exit and grows by spawning new ones.
     *
     * @returns {Promise<void>}
     */
    async uploadAllChunks() {
        const pending = [];
        for (let i = 0; i < this.totalChunks; i++) {
            // Skip already uploaded chunks (for resume)
            if (!this.uploadedChunks.has(i)) {
                pending.push(i);
            }
        }

        if (pending.length === 0) {
            return;
        }

        let nextIndex = 0;
        let activeWorkers = 0;
        let firstError = null;

        await new Promise((resolve, reject) => {
            const settle = () => {
                if (activeWorkers > 0) return;
                if (firstError) {
                    reject(firstError);
                } else if (this.isPaused && nextIndex < pending.length) {
                    this.emit('paused', { uploadedChunks: this.uploadedChunks.size, totalChunks: this.totalChunks });
                    reject(new Error('Upload cancelled'));
                } else {
                    resolve();
                }
            };

            const spawnWorkers = () => {
                while (activeWorkers < this.options.concurrency &&
                       nextIndex < pending.length &&
                       !firstError && !this.isPaused) {
                    worker();
                }
            };

            const worker = async () => {
                // Runs synchronously until the first await, so the counter is
                // accurate inside spawnWorkers' loop.
                activeWorkers++;
                try {
                    while (!firstError && !this.isPaused) {
                        // Shrink pool if adaptive concurrency was lowered
                        if (activeWorkers > this.options.concurrency) break;
                        if (nextIndex >= pending.length) break;
                        const chunkNumber = pending[nextIndex++];
                        await this.uploadChunk(chunkNumber);
                        // Grow pool if adaptive concurrency was raised
                        spawnWorkers();
                    }
                } catch (error) {
                    if (!firstError) {
                        firstError = error;
                    }
                } finally {
                    activeWorkers--;
                    settle();
                }
            };

            spawnWorkers();
            // If pause was requested before any worker started, no worker
            // will ever call settle() — resolve/reject here instead of
            // leaving the promise pending forever.
            settle();
        });
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
     * @param {number} maxAttempts - Maximum number of polling attempts. Defaults
     *   to a budget scaled by file size (floor 150 = 5 minutes, plus one 2s
     *   attempt per 5MB), because assembly time grows with file size: a 20GB
     *   assembly on a slow disk (sequential read + hash + encryption + optional
     *   AV scan) can legitimately exceed a flat 5-minute cap even though the
     *   server is healthy and will finish.
     * @returns {Promise<Object>} - Final upload result with claim_code and download_url
     */
    async pollStatus(pollInterval = 2000, maxAttempts = null) {
        if (maxAttempts === null) {
            maxAttempts = Math.max(150, Math.ceil(this.file.size / (5 * 1024 * 1024)));
        }
        // Transient poll failures get their own budget so a few network blips
        // don't consume the assembly-progress budget. Resets on any successful
        // poll; ~30 consecutive failures with capped backoff means the server
        // has been unreachable for minutes and we give up.
        const maxConsecutiveErrors = 30;
        let consecutiveErrors = 0;
        let attempts = 0;
        const startTime = Date.now();

        while (attempts < maxAttempts) {
            try {
                // Get current status
                const status = await this.getStatus();

                // Calculate elapsed time
                const elapsed = Math.round((Date.now() - startTime) / 1000);

                // Emit progress event for UI updates
                this.emit('assembling_progress', {
                    status: status.status,
                    uploadId: this.uploadId,
                    filename: status.filename,
                    attempts: attempts + 1,
                    maxAttempts: maxAttempts,
                    elapsedSeconds: elapsed,
                    message: `Processing file... (${elapsed}s elapsed)`
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
                        file_size: status.file_size,
                        expires_at: status.expires_at,
                        max_downloads: status.max_downloads,
                        completed_downloads: status.completed_downloads
                    };
                }

                if (status.status === 'failed') {
                    // Assembly failed - throw error
                    const errorMsg = status.error_message || 'File assembly failed';
                    throw new Error(errorMsg);
                }

                // Status is still "processing" or "uploading" - continue polling
                // Wait before next poll
                consecutiveErrors = 0;
                await this.sleep(pollInterval);
                attempts++;

            } catch (error) {
                // If this is a known error (failed status), rethrow immediately
                if (error.message.includes('assembly failed') || error.message.includes('missing claim_code')) {
                    this.emit('error', { stage: 'assembly', error: error.message });
                    throw error;
                }

                // For network errors, retry with exponential backoff against a
                // separate budget (doesn't consume assembly-progress attempts)
                consecutiveErrors++;
                if (consecutiveErrors >= maxConsecutiveErrors) {
                    this.emit('error', {
                        stage: 'assembly_polling',
                        error: `Polling failed after ${maxConsecutiveErrors} consecutive errors: ${error.message}`
                    });
                    throw new Error(`Assembly status polling failed after ${maxConsecutiveErrors} consecutive errors`);
                }

                // Exponential backoff for network errors (up to 10 seconds)
                const backoffDelay = Math.min(pollInterval * Math.pow(1.5, consecutiveErrors), 10000);
                console.warn(`Status polling attempt failed (${consecutiveErrors}/${maxConsecutiveErrors} consecutive), retrying in ${backoffDelay}ms...`, error.message);
                await this.sleep(backoffDelay);
            }
        }

        // Max attempts reached without completion
        const elapsedMinutes = Math.round((Date.now() - startTime) / 60000);
        throw new Error(`Assembly polling timed out after ${maxAttempts} attempts (${elapsedMinutes} minutes elapsed)`);
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

        // Network conditions may have changed while paused (interface switch,
        // congestion cleared). Discard pre-pause latency data so calibration
        // restarts fresh instead of anchoring to a stale window.
        this.networkMetrics.recentLatencies = [];
        this.networkMetrics.avgLatency = 0;
        this.networkMetrics.baselineLatency = null;
        this.networkMetrics.latencyThreshold = this.networkMetrics.staticLatencyThreshold;
        this.networkMetrics.consecutiveSuccesses = 0;
        this.networkMetrics.consecutiveFailures = 0;

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
     * Emit progress event with calculated metrics (throttled for performance)
     */
    emitProgress() {
        const now = Date.now();
        this.progressThrottle.chunksSinceLastEmit++;

        // Throttle: emit only if enough time passed OR enough chunks uploaded
        const timeSinceLastEmit = now - this.progressThrottle.lastEmit;
        const shouldEmit =
            timeSinceLastEmit >= this.progressThrottle.minInterval ||
            this.progressThrottle.chunksSinceLastEmit >= this.progressThrottle.chunkThreshold ||
            this.uploadedChunks.size === this.totalChunks;  // Always emit at 100%

        if (!shouldEmit) {
            return;
        }

        const percentage = (this.uploadedChunks.size / this.totalChunks) * 100;
        const elapsed = now - this.startTime;
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
            speed: bytesPerMs * 1000, // bytes per second
            currentConcurrency: this.options.concurrency,  // Show current concurrency
            avgLatency: Math.round(this.networkMetrics.avgLatency) || 0  // Show network quality
        });

        // Reset throttle counters
        this.progressThrottle.lastEmit = now;
        this.progressThrottle.chunksSinceLastEmit = 0;
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
        // Check if crypto.subtle is available (requires secure context: HTTPS or localhost)
        if (!crypto || !crypto.subtle || !crypto.subtle.digest) {
            console.warn('Web Crypto API not available (requires HTTPS or localhost). Skipping client-side checksum.');
            return null; // Return null to indicate checksum unavailable
        }

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

    /**
     * Custom error class that includes retry recommendations
     */
    createRetryableError(message, code, retryRecommended, retryAfter) {
        const error = new Error(message);
        error.code = code;
        error.retryRecommended = retryRecommended;
        error.retryAfter = retryAfter;
        return error;
    }

    /**
     * Parse error response and extract retry information
     */

    /**
     * Track successful chunk upload and adjust concurrency
     */
    _trackUploadSuccess(latency) {
        this.networkMetrics.consecutiveSuccesses++;
        this.networkMetrics.consecutiveFailures = 0;

        // Track latency (keep last 10)
        this.networkMetrics.recentLatencies.push(latency);
        if (this.networkMetrics.recentLatencies.length > 10) {
            this.networkMetrics.recentLatencies.shift();
        }

        // Anchor the degradation baseline (Guard 2) to the median of the first
        // three samples rather than the first chunk alone: chunk #1 is often an
        // outlier (cold connection/TLS warmup makes it slow; an idle server
        // makes it anomalously fast), and a too-fast anchor would make the
        // 1.5x degradation guard freeze concurrency for the entire upload.
        if (this.networkMetrics.baselineLatency === null && this.networkMetrics.recentLatencies.length >= 3) {
            const firstThree = this.networkMetrics.recentLatencies.slice(0, 3).sort((a, b) => a - b);
            this.networkMetrics.baselineLatency = firstThree[1];
            console.log('Baseline latency established (median of first 3 chunks):', firstThree[1] + 'ms');
        }

        // Calculate average latency
        this.networkMetrics.avgLatency =
            this.networkMetrics.recentLatencies.reduce((a, b) => a + b, 0) /
            this.networkMetrics.recentLatencies.length;

        // Recalibrate the latency ceiling to the observed link speed. The
        // static threshold assumes a >=10 Mbps uplink; on slower links every
        // chunk exceeds it and Guard 1 would freeze the controller for the
        // whole upload. min(recent) approximates the link's best uncongested
        // latency, so 2x that is a realistic ceiling. max() keeps the static
        // value as a floor so fast links behave exactly as before.
        // Note: if fast early samples slide out of the 10-sample window the
        // ceiling can rise; Guards 2/3 (baseline-relative + trend) remain the
        // primary congestion detectors. Below 3 samples the static threshold
        // applies unchanged.
        if (this.networkMetrics.recentLatencies.length >= 3) {
            this.networkMetrics.latencyThreshold = Math.max(
                this.networkMetrics.staticLatencyThreshold,
                Math.min(...this.networkMetrics.recentLatencies) * 2
            );
        }

        // Check if we should adjust concurrency after N consecutive successes
        if (this.networkMetrics.consecutiveSuccesses >= this.networkMetrics.adjustmentThreshold) {
            // ✅ LATENCY-AWARE DECISION MAKING

            // Guard 1: Don't increase if average latency exceeds threshold
            if (this.networkMetrics.avgLatency > this.networkMetrics.latencyThreshold) {
                console.log(`Skipping concurrency increase: avgLatency (${Math.round(this.networkMetrics.avgLatency)}ms) exceeds threshold (${this.networkMetrics.latencyThreshold}ms)`);
                this.networkMetrics.consecutiveSuccesses = 0;
                return;
            }

            // Guard 2: Don't increase if latency has degraded significantly from
            // baseline (skipped until the median-of-3 baseline is anchored)
            if (this.networkMetrics.baselineLatency !== null) {
                const latencyIncrease = (this.networkMetrics.avgLatency - this.networkMetrics.baselineLatency) / this.networkMetrics.baselineLatency;
                if (latencyIncrease > this.networkMetrics.latencyDegradationLimit) {
                    console.log(`Skipping concurrency increase: latency degraded ${Math.round(latencyIncrease * 100)}% from baseline (limit: ${this.networkMetrics.latencyDegradationLimit * 100}%)`);
                    this.networkMetrics.consecutiveSuccesses = 0;
                    return;
                }
            }

            // Guard 3: Don't increase if latency is trending worse
            const latencyTrend = this._calculateLatencyTrend();
            if (latencyTrend > 0.15) {  // More than 15% increase trend
                console.log(`Skipping concurrency increase: latency trending worse (+${Math.round(latencyTrend * 100)}%)`);
                this.networkMetrics.consecutiveSuccesses = 0;
                return;
            }

            // All guards passed - safe to increase concurrency
            this._adjustConcurrency('increase');
            this.networkMetrics.consecutiveSuccesses = 0;
        }

        // ✅ PROACTIVE DECREASE: Check if latency is degrading even without failures
        if (this.networkMetrics.recentLatencies.length >= 5) {
            const latencyTrend = this._calculateLatencyTrend();

            // If latency is rapidly increasing (>30% trend), proactively decrease
            if (latencyTrend > 0.3) {
                console.log(`Proactive concurrency decrease: latency rapidly increasing (+${Math.round(latencyTrend * 100)}%)`);
                this._adjustConcurrency('decrease');
                this.networkMetrics.consecutiveSuccesses = 0;
            }
        }
    }

    /**
     * Track failed chunk upload and adjust concurrency
     */
    _trackUploadFailure() {
        this.networkMetrics.consecutiveFailures++;
        this.networkMetrics.consecutiveSuccesses = 0;

        // Decrease concurrency after N consecutive failures
        if (this.networkMetrics.consecutiveFailures >= this.networkMetrics.adjustmentThreshold) {
            this._adjustConcurrency('decrease');
            this.networkMetrics.consecutiveFailures = 0;
        }
    }

    /**
     * Calculate latency trend (positive = getting slower, negative = getting faster)
     * Uses linear regression on recent latencies to detect trends
     * @returns {number} - Percentage change (-1.0 = improving 100%, +1.0 = degrading 100%)
     */
    _calculateLatencyTrend() {
        const latencies = this.networkMetrics.recentLatencies;
        if (latencies.length < 3) {
            return 0; // Not enough data
        }

        // Simple linear regression to detect trend
        // Compare average of first half vs second half
        const midpoint = Math.floor(latencies.length / 2);
        const firstHalf = latencies.slice(0, midpoint);
        const secondHalf = latencies.slice(midpoint);

        const firstAvg = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
        const secondAvg = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;

        // Return percentage change (positive = getting worse, negative = getting better)
        return (secondAvg - firstAvg) / firstAvg;
    }

    /**
     * Adjust upload concurrency based on network performance
     */
    _adjustConcurrency(direction) {
        const oldConcurrency = this.options.concurrency;

        if (direction === 'increase') {
            // Good network - increase concurrency by 20%
            this.options.concurrency = Math.min(
                Math.ceil(this.options.concurrency * 1.2),
                this.networkMetrics.maxConcurrency
            );
        } else if (direction === 'decrease') {
            // Poor network - decrease concurrency by 30%
            this.options.concurrency = Math.max(
                Math.floor(this.options.concurrency * 0.7),
                this.networkMetrics.minConcurrency
            );
        }

        if (oldConcurrency !== this.options.concurrency) {
            console.log(`Adaptive concurrency: ${oldConcurrency} → ${this.options.concurrency} (${direction}, avg latency: ${Math.round(this.networkMetrics.avgLatency)}ms)`);

            this.emit('concurrency_adjusted', {
                oldConcurrency,
                newConcurrency: this.options.concurrency,
                direction,
                avgLatency: Math.round(this.networkMetrics.avgLatency),
                consecutiveSuccesses: this.networkMetrics.consecutiveSuccesses,
                consecutiveFailures: this.networkMetrics.consecutiveFailures
            });
        }
    }
    async parseErrorResponse(response) {
        try {
            const error = await response.json();
            return this.createRetryableError(
                error.error || 'Unknown error',
                error.code || 'UNKNOWN',
                error.retry_recommended !== undefined ? error.retry_recommended : true,
                error.retry_after || 5
            );
        } catch {
            // If JSON parsing fails, return generic error
            return this.createRetryableError(
                'Request failed',
                'NETWORK_ERROR',
                true,
                5
            );
        }
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