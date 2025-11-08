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
            concurrency: options.concurrency || 6, // Number of parallel chunk uploads (restored to 6 after removing DB writes during upload)
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
                    password: this.options.password
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

                // Create form data
                const formData = new FormData();
                formData.append('chunk', chunkBlob, `chunk_${chunkNumber}`);

                // Upload chunk
                const response = await fetch(`/api/upload/chunk/${this.uploadId}/${chunkNumber}`, {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'Chunk upload failed');
                }

                const data = await response.json();

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
                    totalChunks: this.totalChunks
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

                if (!response.ok) {
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
                this.isCompleted = true;

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
}