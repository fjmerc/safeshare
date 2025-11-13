/**
 * ResumableDownloader - Handles resumable file downloads using HTTP Range requests
 *
 * Features:
 * - Automatic resume after interruption
 * - Progress tracking with speed calculation
 * - localStorage persistence for resume after page refresh
 * - Efficient streaming with minimal memory usage
 * - Event-based architecture for UI updates
 *
 * @example
 * const downloader = new ResumableDownloader(downloadUrl, filename);
 *
 * downloader.on('progress', (progress) => {
 *   console.log(`${progress.percentage}% complete`);
 * });
 *
 * await downloader.start();
 */
class ResumableDownloader {
    constructor(downloadUrl, filename, fileSize = null) {
        this.downloadUrl = downloadUrl;
        this.filename = filename;
        this.fileSize = fileSize; // Can be null initially, will be fetched
        this.downloadedBytes = 0;
        this.startTime = null;
        this.isPaused = false;
        this.isCompleted = false;

        // Storage key for resume capability
        this.storageKey = `download_${this.filename}_${btoa(downloadUrl).slice(0, 16)}`;

        // Event listeners
        this.eventListeners = {};

        // Collected chunks
        this.chunks = [];
    }

    /**
     * Register event listener
     * @param {string} event - Event name (progress, error, complete, resume)
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
     * Check if partial download exists and can be resumed
     * @returns {Object|null} Saved progress or null
     */
    checkForResume() {
        const saved = localStorage.getItem(this.storageKey);
        if (!saved) return null;

        try {
            const progress = JSON.parse(saved);
            // Verify it's recent (within 7 days)
            const savedTime = new Date(progress.timestamp);
            const daysSince = (Date.now() - savedTime.getTime()) / (1000 * 60 * 60 * 24);

            if (daysSince > 7) {
                // Stale - clear it
                localStorage.removeItem(this.storageKey);
                return null;
            }

            return progress;
        } catch (error) {
            console.error('Failed to parse saved download progress:', error);
            localStorage.removeItem(this.storageKey);
            return null;
        }
    }

    /**
     * Save download progress to localStorage
     */
    saveProgress() {
        const progress = {
            downloadedBytes: this.downloadedBytes,
            fileSize: this.fileSize,
            timestamp: new Date().toISOString()
        };
        localStorage.setItem(this.storageKey, JSON.stringify(progress));
    }

    /**
     * Clear saved progress
     */
    clearProgress() {
        localStorage.removeItem(this.storageKey);
    }

    /**
     * Fetch file size from server using HEAD request
     * @returns {Promise<number>} File size in bytes
     */
    async fetchFileSize() {
        const response = await fetch(this.downloadUrl, {
            method: 'HEAD'
        });

        if (!response.ok) {
            throw new Error('Failed to fetch file information');
        }

        // Check if server supports ranges
        const acceptRanges = response.headers.get('Accept-Ranges');
        if (!acceptRanges || acceptRanges === 'none') {
            console.warn('Server does not support Range requests - resume will not be available');
        }

        const contentLength = response.headers.get('Content-Length');
        if (!contentLength) {
            throw new Error('Server did not provide file size');
        }

        return parseInt(contentLength, 10);
    }

    /**
     * Start or resume download
     * @param {boolean} forceNew - Force new download, ignore saved progress
     * @returns {Promise<Blob>} Downloaded file as Blob
     */
    async start(forceNew = false) {
        try {
            this.startTime = Date.now();

            // Get file size if not provided
            if (!this.fileSize) {
                this.fileSize = await this.fetchFileSize();
            }

            // Check for existing progress
            if (!forceNew) {
                const savedProgress = this.checkForResume();
                if (savedProgress && savedProgress.fileSize === this.fileSize && savedProgress.downloadedBytes > 0) {
                    this.downloadedBytes = savedProgress.downloadedBytes;
                    this.emit('resume', {
                        downloadedBytes: this.downloadedBytes,
                        fileSize: this.fileSize,
                        percentage: (this.downloadedBytes / this.fileSize) * 100
                    });
                    console.log(`Resuming download from ${this.downloadedBytes} bytes`);
                }
            }

            // Determine Range header
            const rangeHeader = this.downloadedBytes > 0
                ? `bytes=${this.downloadedBytes}-`
                : undefined;

            // Start download with fetch
            const response = await fetch(this.downloadUrl, {
                headers: rangeHeader ? { 'Range': rangeHeader } : {}
            });

            if (!response.ok && response.status !== 206) {
                throw new Error(`Download failed: ${response.statusText}`);
            }

            // Check if resume was successful
            if (rangeHeader && response.status === 206) {
                console.log('Download resumed successfully (HTTP 206)');
            } else if (rangeHeader && response.status === 200) {
                // Server doesn't support resume, starting fresh
                console.warn('Server returned full file despite Range request - resuming not supported');
                this.downloadedBytes = 0;
                this.chunks = [];
            }

            // Stream download
            const reader = response.body.getReader();
            const chunks = [];
            let receivedBytes = this.downloadedBytes;

            while (true) {
                if (this.isPaused) {
                    this.emit('paused', { downloadedBytes: receivedBytes });
                    throw new Error('Download paused');
                }

                const { done, value } = await reader.read();

                if (done) {
                    break;
                }

                chunks.push(value);
                receivedBytes += value.length;
                this.downloadedBytes = receivedBytes;

                // Save progress periodically (every 1MB)
                if (receivedBytes % (1024 * 1024) < value.length) {
                    this.saveProgress();
                }

                // Emit progress
                this.emitProgress();
            }

            // Download complete
            this.isCompleted = true;
            this.clearProgress();

            // Combine all chunks into single Blob
            const blob = new Blob(chunks);

            this.emit('complete', {
                filename: this.filename,
                fileSize: this.fileSize,
                blob: blob
            });

            return blob;

        } catch (error) {
            this.emit('error', {
                stage: 'download',
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Pause download
     */
    pause() {
        this.isPaused = true;
        this.saveProgress();
    }

    /**
     * Resume download after pause
     */
    async resume() {
        if (!this.isPaused) return;
        this.isPaused = false;
        return this.start();
    }

    /**
     * Emit progress event with calculated metrics
     */
    emitProgress() {
        if (!this.fileSize) return;

        const percentage = (this.downloadedBytes / this.fileSize) * 100;
        const elapsed = Date.now() - this.startTime;
        const bytesPerMs = this.downloadedBytes / elapsed;
        const remainingBytes = this.fileSize - this.downloadedBytes;
        const estimatedTimeRemaining = remainingBytes / bytesPerMs;

        this.emit('progress', {
            downloadedBytes: this.downloadedBytes,
            totalBytes: this.fileSize,
            percentage: Math.round(percentage * 100) / 100,
            estimatedTimeRemaining: Math.round(estimatedTimeRemaining / 1000), // in seconds
            speed: bytesPerMs * 1000 // bytes per second
        });
    }

    /**
     * Trigger browser download of Blob
     * @param {Blob} blob - File blob to download
     */
    triggerBrowserDownload(blob) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = this.filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    /**
     * Start download and automatically trigger browser download when complete
     * @param {boolean} forceNew - Force new download, ignore saved progress
     */
    async downloadWithProgress(forceNew = false) {
        try {
            const blob = await this.start(forceNew);
            this.triggerBrowserDownload(blob);
        } catch (error) {
            console.error('Download failed:', error);
            throw error;
        }
    }

    /**
     * Static method to check if any resumable downloads exist
     * @returns {Array<Object>} List of resumable downloads
     */
    static getResumableDownloads() {
        const resumable = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith('download_')) {
                try {
                    const data = JSON.parse(localStorage.getItem(key));
                    resumable.push({
                        key: key,
                        filename: key.split('_')[1],
                        ...data
                    });
                } catch (e) {
                    // Invalid data, skip
                }
            }
        }
        return resumable;
    }

    /**
     * Static method to clear all saved download progress
     */
    static clearAllProgress() {
        const keys = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith('download_')) {
                keys.push(key);
            }
        }
        keys.forEach(key => localStorage.removeItem(key));
    }
}
