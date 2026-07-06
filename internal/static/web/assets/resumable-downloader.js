/**
 * ResumableDownloader - Handles pausable file downloads using HTTP Range requests
 *
 * Features:
 * - Pause/resume within the page session (received bytes are retained in
 *   memory, so the assembled file is always complete)
 * - Progress tracking with speed calculation
 * - Event-based architecture for UI updates
 *
 * Resume across a page refresh is intentionally NOT supported: the received
 * bytes only ever live in page memory, so nothing durable exists to resume
 * from after a reload.
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
    constructor(downloadUrl, filename, fileSize = null, options = {}) {
        this.downloadUrl = downloadUrl;
        this.filename = filename;
        this.fileSize = fileSize; // Can be null initially, will be fetched
        this.downloadedBytes = 0;
        this.startTime = null;
        this.sessionStartBytes = 0;
        this.isPaused = false;
        this.isCancelled = false;
        this.isCompleted = false;

        // SH-1.5: optional password sent as X-File-Password header on every
        // request instead of being baked into the URL. Keeps the secret out
        // of proxy access logs, browser history, and Referer headers.
        this.password = options.password || null;

        // Event listeners
        this.eventListeners = {};

        // Received chunks. Retained across pause/resume so the final Blob
        // always contains the full byte sequence, not just the post-resume
        // tail fetched via the Range request.
        this.chunks = [];
    }

    /**
     * Build the headers used on every fetch, including the optional
     * X-File-Password header when this download is password-protected.
     */
    _authHeaders(extra = {}) {
        const headers = { ...extra };
        if (this.password) {
            headers['X-File-Password'] = this.password;
        }
        return headers;
    }

    /**
     * Register event listener
     * @param {string} event - Event name (progress, error, complete, paused, cancelled)
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
     * Fetch file size from server using HEAD request
     * @returns {Promise<number>} File size in bytes
     */
    async fetchFileSize() {
        const response = await fetch(this.downloadUrl, {
            method: 'HEAD',
            headers: this._authHeaders(),
            // Cross-origin redirects preserve custom headers like
            // X-File-Password (unlike Authorization) — fail loudly instead
            // of silently leaking the password to another origin.
            redirect: 'error'
        });

        if (!response.ok) {
            throw new Error('Failed to fetch file information');
        }

        // Check if server supports ranges
        const acceptRanges = response.headers.get('Accept-Ranges');
        if (!acceptRanges || acceptRanges === 'none') {
            console.warn('Server does not support Range requests - pause/resume will restart from the beginning');
        }

        const contentLength = response.headers.get('Content-Length');
        if (!contentLength) {
            throw new Error('Server did not provide file size');
        }

        return parseInt(contentLength, 10);
    }

    /**
     * Start download
     * @returns {Promise<Blob|null>} Downloaded file as Blob, or null if paused/cancelled
     */
    async start() {
        this.startTime = Date.now();
        try {
            // Get file size if not provided
            if (!this.fileSize) {
                this.fileSize = await this.fetchFileSize();
            }
            return await this._download();
        } catch (error) {
            this.emit('error', {
                stage: 'download',
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Resume download after pause. Continues appending to the chunks
     * received before the pause.
     * @returns {Promise<Blob|null>} Downloaded file as Blob, or null if paused/cancelled again
     */
    async resume() {
        if (!this.isPaused || this.isCancelled) return null;
        this.isPaused = false;
        // Restart the speed/ETA baseline so paused time doesn't drag the
        // average down.
        this.startTime = Date.now();
        this.sessionStartBytes = this.downloadedBytes;
        try {
            return await this._download();
        } catch (error) {
            this.emit('error', {
                stage: 'download',
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Fetch (the remainder of) the file and stream it into this.chunks.
     * @returns {Promise<Blob|null>} Complete file Blob, or null if paused/cancelled
     */
    async _download() {
        const rangeHeader = this.downloadedBytes > 0
            ? `bytes=${this.downloadedBytes}-`
            : undefined;

        const response = await fetch(this.downloadUrl, {
            headers: this._authHeaders(rangeHeader ? { 'Range': rangeHeader } : {}),
            // See fetchFileSize(): don't follow redirects that would carry
            // X-File-Password to another origin.
            redirect: 'error'
        });

        if (!response.ok && response.status !== 206) {
            throw new Error(`Download failed: ${response.statusText}`);
        }

        if (rangeHeader && response.status === 206) {
            // Verify the 206 actually starts where we asked. A misbehaving
            // proxy could return a different offset, which would corrupt the
            // assembled file just like the original resume bug.
            const contentRange = response.headers.get('Content-Range');
            const match = contentRange && contentRange.match(/^bytes (\d+)-/);
            const start = match ? parseInt(match[1], 10) : NaN;
            if (start !== this.downloadedBytes) {
                // Unlike the 200 fallback, this body starts at the wrong
                // offset, so it can't be consumed — drop it and re-fetch
                // the whole file (downloadedBytes=0 means no Range header,
                // so this can't recurse a second time).
                console.warn(`Server returned unexpected Content-Range "${contentRange}" (expected start ${this.downloadedBytes}) - restarting from the beginning`);
                this.downloadedBytes = 0;
                this.sessionStartBytes = 0;
                this.chunks = [];
                await response.body.cancel();
                return this._download();
            }
            console.log(`Download resumed from byte ${this.downloadedBytes} (HTTP 206)`);
        } else if (rangeHeader && response.status === 200) {
            // Server ignored the Range request and is sending the full file:
            // drop what we have and start over so bytes aren't duplicated.
            console.warn('Server returned full file despite Range request - restarting from the beginning');
            this.downloadedBytes = 0;
            this.sessionStartBytes = 0;
            this.chunks = [];
        }

        const reader = response.body.getReader();

        while (true) {
            if (this.isPaused || this.isCancelled) {
                // Release the connection; a resume issues a fresh Range request.
                await reader.cancel();
                break;
            }

            const { done, value } = await reader.read();

            if (done) {
                break;
            }

            this.chunks.push(value);
            this.downloadedBytes += value.length;

            // Emit progress
            this.emitProgress();
        }

        if (this.isCancelled) {
            return null;
        }

        if (this.isPaused) {
            this.emit('paused', { downloadedBytes: this.downloadedBytes });
            return null;
        }

        // Guard against serving a truncated file if the stream ended early
        // (e.g. dropped connection that didn't surface as a fetch error).
        if (this.fileSize && this.downloadedBytes !== this.fileSize) {
            throw new Error(`Download incomplete: received ${this.downloadedBytes} of ${this.fileSize} bytes`);
        }

        // Download complete
        this.isCompleted = true;

        // Combine all chunks into single Blob
        const blob = new Blob(this.chunks);

        this.emit('complete', {
            filename: this.filename,
            fileSize: this.fileSize,
            blob: blob
        });

        return blob;
    }

    /**
     * Pause download. Received chunks are kept so resume() can continue
     * from where it left off.
     */
    pause() {
        this.isPaused = true;
    }

    /**
     * Cancel download permanently
     */
    cancel() {
        this.isCancelled = true;
        this.emit('cancelled', { downloadedBytes: this.downloadedBytes });
        this.chunks = [];
        this.downloadedBytes = 0;
    }

    /**
     * Emit progress event with calculated metrics
     */
    emitProgress() {
        if (!this.fileSize) return;

        const percentage = (this.downloadedBytes / this.fileSize) * 100;
        const elapsed = Math.max(Date.now() - this.startTime, 1);
        const bytesPerMs = (this.downloadedBytes - this.sessionStartBytes) / elapsed;
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
     */
    async downloadWithProgress() {
        try {
            const blob = await this.start();
            // If blob is null, download was paused or cancelled (not an error)
            if (blob) {
                this.triggerBrowserDownload(blob);
            }
        } catch (error) {
            console.error('Download failed:', error);
            throw error;
        }
    }
}
